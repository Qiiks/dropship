use std::io::{BufRead, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use super::protocol::{Request, Response};
use super::ruleset::{self, Ruleset};

const LOCK_PATH: &str = "/run/dropship-firewall.lock";
const STATE_DIR: &str = "/var/lib/dropship";
const STATE_PATH: &str = "/var/lib/dropship/blocked.nft";
const UNIT_PATH: &str = "/etc/systemd/system/dropship-firewall.service";
const UNIT_NAME: &str = "dropship-firewall.service";
const UNIT: &str = include_str!("../../../assets/linux/dropship-firewall.service");

const NFT_PATHS: [&str; 4] = ["/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft", "/bin/nft"];
const SYSTEMCTL_PATHS: [&str; 2] = ["/usr/bin/systemctl", "/bin/systemctl"];

pub(crate) fn run() -> i32 {
    let lock = match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(LOCK_PATH)
    {
        Ok(file) => file,
        Err(e) => {
            write_response(&failure(format!("failed to open the firewall lock: {e}")));
            return 1;
        }
    };

    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        write_response(&failure(
            "another dropship instance is already managing the firewall",
        ));
        return 1;
    }

    let _lock = lock;

    let Some(nft) = resolve(&NFT_PATHS) else {
        write_response(&failure("nft was not found; install nftables"));
        return 1;
    };

    let mut helper = Helper {
        nft,
        systemctl: resolve(&SYSTEMCTL_PATHS),
        uid: 0,
        last_persist: true,
        unit_enabled: false,
    };

    write_response(&Response {
        ok: true,
        warning: None,
        error: None,
    });

    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };

        let Ok(request) = serde_json::from_str::<Request>(&line) else {
            write_response(&failure("invalid request"));
            continue;
        };

        write_response(&helper.handle(request));
    }

    if !helper.last_persist && helper.table_exists() {
        let _ = helper.run_nft_args(&["delete", "table", "inet", "dropship"]);
    }

    0
}

struct Helper {
    nft: PathBuf,
    systemctl: Option<PathBuf>,
    uid: u32,
    last_persist: bool,
    unit_enabled: bool,
}

impl Helper {
    fn handle(&mut self, request: Request) -> Response {
        match request {
            Request::Hello { dynamic, uid } => self.hello(dynamic, uid),
            Request::Apply { blocks, persist } => self.apply(&blocks, persist),
        }
    }

    fn hello(&mut self, dynamic: bool, uid: u32) -> Response {
        self.uid = target_uid(uid);
        self.last_persist = !dynamic;

        let mut warning = None;

        if dynamic {
            if let Err(e) = remove_state_file() {
                warning = Some(format!("the firewall state file could not be removed: {e}"));
            }

            if let Some(systemctl) = self.systemctl.clone() {
                if unit_is_enabled(&systemctl) {
                    if let Err(e) = run_systemctl(&systemctl, &["disable", UNIT_NAME]) {
                        warning = Some(e);
                    } else {
                        self.unit_enabled = false;
                    }
                }
            }
        }

        Response {
            ok: true,
            warning,
            error: None,
        }
    }

    fn apply(&mut self, blocks: &[String], persist: bool) -> Response {
        let ruleset = match ruleset::generate(blocks, self.uid) {
            Ok(ruleset) => ruleset,
            Err(e) => return failure(e),
        };

        let Some(ruleset) = ruleset else {
            return self.clear();
        };

        if let Err(e) = self.run_batch(&ruleset.base) {
            return failure(e);
        }

        let replace = format!("flush chain inet dropship output\n{}", ruleset.rules);
        if let Err(e) = self.run_batch(&replace) {
            return failure(e);
        }

        self.last_persist = persist;

        let warning = if persist {
            self.persist(&ruleset).err()
        } else {
            self.clear_persistence().err()
        };

        Response {
            ok: true,
            warning,
            error: None,
        }
    }

    fn clear(&mut self) -> Response {
        if self.table_exists() {
            if let Err(e) = self.run_nft_args(&["delete", "table", "inet", "dropship"]) {
                return failure(e);
            }
        }

        self.last_persist = false;

        Response {
            ok: true,
            warning: self.clear_persistence().err(),
            error: None,
        }
    }

    fn persist(&mut self, ruleset: &Ruleset) -> Result<(), String> {
        let Some(systemctl) = self.systemctl.clone() else {
            return Err(
                "blocks will not survive a reboot because systemd was not available".to_string(),
            );
        };

        let content = format!("{}{}", ruleset.base, ruleset.rules);
        write_state_file(&content)
            .map_err(|e| format!("blocks are active but will not survive a reboot: {e}"))?;

        let changed = match std::fs::read_to_string(UNIT_PATH) {
            Ok(existing) => existing != UNIT,
            Err(_) => true,
        };

        if changed {
            std::fs::write(UNIT_PATH, UNIT)
                .map_err(|e| format!("blocks are active but will not survive a reboot: {e}"))?;
            run_systemctl(&systemctl, &["daemon-reload"])
                .map_err(|e| format!("blocks are active but will not survive a reboot: {e}"))?;
        }

        if !self.unit_enabled {
            run_systemctl(&systemctl, &["enable", UNIT_NAME])
                .map_err(|e| format!("blocks are active but will not survive a reboot: {e}"))?;
            self.unit_enabled = true;
        }

        Ok(())
    }

    fn clear_persistence(&mut self) -> Result<(), String> {
        remove_state_file()
            .map_err(|e| format!("the firewall state file could not be removed: {e}"))?;

        let Some(systemctl) = self.systemctl.clone() else {
            return Ok(());
        };

        if self.unit_enabled || unit_is_enabled(&systemctl) {
            run_systemctl(&systemctl, &["disable", "--now", UNIT_NAME])
                .map_err(|e| format!("the firewall service could not be disabled: {e}"))?;
            self.unit_enabled = false;
        }

        Ok(())
    }

    fn table_exists(&self) -> bool {
        Command::new(&self.nft)
            .args(["list", "table", "inet", "dropship"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    fn run_batch(&self, batch: &str) -> Result<(), String> {
        let mut child = Command::new(&self.nft)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("failed to start nft: {e}"))?;

        let mut write_error = None;
        if let Some(mut stdin) = child.stdin.take() {
            if let Err(e) = stdin.write_all(batch.as_bytes()) {
                write_error = Some(format!("failed to send the rules to nft: {e}"));
            }
        }

        let output = child
            .wait_with_output()
            .map_err(|e| format!("failed to run nft: {e}"))?;

        if let Some(e) = write_error {
            return Err(e);
        }

        nft_result(output)
    }

    fn run_nft_args(&self, args: &[&str]) -> Result<(), String> {
        let output = Command::new(&self.nft)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| format!("failed to run nft: {e}"))?;

        nft_result(output)
    }
}

fn nft_result(output: Output) -> Result<(), String> {
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(if stderr.is_empty() {
        format!("nft exited with {}", output.status)
    } else {
        stderr
    })
}

fn resolve(paths: &[&str]) -> Option<PathBuf> {
    paths
        .iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .map(Path::to_path_buf)
}

fn target_uid(fallback: u32) -> u32 {
    for key in ["PKEXEC_UID", "SUDO_UID"] {
        if let Ok(value) = std::env::var(key) {
            if let Ok(uid) = value.trim().parse::<u32>() {
                return uid;
            }
        }
    }

    fallback
}

fn run_systemctl(systemctl: &Path, args: &[&str]) -> Result<(), String> {
    let output = Command::new(systemctl)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("failed to run systemctl: {e}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(if stderr.is_empty() {
        format!("systemctl exited with {}", output.status)
    } else {
        format!("systemctl failed: {stderr}")
    })
}

fn unit_is_enabled(systemctl: &Path) -> bool {
    Command::new(systemctl)
        .args(["is-enabled", UNIT_NAME])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn write_state_file(content: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::create_dir_all(STATE_DIR)?;
    std::fs::set_permissions(STATE_DIR, std::fs::Permissions::from_mode(0o755))?;
    std::fs::write(STATE_PATH, content)?;
    std::fs::set_permissions(STATE_PATH, std::fs::Permissions::from_mode(0o644))
}

fn remove_state_file() -> std::io::Result<()> {
    match std::fs::remove_file(STATE_PATH) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn failure(message: impl Into<String>) -> Response {
    Response {
        ok: false,
        warning: None,
        error: Some(message.into()),
    }
}

fn write_response(response: &Response) {
    let mut stdout = std::io::stdout().lock();
    let _ = serde_json::to_writer(&mut stdout, response);
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
}

#[cfg(test)]
mod tests {
    use super::{STATE_PATH, UNIT};

    #[test]
    fn unit_file_uses_the_state_path() {
        let condition = format!("ConditionPathExists={STATE_PATH}");
        let command = format!("-f {STATE_PATH}");

        assert!(UNIT.contains(condition.as_str()));
        assert!(UNIT.contains(command.as_str()));
    }
}

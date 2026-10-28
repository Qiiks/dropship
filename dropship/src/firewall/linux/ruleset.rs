use std::str::FromStr;

use ipnet::IpNet;

pub(crate) struct Ruleset {
    pub base: String,
    pub rules: String,
}

pub(crate) const BASE: &str = concat!(
    "add table inet dropship\n",
    "add chain inet dropship output {\n",
    "    type filter hook output priority mangle; policy accept;\n",
    "}\n",
);

pub(crate) fn generate(blocks: &[String], uid: u32) -> Result<Option<Ruleset>, String> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();

    for block in blocks {
        for value in block.split(',') {
            let value = value.trim();
            let network = IpNet::from_str(value)
                .map_err(|_| format!("invalid network: {value}"))?
                .trunc();

            match network {
                IpNet::V4(_) => v4.push(network.to_string()),
                IpNet::V6(_) => v6.push(network.to_string()),
            }
        }
    }

    v4.sort();
    v4.dedup();
    v6.sort();
    v6.dedup();

    if v4.is_empty() && v6.is_empty() {
        return Ok(None);
    }

    let mut rules = String::new();
    if !v4.is_empty() {
        rules.push_str(&format!(
            "add rule inet dropship output meta skuid {uid} ip daddr {{ {} }} counter drop\n",
            v4.join(", ")
        ));
    }
    if !v6.is_empty() {
        rules.push_str(&format!(
            "add rule inet dropship output meta skuid {uid} ip6 daddr {{ {} }} counter drop\n",
            v6.join(", ")
        ));
    }

    Ok(Some(Ruleset {
        base: BASE.to_string(),
        rules,
    }))
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::process::{Command, Stdio};

    use super::{BASE, generate};

    fn blocks(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn v4_only() {
        let ruleset = generate(&blocks(&["64.224.26.0/23"]), 1000)
            .unwrap()
            .unwrap();

        assert_eq!(ruleset.base, BASE);
        assert_eq!(
            ruleset.rules,
            "add rule inet dropship output meta skuid 1000 ip daddr { 64.224.26.0/23 } counter drop\n"
        );
    }

    #[test]
    fn v6_only() {
        let ruleset = generate(&blocks(&["2600:1f18::/32"]), 1000)
            .unwrap()
            .unwrap();

        assert_eq!(ruleset.base, BASE);
        assert_eq!(
            ruleset.rules,
            "add rule inet dropship output meta skuid 1000 ip6 daddr { 2600:1f18::/32 } counter drop\n"
        );
    }

    #[test]
    fn both_families() {
        let ruleset = generate(&blocks(&["64.224.26.0/23", "2600:1f18::/32"]), 1000)
            .unwrap()
            .unwrap();

        assert_eq!(ruleset.base, BASE);
        assert_eq!(
            ruleset.rules,
            concat!(
                "add rule inet dropship output meta skuid 1000 ip daddr { 64.224.26.0/23 } counter drop\n",
                "add rule inet dropship output meta skuid 1000 ip6 daddr { 2600:1f18::/32 } counter drop\n",
            )
        );
    }

    #[test]
    fn comma_separated() {
        let ruleset = generate(&blocks(&["5.42.0.0/16,64.224.26.0/23"]), 1000)
            .unwrap()
            .unwrap();

        assert_eq!(
            ruleset.rules,
            "add rule inet dropship output meta skuid 1000 ip daddr { 5.42.0.0/16, 64.224.26.0/23 } counter drop\n"
        );
    }

    #[test]
    fn duplicates_are_dropped() {
        let ruleset = generate(
            &blocks(&["5.42.0.0/16", "5.42.0.0/16", "5.42.0.0/16,5.42.0.0/16"]),
            1000,
        )
        .unwrap()
        .unwrap();

        assert_eq!(
            ruleset.rules,
            "add rule inet dropship output meta skuid 1000 ip daddr { 5.42.0.0/16 } counter drop\n"
        );
    }

    #[test]
    fn host_bits_are_truncated() {
        let ruleset = generate(&blocks(&["5.42.0.1/16"]), 1000)
            .unwrap()
            .unwrap();

        assert_eq!(
            ruleset.rules,
            "add rule inet dropship output meta skuid 1000 ip daddr { 5.42.0.0/16 } counter drop\n"
        );
    }

    #[test]
    fn invalid_network_errors() {
        let error = match generate(&blocks(&["5.42.0.0/16", "not-a-network"]), 1000) {
            Err(e) => e,
            Ok(_) => panic!("expected an error"),
        };

        assert_eq!(error, "invalid network: not-a-network");
    }

    #[test]
    fn empty_input_is_none() {
        assert!(generate(&[], 1000).unwrap().is_none());
    }

    #[test]
    fn nft_accepts_the_ruleset() {
        let ruleset = generate(&blocks(&["64.224.26.0/23", "2600:1f18::/32"]), 1000)
            .unwrap()
            .unwrap();

        let mut child = match Command::new("nft")
            .args(["-c", "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipping nft check: nft is not installed");
                return;
            }
            Err(e) => panic!("failed to start nft: {e}"),
        };

        let rules = format!("{}{}", ruleset.base, ruleset.rules);

        child
            .stdin
            .take()
            .unwrap()
            .write_all(rules.as_bytes())
            .unwrap();

        let output = child.wait_with_output().unwrap();
        if output.status.success() {
            return;
        }

        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        // an unprivileged runner cannot read the netlink cache; retry in a user namespace
        if stderr.contains("Operation not permitted") || stderr.contains("cache initialization failed") {
            let retry = Command::new("unshare")
                .args(["-Urn", "nft", "-c", "-f", "-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn();

            let Ok(mut retry) = retry else {
                eprintln!("skipping nft check: {stderr}");
                return;
            };

            retry.stdin.take().unwrap().write_all(rules.as_bytes()).unwrap();
            let output = retry.wait_with_output().unwrap();
            if output.status.success() {
                return;
            }

            let retry_stderr = String::from_utf8_lossy(&output.stderr).to_string();
            assert!(
                retry_stderr.contains("Operation not permitted") || retry_stderr.contains("unshare failed"),
                "{}",
                retry_stderr
            );
            eprintln!("skipping nft check: a user namespace is not permitted here");
            return;
        }

        panic!("{stderr}");
    }
}

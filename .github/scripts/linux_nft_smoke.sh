#!/usr/bin/env bash
# behavior test for the linux helper: run as root inside a network namespace
#   sudo env TARGET_UID=$(id -u) PKEXEC_UID=$(id -u) unshare -n bash .github/scripts/linux_nft_smoke.sh
set -euo pipefail

BIN="${DROPSHIP_BIN:-dropship/target/debug/dropship}"
: "${TARGET_UID:?set TARGET_UID to the uid whose traffic should be blocked}"
PORT=47831
CGROUP_PARENT="/sys/fs/cgroup/user.slice/user-$TARGET_UID.slice/user@$TARGET_UID.service"
CGROUP="$CGROUP_PARENT/dropship-game"

WORK="$(mktemp -d)"
FIFO="$WORK/helper.in"
OUT="$WORK/helper.out"
ERR="$WORK/helper.err"
HELPER_PID=""
LISTENER_PID=""
RESPONSE=""

fail() {
  echo "FAIL: $*" >&2
  if [ -s "$ERR" ]; then
    echo "--- helper stderr ---" >&2
    tail -n 20 "$ERR" >&2
  fi
  if [ -s "$OUT" ]; then
    echo "--- helper stdout ---" >&2
    tail -n 20 "$OUT" >&2
  fi
  exit 1
}

cleanup() {
  local rc=$?
  exec 3>&- 2>/dev/null || true
  if [ -n "$HELPER_PID" ] && kill -0 "$HELPER_PID" 2>/dev/null; then
    kill "$HELPER_PID" 2>/dev/null || true
    wait "$HELPER_PID" 2>/dev/null || true
  fi
  if [ -n "$LISTENER_PID" ] && kill -0 "$LISTENER_PID" 2>/dev/null; then
    kill "$LISTENER_PID" 2>/dev/null || true
    wait "$LISTENER_PID" 2>/dev/null || true
  fi
  nft delete table inet dropship 2>/dev/null || true
  rmdir "$CGROUP" 2>/dev/null || true
  rm -rf "$WORK"
  exit "$rc"
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || fail "run as root, e.g. sudo env TARGET_UID=\$(id -u) unshare -n bash $0"
[ -x "$BIN" ] || fail "dropship binary not found: $BIN (build it or set DROPSHIP_BIN)"

ip link set lo up
nft delete table inet dropship 2>/dev/null || true

# mimic what systemd does for a logged-in user: the manager's cgroup is owned
# by the user, so the helper only has to hand over cgroup.procs
mkdir -p "$CGROUP_PARENT"
chown "$TARGET_UID:$TARGET_UID" "$CGROUP_PARENT"
rmdir "$CGROUP" 2>/dev/null || true

# opening the fifo read/write lets us hold a writer without blocking; the
# helper closes the inherited descriptor so our close is the only eof
mkfifo "$FIFO"
exec 3<>"$FIFO"
env PKEXEC_UID="$TARGET_UID" "$BIN" --firewall-helper <"$FIFO" >"$OUT" 2>"$ERR" 3>&- &
HELPER_PID=$!

for _ in $(seq 1 100); do
  if grep -qx '{"ok":true}' "$OUT" 2>/dev/null; then break; fi
  kill -0 "$HELPER_PID" 2>/dev/null || fail "helper exited before becoming ready"
  sleep 0.1
done
grep -qx '{"ok":true}' "$OUT" 2>/dev/null || fail "helper did not report ready"
echo "ok: helper ready"

request() {
  local payload="$1" before after
  before=$(wc -l <"$OUT")
  printf '%s\n' "$payload" >&3
  for _ in $(seq 1 100); do
    after=$(wc -l <"$OUT")
    if [ "$after" -gt "$before" ]; then break; fi
    kill -0 "$HELPER_PID" 2>/dev/null || fail "helper exited while handling $payload"
    sleep 0.1
  done
  if [ "$after" -le "$before" ]; then fail "helper did not respond to $payload"; fi
  RESPONSE=$(tail -n 1 "$OUT")
}

expect_ok() {
  case "$1" in
    *'"ok":true'*) ;;
    *) fail "helper rejected the request: $1" ;;
  esac
}

request '{"op":"hello","dynamic":false,"uid":0}'
expect_ok "$RESPONSE"
echo "ok: hello accepted"

request '{"op":"apply","blocks":["127.0.0.1/32","::1/128"],"persist":false}'
expect_ok "$RESPONSE"
echo "ok: blocks applied"

cat >"$WORK/listener.py" <<'PY'
import select, socket, sys

port = int(sys.argv[1])
socks = []
for family, addr in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((addr, port))
    sock.listen(8)
    socks.append(sock)
with open(sys.argv[2], "w") as ready_file:
    ready_file.write("ready")
while True:
    ready, _, _ = select.select(socks, [], [], 1.0)
    for sock in ready:
        conn, _ = sock.accept()
        conn.close()
PY
python3 "$WORK/listener.py" "$PORT" "$WORK/listener.ready" &
LISTENER_PID=$!

for _ in $(seq 1 50); do
  if [ -f "$WORK/listener.ready" ]; then break; fi
  kill -0 "$LISTENER_PID" 2>/dev/null || fail "listener exited"
  sleep 0.1
done
[ -f "$WORK/listener.ready" ] || fail "listener did not start on port $PORT"

probe() {
  # the real path is `dropship launch`, which joins before exec; here root
  # places the probe in the cgroup and then drops to the target uid, since a
  # user outside the user-manager subtree cannot move its own process
  python3 - "$1" "$PORT" "$2" "$TARGET_UID" "$CGROUP" <<'PY'
import os, socket, sys

host, port, join, uid, cgroup = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "join", int(sys.argv[4]), sys.argv[5]
if join:
    with open(cgroup + "/cgroup.procs", "w") as procs:
        procs.write(str(os.getpid()))

os.setgroups([])
os.setgid(uid)
os.setuid(uid)

sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(3)
try:
    sock.connect((host, port))
    print("connected")
except socket.timeout:
    print("timeout")
except OSError as exc:
    print("error:%s" % exc)
finally:
    sock.close()
PY
}

for host in 127.0.0.1 ::1; do
  result=$(probe "$host" join)
  if [ "$result" != "timeout" ]; then
    fail "expected a blocked connect from the game cgroup to $host to time out, got: $result"
  fi
done
echo "ok: blocked connect from the game cgroup timed out"

for host in 127.0.0.1 ::1; do
  result=$(probe "$host" nojoin)
  if [ "$result" != "connected" ]; then
    fail "expected a connect from outside the cgroup to $host to succeed, got: $result"
  fi
done
echo "ok: the same user outside the cgroup is unaffected"

packets=$(nft -j list table inet dropship | python3 -c '
import json, sys

total = 0
for item in json.load(sys.stdin).get("nftables", []):
    rule = item.get("rule")
    if not rule:
        continue
    for expr in rule.get("expr", []):
        counter = expr.get("counter")
        if counter:
            total += int(counter.get("packets", 0))
print(total)
')
if [ "$packets" -le 0 ]; then
  fail "expected the drop counter to increase, got $packets packets"
fi
echo "ok: counter increased ($packets packets)"

request '{"op":"apply","blocks":[],"persist":false}'
expect_ok "$RESPONSE"
if nft list table inet dropship >/dev/null 2>&1; then
  fail "empty apply left the table in place"
fi

for host in 127.0.0.1 ::1; do
  result=$(probe "$host" nojoin)
  if [ "$result" != "connected" ]; then
    fail "expected a connect to $host after clearing to succeed, got: $result"
  fi
done
if [ -d "$CGROUP" ]; then
  fail "clearing left the game cgroup behind"
fi
echo "ok: cleared connect succeeded and the cgroup was removed"

# the listener inherited the fifo descriptor; kill it before closing the writer
kill "$LISTENER_PID" 2>/dev/null || true
wait "$LISTENER_PID" 2>/dev/null || true
LISTENER_PID=""

exec 3>&-
for _ in $(seq 1 100); do
  state=$(ps -o stat= -p "$HELPER_PID" 2>/dev/null || true)
  case "$state" in
    ""|Z*) break ;;
  esac
  sleep 0.1
done
state=$(ps -o stat= -p "$HELPER_PID" 2>/dev/null || true)
if [ -n "$state" ] && [ "${state#Z}" = "$state" ]; then
  fail "helper did not exit after stdin closed"
fi
wait "$HELPER_PID" || fail "helper exited with a nonzero status"
HELPER_PID=""

if nft list table inet dropship >/dev/null 2>&1; then
  fail "table still present after the helper exited"
fi
echo "ok: table removed"

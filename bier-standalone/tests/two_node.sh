#!/usr/bin/env bash
#
# Two-node test over UDP loopback:
#   node A (127.0.0.1) imposes BIER and forwards to node B
#   node B (127.0.0.2) disposes the packet and delivers the payload
#
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIERD=${1:-$ROOT/build/bierd}
TMP=$(mktemp -d)
A_PID=
B_PID=
RX_PID=

cleanup() {
    [ -n "$RX_PID" ] && kill "$RX_PID" 2>/dev/null || true
    [ -n "$A_PID" ] && kill "$A_PID" 2>/dev/null || true
    [ -n "$B_PID" ] && kill "$B_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT

# Receiver for the payload delivered by node B.
python3 - "$TMP/rx.bin" <<'PY' &
import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.2", 19002))
s.settimeout(5)
data, _ = s.recvfrom(65535)
with open(sys.argv[1], "wb") as f:
    f.write(data)
PY
RX_PID=$!

"$BIERD" -c "$ROOT/configs/node-a.json" -v >"$TMP/a.log" 2>&1 &
A_PID=$!

"$BIERD" -c "$ROOT/configs/node-b.json" -v >"$TMP/b.log" 2>&1 &
B_PID=$!

sleep 0.5

python3 - <<'PY'
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"HELLO-TWO-NODE", ("127.0.0.1", 19001))
PY

if ! wait "$RX_PID"; then
    echo "receiver timed out" >&2
    echo "--- node A ---" >&2
    cat "$TMP/a.log" >&2
    echo "--- node B ---" >&2
    cat "$TMP/b.log" >&2
    exit 1
fi
RX_PID=

if ! grep -q "HELLO-TWO-NODE" "$TMP/rx.bin"; then
    echo "payload mismatch: $(cat "$TMP/rx.bin")" >&2
    exit 1
fi

echo "two-node BIER test passed"

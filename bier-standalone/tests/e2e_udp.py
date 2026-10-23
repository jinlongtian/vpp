#!/usr/bin/env python3
"""
End-to-end test for bierd over the non-MPLS/UDP encapsulation.

Starts bierd with configs/example.json, injects BIER packets on the midpoint
port, checks replication and disposition, then injects an inner packet on the
imposition port and checks the resulting BIER packets.
"""

import socket
import struct
import subprocess
import sys
import time


def mkpkt(bits, ttl=10, sender=333, proto=5, entropy=0, payload=b"PAYLOAD"):
    # BIER over UDP: 4-byte BIFT field, 8-byte BIER header, bit-string, payload.
    bid = (0 << 16) | (1 << 8) | 0  # bsl=64, sd=1, set=0
    wire = (bid << 12) | (1 << 8) | ttl
    first = (0x5 << 28) | (0 << 20) | (entropy & 0xFFFFF)
    return (
        struct.pack(">I", wire)
        + struct.pack(">IHH", first, proto & 0x3F, sender)
        + bits
        + payload
    )


def bind(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    s.settimeout(2.0)
    return s


def drain(*socks):
    for s in socks:
        s.setblocking(False)
        try:
            while True:
                s.recvfrom(65535)
        except BlockingIOError:
            pass
        s.setblocking(True)
        s.settimeout(2.0)


def bitcount(data):
    return sum(bin(b).count("1") for b in data)


def main():
    bierd = sys.argv[1]
    config = sys.argv[2]

    proc = subprocess.Popen(
        [bierd, "-c", config, "-v"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(0.5)

    s1, s2, s3 = bind(18201), bind(18202), bind(18203)
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Midpoint: BP1 and BP2 are replicated to two next hops.
    bits = bytearray(8)
    bits[7] = 0x03
    tx.sendto(mkpkt(bytes(bits)), ("127.0.0.1", 18138))
    d1, _ = s1.recvfrom(65535)
    d2, _ = s2.recvfrom(65535)

    for name, data, want in (("18201", d1, 0x01), ("18202", d2, 0x02)):
        wire = struct.unpack(">I", data[:4])[0]
        assert (wire & 0xFF) == 9, f"{name}: ttl"
        assert bitcount(data[12:20]) == 1, f"{name}: one bit"
        assert data[12:20][7] == want, f"{name}: bit-string"
        assert data[20:] == b"PAYLOAD", f"{name}: payload"

    # Disposition: BP3 is delivered locally without the BIER header.
    bits = bytearray(8)
    bits[7] = 0x04
    tx.sendto(mkpkt(bytes(bits), sender=99), ("127.0.0.1", 18138))
    d3, _ = s3.recvfrom(65535)
    assert d3 == b"PAYLOAD", "disposition payload"

    drain(s1, s2, s3)

    # Imposition: every bit is set; only BP1/BP2/BP3 are configured.
    tx.sendto(b"HELLO", ("127.0.0.1", 18139))
    d1, _ = s1.recvfrom(65535)
    d2, _ = s2.recvfrom(65535)
    d3, _ = s3.recvfrom(65535)

    for name, data in (("18201", d1), ("18202", d2)):
        wire = struct.unpack(">I", data[:4])[0]
        first = struct.unpack(">I", data[4:8])[0]
        sender = struct.unpack(">H", data[10:12])[0]
        assert (wire & 0xFF) == 64, f"{name}: imposed ttl"
        assert ((first >> 24) & 0xF) == 0, f"{name}: version"
        assert sender == 333, f"{name}: sender"
        assert bitcount(data[12:20]) == 1, f"{name}: one bit"
        assert data[20:] == b"HELLO", f"{name}: inner payload"

    assert d3 == b"HELLO", "imposition disposition payload"

    proc.stdin.write("show stats\nquit\n")
    proc.stdin.flush()
    out, err = proc.communicate(timeout=3)

    assert "rx=" in out and "tx=" in out and "disposed=" in out, "cli stats"
    assert proc.returncode == 0, f"bierd exit code {proc.returncode}: {err}"
    print("BIER UDP end-to-end test passed")


if __name__ == "__main__":
    main()

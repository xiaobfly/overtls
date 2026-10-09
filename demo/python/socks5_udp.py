#!/usr/bin/env python3
"""SOCKS5 UDP ASSOCIATE round-trip helper for the overtls demo suite.

Does the SOCKS5 handshake (no auth) against `--proxy`, requests UDP ASSOCIATE and then
sends `--count` SOCKS5 UDP datagrams (RSV=0, FRAG=0, ATYP=1) to the relay address.
"""

import argparse
import socket
import struct
import sys


def host_port(text):
    host, sep, port = text.rpartition(":")
    if not sep or not host or not port.isdigit():
        raise argparse.ArgumentTypeError(f"expected HOST:PORT, got {text!r}")
    return host, int(port)


def recv_exact(sock, size):
    buf = b""
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise OSError("connection closed by proxy")
        buf += chunk
    return buf


def read_addr(data, offset):
    """Parse ATYP+ADDR+PORT at `offset`; returns (host, port, next_offset)."""
    atyp = data[offset]
    offset += 1
    if atyp == 0x01:
        host = socket.inet_ntoa(data[offset:offset + 4])
        offset += 4
    elif atyp == 0x04:
        host = socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
        offset += 16
    elif atyp == 0x03:
        length = data[offset]
        offset += 1
        host = data[offset:offset + length].decode("utf-8", "replace")
        offset += length
    else:
        raise OSError(f"unknown address type 0x{atyp:02x}")
    port = struct.unpack("!H", data[offset:offset + 2])[0]
    return host, port, offset + 2


def read_addr_stream(sock):
    """Parse ATYP+ADDR+PORT straight off a stream socket."""
    atyp = recv_exact(sock, 1)[0]
    if atyp == 0x01:
        host = socket.inet_ntoa(recv_exact(sock, 4))
    elif atyp == 0x04:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    elif atyp == 0x03:
        host = recv_exact(sock, recv_exact(sock, 1)[0]).decode("utf-8", "replace")
    else:
        raise OSError(f"unknown address type 0x{atyp:02x}")
    return host, struct.unpack("!H", recv_exact(sock, 2))[0]


def run(args):
    proxy = host_port(args.proxy)
    target = host_port(args.target)

    control = socket.create_connection(proxy, timeout=args.timeout)
    try:
        control.sendall(b"\x05\x01\x00")  # VER, NMETHODS=1, no auth
        greeting = recv_exact(control, 2)
        if greeting != b"\x05\x00":
            raise OSError(f"greeting rejected: {greeting.hex()}")

        control.sendall(b"\x05\x03\x00\x01" + b"\x00" * 4 + b"\x00\x00")  # UDP ASSOCIATE 0.0.0.0:0
        head = recv_exact(control, 3)  # VER, REP, RSV
        if head[0] != 0x05:
            raise OSError(f"bad reply version: {head.hex()}")
        if head[1] != 0x00:
            raise OSError(f"UDP ASSOCIATE failed with REP=0x{head[1]:02x}")
        relay = read_addr_stream(control)

        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(args.timeout)
        try:
            # The relay advertises a loopback address in these demos, so binding loopback keeps the
            # source address of every datagram deterministic (and matches the relay's filters).
            udp.bind(("127.0.0.1", 0))
            payload = args.payload.encode("utf-8")
            request_addr = b"\x01" + socket.inet_aton(target[0]) + struct.pack("!H", target[1])
            for i in range(1, args.count + 1):
                udp.sendto(b"\x00\x00\x00" + request_addr + payload, relay)
                data, _ = udp.recvfrom(65535)
                if len(data) < 4 or data[0:2] != b"\x00\x00" or data[2] != 0:
                    raise OSError(f"malformed UDP reply: {data.hex()}")
                from_host, from_port, offset = read_addr(data, 3)
                echoed = data[offset:]
                print(f"REPLY {i} from={from_host}:{from_port} len={len(echoed)} payload={echoed!r}", flush=True)
                if echoed != payload:
                    raise OSError(f"payload mismatch: sent {payload!r}, got {echoed!r}")
        finally:
            udp.close()
    finally:
        control.close()


def main():
    parser = argparse.ArgumentParser(description="SOCKS5 UDP ASSOCIATE round trip")
    parser.add_argument("--proxy", required=True, help="SOCKS5 proxy HOST:PORT")
    parser.add_argument("--target", required=True, help="UDP target HOST:PORT")
    parser.add_argument("--payload", default="hello-over-udp", help="datagram payload to send")
    parser.add_argument("--timeout", type=float, default=5.0, help="socket timeout in seconds")
    parser.add_argument("--count", type=int, default=1, help="number of datagrams to send")
    args = parser.parse_args()
    try:
        run(args)
    except (OSError, ValueError, struct.error, IndexError) as exc:
        print(f"FAILED {exc}", flush=True)
        return 1
    print("OK", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

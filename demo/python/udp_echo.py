#!/usr/bin/env python3
"""UDP echo server for the overtls demo suite.

Prints the bound port as the first stdout line ("PORT <n>"), then echoes every
datagram back to its sender. `--count N` exits after N datagrams.
"""

import argparse
import socket
import sys


def main():
    parser = argparse.ArgumentParser(description="UDP echo server")
    parser.add_argument("--port", type=int, default=0, help="UDP port to bind (0 = ephemeral)")
    parser.add_argument("--count", type=int, default=0, help="exit after N datagrams (0 = unlimited)")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", args.port))
    print(f"PORT {sock.getsockname()[1]}", flush=True)

    seen = 0
    try:
        while True:
            data, addr = sock.recvfrom(65535)
            sock.sendto(data, addr)
            seen += 1
            print(f"ECHO {seen} from={addr[0]}:{addr[1]} len={len(data)}", flush=True)
            if args.count and seen >= args.count:
                break
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Minimal HTTP probe for the demo scenarios (stdlib only).

The scenarios must show what the wire looks like, so this probe can send a byte-exact request
straight to a host (`--raw FILE --host HOST:PORT`), an absolute-form request through an HTTP proxy
(`--proxy`) or a request inside a CONNECT tunnel (`--connect-proxy`). It prints
`STATUS <first line>`, optionally `BODY <repr>`, then either `EOF ...` or `FAILED ...`, and exits
non-zero when no response arrived.

usage: http_probe.py (--url URL | --raw FILE --host HOST:PORT) [--header "K: V"]...
                     [--proxy HOST:PORT] [--connect-proxy HOST:PORT] [--timeout SECONDS]
"""
import argparse
import socket
import sys
from urllib.parse import urlsplit


def parse_hostport(value):
    host, _, port = value.rpartition(":")
    return (host or "127.0.0.1", int(port))


def read_until(sock, timeout, marker):
    """Read until `marker` shows up; returns (data, complete)."""
    sock.settimeout(timeout)
    data = b""
    while marker not in data:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        except OSError:
            break
        if not chunk:
            break
        data += chunk
    return data, marker in data


def read_all(sock, timeout, initial=b""):
    """Read until EOF or timeout; returns (bytes, timed_out)."""
    sock.settimeout(timeout)
    chunks = [initial] if initial else []
    timed_out = False
    while True:
        try:
            data = sock.recv(65536)
        except socket.timeout:
            timed_out = True
            break
        except OSError as error:
            if not chunks:
                print("FAILED %s" % error)
            break
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks), timed_out


def report(body):
    if not body:
        print("EOF no response bytes")
        return 1
    print("STATUS %s" % body.split(b"\r\n", 1)[0].decode("latin1", "replace"))
    if b"\r\n\r\n" in body:
        payload = body.split(b"\r\n\r\n", 1)[1]
        if payload:
            print("BODY %r" % payload[:256])
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url")
    parser.add_argument("--raw")
    parser.add_argument("--host")
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--proxy")
    parser.add_argument("--connect-proxy")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    if args.raw and (args.proxy or args.connect_proxy):
        parser.error("--raw sends the file straight to --host; --proxy/--connect-proxy need --url")

    if args.raw:
        if not args.host:
            print("FAILED --raw requires --host HOST:PORT")
            return 1
        connect_to = parse_hostport(args.host)
        request = open(args.raw, "rb").read()
    elif args.url:
        parts = urlsplit(args.url)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        host_header = args.host or parts.netloc
        if args.proxy:
            connect_to = parse_hostport(args.proxy)
            request_line = "GET %s HTTP/1.1" % args.url
        elif args.connect_proxy:
            connect_to = parse_hostport(args.connect_proxy)
            request_line = "GET %s HTTP/1.1" % path
        else:
            connect_to = (parts.hostname, parts.port or 80)
            request_line = "GET %s HTTP/1.1" % path
        lines = [request_line, "Host: %s" % host_header, "Connection: close"] + args.header
        request = ("\r\n".join(lines) + "\r\n\r\n").encode()
    else:
        print("FAILED either --url or --raw is required")
        return 1

    sock = socket.create_connection(connect_to, args.timeout)
    leftover = b""
    if args.connect_proxy:
        target = urlsplit(args.url).netloc if args.url else args.host
        sock.sendall(("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (target, target)).encode())
        # Only the response head is read here: after the 200 the proxy stays silent for a refused
        # tunnel, so a full read_all() would block for the whole --timeout before the request is
        # even sent.
        head, complete = read_until(sock, args.timeout, b"\r\n\r\n")
        first = head.split(b"\r\n", 1)[0].decode("latin1", "replace") if head else "EOF"
        print("CONNECT-STATUS %s" % first)
        if " 200" not in first:
            print("FAILED connect rejected")
            return 1
        if complete:
            leftover = head.split(b"\r\n\r\n", 1)[1]
    sock.sendall(request)
    body, timed_out = read_all(sock, args.timeout, leftover)
    if not body and timed_out:
        print("FAILED no response within %ss" % args.timeout)
        return 1
    return report(body)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print("FAILED %s" % error)
        sys.exit(1)

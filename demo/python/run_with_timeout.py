#!/usr/bin/env python3
"""Run a command with a hard deadline for the demo suite (stdlib only).

`run_with_timeout.py [--log FILE] SECONDS COMMAND...` runs COMMAND with stdout and stderr combined
into one pipe, copied to this process's stdout (so the caller still sees it live) and, with
`--log`, appended to FILE as well. The exit code is COMMAND's; when the deadline expires the whole
process tree is signalled, `!! timed out after <s>s: <command>` is printed (and written to the log)
and 124 is returned.

The output is pumped by a reader thread that is deliberately allowed to lag: a hard-killed MSYS
shell can leave a forked child behind holding the pipe (and the process itself can refuse to die),
so neither the wrapper nor its caller may ever block waiting for that pipe to close.

Used by demo/lib.sh and demo/run_all.sh.
"""

import os
import signal
import subprocess
import sys
import threading


def pump(stream, log_handle):
    """Copy the child's combined output to our stdout and to the log until the pipe ends."""
    try:
        while True:
            # read1() returns as soon as some bytes are available; read() would wait for a full
            # buffer and make a chatty command look silent.
            chunk = stream.read1(4096)
            if not chunk:
                break
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
            if log_handle is not None:
                log_handle.write(chunk)
                log_handle.flush()
    except (OSError, ValueError):
        pass


def report(message, log_handle):
    line = message.encode() + b"\n"
    sys.stderr.buffer.write(line)
    sys.stderr.buffer.flush()
    if log_handle is not None:
        log_handle.write(line)
        log_handle.flush()


def signal_tree(child, sig):
    """Signal the child's whole process tree (Windows has no signals: taskkill /T is forceful)."""
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(child.pid)], capture_output=True)
    else:
        try:
            os.killpg(child.pid, sig)
        except OSError:
            pass


def reap(child, timeout):
    """Wait for the child, but never longer than `timeout`; None when it is still alive."""
    try:
        return child.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


def main():
    argv = sys.argv[1:]
    if argv[:1] == ["--log"]:
        log_path, argv = argv[1], argv[2:]
    else:
        log_path = None
    seconds = float(argv[0])
    command = argv[1:]
    log_handle = open(log_path, "wb") if log_path else None
    # A new session on POSIX makes the child a process-group leader, so its group can be signalled.
    child = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=os.name != "nt",
    )
    reader = threading.Thread(target=pump, args=(child.stdout, log_handle), daemon=True)
    reader.start()

    code = reap(child, seconds)
    if code is not None:
        reader.join(timeout=10)  # drain what the child produced before it exited
        return code

    report("!! timed out after %gs: %s" % (seconds, " ".join(command)), log_handle)
    signal_tree(child, signal.SIGTERM)
    if reap(child, 5) is None:
        signal_tree(child, signal.SIGKILL)
        reap(child, 5)
    return 124


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: run_with_timeout.py [--log FILE] SECONDS COMMAND...", file=sys.stderr)
        sys.exit(2)
    sys.exit(main())

import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class ExecResult:
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    truncated: bool
    timed_out: bool


def execute_verified(fd, argv, *, timeout_ms, output_bytes):
    os.set_inheritable(fd, True)
    path = f"/proc/self/fd/{fd}"
    process = subprocess.Popen([path, *argv], executable=path, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/", env={"PATH": "/nonexistent", "LANG": "C"}, close_fds=True, pass_fds=(fd,), start_new_session=True)
    for stream in (process.stdout, process.stderr):
        os.set_blocking(stream.fileno(), False)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "out")
    selector.register(process.stderr, selectors.EVENT_READ, "err")
    out, err = bytearray(), bytearray()
    truncated = timed_out = False
    deadline = time.monotonic() + timeout_ms / 1000
    while selector.get_map():
        if not timed_out and time.monotonic() >= deadline:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for key, _ in selector.select(0.01):
            chunk = os.read(key.fileobj.fileno(), 65536)
            if not chunk:
                selector.unregister(key.fileobj)
                continue
            room = max(0, output_bytes - len(out) - len(err))
            kept = chunk[:room]
            (out if key.data == "out" else err).extend(kept)
            truncated |= len(kept) < len(chunk)
    process.wait()
    os.close(fd)
    return ExecResult(None if timed_out else process.returncode, bytes(out), bytes(err), truncated, timed_out)

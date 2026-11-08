"""The only subprocess entry point of the sandbox package, and the only reader of os.environ."""
from __future__ import annotations

import os
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from . import _consts


def _minimal_env(parent: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return the minimal environment handed to every docker subprocess.

    ``PATH`` is always present (with a fixed fallback); the other allowed keys are copied
    only if present in ``parent`` (default: the process environment). Nothing else passes.
    """
    source = os.environ if parent is None else parent
    env = {"PATH": source.get("PATH") or _consts.DEFAULT_PATH}
    for key in _consts.ALLOWED_ENV_KEYS:
        if key != "PATH" and key in source:
            env[key] = source[key]
    return env


@dataclass(frozen=True)
class _Proc:
    returncode: int | None      # None if host-killed on timeout or not started
    out: bytes                  # first `cap` bytes of stdout (stdout+stderr when merged)
    out_total: int              # all stdout bytes seen, including discarded ones
    tail: bytes                 # last TAIL_BYTES of stdout seen
    err: bytes                  # first STDERR_CAP_BYTES of stderr; b"" when merged
    timed_out: bool             # host-side timeout fired and the child was killed
    start_error: str | None     # "docker_unavailable" | "os_error" | None
    stdin_error: bool           # BrokenPipe/OSError while writing stdin (recorded, not raised)
    duration_ms: int


class _Capture:
    """Keeps at most `cap` bytes, counts every byte and remembers the last bytes seen."""

    def __init__(self, cap: int) -> None:
        self.cap = cap
        self.buf = bytearray()
        self.total = 0
        self.tail = b""
        self.read_error = False

    def feed(self, chunk: bytes) -> None:
        self.total += len(chunk)
        room = self.cap - len(self.buf)
        if room > 0:
            self.buf += chunk[:room]
        self.tail = (self.tail + chunk)[-_consts.TAIL_BYTES:]


def _drain(stream, capture: _Capture) -> None:
    try:
        while True:
            chunk = stream.read1(_consts.READ_CHUNK)
            if not chunk:
                return
            capture.feed(chunk)
    except (OSError, ValueError):
        # The pipe was torn down under us (process killed / stream closed); the
        # condition is recorded and the partial capture is still reported.
        capture.read_error = True


def _feed_stdin(pipe, data: bytes, flags: dict[str, bool]) -> None:
    try:
        pipe.write(data)
        pipe.flush()
    except (OSError, ValueError):
        flags["stdin_error"] = True
    finally:
        try:
            pipe.close()
        except (OSError, ValueError):
            flags["stdin_error"] = True


def _run_capped(argv: Sequence[str], *, stdin: bytes | None, timeout_s: float,
                cap: int, merge_stderr: bool) -> _Proc:
    """Run argv (never through a shell) with a deadline and capped capture.

    Reader threads keep at most `cap` bytes while counting every byte. On deadline the
    child is killed. OS-level start failures are reported in `start_error`, not raised.
    """
    started = time.monotonic()

    def elapsed_ms() -> int:
        return int((time.monotonic() - started) * 1000)

    try:
        proc = subprocess.Popen(
            list(argv),
            shell=False,
            env=_minimal_env(),
            stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if merge_stderr else subprocess.PIPE,
            close_fds=True,
        )
    except (FileNotFoundError, PermissionError):
        return _Proc(None, b"", 0, b"", b"", False, "docker_unavailable", False, elapsed_ms())
    except (OSError, ValueError):
        return _Proc(None, b"", 0, b"", b"", False, "os_error", False, elapsed_ms())

    out_cap = _Capture(cap)
    err_cap = _Capture(_consts.STDERR_CAP_BYTES)
    flags = {"stdin_error": False}
    threads: list[threading.Thread] = []

    def spawn(target, *args) -> None:
        thread = threading.Thread(target=target, args=args, daemon=True)
        thread.start()
        threads.append(thread)

    spawn(_drain, proc.stdout, out_cap)
    if not merge_stderr:
        spawn(_drain, proc.stderr, err_cap)
    if stdin is not None:
        spawn(_feed_stdin, proc.stdin, stdin, flags)

    timed_out = False
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        try:
            proc.wait(timeout=_consts.KILL_WAIT_S)
        except subprocess.TimeoutExpired:
            timed_out = True  # unkillable child: give up waiting, still report the timeout
    for thread in threads:
        thread.join(timeout=_consts.KILL_WAIT_S)
    if not any(t.is_alive() for t in threads):
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                try:
                    stream.close()
                except (OSError, ValueError):
                    flags["stdin_error"] = flags["stdin_error"]  # close failure is harmless

    return _Proc(
        returncode=None if timed_out else proc.returncode,
        out=bytes(out_cap.buf),
        out_total=out_cap.total,
        tail=out_cap.tail,
        err=b"" if merge_stderr else bytes(err_cap.buf),
        timed_out=timed_out,
        start_error=None,
        stdin_error=flags["stdin_error"],
        duration_ms=elapsed_ms(),
    )

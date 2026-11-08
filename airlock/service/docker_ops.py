"""Docker calls of the service (startup checks, leftover cleanup): argv lists only, via M1's
capped subprocess helper."""
from __future__ import annotations

import json
import logging
import re

from airlock.sandbox._proc import _run_capped

_log = logging.getLogger("airlock.service")

DOCKER_TIMEOUT_S: float = 30.0
CID_LINE_RE = r"[0-9a-f]{64}"
_CAP_BYTES = 256 * 1024


class DockerCheckError(Exception):
    """str() is a fixed check name: docker_runtime | docker_image | leftover_list."""


def _run(argv: list[str]):
    return _run_capped(argv, stdin=None, timeout_s=DOCKER_TIMEOUT_S, cap=_CAP_BYTES,
                       merge_stderr=False)


def check_runtime(docker_cmd: tuple[str, ...], runtime: str) -> None:
    proc = _run([*docker_cmd, "info", "--format", "{{json .Runtimes}}"])
    if proc.start_error is not None or proc.timed_out or proc.returncode != 0:
        raise DockerCheckError("docker_runtime")
    try:
        runtimes = json.loads(proc.out.decode("utf-8"))
    except (ValueError, RecursionError):
        raise DockerCheckError("docker_runtime") from None
    if not isinstance(runtimes, dict) or runtime not in runtimes:
        raise DockerCheckError("docker_runtime")


def check_image(docker_cmd: tuple[str, ...], image: str) -> None:
    proc = _run([*docker_cmd, "image", "inspect", "--format", "{{.Id}}", image])
    if proc.start_error is not None or proc.timed_out or proc.returncode != 0:
        raise DockerCheckError("docker_image")


def remove_leftovers(docker_cmd: tuple[str, ...]) -> tuple[int, int]:
    """Remove containers labelled airlock=1. Returns (removed, failed); logs counts only."""
    proc = _run([*docker_cmd, "ps", "-aq", "--no-trunc", "--filter", "label=airlock=1"])
    if (proc.start_error is not None or proc.timed_out or proc.returncode != 0
            or proc.out_total > len(proc.out)):
        raise DockerCheckError("leftover_list")
    try:
        text = proc.out.decode("ascii")
    except UnicodeDecodeError:
        raise DockerCheckError("leftover_list") from None
    ids = [line for line in text.splitlines() if line]
    if any(not re.fullmatch(CID_LINE_RE, line) for line in ids):
        raise DockerCheckError("leftover_list")
    removed = failed = 0
    for cid in ids:
        result = _run([*docker_cmd, "rm", "-f", cid])
        if result.start_error is None and not result.timed_out and result.returncode == 0:
            removed += 1
        else:
            failed += 1
    _log.info("leftover containers removed=%d failed=%d", removed, failed)
    return removed, failed

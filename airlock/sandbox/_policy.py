"""Validation of agent tool calls and classification of resource-limit outcomes."""
from __future__ import annotations

import posixpath
from dataclasses import dataclass
from typing import Literal

from . import _consts

ARG_SCHEMAS: dict[str, frozenset[str]] = {
    "list_dir": frozenset({"path"}),
    "read_file": frozenset({"path"}),
    "write_file": frozenset({"path", "content"}),
    "run_command": frozenset({"command"}),
}


@dataclass(frozen=True)
class Rejection:
    blocked_reason: Literal["path_escape", "forbidden_tool", "too_large"]
    message: str            # fixed runner text; never contains agent input


@dataclass(frozen=True)
class Validated:
    tool: str
    path: str | None        # absolute, normalised, == WORK_ROOT or under WORK_ROOT + "/"
    content: bytes | None   # strict UTF-8 encoding of write content
    command: str | None


def resolve_work_path(path: str) -> str | None:
    """Lexical resolution against the work root; None if the result leaves it."""
    root = _consts.WORK_ROOT
    if path.startswith("/"):
        c = posixpath.normpath(path)
    else:
        c = posixpath.normpath(posixpath.join(root, path))
    if c == root or c.startswith(root + "/"):
        return c
    return None


def validate_call(tool: object, args: object, *, file_write_max_bytes: int) -> Validated | Rejection:
    """Deny-by-default validation; the first failing check wins."""
    if not isinstance(tool, str) or tool not in ARG_SCHEMAS:
        return Rejection("forbidden_tool", "unknown tool")
    if not isinstance(args, dict):
        return Rejection("forbidden_tool", "arguments must be an object")
    if set(args) != ARG_SCHEMAS[tool]:
        return Rejection("forbidden_tool", "wrong argument names")
    if any(not isinstance(v, str) for v in args.values()):
        return Rejection("forbidden_tool", "arguments must be strings")
    encoded: dict[str, bytes] = {}
    for key, value in args.items():
        try:
            encoded[key] = value.encode("utf-8")
        except UnicodeEncodeError:
            return Rejection("forbidden_tool", "argument is not valid UTF-8 text")
    path = args.get("path")
    command = args.get("command")
    if "\x00" in (path or "") or "\x00" in (command or ""):
        return Rejection("forbidden_tool", "NUL byte in argument")
    if path is not None and len(encoded["path"]) > _consts.MAX_PATH_BYTES:
        return Rejection("forbidden_tool", "path too long")
    if command is not None and len(encoded["command"]) > _consts.MAX_COMMAND_BYTES:
        return Rejection("too_large", "command too large")
    if "content" in encoded and len(encoded["content"]) > file_write_max_bytes:
        return Rejection("too_large", "content too large")
    resolved: str | None = None
    if path is not None:
        resolved = resolve_work_path(path)
        if resolved is None:
            return Rejection("path_escape", "path escapes the work directory")
    return Validated(tool, resolved, encoded.get("content"), command)


def classify_limit(*, rc: int | None, duration_ms: int, timeout_s: int,
                   host_timed_out: bool, output_tail: bytes) -> str | None:
    """Map an exec outcome to "timeout" / "memory" / "pids" / None (first match wins)."""
    if host_timed_out:
        return "timeout"
    if rc == _consts.TIMEOUT_EXIT and duration_ms >= timeout_s * 1000 - _consts.TIMEOUT_SLACK_MS:
        return "timeout"
    if rc == 137:
        return "memory"
    if rc not in (None, 0) and _consts.FORK_FAILURE_RE.search(output_tail):
        return "pids"
    return None

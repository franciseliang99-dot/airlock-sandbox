"""Allow-listed event builders and the synchronous emitter."""
from __future__ import annotations

import dataclasses
import json
from collections.abc import Callable

from airlock.sandbox import DestroyProof, DiffResult, Limits, ToolResult

from .prompt import TOOL_ARGS

EVENT_MAX_BYTES = 32768               # len(json.dumps(ev, ensure_ascii=True, separators=(",",":")))
EVENT_TEXT_MAX_CHARS = 2000           # assistant_text, output_excerpt, summary
EVENT_ARG_MAX_CHARS = 1000            # per tool arg value
FILES_BUDGET_BYTES = 16384
FILES_MAX_ENTRIES = 200
_PATH_MAX_CHARS = 256

EVENT_FIELDS: dict[str, frozenset[str]] = {
    "sandbox_created": frozenset({"type", "limits"}),
    "llm_call": frozenset({"type", "step", "status", "tokens_in", "tokens_out", "usage_reported",
                           "error_kind", "assistant_text", "truncated", "duration_ms"}),
    "tool_call": frozenset({"type", "step", "tool", "args", "args_truncated"}),
    "tool_result": frozenset({"type", "step", "tool", "ok", "exit_code", "limit_hit",
                              "duration_ms", "output_bytes", "output_excerpt", "truncated"}),
    "action_blocked": frozenset({"type", "step", "tool", "blocked_reason", "source"}),
    "budget_stop": frozenset({"type", "step", "reason", "hook"}),
    "resource_peak": frozenset({"type", "memory_bytes", "pids", "cpu_ms"}),
    "artifact_collected": frozenset({"type", "state", "size_bytes", "sha256", "files",
                                     "files_truncated"}),
    "sandbox_destroyed": frozenset({"type", "container_ref", "verified"}),
    "sandbox_destroy_failed": frozenset({"type", "container_ref", "verified", "error_class"}),
    "task_finished": frozenset({"type", "reason", "steps_used", "tokens_in", "tokens_out",
                                "summary"}),
}

_DIFF_STATES = frozenset({"ok", "no_changes", "too_large", "error"})


class _EmitFailed(Exception):
    """Private: the sink raised, or the event was malformed or oversize."""


class Emitter:
    def __init__(self, sink: Callable[[dict], None]) -> None:
        self._sink = sink
        self.broken = False

    def emit(self, event: dict) -> None:
        if self.broken:
            return
        kind = event.get("type") if isinstance(event, dict) else None
        expected = EVENT_FIELDS.get(kind) if isinstance(kind, str) else None
        if expected is None or set(event) != expected:
            raise _EmitFailed("bad event keys")
        try:
            text = json.dumps(event, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        except (TypeError, ValueError, RecursionError):
            raise _EmitFailed("unserialisable event") from None
        if len(text) > EVENT_MAX_BYTES:
            raise _EmitFailed("event too large")
        copy = json.loads(text)
        try:
            self._sink(copy)
        except Exception:
            self.broken = True
            raise _EmitFailed("sink failed") from None


# ---------------------------------------------------------------------- builders

def _int_or_none(v: object) -> int | None:
    return v if type(v) is int else None


def sandbox_created(limits: Limits) -> dict:
    return {"type": "sandbox_created", "limits": dataclasses.asdict(limits)}


def llm_call(step: int, status: str, tokens_in: int, tokens_out: int, usage_reported: bool,
             error_kind: str | None, assistant_text: str, duration_ms: int) -> dict:
    return {"type": "llm_call", "step": step, "status": status, "tokens_in": tokens_in,
            "tokens_out": tokens_out, "usage_reported": usage_reported, "error_kind": error_kind,
            "assistant_text": assistant_text[:EVENT_TEXT_MAX_CHARS],
            "truncated": len(assistant_text) > EVENT_TEXT_MAX_CHARS, "duration_ms": duration_ms}


def tool_call(step: int, tool: str, args: dict) -> dict:
    out: dict[str, str] = {}
    truncated = False
    for key in TOOL_ARGS.get(tool, ()):
        value = args.get(key)
        if isinstance(value, str):
            if len(value) > EVENT_ARG_MAX_CHARS:
                truncated = True
            out[key] = value[:EVENT_ARG_MAX_CHARS]
    if len(out) != len(args):
        truncated = True
    return {"type": "tool_call", "step": step, "tool": tool, "args": out,
            "args_truncated": truncated}


def tool_result(step: int, tool: str, result: ToolResult) -> dict:
    return {"type": "tool_result", "step": step, "tool": tool, "ok": bool(result.ok),
            "exit_code": result.exit_code, "limit_hit": result.limit_hit,
            "duration_ms": result.duration_ms, "output_bytes": result.output_bytes,
            "output_excerpt": result.output[:EVENT_TEXT_MAX_CHARS],
            "truncated": bool(result.truncated) or len(result.output) > EVENT_TEXT_MAX_CHARS}


def action_blocked(step: int, tool: str | None, blocked_reason: str, source: str) -> dict:
    return {"type": "action_blocked", "step": step, "tool": tool,
            "blocked_reason": blocked_reason, "source": source}


def budget_stop(step: int, reason: str, hook: str) -> dict:
    return {"type": "budget_stop", "step": step, "reason": reason, "hook": hook}


def resource_peak(peak: dict) -> dict:
    return {"type": "resource_peak", "memory_bytes": peak.get("memory_bytes"),
            "pids": peak.get("pids"), "cpu_ms": peak.get("cpu_ms")}


def _budget_files(files: object) -> tuple[list[dict], bool]:
    out: list[dict] = []
    used = 0
    if not isinstance(files, list):
        return out, True
    for item in files:
        if not isinstance(item, dict):
            continue
        if len(out) >= FILES_MAX_ENTRIES:
            return out, True
        entry = {"path": str(item.get("path", ""))[:_PATH_MAX_CHARS],
                 "change": str(item.get("change", ""))[:32],
                 "lines_added": _int_or_none(item.get("lines_added")),
                 "lines_removed": _int_or_none(item.get("lines_removed"))}
        size = len(json.dumps(entry, ensure_ascii=True, separators=(",", ":"))) + 1
        if used + size > FILES_BUDGET_BYTES:
            return out, True
        out.append(entry)
        used += size
    return out, False


def artifact_collected(diff: DiffResult | None) -> dict:
    if diff is None:
        return {"type": "artifact_collected", "state": "error", "size_bytes": 0, "sha256": None,
                "files": [], "files_truncated": False}
    files, truncated = _budget_files(diff.files)
    state = diff.state if diff.state in _DIFF_STATES else "error"
    sha = diff.sha256[:64] if isinstance(diff.sha256, str) else None
    return {"type": "artifact_collected", "state": state, "size_bytes": _int_or_none(diff.size_bytes) or 0,
            "sha256": sha, "files": files, "files_truncated": truncated}


def sandbox_destroyed(proof: DestroyProof) -> dict:
    return {"type": "sandbox_destroyed", "container_ref": str(proof.container_ref)[:64],
            "verified": True}


def sandbox_destroy_failed(proof: DestroyProof) -> dict:
    return {"type": "sandbox_destroy_failed", "container_ref": str(proof.container_ref)[:64],
            "verified": False, "error_class": str(proof.error_class)[:64]
            if proof.error_class is not None else None}


def task_finished(reason: str, steps_used: int, tokens_in: int, tokens_out: int,
                  summary: str | None) -> dict:
    return {"type": "task_finished", "reason": reason, "steps_used": steps_used,
            "tokens_in": tokens_in, "tokens_out": tokens_out,
            "summary": None if summary is None else summary[:EVENT_TEXT_MAX_CHARS]}

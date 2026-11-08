"""Deterministic, deny-by-default parsing of model replies."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Literal

from .contract import RawToolCall
from .prompt import (REJ_MULTIPLE, REJ_NO_ACTION, REJ_TOO_LONG, REJ_UNPARSEABLE_NATIVE,
                     REJ_UNPARSEABLE_TEXT)

REPLY_MAX_CHARS = 65536
_MAX_ARGS = 8
_BLOCK_RE = re.compile(r"^```json[ \t]*\r?\n(.*?)\r?\n```[ \t]*$", re.M | re.S)
_FAIL = object()


@dataclass(frozen=True)
class Action:
    tool: str
    args: dict[str, str]


@dataclass(frozen=True)
class Rejected:
    reason: Literal["unparseable", "multiple_actions", "no_action", "reply_too_long"]
    message: str                      # fixed text


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _no_constants(name: str) -> object:
    raise ValueError("non-finite number")


def _load(text: str) -> object:
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except (ValueError, RecursionError):
        return _FAIL


def _valid_args(obj: object) -> dict[str, str] | None:
    if not isinstance(obj, dict) or len(obj) > _MAX_ARGS:
        return None
    for key, value in obj.items():
        if not isinstance(key, str) or not isinstance(value, str):
            return None
    return obj


def _valid_tool(name: object) -> bool:
    return isinstance(name, str) and 1 <= len(name) <= 64


def parse_text_reply(content: str | None) -> Action | Rejected:
    unparseable = Rejected("unparseable", REJ_UNPARSEABLE_TEXT)
    if not content:
        return unparseable
    if len(content) > REPLY_MAX_CHARS:
        return Rejected("reply_too_long", REJ_TOO_LONG)
    blocks = _BLOCK_RE.findall(content)
    if len(blocks) != 1:
        return unparseable
    obj = _load(blocks[0])
    if not isinstance(obj, dict) or set(obj) != {"tool", "args"}:
        return unparseable
    tool = obj["tool"]
    args = _valid_args(obj["args"])
    if not _valid_tool(tool) or args is None:
        return unparseable
    return Action(tool, args)


def parse_native_reply(content: str | None,
                       tool_calls: tuple[RawToolCall, ...]) -> Action | Rejected:
    if len(tool_calls) == 0:
        return Rejected("no_action", REJ_NO_ACTION)
    if len(tool_calls) > 1:
        return Rejected("multiple_actions", REJ_MULTIPLE)
    call = tool_calls[0]
    if len(call.arguments) > REPLY_MAX_CHARS:
        return Rejected("reply_too_long", REJ_TOO_LONG)
    unparseable = Rejected("unparseable", REJ_UNPARSEABLE_NATIVE)
    obj = {} if call.arguments == "" else _load(call.arguments)
    args = _valid_args(obj)
    if args is None or not _valid_tool(call.name):
        return unparseable
    return Action(call.name, args)

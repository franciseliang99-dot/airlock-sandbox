"""Bounded conversation history and the builders for assistant / follow-up messages."""
from __future__ import annotations

import json

from .contract import AgentConfig
from .parse import Action
from .prompt import HISTORY_ARG_MAX_CHARS, OFFERED_TOOLS

_TRUNC_NOTE = "\n[... truncated by airlock]"


def history_chars(messages: tuple[dict, ...] | list[dict]) -> int:
    total = 0
    for m in messages:
        total += len(m.get("content") or "")
        for call in m.get("tool_calls") or ():
            fn = call["function"]
            total += len(fn["name"]) + len(fn["arguments"])
    return total


def _clean(text: str) -> str:
    """Replace lone surrogates so the request body always encodes as UTF-8."""
    return text.encode("utf-8", "replace").decode("utf-8")


def truncate_text(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + _TRUNC_NOTE


def assistant_message(config: AgentConfig, content: str | None, action: Action | None,
                      step: int) -> dict:
    text = truncate_text(_clean(content), config.assistant_history_max_chars) if content else None
    if config.action_mode == "native" and action is not None:
        name = action.tool if action.tool in OFFERED_TOOLS else "unknown"
        args = {_clean(k): _clean(v)[:HISTORY_ARG_MAX_CHARS] for k, v in action.args.items()}
        return {"role": "assistant", "content": text,
                "tool_calls": [{"id": f"call_{step}", "type": "function",
                                "function": {"name": name,
                                             "arguments": json.dumps(args, ensure_ascii=False)}}]}
    return {"role": "assistant", "content": text if text is not None else "[no text]"}


def follow_up_message(config: AgentConfig, frame: str, *, step: int, as_tool: bool) -> dict:
    if config.action_mode == "native" and as_tool:
        return {"role": "tool", "tool_call_id": f"call_{step}", "content": frame}
    return {"role": "user", "content": frame}


class History:
    def __init__(self, config: AgentConfig, system_prompt: str, instruction_msg: str) -> None:
        self._config = config
        self._system = {"role": "system", "content": system_prompt}
        self._instruction = instruction_msg
        self._turns: list[tuple[dict, dict]] = []

    def add_turn(self, assistant: dict, follow_up: dict) -> None:
        """A turn is added atomically so tool messages never lose their assistant call."""
        self._turns.append((assistant, follow_up))

    def _assemble(self, turns: list[tuple[dict, dict]], dropped: int) -> list[dict]:
        content = self._instruction
        if dropped:
            content += f"\n[[AIRLOCK]] {dropped} earlier steps were omitted to save space."
        messages = [dict(self._system), {"role": "user", "content": content}]
        for assistant, follow_up in turns:
            messages.append(dict(assistant))
            messages.append(dict(follow_up))
        return messages

    def render(self) -> tuple[dict, ...]:
        turns = list(self._turns)
        dropped = 0
        while True:
            messages = self._assemble(turns, dropped)
            if len(turns) <= 1:
                break
            if (len(turns) > self._config.history_max_turns
                    or history_chars(messages) > self._config.context_max_chars):
                turns.pop(0)
                dropped += 1
                continue
            break
        return tuple(messages)

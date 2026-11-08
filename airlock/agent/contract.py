"""Public data contract of the agent loop: config, outcome, client and budget protocols."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Literal, Protocol

from airlock.sandbox import DestroyProof, DiffResult, Limits

END_REASONS: tuple[str, ...] = ("agent_finished", "step_limit", "wall_timeout",
                                "inference_error", "sandbox_error", "internal_error")

INSTRUCTION_MAX_CHARS = 2000
FINISH_SUMMARY_MAX_CHARS = 2000


def _check_int(name: str, value: object, low: int, high: int) -> None:
    # bool is a subclass of int; it is never a valid number here.
    if type(value) is not int or not (low <= value <= high):
        raise ValueError(f"invalid {name}")


@dataclass(frozen=True)
class AgentConfig:
    action_mode: Literal["native", "text"] = "text"
    max_steps: int = 25                       # 1..100
    wall_clock_s: float = 300.0               # 0.05..3600
    max_tokens: int = 1024                    # 16..32768, sent as max_tokens on every call
    tool_output_model_max_bytes: int = 8192   # 256..65536, UTF-8 bytes of tool output shown to the model
    assistant_history_max_chars: int = 8000   # 256..65536, assistant text kept in history
    history_max_turns: int = 12               # 1..100
    context_max_chars: int = 120_000          # 4096..1_000_000
    limits: Limits = field(default_factory=Limits)
    image: str = "airlock-sandbox:dev"
    runtime: str = "runsc"

    def __post_init__(self) -> None:
        """Raise ValueError on any out-of-range value or wrong type (bool is not int)."""
        if self.action_mode not in ("native", "text"):
            raise ValueError("invalid action_mode")
        _check_int("max_steps", self.max_steps, 1, 100)
        if type(self.wall_clock_s) not in (int, float) or not (0.05 <= self.wall_clock_s <= 3600):
            raise ValueError("invalid wall_clock_s")
        _check_int("max_tokens", self.max_tokens, 16, 32768)
        _check_int("tool_output_model_max_bytes", self.tool_output_model_max_bytes, 256, 65536)
        _check_int("assistant_history_max_chars", self.assistant_history_max_chars, 256, 65536)
        _check_int("history_max_turns", self.history_max_turns, 1, 100)
        _check_int("context_max_chars", self.context_max_chars, 4096, 1_000_000)
        if not isinstance(self.limits, Limits):
            raise ValueError("invalid limits")
        if not isinstance(self.image, str) or not self.image:
            raise ValueError("invalid image")
        if not isinstance(self.runtime, str) or not self.runtime:
            raise ValueError("invalid runtime")


@dataclass(frozen=True)
class TaskOutcome:
    reason: str                       # one of END_REASONS or a validated budget cancel string
    steps_used: int
    tokens_in: int
    tokens_out: int
    diff: DiffResult | None
    destroy_proof: DestroyProof | None    # None iff no sandbox was created
    peak: dict                        # {"memory_bytes", "pids", "cpu_ms"}: int | None each
    summary: str | None               # finish summary iff reason == "agent_finished"


@dataclass(frozen=True)
class ChatRequest:
    messages: tuple[dict, ...]        # OpenAI chat messages, JSON-serialisable
    tools: tuple[dict, ...] | None    # TOOL_SPECS in native mode, None in text mode
    max_tokens: int


@dataclass(frozen=True)
class RawToolCall:
    name: str
    arguments: str                    # raw JSON text from the provider


@dataclass(frozen=True)
class ChatResponse:
    content: str | None
    tool_calls: tuple[RawToolCall, ...]
    prompt_tokens: int | None         # None when missing or invalid
    completion_tokens: int | None
    uncertain_attempts: int           # earlier failed attempts in this call that may have been billed


class InferenceError(Exception):
    """Fixed text only: str() == repr() == f"inference error: {kind}". Never chains a cause."""
    KINDS = frozenset({"timeout", "deadline", "connection", "http_429", "http_5xx",
                       "http_status", "oversize", "bad_response", "credential"})

    def __init__(self, kind: str, *, status: int | None = None,
                 uncertain_attempts: int = 0) -> None:
        if kind not in self.KINDS:
            raise ValueError("invalid inference error kind")
        super().__init__(f"inference error: {kind}")
        self.kind = kind
        self.status = status
        self.uncertain_attempts = uncertain_attempts

    def __str__(self) -> str:
        return f"inference error: {self.kind}"

    def __repr__(self) -> str:
        return f"inference error: {self.kind}"


class ChatClient(Protocol):
    max_attempts: int                 # 1..10: attempts complete() may make per call

    def complete(self, request: ChatRequest, *, deadline: float) -> ChatResponse:
        """deadline is a time.monotonic() value. Raise InferenceError for every provider failure."""
        ...


class Budget(Protocol):
    def charge(self, tokens_in: int, tokens_out: int) -> str | None: ...

    def should_stop(self) -> str | None: ...


def prompt_chars(request: ChatRequest) -> int:
    """Size of the serialised prompt; used only for the conservative token charge."""
    return len(json.dumps({"messages": list(request.messages), "tools": list(request.tools or ())},
                          ensure_ascii=False, separators=(",", ":")))

"""The agent loop: one task, one sandbox, bounded in steps, time, tokens and events."""
from __future__ import annotations

import logging
import math
import pathlib
import re
import secrets
import threading
import time
from collections.abc import Callable

from airlock.sandbox import DestroyProof, DiffResult, Sandbox, SandboxError, ToolResult

from . import events
from .contract import (END_REASONS, FINISH_SUMMARY_MAX_CHARS, INSTRUCTION_MAX_CHARS, AgentConfig,
                       Budget, ChatClient, ChatRequest, ChatResponse, TaskOutcome, prompt_chars)
from .events import Emitter, _EmitFailed
from .history import History, assistant_message, follow_up_message
from .parse import Action, Rejected, parse_native_reply, parse_text_reply
from .prompt import (OFFERED_TOOLS, REJ_BAD_FINISH, SYSTEM_PROMPT_NATIVE, SYSTEM_PROMPT_TEXT,
                     TOOL_SPECS, frame_instruction, frame_rejection, frame_tool_result)
from .contract import InferenceError

_log = logging.getLogger("airlock.agent")

# M1's fixed runner texts that mean "the sandbox is gone"; pinned against runner.py by a test.
SANDBOX_FATAL_OUTPUTS = frozenset({"sandbox not running", "sandbox destroyed",
                                   "docker unavailable", "internal error", "sandbox busy"})

_CANCEL_RE = re.compile(r"[a-z][a-z0-9_]{0,62}")
_PEAK_KEYS = ("memory_bytes", "pids", "cpu_ms")
_MAX_UNCERTAIN = 10


class _BadHook(Exception):
    """A budget hook returned something that is not a valid cancel reason."""


class _ClientCrashed(Exception):
    """The client raised something other than InferenceError, or returned a bad object."""


def _check_cancel(value: object) -> str:
    if type(value) is str and _CANCEL_RE.fullmatch(value) and value not in END_REASONS:
        return value
    raise _BadHook("invalid budget reason")


def _is_fatal(r: ToolResult) -> bool:
    return (r.ok is False and r.exit_code is None and r.blocked_reason is None
            and r.limit_hit is None and r.duration_ms == 0 and r.output in SANDBOX_FATAL_OUTPUTS)


def _merge_peak(old: dict, new: object) -> dict:
    out: dict = {}
    for key in _PEAK_KEYS:
        a = old.get(key)
        b = new.get(key) if isinstance(new, dict) else None
        a = a if type(a) is int else None
        b = b if type(b) is int else None
        if a is None:
            out[key] = b
        elif b is None:
            out[key] = a
        else:
            out[key] = max(a, b)
    return out


def _validate_finish(args: dict) -> str | None:
    if set(args) != {"summary"}:
        return None
    summary = args["summary"]
    if not isinstance(summary, str) or len(summary) > FINISH_SUMMARY_MAX_CHARS:
        return None
    return summary


def _pick(value: object, fallback: int) -> int:
    return value if type(value) is int and value >= 1 else fallback


def _validate_args(instruction: object, sample_repo: object, client: object, config: object,
                   sink: object, budget: object, sandbox_factory: object) -> None:
    if not isinstance(instruction, str):
        raise TypeError("instruction must be a str")
    if not instruction or len(instruction) > INSTRUCTION_MAX_CHARS:
        raise ValueError("instruction length out of range")
    if "\x00" in instruction:
        raise ValueError("instruction contains NUL")
    try:
        instruction.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("instruction is not valid UTF-8 text") from None
    if not isinstance(sample_repo, pathlib.Path):
        raise TypeError("sample_repo must be a pathlib.Path")
    if not isinstance(config, AgentConfig):
        raise TypeError("config must be an AgentConfig")
    if not callable(getattr(client, "complete", None)):
        raise TypeError("client must have a callable complete")
    attempts = getattr(client, "max_attempts", None)
    if type(attempts) is not int:
        raise TypeError("client.max_attempts must be an int")
    if not 1 <= attempts <= 10:
        raise ValueError("client.max_attempts out of range")
    if not callable(sink):
        raise TypeError("sink must be callable")
    if not callable(getattr(budget, "charge", None)) or not callable(getattr(budget, "should_stop", None)):
        raise TypeError("budget must have callable charge and should_stop")
    if not callable(sandbox_factory):
        raise TypeError("sandbox_factory must be callable")


class _Run:
    def __init__(self, instruction: str, sample_repo: pathlib.Path, client: ChatClient,
                 config: AgentConfig, sink: Callable[[dict], None], budget: Budget,
                 factory: Callable[..., Sandbox]) -> None:
        self.instruction = instruction
        self.sample_repo = sample_repo
        self.client = client
        self.cfg = config
        self.budget = budget
        self.factory = factory
        self.deadline = time.monotonic() + config.wall_clock_s
        self.tag = secrets.token_hex(8)
        self.emitter = Emitter(sink)
        self.reason: str | None = None
        self.steps_used = 0
        self.tok_in = 0
        self.tok_out = 0
        self.peak: dict = {k: None for k in _PEAK_KEYS}
        self.summary: str | None = None
        self.sandbox: Sandbox | None = None
        self.diff: DiffResult | None = None
        self.proof: DestroyProof | None = None
        native = config.action_mode == "native"
        self.tools = TOOL_SPECS if native else None
        self.history = History(config, SYSTEM_PROMPT_NATIVE if native else SYSTEM_PROMPT_TEXT,
                               frame_instruction(instruction))

    # ------------------------------------------------------------------ helpers

    def _emit(self, event: dict) -> None:
        self.emitter.emit(event)

    def _guard(self, fn: Callable[[], None]) -> None:
        """Cleanup step: a failure marks internal_error but never skips the next step."""
        try:
            fn()
        except Exception:
            self.reason = "internal_error"

    def _charge(self, tokens_in: int, tokens_out: int) -> object:
        # Account first: the tokens are spent even if the hook raises.
        self.tok_in += tokens_in
        self.tok_out += tokens_out
        result = self.budget.charge(tokens_in, tokens_out)
        return result

    def _add_turn(self, step: int, content: str | None, action: Action | None,
                  frame: str) -> None:
        assistant = assistant_message(self.cfg, content, action, step)
        follow = follow_up_message(self.cfg, frame, step=step, as_tool=action is not None)
        self.history.add_turn(assistant, follow)

    # ------------------------------------------------------------------ body

    def body(self) -> None:
        cfg = self.cfg
        try:
            self.sandbox = self.factory(self.sample_repo, limits=cfg.limits, image=cfg.image,
                                        runtime=cfg.runtime)
        except SandboxError:
            self.reason = "sandbox_error"
            _log.info("sandbox creation failed")
            return
        self._emit(events.sandbox_created(cfg.limits))
        while self.reason is None:
            stop = self.budget.should_stop()
            if stop is not None:
                self.reason = _check_cancel(stop)
                self._emit(events.budget_stop(self.steps_used, self.reason, "should_stop"))
                return
            if time.monotonic() >= self.deadline:
                self.reason = "wall_timeout"
                return
            if self.steps_used >= cfg.max_steps:
                self.reason = "step_limit"
                return
            self._step()

    def _step(self) -> None:
        cfg = self.cfg
        step = self.steps_used + 1
        request = ChatRequest(self.history.render(), self.tools, cfg.max_tokens)
        bound_in = math.ceil(prompt_chars(request) / 2)
        slot: dict = {}
        done = threading.Event()
        client = self.client
        deadline = self.deadline

        def work() -> None:
            try:
                slot["response"] = client.complete(request, deadline=deadline)
            except BaseException as exc:  # stored for the loop thread; never raised here
                slot["error"] = exc
            finally:
                done.set()

        started = time.monotonic()
        threading.Thread(target=work, name="airlock-llm", daemon=True).start()
        finished = done.wait(max(0.0, self.deadline - time.monotonic()))
        duration_ms = int((time.monotonic() - started) * 1000)

        if not finished:
            # Abandoned: the slot is never read again, so a late result cannot affect the task.
            attempts = self.client.max_attempts
            tin, tout = bound_in * attempts, cfg.max_tokens * attempts
            result = self._charge(tin, tout)
            if result is not None:
                _check_cancel(result)
            self._emit(events.llm_call(step, "abandoned", tin, tout, False, None, "", duration_ms))
            self.reason = "wall_timeout"
            _log.info("step=%d tool=%s outcome=%s", step, "-", "abandoned")
            return

        error = slot.get("error")
        if error is not None:
            if isinstance(error, InferenceError):
                uncertain = max(0, min(int(error.uncertain_attempts), _MAX_UNCERTAIN))
                tin, tout = bound_in * uncertain, cfg.max_tokens * uncertain
                if uncertain:
                    result = self._charge(tin, tout)
                    if result is not None:
                        _check_cancel(result)
                self._emit(events.llm_call(step, "error", tin, tout, False, error.kind, "",
                                           duration_ms))
                self.reason = "inference_error"
                _log.info("step=%d tool=%s outcome=%s", step, "-", error.kind)
                return
            self._emit(events.llm_call(step, "error", 0, 0, False, "internal", "", duration_ms))
            raise _ClientCrashed("client failed")

        response = slot.get("response")
        if (not isinstance(response, ChatResponse)
                or not (response.content is None or isinstance(response.content, str))
                or not isinstance(response.tool_calls, tuple)):
            raise _ClientCrashed("client returned a bad object")

        uncertain = 0
        if type(response.uncertain_attempts) is int:
            uncertain = max(0, min(response.uncertain_attempts, _MAX_UNCERTAIN))
        tin = _pick(response.prompt_tokens, bound_in) + bound_in * uncertain
        tout = _pick(response.completion_tokens, cfg.max_tokens) + cfg.max_tokens * uncertain
        usage_reported = (_pick(response.prompt_tokens, 0) > 0
                          and _pick(response.completion_tokens, 0) > 0)
        self.steps_used += 1
        cancel = self._charge(tin, tout)
        self._emit(events.llm_call(step, "ok", tin, tout, usage_reported, None,
                                   response.content or "", duration_ms))
        if cancel is not None:
            self.reason = _check_cancel(cancel)
            self._emit(events.budget_stop(step, self.reason, "charge"))
            return  # the action in this reply is deliberately not executed

        if cfg.action_mode == "text":
            parsed = parse_text_reply(response.content)
        else:
            parsed = parse_native_reply(response.content, response.tool_calls)
        self._handle(step, response.content, parsed)

    def _handle(self, step: int, content: str | None, parsed: Action | Rejected) -> None:
        if isinstance(parsed, Rejected):
            self._emit(events.action_blocked(step, None, parsed.reason, "agent_loop"))
            self._add_turn(step, content, None, frame_rejection(parsed.message))
            _log.info("step=%d tool=%s outcome=%s", step, "-", parsed.reason)
            return
        action = parsed
        tool = action.tool if action.tool in OFFERED_TOOLS else "unknown"
        self._emit(events.tool_call(step, tool, action.args))

        if action.tool == "finish":
            summary = _validate_finish(action.args)
            if summary is not None:
                self.summary = summary
                self.reason = "agent_finished"
                _log.info("step=%d tool=%s outcome=%s", step, "finish", "finished")
                return
            self._emit(events.action_blocked(step, "finish", "bad_finish_args", "agent_loop"))
            self._add_turn(step, content, action, frame_rejection(REJ_BAD_FINISH))
            _log.info("step=%d tool=%s outcome=%s", step, "finish", "bad_finish_args")
            return

        assert self.sandbox is not None
        result = self.sandbox.call(action.tool, dict(action.args))
        if not isinstance(result, ToolResult):
            raise TypeError("sandbox returned a bad result")
        if _is_fatal(result):
            self._emit(events.tool_result(step, tool, result))
            self.reason = "sandbox_error"
            _log.info("step=%d tool=%s outcome=%s", step, tool, "sandbox_error")
            return
        if result.blocked_reason is not None:
            self._emit(events.action_blocked(step, tool, result.blocked_reason, "sandbox"))
        else:
            self._emit(events.tool_result(step, tool, result))
        if action.tool == "run_command" and result.blocked_reason is None:
            self.peak = _merge_peak(self.peak, self.sandbox.resource_peak())
        frame = frame_tool_result(self.tag, tool, result, self.cfg.tool_output_model_max_bytes)
        self._add_turn(step, content, action, frame)
        _log.info("step=%d tool=%s outcome=%s", step, tool,
                  "blocked" if result.blocked_reason is not None else "ok")

    # ------------------------------------------------------------------ cleanup

    def cleanup(self) -> None:
        sandbox = self.sandbox
        if sandbox is None:
            return
        self._guard(lambda: self._emit(events.resource_peak(self.peak)))
        self._guard(lambda: self._collect(sandbox))
        self._guard(lambda: self._destroy(sandbox))

    def _collect(self, sandbox: Sandbox) -> None:
        if self.reason == "sandbox_error":
            return
        try:
            diff = sandbox.collect_diff()
        except SandboxError:
            self.diff = None
            self._emit(events.artifact_collected(None))
            return
        self.diff = diff
        self._emit(events.artifact_collected(diff))

    def _destroy(self, sandbox: Sandbox) -> None:
        try:
            proof = sandbox.destroy()
        except Exception:
            self.proof = DestroyProof("unknown", False, "internal_error")
            self.reason = "internal_error"
            self._emit(events.sandbox_destroy_failed(self.proof))
            return
        self.proof = proof
        if proof.verified:
            self._emit(events.sandbox_destroyed(proof))
        else:
            self._emit(events.sandbox_destroy_failed(proof))

    def finish_task(self) -> TaskOutcome:
        if self.reason is None:
            self.reason = "internal_error"
        reason = self.reason
        summary = self.summary if reason == "agent_finished" else None
        self._guard(lambda: self._emit(events.task_finished(
            reason, self.steps_used, self.tok_in, self.tok_out, summary)))
        # A failed final emit flips the reason; the outcome reflects the final value.
        reason = self.reason
        summary = self.summary if reason == "agent_finished" else None
        _log.info("reason=%s steps=%d", reason, self.steps_used)
        return TaskOutcome(reason=reason, steps_used=self.steps_used, tokens_in=self.tok_in,
                           tokens_out=self.tok_out, diff=self.diff, destroy_proof=self.proof,
                           peak=dict(self.peak), summary=summary)


def run_task(instruction: str, sample_repo: pathlib.Path, *, client: ChatClient,
             config: AgentConfig, sink: Callable[[dict], None], budget: Budget,
             sandbox_factory: Callable[..., Sandbox] = Sandbox.create) -> TaskOutcome:
    """Run one task; never raises after argument validation (except BaseException
    non-Exception, re-raised after cleanup).

    Raises TypeError/ValueError before any side effect when the arguments are invalid:
    instruction is not str, is empty, has more than 2000 chars, contains NUL, or is not encodable as
    strict UTF-8; sample_repo is not a pathlib.Path; config is not an AgentConfig; client lacks a
    callable complete or an int max_attempts in 1..10; sink is not callable; budget lacks
    callable charge/should_stop; sandbox_factory is not callable.
    The factory is called as sandbox_factory(sample_repo, limits=config.limits,
    image=config.image, runtime=config.runtime).
    An LLM call abandoned at the wall-clock deadline is charged
    client.max_attempts x (ceil(prompt_chars/2), max_tokens).
    """
    _validate_args(instruction, sample_repo, client, config, sink, budget, sandbox_factory)
    run = _Run(instruction, sample_repo, client, config, sink, budget, sandbox_factory)
    try:
        try:
            run.body()
        except Exception:
            # Bookkeeping can no longer be trusted: override any earlier reason. No text kept.
            run.reason = "internal_error"
            _log.error("internal error in agent loop")
    finally:
        run.cleanup()
        outcome = run.finish_task()
    return outcome

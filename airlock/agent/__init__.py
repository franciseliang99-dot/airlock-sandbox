"""Airlock M2: drives one LLM agent against one sandbox for one task."""
import logging

from .contract import (AgentConfig, Budget, ChatClient, ChatRequest, ChatResponse,
                       END_REASONS, InferenceError, RawToolCall, TaskOutcome)
from .client import OpenAICompatClient
from .loop import run_task

logging.getLogger("airlock.agent").addHandler(logging.NullHandler())

__all__ = ["AgentConfig", "Budget", "ChatClient", "ChatRequest", "ChatResponse", "END_REASONS",
           "InferenceError", "OpenAICompatClient", "RawToolCall", "TaskOutcome", "run_task"]

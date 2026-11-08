"""Sandbox runner: the only component that talks to Docker."""
import logging

from .runner import DestroyProof, DiffResult, Limits, Sandbox, SandboxError, ToolResult

logging.getLogger("airlock.sandbox").addHandler(logging.NullHandler())

__all__ = ["DestroyProof", "DiffResult", "Limits", "Sandbox", "SandboxError", "ToolResult"]

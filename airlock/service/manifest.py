"""Bundled sample repositories and presets: loader, validation and the public view."""
from __future__ import annotations

import json
import pathlib
import re
from dataclasses import dataclass

from airlock.agent.contract import INSTRUCTION_MAX_CHARS

ID_RE = r"[a-z0-9][a-z0-9-]{0,39}"
_TITLE_MAX = 80
_DESCRIPTION_MAX = 500
_MAX_SAMPLES = 20
_MAX_PRESETS = 20


class ManifestError(Exception):
    """Fixed text naming the failed rule; never echoes manifest values."""


@dataclass(frozen=True)
class Preset:
    id: str
    title: str
    description: str
    instruction: str


@dataclass(frozen=True)
class Sample:
    id: str
    title: str
    description: str
    path: pathlib.Path                 # resolved, an existing directory inside the manifest's directory
    presets: tuple[Preset, ...]


@dataclass(frozen=True)
class Manifest:
    samples: tuple[Sample, ...]

    def get_sample(self, sample_id: str) -> Sample | None:
        for sample in self.samples:
            if sample.id == sample_id:
                return sample
        return None

    def public_view(self) -> dict:
        """No filesystem paths are ever exposed."""
        return {"samples": [
            {"id": s.id, "title": s.title, "description": s.description,
             "presets": [{"id": p.id, "title": p.title, "description": p.description,
                          "instruction": p.instruction} for p in s.presets]}
            for s in self.samples]}


def validate_instruction(value: object) -> str:
    """M2's rules: str; 1..INSTRUCTION_MAX_CHARS code points; no NUL; strict UTF-8 encodable
    (rejects lone surrogates). ValueError("invalid instruction") otherwise."""
    if not isinstance(value, str):
        raise ValueError("invalid instruction")
    if not 1 <= len(value) <= INSTRUCTION_MAX_CHARS or "\x00" in value:
        raise ValueError("invalid instruction")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("invalid instruction") from None
    return value


class _DuplicateKey(Exception):
    pass


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise _DuplicateKey()
        out[key] = value
    return out


def _reject_constant(name: str) -> object:
    raise ValueError("non-finite number")


def _obj(value: object, required: set[str], optional: set[str], what: str) -> dict:
    if not isinstance(value, dict):
        raise ManifestError(f"{what} must be an object")
    keys = set(value)
    if not required <= keys or not keys <= required | optional:
        raise ManifestError(f"{what} has missing or unknown keys")
    return value


def _text(value: object, what: str, max_chars: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= max_chars or "\x00" in value:
        raise ManifestError(f"{what} is invalid")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ManifestError(f"{what} is invalid") from None
    return value


def _ident(value: object, what: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(ID_RE, value):
        raise ManifestError(f"{what} is invalid")
    return value


def _load_preset(raw: object) -> Preset:
    item = _obj(raw, {"id", "title", "description", "instruction"}, set(), "preset")
    try:
        instruction = validate_instruction(item["instruction"])
    except ValueError:
        raise ManifestError("preset instruction is invalid") from None
    return Preset(id=_ident(item["id"], "preset id"),
                  title=_text(item["title"], "preset title", _TITLE_MAX),
                  description=_text(item["description"], "preset description", _DESCRIPTION_MAX),
                  instruction=instruction)


def _resolve_sample_dir(base: pathlib.Path, rel: str) -> pathlib.Path:
    pure = pathlib.PurePosixPath(rel)
    if pure.is_absolute() or ".." in pure.parts:
        raise ManifestError("sample path must be relative without '..'")
    candidate = base / rel
    if candidate.is_symlink():
        raise ManifestError("sample path must not be a symlink")
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ManifestError("sample path does not exist") from None
    if not resolved.is_relative_to(base) or resolved == base:
        raise ManifestError("sample path escapes the manifest directory")
    if not resolved.is_dir():
        raise ManifestError("sample path is not a directory")
    return resolved


def load_manifest(path: pathlib.Path) -> Manifest:
    path = pathlib.Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise ManifestError("manifest is unreadable") from None
    try:
        doc = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    except _DuplicateKey:
        raise ManifestError("manifest has a duplicate key") from None
    except (ValueError, RecursionError):
        raise ManifestError("manifest is not valid JSON") from None
    root = _obj(doc, {"version", "samples"}, set(), "manifest")
    if type(root["version"]) is not int or root["version"] != 1:
        raise ManifestError("unsupported manifest version")
    raw_samples = root["samples"]
    if not isinstance(raw_samples, list) or not 1 <= len(raw_samples) <= _MAX_SAMPLES:
        raise ManifestError("manifest needs 1..20 samples")
    base = path.resolve().parent

    samples: list[Sample] = []
    seen: set[str] = set()
    for raw in raw_samples:
        item = _obj(raw, {"id", "title", "description", "path", "presets"}, set(), "sample")
        sample_id = _ident(item["id"], "sample id")
        if sample_id in seen:
            raise ManifestError("duplicate sample id")
        seen.add(sample_id)
        raw_presets = item["presets"]
        if not isinstance(raw_presets, list) or len(raw_presets) > _MAX_PRESETS:
            raise ManifestError("a sample needs 0..20 presets")
        presets = tuple(_load_preset(p) for p in raw_presets)
        if len({p.id for p in presets}) != len(presets):
            raise ManifestError("duplicate preset id")
        rel = _text(item["path"], "sample path", 255)
        samples.append(Sample(
            id=sample_id, title=_text(item["title"], "sample title", _TITLE_MAX),
            description=_text(item["description"], "sample description", _DESCRIPTION_MAX),
            path=_resolve_sample_dir(base, rel), presets=presets))
    return Manifest(samples=tuple(samples))

"""Pure parsers for `git diff -z` output."""
from __future__ import annotations

CHANGE_BY_STATUS = {"A": "added", "M": "modified", "D": "deleted", "T": "type_changed"}


def _split_z(data: bytes) -> list[bytes]:
    if not data:
        return []
    parts = data.split(b"\0")
    if parts[-1] != b"":
        raise ValueError("unterminated record")
    return parts[:-1]


def parse_raw_z(data: bytes) -> dict[str, str]:
    """Parse `git diff --raw -z --no-renames` into {path: change}."""
    tokens = _split_z(data)
    if len(tokens) % 2:
        raise ValueError("odd token count")
    out: dict[str, str] = {}
    for i in range(0, len(tokens), 2):
        meta, path = tokens[i], tokens[i + 1]
        if not meta.startswith(b":") or not path:
            raise ValueError("malformed raw record")
        fields = meta[1:].split(b" ")
        if len(fields) != 5:
            raise ValueError("malformed raw record")
        change = CHANGE_BY_STATUS.get(fields[4].decode("ascii", "replace"))
        if change is None:
            raise ValueError("unknown status")
        out[path.decode("utf-8", "replace")] = change
    return out


def _count(token: bytes) -> int | None:
    if token == b"-":
        return None
    if not token.isdigit():
        raise ValueError("bad count")
    return int(token)


def parse_numstat_z(data: bytes) -> dict[str, tuple[int | None, int | None]]:
    """Parse `git diff --numstat -z --no-renames` into {path: (added, removed)}."""
    out: dict[str, tuple[int | None, int | None]] = {}
    for token in _split_z(data):
        parts = token.split(b"\t", 2)
        if len(parts) != 3 or not parts[2]:
            raise ValueError("malformed numstat record")
        out[parts[2].decode("utf-8", "replace")] = (_count(parts[0]), _count(parts[1]))
    return out


def build_files(raw: dict[str, str],
                numstat: dict[str, tuple[int | None, int | None]]) -> list[dict]:
    """Combine both parses into the sorted file list; binary files get None counts."""
    files: list[dict] = []
    for path in sorted(raw):
        added, removed = numstat.get(path, (None, None))
        files.append({"path": path, "change": raw[path],
                      "lines_added": added, "lines_removed": removed})
    return files

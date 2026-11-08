"""Builds the seed archive from the bundled sample repository.

This is the only module that touches the host filesystem, and only below the given root.
"""
from __future__ import annotations

import io
import os
import pathlib
import stat
import tarfile
from typing import Literal

from . import _consts


class SeedError(Exception):
    """Refusal to seed. `kind` is a fixed token; the message never contains paths."""

    def __init__(self, kind: Literal["not_a_directory", "symlink", "special_file", "bad_name",
                                     "git_dir", "too_large", "too_many"]) -> None:
        super().__init__(kind)
        self.kind = kind


def check_arcname(name: str) -> None:
    """Reject archive member names that are empty, absolute, escaping or inside .git."""
    if not name or name.startswith("/") or "\x00" in name or "\\" in name:
        raise SeedError("bad_name")
    parts = name.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise SeedError("bad_name")
    if parts[0] == ".git":
        raise SeedError("git_dir")


class _State:
    def __init__(self) -> None:
        self.entries = 0
        self.total = 0


def _read_regular(path: str, state: _State) -> tuple[bytes, int]:
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise SeedError("special_file") from None
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise SeedError("special_file")
        budget = _consts.SEED_MAX_TOTAL_BYTES - state.total
        data = handle.read(budget + 1)
    if len(data) > budget:
        raise SeedError("too_large")
    state.total += len(data)
    return data, info.st_mode


def _add_dir(tf: tarfile.TarFile, dir_path: str, prefix: str, state: _State) -> None:
    with os.scandir(dir_path) as it:
        entries = sorted(it, key=lambda e: e.name)
    for entry in entries:
        arc = prefix + entry.name
        check_arcname(arc)
        state.entries += 1
        if state.entries > _consts.SEED_MAX_ENTRIES:
            raise SeedError("too_many")
        info = entry.stat(follow_symlinks=False)
        mode = info.st_mode
        full = os.path.join(dir_path, entry.name)
        member = tarfile.TarInfo(arc)
        member.uid = member.gid = 1000
        member.uname = member.gname = "agent"
        member.mtime = 0
        if stat.S_ISLNK(mode):
            raise SeedError("symlink")
        if stat.S_ISDIR(mode):
            member.type = tarfile.DIRTYPE
            member.mode = 0o755
            tf.addfile(member)
            _add_dir(tf, full, arc + "/", state)
        elif stat.S_ISREG(mode):
            data, real_mode = _read_regular(full, state)
            member.type = tarfile.REGTYPE
            member.mode = 0o755 if real_mode & 0o111 else 0o644
            member.size = len(data)
            tf.addfile(member, io.BytesIO(data))
        else:
            raise SeedError("special_file")


def build_seed_tar(root: pathlib.Path) -> bytes:
    """Return a USTAR archive of `root` (regular files and directories only)."""
    root_str = os.fspath(root)
    try:
        info = os.lstat(root_str)
    except OSError:
        raise SeedError("not_a_directory") from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise SeedError("not_a_directory")
    state = _State()
    buf = io.BytesIO()
    try:
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
            _add_dir(tf, root_str, "", state)
    except RecursionError:
        raise SeedError("too_many") from None
    except (ValueError, tarfile.TarError):
        raise SeedError("bad_name") from None
    return buf.getvalue()

"""In-memory per-client rate limiting and trusted-proxy client identification."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
import threading
import time
from collections.abc import Callable
from typing import Literal


class RateLimiter:
    """Fixed hourly windows keyed by an HMAC of the client key under a per-process random salt.
    Raw client keys are never stored; the table lives in memory only."""

    MAX_KEYS: int = 100_000

    def __init__(self, *, clock_s: Callable[[], float] = time.time, salt: bytes | None = None,
                 max_keys: int = MAX_KEYS) -> None:
        self._clock_s = clock_s
        self._salt = salt if salt is not None else secrets.token_bytes(32)
        self._max_keys = max_keys
        self._lock = threading.Lock()
        self._hour: int | None = None
        self._counts: dict[tuple[str, bytes], int] = {}

    def allow(self, bucket: Literal["sessions", "tasks"], client: str, limit_per_hour: int) -> bool:
        """Count one attempt. True while the hourly count is below the limit. A new key when the
        table is full is denied (fail closed). Entries of earlier hours are dropped on rollover."""
        hour = int(self._clock_s() // 3600)
        digest = hmac.new(self._salt, client.encode("utf-8"), hashlib.sha256).digest()[:16]
        key = (bucket, digest)
        with self._lock:
            if hour != self._hour:
                self._counts.clear()
                self._hour = hour
            count = self._counts.get(key)
            if count is None:
                if len(self._counts) >= self._max_keys:
                    return False
                count = 0
            if count >= limit_per_hour:
                return False
            self._counts[key] = count + 1
            return True


def _parse_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        addr = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _normalize(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if isinstance(addr, ipaddress.IPv6Address):
        return str(ipaddress.IPv6Address((int(addr) >> 64) << 64))       # its /64 network address
    return str(addr)


def client_key(peer: str, header_value: str | None, header_enabled: bool) -> str:
    """The proxy header is honoured only when the TCP peer is loopback; the RIGHTMOST entry is
    used (correct whether the proxy appends or replaces). Never logged."""
    peer_addr = _parse_ip(peer)
    if peer_addr is None:
        return "invalid"
    if header_enabled and header_value is not None and peer_addr.is_loopback:
        addr = _parse_ip(header_value.rsplit(",", 1)[-1])
        if addr is None:
            return "invalid"
        return _normalize(addr)
    return _normalize(peer_addr)

"""Time sources and UTC day helpers. All persisted times are UTC epoch milliseconds."""
from __future__ import annotations

import datetime as _dt
import time
from typing import Protocol

_EPOCH = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)


class Clock(Protocol):
    def now_ms(self) -> int: ...          # UTC epoch milliseconds

    def monotonic(self) -> float: ...     # time.monotonic() domain


class SystemClock:
    def now_ms(self) -> int:
        return int(time.time() * 1000)

    def monotonic(self) -> float:
        return time.monotonic()


def _to_datetime(epoch_ms: int) -> _dt.datetime:
    return _EPOCH + _dt.timedelta(milliseconds=epoch_ms)


def utc_day(now_ms: int) -> str:
    """'YYYY-MM-DD' in UTC."""
    return _to_datetime(now_ms).strftime("%Y-%m-%d")


def iso_ms(epoch_ms: int) -> str:
    """'2026-11-03T12:00:00.000Z'."""
    moment = _to_datetime(epoch_ms)
    return moment.strftime("%Y-%m-%dT%H:%M:%S") + ".%03dZ" % (moment.microsecond // 1000)


def seconds_to_next_utc_midnight(now_ms: int) -> int:
    """Whole seconds until the next UTC midnight; always >= 1."""
    return 86_400 - (now_ms // 1000) % 86_400

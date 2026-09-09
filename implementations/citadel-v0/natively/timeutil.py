"""RFC 3339 UTC timestamps at second precision, e.g. 2026-09-07T07:00:00Z."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from .errors import VerifyError


def now_utc() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def fmt(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError("naive datetime")
    return dt.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse(s: str, field: str = "ts") -> datetime:
    if not isinstance(s, str) or not s.endswith("Z"):
        raise VerifyError(f"{field}.format", f"expected RFC 3339 UTC 'Z' timestamp, got {s!r}")
    try:
        return datetime.fromisoformat(s)
    except ValueError as e:
        raise VerifyError(f"{field}.format", str(e)) from e


def plus(dt: datetime, seconds: int) -> datetime:
    return dt + timedelta(seconds=seconds)

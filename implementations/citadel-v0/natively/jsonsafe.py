"""Bounded, JCS-agreeing JSON parsing for everything that arrives from a peer.

  - duplicate member names are rejected (RFC 8785 requires unique names; Python's
    default keeps the last value, so a signed object could carry a second `to`);
  - integer literals beyond 2^53 are rejected at parse time, so parsing and
    canonicalization (which refuses them) agree;
  - NaN / Infinity literals are rejected, and so is a number literal that overflows
    to infinity (1e999): canonicalization refuses non-finite values, so parsing must
    refuse them too (otherwise a signed body fails at hashing instead of verification);
  - nesting depth is bounded (32) after the parse, and the interpreter's own
    RecursionError on a hostile document becomes a VerifyError;
  - the text size is bounded before the parse.

Every failure is a VerifyError with reason `<what>.json` so the caller ledgers it."""

from __future__ import annotations

import json
import math
from typing import Any

from .errors import VerifyError

MAX_DEPTH = 32
_MAX_SAFE = 2**53


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate member name {k!r}")
        out[k] = v
    return out


def _bounded_int(s: str) -> int:
    v = int(s)
    if abs(v) > _MAX_SAFE:
        raise ValueError(f"integer {s} exceeds 2^53")
    return v


def _finite_float(s: str) -> float:
    v = float(s)
    if not math.isfinite(v):
        raise ValueError(f"number {s} is not finite")
    return v


def _no_constants(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def check_depth(v: Any, what: str, limit: int = MAX_DEPTH) -> None:
    """Iterative nesting check (no recursion, so a deep document cannot hurt us)."""
    stack: list[tuple[Any, int]] = [(v, 1)]
    while stack:
        x, d = stack.pop()
        if isinstance(x, dict):
            if d > limit:
                raise VerifyError(f"{what}.json", f"nesting deeper than {limit}")
            stack.extend((y, d + 1) for y in x.values())
        elif isinstance(x, list):
            if d > limit:
                raise VerifyError(f"{what}.json", f"nesting deeper than {limit}")
            stack.extend((y, d + 1) for y in x)


def loads(data: bytes | str, what: str, *, max_bytes: int) -> Any:
    if isinstance(data, str):
        data = data.encode("utf-8", "surrogatepass")
    if len(data) > max_bytes:
        raise VerifyError(f"{what}.size", f"{len(data)} bytes, over {max_bytes}")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise VerifyError(f"{what}.json", f"not UTF-8: {e}") from e
    try:
        v = json.loads(
            text,
            object_pairs_hook=_no_duplicates,
            parse_int=_bounded_int,
            parse_float=_finite_float,
            parse_constant=_no_constants,
        )
    except RecursionError as e:
        raise VerifyError(f"{what}.json", "nesting too deep to parse") from e
    except (json.JSONDecodeError, ValueError) as e:
        raise VerifyError(f"{what}.json", f"not JSON: {e}") from e
    check_depth(v, what)
    return v

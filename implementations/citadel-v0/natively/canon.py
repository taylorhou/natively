"""JSON Canonicalization Scheme, RFC 8785, in-tree.

Rules implemented:
  - objects: keys sorted by UTF-16 code units; no whitespace;
  - strings: the RFC 8785 escape set (\\b \\t \\n \\f \\r \\" \\\\, other C0 controls as
    \\u00xx lowercase); everything else emitted raw as UTF-8;
  - numbers: ES6 Number::toString (shortest round-trip digits, the 1e21 / 1e-7
    exponent thresholds); NaN/Infinity rejected; ints beyond 2^53 rejected because
    they are not representable as an ES6 double;
  - literals: null/true/false.

`canonicalize` returns bytes; `sha256_hex` hashes them.
"""

from __future__ import annotations

import hashlib
import math
from decimal import Decimal
from typing import Any

_ESC = {
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
    '"': '\\"',
    "\\": "\\\\",
}

_MAX_SAFE = 2**53


def _str(s: str) -> str:
    out = []
    for ch in s:
        if ch in _ESC:
            out.append(_ESC[ch])
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _digits(x: float) -> tuple[str, int]:
    """Shortest round-trip digit string and the decimal-point position n such
    that x = 0.<digits> * 10^n (ES6 Number::toString notation)."""
    d = Decimal(repr(x)).as_tuple()
    digits = "".join(str(i) for i in d.digits).lstrip("0") or "0"
    # Decimal(repr) exponent is relative to the last digit; strip trailing zeros.
    exp = d.exponent
    assert isinstance(exp, int)
    stripped = digits.rstrip("0")
    if stripped == "":
        return "0", 1
    exp += len(digits) - len(stripped)
    digits = stripped
    return digits, len(digits) + exp


def _num(x: int | float) -> str:
    if isinstance(x, bool):
        raise TypeError("bool is not a number")
    if isinstance(x, int):
        if abs(x) > _MAX_SAFE:
            raise ValueError(f"integer {x} exceeds 2^53; not representable in ES6")
        return str(x)
    if math.isnan(x) or math.isinf(x):
        raise ValueError("NaN and Infinity are not JSON")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    s, n = _digits(abs(x))
    k = len(s)
    if k <= n <= 21:
        body = s + "0" * (n - k)
    elif 0 < n <= 21:
        body = s[:n] + "." + s[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + s
    else:
        e = n - 1
        esign = "+" if e >= 0 else "-"
        mant = s if k == 1 else s[0] + "." + s[1:]
        body = f"{mant}e{esign}{abs(e)}"
    return sign + body


def _ser(v: Any, out: list[str]) -> None:
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, str):
        out.append(_str(v))
    elif isinstance(v, int | float):
        out.append(_num(v))
    elif isinstance(v, list | tuple):
        out.append("[")
        for i, item in enumerate(v):
            if i:
                out.append(",")
            _ser(item, out)
        out.append("]")
    elif isinstance(v, dict):
        out.append("{")
        keys = list(v.keys())
        for k in keys:
            if not isinstance(k, str):
                raise TypeError(f"object key must be str, got {type(k).__name__}")
        for i, k in enumerate(sorted(keys, key=lambda k: k.encode("utf-16-be"))):
            if i:
                out.append(",")
            out.append(_str(k))
            out.append(":")
            _ser(v[k], out)
        out.append("}")
    else:
        raise TypeError(f"not JSON-serializable: {type(v).__name__}")


def canonicalize(value: Any) -> bytes:
    """RFC 8785 canonical UTF-8 bytes of a JSON value."""
    out: list[str] = []
    _ser(value, out)
    return "".join(out).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_of(value: Any, *, drop: tuple[str, ...] = ()) -> str:
    """'sha256:<hex>' over the canonical form of `value` minus the named keys."""
    if drop and isinstance(value, dict):
        value = {k: v for k, v in value.items() if k not in drop}
    return "sha256:" + sha256_hex(canonicalize(value))

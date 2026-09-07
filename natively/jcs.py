"""JCS (RFC 8785) JSON canonicalization, Python subset.

Deterministic serialization for signing: sorted keys, no insignificant
whitespace, UTF-8, ES6-style number formatting. Covers the JSON types the
protocol uses: null/bool/int/float/str/list/dict. No NaN/Infinity (invalid).
"""
import json
import struct


def _es6_number(n):
    if isinstance(n, bool):
        raise TypeError("bool is not a number here")
    if isinstance(n, int):
        return str(n)
    if not isinstance(n, float):
        raise TypeError("not a number")
    if n != n or n in (float("inf"), float("-inf")):
        raise ValueError("non-finite number not allowed in JCS")
    if n == 0:
        return "0"
    # ECMAScript Number::toString: shortest repr that round-trips, with
    # exponential notation only for exp < -6 or >= 21.
    r = repr(n)
    if "e" in r or "E" in r:
        mant, _, exp = r.replace("E", "e").partition("e")
        exp = int(exp)
        if -6 < exp < 21:
            # shift decimal point
            sign = ""
            if mant.startswith("-"):
                sign, mant = "-", mant[1:]
            mant = mant.replace(".", "")
            if exp >= 0:
                digits = mant + "0" * max(0, exp - len(mant) + 1)
                cut = exp + 1
                out = digits[:cut] + ("." + digits[cut:] if digits[cut:] else "")
            else:
                out = "0." + "0" * (-exp - 1) + mant
            out = out.rstrip("0").rstrip(".") if "." in out else out
            return sign + out
        return r.replace("e+", "e")
    return r


def _dump(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return _es6_number(v)
    if isinstance(v, str):
        # JCS escaping: JSON with minimal escapes, lone surrogates invalid
        return json.dumps(v, ensure_ascii=False).encode("utf-8").decode("utf-8")
    if isinstance(v, list):
        return "[" + ",".join(_dump(x) for x in v) + "]"
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _dump(val) for k, val in items) + "}"
    raise TypeError("unsupported type: %r" % type(v))


def canonicalize(v) -> bytes:
    return _dump(v).encode("utf-8")


def sha256(b: bytes) -> str:
    import hashlib
    return hashlib.sha256(b).hexdigest()

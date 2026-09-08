"""JCS (RFC 8785) JSON canonicalization, Python subset.

Deterministic serialization for signing: sorted keys (UTF-16 code unit
order), no insignificant whitespace, UTF-8, ES6 Number::toString number
formatting. Covers the JSON types the protocol uses:
null/bool/int/float/str/list/dict. No NaN/Infinity (invalid).

`loads` is the matching parser for every wire boundary: it refuses
duplicate keys (a first-wins and a last-wins reader would verify
different objects) and non-finite numbers.
"""
import json


def _es6_number(n):
    """ECMAScript Number::toString (ES2015 7.1.12.1), which RFC 8785
    section 3.2.2.3 adopts: the shortest digit string that round-trips,
    laid out as an integer, a decimal, or `d.ddde+x` / `de-x` with the
    exponent sign always written and never zero-padded."""
    if isinstance(n, bool):
        raise TypeError("bool is not a number here")
    if isinstance(n, int):
        if abs(n) > 2 ** 53:
            raise ValueError("integer outside the exactly representable double range")
        return str(n)
    if not isinstance(n, float):
        raise TypeError("not a number")
    if n != n or n in (float("inf"), float("-inf")):
        raise ValueError("non-finite number not allowed in JCS")
    if n == 0:
        return "0"
    sign = "-" if n < 0 else ""
    r = repr(abs(n))  # shortest round-trip digits, as ES6 requires
    mant, _, exp = r.partition("e")
    exp = int(exp) if exp else 0
    ip, _, fp = mant.partition(".")
    raw = ip + fp
    stripped = raw.lstrip("0")
    e10 = exp - len(fp)
    trailing = len(stripped) - len(stripped.rstrip("0"))
    digits = stripped.rstrip("0")
    e10 += trailing
    k = len(digits)
    pos = k + e10  # value = 0.digits x 10^pos
    if k <= pos <= 21:
        out = digits + "0" * (pos - k)
    elif 0 < pos <= 21:
        out = digits[:pos] + "." + digits[pos:]
    elif -6 < pos <= 0:
        out = "0." + "0" * (-pos) + digits
    else:
        e = pos - 1
        out = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + out


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


def _no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate key: %r" % k)
        d[k] = v
    return d


def _constant(name):
    raise ValueError("non-finite number not allowed: %s" % name)


def _float(s):
    f = float(s)
    if f != f or f in (float("inf"), float("-inf")):
        raise ValueError("number out of range: %s" % s)
    return f


def _int(s):
    n = int(s)
    if abs(n) > 2 ** 53:
        raise ValueError("integer outside the exactly representable double range: %s" % s)
    return n


def loads(b):
    """json.loads for signed or wire JSON: duplicate keys, NaN, Infinity,
    out-of-range floats and integers beyond 2^53 (which canonicalize would
    refuse) are errors, never silently normalized."""
    if isinstance(b, (bytes, bytearray)):
        b = b.decode("utf-8")
    return json.loads(b, object_pairs_hook=_no_dupes, parse_constant=_constant, parse_float=_float, parse_int=_int)


def sha256(b: bytes) -> str:
    import hashlib
    return hashlib.sha256(b).hexdigest()

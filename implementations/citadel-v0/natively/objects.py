"""Shared helpers for signed protocol objects."""

from __future__ import annotations

import base64
import re
from typing import Any

from ulid import ULID

from . import keys
from .canon import canonicalize
from .errors import VerifyError

# <prefix>_<26-char Crockford base32 ULID>; validated in full so an id never reaches
# the filesystem or the ledger with a slash, a dot, or a surrogate in it. The first
# character is 0-7: 26 base32 digits hold 130 bits, a ULID is 128, so anything from
# 8 up overflows (the ULID library refuses it; the regex must agree).
ULID_RE = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")
ID_PREFIXES = ("msg_", "ack_", "grt_", "rev_", "dny_")
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")  # a card hash, an entry hash: sha256:<64 hex>
SIG_BYTES = 64  # an Ed25519 signature, raw


def new_id(prefix: str) -> str:
    return f"{prefix}_{ULID()}"


def _canon(body: dict[str, Any], what: str) -> bytes:
    try:
        return canonicalize(body)
    except (UnicodeEncodeError, TypeError, ValueError) as e:
        raise VerifyError(f"{what}.canon", f"{what} cannot be canonicalized: {e}") from e


def signed(obj: dict[str, Any], kp: keys.KeyPair, field: str = "sig") -> dict[str, Any]:
    """Return a copy of obj with `field` = Ed25519 signature over JCS(obj minus field)."""
    body = {k: v for k, v in obj.items() if k != field}
    out = dict(body)
    out[field] = kp.sign(canonicalize(body))
    return out


def check_sig(obj: dict[str, Any], public: str, what: str, field: str = "sig") -> None:
    if field not in obj:
        raise VerifyError(f"{what}.{field}.missing", f"{what} carries no {field}")
    body = {k: v for k, v in obj.items() if k != field}
    keys.verify(public, _canon(body, what), obj[field], what=f"{what}.{field}")


def require(obj: Any, what: str, required: tuple[str, ...], optional: tuple[str, ...] = ()) -> None:
    """Structural check: obj is a dict with exactly the known keys. Unknown keys are
    rejected (fail closed: a constraint we do not understand is never ignored)."""
    if not isinstance(obj, dict):
        raise VerifyError(f"{what}.format", f"{what} must be an object")
    missing = [k for k in required if k not in obj]
    if missing:
        raise VerifyError(f"{what}.missing", f"{what} lacks {', '.join(missing)}")
    unknown = [k for k in obj if k not in required and k not in optional]
    if unknown:
        raise VerifyError(f"{what}.unknown_field", f"{what} carries unknown {', '.join(unknown)}")


def require_str(obj: dict[str, Any], key: str, what: str, prefix: str | None = None) -> str:
    v = obj.get(key)
    if not isinstance(v, str) or not v:
        raise VerifyError(f"{what}.{key}.format", f"{what}.{key} must be a non-empty string")
    if prefix and not v.startswith(prefix):
        raise VerifyError(f"{what}.{key}.format", f"{what}.{key} must start with {prefix!r}")
    return v


def require_sig(obj: dict[str, Any], what: str, field: str = "sig") -> str:
    """The signature field is a string of its encoding and length — base64 of the
    64 raw bytes of an Ed25519 signature — as a matter of STRUCTURE; whether it
    verifies under a key is `check_sig`'s. So a signature that is an empty list, a
    number, a string that is not base64 or one of the wrong length is refused by the
    structure check, at receipt on peer input and at every load of a file of ours."""
    v = obj.get(field)
    if not isinstance(v, str):
        raise VerifyError(f"{what}.{field}.format", f"{what}.{field} must be a base64 string")
    try:
        raw = base64.b64decode(v, validate=True)
    except Exception as e:  # noqa: BLE001 — any decode failure is a format failure
        raise VerifyError(f"{what}.{field}.format", f"{what}.{field} is not base64") from e
    if len(raw) != SIG_BYTES:
        raise VerifyError(
            f"{what}.{field}.format", f"{what}.{field} must be {SIG_BYTES} bytes, not {len(raw)}"
        )
    return v


def require_key(obj: dict[str, Any], key: str, what: str) -> str:
    """A public-key field: 'ed25519:<base64 of 32 bytes>' that decodes to a key (the
    prefix alone is not a key; a damaged key field is a structure failure, never a
    later exception at the signature check)."""
    v = require_str(obj, key, what, keys.PREFIX)
    try:
        keys.public_from_str(v, f"{what}.{key}")
    except VerifyError as e:
        raise VerifyError(f"{what}.{key}.format", e.detail) from e
    return v


def require_hash(obj: dict[str, Any], key: str, what: str) -> str:
    """A hash field: 'sha256:<64 hex>'."""
    v = obj.get(key)
    if not isinstance(v, str) or not HASH_RE.fullmatch(v):
        raise VerifyError(f"{what}.{key}.format", f"{what}.{key} must be sha256:<64 hex>")
    return v


def check_id(v: Any, what: str, prefix: str) -> str:
    """`v` is `<prefix><ULID>`; anything else is a format failure."""
    if (
        not isinstance(v, str)
        or not v.startswith(prefix)
        or not ULID_RE.fullmatch(v[len(prefix) :])
    ):
        raise VerifyError(f"{what}.format", f"{what} must be {prefix}<26-char ULID>")
    return v


def require_id(obj: dict[str, Any], key: str, what: str, prefix: str) -> str:
    return check_id(obj.get(key), f"{what}.{key}", prefix)


def is_id(v: Any, prefix: str) -> bool:
    return isinstance(v, str) and v.startswith(prefix) and bool(ULID_RE.fullmatch(v[len(prefix) :]))

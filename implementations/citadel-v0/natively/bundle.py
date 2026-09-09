"""Wire envelope (spec section 7, adapter contract). One bundle per transport
message: the protocol object plus the cards and grants the recipient needs to
verify it. The transport sees only base64; msg_id / in_reply_to live inside.

  {"natively": "v0", "kind": "message"|"ack"|"card"|"revocation",
   "object": {...}, "cards": [...], "grants": [...]}

Body text on the mail wire:
  X-Natively: v0
  <base64 of the bundle JSON, wrapped at 76 columns>

Limits: 512 KiB of DECODED bundle JSON (checked on the decoded bytes; the base64
text is bounded before decoding too), nesting depth 32, no duplicate member names,
no integers beyond 2^53 (jsonsafe)."""

from __future__ import annotations

import base64
import json
import textwrap
from typing import Any

from . import PROTOCOL_VERSION, jsonsafe
from .errors import VerifyError

KINDS = ("message", "ack", "card", "revocation")
HEADER = f"X-Natively: {PROTOCOL_VERSION}"
MAX_WIRE_BYTES = 512 * 1024
# base64 of MAX_WIRE_BYTES, plus padding; the wrapped text has its whitespace
# stripped before this bound is applied.
MAX_WIRE_B64_CHARS = (MAX_WIRE_BYTES + 2) // 3 * 4
# The wire TEXT of the largest bundle as encode() writes it: the header line, then
# the base64 wrapped at 76 columns (one newline per line). This is what the mail
# helper's --chars must cover; the base64 bound alone is short by the header and the
# line breaks, and a body cut there decodes as garbage (gate round 3, F8).
MAX_WIRE_TEXT_CHARS = len(HEADER) + 1 + MAX_WIRE_B64_CHARS + -(-MAX_WIRE_B64_CHARS // 76)


def make(
    kind: str,
    obj: dict[str, Any],
    *,
    cards: list[dict[str, Any]] | None = None,
    grants: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}")
    return {
        "natively": PROTOCOL_VERSION,
        "kind": kind,
        "object": obj,
        "cards": list(cards or []),
        "grants": list(grants or []),
    }


def check(b: Any) -> dict[str, Any]:
    jsonsafe.check_depth(b, "bundle")
    if not isinstance(b, dict):
        raise VerifyError("bundle.format", "bundle must be an object")
    if b.get("natively") != PROTOCOL_VERSION:
        raise VerifyError(
            "bundle.version", f"expected natively {PROTOCOL_VERSION!r}, got {b.get('natively')!r}"
        )
    if set(b) != {"natively", "kind", "object", "cards", "grants"}:
        raise VerifyError("bundle.fields", f"unexpected bundle fields {sorted(b)}")
    if b["kind"] not in KINDS:
        raise VerifyError("bundle.kind", f"unknown kind {b['kind']!r}")
    if not isinstance(b["object"], dict):
        raise VerifyError("bundle.object", "object must be an object")
    for k in ("cards", "grants"):
        if not isinstance(b[k], list) or not all(isinstance(x, dict) for x in b[k]):
            raise VerifyError(f"bundle.{k}", f"{k} must be a list of objects")
    return b


def encode(b: dict[str, Any]) -> str:
    """Wire body text: header line + wrapped base64 of the bundle JSON."""
    raw = json.dumps(b, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_WIRE_BYTES:
        raise ValueError(f"bundle is {len(raw)} bytes, over {MAX_WIRE_BYTES}")
    b64 = base64.b64encode(raw).decode("ascii")
    return HEADER + "\n" + "\n".join(textwrap.wrap(b64, 76)) + "\n"


def decode(text: str) -> dict[str, Any]:
    """Parse a wire body. Tolerates leading blank lines, trailing quoted text after a
    blank line, and any whitespace inside the base64 (mail clients rewrap)."""
    lines = [ln.strip() for ln in text.replace("\r\n", "\n").split("\n")]
    while lines and not lines[0]:
        lines.pop(0)
    if not lines or lines[0] != HEADER:
        raise VerifyError("wire.header", f"first line must be {HEADER!r}")
    b64_lines: list[str] = []
    for ln in lines[1:]:
        if not ln:
            if b64_lines:
                break
            continue
        if ln.startswith(">"):
            break
        b64_lines.append(ln)
    b64 = "".join(b64_lines)
    if len(b64) > MAX_WIRE_B64_CHARS:
        raise VerifyError("wire.size", f"wire body {len(b64)} base64 chars, over the limit")
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception as e:  # noqa: BLE001
        raise VerifyError("wire.base64", "wire body is not base64") from e
    if len(raw) > MAX_WIRE_BYTES:
        raise VerifyError("wire.size", f"decoded bundle {len(raw)} bytes, over {MAX_WIRE_BYTES}")
    obj = jsonsafe.loads(raw, "wire", max_bytes=MAX_WIRE_BYTES)
    return check(obj)

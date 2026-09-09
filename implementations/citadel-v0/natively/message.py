"""Messages (spec section 4): {msg_id, ts, from, to, in_reply_to, grant_ids, body, sig}.
Bodies are base64 end to end; the plaintext is a small JSON document:
  {"type": "info", "text": "..."}                                   information
  {"type": "action", "action": "...", "resource": "...", "params": {}}   a request
A message with an empty grant_ids is information whatever its (well-formed) body
says; a malformed body is refused. The decoded body is bounded at 256 KiB."""

from __future__ import annotations

import base64
import json
from typing import Any

from . import jsonsafe, keys
from .errors import VerifyError
from .objects import check_id, check_sig, new_id, require, require_id, require_str, signed
from .timeutil import parse

_TOP = ("msg_id", "ts", "from", "to", "in_reply_to", "grant_ids", "body")
MAX_BODY_BYTES = 256 * 1024
MAX_BODY_B64_CHARS = (MAX_BODY_BYTES + 2) // 3 * 4
MAX_GRANT_IDS = 16


def encode_body(plain: dict[str, Any]) -> str:
    return base64.b64encode(json.dumps(plain, ensure_ascii=False).encode("utf-8")).decode("ascii")


def build(
    *,
    from_key: str,
    to_key: str,
    ts: str,
    body: dict[str, Any],
    grant_ids: list[str] | None = None,
    in_reply_to: str | None = None,
) -> dict[str, Any]:
    return {
        "msg_id": new_id("msg"),
        "ts": ts,
        "from": from_key,
        "to": to_key,
        "in_reply_to": in_reply_to,
        "grant_ids": list(grant_ids or []),
        "body": encode_body(body),
    }


def info(*, from_key: str, to_key: str, ts: str, text: str, in_reply_to: str | None = None):
    return build(
        from_key=from_key,
        to_key=to_key,
        ts=ts,
        in_reply_to=in_reply_to,
        body={"type": "info", "text": text},
    )


def action(
    *,
    from_key: str,
    to_key: str,
    ts: str,
    action: str,
    resource: str,
    params: dict[str, Any],
    grant_ids: list[str],
    in_reply_to: str | None = None,
):
    return build(
        from_key=from_key,
        to_key=to_key,
        ts=ts,
        in_reply_to=in_reply_to,
        grant_ids=grant_ids,
        body={"type": "action", "action": action, "resource": resource, "params": params},
    )


def sign(m: dict[str, Any], kp: keys.KeyPair) -> dict[str, Any]:
    if kp.public != m["from"]:
        raise ValueError("signing key does not match message.from")
    return signed(m, kp)


def verify(m: Any) -> None:
    """Structure and the sender's signature (the sender key is m['from']; whether that
    key belongs to a trusted card is the node's decision)."""
    require(m, "message", _TOP + ("sig",))
    require_id(m, "msg_id", "message", "msg_")
    parse(require_str(m, "ts", "message"), "message.ts")
    require_str(m, "from", "message", keys.PREFIX)
    require_str(m, "to", "message", keys.PREFIX)
    if m["in_reply_to"] is not None:
        check_id(m["in_reply_to"], "message.in_reply_to", "msg_")
    if not isinstance(m["grant_ids"], list) or len(m["grant_ids"]) > MAX_GRANT_IDS:
        raise VerifyError(
            "message.grant_ids.format", f"must be a list of at most {MAX_GRANT_IDS} grt_ ids"
        )
    for g in m["grant_ids"]:
        check_id(g, "message.grant_ids", "grt_")
    if len(set(m["grant_ids"])) != len(m["grant_ids"]):
        raise VerifyError("message.grant_ids.format", "grant_ids repeats an id")
    b = require_str(m, "body", "message")
    if len(b) > MAX_BODY_B64_CHARS:
        raise VerifyError("message.body.size", f"body over {MAX_BODY_BYTES} bytes")
    try:
        raw = base64.b64decode(b, validate=True)
    except Exception as e:  # noqa: BLE001
        raise VerifyError("message.body.encoding", "body is not base64") from e
    if len(raw) > MAX_BODY_BYTES:
        raise VerifyError("message.body.size", f"decoded body over {MAX_BODY_BYTES} bytes")
    check_sig(m, m["from"], "message")


def decode_body(m: dict[str, Any]) -> dict[str, Any]:
    raw = base64.b64decode(m["body"], validate=True)
    try:
        plain = jsonsafe.loads(raw, "message.body", max_bytes=MAX_BODY_BYTES)
    except VerifyError as e:
        raise VerifyError("message.body.json", f"body is not a JSON document: {e.detail}") from e
    if not isinstance(plain, dict) or plain.get("type") not in ("info", "action"):
        raise VerifyError("message.body.type", "body.type must be info or action")
    if plain["type"] == "action":
        require(plain, "message.body", ("type", "action", "resource", "params"))
        require_str(plain, "action", "message.body")
        require_str(plain, "resource", "message.body")
        if not isinstance(plain["params"], dict):
            raise VerifyError("message.body.params", "params must be an object")
    else:
        require(plain, "message.body", ("type",), ("text",))
        if "text" in plain and not isinstance(plain["text"], str):
            raise VerifyError("message.body.text", "text must be a string")
    return plain


def is_information(m: dict[str, Any]) -> bool:
    return len(m["grant_ids"]) == 0

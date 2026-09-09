"""Ack (spec section 4, 'receipts are an explicit ack message type'): signed by the
recipient agent key; carries the recipient's ledger head after the entry it made
for the message, so heads reconcile through the acks."""

from __future__ import annotations

from typing import Any

from . import keys
from .errors import VerifyError
from .objects import check_sig, new_id, require, require_id, require_str, signed
from .timeutil import parse

_TOP = ("ack_id", "ts", "from", "to", "in_reply_to", "outcome", "ledger_head", "ledger_entry")
OUTCOMES = ("information", "applied", "refused", "failed", "duplicate")


def build(
    *,
    from_key: str,
    to_key: str,
    ts: str,
    in_reply_to: str,
    outcome: str,
    ledger_head: str,
    ledger_entry: str,
    detail: str = "",
) -> dict[str, Any]:
    if outcome not in OUTCOMES:
        raise ValueError(f"outcome must be one of {OUTCOMES}")
    return {
        "ack_id": new_id("ack"),
        "ts": ts,
        "from": from_key,
        "to": to_key,
        "in_reply_to": in_reply_to,
        "outcome": outcome if not detail else f"{outcome}:{detail}",
        "ledger_head": ledger_head,
        "ledger_entry": ledger_entry,
    }


def sign(a: dict[str, Any], kp: keys.KeyPair) -> dict[str, Any]:
    if kp.public != a["from"]:
        raise ValueError("signing key does not match ack.from")
    return signed(a, kp)


def verify(a: Any) -> None:
    require(a, "ack", _TOP + ("sig",))
    require_id(a, "ack_id", "ack", "ack_")
    parse(require_str(a, "ts", "ack"), "ack.ts")
    require_str(a, "from", "ack", keys.PREFIX)
    require_str(a, "to", "ack", keys.PREFIX)
    require_id(a, "in_reply_to", "ack", "msg_")
    oc = require_str(a, "outcome", "ack")
    if oc.split(":", 1)[0] not in OUTCOMES:
        raise VerifyError("ack.outcome", f"unknown outcome {oc!r}")
    require_str(a, "ledger_head", "ack", "sha256:")
    require_str(a, "ledger_entry", "ack", "sha256:")
    check_sig(a, a["from"], "ack")


def outcome_kind(a: dict[str, Any]) -> str:
    return a["outcome"].split(":", 1)[0]

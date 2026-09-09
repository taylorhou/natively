"""Agent card (spec section 2): {agent key, node key, principal key ref, capabilities,
ledger url}. The node vouches (node_sig over the card minus both signatures), then
the principal signs (sig over the card minus sig, which includes node_sig). The card
hash is SHA-256 over JCS(card minus sig)."""

from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Any

from . import keys
from .canon import hash_of
from .errors import VerifyError
from .objects import check_sig, require, require_str, signed

CARD_VERSION = "v0"
PRINCIPAL_KINDS = ("principal", "stand-in")

_TOP = ("card_version", "agent", "node", "principal", "capabilities", "ledger_url", "issued_at")


def build(
    *,
    agent_name: str,
    agent_key: str,
    node_name: str,
    node_key: str,
    principal_name: str,
    principal_key: str,
    principal_kind: str,
    capabilities: list[dict[str, str]],
    ledger_url: str,
    issued_at: str,
) -> dict[str, Any]:
    if principal_kind not in PRINCIPAL_KINDS:
        raise ValueError(f"principal_kind must be one of {PRINCIPAL_KINDS}")
    return {
        "card_version": CARD_VERSION,
        "agent": {"name": agent_name, "key": agent_key},
        "node": {"name": node_name, "key": node_key},
        "principal": {
            "name": principal_name,
            "key": principal_key,
            "principal_kind": principal_kind,
        },
        "capabilities": [{"action": c["action"], "resource": c["resource"]} for c in capabilities],
        "ledger_url": ledger_url,
        "issued_at": issued_at,
    }


def sign(card: dict[str, Any], node_kp: keys.KeyPair, principal_kp: keys.KeyPair) -> dict[str, Any]:
    if node_kp.public != card["node"]["key"]:
        raise ValueError("node key does not match card.node.key")
    if principal_kp.public != card["principal"]["key"]:
        raise ValueError("principal key does not match card.principal.key")
    vouched = signed(
        {k: v for k, v in card.items() if k not in ("sig", "node_sig")}, node_kp, "node_sig"
    )
    return signed(vouched, principal_kp, "sig")


def card_hash(card: dict[str, Any]) -> str:
    return hash_of(card, drop=("sig",))


def verify(card: Any, *, pinned: set[str] | None = None) -> str:
    """Structure + both signatures. With `pinned`, the principal must be a pinned root.
    Returns the card hash."""
    require(card, "card", _TOP + ("node_sig", "sig"))
    if card["card_version"] != CARD_VERSION:
        raise VerifyError("card.version", f"unsupported card_version {card['card_version']!r}")
    for sect, fields in (
        ("agent", ("name", "key")),
        ("node", ("name", "key")),
        ("principal", ("name", "key", "principal_kind")),
    ):
        require(card[sect], f"card.{sect}", fields)
        require_str(card[sect], "name", f"card.{sect}")
        require_str(card[sect], "key", f"card.{sect}", keys.PREFIX)
    if card["principal"]["principal_kind"] not in PRINCIPAL_KINDS:
        raise VerifyError("card.principal.kind", "principal_kind must be principal or stand-in")
    if not isinstance(card["capabilities"], list):
        raise VerifyError("card.capabilities.format", "capabilities must be a list")
    for i, cap in enumerate(card["capabilities"]):
        require(cap, f"card.capabilities[{i}]", ("action", "resource"))
        require_str(cap, "action", f"card.capabilities[{i}]")
        require_str(cap, "resource", f"card.capabilities[{i}]")
    require_str(card, "ledger_url", "card")
    require_str(card, "issued_at", "card")
    unsigned = {k: v for k, v in card.items() if k not in ("sig", "node_sig")}
    unsigned["node_sig"] = card["node_sig"]
    check_sig(unsigned, card["node"]["key"], "card", "node_sig")
    check_sig(card, card["principal"]["key"], "card", "sig")
    if pinned is not None and card["principal"]["key"] not in pinned:
        raise VerifyError(
            "card.principal.unpinned",
            f"principal {card['principal']['key']} is not a pinned root; pin it explicitly",
        )
    return card_hash(card)


def allows(card: dict[str, Any], action: str, resource: str) -> bool:
    """The capabilities-of-card check: the card lists an entry whose action equals
    `action` and whose resource glob matches `resource`."""
    for cap in card.get("capabilities", []):
        if cap["action"] == action and fnmatchcase(resource, cap["resource"]):
            return True
    return False

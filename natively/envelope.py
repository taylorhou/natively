"""Protocol envelopes: agent cards, grants, messages (spec sections 2-4).

All signed objects are JCS-canonicalized JSON, signed over the canonical
form minus the `sig` field. Bodies are base64 ciphertext (suite nv1).
"""
import time

from . import jcs, crypto


def _ulid():
    try:
        import ulid as _u
        return str(_u.new()).lower()
    except ImportError:
        import os, time as _t
        # Crockford base32 timestamp+randomness, ULID-compatible shape
        alphabet = "0123456789abcdefghjkmnpqrstvwxyz"
        def enc(n, ln):
            s = ""
            for _ in range(ln):
                s = alphabet[n & 31] + s
                n >>= 5
            return s
        return enc(int(_t.time() * 1000), 10) + enc(int.from_bytes(os.urandom(10), "big"), 16)


def new_id(prefix: str) -> str:
    return "%s_%s" % (prefix, _ulid())


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def parse_iso(ts: str) -> float:
    """'YYYY-MM-DDTHH:MM:SSZ' -> epoch seconds. Raises ValueError on any
    other shape (the protocol's timestamps are always this form)."""
    import calendar
    if not isinstance(ts, str):
        raise ValueError("timestamp must be a string")
    return float(calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")))


def sign_obj(obj: dict, seed: bytes) -> dict:
    o = {k: v for k, v in obj.items() if k != "sig"}
    sig = crypto.sign(seed, jcs.canonicalize(o))
    o["sig"] = crypto.b64e(sig)
    return o


def verify_obj(obj: dict, pub_b64: str) -> bool:
    o = {k: v for k, v in obj.items() if k != "sig"}
    return crypto.verify(crypto.b64d(pub_b64), jcs.canonicalize(o), crypto.b64d(obj["sig"]))


def obj_hash(obj: dict) -> str:
    o = {k: v for k, v in obj.items() if k != "sig"}
    return jcs.sha256(jcs.canonicalize(o))


# ---------- Agent card (spec 2) ----------

def make_card(agent_seed: bytes, node_pub: bytes, principal_seed: bytes,
              capabilities, ledger_url, ttl_s=30 * 86400, supersedes=None) -> dict:
    card = {
        "card_version": 1,
        "agent_key": "ed25519:" + crypto.b64e(crypto.sign_pub(agent_seed)),
        "node_key": "ed25519:" + crypto.b64e(node_pub),
        "principal_key_ref": "ed25519:" + crypto.b64e(crypto.sign_pub(principal_seed)),
        "capabilities": sorted(capabilities),
        "ledger_url": ledger_url,
        "issued_at": now_iso(),
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + ttl_s)),
        "supersedes": supersedes,
    }
    return sign_obj(card, principal_seed)


def verify_card(card: dict, pinned_principal_pub_b64: str = None) -> bool:
    ref = card["principal_key_ref"].split(":", 1)[1]
    if pinned_principal_pub_b64 and ref != pinned_principal_pub_b64:
        return False
    if card["expires_at"] < now_iso():
        return False
    return verify_obj(card, ref)


# ---------- Grant envelope (spec 3) ----------

def make_grant(principal_seed: bytes, principal_name: str, subject_card: dict,
               executor_key_b64: str, scope: list, statement: str,
               max_uses: int = 1, ttl_s: int = 86400,
               revocation_ledger: str = "", parent_grant: str = None) -> dict:
    g = {
        "grant_id": new_id("grt"),
        "issuer": {"principal": principal_name,
                   "key": "ed25519:" + crypto.b64e(crypto.sign_pub(principal_seed))},
        "subject": {"agent": obj_hash(subject_card),
                    "key": subject_card["agent_key"]},
        "audience": {"executor": executor_key_b64},
        "scope": scope,
        "principal_statement": statement,
        "max_uses": max_uses,
        "not_before": now_iso(),
        "issued_at": now_iso(),
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + ttl_s)),
        "revocation": {"ledger": revocation_ledger, "max_check_interval_s": 300},
        "parent_grant": parent_grant,
    }
    if max_uses is None:
        del g["max_uses"]  # scope entries carry max_uses_per_window instead
    return sign_obj(g, principal_seed)


class GrantError(Exception):
    pass


def verify_grant(grant: dict, pinned_principal_pub_b64: str = None) -> None:
    ik = grant["issuer"]["key"].split(":", 1)[1]
    if pinned_principal_pub_b64 and ik != pinned_principal_pub_b64:
        raise GrantError("issuer not the pinned principal")
    if not verify_obj(grant, ik):
        raise GrantError("bad grant signature")
    t = now_iso()
    if grant["not_before"] > t:
        raise GrantError("grant not yet valid")
    if grant["expires_at"] < t:
        raise GrantError("grant expired")
    if ("max_uses" in grant) == any("max_uses_per_window" in sc for sc in grant["scope"]):
        raise GrantError("grant must carry max_uses XOR per-scope max_uses_per_window")


def grant_covers(grant: dict, action: str, resource: str, params: dict) -> bool:
    """Does a scope entry cover this action/resource/params? v0 constraint
    grammar: in / range / regex (spec 3)."""
    for sc in grant["scope"]:
        if sc["action"] != action:
            continue
        if sc["resource"] != resource:
            continue
        p = sc.get("params", {})
        ok = True
        for k in p.get("keys", []):
            if k not in params:
                ok = False
                break
        for k, rule in p.get("values", {}).items():
            v = params.get(k)
            if "in" in rule and v not in rule["in"]:
                ok = False
            if "range" in rule and not (rule["range"][0] <= v <= rule["range"][1]):
                ok = False
            if "regex" in rule:
                import re
                if not re.fullmatch(rule["regex"], str(v or "")):
                    ok = False
        if ok:
            return True
    return False


# ---------- Message envelope (spec 4) ----------

def make_message(from_key_b64: str, to_key_b64: str, body_ciphertext_b64: str,
                 agent_seed: bytes, grant_ids=None, in_reply_to=None,
                 msg_type="msg", suite=crypto.SUITE, extra=None) -> dict:
    m = {
        "msg_id": new_id("msg"),
        "ts": now_iso(),
        "type": msg_type,
        "suite": suite,
        "from": "ed25519:" + from_key_b64,
        "to": "ed25519:" + to_key_b64,
        "in_reply_to": in_reply_to,
        "grant_ids": grant_ids or [],
        "body": body_ciphertext_b64,
    }
    if extra:
        m.update(extra)
    return sign_obj(m, agent_seed)


def verify_message(msg: dict) -> bool:
    fk = msg["from"].split(":", 1)[1]
    return verify_obj(msg, fk)

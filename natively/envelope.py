"""Protocol envelopes: agent cards, grants, messages (spec sections 2-4).

All signed objects are JCS-canonicalized JSON, signed over the canonical
form minus the `sig` field. Bodies are base64 ciphertext (suite nv1).
"""
import re
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


# Crockford base32 as _ulid emits it: digits and lowercase letters minus i, l, o, u
_ID_RE = re.compile(r"[a-z]{3}_[0-9a-hjkmnp-tv-z]{26}")
_HEX32_RE = re.compile(r"[0-9a-f]{32}")


def safe_id(s, prefix: str = None) -> bool:
    """Is `s` a protocol identifier (`<3 lowercase letters>_<26 Crockford
    base32>`, e.g. msg_..., grt_..., grp_...)? Every identifier that
    arrives over the wire or out of a decrypted body is checked with this
    before it names a file, a dict key or a ledger row. A prefix pins the
    kind. fullmatch: no trailing newline or any other extra byte."""
    if not isinstance(s, str) or _ID_RE.fullmatch(s) is None:
        return False
    return prefix is None or s.startswith(prefix + "_")


def safe_fp(s) -> bool:
    """Is `s` a node fingerprint / blob id (exactly 32 lowercase hex)?"""
    return isinstance(s, str) and _HEX32_RE.fullmatch(s) is not None


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


_ISO_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


def parse_iso(ts: str) -> float:
    """'YYYY-MM-DDTHH:MM:SSZ' -> epoch seconds. Raises ValueError on any
    other shape (the protocol's timestamps are always this form) and on
    a value that is not a real instant: strptime would accept a second
    of 61 or a 30th of February and normalize it into a later time, so
    the parsed value must print back to exactly the string given."""
    import calendar
    if not isinstance(ts, str) or _ISO_RE.fullmatch(ts) is None:
        raise ValueError("timestamp is not YYYY-MM-DDTHH:MM:SSZ")
    secs = calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))
    if time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(secs)) != ts:
        raise ValueError("timestamp is not a real instant")
    return float(secs)


def sign_obj(obj: dict, seed: bytes) -> dict:
    o = {k: v for k, v in obj.items() if k != "sig"}
    sig = crypto.sign(seed, jcs.canonicalize(o))
    o["sig"] = crypto.b64e(sig)
    return o


def key_bytes(key) -> bytes:
    """'ed25519:<b64>' -> the 32 raw bytes. Raises ValueError for any other
    shape: another or no algorithm prefix, base64 that is not canonical,
    a length other than 32. Every identity comparison goes through this,
    so two spellings of one key never compare unequal and a malformed key
    never verifies anything."""
    import base64
    import binascii
    if not isinstance(key, str) or not key.startswith("ed25519:"):
        raise ValueError("not an ed25519 key reference")
    b64 = key[len("ed25519:"):]
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("key is not base64")
    if len(raw) != 32 or base64.b64encode(raw).decode() != b64:
        raise ValueError("key is not a canonical 32-byte ed25519 public key")
    return raw


def _key_arg(key) -> bytes:
    """Accept a bare b64 key or an 'ed25519:' reference."""
    if isinstance(key, str) and not key.startswith("ed25519:"):
        key = "ed25519:" + key
    return key_bytes(key)


def verify_obj(obj: dict, pub) -> bool:
    """Signature check over JCS(obj minus sig). False, never an exception,
    for a malformed object, key or signature."""
    try:
        pub_raw = _key_arg(pub)
        if not isinstance(obj, dict) or not isinstance(obj.get("sig"), str):
            return False
        o = {k: v for k, v in obj.items() if k != "sig"}
        return crypto.verify(pub_raw, jcs.canonicalize(o), sig_bytes(obj["sig"]))
    except Exception:
        return False


def sig_bytes(sig) -> bytes:
    """A signature's 64 raw bytes from its canonical base64 (padded, no
    stray characters, re-encodes to the same string). Raises ValueError
    otherwise: a decoder that skips characters it does not know would
    let several spellings of one signature verify, and a signed document
    is meant to have exactly one."""
    import base64
    if not isinstance(sig, str):
        raise ValueError("signature must be a string")
    try:
        raw = base64.b64decode(sig, validate=True)
    except Exception:
        raise ValueError("signature is not base64")
    if base64.b64encode(raw).decode() != sig or len(raw) != 64:
        raise ValueError("signature is not a canonical 64-byte value")
    return raw


def obj_hash(obj: dict) -> str:
    o = {k: v for k, v in obj.items() if k != "sig"}
    return jcs.sha256(jcs.canonicalize(o))


# ---------- Agent card (spec 2) ----------

def make_card(agent_seed: bytes, node_pub: bytes, principal_seed: bytes,
              capabilities, ledger_url, ttl_s=30 * 86400, supersedes=None) -> dict:
    return make_card_for_pub(crypto.sign_pub(agent_seed), node_pub, principal_seed,
                             capabilities, ledger_url, ttl_s, supersedes)


def make_card_for_pub(agent_pub: bytes, node_pub: bytes, principal_seed: bytes,
                      capabilities, ledger_url, ttl_s=30 * 86400, supersedes=None) -> dict:
    # Same card as make_card, but for an agent keypair generated elsewhere:
    # only the public key crosses, so the agent's seed never leaves its node.
    card = {
        "card_version": 1,
        "agent_key": "ed25519:" + crypto.b64e(agent_pub),
        "node_key": "ed25519:" + crypto.b64e(node_pub),
        "principal_key_ref": "ed25519:" + crypto.b64e(crypto.sign_pub(principal_seed)),
        "capabilities": sorted(capabilities),
        "ledger_url": ledger_url,
        "issued_at": now_iso(),
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + ttl_s)),
        "supersedes": supersedes,
    }
    return sign_obj(card, principal_seed)


def verify_card(card, roots, now=None) -> bool:
    """Is `card` a well-formed, unexpired agent card signed by one of
    `roots` (bare-b64 principal keys, the verifier's pinned root set)?
    An empty root set verifies nothing: a missing pin fails closed."""
    try:
        roots = {r for r in (roots or ()) if isinstance(r, str)}
        if not roots or not isinstance(card, dict):
            return False
        if card.get("card_version") != 1 or isinstance(card.get("card_version"), bool):
            return False
        for k in ("agent_key", "node_key", "principal_key_ref"):
            key_bytes(card.get(k))
        caps = card.get("capabilities")
        if not isinstance(caps, list) or not all(isinstance(c, str) and c for c in caps):
            return False
        if card.get("supersedes") is not None and not isinstance(card["supersedes"], str):
            return False
        ref = card["principal_key_ref"][len("ed25519:"):]
        if ref not in roots:
            return False
        parse_iso(card.get("issued_at"))
        if parse_iso(card.get("expires_at")) <= (time.time() if now is None else now):
            return False
        return verify_obj(card, ref)
    except Exception:
        return False


# ---------- Grant envelope (spec 3) ----------

def make_grant(principal_seed: bytes, principal_name: str, subject_card: dict,
               executor_key_b64: str, scope: list, statement: str,
               max_uses: int = 1, ttl_s: int = 86400,
               revocation_ledger: str = "", parent_grant: str = None,
               max_check_interval_s: int = 300) -> dict:
    # a scope that does not parse is refused at mint: signed, it would be
    # refused by every executor (2026-09-08: a dict-shaped scope in both
    # directions of the first cross-principal exchange)
    try:
        _require(isinstance(scope, list) and bool(scope), "scope must be a non-empty list")
        for sc in scope:
            check_scope_entry(sc)
    except GrantError as e:
        raise ValueError("refusing to sign a grant with malformed scope: %s" % e)
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
        "revocation": {"ledger": revocation_ledger, "max_check_interval_s": max_check_interval_s},
        "parent_grant": parent_grant,
    }
    if max_uses is None:
        del g["max_uses"]  # scope entries carry max_uses_per_window instead
    return sign_obj(g, principal_seed)


class GrantError(Exception):
    pass


def _require(cond, msg):
    if not cond:
        raise GrantError(msg)


MAX_SECONDS = 10 * 366 * 86400  # ten years: the largest duration any grant field may carry
MAX_COUNT = 10 ** 9


def _pos_int(v, cap=MAX_COUNT) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 < v <= cap


def _number(v) -> bool:
    """A JSON number: int or finite float, never a bool. A non-finite
    float (json.loads turns 1e400 into inf) is not a number JCS can
    write, so it is not one a constraint can carry."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return False
    return not isinstance(v, float) or v == v and v not in (float("inf"), float("-inf"))


def _scalar(v) -> bool:
    return v is None or isinstance(v, (bool, str)) or _number(v)


def _same(a, b) -> bool:
    """Equality that never crosses JSON types: True is not 1, "1" is not 1.
    JSON has one number type and JCS writes 1 and 1.0 as the same bytes,
    so a signed constraint of [1] and one of [1.0] are the same signed
    document and must authorize the same requests: numbers compare as
    numbers (bool stays its own type)."""
    if _number(a) and _number(b):
        return a == b
    return type(a) is type(b) and a == b


CONSTRAINT_OPS = ("in", "range", "regex")
_SCOPE_FIELDS = {"action", "resource", "params", "max_uses_per_window", "offline_ok", "max_offline_s"}
_GRANT_FIELDS = {"grant_id", "issuer", "subject", "audience", "scope", "principal_statement", "max_uses",
                 "not_before", "issued_at", "expires_at", "revocation", "parent_grant", "sig"}
_HASH_RE = re.compile(r"[0-9a-f]{64}")


def parse_resource(resource):
    """'host:ed25519:<b64>:<name>' -> ('ed25519:<b64>', name); None for any
    other shape. A resource is an opaque label matched literally (spec 3);
    this form is the one that names a host, and an executor refuses it
    when the host is not itself."""
    if not isinstance(resource, str) or not resource.startswith("host:"):
        return None
    parts = resource[len("host:"):].split(":", 2)
    if len(parts) != 3 or not parts[2]:
        return None
    key = parts[0] + ":" + parts[1]
    try:
        key_bytes(key)
    except ValueError:
        return None
    return key, parts[2]


def check_scope_entry(sc) -> None:
    """The closed v0 scope grammar: action, a resource label (a string,
    matched literally; the host:<node-key>:<name> form binds it to a
    host), params as an allowlist of keys plus in / range / regex value
    constraints on a subset of those keys, an optional per-window budget,
    an optional offline allowance. Anything else is refused."""
    _require(isinstance(sc, dict), "scope entry is not an object")
    _require(set(sc) <= _SCOPE_FIELDS, "unknown scope field")
    _require(isinstance(sc.get("action"), str) and bool(sc["action"]), "scope action missing")
    _require(isinstance(sc.get("resource"), str), "scope resource must be a string")
    p = sc.get("params", {})
    _require(isinstance(p, dict) and set(p) <= {"keys", "values"}, "scope params must hold keys and values only")
    keys = p.get("keys", [])
    _require(isinstance(keys, list) and all(isinstance(k, str) and k for k in keys), "params.keys must be strings")
    _require(len(set(keys)) == len(keys), "params.keys repeats a key")
    values = p.get("values", {})
    _require(isinstance(values, dict) and set(values) <= set(keys), "params.values constrains a key outside params.keys")
    for k, rule in values.items():
        _require(isinstance(rule, dict) and rule and set(rule) <= set(CONSTRAINT_OPS), "unknown constraint operator on %s" % k)
        if "in" in rule:
            _require(isinstance(rule["in"], list) and rule["in"] and all(_scalar(x) for x in rule["in"]),
                     "'in' needs a non-empty list of scalars")
        if "range" in rule:
            r = rule["range"]
            _require(isinstance(r, list) and len(r) == 2 and _number(r[0]) and _number(r[1]) and r[0] <= r[1],
                     "'range' needs [low, high] numbers")
        if "regex" in rule:
            _require(isinstance(rule["regex"], str), "'regex' needs a pattern string")
            try:
                re.compile(rule["regex"])
            except Exception:  # re.error, OverflowError on absurd repeat counts, RecursionError
                raise GrantError("'regex' pattern does not compile")
    if "max_uses_per_window" in sc:
        w = sc["max_uses_per_window"]
        _require(isinstance(w, dict) and set(w) == {"n", "window_s"} and _pos_int(w["n"]) and _pos_int(w["window_s"], MAX_SECONDS),
                 "max_uses_per_window needs positive integers n and window_s (at most ten years)")
    _require(isinstance(sc.get("offline_ok", False), bool), "offline_ok must be a boolean")
    if "max_offline_s" in sc:
        _require(_pos_int(sc["max_offline_s"], MAX_SECONDS), "max_offline_s must be a positive integer (at most ten years)")
    if sc.get("offline_ok"):
        _require("max_offline_s" in sc, "offline_ok needs max_offline_s")


def check_grant_shape(g) -> None:
    """Every field spec 3 names, with its type; the budget rule (max_uses
    XOR every scope entry carries max_uses_per_window); identifiers and
    keys in canonical form. Raises GrantError."""
    _require(isinstance(g, dict), "grant is not an object")
    _require(set(g) <= _GRANT_FIELDS, "unknown grant field")
    _require(safe_id(g.get("grant_id"), "grt"), "grant_id is not an identifier")
    issuer, subject, audience = g.get("issuer"), g.get("subject"), g.get("audience")
    _require(isinstance(issuer, dict) and set(issuer) == {"principal", "key"} and isinstance(issuer["principal"], str),
             "issuer must carry principal and key only")
    _require(isinstance(subject, dict) and set(subject) == {"agent", "key"} and isinstance(subject["agent"], str)
             and _HASH_RE.fullmatch(subject["agent"]), "subject must carry a card hash and a key only")
    _require(isinstance(audience, dict) and set(audience) == {"executor"}, "audience must carry executor only")
    try:
        key_bytes(issuer.get("key"))
        key_bytes(subject.get("key"))
        ex = audience.get("executor")
        # the prefixed or the bare key form (#46)
        key_bytes(ex if isinstance(ex, str) and ex.startswith("ed25519:") else "ed25519:%s" % ex)
    except ValueError as e:
        raise GrantError("grant key: %s" % e)
    _require(isinstance(g.get("principal_statement"), str) and bool(g["principal_statement"].strip()),
             "principal_statement missing")
    scope = g.get("scope")
    _require(isinstance(scope, list) and bool(scope), "scope must be a non-empty list")
    for sc in scope:
        check_scope_entry(sc)
    for f in ("not_before", "issued_at", "expires_at"):
        try:
            parse_iso(g.get(f))
        except ValueError:
            raise GrantError("%s is not a timestamp" % f)
    rev = g.get("revocation")
    _require(isinstance(rev, dict) and set(rev) == {"ledger", "max_check_interval_s"} and isinstance(rev["ledger"], str)
             and _pos_int(rev["max_check_interval_s"], MAX_SECONDS),
             "revocation must carry ledger and a positive max_check_interval_s (at most ten years)")
    _require("parent_grant" in g, "parent_grant must be present (null for a root grant)")
    pg = g["parent_grant"]
    _require(pg is None or safe_id(pg, "grt"), "parent_grant is not an identifier")
    windowed = ["max_uses_per_window" in sc for sc in scope]
    if "max_uses" in g:
        _require(_pos_int(g["max_uses"]), "max_uses must be a positive integer")
        _require(not any(windowed), "a grant carries max_uses or per-scope max_uses_per_window, never both")
    else:
        _require(all(windowed), "without max_uses every scope entry needs max_uses_per_window")


def make_delegated_grant(agent_seed: bytes, parent: dict, subject_card: dict, scope: list,
                         statement: str, max_uses: int = 1, ttl_s: int = 86400) -> dict:
    """A depth-one delegation: the parent's subject agent (holder of
    `agent_seed`) hands a strict subset of the parent's scope to another
    agent. Signed by the agent; verify_grant walks it back to the
    principal-signed parent."""
    from . import crypto
    g = {
        "grant_id": new_id("grt"),
        "issuer": {"principal": parent["issuer"]["principal"],
                   "key": "ed25519:" + crypto.b64e(crypto.sign_pub(agent_seed))},
        "subject": {"agent": obj_hash(subject_card), "key": subject_card["agent_key"]},
        "audience": dict(parent["audience"]),
        "scope": scope,
        "principal_statement": statement,
        "max_uses": max_uses,
        "not_before": now_iso(),
        "issued_at": now_iso(),
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(min(time.time() + ttl_s, parse_iso(parent["expires_at"])))),
        "revocation": dict(parent["revocation"]),
        "parent_grant": parent["grant_id"],
    }
    if max_uses is None:
        del g["max_uses"]
    return sign_obj(g, agent_seed)


def _rule_narrower(child, parent) -> bool:
    """Is the child's constraint at least as tight as the parent's? Every
    operator the parent uses must appear in the child with an equal or
    narrower argument (in: subset; range: inside; regex: identical)."""
    if "in" in parent:
        if "in" not in child or not all(any(_same(x, y) for y in parent["in"]) for x in child["in"]):
            return False
    if "range" in parent:
        if "range" not in child or child["range"][0] < parent["range"][0] or child["range"][1] > parent["range"][1]:
            return False
    if "regex" in parent and child.get("regex") != parent["regex"]:
        return False
    return True


def scope_entry_within(child: dict, parent: dict) -> bool:
    """Is a (shape-checked) child scope entry a subset of a parent entry?
    Same action and resource; the child's key allowlist inside the
    parent's; every parent value constraint present and no wider in the
    child; a child budget or offline allowance no larger than the parent's."""
    if child["action"] != parent["action"] or child["resource"] != parent["resource"]:
        return False
    cp, pp = child.get("params", {}), parent.get("params", {})
    if not set(cp.get("keys", [])) <= set(pp.get("keys", [])):
        return False
    cv, pv = cp.get("values", {}), pp.get("values", {})
    for k, rule in pv.items():
        if k not in cv or not _rule_narrower(cv[k], rule):
            return False
    if "max_uses_per_window" in parent:
        cw, pw = child.get("max_uses_per_window"), parent["max_uses_per_window"]
        if cw is None or cw["n"] > pw["n"] or cw["window_s"] < pw["window_s"]:
            return False
    if child.get("offline_ok") and (not parent.get("offline_ok") or child["max_offline_s"] > parent["max_offline_s"]):
        return False
    return True


def verify_grant(grant: dict, issuers, subject_card: dict = None, parent: dict = None, now=None,
                 parent_subject_card: dict = None) -> None:
    """A grant is valid when it is well formed, inside its validity
    window, every scope action is inside the subject card's capabilities
    (when the card is given), and its chain roots in a pinned principal:
    a root grant (parent_grant null) is signed by one of `issuers`
    (bare-b64 principal keys; an empty set fails closed); a delegated
    grant names a parent (which the caller supplies, having looked it up
    by that id), the parent is itself a valid ROOT grant, the child is
    signed by the parent's subject key, shares the parent's audience,
    lies inside the parent's validity window, and every child scope
    entry is a subset of some parent entry. The parent is verified with
    its own subject's card (parent_subject_card, which must be the card
    the parent names by hash and key): a parent whose subject lacks a
    capability is invalid, so it cannot delegate what it could never
    exercise. Raises GrantError."""
    check_grant_shape(grant)
    t = time.time() if now is None else now
    ik = grant["issuer"]["key"][len("ed25519:"):]
    if grant["parent_grant"] is None:
        issuers = {r for r in (issuers or ()) if isinstance(r, str)}
        _require(bool(issuers), "no pinned principal to check the issuer against")
        _require(ik in issuers, "issuer not a pinned principal")
    else:
        _require(parent is not None, "parent grant %s not held" % grant["parent_grant"])
        _require(isinstance(parent, dict) and parent.get("grant_id") == grant["parent_grant"], "parent grant id mismatch")
        _require(parent.get("parent_grant") is None, "delegation depth is one")
        _require(isinstance(parent_subject_card, dict), "parent grant's subject card not resolved")
        _require(obj_hash(parent_subject_card) == parent.get("subject", {}).get("agent")
                 and parent_subject_card.get("agent_key") == parent.get("subject", {}).get("key"),
                 "parent grant's subject card is not the card the parent names")
        verify_grant(parent, issuers, subject_card=parent_subject_card, now=now)
        _require(grant["issuer"]["key"] == parent["subject"]["key"], "delegated grant not issued by the parent's subject")
        _require(grant["audience"] == parent["audience"], "delegated grant changes the audience")
        # the child is revoked wherever the parent is: same feed, same interval
        _require(grant["revocation"] == parent["revocation"],
                 "delegated grant changes the revocation feed or its check interval")
        _require(parse_iso(grant["not_before"]) >= parse_iso(parent["not_before"])
                 and parse_iso(grant["expires_at"]) <= parse_iso(parent["expires_at"]),
                 "delegated grant outlives its parent")
        if "max_uses" in parent:
            _require("max_uses" in grant and grant["max_uses"] <= parent["max_uses"],
                     "delegated grant budget exceeds the parent's")
        for sc in grant["scope"]:
            _require(any(scope_entry_within(sc, psc) for psc in parent["scope"]),
                     "delegated scope entry %s is not a subset of the parent's" % sc["action"])
    _require(verify_obj(grant, ik), "bad grant signature")
    _require(parse_iso(grant["not_before"]) <= t, "grant not yet valid")
    _require(parse_iso(grant["expires_at"]) > t, "grant expired")
    if subject_card is not None:
        _require(isinstance(subject_card, dict) and isinstance(subject_card.get("capabilities"), list)
                 and all(isinstance(c, str) for c in subject_card["capabilities"]),
                 "subject card is malformed: capabilities must be a list of strings")
        caps = set(subject_card["capabilities"])
        for sc in grant["scope"]:
            _require(sc["action"] in caps, "scope action %s outside the subject card's capabilities" % sc["action"])


def _value_ok(rule, v) -> bool:
    if "in" in rule and not any(_same(v, x) for x in rule["in"]):
        return False
    if "range" in rule:
        lo, hi = rule["range"]
        if not _number(v) or not (lo <= v <= hi):
            return False
    if "regex" in rule and (not isinstance(v, str) or re.fullmatch(rule["regex"], v) is None):
        return False
    return True


def grant_covers(grant: dict, action, resource, params):
    """The first scope entry covering this action, resource and params as
    (index, entry), or None; GrantError for a malformed scope. See
    covering_entries."""
    found = covering_entries(grant, action, resource, params)
    return found[0] if found else None


def covering_entries(grant: dict, action, resource, params):
    """Every scope entry covering this action, resource and params, as
    (index, entry) pairs in scope order. The index is the entry's
    position in the signed scope list - the executor accounts uses under
    it, so two entries that differ only in a constraint value are charged
    separately, and an entry whose budget is spent does not hide a later
    entry that still covers the request. params.keys is the allowlist (a
    parameter outside it refuses); every key under params.values must be
    present and satisfy its constraint; comparisons never cross JSON
    types."""
    # the scope is checked against the closed grammar before it is walked:
    # a caller that did not run check_grant_shape first gets GrantError for
    # a malformed scope, never a match on an operator this grammar lacks
    scope = grant.get("scope") if isinstance(grant, dict) else None
    _require(isinstance(scope, list) and bool(scope), "scope must be a non-empty list")
    for sc in scope:
        check_scope_entry(sc)
    found = []
    if not isinstance(params, dict):
        return found
    for i, sc in enumerate(scope):
        if sc.get("action") != action or sc.get("resource") != resource:
            continue
        p = sc.get("params", {})
        allowed = set(p.get("keys", []))
        if not set(params) <= allowed:
            continue
        values = p.get("values", {})
        if not all(k in params and _value_ok(rule, params[k]) for k, rule in values.items()):
            continue
        found.append((i, sc))
    return found


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

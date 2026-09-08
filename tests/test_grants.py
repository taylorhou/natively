"""Grant enforcement (review 2026-09-07, point 3, first half): a grant
runs the spec 3 checks - pinned issuer (a missing pin fails closed), the
full schema, real timestamps, the closed constraint grammar on values,
subject and audience binding, host-bound resources, card capabilities,
budgets counted from the ledger (max_uses and rolling windows) - and one
message executes its action once."""
import json
import os
import time

import pytest

from natively import crypto, envelope

from conftest import (Principal, agent_key, issue_grant, ledger_entries, make_node, outcomes, pump,
                      resource, send_action, uses)


def _iso(offset_s):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + offset_s))


def _pair(tmp_path, hub, principal, caps=("test.ping",)):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": list(caps)})
    return n1, n2


def _checks(node):
    return [(e["outcome"], e["grant_id"]) for e in ledger_entries(node) if e["action"] == "grant.check"]


# ---------- envelope-level checks ----------

def test_missing_pins_fail_closed(principal):
    node_seed, agent_seed = crypto.gen_signing_key(), crypto.gen_signing_key()
    card = envelope.make_card(agent_seed, crypto.sign_pub(node_seed), principal.seed, ["test.ping"], "")
    assert envelope.verify_card(card, {principal.pub})
    assert not envelope.verify_card(card, set())
    assert not envelope.verify_card(card, None)
    assert not envelope.verify_card(card, {Principal().pub})
    g = envelope.make_grant(principal.seed, "p", card, "ed25519:" + crypto.b64e(crypto.sign_pub(node_seed)),
                            [{"action": "test.ping", "resource": "host:ed25519:%s:ping" % crypto.b64e(crypto.sign_pub(node_seed)), "params": {}}], "s")
    envelope.verify_grant(g, {principal.pub})
    for pins in (set(), None, {Principal().pub}):
        with pytest.raises(envelope.GrantError):
            envelope.verify_grant(g, pins)


def test_key_references_are_canonical():
    raw = crypto.sign_pub(crypto.gen_signing_key())
    good = "ed25519:" + crypto.b64e(raw)
    assert envelope.key_bytes(good) == raw
    for bad in (good[len("ed25519:"):], "rsa:" + good[8:], good + "=", good[:-4] + "A===",
                "ed25519:" + crypto.b64e(raw[:-1]), "ed25519:" + crypto.b64e(raw + b"\x00"), None, 5,
                "ed25519:" + crypto.b64e(raw).replace("=", "")):
        with pytest.raises(ValueError):
            envelope.key_bytes(bad)
    # a signature checked under a malformed key is False, never an exception
    assert envelope.verify_obj({"a": 1, "sig": "AAAA"}, "not-a-key") is False
    assert envelope.verify_obj({"a": 1}, good) is False


def _grant(principal, card, node_pub, scope=None, **kw):
    return envelope.make_grant(principal.seed, "p", card, "ed25519:" + crypto.b64e(node_pub),
                               scope or [{"action": "test.ping", "resource": "host:ed25519:%s:ping" % crypto.b64e(node_pub), "params": {}}],
                               "words", **kw)


def test_grant_dates_are_compared_as_instants(principal):
    node_seed, agent_seed = crypto.gen_signing_key(), crypto.gen_signing_key()
    node_pub = crypto.sign_pub(node_seed)
    card = envelope.make_card(agent_seed, node_pub, principal.seed, ["test.ping"], "")
    g = _grant(principal, card, node_pub)
    envelope.verify_grant(g, {principal.pub})
    for field, value, why in (("expires_at", _iso(-1), "expired"), ("not_before", _iso(3600), "not yet"),
                              ("expires_at", "garbage", "timestamp"), ("expires_at", "2030-01-01T00:00:00+02:00", "timestamp"),
                              ("issued_at", None, "timestamp")):
        bad = envelope.sign_obj(dict(g, **{field: value}), principal.seed)
        with pytest.raises(envelope.GrantError, match=why):
            envelope.verify_grant(bad, {principal.pub})
    # expiry is exclusive: a grant at its own expires_at is expired
    at = envelope.parse_iso(g["expires_at"])
    with pytest.raises(envelope.GrantError, match="expired"):
        envelope.verify_grant(g, {principal.pub}, now=at)
    envelope.verify_grant(g, {principal.pub}, now=at - 1)


def test_grant_schema_is_closed(principal):
    node_seed, agent_seed = crypto.gen_signing_key(), crypto.gen_signing_key()
    node_pub = crypto.sign_pub(node_seed)
    card = envelope.make_card(agent_seed, node_pub, principal.seed, ["test.ping", "svc.restart"], "")
    res = "host:ed25519:%s:ping" % crypto.b64e(node_pub)
    ok = _grant(principal, card, node_pub)
    envelope.verify_grant(ok, {principal.pub}, subject_card=card)

    def refused(why, **changes):
        bad = envelope.sign_obj(dict(ok, **changes), principal.seed)
        with pytest.raises(envelope.GrantError, match=why):
            envelope.verify_grant(bad, {principal.pub}, subject_card=card)

    refused("principal_statement", principal_statement="   ")
    refused("scope", scope=[])
    refused("resource", scope=[{"action": "test.ping", "resource": 5, "params": {}}])
    # a resource is an opaque label (spec 3): the bare and the empty form are legal
    for label in ("ping", ""):
        envelope.verify_grant(envelope.sign_obj(dict(ok, scope=[{"action": "test.ping", "resource": label, "params": {}}]),
                                                principal.seed), {principal.pub}, subject_card=card)
    refused("unknown scope field", scope=[{"action": "test.ping", "resource": res, "params": {}, "extra": 1}])
    refused("operator", scope=[{"action": "test.ping", "resource": res, "params": {"keys": ["x"], "values": {"x": {"gt": 1}}}}])
    refused("outside params.keys", scope=[{"action": "test.ping", "resource": res, "params": {"keys": [], "values": {"x": {"in": [1]}}}}])
    refused("range", scope=[{"action": "test.ping", "resource": res, "params": {"keys": ["x"], "values": {"x": {"range": [2, 1]}}}}])
    refused("regex", scope=[{"action": "test.ping", "resource": res, "params": {"keys": ["x"], "values": {"x": {"regex": "("}}}}])
    refused("max_uses", max_uses=0)
    refused("max_uses", max_uses=1.5)
    refused("max_uses", max_uses=True)
    refused("never both", scope=[{"action": "test.ping", "resource": res, "params": {}, "max_uses_per_window": {"n": 1, "window_s": 60}}])
    refused("max_uses_per_window", scope=[{"action": "test.ping", "resource": res, "params": {}, "max_uses_per_window": {"n": 0, "window_s": 60}}])
    refused("max_offline_s", scope=[{"action": "test.ping", "resource": res, "params": {}, "offline_ok": True}])
    refused("max_offline_s", scope=[{"action": "test.ping", "resource": res, "params": {}, "offline_ok": False, "max_offline_s": "forever"}])
    refused("ten years", scope=[{"action": "test.ping", "resource": res, "params": {}, "max_uses_per_window": {"n": 1, "window_s": 10 ** 9}}])
    refused("ten years", revocation={"ledger": "", "max_check_interval_s": 10 ** 12})
    # an integer beyond 2^53 has no exact double: JCS refuses to sign it at all
    with pytest.raises(ValueError, match="double"):
        envelope.sign_obj(dict(ok, max_uses=2 ** 53 + 1), principal.seed)
    refused("regex", scope=[{"action": "test.ping", "resource": res, "params": {"keys": ["x"], "values": {"x": {"regex": "a{4294967296}"}}}}])
    # a non-finite float (1e400 parses to inf) cannot be signed at all - JCS
    # refuses it - and the grammar refuses it on its own too
    with pytest.raises(envelope.GrantError, match="range"):
        envelope.check_scope_entry({"action": "test.ping", "resource": res, "params": {"keys": ["x"], "values": {"x": {"range": [0, float("inf")]}}}})
    with pytest.raises(envelope.GrantError, match="scalars"):
        envelope.check_scope_entry({"action": "test.ping", "resource": res, "params": {"keys": ["x"], "values": {"x": {"in": [float("nan")]}}}})
    refused("unknown grant field", extra_field=1)
    refused("issuer", issuer=dict(ok["issuer"], note="x"))
    refused("subject", subject=dict(ok["subject"], extra=1))
    refused("audience", audience=dict(ok["audience"], also="me"))
    refused("revocation", revocation={"ledger": ""})
    refused("revocation", revocation={"ledger": "", "max_check_interval_s": 0})
    refused("parent_grant", parent_grant="../x")
    refused("capabilities", scope=[{"action": "node.config.set", "resource": res, "params": {}}])
    refused("grant key", audience={"executor": "any"})
    with pytest.raises(envelope.GrantError, match="signature"):
        envelope.verify_grant(dict(ok, principal_statement="other words"), {principal.pub})  # tampered, not re-signed
    # without max_uses EVERY scope entry needs a window, not just one
    windowed = {"action": "test.ping", "resource": res, "params": {}, "max_uses_per_window": {"n": 2, "window_s": 60}}
    plain = {"action": "svc.restart", "resource": res, "params": {}}
    g = dict(ok, scope=[windowed, plain])
    del g["max_uses"]
    with pytest.raises(envelope.GrantError, match="every scope entry"):
        envelope.verify_grant(envelope.sign_obj(g, principal.seed), {principal.pub})
    g["scope"] = [windowed, dict(plain, max_uses_per_window={"n": 1, "window_s": 3600})]
    envelope.verify_grant(envelope.sign_obj(g, principal.seed), {principal.pub}, subject_card=card)


def test_params_are_constrained_by_value_with_a_closed_allowlist():
    res = "host:ed25519:%s:cfg" % crypto.b64e(crypto.sign_pub(crypto.gen_signing_key()))
    g = {"scope": [{"action": "cfg.set", "resource": res,
                    "params": {"keys": ["n", "mode", "name"],
                               "values": {"n": {"in": [1, 2, 4]}, "mode": {"regex": "fast|slow"}, "name": {"range": [0, 10]}}}}]}
    ok = {"n": 2, "mode": "fast", "name": 3}
    assert envelope.grant_covers(g, "cfg.set", res, ok)
    assert envelope.grant_covers(g, "cfg.set", res, dict(ok, name=10)) and envelope.grant_covers(g, "cfg.set", res, dict(ok, name=0))
    assert envelope.grant_covers(g, "cfg.set", res, dict(ok, n=2.0))  # JSON has one number type: 2.0 is 2 (JCS writes both as 2)
    for params in (dict(ok, extra=1),             # a key outside the allowlist
                   dict(ok, n=True),               # True is not 1
                   dict(ok, n="2"),                # "2" is not 2
                   dict(ok, n=3),
                   dict(ok, mode="faster"),        # regex is a full match
                   dict(ok, mode=1),               # regex applies to strings only
                   dict(ok, name="3"),             # range applies to numbers only
                   dict(ok, name=True),
                   dict(ok, name=11),
                   {"n": 2, "mode": "fast"},       # a constrained key must be present
                   [], None, "n=2"):
        assert envelope.grant_covers(g, "cfg.set", res, params) is None, params
    assert envelope.grant_covers(g, "cfg.get", res, ok) is None
    assert envelope.grant_covers(g, "cfg.set", res + "2", ok) is None
    # an allowlist with no value constraints: only the listed keys, any value
    g2 = {"scope": [{"action": "cfg.set", "resource": res, "params": {"keys": ["n"]}}]}
    assert envelope.grant_covers(g2, "cfg.set", res, {"n": "anything"}) and envelope.grant_covers(g2, "cfg.set", res, {})
    assert envelope.grant_covers(g2, "cfg.set", res, {"m": 1}) is None


# ---------- node-level enforcement ----------

def test_grant_for_another_executor_is_information(tmp_path, hub, principal):
    n1, n2 = _pair(tmp_path, hub, principal)
    other = make_node(tmp_path, "n3", hub.url, principal, {"gamma": ["test.ping"]})
    g = issue_grant(n2, "beta", principal, executor=other.node_key)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == []
    assert ("wrong-executor", g["grant_id"]) in _checks(n2)
    # the receiving agent's own key is a valid executor too
    g2 = issue_grant(n2, "beta", principal, executor=agent_key(n2, "beta"))
    send_action(n1, "alpha", n2, "beta", [g2["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]


def test_host_bound_resource_names_this_node(tmp_path, hub, principal):
    n1, n2 = _pair(tmp_path, hub, principal)
    other = make_node(tmp_path, "n3", hub.url, principal, {"gamma": ["test.ping"]})
    foreign = resource(other)
    g = issue_grant(n2, "beta", principal, scope=[{"action": "test.ping", "resource": foreign, "params": {}}])
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]], res=foreign)
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == []
    assert ("wrong-host", g["grant_id"]) in _checks(n2)
    # a label is matched literally (spec 3): a request for another label
    # is out of scope, and the empty label is a legal resource
    g2 = issue_grant(n2, "beta", principal)
    send_action(n1, "alpha", n2, "beta", [g2["grant_id"]], res="host:any:ping")
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == []
    assert ("out-of-scope", g2["grant_id"]) in _checks(n2)
    g3 = issue_grant(n2, "beta", principal, scope=[{"action": "test.ping", "resource": "", "params": {}}])
    send_action(n1, "alpha", n2, "beta", [g3["grant_id"]], res="")
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]


def test_scope_outside_card_capabilities_is_invalid(tmp_path, hub, principal):
    n1, n2 = _pair(tmp_path, hub, principal, caps=("msg.send",))  # beta may not ping
    g = issue_grant(n2, "beta", principal)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == []
    assert [c for c in _checks(n2) if c[0] == "invalid"] == [("invalid", g["grant_id"])]


def test_grant_subject_key_must_match(tmp_path, hub, principal):
    n1, n2 = _pair(tmp_path, hub, principal)
    g = issue_grant(n2, "beta", principal)
    # same card hash, a different subject key: the signed object changes, so
    # the signature check catches it first
    forged = envelope.sign_obj(dict(g, subject=dict(g["subject"], key=agent_key(n1, "alpha"))), principal.seed)
    json.dump(forged, open(os.path.join(n2.home, "grants", g["grant_id"] + ".json"), "w"))
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == []
    assert ("wrong-subject", g["grant_id"]) in _checks(n2)


def test_one_message_executes_once_with_several_valid_grants(tmp_path, hub, principal):
    n1, n2 = _pair(tmp_path, hub, principal)
    g1 = issue_grant(n2, "beta", principal, max_uses=3)
    g2 = issue_grant(n2, "beta", principal, max_uses=3)
    send_action(n1, "alpha", n2, "beta", [g1["grant_id"], g2["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    assert uses(n2, g1["grant_id"]) == 1 and uses(n2, g2["grant_id"]) == 0
    # the first grant failing falls through to the second, still one ping
    exhausted = issue_grant(n2, "beta", principal, max_uses=1)
    send_action(n1, "alpha", n2, "beta", [exhausted["grant_id"]])
    pump([n1, n2], 3)
    send_action(n1, "alpha", n2, "beta", [exhausted["grant_id"], g2["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok", "ok", "ok"]
    assert ("exhausted", exhausted["grant_id"]) in _checks(n2)
    assert uses(n2, g2["grant_id"]) == 1


def test_max_uses_is_counted_from_the_ledger(tmp_path, hub, principal):
    n1, n2 = _pair(tmp_path, hub, principal)
    g = issue_grant(n2, "beta", principal, max_uses=2)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    # the state file is lost: the ledger still remembers the use
    n2.stop()
    os.unlink(os.path.join(n2.home, "state.json"))
    from natively import node as nodemod
    time.sleep(1.1)  # a node re-registers only once the clock has passed its last registration second
    n2b = nodemod.Node(n2.home)
    n2b.start()
    assert n2b._last_reg_time  # registered: the restart was not inside the last registration's second
    for _ in range(2):
        send_action(n1, "alpha", n2b, "beta", [g["grant_id"]])
        pump([n1, n2b], 3)
    assert outcomes(n2b, "test.ping") == ["ok", "ok"]
    assert ("exhausted", g["grant_id"]) in _checks(n2b)
    assert uses(n2b, g["grant_id"]) == 2


def test_rolling_window_limit_is_enforced(tmp_path, hub, principal):
    n1, n2 = _pair(tmp_path, hub, principal)
    g = issue_grant(n2, "beta", principal, max_uses=None,
                    scope=[{"action": "test.ping", "resource": resource(n2), "params": {},
                            "max_uses_per_window": {"n": 2, "window_s": 3600}}])
    for _ in range(3):
        send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
        pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok", "ok"]
    assert ("exhausted", g["grant_id"]) in _checks(n2)
    # older executions fall out of the window
    entries = ledger_entries(n2)
    old = _iso(-7200)
    for e in entries:
        if e["action"] == "test.ping":
            e["ts"] = old
    # (rewrite the ledger with aged rows; the chain is not the subject here)
    with open(n2.ledger.path, "w") as f:
        for e in entries:
            f.write(json.dumps(e, separators=(",", ":")) + "\n")
    assert uses(n2, g["grant_id"], ) == 2
    assert n2._grant_uses(g["grant_id"], since=time.time() - 3600) == 0
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping").count("ok") == 3


def test_malformed_action_body_is_information(tmp_path, hub, principal):
    n1, n2 = _pair(tmp_path, hub, principal)
    g = issue_grant(n2, "beta", principal)
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "action", "action": "test.ping", "params": "x"},
                  grant_ids=[g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == []
    assert "malformed-action" in outcomes(n2, "grant.check")
    assert uses(n2, g["grant_id"]) == 0


def test_unsupported_action_is_refused_once(tmp_path, hub, principal):
    n1, n2 = _pair(tmp_path, hub, principal, caps=("svc.restart",))
    g = issue_grant(n2, "beta", principal, max_uses=5,
                    scope=[{"action": "svc.restart", "resource": resource(n2, "svc"), "params": {}}])
    send_action(n1, "alpha", n2, "beta", [g["grant_id"], g["grant_id"]], action="svc.restart", res=resource(n2, "svc"))
    pump([n1, n2], 3)
    assert outcomes(n2, "svc.restart") == ["unsupported"]
    assert "refused" in outcomes(n2, "msg.recv")
    assert uses(n2, g["grant_id"]) == 0


def test_rolling_windows_are_counted_per_scope_entry(tmp_path, hub, principal):
    n1, n2 = _pair(tmp_path, hub, principal)
    g = issue_grant(n2, "beta", principal, max_uses=None,
                    scope=[{"action": "test.ping", "resource": resource(n2, "a"), "params": {},
                            "max_uses_per_window": {"n": 1, "window_s": 3600}},
                           {"action": "test.ping", "resource": resource(n2, "b"), "params": {},
                            "max_uses_per_window": {"n": 1, "window_s": 3600}}])
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]], res=resource(n2, "a"))
    pump([n1, n2], 3)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]], res=resource(n2, "a"))
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    assert ("exhausted", g["grant_id"]) in _checks(n2)
    # the second scope entry has its own window: one more execution
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]], res=resource(n2, "b"))
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok", "ok"]
    rows = [e for e in ledger_entries(n2) if e["action"] == "test.ping"]
    assert [e["scope"] for e in rows] == [0, 1]
    assert n2._grant_uses(g["grant_id"], scope=0) == 1 and n2._grant_uses(g["grant_id"], scope=1) == 1
    assert n2._grant_uses(g["grant_id"]) == 2


def test_window_accounting_never_lets_a_use_leave_early():
    """Ledger timestamps are whole seconds; a use recorded at T is treated
    as possibly at T+0.999, so a cutoff between T and T+1 keeps it."""
    from natively.ledger import Ledger
    import tempfile

    class N:
        _grant_uses = __import__("natively.node", fromlist=["Node"]).Node._grant_uses
    n = N()
    d = tempfile.mkdtemp()
    n.ledger = Ledger(os.path.join(d, "ledger.jsonl"))
    e = n.ledger.append("agent:a", "grt_" + "0" * 26, "test.ping", {}, "ok", "pong")
    t = envelope.parse_iso(e["ts"])
    assert n._grant_uses("grt_" + "0" * 26, since=t + 0.5) == 1   # cutoff inside the recorded second: still counted
    assert n._grant_uses("grt_" + "0" * 26, since=t + 1.0) == 0   # a full second later: out of the window


def test_numeric_constraints_mean_the_same_whatever_their_signed_spelling():
    """JCS canonicalizes 0 and 0.0 to the same bytes, so a constraint
    written either way is the same signed document: it must authorize
    the same requests, or a value could change what a signature covers."""
    res = "host:ed25519:%s:cfg" % crypto.b64e(crypto.sign_pub(crypto.gen_signing_key()))
    for spelled in (0, 0.0):
        g = {"scope": [{"action": "cfg.set", "resource": res, "params": {"keys": ["x"], "values": {"x": {"in": [spelled]}}}}]}
        assert envelope.grant_covers(g, "cfg.set", res, {"x": 0})
        assert envelope.grant_covers(g, "cfg.set", res, {"x": 0.0})
        assert envelope.grant_covers(g, "cfg.set", res, {"x": False}) is None  # a bool is never a number
        assert envelope.grant_covers(g, "cfg.set", res, {"x": "0"}) is None


def test_a_use_is_charged_to_the_scope_entry_that_matched(tmp_path, hub, principal):
    """Two entries alike except for one constraint value: a request that
    matches the second must spend the second's window, not the first's.
    Otherwise a look-alike entry can be exhausted by requests it never
    covered, and its own valid requests refused."""
    n1, n2 = _pair(tmp_path, hub, principal)
    res = resource(n2)
    e_true = {"action": "test.ping", "resource": res, "params": {"keys": ["x"], "values": {"x": {"in": [True]}}},
              "max_uses_per_window": {"n": 1, "window_s": 3600}}
    e_one = {"action": "test.ping", "resource": res, "params": {"keys": ["x"], "values": {"x": {"in": [1]}}},
             "max_uses_per_window": {"n": 1, "window_s": 3600}}
    g = issue_grant(n2, "beta", principal, scope=[e_true, e_one], max_uses=None)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]], params={"x": 1})  # matches entry 1 only
    pump([n1, n2], 4)
    assert outcomes(n2, "test.ping") == ["ok"]
    rows = [e for e in ledger_entries(n2) if e["action"] == "test.ping"]
    assert rows[-1]["scope"] == 1
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]], params={"x": True})  # entry 0 still has its one use
    pump([n1, n2], 4)
    assert outcomes(n2, "test.ping") == ["ok", "ok"]
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]], params={"x": 1})  # entry 1 is spent
    pump([n1, n2], 4)
    assert outcomes(n2, "test.ping") == ["ok", "ok"]
    assert _checks(n2)[-1][0] == "exhausted"


def test_subject_hash_is_exactly_64_hex_characters(principal):
    node_seed, agent_seed = crypto.gen_signing_key(), crypto.gen_signing_key()
    node_key = "ed25519:" + crypto.b64e(crypto.sign_pub(node_seed))
    card = envelope.make_card(agent_seed, crypto.sign_pub(node_seed), principal.seed, ["test.ping"], "")
    res = "host:%s:ping" % node_key
    ok = envelope.make_grant(principal.seed, "p", card, node_key, [{"action": "test.ping", "resource": res, "params": {}}], "ping", max_uses=1)
    envelope.verify_grant(ok, {principal.pub}, subject_card=card)
    for bad in (ok["subject"]["agent"] + "\n", ok["subject"]["agent"][:-1], ok["subject"]["agent"].upper()):
        g = envelope.sign_obj(dict(ok, subject={"agent": bad, "key": ok["subject"]["key"]}), principal.seed)
        with pytest.raises(envelope.GrantError, match="subject"):
            envelope.verify_grant(g, {principal.pub}, subject_card=card)


def test_parse_iso_accepts_only_real_instants_in_the_one_shape():
    assert envelope.parse_iso("2030-01-01T00:00:59Z") == 1893456059.0
    for bad in ("2030-01-01T00:00:61Z", "2030-02-30T00:00:00Z", "2030-1-01T00:00:00Z", "2030-01-01T00:00:00",
                "2030-01-01T00:00:00+00:00", "2030-01-01 00:00:00Z", " 2030-01-01T00:00:00Z", 1893456000, None):
        with pytest.raises(ValueError):
            envelope.parse_iso(bad)


def test_a_signature_verifies_under_exactly_one_spelling():
    seed = crypto.gen_signing_key()
    pub = crypto.b64e(crypto.sign_pub(seed))
    o = envelope.sign_obj({"a": 1}, seed)
    assert envelope.verify_obj(o, pub)
    sig = o["sig"]
    for bad in ("!@" + sig, sig + "!@", sig[:-1], sig + "=", sig.rstrip("=") , " " + sig, sig.lower(), 7, None):
        assert not envelope.verify_obj(dict(o, sig=bad), pub), bad
    # the last base64 character carries two padding bits: another value there is another spelling of the same bytes
    alt = sig[:-2] + chr(ord(sig[-2]) + 1) + sig[-1]
    assert not envelope.verify_obj(dict(o, sig=alt), pub)


def test_a_use_of_unknown_age_counts_against_every_window(tmp_path, hub, principal, monkeypatch):
    """A ledger execution row whose ts cannot be parsed is a use whose age
    is unknown: it counts against the window (unknown never frees budget)."""
    n1, n2 = _pair(tmp_path, hub, principal)
    res = resource(n2)
    g = issue_grant(n2, "beta", principal, max_uses=None,
                    scope=[{"action": "test.ping", "resource": res, "params": {}, "max_uses_per_window": {"n": 1, "window_s": 3600}}])
    real_strftime = time.strftime
    monkeypatch.setattr(time, "strftime", lambda *a, **k: "not-a-time")
    n2.ledger.append("agent:beta", g["grant_id"], "test.ping", {}, "ok", "pong", scope=0)
    monkeypatch.setattr(time, "strftime", real_strftime)
    assert n2._grant_uses(g["grant_id"], since=time.time() - 3600, scope=0) == 1
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]  # only the injected row: the window is spent by the use of unknown age
    assert _checks(n2)[-1][0] == "exhausted"


def test_a_spent_scope_entry_does_not_hide_a_later_entry_that_covers(tmp_path, hub, principal):
    """Overlapping entries x in [1,2] and x in [2,3], one use per window
    each: after x=1 spends entry 0, x=2 runs under entry 1 (charged to
    index 1), and only when both are spent is the grant exhausted."""
    n1, n2 = _pair(tmp_path, hub, principal)
    res = resource(n2)
    w = {"n": 1, "window_s": 3600}
    g = issue_grant(n2, "beta", principal, max_uses=None, scope=[
        {"action": "test.ping", "resource": res, "params": {"keys": ["x"], "values": {"x": {"in": [1, 2]}}}, "max_uses_per_window": w},
        {"action": "test.ping", "resource": res, "params": {"keys": ["x"], "values": {"x": {"in": [2, 3]}}}, "max_uses_per_window": w}])
    for x, expected in ((1, ["ok"]), (2, ["ok", "ok"]), (2, ["ok", "ok"]), (3, ["ok", "ok"])):
        send_action(n1, "alpha", n2, "beta", [g["grant_id"]], params={"x": x})
        pump([n1, n2], 3)
        assert outcomes(n2, "test.ping") == expected, x
    rows = [e for e in ledger_entries(n2) if e["action"] == "test.ping"]
    assert [r["scope"] for r in rows] == [0, 1]
    assert [c[0] for c in _checks(n2)].count("exhausted") == 2


def test_a_malformed_subject_card_is_a_grant_error_not_a_crash(principal):
    node_seed, agent_seed = crypto.gen_signing_key(), crypto.gen_signing_key()
    node_key = "ed25519:" + crypto.b64e(crypto.sign_pub(node_seed))
    card = envelope.make_card(agent_seed, crypto.sign_pub(node_seed), principal.seed, ["test.ping"], "")
    g = envelope.make_grant(principal.seed, "p", card, node_key,
                            [{"action": "test.ping", "resource": "host:%s:ping" % node_key, "params": {}}], "ping", max_uses=1)
    for bad in ([], "card", {"capabilities": [{}]}, {"capabilities": "test.ping"}, {}):
        with pytest.raises(envelope.GrantError, match="malformed"):
            envelope.verify_grant(g, {principal.pub}, subject_card=bad)


def test_card_version_is_the_integer_one(principal):
    """True == 1 in Python; a card whose version is the boolean is not
    version 1 and verifies nothing."""
    node_seed, agent_seed = crypto.gen_signing_key(), crypto.gen_signing_key()
    card = envelope.make_card(agent_seed, crypto.sign_pub(node_seed), principal.seed, ["test.ping"], "")
    assert envelope.verify_card(card, {principal.pub})
    bad = envelope.sign_obj(dict(card, card_version=True), principal.seed)
    assert not envelope.verify_card(bad, {principal.pub})
    assert not envelope.verify_card(envelope.sign_obj(dict(card, card_version=2), principal.seed), {principal.pub})


def test_a_malformed_scope_is_refused_at_mint(principal):
    """Signing a scope the executors will refuse helps nobody: make_grant
    checks the closed grammar first (the dict-shaped scope of the first
    cross-principal exchange, a resource that is not a string, an unknown
    field)."""
    node_seed, agent_seed = crypto.gen_signing_key(), crypto.gen_signing_key()
    node_pub = crypto.sign_pub(node_seed)
    card = envelope.make_card(agent_seed, node_pub, principal.seed, ["test.ping"], "")
    res = "host:ed25519:%s:ping" % crypto.b64e(node_pub)
    for scope in ({"caps": ["test.ping"]}, [], [{"action": "test.ping", "resource": 5}],
                  [{"action": "test.ping", "resource": res, "params": {}, "extra": 1}]):
        with pytest.raises(ValueError, match="malformed scope"):
            envelope.make_grant(principal.seed, "p", card, "ed25519:" + crypto.b64e(node_pub), scope, "words")
    envelope.make_grant(principal.seed, "p", card, "ed25519:" + crypto.b64e(node_pub),
                        [{"action": "test.ping", "resource": res, "params": {}}], "words")


def test_grant_covers_refuses_a_malformed_scope():
    """The helper keeps its contract on its own: a scope that is not the
    closed grammar is GrantError, never an AttributeError and never a
    silent match on an operator the grammar lacks."""
    res = "host:ed25519:%s:ping" % crypto.b64e(crypto.sign_pub(crypto.gen_signing_key()))
    with pytest.raises(envelope.GrantError, match="scope"):
        envelope.grant_covers({"scope": {"caps": ["test.ping"]}}, "test.ping", res, {})
    with pytest.raises(envelope.GrantError, match="operator"):
        envelope.grant_covers({"scope": [{"action": "test.ping", "resource": res,
                                          "params": {"keys": ["x"], "values": {"x": {"gt": 1}}}}]}, "test.ping", res, {"x": 5})
    with pytest.raises(envelope.GrantError):
        envelope.covering_entries({"scope": []}, "test.ping", res, {})
    assert envelope.grant_covers({"scope": [{"action": "test.ping", "resource": res, "params": {}}]}, "test.ping", res, {}) is not None


def test_the_senders_ledger_row_names_a_grant_id_or_none(tmp_path, hub, principal):
    """A grant id that is not an identifier in an outbound request (a CLI
    typo, a list where a string goes) never reaches the sender's ledger
    row - and never crashes the flush."""
    n1, n2 = _pair(tmp_path, hub, principal)
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "x"}, grant_ids=[{}, [], "nope"])
    pump([n1, n2], 3)
    sent = [e for e in ledger_entries(n1) if e["action"] == "msg.send"]
    assert len(sent) == 1 and sent[0]["grant_id"] is None
    assert n1.ledger.verify_chain()
    n2.step()  # the receiver lives through it too, whatever it makes of the ids


def test_a_crash_before_the_batch_save_does_not_let_a_message_execute_twice(tmp_path, hub, principal):
    """The seen entry is on disk before the action runs. A process that
    dies after executing and before the end-of-poll save comes back
    knowing the message; a resubmission of the same msg_id executes
    nothing."""
    from conftest import http
    from natively import node as nodemod
    n1, n2 = _pair(tmp_path, hub, principal)
    g = issue_grant(n2, "beta", principal, max_uses=5)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    n1.step()  # the message is on the hub
    (mid,) = n1.state["unacked"].keys()
    env = n1.state["unacked"][mid]["env"]
    real_save, saves = n2._save_state, []

    def dies_at_the_batch_end():
        saves.append(1)
        if len(saves) == 2:  # the first save is the one before the action; the second is the end of the poll
            raise OSError("power lost")
        real_save()
    n2._save_state = dies_at_the_batch_end
    n2.step()
    assert outcomes(n2, "test.ping") == ["ok"] and len(saves) == 2
    n2.stop()
    time.sleep(1.1)
    n2b = nodemod.Node(n2.home)
    assert mid in n2b.state["seen"]
    n2b.start()
    assert http("POST", hub.url + "/v1/msg", env)[0] == 200  # the sender resubmits the very same envelope
    pump([n1, n2b], 3)
    assert outcomes(n2b, "test.ping") == ["ok"] and uses(n2b, g["grant_id"]) == 1


def test_issuer_model_is_on_every_grant_row_and_compares_whole_keys(tmp_path, hub, principal):
    """The issuer_model field (#48) is derived before the subject check, so
    a wrong-subject refusal carries it too; and the comparison is on the
    whole canonical key reference - an issuer key under another algorithm
    prefix with the receiving principal's bytes is sender-principal."""
    n1, n2 = _pair(tmp_path, hub, principal)
    other = make_node(tmp_path, "n3", hub.url, principal, {"gamma": ["test.ping"]})
    # a grant for another agent, presented to beta: wrong-subject, with the model
    g = issue_grant(other, "gamma", principal)
    os.makedirs(os.path.join(n2.home, "grants"), exist_ok=True)
    json.dump(g, open(os.path.join(n2.home, "grants", g["grant_id"] + ".json"), "w"))
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    rows = [e for e in ledger_entries(n2) if e["action"] == "grant.check" and e["grant_id"] == g["grant_id"]]
    assert [e["outcome"] for e in rows] == ["wrong-subject"]
    assert rows[0]["issuer_model"] == "receiver-principal"
    # the same principal bytes under another prefix are not this principal
    g2 = issue_grant(n2, "beta", principal, max_uses=2)
    g2["issuer"] = dict(g2["issuer"], key="rsa:" + g2["issuer"]["key"].split(":", 1)[1])
    g2 = envelope.sign_obj({k: v for k, v in g2.items() if k != "sig"}, principal.seed)
    json.dump(g2, open(os.path.join(n2.home, "grants", g2["grant_id"] + ".json"), "w"))
    send_action(n1, "alpha", n2, "beta", [g2["grant_id"]])
    pump([n1, n2], 3)
    rows = [e for e in ledger_entries(n2) if e["action"] == "grant.check" and e["grant_id"] == g2["grant_id"]]
    assert [e["outcome"] for e in rows] == ["invalid"]
    assert rows[0]["issuer_model"] == "sender-principal"


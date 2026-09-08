"""Grant robustness (2026-09-08 Citadel wire exchange): both directions of
the first cross-principal ping died on a DICT-shaped scope - the signers
signed whatever JSON they were handed and the executors crashed walking
it. make_grant now refuses to sign a malformed scope, grant_covers raises
GrantError instead of TypeError, and _apply_grants ledgers the grant
invalid instead of crashing the handler. audience.executor (spec 3:
"presented to a different executor is invalid") is now enforced."""
import pytest

from natively import envelope

from conftest import Principal, agent_key, inbox, ledger_entries, make_node, outcomes, pump


def _install_grant(node, grant):
    import json, os
    d = os.path.join(node.home, "grants")
    os.makedirs(d, exist_ok=True)
    json.dump(grant, open(os.path.join(d, grant["grant_id"] + ".json"), "w"))


def _ping_pair(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["test.ping", "msg.send"]})
    return n1, n2


def test_make_grant_rejects_dict_scope():
    p = Principal()
    with pytest.raises(ValueError):
        envelope.make_grant(p.seed, "p", {"agent_key": "ed25519:x", "node_key": "ed25519:y"},
                            "k", {"caps": ["test.ping"]}, "dict scope", max_uses=1)


def test_dict_scope_grant_ledgers_invalid_and_the_node_lives(tmp_path, hub, principal):
    n1, n2 = _ping_pair(tmp_path, hub, principal)
    # a VALIDLY SIGNED grant whose scope is then mangled into dict shape
    # and re-signed - the exact wire case: mint bug, not a forgery
    g = envelope.make_grant(principal.seed, "p", n2.agents["beta"]["card"],
                            n2.agents["beta"]["card"]["node_key"],
                            [{"action": "test.ping", "resource": ""}], "ping", max_uses=2)
    g["scope"] = {"caps": ["test.ping"]}
    g = envelope.sign_obj({k: v for k, v in g.items() if k != "sig"}, principal.seed)
    _install_grant(n2, g)
    n1.queue_send("alpha", agent_key(n2, "beta"),
                  {"kind": "action", "action": "test.ping", "resource": "", "params": {}},
                  grant_ids=[g["grant_id"]])
    # a plain message right behind it: the handler must survive
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "still alive"})
    pump([n1, n2], 4)
    assert outcomes(n2, "test.ping") == []
    assert "invalid" in outcomes(n2, "grant.check")
    assert any(r.get("body", {}).get("text") == "still alive" for r in inbox(n2, "beta"))


def test_wrong_executor_is_refused(tmp_path, hub, principal):
    n1, n2 = _ping_pair(tmp_path, hub, principal)
    other_node = make_node(tmp_path, "n3", hub.url, principal, {"x": ["msg.send"]})
    g = envelope.make_grant(principal.seed, "p", n2.agents["beta"]["card"],
                            other_node.agents["x"]["card"]["node_key"],  # not n2's node
                            [{"action": "test.ping", "resource": ""}], "ping", max_uses=2)
    _install_grant(n2, g)
    n1.queue_send("alpha", agent_key(n2, "beta"),
                  {"kind": "action", "action": "test.ping", "resource": "", "params": {}},
                  grant_ids=[g["grant_id"]])
    pump([n1, n2], 4)
    assert outcomes(n2, "test.ping") == []
    assert "wrong-executor" in outcomes(n2, "grant.check")


def test_executor_may_name_the_agent_key(tmp_path, hub, principal):
    n1, n2 = _ping_pair(tmp_path, hub, principal)
    g = envelope.make_grant(principal.seed, "p", n2.agents["beta"]["card"],
                            n2.agents["beta"]["card"]["agent_key"],  # agent, not node
                            [{"action": "test.ping", "resource": ""}], "ping", max_uses=2)
    _install_grant(n2, g)
    n1.queue_send("alpha", agent_key(n2, "beta"),
                  {"kind": "action", "action": "test.ping", "resource": "", "params": {}},
                  grant_ids=[g["grant_id"]])
    pump([n1, n2], 4)
    assert outcomes(n2, "test.ping") == ["ok"]

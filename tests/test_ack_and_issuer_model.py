"""Ack lifecycle + issuer-model ledgering (2026-09-08 Citadel exchange):
acks entered the retry table on both implementations and dead-lettered as
false UNDELIVERED rows; a late ack met an empty unacked table and dropped
silently; and grant rows carried no issuer_model, so ledger comparisons
could not tell receiver-principal from sender-principal executions."""
import os

from natively import envelope

from conftest import (Principal, agent_key, ledger_entries, make_node,
                      outcomes, pump)


def _install_grant(node, grant):
    import json
    d = os.path.join(node.home, "grants")
    os.makedirs(d, exist_ok=True)
    json.dump(grant, open(os.path.join(d, grant["grant_id"] + ".json"), "w"))


def test_ack_never_enters_retry_table(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "hi"})
    pump([n1, n2], 8)
    # the original was delivered and acked: n1's unacked is empty...
    assert n1.state["unacked"] == {}
    # ...and n2's ack left no retry-table entry behind (previously every
    # ack dead-lettered as a false UNDELIVERED after 3 retries)
    assert all(e.get("type") != "ack" for e in
               (r["env"] for r in n2.state["unacked"].values()))
    assert "dead" not in outcomes(n2, "msg.undelivered")
    assert "ok" in outcomes(n1, "msg.ack")


def test_late_ack_is_ledgered_not_dropped(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    # an ack for a msg_id n1 never sent (or already expunged); the id is
    # well formed - an ack naming something that is not an identifier is
    # rejected as malformed before the unacked table is consulted
    n2.queue_send("beta", agent_key(n1, "alpha"),
                  {"kind": "ack", "ack": "msg_" + "0" * 26, "ledger_head": "x"},
                  msg_type="ack")
    pump([n1, n2], 6)
    assert "late" in outcomes(n1, "msg.ack-late")


def _ping(tmp_path, hub, principal, issuer):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["test.ping"]},
                   roots=[principal.pub, issuer.pub])
    g = envelope.make_grant(issuer.seed, "issuer", n2.agents["beta"]["card"],
                            n2.agents["beta"]["card"]["node_key"],
                            [{"action": "test.ping", "resource": ""}], "ping",
                            max_uses=2)
    _install_grant(n2, g)
    n1.queue_send("alpha", agent_key(n2, "beta"),
                  {"kind": "action", "action": "test.ping", "resource": "",
                   "params": {}}, grant_ids=[g["grant_id"]])
    pump([n1, n2], 5)
    return n2


def test_issuer_model_receiver_principal(tmp_path, hub, principal):
    # the executing node's own principal signs the grant
    n2 = _ping(tmp_path, hub, principal, principal)
    rows = [e for e in ledger_entries(n2) if e["action"] == "test.ping"]
    assert rows and all(e.get("issuer_model") == "receiver-principal" for e in rows)


def test_issuer_model_sender_principal(tmp_path, hub, principal):
    # a foreign (pinned) principal signs the grant: sender-principal
    n2 = _ping(tmp_path, hub, principal, Principal())
    rows = [e for e in ledger_entries(n2) if e["action"] == "test.ping"]
    assert rows and all(e.get("issuer_model") == "sender-principal" for e in rows)

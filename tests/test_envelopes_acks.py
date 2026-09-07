"""Every envelope is verified before anything trusts it, and an ack clears
an outstanding message only when it comes from the party that message was
sent to (review 2026-09-07, point 4)."""
import json
import os

from natively import crypto, envelope

from conftest import agent_key, http, inbox, ledger_entries, make_node, outcomes, pump


def _enqueue_raw(hub, fp, env):
    """Put an envelope straight into a node's hub queue, as an operator or
    a hub bug could: the hub is not where verification lives."""
    with hub.state.lock:
        hub.state.seq[fp] = hub.state.seq.get(fp, 0) + 1
        hub.state.queues.setdefault(fp, []).append({"env": env, "_seq": hub.state.seq[fp]})


def _signed_env(n_from, agent_from, to_key, to_node, body, seed_from_node=None, msg_type="msg", **overrides):
    """A correctly signed and encrypted envelope, optionally with fields
    overridden AFTER signing (a tampered one) or with type/extra fields."""
    ct = n_from._enc_pairwise(to_node.fp, body)
    a = n_from.agents[agent_from]
    m = envelope.make_message(a["card"]["agent_key"].split(":", 1)[1], to_key.split(":", 1)[1], ct, a["seed"],
                              msg_type=msg_type, extra={"to": to_key, "to_node": to_node.fp})
    return dict(m, **overrides)


def test_malformed_envelopes_are_refused_and_the_loop_continues(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    beta = agent_key(n2, "beta")
    good = _signed_env(n1, "alpha", beta, n2, {"kind": "text", "text": "fine"})
    variants = [{"to": [beta]}, {"from": 5}, {"sig": None}, {"type": "weird"}, {"suite": "nv2"}, {"grant_ids": "grt_x"},
                {"in_reply_to": "../x"}, {"body": None}, {"ts": "yesterday"}, {"to_node": "nope"}, {"class": "vip"}]
    bad = [dict(good, msg_id=envelope.new_id("msg"), **v) for v in variants] + ["not an object"]
    # every variant is refused by SHAPE, one by one: a field the shape check
    # missed would fall through to the signature check (the msg_id changed
    # after signing) and hide behind a looser count
    for v, b in zip(variants, bad):
        assert envelope.check_message_shape(b) is not None, v
    assert envelope.check_message_shape(good) is None
    for b in bad:
        _enqueue_raw(hub, n2.fp, b)
    _enqueue_raw(hub, n2.fp, good)
    pump([n2], 3)
    assert [r["body"]["text"] for r in inbox(n2, "beta")] == ["fine"]
    recv = outcomes(n2, "msg.recv")
    assert recv.count("rejected-malformed") + recv.count("rejected-bad-id") == len(bad)
    assert "rejected-bad-sig" not in recv
    assert n2.state["last_seq"] == len(bad) + 1


def test_tampered_envelope_is_refused_by_signature(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    env = _signed_env(n1, "alpha", agent_key(n2, "beta"), n2, {"kind": "text", "text": "x"}, grant_ids=["grt_" + "0" * 26])
    assert http("POST", hub.url + "/v1/msg", env)[0] == 200
    pump([n2], 2)
    assert inbox(n2, "beta") == []
    assert "rejected-bad-sig" in outcomes(n2, "msg.recv")


def _outstanding(n1, n2):
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "please ack"})
    pump([n1], 1)
    assert len(n1.state["unacked"]) == 1
    return next(iter(n1.state["unacked"]))


def test_ack_from_a_third_party_does_not_clear_the_message(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n3 = make_node(tmp_path, "n3", hub.url, principal, {"gamma": ["msg.send"]})
    mid = _outstanding(n1, n2)
    # gamma, a valid sender, acks a message that was sent to beta
    forged = _signed_env(n3, "gamma", agent_key(n1, "alpha"), n1, {"kind": "ack", "ack": mid}, msg_type="ack")
    assert http("POST", hub.url + "/v1/msg", forged)[0] == 200
    pump([n1], 2)
    assert mid in n1.state["unacked"]
    assert "rejected-wrong-party" in outcomes(n1, "msg.ack")
    # the real ack from beta clears it
    pump([n2, n1], 4)
    assert n1.state["unacked"] == {}
    assert outcomes(n1, "msg.ack")[-1] == "ok"


def test_ack_with_a_bad_signature_is_refused(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    mid = _outstanding(n1, n2)
    ack = _signed_env(n2, "beta", agent_key(n1, "alpha"), n1, {"kind": "ack", "ack": mid}, msg_type="ack")
    tampered = dict(ack, in_reply_to=envelope.new_id("msg"))  # a field changed after signing
    _enqueue_raw(hub, n1.fp, tampered)
    pump([n1], 1)
    assert mid in n1.state["unacked"]
    assert "rejected-bad-sig" in outcomes(n1, "msg.recv")


def test_ack_addressed_to_another_local_agent_is_refused(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"], "alpha2": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    mid = _outstanding(n1, n2)
    ack = _signed_env(n2, "beta", agent_key(n1, "alpha2"), n1, {"kind": "ack", "ack": mid}, msg_type="ack")
    assert http("POST", hub.url + "/v1/msg", ack)[0] == 200
    pump([n1], 2)
    assert mid in n1.state["unacked"]
    assert "rejected-wrong-party" in outcomes(n1, "msg.ack")


def test_ack_in_a_msg_envelope_is_information_not_an_ack(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    mid = _outstanding(n1, n2)
    fake = _signed_env(n2, "beta", agent_key(n1, "alpha"), n1, {"kind": "ack", "ack": mid}, msg_type="msg")
    assert http("POST", hub.url + "/v1/msg", fake)[0] == 200
    pump([n1], 2)
    assert mid in n1.state["unacked"]
    assert [r["body"]["kind"] for r in inbox(n1, "alpha")] == ["ack"]


def test_ack_carries_in_reply_to_and_each_envelope_is_decrypted_once(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    calls = []
    orig = n1._dec_pairwise
    n1._dec_pairwise = lambda fp, b: calls.append(1) or orig(fp, b)
    mid = _outstanding(n1, n2)
    pump([n2], 2)
    acks = [m["env"] for m in hub.state.queues[n1.fp] if m["env"]["type"] == "ack"]
    assert len(acks) == 1 and acks[0]["in_reply_to"] == mid
    pump([n1], 1)
    assert n1.state["unacked"] == {} and outcomes(n1, "msg.ack") == ["ok"]
    assert len(calls) == 1
    # and an ordinary message: one decryption too
    n2.queue_send("beta", agent_key(n1, "alpha"), {"kind": "text", "text": "hi"})
    pump([n2, n1], 2)
    assert [r["body"]["text"] for r in inbox(n1, "alpha")] == ["hi"]
    assert len(calls) == 2

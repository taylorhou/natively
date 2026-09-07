"""Identifier constraints (review 2026-09-07, point 2): no remote string
becomes a path component unless it matches the identifier grammar, and a
grant is accounted under its signed grant_id, never a path alias."""
import json
import os

from natively import crypto, envelope

from conftest import agent_key, http, inbox, issue_grant, make_node, outcomes, pump, send_action, uses


def test_safe_id_grammar():
    assert envelope.safe_id(envelope.new_id("msg"), "msg")
    assert envelope.safe_id(envelope.new_id("grt"))
    assert not envelope.safe_id(envelope.new_id("msg"), "grt")
    for bad in ("../../state", "msg_../x", "MSG_" + "0" * 26, "msg_" + "0" * 25, "msg_" + "0" * 27,
                "ms_" + "0" * 26, "", None, 5, "msg_" + "0" * 25 + "/", "msg_" + "0" * 26 + "\n",
                "msg_" + "i" * 26, "msg_" + "0" * 25 + "l", "msg_" + "0" * 25 + "o", "msg_" + "0" * 25 + "u"):
        assert not envelope.safe_id(bad), bad
    assert envelope.safe_id("msg_" + "0123456789abcdefghjkmnpqrs")
    assert envelope.safe_fp("0" * 32) and envelope.safe_fp("abcdef0123456789" * 2)
    for bad in ("0" * 31, "0" * 33, "G" * 32, "../" + "0" * 29, None, "0" * 32 + "\n"):
        assert not envelope.safe_fp(bad), bad


def _hostile_envelope(n_from, agent_from, n_to, agent_to, msg_id, body, grant_ids=()):
    """A correctly signed and encrypted envelope whose msg_id is chosen by
    the sender (the CLI would never write one; a hostile sender can)."""
    ct = n_from._enc_pairwise(n_to.fp, body)
    a = n_from.agents[agent_from]
    m = {"msg_id": msg_id, "ts": envelope.now_iso(), "type": "msg", "suite": crypto.SUITE,
         "from": a["card"]["agent_key"], "to": agent_key(n_to, agent_to), "in_reply_to": None,
         "grant_ids": list(grant_ids), "body": ct}
    return envelope.sign_obj(m, a["seed"])


def test_wire_msg_id_never_becomes_a_path(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    env = _hostile_envelope(n1, "alpha", n2, "beta", "../../state", {"kind": "text", "text": "x"})
    assert http("POST", hub.url + "/v1/msg", env)[0] == 200
    pump([n2], 2)
    assert inbox(n2, "beta") == []
    assert "rejected-bad-id" in outcomes(n2, "msg.recv")
    state = json.load(open(os.path.join(n2.home, "state.json")))
    assert state["last_seq"] >= 1  # cursor moved past it
    assert "body" not in state and "from" not in state  # never overwritten by an inbox record
    assert not os.path.exists(os.path.join(n2.home, "state.json.json"))
    assert "../../state" not in n2.state["seen"]
    # the receive ledger never names a malformed grant id either
    env = _hostile_envelope(n1, "alpha", n2, "beta", envelope.new_id("msg"), {"kind": "text", "text": "y"}, grant_ids=[123, "x"])
    assert http("POST", hub.url + "/v1/msg", env)[0] == 200
    pump([n2], 2)
    recv = [e for e in n2.ledger.entries() if e["action"] == "msg.recv" and e["outcome"] == "information-only"]
    assert len(recv) == 1 and recv[0]["grant_id"] is None


def test_decrypted_group_id_never_becomes_a_path(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    evil = {"kind": "group_key", "group_id": "../../evil", "group_name": "g", "sender_fp": n1.fp,
            "state": crypto.SenderKey().state(), "members": []}
    n1.queue_send("alpha", agent_key(n2, "beta"), evil)
    pump([n1, n2], 3)
    assert not os.path.exists(os.path.join(n2.home, "evil.json"))
    assert not os.path.exists(os.path.join(tmp_path, "evil.json"))
    assert not os.path.isdir(os.path.join(n2.home, "groups")) or os.listdir(os.path.join(n2.home, "groups")) == []
    assert "rejected-bad-id" in outcomes(n2, "group.key")
    relay = {"kind": "group_relay", "group_id": "../../evil",
             "wire": {"kind": "group_msg", "group_id": "../../evil", "n": 0, "ct": "", "sender_fp": n1.fp}}
    n1.queue_send("alpha", agent_key(n2, "beta"), relay)
    pump([n1, n2], 3)
    assert "rejected-bad-id" in outcomes(n2, "group.recv")


def _ping(n1, n2, grant_ids):
    send_action(n1, "alpha", n2, "beta", grant_ids)


def test_grant_path_aliases_do_not_bypass_max_uses(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["test.ping"]})
    g = issue_grant(n2, "beta", principal, max_uses=1)
    gid = g["grant_id"]
    _ping(n1, n2, [gid])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    for alias in ("./" + gid, "../grants/" + gid, gid + "/", gid.upper()):
        _ping(n1, n2, [alias])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]  # still exactly one execution
    assert outcomes(n2, "grant.check").count("rejected-bad-id") == 4
    assert uses(n2, gid) == 1


def test_grant_file_must_carry_its_own_id(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["test.ping"]})
    g = issue_grant(n2, "beta", principal, max_uses=5)
    alias = envelope.new_id("grt")
    gdir = os.path.join(n2.home, "grants")
    json.dump(g, open(os.path.join(gdir, alias + ".json"), "w"))  # a copy under another name
    _ping(n1, n2, [alias])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == []
    assert "unknown-grant" in outcomes(n2, "grant.check")
    assert uses(n2, g["grant_id"]) == 0 and uses(n2, alias) == 0


def test_grant_listed_twice_executes_once(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["test.ping"]})
    g = issue_grant(n2, "beta", principal, max_uses=5)
    _ping(n1, n2, [g["grant_id"], g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    assert uses(n2, g["grant_id"]) == 1


def test_hub_paths_are_checked(hub):
    assert http("GET", hub.url + "/v1/blob/..%2F..%2Fhub.json")[0] == 400
    assert http("GET", hub.url + "/v1/blob/" + "0" * 32)[0] == 404
    assert http("GET", hub.url + "/v1/prekey/notahexfingerprint")[0] == 400
    st, r = http("PUT", hub.url + "/v1/prekey/..", {})
    assert st == 400 and r["error"] == "bad node fingerprint"  # the path, not the (missing) signature
    assert http("GET", hub.url + "/v1/poll/..?after=0")[0] == 400

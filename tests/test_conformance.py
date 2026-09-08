"""The asserted replacement for the smoke script (review 2026-09-07, point
10): the same journey tests/itest.sh walks, driven through the CLI where
the script used it, with every expected outcome asserted - a run in which
a message is not delivered, a group message does not reach every member,
a grant is honoured past its budget or a blob does not round-trip FAILS.
Everything runs in-process on a random port, every key is generated here."""
import hashlib
import json
import os
import time

import pytest

from natively import cli, envelope, node as nodemod

from conftest import agent_key, inbox, ledger_entries, make_node, outcomes, pump
from test_group_grants import _join_grant


def _cli(home, *args):
    cli.main(["--home", home, *args])


def _addr(node, agent):
    return "%s@%s" % (agent, node.fp)


def test_one_to_one_both_directions_acked_and_chained(tmp_path, hub, principal, capsys):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    _cli(n1.home, "send", "--from", "alpha", "--to", _addr(n2, "beta"), "--text", "hello from alpha")
    pump([n1, n2], 5)
    assert [r["body"]["text"] for r in inbox(n2, "beta")] == ["hello from alpha"]
    assert n1.state["unacked"] == {} and outcomes(n1, "msg.ack") == ["ok"]  # delivered AND acknowledged
    _cli(n2.home, "send", "--from", "beta", "--to", _addr(n1, "alpha"), "--text", "hi alpha, beta here")
    pump([n2, n1], 5)
    assert [r["body"]["text"] for r in inbox(n1, "alpha")] == ["hi alpha, beta here"]
    assert n2.state["unacked"] == {} and outcomes(n2, "msg.ack") == ["ok"]  # acknowledged, not merely retired
    # the CLI inbox shows it, and both chains verify
    _cli(n2.home, "inbox", "--agent", "beta")
    assert "hello from alpha" in capsys.readouterr().out
    for n in (n1, n2):
        assert n.ledger.verify_chain()
        with pytest.raises(SystemExit) as ex:
            _cli(n.home, "ledger", "verify")  # exits 0 on a chain that verifies, 1 otherwise
        assert ex.value.code == 0 and "chain ok" in capsys.readouterr().out


def test_group_reaches_every_member_including_the_creator(tmp_path, hub, principal, capsys):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send", "group.join"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send", "group.join"], "gamma": ["msg.send", "group.join"]})
    g1, g2b, g2g = _join_grant(n1, "alpha", principal), _join_grant(n2, "beta", principal), _join_grant(n2, "gamma", principal)
    _cli(n1.home, "group-create", "--from", "alpha", "--members", "%s,%s" % (_addr(n2, "beta"), _addr(n2, "gamma")),
         "--name", "testgroup", "--grants", "%s,%s" % (g2b["grant_id"], g2g["grant_id"]), "--creator-grants", g1["grant_id"])
    gid = capsys.readouterr().out.split()[-1]
    assert envelope.safe_id(gid, "grp")
    pump([n1, n2], 8)
    assert outcomes(n2, "group.join").count("ok") == 2  # beta and gamma joined under their grants
    assert n2.fp in n1._group(gid)["_recv"]  # and their keys came back to the creator
    _cli(n1.home, "group-send", "--from", "alpha", "--gid", gid, "--text", "first group message")
    pump([n1, n2], 6)
    for agent in ("beta", "gamma"):
        assert [r["body"]["text"] for r in inbox(n2, agent) if r["body"].get("kind") == "group_text"] == ["first group message"]
    _cli(n2.home, "group-send", "--from", "beta", "--gid", gid, "--text", "beta in the group too")
    pump([n2, n1], 6)
    assert [r["body"]["text"] for r in inbox(n1, "alpha") if r["body"].get("kind") == "group_text"] == ["beta in the group too"]
    assert [r["body"]["text"] for r in inbox(n2, "gamma") if r["body"].get("kind") == "group_text"] == ["first group message", "beta in the group too"]
    assert not [o for o in outcomes(n2, "group.recv") + outcomes(n1, "group.recv") if o.startswith("rejected") or o in ("no-sender-key", "unknown-group")]


def test_a_grant_is_honoured_exactly_max_uses_times(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["test.ping", "msg.send"]})
    from conftest import issue_grant, resource
    g = issue_grant(n2, "beta", principal, max_uses=2)
    for i in range(3):
        _cli(n1.home, "send", "--from", "alpha", "--to", _addr(n2, "beta"), "--text", "ping please %d" % i,
             "--action", "test.ping", "--resource", resource(n2), "--grants", g["grant_id"])
        pump([n1, n2], 5)
    assert outcomes(n2, "test.ping") == ["ok", "ok"]  # the budget, not one more
    recs = sorted(inbox(n2, "beta"), key=lambda r: r["body"]["text"])
    assert [r["outcome"] for r in recs] == ["acted:test.ping", "acted:test.ping", "refused"]
    assert "exhausted" in [e["outcome"] for e in ledger_entries(n2) if e["action"] == "grant.check"]
    # a message that names no grant carrying an action body is information, not an execution:
    # it reaches the inbox as delivered, and the count does not move
    _cli(n1.home, "send", "--from", "alpha", "--to", _addr(n2, "beta"), "--text", "no grant",
         "--action", "test.ping", "--resource", resource(n2))
    pump([n1, n2], 5)
    (rec,) = [r for r in inbox(n2, "beta") if r["body"]["text"] == "no grant"]
    assert rec["outcome"] == "delivered" and rec["grant_ids"] == []
    assert outcomes(n2, "test.ping") == ["ok", "ok"]
    assert n2.ledger.verify_chain()


def test_a_blob_round_trips(tmp_path, hub, principal, capsys):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    photo = tmp_path / "photo.jpg"
    photo.write_bytes(os.urandom(200000))
    _cli(n1.home, "blob", "--from", "alpha", "--to", _addr(n2, "beta"), "--file", str(photo))
    pump([n1, n2], 6)
    (rec,) = [r for r in inbox(n2, "beta") if r["body"].get("kind") == "blob_ref"]
    assert rec["body"]["sha256"] == hashlib.sha256(photo.read_bytes()).hexdigest()
    out = tmp_path / "photo-out.jpg"
    _cli(n2.home, "fetch-blob", "--agent", "beta", "--msg-id", rec["msg_id"], "--out", str(out))
    assert out.read_bytes() == photo.read_bytes()
    assert "sha256 verified" in capsys.readouterr().out
    # (a second fetch of the same blob is review point 8's PR: tests/test_blobs.py there)


def test_a_duplicate_delivery_is_acked_again_and_a_restart_keeps_the_cursor(tmp_path, hub, principal):
    from conftest import http, issue_grant, send_action
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["test.ping", "msg.send"]})
    g = issue_grant(n2, "beta", principal, max_uses=5)  # spare budget: a re-application would show as a second ok
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    n1.step()
    env = list(n1.state["unacked"].values())[0]["env"]
    pump([n2, n1], 4)
    assert outcomes(n2, "test.ping") == ["ok"] and n1.state["unacked"] == {}
    delivered = [e for e in ledger_entries(n2) if e["action"] == "msg.recv" and e["outcome"].startswith("acted")]
    assert len(delivered) == 1
    assert http("POST", hub.url + "/v1/msg", body=env)[0] == 200  # the same envelope again (a sender that lost our ack)
    pump([n2, n1], 4)
    assert outcomes(n2, "test.ping") == ["ok"]  # executed exactly once: the budget did not move
    assert len([e for e in ledger_entries(n2) if e["action"] == "msg.recv" and e["outcome"].startswith("acted")]) == 1
    assert [r["outcome"] for r in inbox(n2, "beta")] == ["acted:test.ping"]
    assert "duplicate" in outcomes(n2, "msg.recv") and "late" in outcomes(n1, "msg.ack-late")
    seq = n2.state["last_seq"]
    assert seq > 0  # the cursor advanced past the two deliveries; 0 == 0 would prove nothing
    n2.stop()
    n2b = nodemod.Node(n2.home)
    assert n2b.state["last_seq"] == seq and env["msg_id"] in n2b.state["seen"]  # the cursor and dedup survive a restart
    polls = []
    real_req = n2b._hub_req

    def spy(method, path, body=None, headers=None):
        if method == "GET" and path.startswith("/v1/poll/"):
            polls.append(path)
        return real_req(method, path, body=body, headers=headers)
    n2b._hub_req = spy
    n2b.start()
    assert n2b.state["last_seq"] == seq  # startup itself did not reset the cursor
    # the hub orders one node's registrations by whole second, so a restart
    # inside the second of the last registration waits for the clock before
    # it polls: a bounded readiness wait, not a fixed number of rounds
    for _ in range(100):
        n2b.step()
        if n2b._last_reg_time:
            break
        time.sleep(0.1)
    assert n2b._last_reg_time, "the replacement node never registered"
    assert polls and polls[0].endswith("?after=%d" % seq)  # the first poll asked from the preserved cursor
    assert n2b.state["last_seq"] == seq
    # the replacement node sees the envelope a third time: acked again from
    # the survived dedup set, and still executed exactly once
    assert http("POST", hub.url + "/v1/msg", body=env)[0] == 200
    pump([n2b, n1], 4)
    assert outcomes(n2b, "test.ping") == ["ok"]
    assert outcomes(n2b, "msg.recv").count("duplicate") == 2 and outcomes(n1, "msg.ack-late").count("late") == 2
    assert [r["outcome"] for r in inbox(n2b, "beta")] == ["acted:test.ping"]
    assert n2b.state["last_seq"] > seq
    assert n2b.ledger.verify_chain()
    n2b.stop()

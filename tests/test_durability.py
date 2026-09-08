"""Durable, recoverable state (review 2026-09-07, point 6): the ledger is
fsynced and a torn tail is recovered, a broken chain refuses to start,
node state is written atomically and validated on load, a transient
failure while handling a message leaves it for the sender's retry, a
duplicate delivery is acked again without being re-applied, and the
ledger heads peers declare in their acks are recorded."""
import json
import os
import urllib.error

import pytest

from natively import envelope
from natively import node as nodemod
from natively.ledger import Ledger, LedgerCorrupt

from conftest import agent_key, http, inbox, ledger_entries, make_node, outcomes, pump


def _rows(path):
    return [json.loads(l) for l in open(path).read().splitlines() if l.strip()]


def test_a_torn_tail_is_moved_aside_and_the_chain_resumes(tmp_path):
    path = str(tmp_path / "ledger.jsonl")
    led = Ledger(path)
    for i in range(3):
        led.append("node:t", None, "test", {"i": i}, "ok", "row %d" % i)
    head = led.head()
    with open(path, "a") as f:
        f.write('{"ts":"2026-09-08T00:00:00Z","actor":"node:t","action":"tes')  # a crash mid-append
    fresh = Ledger(path)  # recovers on open
    assert [e["params_hash"] for e in _rows(path)] == [e["params_hash"] for e in fresh.entries()]
    assert len(list(fresh.entries())) == 3 and fresh.head() == head and fresh.verify_chain()
    torn = open(path + ".torn").read()
    assert "# torn tail found" in torn and '"action":"tes' in torn
    assert "ledger.torn-tail -> recovered" in open(path + ".prose").read()
    fresh.append("node:t", None, "test", {"i": 3}, "ok", "after recovery")
    assert fresh.verify_chain() and len(list(Ledger(path).entries())) == 4
    # a whole row that lost only its newline is kept: the delimiter comes back
    row = open(path).read().splitlines()[-1]
    with open(path, "r+b") as f:
        f.seek(0, os.SEEK_END)
        f.truncate(f.tell() - 1)
    kept = Ledger(path)
    assert len(list(kept.entries())) == 4 and kept.verify_chain() and open(path).read().endswith(row + "\n")
    assert "delimiter restored" in open(path + ".prose").read()
    # a complete last line that is not a row is corruption, not a torn tail: never recovered away
    with open(path, "a") as f:
        f.write('{"not": "a row"}\n')
    again = Ledger(path)
    assert not again.verify_chain()
    with pytest.raises(LedgerCorrupt):
        again.head()
    assert open(path).read().endswith('{"not": "a row"}\n')


def test_another_writers_torn_tail_is_recovered_before_this_append(tmp_path):
    path = str(tmp_path / "ledger.jsonl")
    a, b = Ledger(path), Ledger(path)
    a.append("node:t", None, "test", {}, "ok", "one")
    with open(path, "a") as f:
        f.write('{"ts":"2026')  # b died mid-line
    a.append("node:t", None, "test", {}, "ok", "two")  # a recovers, then chains onto the last whole row
    assert Ledger(path).verify_chain() and len(list(a.entries())) == 2


def test_recovery_never_erases_middle_corruption_over_repeated_opens(tmp_path):
    path = str(tmp_path / "ledger.jsonl")
    led = Ledger(path)
    led.append("node:t", None, "test", {}, "ok", "one")
    with open(path, "a") as f:
        f.write("garbage in the middle\n")
        f.write('{"ts":"2026')  # and a torn tail after it
    for _ in range(3):
        again = Ledger(path)  # each open recovers at most the unterminated tail
        assert not again.verify_chain()
        with pytest.raises(LedgerCorrupt):
            again.head()
    assert "garbage in the middle" in open(path).read()  # still there to be seen


def test_damage_the_reader_cannot_even_parse_is_reported_not_raised(tmp_path):
    path = str(tmp_path / "ledger.jsonl")
    led = Ledger(path)
    led.append("node:t", None, "test", {}, "ok", "one")
    with open(path, "a") as f:
        f.write("[" * 100000 + "\n")  # a row nested past the parser's limit
    led2 = Ledger(path)
    assert led2.verify_chain() is False
    with pytest.raises(LedgerCorrupt):
        led2.head()


def test_a_row_in_the_middle_that_does_not_parse_is_corrupt_not_recovered(tmp_path):
    path = str(tmp_path / "ledger.jsonl")
    led = Ledger(path)
    for i in range(3):
        led.append("node:t", None, "test", {"i": i}, "ok", "row")
    lines = open(path).read().splitlines()
    lines[1] = lines[1][:-5]  # damage in the middle
    open(path, "w").write("\n".join(lines) + "\n")
    fresh = Ledger(path)
    assert not fresh.verify_chain()
    with pytest.raises(LedgerCorrupt):
        fresh.head()
    assert not os.path.exists(path + ".torn")


def test_a_node_refuses_to_start_on_a_ledger_whose_chain_does_not_verify(tmp_path, hub, principal):
    n = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n.stop()
    path = n.ledger.path
    lines = open(path).read().splitlines()
    e = json.loads(lines[0])
    e["outcome"] = "tampered"
    lines[0] = json.dumps(e, separators=(",", ":"))
    open(path, "w").write("\n".join(lines) + "\n")
    with pytest.raises(LedgerCorrupt, match="does not verify"):
        nodemod.Node(n.home).start()


def test_a_torn_tail_left_by_another_writer_after_open_is_recovered_at_start(tmp_path, hub, principal):
    n = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n.stop()
    nb = nodemod.Node(n.home)  # constructed (and recovered) ...
    with open(nb.ledger.path, "a") as f:
        f.write('{"ts":"2026')  # ... then another writer dies mid-append before start()
    nb.start()  # recover-and-verify together: recoverable damage is recovered, not refused
    assert nb.ledger.verify_chain() and os.path.exists(nb.ledger.path + ".torn")
    nb.stop()


def test_a_duplicate_whose_agent_card_is_broken_does_not_kill_the_loop(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "once"})
    n1.step()
    env = list(n1.state["unacked"].values())[0]["env"]
    pump([n2, n1], 4)
    open(os.path.join(n2.home, "agents", "beta.card.json"), "w").write("{}")  # a hot-loaded card with no agent_key
    http("POST", hub.url + "/v1/msg", body=env)
    pump([n2], 3)  # the duplicate's re-ack fails and is ledgered; the loop goes on
    assert any(o.startswith("error") for o in outcomes(n2, "msg.recv", classified=True))
    assert n2.state["last_seq"] >= 2


def test_a_new_ledger_and_an_inbox_record_are_durably_linked(tmp_path, monkeypatch):
    calls = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (calls.append(fd), real(fd))[1])
    Ledger(str(tmp_path / "fresh" / "ledger.jsonl"))
    assert len(calls) >= 1  # the directory that now holds the new file
    calls.clear()
    nodemod._w600_sync(str(tmp_path / "inbox" / "x.json"), b"{}")
    assert len(calls) == 3  # the file, its directory, and the parent the new directory was linked in


def test_a_receipt_that_could_not_be_saved_is_not_kept_in_memory(tmp_path, hub, principal, monkeypatch):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "once"})
    n1.step()
    env = list(n1.state["unacked"].values())[0]["env"]
    real = n2._save_state

    def failing():
        raise OSError("disk full")
    monkeypatch.setattr(n2, "_save_state", failing)
    pump([n2], 2)
    assert env["msg_id"] not in n2.state.get("acked", {})  # nothing vouched for that is not on disk
    monkeypatch.setattr(n2, "_save_state", real)
    acks = []
    monkeypatch.setattr(n2, "_ack", lambda e, a: acks.append(e["msg_id"]))
    http("POST", hub.url + "/v1/msg", body=env)
    pump([n2], 3)
    assert acks == []  # a duplicate of a message with no persisted receipt gets no ack


def test_sessions_and_new_inbox_directories_are_written_durably(tmp_path, monkeypatch):
    calls = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (calls.append(fd), real(fd))[1])
    nodemod._w600_sync(str(tmp_path / "inbox" / "beta" / "x.json"), b"{}")
    assert len(calls) == 4  # the file, beta/, then inbox/ and tmp_path for the two directories created
    calls.clear()
    nodemod._w600_sync(str(tmp_path / "inbox" / "beta" / "y.json"), b"{}")
    assert len(calls) == 2  # nothing new to link this time


def test_bytes_that_are_not_utf8_are_corruption(tmp_path):
    path = str(tmp_path / "ledger.jsonl")
    led = Ledger(path)
    led.append("node:t", None, "test", {}, "ok", "one")
    with open(path, "ab") as f:
        f.write(b"\xff\xfe not text\n")
    led2 = Ledger(path)
    assert led2.verify_chain() is False
    with pytest.raises(LedgerCorrupt):
        led2.head()


def test_ledger_rows_and_state_are_fsynced(tmp_path, monkeypatch):
    calls = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (calls.append(fd), real(fd))[1])
    led = Ledger(str(tmp_path / "ledger.jsonl"))
    calls.clear()
    led.append("node:t", None, "test", {}, "ok", "one")
    assert len(calls) >= 1
    line = open(led.mirror_path).read().splitlines()[-2]
    assert line.startswith(led.head()[:12] + " [")  # the prose line names its row
    # a state save fsyncs the file and then its directory (the rename is durable)
    from natively import node as nodemod
    n = nodemod.Node.__new__(nodemod.Node)
    n.state_path = str(tmp_path / "state.json")
    n.state = {"last_seq": 1, "unacked": {}, "seen": []}
    calls.clear()
    n._save_state()
    assert len(calls) == 2 and json.load(open(n.state_path))["last_seq"] == 1


def test_state_is_validated_on_load_and_written_atomically(tmp_path, hub, principal):
    n = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n.stop()
    n._save_state()
    assert not os.path.exists(n.state_path + ".tmp")
    for bad in ('{"last_seq": "0", "unacked": {}, "seen": []}', '{"last_seq": 0, "unacked": [], "seen": []}', "[]", "{not json"):
        open(n.state_path, "w").write(bad)
        with pytest.raises(ValueError):
            nodemod.Node(n.home)


def test_a_transient_failure_while_handling_leaves_the_message_for_the_senders_retry(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    real = n2._peer_card
    away = {"on": True}

    def flaky(key, fresh=False, directory=None):
        if away["on"]:
            raise urllib.error.URLError("hub away")
        return real(key, fresh, directory=directory)
    n2._peer_card = flaky
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "first try"})
    pump([n1, n2], 3)
    mid = list(n1.state["unacked"])[0]
    assert "retry" in outcomes(n2, "msg.recv") and mid not in n2.state["seen"] and inbox(n2, "beta") == []
    away["on"] = False
    # the sender's retry of the same envelope (re-POSTed to the hub) is handled now
    env = n1.state["unacked"][mid]["env"]
    status, _ = http("POST", hub.url + "/v1/msg", body=env)
    assert status == 200
    pump([n1, n2], 4)
    assert [r["body"]["text"] for r in inbox(n2, "beta")] == ["first try"]
    assert mid in n2.state["seen"] and n1.state["unacked"] == {}


def test_a_duplicate_delivery_is_acked_again_and_never_re_applied(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "once"})
    pump([n1, n2], 1)
    env = list(n1.state["unacked"].values())[0]["env"]
    pump([n1, n2], 5)
    assert n1.state["unacked"] == {} and [r["body"]["text"] for r in inbox(n2, "beta")] == ["once"]
    acks_before = outcomes(n1, "msg.ack").count("ok")
    status, _ = http("POST", hub.url + "/v1/msg", body=env)  # the same envelope again (a sender that lost our ack)
    assert status == 200
    pump([n1, n2], 5)
    assert [r["body"]["text"] for r in inbox(n2, "beta")] == ["once"]  # not re-applied
    assert "duplicate" in outcomes(n2, "msg.recv")
    assert "late" in outcomes(n1, "msg.ack-late") or outcomes(n1, "msg.ack").count("ok") > acks_before  # the ack went again
    # a duplicate whose signature does not verify gets nothing
    forged = dict(env, sig="A" * 86 + "==")
    dupes = outcomes(n2, "msg.recv").count("duplicate")
    http("POST", hub.url + "/v1/msg", body=forged)
    pump([n1, n2], 3)
    assert outcomes(n2, "msg.recv").count("duplicate") == dupes


def test_a_seen_message_that_was_never_answered_is_not_acked_on_a_duplicate(tmp_path, hub, principal, monkeypatch):
    """A bad-signature copy arrives first (seen, refused), then the valid
    envelope: the valid one is a duplicate by msg_id, and it must not be
    acked - nothing was delivered."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "real"})
    n1.step()
    env = list(n1.state["unacked"].values())[0]["env"]
    forged = dict(env, sig="A" * 86 + "==")
    with hub.state.lock:  # the forged copy is served first, ahead of the real one
        q = hub.state.queues[n2.fp]
        q[0]["_seq"] = 2
        q.insert(0, {"env": forged, "_seq": 1})
        hub.state.seq[n2.fp] = 2
    acks = []
    monkeypatch.setattr(n2, "_ack", lambda e, a: acks.append(e["msg_id"]))
    pump([n2], 3)
    assert env["msg_id"] in n2.state["seen"] and "rejected-bad-sig" in outcomes(n2, "msg.recv")
    assert acks == [] and inbox(n2, "beta") == []
    assert env["msg_id"] not in n2.state.get("acked", {})


def test_a_re_signed_envelope_under_an_answered_id_is_not_acked(tmp_path, hub, principal, monkeypatch):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "the original"})
    n1.step()
    env = list(n1.state["unacked"].values())[0]["env"]
    pump([n2, n1], 4)
    assert n2.state["acked"][env["msg_id"]] == env["sig"]  # the receipt names the envelope
    assert json.load(open(n2.state_path))["acked"][env["msg_id"]] == env["sig"]  # and is on disk
    # the same id, a different body, freshly signed by the sender's agent
    a = n1.agents["alpha"]
    other = envelope.make_message(agent_key(n1, "alpha").split(":", 1)[1], agent_key(n2, "beta").split(":", 1)[1],
                                  n1._enc_pairwise(n2.fp, {"kind": "text", "text": "not the original"}), a["seed"],
                                  extra={"to": agent_key(n2, "beta"), "to_node": n2.fp})
    other["msg_id"] = env["msg_id"]
    other = envelope.sign_obj({k: v for k, v in other.items() if k != "sig"}, a["seed"])
    acks = []
    monkeypatch.setattr(n2, "_ack", lambda e, ag: acks.append(e["msg_id"]))
    http("POST", hub.url + "/v1/msg", body=other)
    pump([n2], 3)
    assert acks == [] and [r["body"]["text"] for r in inbox(n2, "beta")] == ["the original"]
    # the exact envelope again IS answered again
    http("POST", hub.url + "/v1/msg", body=env)
    pump([n2], 3)
    assert acks == [env["msg_id"]]


def test_peer_ledger_heads_from_acks_are_recorded_not_acted_on(tmp_path, hub, principal, capsys):
    from natively import cli
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "hi"})
    pump([n1, n2], 6)
    rec = n1.state["peer_heads"][n2.fp]
    assert len(rec["head"]) == 64 and envelope.safe_id(rec["msg_id"], "msg")
    assert json.load(open(n1.state_path))["peer_heads"][n2.fp] == rec  # persisted in the save that consumed the ack
    n1.stop()
    cli.main(["--home", n1.home, "ledger", "peers"])
    assert n2.fp in capsys.readouterr().out

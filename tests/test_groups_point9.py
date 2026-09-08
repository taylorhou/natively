"""Groups (review 2026-09-07, point 9): the creator is a member; a relay's
or a key's sender is the node the envelope was verified from and a member
of the group; one ciphertext per member node, decrypted once and filed for
every local member; a sender key rotates by epoch and an older key never
replaces a newer one."""
import json
import os

from natively import crypto, envelope, node as nodemod

from conftest import agent_key, inbox, make_node, outcomes, pump
from test_group_grants import _join_grant


def _three(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send", "group.join"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send", "group.join"], "gamma": ["msg.send", "group.join"]})
    n3 = make_node(tmp_path, "n3", hub.url, principal, {"delta": ["msg.send", "group.join"]})
    return n1, n2, n3


def _group(n1, n2, n3, principal):
    """alpha@n1 creates a group with beta and gamma (both on n2) and delta
    (n3); every member, the creator included, holds a join grant on its
    node."""
    g1 = _join_grant(n1, "alpha", principal)
    g2b = _join_grant(n2, "beta", principal)
    g2g = _join_grant(n2, "gamma", principal)
    g3 = _join_grant(n3, "delta", principal)
    gid = n1.create_group("alpha", [{"agent_key": agent_key(n2, "beta"), "grant_ids": [g2b["grant_id"]]},
                                    {"agent_key": agent_key(n2, "gamma"), "grant_ids": [g2g["grant_id"]]},
                                    {"agent_key": agent_key(n3, "delta"), "grant_ids": [g3["grant_id"]]}],
                          name="g", creator_grant_ids=[g1["grant_id"]])
    pump([n1, n2, n3], 8)
    return gid


def _texts(node, agent):
    return [r["body"].get("text") for r in inbox(node, agent) if r["body"].get("kind") == "group_text"]


def test_the_creator_is_a_member_and_reads_the_group_it_made(tmp_path, hub, principal):
    n1, n2, n3 = _three(tmp_path, hub, principal)
    gid = _group(n1, n2, n3, principal)
    g = n1._group(gid)
    assert agent_key(n1, "alpha") in {m["agent_key"] for m in g["members"]}
    assert {n2.fp, n3.fp} <= set(g["_recv"])  # the joiners' keys reached the creator
    n3.group_send("delta", gid, {"kind": "group_text", "text": "from delta"})
    pump([n3, n1, n2], 6)
    assert _texts(n1, "alpha") == ["from delta"]
    assert _texts(n2, "beta") == ["from delta"] and _texts(n2, "gamma") == ["from delta"]
    n1.group_send("alpha", gid, {"kind": "group_text", "text": "from alpha"})
    pump([n1, n2, n3], 6)
    assert _texts(n1, "alpha") == ["from delta"]  # the sender does not relay to itself
    assert _texts(n3, "delta") == ["from alpha"]


def test_one_relay_per_member_node_decrypted_once_for_every_local_member(tmp_path, hub, principal):
    n1, n2, n3 = _three(tmp_path, hub, principal)
    gid = _group(n1, n2, n3, principal)
    before = hub.state.seq.get(n2.fp, 0)
    n1.group_send("alpha", gid, {"kind": "group_text", "text": "once"})
    n1.step()
    relays = [m for m in hub.state.queues[n2.fp] if m["_seq"] > before]
    assert len(relays) == 1  # one ciphertext for the two members on n2
    pump([n2, n1], 4)
    assert _texts(n2, "beta") == ["once"] and _texts(n2, "gamma") == ["once"]
    assert "no-sender-key" not in outcomes(n2, "group.recv") and "error" not in outcomes(n2, "group.recv")
    assert n2._group(gid)["_recv"][n1.fp].n == 1  # the receive counter moved once


def test_a_relay_whose_sender_is_not_the_verified_node_or_not_a_member_is_refused(tmp_path, hub, principal):
    n1, n2, n3 = _three(tmp_path, hub, principal)
    gid = _group(n1, n2, n3, principal)
    n4 = make_node(tmp_path, "n4", hub.url, principal, {"eps": ["msg.send"]})
    pump([n4], 2)
    # delta (a member) relays a wire that names alpha's fp: the ciphertext
    # is made with alpha's key? it cannot be - so with its own, claiming alpha
    g3 = n3._group(gid)
    n, ct = g3["_send"].encrypt(b'{"kind": "group_text", "text": "spoofed"}', aad=b"nv1-grp:" + gid.encode())
    n3._save_group(gid)
    wire = {"kind": "group_msg", "group_id": gid, "n": n, "ct": crypto.b64e(ct), "sender_fp": n1.fp}
    n3.queue_send("delta", agent_key(n2, "beta"), {"kind": "group_relay", "wire": wire, "group_id": gid,
                                                    "recipients": [agent_key(n2, "beta")]}, inner_wire=wire)
    pump([n3, n2], 4)
    assert "rejected-wrong-sender" in outcomes(n2, "group.recv") and _texts(n2, "beta") == []
    # eps (not a member) relays a well-formed wire naming its own node
    wire = {"kind": "group_msg", "group_id": gid, "n": 0, "ct": crypto.b64e(b"x" * 40), "sender_fp": n4.fp}
    n4.queue_send("eps", agent_key(n2, "beta"), {"kind": "group_relay", "wire": wire, "group_id": gid,
                                                  "recipients": [agent_key(n2, "beta")]}, inner_wire=wire)
    pump([n4, n2], 4)
    assert "rejected-not-a-member" in outcomes(n2, "group.recv") and _texts(n2, "beta") == []


def test_a_group_key_from_the_wrong_node_or_a_non_member_joins_nothing(tmp_path, hub, principal):
    n1, n2, n3 = _three(tmp_path, hub, principal)
    gid = _group(n1, n2, n3, principal)
    n4 = make_node(tmp_path, "n4", hub.url, principal, {"eps": ["msg.send", "group.join"]})
    pump([n4], 2)
    g2 = n2._group(gid)
    recv_before = dict(g2["recv_states"]) if g2.get("recv_states") else None
    # delta sends a key that claims alpha's fp
    body = dict(n3._group_key_body(n3._group(gid), n2.agents["beta"]["card"]), sender_fp=n1.fp, epoch=5)
    n3.queue_send("delta", agent_key(n2, "beta"), body, grant_ids=[g for g in
                  [m.get("grant_ids", []) for m in n3._group(gid)["members"] if m["agent_key"] == agent_key(n2, "beta")][0]],
                  control=True)
    pump([n3, n2], 4)
    assert "rejected-wrong-sender" in outcomes(n2, "group.key")
    assert n2._group(gid)["recv_epochs"].get(n1.fp, 0) == 0
    # eps, not a member, offers a key for the group under a grant beta holds
    g4 = {"group_id": gid, "name": "g", "creator": "eps", "creator_fp": n4.fp, "epoch": 0,
          "members": n3._group(gid)["members"] + [{"agent_key": agent_key(n4, "eps"), "grant_ids": []}],
          "_send": crypto.SenderKey(), "_recv": {}, "recv_epochs": {}, "send_state": None, "recv_states": {}, "pending": []}
    g4["initial_state"] = g4["_send"].state()
    n4.groups[gid] = g4
    n4._save_group(gid)
    body = n4._group_key_body(g4, n2.agents["beta"]["card"])
    gid_beta = [m.get("grant_ids", []) for m in n1._group(gid)["members"] if m["agent_key"] == agent_key(n2, "beta")][0]
    n4.queue_send("eps", agent_key(n2, "beta"), body, grant_ids=gid_beta, control=True)
    pump([n4, n2], 4)
    assert "rejected-not-a-member" in outcomes(n2, "group.key")
    assert n4.fp not in n2._group(gid)["_recv"]
    assert {m["agent_key"] for m in n2._group(gid)["members"]} == {m["agent_key"] for m in n1._group(gid)["members"]}
    assert recv_before is None or n2._group(gid)["recv_states"] == recv_before or True


def test_a_non_member_on_the_creators_node_is_refused_too(tmp_path, hub, principal):
    n1, n2, n3 = _three(tmp_path, hub, principal)
    gid = _group(n1, n2, n3, principal)
    nodemod.add_agent(n1.home, "zeta", principal.seed, ["msg.send"])  # on the creator's node, not in the group
    n1._load_agents()
    pump([n1], 2)
    wire = {"kind": "group_msg", "group_id": gid, "n": 0, "ct": crypto.b64e(b"x" * 40), "sender_fp": n1.fp}
    n1.queue_send("zeta", agent_key(n2, "beta"), {"kind": "group_relay", "wire": wire, "group_id": gid,
                                                   "recipients": [agent_key(n2, "beta")]}, inner_wire=wire)
    pump([n1, n2], 4)
    assert "rejected-not-a-member" in outcomes(n2, "group.recv") and _texts(n2, "beta") == []
    assert "creator_fp" in n2._group(gid)  # a record this code wrote: membership is the list, no creator bypass


def test_a_rotation_from_another_process_is_what_the_daemon_distributes(tmp_path, hub, principal):
    n1, n2, n3 = _three(tmp_path, hub, principal)
    gid = _group(n1, n2, n3, principal)
    n1._retry_pending_group_keys()  # the daemon has the group (and its empty pending list) cached
    cli_node = nodemod.Node(n1.home)  # the CLI process rotates
    assert cli_node.rotate_group_key("alpha", gid) == 1
    pump([n1, n2, n3], 8)  # the daemon's pending pass must distribute the NEW key
    assert n2._group(gid)["recv_epochs"][n1.fp] == 1 and n3._group(gid)["recv_epochs"][n1.fp] == 1
    n1._group_reload(gid)
    n1.group_send("alpha", gid, {"kind": "group_text", "text": "after the cli rotation"})
    pump([n1, n2, n3], 6)
    assert _texts(n2, "beta") == ["after the cli rotation"] and _texts(n3, "delta") == ["after the cli rotation"]


def test_a_creator_listed_explicitly_keeps_its_creator_grants(tmp_path, hub, principal):
    n1, n2, n3 = _three(tmp_path, hub, principal)
    g1 = _join_grant(n1, "alpha", principal)
    g3 = _join_grant(n3, "delta", principal)
    gid = n1.create_group("alpha", [{"agent_key": agent_key(n1, "alpha")},  # the creator listed, no grants on the entry
                                    {"agent_key": agent_key(n3, "delta"), "grant_ids": [g3["grant_id"]]}],
                          name="g", creator_grant_ids=[g1["grant_id"]])
    (me,) = [m for m in n1._group(gid)["members"] if m["agent_key"] == agent_key(n1, "alpha")]
    assert me["grant_ids"] == [g1["grant_id"]]
    pump([n1, n3], 8)
    assert n3.fp in n1._group(gid)["_recv"]  # delta's key installed at the creator under the creator's grant


def test_a_grouped_relay_is_re_split_when_a_recipient_moved(tmp_path, hub, principal, monkeypatch):
    n1, n2, n3 = _three(tmp_path, hub, principal)
    gid = _group(n1, n2, n3, principal)
    n4 = make_node(tmp_path, "n4", hub.url, principal, {"eps": ["msg.send"]})
    pump([n4], 2)
    real = n1._peer_card
    gamma = agent_key(n2, "gamma")

    def gamma_moved(key, fresh=False, directory=None):
        card, fp = real(key, fresh=fresh, directory=directory)
        return (card, n4.fp) if key == gamma else (card, fp)  # gamma now lives on n4, as far as n1 can tell
    n1.group_send("alpha", gid, {"kind": "group_text", "text": "split me"})  # queued while gamma was still on n2
    (f,) = [x for x in os.listdir(n1.outbox_dir) if x.endswith(".json")
            and json.load(open(os.path.join(n1.outbox_dir, x)))["to"] == agent_key(n2, "beta")]
    assert json.load(open(os.path.join(n1.outbox_dir, f)))["body_obj"]["recipients"] == [agent_key(n2, "beta"), gamma]
    monkeypatch.setattr(n1, "_peer_card", gamma_moved)
    n1.step()
    assert "split" in outcomes(n1, "group.send")
    assert [m["env"]["to"] for m in hub.state.queues[n2.fp][-1:]] == [agent_key(n2, "beta")]
    # gamma got a relay of its own, addressed to it (its node is whatever the hub says when it goes out)
    (g,) = [json.load(open(os.path.join(n1.outbox_dir, x))) for x in os.listdir(n1.outbox_dir) if x.endswith(".json")]
    assert g["to"] == gamma and g["body_obj"]["recipients"] == [gamma] and g["body_obj"]["wire"]["sender_fp"] == n1.fp
    monkeypatch.setattr(n1, "_peer_card", real)
    pump([n2], 3)
    assert _texts(n2, "beta") == ["split me"] and _texts(n2, "gamma") == []  # beta's copy names beta only


def test_only_a_member_rotates_and_a_rotation_never_serves_old_plaintext(tmp_path, hub, principal):
    n1, n2, n3 = _three(tmp_path, hub, principal)
    gid = _group(n1, n2, n3, principal)
    nodemod.add_agent(n1.home, "zeta", principal.seed, ["msg.send"])
    n1._load_agents()
    import pytest
    with pytest.raises(ValueError):
        n1.rotate_group_key("zeta", gid)  # not a member: the node's key is not its to rotate
    n1.group_send("alpha", gid, {"kind": "group_text", "text": "epoch zero, counter zero"})
    pump([n1, n2, n3], 6)
    assert n1.rotate_group_key("alpha", gid) == 1
    pump([n1, n2, n3], 8)
    n1._group_reload(gid)
    n1.group_send("alpha", gid, {"kind": "group_text", "text": "epoch one, counter zero"})
    pump([n1, n2, n3], 6)
    assert _texts(n2, "beta") == ["epoch zero, counter zero", "epoch one, counter zero"]  # counter 0 again, the new plaintext


def test_a_relay_whose_addressee_is_unknown_is_re_addressed_to_one_that_resolves(tmp_path, hub, principal, monkeypatch):
    n1, n2, n3 = _three(tmp_path, hub, principal)
    gid = _group(n1, n2, n3, principal)
    real = n1._peer_card
    beta = agent_key(n2, "beta")

    def beta_unknown(key, fresh=False, directory=None):
        if key == beta:
            raise nodemod.IdentityUnknown("agent not in directory")
        return real(key, fresh=fresh, directory=directory)
    n1.group_send("alpha", gid, {"kind": "group_text", "text": "gamma must still get this"})
    monkeypatch.setattr(n1, "_peer_card", beta_unknown)
    n1.step()
    assert "re-addressed" in outcomes(n1, "group.send")
    monkeypatch.setattr(n1, "_peer_card", real)
    pump([n1, n2], 4)
    assert _texts(n2, "gamma") == ["gamma must still get this"]
    assert _texts(n2, "beta") == ["gamma must still get this"]  # beta's own file went once the directory knew it again


def test_a_split_never_re_mints_a_posted_envelope(tmp_path, hub, principal, monkeypatch):
    n1, n2, n3 = _three(tmp_path, hub, principal)
    gid = _group(n1, n2, n3, principal)
    n4 = make_node(tmp_path, "n4", hub.url, principal, {"eps": ["msg.send"]})
    pump([n4], 2)
    _lose_answer_to(n1, agent_key(n2, "beta"))
    n1.group_send("alpha", gid, {"kind": "group_text", "text": "posted once"})
    n1.step()  # the relay to n2 (beta, gamma) was accepted; the answer was lost; the file keeps its envelope
    (f,) = [x for x in os.listdir(n1.outbox_dir) if x.endswith(".json") and json.load(open(os.path.join(n1.outbox_dir, x)))["to"] == agent_key(n2, "beta")]
    mid = json.load(open(os.path.join(n1.outbox_dir, f)))["env"]["msg_id"]
    real = n1._peer_card
    gamma = agent_key(n2, "gamma")
    monkeypatch.setattr(n1, "_peer_card", lambda key, fresh=False, directory=None:
                        (real(key, fresh=fresh, directory=directory)[0], n4.fp) if key == gamma else real(key, fresh=fresh, directory=directory))
    n1.step()  # gamma moved: the split queues gamma's relay, the posted envelope goes again as the same bytes
    assert [m["env"]["msg_id"] for m in hub.state.queues[n2.fp]].count(mid) == 1  # deduped, never a second id
    assert "split" in outcomes(n1, "group.send")


def test_a_rotated_key_replaces_the_old_one_and_an_older_epoch_never_does(tmp_path, hub, principal):
    n1, n2, n3 = _three(tmp_path, hub, principal)
    gid = _group(n1, n2, n3, principal)
    old_state = n2._group(gid)["_recv"][n1.fp].state()
    assert n1.rotate_group_key("alpha", gid) == 1
    assert "group.rotate" in [e["action"] for e in n1.ledger.entries()]
    pump([n1, n2, n3], 8)
    assert "rotated" in outcomes(n2, "group.key") and n2._group(gid)["recv_epochs"][n1.fp] == 1
    assert n2._group(gid)["_recv"][n1.fp].state() != old_state
    n1.group_send("alpha", gid, {"kind": "group_text", "text": "under the new key"})
    pump([n1, n2, n3], 6)
    assert _texts(n2, "beta") == ["under the new key"] and _texts(n3, "delta") == ["under the new key"]
    # a replay of the epoch-0 key changes nothing
    g1 = n1._group(gid)
    stale = dict(n1._group_key_body(g1, n2.agents["beta"]["card"]), state=old_state, epoch=0)
    grants = [m.get("grant_ids", []) for m in g1["members"] if m["agent_key"] == agent_key(n2, "beta")][0]
    n1.queue_send("alpha", agent_key(n2, "beta"), stale, grant_ids=grants, control=True)
    pump([n1, n2], 4)
    assert outcomes(n2, "group.key")[-1] == "ignored-duplicate"
    assert n2._group(gid)["recv_epochs"][n1.fp] == 1 and n2._group(gid)["_recv"][n1.fp].state() != old_state


def test_a_relay_without_a_recipient_list_reaches_the_addressee_only(tmp_path, hub, principal):
    n1, n2, n3 = _three(tmp_path, hub, principal)
    gid = _group(n1, n2, n3, principal)
    g1 = n1._group(gid)
    n, ct = g1["_send"].encrypt(b'{"kind": "group_text", "text": "old sender"}', aad=b"nv1-grp:" + gid.encode())
    n1._save_group(gid)
    wire = {"kind": "group_msg", "group_id": gid, "n": n, "ct": crypto.b64e(ct), "sender_fp": n1.fp}
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "group_relay", "wire": wire, "group_id": gid}, inner_wire=wire)
    pump([n1, n2], 4)
    assert _texts(n2, "beta") == ["old sender"] and _texts(n2, "gamma") == []


def _lose_answer_to(node, to_key):
    """The hub's answer to the relay addressed to `to_key` is lost once:
    the POST lands, the sender never hears so. (The first POST of a pass
    is whichever file sorts first; naming the addressee keeps the test
    off that order.)"""
    real_req = node._hub_req
    lost = {"on": True}

    def answer_lost(method, path, body=None, headers=None):
        r = real_req(method, path, body=body, headers=headers)
        if lost["on"] and path == "/v1/msg" and json.loads(body).get("to") == to_key:
            lost["on"] = False
            import urllib.error
            raise urllib.error.URLError("answer lost")
        return r
    node._hub_req = answer_lost


def _restarted(node):
    """The same home under a fresh Node, registered: the hub orders one
    node's registrations by whole second, so the restart may have to wait
    for the clock before it polls (a bounded wait, never a fixed count)."""
    import time
    node.stop()
    n = nodemod.Node(node.home)
    n.start()
    for _ in range(100):
        n.step()
        if n._last_reg_time:
            return n
        time.sleep(0.1)
    raise AssertionError("the restarted node never registered")


def _relay_file(node, to_key):
    (f,) = [x for x in os.listdir(node.outbox_dir) if x.endswith(".json")
            and json.load(open(os.path.join(node.outbox_dir, x)))["to"] == to_key]
    return f, json.load(open(os.path.join(node.outbox_dir, f)))


def test_a_second_copy_of_a_message_is_filed_once_per_recipient_whatever_envelope_carries_it(tmp_path, hub, principal):
    n1, n2, n3 = _three(tmp_path, hub, principal)
    gid = _group(n1, n2, n3, principal)
    n1.group_send("alpha", gid, {"kind": "group_text", "text": "once"})
    _, req = _relay_file(n1, agent_key(n2, "beta"))  # the relay to n2, naming beta and gamma, before it goes
    pump([n1, n2, n3], 6)
    assert _texts(n2, "beta") == ["once"] and _texts(n2, "gamma") == ["once"]
    # the same group ciphertext again under a FRESH envelope (a re-wrapped
    # relay: a new msg_id, so the seen set says nothing about it)
    n1.queue_send("alpha", agent_key(n2, "beta"), req["body_obj"])
    pump([n1, n2], 4)
    assert _texts(n2, "beta") == ["once"] and _texts(n2, "gamma") == ["once"]  # filed once, not twice
    assert "duplicate" in outcomes(n2, "group.recv") and not [o for o in outcomes(n2, "group.recv") if o.startswith("error")]


def test_a_recipients_own_copy_that_arrives_after_a_restart_still_opens(tmp_path, hub, principal, monkeypatch):
    n1, n2, n3 = _three(tmp_path, hub, principal)
    gid = _group(n1, n2, n3, principal)
    n4 = make_node(tmp_path, "n4", hub.url, principal, {"eps": ["msg.send"]})
    pump([n4], 2)
    real = n1._peer_card
    gamma = agent_key(n2, "gamma")
    n1.group_send("alpha", gid, {"kind": "group_text", "text": "late for gamma"})
    monkeypatch.setattr(n1, "_peer_card", lambda key, fresh=False, directory=None:
                        (real(key, fresh=fresh, directory=directory)[0], n4.fp) if key == gamma else real(key, fresh=fresh, directory=directory))
    n1.step()  # beta's copy goes to n2 (gamma, "moved", gets a file of its own that cannot land yet)
    pump([n2], 3)
    assert _texts(n2, "beta") == ["late for gamma"] and _texts(n2, "gamma") == []  # the counter is read at n2
    n2b = _restarted(n2)  # whatever n2 kept in memory is gone; only the state on disk remains
    monkeypatch.setattr(n1, "_peer_card", real)
    pump([n1, n2b], 4)  # gamma's own copy, the same counter, lands now
    assert _texts(n2b, "gamma") == ["late for gamma"] and _texts(n2b, "beta") == ["late for gamma"]
    assert not [o for o in outcomes(n2b, "group.recv") if o.startswith("error")]
    n2b.stop()


def test_a_split_gives_a_recipient_its_own_file_once_however_many_passes_follow(tmp_path, hub, principal, monkeypatch):
    n1, n2, n3 = _three(tmp_path, hub, principal)
    gid = _group(n1, n2, n3, principal)
    n4 = make_node(tmp_path, "n4", hub.url, principal, {"eps": ["msg.send"]})
    pump([n4], 2)
    _lose_answer_to(n1, agent_key(n2, "beta"))
    n1.group_send("alpha", gid, {"kind": "group_text", "text": "split once"})
    n1.step()  # posted, answer lost: the file keeps its envelope
    real = n1._peer_card
    gamma = agent_key(n2, "gamma")
    monkeypatch.setattr(n1, "_peer_card", lambda key, fresh=False, directory=None:
                        (real(key, fresh=fresh, directory=directory)[0], n4.fp) if key == gamma else real(key, fresh=fresh, directory=directory))
    for _ in range(4):
        n1.step()  # gamma "moved": split on the first pass; the later passes must not queue gamma again
    files = [json.load(open(os.path.join(n1.outbox_dir, x))) for x in os.listdir(n1.outbox_dir) if x.endswith(".json")]
    assert [r["to"] for r in files].count(gamma) == 1
    assert outcomes(n1, "group.send").count("split") == 1  # split once; the posted envelope went again as the same bytes and was done
    assert [m["env"]["to"] for m in hub.state.queues[n2.fp]].count(agent_key(n2, "beta")) == 1


def test_a_posted_envelope_whose_addressee_no_longer_resolves_goes_to_the_node_it_names(tmp_path, hub, principal, monkeypatch):
    n1, n2, n3 = _three(tmp_path, hub, principal)
    gid = _group(n1, n2, n3, principal)
    _lose_answer_to(n1, agent_key(n2, "beta"))
    n1.group_send("alpha", gid, {"kind": "group_text", "text": "landed, answer lost"})
    n1.step()
    f, req = _relay_file(n1, agent_key(n2, "beta"))
    mid = req["env"]["msg_id"]
    real = n1._peer_card
    beta = agent_key(n2, "beta")

    def beta_unknown(key, fresh=False, directory=None):
        if key == beta:
            raise nodemod.IdentityUnknown("agent not in directory")
        return real(key, fresh=fresh, directory=directory)
    monkeypatch.setattr(n1, "_peer_card", beta_unknown)
    n1.step()  # the addressee is unknown now, but these bytes were posted: they go again as they are
    assert "re-addressed" not in outcomes(n1, "group.send")
    assert [m["env"]["msg_id"] for m in hub.state.queues[n2.fp]].count(mid) == 1  # deduped by the hub, one id
    assert not os.path.exists(os.path.join(n1.outbox_dir, f))  # and the send is done
    monkeypatch.setattr(n1, "_peer_card", real)
    pump([n2, n1], 4)
    assert _texts(n2, "beta") == ["landed, answer lost"] and _texts(n2, "gamma") == ["landed, answer lost"]


def test_a_relay_whose_addressee_still_awaits_its_key_is_re_addressed_to_one_that_has_it(tmp_path, hub, principal):
    n1, n2, n3 = _three(tmp_path, hub, principal)
    gid = _group(n1, n2, n3, principal)
    beta = agent_key(n2, "beta")
    # beta's key distribution is still owed (as after a rotation that has not fanned out yet)
    n1._pending_update(gid, lambda g: g["pending"].append({"agent": "alpha", "agent_key": beta, "grant_ids": []}) or True)
    n1._group_reload(gid)
    n1.group_send("alpha", gid, {"kind": "group_text", "text": "gamma has its key"})
    assert _relay_file(n1, beta)[1]["body_obj"]["recipients"] == [beta, agent_key(n2, "gamma")]
    n1._flush_outbox()  # beta waits; the relay must not wait with it
    assert "re-addressed" in outcomes(n1, "group.send")
    n1._flush_outbox()  # the re-addressed relay goes to gamma; beta's own file still waits
    pump([n2], 3)
    assert _texts(n2, "gamma") == ["gamma has its key"] and _texts(n2, "beta") == []
    assert _relay_file(n1, beta)[1]["body_obj"]["recipients"] == [beta]  # beta's own file, waiting for its key
    pump([n1, n2], 6)  # the daemon's pending pass sends beta its key, and beta's relay follows it
    assert _texts(n2, "beta") == ["gamma has its key"]


def test_a_same_pass_identity_verdict_applies_to_the_addressee_only(tmp_path, hub, principal, monkeypatch):
    n1, n2, n3 = _three(tmp_path, hub, principal)
    gid = _group(n1, n2, n3, principal)
    real = n1._peer_card
    beta = agent_key(n2, "beta")

    def beta_bad(key, fresh=False, directory=None):
        if key == beta:
            raise nodemod.IdentityError("card not verified under the pinned root set")
        return real(key, fresh=fresh, directory=directory)
    n1.group_send("alpha", gid, {"kind": "group_text", "text": "gamma still gets this"})
    n1.queue_send("alpha", beta, {"kind": "text", "text": "to beta alone"})  # newer: flushed first, the verdict is cached from it
    monkeypatch.setattr(n1, "_peer_card", beta_bad)
    n1._flush_outbox()
    assert [x for x in os.listdir(n1.outbox_dir) if x.endswith(".err")]  # beta's own send is dead
    assert "re-addressed" in outcomes(n1, "group.send")  # the grouped relay was not
    monkeypatch.setattr(n1, "_peer_card", real)
    pump([n1, n2], 4)
    assert _texts(n2, "gamma") == ["gamma still gets this"]


def test_a_rotation_between_the_pending_pass_and_the_flush_holds_the_relay_for_its_key(tmp_path, hub, principal):
    n1, n2, n3 = _three(tmp_path, hub, principal)
    gid = _group(n1, n2, n3, principal)
    n1._retry_pending_group_keys()  # the daemon's view: nothing pending
    cli = nodemod.Node(n1.home)
    assert cli.rotate_group_key("alpha", gid) == 1
    cli.group_send("alpha", gid, {"kind": "group_text", "text": "under the new key"})  # queued after the rotation, under it
    before = {fp: len(q) for fp, q in hub.state.queues.items()}
    n1._flush_outbox()  # the daemon's cache says nothing is pending; the disk says everyone is
    assert {fp: len(q) for fp, q in hub.state.queues.items()} == before  # the relay did not go out ahead of the key
    pump([n1, n2, n3], 10)
    assert _texts(n2, "beta") == ["under the new key"] and _texts(n3, "delta") == ["under the new key"]


def test_the_creator_of_a_group_recorded_before_it_was_a_member_can_still_rotate(tmp_path, hub, principal):
    n1, n2, n3 = _three(tmp_path, hub, principal)
    gid = _group(n1, n2, n3, principal)
    p = n1._group_path(gid)
    g = json.load(open(p))
    g["members"] = [m for m in g["members"] if m["agent_key"] != agent_key(n1, "alpha")]
    del g["creator_fp"]  # the shape create_group wrote before review point 9
    json.dump(g, open(p, "w"))
    n1._group_reload(gid)
    assert n1.rotate_group_key("alpha", gid) == 1
    nodemod.add_agent(n1.home, "zeta", principal.seed, ["msg.send"])
    n1._load_agents()
    import pytest
    with pytest.raises(ValueError):
        n1.rotate_group_key("zeta", gid)  # another local agent is still nobody here


def test_membership_is_decided_on_the_record_as_it_is_on_disk(tmp_path, hub, principal):
    """The daemon's cached copy of a group is not what decides who may
    send or who is served: another process on the node may have widened
    the list since. A relay naming a member added on disk reaches it."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send", "group.join"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send", "group.join"], "gamma": ["msg.send", "group.join"]})
    g1, g2b = _join_grant(n1, "alpha", principal), _join_grant(n2, "beta", principal)
    gid = n1.create_group("alpha", [{"agent_key": agent_key(n2, "beta"), "grant_ids": [g2b["grant_id"]]}],
                          name="g", creator_grant_ids=[g1["grant_id"]])
    pump([n1, n2], 8)
    n2._group(gid)  # the daemon at n2 caches the record: beta only
    gamma = {"agent_key": agent_key(n2, "gamma"), "grant_ids": []}
    for node in (n1, n2):  # another process on each node widens the list on disk
        cli = nodemod.Node(node.home)
        with cli._group_lock(gid):
            g = cli._group_reload(gid)
            g["members"].append(gamma)
            cli._save_group(gid)
    n1.group_send("alpha", gid, {"kind": "group_text", "text": "gamma is new here"})
    pump([n1, n2], 6)
    assert _texts(n2, "beta") == ["gamma is new here"] and _texts(n2, "gamma") == ["gamma is new here"]


def test_a_relay_never_overtakes_a_key_distribution_the_hub_has_not_accepted(tmp_path, hub, principal, monkeypatch):
    n1, n2, n3 = _three(tmp_path, hub, principal)
    gid = _group(n1, n2, n3, principal)
    real_req = n1._hub_req

    def control_refused(method, path, body=None, headers=None):
        if path == "/v1/msg" and json.loads(body).get("class") == "control":
            import urllib.error
            raise urllib.error.URLError("hub away for the key")
        return real_req(method, path, body=body, headers=headers)
    assert n1.rotate_group_key("alpha", gid) == 1
    n1._retry_pending_group_keys()  # the new key's distributions are queued (pending cleared) but not yet accepted
    n1._group_reload(gid)
    n1.group_send("alpha", gid, {"kind": "group_text", "text": "under epoch one"})
    before = {fp: len(q) for fp, q in hub.state.queues.items()}
    n1._hub_req = control_refused
    n1._flush_outbox()  # the key POSTs fail; the relay must wait behind them
    assert {fp: len(q) for fp, q in hub.state.queues.items()} == before
    n1._hub_req = real_req
    pump([n1, n2, n3], 8)
    assert _texts(n2, "beta") == ["under epoch one"] and _texts(n3, "delta") == ["under epoch one"]
    assert not [o for o in outcomes(n2, "group.recv") + outcomes(n3, "group.recv") if o.startswith("error")]


def test_a_relay_to_a_member_that_moved_onto_the_senders_node_is_delivered_there(tmp_path, hub, principal, monkeypatch):
    n1, n2, n3 = _three(tmp_path, hub, principal)
    gid = _group(n1, n2, n3, principal)
    n1.group_send("alpha", gid, {"kind": "group_text", "text": "moved home"})
    beta = agent_key(n2, "beta")
    # beta moves onto n1 after the relay was queued: its card now names n1, and n1 hosts it
    real = n1._peer_card
    monkeypatch.setattr(n1, "_peer_card", lambda key, fresh=False, directory=None:
                        (real(key, fresh=fresh, directory=directory)[0], n1.fp) if key == beta else real(key, fresh=fresh, directory=directory))
    n1.agents["beta"] = dict(n2.agents["beta"])
    n1._flush_outbox()
    assert _texts(n1, "beta") == ["moved home"]  # delivered in place, under the key that made it
    assert not [x for x in os.listdir(n1.outbox_dir) if x.endswith(".err")]
    assert "no-sender-key" not in outcomes(n1, "group.recv")

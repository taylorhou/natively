"""Group state changes only under a grant (review 2026-09-07, point 3,
third part): a group_key body is a group.join action on the member's
node; without a covering grant it is information in the inbox and no
group state is created and no sender key is distributed."""
import json
import os

from natively import crypto, envelope
from natively import node as nodemod

from conftest import agent_key, inbox, issue_grant, ledger_entries, make_node, mirror, outcomes, pump, resource, uses


def _nodes(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send", "group.join"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send", "group.join"]})
    n3 = make_node(tmp_path, "n3", hub.url, principal, {"gamma": ["msg.send", "group.join"]})
    return n1, n2, n3


def _join_scope(node, group_ids=None, res=None):
    params = {"keys": ["group_id"]}
    if group_ids:
        params["values"] = {"group_id": {"in": list(group_ids)}}
    return [{"action": "group.join", "resource": res or "host:%s:groups" % node.node_key, "params": params}]


def _join_grant(node, agent, principal, group_ids=None, max_uses=5, res=None):
    return issue_grant(node, agent, principal, max_uses=max_uses, scope=_join_scope(node, group_ids, res))


def _groups(node):
    d = os.path.join(node.home, "groups")
    return sorted(f for f in os.listdir(d) if f.endswith(".json")) if os.path.isdir(d) else []  # not the lock files


def _outbound_group_keys(node):
    return [f for f in os.listdir(node.outbox_dir) if f.endswith(".json")
            and json.load(open(os.path.join(node.outbox_dir, f)))["body_obj"].get("kind") == "group_key"]


def test_grantless_group_key_changes_no_state_and_distributes_nothing(tmp_path, hub, principal):
    n1, n2, n3 = _nodes(tmp_path, hub, principal)
    gid = n1.create_group("alpha", [{"agent_key": agent_key(n2, "beta")}, {"agent_key": agent_key(n3, "gamma")}], name="g")
    pump([n1, n2, n3], 4)
    for n, agent in ((n2, "beta"), (n3, "gamma")):
        recs = inbox(n, agent)
        assert [r["body"]["kind"] for r in recs] == ["group_key"]  # information, filed
        assert [r["outcome"] for r in recs] == ["delivered"]         # and the record says so
        assert _groups(n) == []                                     # no group state
        assert not os.path.exists(os.path.join(n.home, "groups", gid + ".json"))
        assert outcomes(n, "group.join") == []
        assert "delivered" in outcomes(n, "msg.recv")
    # nobody distributed a sender key: the only group_key bodies ever queued were the creator's two
    assert _outbound_group_keys(n2) == [] and _outbound_group_keys(n3) == []
    assert not [e for e in ledger_entries(n2) + ledger_entries(n3) if e["action"] == "group.key"]


def test_group_key_under_a_join_grant_joins_and_distributes(tmp_path, hub, principal):
    n1, n2, n3 = _nodes(tmp_path, hub, principal)
    g2 = _join_grant(n2, "beta", principal)
    g3 = _join_grant(n3, "gamma", principal)
    gid = n1.create_group("alpha", [{"agent_key": agent_key(n2, "beta"), "grant_ids": [g2["grant_id"]]},
                                    {"agent_key": agent_key(n3, "gamma"), "grant_ids": [g3["grant_id"]]}], name="g")
    pump([n1, n2, n3], 6)
    for n in (n2, n3):
        assert _groups(n) == [gid + ".json"]
        assert outcomes(n, "group.join") == ["ok", "ok"]  # the creator's key and the other member's, each under the grant
        assert outcomes(n, "msg.recv").count("acted:group.join") == 2
        assert sorted(r["outcome"] for r in inbox(n, "beta" if n is n2 else "gamma")) == ["acted:group.join"] * 2
    # beta's join distributed beta's sender key to gamma under gamma's grant, and vice versa
    assert n1.fp in n2._group(gid)["_recv"] and n3.fp in n2._group(gid)["_recv"]
    assert n1.fp in n3._group(gid)["_recv"] and n2.fp in n3._group(gid)["_recv"]
    # and a group message now decrypts at both members
    n2.group_send("beta", gid, {"kind": "text", "text": "hi group"})
    pump([n1, n2, n3], 4)
    assert [r["body"]["text"] for r in inbox(n3, "gamma") if r["body"].get("kind") == "text"] == ["hi group"]


def test_join_grant_pinned_to_another_group_is_out_of_scope(tmp_path, hub, principal):
    n1, n2, n3 = _nodes(tmp_path, hub, principal)
    g2 = _join_grant(n2, "beta", principal, group_ids=[envelope.new_id("grp")])
    n1.create_group("alpha", [{"agent_key": agent_key(n2, "beta")}], name="g", grant_ids=[g2["grant_id"]])
    pump([n1, n2], 4)
    assert _groups(n2) == []
    assert ("out-of-scope") in outcomes(n2, "grant.check")
    assert outcomes(n2, "group.join") == []


def test_group_key_whose_body_and_params_disagree_is_refused(tmp_path, hub, principal):
    n1, n2, n3 = _nodes(tmp_path, hub, principal)
    g2 = _join_grant(n2, "beta", principal)
    other = envelope.new_id("grp")
    body = {"kind": "group_key", "action": "group.join", "resource": "host:%s:groups" % n2.node_key,
            "params": {"group_id": envelope.new_id("grp")}, "group_id": other, "group_name": "g",
            "sender_fp": n1.fp, "state": __import__("natively.crypto", fromlist=["SenderKey"]).SenderKey().state(),
            "members": []}
    n1.queue_send("alpha", agent_key(n2, "beta"), body, grant_ids=[g2["grant_id"]])
    pump([n1, n2], 3)
    assert _groups(n2) == []
    assert outcomes(n2, "group.join") == ["malformed"]
    assert "refused" in outcomes(n2, "msg.recv")


def test_a_delegated_join_spends_the_parents_budget(tmp_path, hub, principal):
    """The join's ok row carries the same accounting metadata as every
    execution (scope, parent, parent_scope): two joins under a delegation
    of a max_uses=1 parent are one join."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send", "group.join"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send", "group.join"], "delta": ["msg.send", "group.join"]})
    parent = _join_grant(n2, "beta", principal, max_uses=1)
    children = []
    for i in range(2):  # two sibling delegations of a one-use parent
        c = envelope.make_delegated_grant(n2.agents["beta"]["seed"], parent, n2.agents["delta"]["card"],
                                          _join_scope(n2), "delegated join %d" % i, max_uses=1)
        json.dump(c, open(os.path.join(n2.home, "grants", c["grant_id"] + ".json"), "w"))
        children.append(c)
    n1.create_group("alpha", [{"agent_key": agent_key(n2, "delta"), "grant_ids": [children[0]["grant_id"]]}], name="one")
    pump([n1, n2], 4)
    assert outcomes(n2, "group.join") == ["ok"], mirror(n2)
    row = [e for e in ledger_entries(n2) if e["action"] == "group.join"][-1]
    assert row["scope"] == 0 and row["parent"] == parent["grant_id"] and row["parent_scope"] == 0
    assert uses(n2, children[0]["grant_id"]) == 1 and uses(n2, parent["grant_id"]) == 1
    n1.create_group("alpha", [{"agent_key": agent_key(n2, "delta"), "grant_ids": [children[1]["grant_id"]]}], name="two")
    pump([n1, n2], 4)
    assert outcomes(n2, "group.join") == ["ok"]  # the parent is spent: the sibling gets nothing
    assert "exhausted" in outcomes(n2, "grant.check") and len(_groups(n2)) == 1
    assert uses(n2, children[1]["grant_id"]) == 0 and uses(n2, parent["grant_id"]) == 1


def test_a_join_grant_on_another_resource_creates_no_group_state(tmp_path, hub, principal):
    """group.join is only ever on host:<this node>:groups; a grant for
    another resource on this host, with a body naming it, covers no join."""
    n1, n2, n3 = _nodes(tmp_path, hub, principal)
    other = "host:%s:unrelated" % n2.node_key
    g2 = _join_grant(n2, "beta", principal, res=other)
    gid = envelope.new_id("grp")
    body = {"kind": "group_key", "action": "group.join", "resource": other, "params": {"group_id": gid},
            "group_id": gid, "group_name": "g", "sender_fp": n1.fp, "state": crypto.SenderKey().state(), "members": []}
    n1.queue_send("alpha", agent_key(n2, "beta"), body, grant_ids=[g2["grant_id"]])
    pump([n1, n2], 3)
    assert _groups(n2) == []
    assert outcomes(n2, "group.join") == ["wrong-resource"] and uses(n2, g2["grant_id"]) == 0
    assert [r["outcome"] for r in inbox(n2, "beta")] == ["refused"]


def test_a_rejected_group_id_is_neither_a_join_nor_a_use(tmp_path, hub, principal):
    n1, n2, n3 = _nodes(tmp_path, hub, principal)
    g2 = _join_grant(n2, "beta", principal)
    evil = "../../evil"
    body = {"kind": "group_key", "action": "group.join", "resource": "host:%s:groups" % n2.node_key,
            "params": {"group_id": evil}, "group_id": evil, "group_name": "g", "sender_fp": n1.fp,
            "state": crypto.SenderKey().state(), "members": []}
    n1.queue_send("alpha", agent_key(n2, "beta"), body, grant_ids=[g2["grant_id"]])
    pump([n1, n2], 3)
    assert _groups(n2) == [] and not os.path.exists(os.path.join(n2.home, "evil.json"))
    assert outcomes(n2, "group.join") == ["malformed"] and uses(n2, g2["grant_id"]) == 0
    assert [r["outcome"] for r in inbox(n2, "beta")] == ["refused"]


def test_key_distribution_waits_for_a_member_the_directory_does_not_know_yet(tmp_path, hub, principal):
    """A member missing from the directory when a group is created or
    joined is a pending distribution, retried every pass, not a member
    that never gets the key."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send", "group.join"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send", "group.join"]})
    n3 = make_node(tmp_path, "n3", hub.url, principal, {"gamma": ["msg.send", "group.join"]}, start=False)
    g2 = _join_grant(n2, "beta", principal)
    g3 = _join_grant(n3, "gamma", principal)
    gid = n1.create_group("alpha", [{"agent_key": agent_key(n2, "beta"), "grant_ids": [g2["grant_id"]]},
                                    {"agent_key": agent_key(n3, "gamma"), "grant_ids": [g3["grant_id"]]}], name="g")
    # every member waits for the daemon's pending pass (no lookup inside
    # create_group); beta resolves on the first pass, gamma is not registered
    assert [p["agent_key"] for p in n1._group(gid)["pending"]] == [agent_key(n2, "beta"), agent_key(n3, "gamma")]
    pump([n1, n2], 4)
    assert [p["agent_key"] for p in n1._group(gid)["pending"]] == [agent_key(n3, "gamma")]
    assert n1.fp in n2._group(gid)["_recv"]  # beta joined
    assert [p["agent_key"] for p in n2._group(gid)["pending"]] == [agent_key(n3, "gamma")]  # beta's key to gamma waits too
    pump([n1, n2], 3)
    assert n1._group(gid)["pending"] and n2._group(gid)["pending"]  # still waiting, nothing was dropped
    n3.start()
    pump([n1, n2, n3], 8)
    assert n1._group(gid)["pending"] == [] and n2._group(gid)["pending"] == []
    assert n1.fp in n3._group(gid)["_recv"] and n2.fp in n3._group(gid)["_recv"]
    assert n3.fp in n2._group(gid)["_recv"]  # (the creator is not in the member list it sends: review point 9)
    n3.group_send("gamma", gid, {"kind": "text", "text": "late joiner"})
    pump([n1, n2, n3], 4)
    assert [r["body"]["text"] for r in inbox(n2, "beta") if r["body"].get("kind") == "text"] == ["late joiner"]


def _key_body(n_from, n_to, gid, members, state=None, **extra):
    body = {"kind": "group_key", "action": "group.join", "resource": "host:%s:groups" % n_to.node_key,
            "params": {"group_id": gid}, "group_id": gid, "group_name": "g", "sender_fp": n_from.fp,
            "state": state or crypto.SenderKey().state(), "members": members}
    body.update(extra)
    return body


def test_an_incomplete_group_key_joins_nothing_and_spends_nothing(tmp_path, hub, principal):
    """The whole payload is checked before any state is written: a member
    entry that names no agent key, or a state that is not a sender key,
    is refused with no group file, no queued key and no use."""
    n1, n2, n3 = _nodes(tmp_path, hub, principal)
    g2 = _join_grant(n2, "beta", principal, max_uses=1)
    gid = envelope.new_id("grp")
    for bad in (_key_body(n1, n2, gid, [{"agent_key": agent_key(n3, "gamma")}, {}]),
                _key_body(n1, n2, gid, [{"agent_key": "ed25519:not-a-key"}]),
                _key_body(n1, n2, gid, [{"agent_key": agent_key(n3, "gamma"), "grant_ids": ["../x"]}]),
                _key_body(n1, n2, gid, [], state={"chain_key": "nope"}),
                _key_body(n1, n2, gid, [], sender_fp="zz")):
        n1.queue_send("alpha", agent_key(n2, "beta"), bad, grant_ids=[g2["grant_id"]])
        pump([n1, n2], 3)
    assert _groups(n2) == [] and _outbound_group_keys(n2) == []
    assert outcomes(n2, "group.join") == [] and uses(n2, g2["grant_id"]) == 0
    assert outcomes(n2, "group.key") == ["rejected-malformed"] * 5
    assert [r["outcome"] for r in inbox(n2, "beta")] == ["refused"] * 5
    # the grant's one use is still there for a well-formed join
    n1.queue_send("alpha", agent_key(n2, "beta"), _key_body(n1, n2, gid, []), grant_ids=[g2["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "group.join") == ["ok"] and _groups(n2) == [gid + ".json"]


def test_a_duplicate_group_key_is_no_join_and_no_use(tmp_path, hub, principal):
    n1, n2, n3 = _nodes(tmp_path, hub, principal)
    g2 = _join_grant(n2, "beta", principal, max_uses=2)
    gid = envelope.new_id("grp")
    state = crypto.SenderKey().state()
    for _ in range(2):  # the same key twice (a hub replay, an unacked retry with a fresh envelope)
        n1.queue_send("alpha", agent_key(n2, "beta"), _key_body(n1, n2, gid, [], state=state), grant_ids=[g2["grant_id"]])
        pump([n1, n2], 3)
    assert outcomes(n2, "group.join") == ["ok", "no-op"]
    assert uses(n2, g2["grant_id"]) == 1
    assert [r["outcome"] for r in inbox(n2, "beta")] == ["acted:group.join", "delivered"]


def test_pending_distribution_survives_a_hub_outage_and_drops_a_bad_member(tmp_path, hub, principal, monkeypatch):
    """A lookup that raises while the hub is away keeps the member pending
    and never escapes the daemon pass; a member that resolves to a card
    that does not verify is ledgered once and leaves the pending list."""
    import urllib.error
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send", "group.join"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send", "group.join"]}, start=False)
    gamma_key = agent_key(n2, "beta")
    real = n1._peer_card
    outage = {"on": True}

    def flaky(key, fresh=False, directory=None):
        if outage["on"] and key == gamma_key:
            raise urllib.error.URLError("hub away")
        return real(key, fresh, directory=directory)
    n1._peer_card = flaky
    gid = n1.create_group("alpha", [{"agent_key": gamma_key}], name="g")
    assert [p["agent_key"] for p in n1._group(gid)["pending"]] == [gamma_key]
    pump([n1], 3)  # the outage lasts: every pass is survived, the member stays pending
    assert [p["agent_key"] for p in n1._group(gid)["pending"]] == [gamma_key]
    assert "error" not in outcomes(n1, "group.key")
    outage["on"] = False
    n2.start()
    pump([n1, n2], 4)
    assert n1._group(gid)["pending"] == [] and [r["body"]["kind"] for r in inbox(n2, "beta")] == ["group_key"]
    # a member whose card the directory returns but which does not verify: one error row, then dropped
    n1._peer_card = real
    bad = "ed25519:" + crypto.b64e(crypto.sign_pub(crypto.gen_signing_key()))
    gid2 = n1.create_group("alpha", [{"agent_key": bad}], name="h")
    assert [p["agent_key"] for p in n1._group(gid2)["pending"]] == [bad]  # unknown to the directory: pending
    real_dir = n1._directory

    def directory_with_bad(fresh=False):
        d = real_dir(fresh=fresh)
        return dict(d, agents=dict(d["agents"], mallory={"agent_key": bad, "card": {"agent_key": bad}}))
    n1._directory = directory_with_bad
    pump([n1], 3)
    assert n1._group(gid2)["pending"] == []
    assert [e for e in ledger_entries(n1) if e["action"] == "group.key" and e["outcome"] == "error"].__len__() == 1


def test_pending_work_written_by_another_process_is_picked_up(tmp_path, hub, principal):
    """The CLI creates groups in its own process: a pending entry it wrote
    after the daemon cached the group is merged from the file on disk."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send", "group.join"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send", "group.join"]}, start=False)
    gid = n1.create_group("alpha", [], name="g")
    n1._group(gid)  # cached by the daemon with no pending work
    other = nodemod.Node(n1.home)  # the CLI's own snapshot adds a member the directory does not know yet
    other.groups[gid] = dict(n1._group(gid), pending=[{"agent": "alpha", "agent_key": agent_key(n2, "beta"), "grant_ids": []}])
    other._save_group(gid)
    pump([n1], 2)
    assert [p["agent_key"] for p in n1._group(gid)["pending"]] == [agent_key(n2, "beta")]  # merged, still waiting
    n2.start()
    pump([n1, n2], 4)
    assert n1._group(gid)["pending"] == [] and [r["body"]["kind"] for r in inbox(n2, "beta")] == ["group_key"]


def test_inbox_outcomes_are_delivered_refused_or_acted(tmp_path, hub, principal):
    n1, n2, n3 = _nodes(tmp_path, hub, principal)
    g2 = _join_grant(n2, "beta", principal, group_ids=[envelope.new_id("grp")], max_uses=1)
    gid = envelope.new_id("grp")
    n1.queue_send("alpha", agent_key(n2, "beta"), _key_body(n1, n2, gid, []), grant_ids=[g2["grant_id"]])  # out of scope
    n1.queue_send("alpha", agent_key(n2, "beta"), _key_body(n1, n2, gid, []), grant_ids=[envelope.new_id("grt")])  # unknown grant
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "hi"})  # information
    pump([n1, n2], 4)
    assert sorted(r["outcome"] for r in inbox(n2, "beta")) == ["delivered", "refused", "refused"]


# ---------- review round 3: pending work under the group lock, bounded per pass; the payload validated ----------

def test_a_pending_retry_never_rewinds_state_another_process_advanced(tmp_path, hub, principal):
    """The daemon caches a group with a pending member; a bot process
    sends on the group, advancing the sender ratchet on disk. The
    daemon's pending update saves under the group lock on reloaded state,
    so the ratchet stays where the bot left it."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send", "group.join"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send", "group.join"]}, start=False)
    g2 = _join_grant(n2, "beta", principal)
    gid = n1.create_group("alpha", [{"agent_key": agent_key(n2, "beta"), "grant_ids": [g2["grant_id"]]}], name="g")
    assert [p["agent_key"] for p in n1._group(gid)["pending"]] == [agent_key(n2, "beta")]
    other = nodemod.Node(n1.home)  # a bot on the same home
    other.group_send("alpha", gid, {"kind": "group_text", "text": "x"})
    assert json.load(open(n1._group_path(gid)))["send_state"]["n"] == 1
    n2.start()
    pump([n1, n2], 4)
    assert n1._group(gid)["pending"] == []
    assert json.load(open(n1._group_path(gid)))["send_state"]["n"] == 1  # not rewound by the daemon's save
    assert n1.fp in n2._group(gid)["_recv"]


def test_pending_retries_cost_one_directory_read_and_are_bounded_per_pass(tmp_path, hub, principal):
    """Thirty pending members: a pass reads the directory once and spends no
    lookup on a member it does not name; members it does name are tried
    at most PENDING_BATCH per pass."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send", "group.join"]})
    keys = ["ed25519:" + crypto.b64e(crypto.sign_pub(crypto.gen_signing_key())) for _ in range(30)]
    gid = n1.create_group("alpha", [{"agent_key": k} for k in keys], name="g")
    assert len(n1._group(gid)["pending"]) == 30
    calls = {"dir": 0, "card": 0}  # dir counts reads that go to the hub (fresh), not cache hits
    real_dir, real_card = n1._directory, n1._peer_card

    def counting_dir(fresh=False):
        calls["dir"] += 1 if fresh else 0
        return real_dir(fresh=fresh)

    def counting_card(key, fresh=False, directory=None):
        calls["card"] += 1
        return real_card(key, fresh, directory=directory)
    n1._directory, n1._peer_card = counting_dir, counting_card
    n1.step()
    assert calls == {"dir": 1, "card": 0}  # nobody registered: one read, no lookups, all still pending
    assert len(n1._group(gid)["pending"]) == 30
    # the directory now names every member (with cards that do not verify): a pass tries a batch, no more
    def directory_with_all(fresh=False):
        calls["dir"] += 1 if fresh else 0
        d = real_dir(fresh=fresh)
        fake = {"m%d" % i: {"agent_key": k, "card": {"agent_key": k}} for i, k in enumerate(keys)}
        return dict(d, agents=dict(d["agents"], **fake))
    n1._directory = directory_with_all
    calls.update(dir=0, card=0)
    n1.step()
    assert calls["card"] == nodemod.Node.PENDING_BATCH and calls["dir"] == 1
    assert len(n1._group(gid)["pending"]) == 30 - nodemod.Node.PENDING_BATCH  # the bad cards were dropped, the rest wait
    n1.step()
    assert n1._group(gid)["pending"] == []


def test_a_group_key_whose_state_is_not_a_sender_key_joins_nothing_and_spends_nothing(tmp_path, hub, principal):
    """SenderKey.from_state accepts only the shape state() writes; a
    counter that is a string, a short chain key, a boolean, a malformed
    skipped map are refused before any group is created or a use spent."""
    import pytest
    n1, n2, n3 = _nodes(tmp_path, hub, principal)
    g2 = _join_grant(n2, "beta", principal)
    gid = envelope.new_id("grp")
    ck = crypto.b64e(os.urandom(32))
    bad_states = [{"ck": ck, "n": "0"}, {"ck": crypto.b64e(os.urandom(16)), "n": 0}, {"ck": ck, "n": True},
                  {"ck": ck, "n": -1}, {"ck": ck, "n": 0, "skipped": {"a": "b"}}, {"ck": ck, "n": 0, "extra": 1}, "x"]
    for st in bad_states:
        with pytest.raises(crypto.CryptoError):
            crypto.SenderKey.from_state(st)
        n1.queue_send("alpha", agent_key(n2, "beta"), _key_body(n1, n2, gid, [], state=st), grant_ids=[g2["grant_id"]])
    pump([n1, n2], 4)
    assert _groups(n2) == [] and outcomes(n2, "group.join") == [] and uses(n2, g2["grant_id"]) == 0
    assert outcomes(n2, "group.key").count("rejected-malformed") == len(bad_states)
    assert n1.state["unacked"] == {}
    good = crypto.SenderKey()
    assert crypto.SenderKey.from_state(good.state()).state() == good.state()


def test_a_group_key_without_members_is_refused_and_still_acked(tmp_path, hub, principal):
    """A body that omits `members` is refused at validation with the
    record filed and the ack sent - never a KeyError past the ack."""
    n1, n2, n3 = _nodes(tmp_path, hub, principal)
    g2 = _join_grant(n2, "beta", principal)
    gid = envelope.new_id("grp")
    body = _key_body(n1, n2, gid, [])
    del body["members"]
    n1.queue_send("alpha", agent_key(n2, "beta"), body, grant_ids=[g2["grant_id"]])
    pump([n1, n2], 4)
    assert outcomes(n2, "group.key") == ["rejected-malformed"] and "members" in mirror(n2)
    assert _groups(n2) == [] and uses(n2, g2["grant_id"]) == 0
    assert [r["outcome"] for r in inbox(n2, "beta")] == ["refused"]
    assert n1.state["unacked"] == {}


def test_a_key_distribution_is_flushed_ahead_of_relays_however_deep_the_outbox(tmp_path, hub, principal):
    """A group message queued while a member's key distribution is still
    pending is delivered after the key: the flush sends every control
    envelope before the batch window, so a relay never overtakes the key it
    decrypts under - not when both are queued together, and not when the
    key falls outside the window of newest files."""
    n1, n2, n3 = _nodes(tmp_path, hub, principal)
    g2, g3 = _join_grant(n2, "beta", principal), _join_grant(n3, "gamma", principal)
    n1.PENDING_BATCH = 1  # one key distribution per pass: gamma's key waits a pass
    gid = n1.create_group("alpha", [{"agent_key": agent_key(n2, "beta"), "grant_ids": [g2["grant_id"]]},
                                    {"agent_key": agent_key(n3, "gamma"), "grant_ids": [g3["grant_id"]]}], name="g")
    # sent before ANY pass: both members' keys are still pending, so the
    # relays wait in the outbox until the pending pass has queued each key
    n1.LIVE_WINDOW, n1.DRAIN_SLICE = 2, 1  # a window smaller than the relays queued
    for i in range(4):
        n1.group_send("alpha", gid, {"kind": "text", "text": "m%d" % i})
    assert len([f for f in os.listdir(n1.outbox_dir) if f.startswith("out_")]) == 8
    pump([n1, n2, n3], 12)
    assert n1._group(gid)["pending"] == []
    assert "unknown-group" not in outcomes(n3, "group.recv") and "no-sender-key" not in outcomes(n3, "group.recv")
    for n, agent in ((n2, "beta"), (n3, "gamma")):
        assert sorted(r["body"]["text"] for r in inbox(n, agent) if r["body"].get("kind") == "text") == ["m0", "m1", "m2", "m3"]


def test_skipped_key_store_is_bounded_and_a_wide_persisted_store_loads(tmp_path):
    """Gaps accumulate skipped keys across messages: the store is bounded
    at MAX_SKIP overall (oldest out), so a persisted state always loads;
    a state written before the bound with more entries loads too,
    keeping the newest MAX_SKIP, and still decrypts inside them."""
    # a receiver starting from the sender's initial state
    initial = crypto.SenderKey()
    peer = crypto.SenderKey.from_state(initial.state())
    msgs = [initial.encrypt(b"m%d" % i) for i in range(402)]
    assert peer.decrypt_at(msgs[200][0], msgs[200][1]) == b"m200"
    assert peer.decrypt_at(msgs[401][0], msgs[401][1]) == b"m401"
    assert len(peer.skipped) <= crypto.SenderKey.MAX_SKIP
    assert crypto.SenderKey.from_state(peer.state()).state() == peer.state()
    # a wide store from before the bound: loads, newest kept
    st = peer.state()
    wide = dict(st, skipped={str(i): crypto.b64e(os.urandom(32)) for i in range(400)})
    loaded = crypto.SenderKey.from_state(wide)
    assert len(loaded.skipped) == crypto.SenderKey.MAX_SKIP and min(loaded.skipped) == 200
    # and a message whose key is among the kept ones still decrypts
    assert peer.decrypt_at(msgs[300][0], msgs[300][1]) == b"m300"


def test_a_group_file_that_does_not_load_is_this_groups_trouble_not_the_daemons(tmp_path, hub, principal):
    """The pending refresh reads a changed group file under the group lock
    and contains a load failure to that group: the pass and the daemon go
    on, the event is ledgered once. Group writes are atomic (temp file +
    rename), so a reader never sees a truncated file."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send", "group.join"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send", "group.join"]})
    gid = n1.create_group("alpha", [{"agent_key": agent_key(n2, "beta")}], name="g")
    pump([n1, n2], 3)
    assert n1._group(gid)["pending"] == []
    path = os.path.join(n1.home, "groups", gid + ".json")
    on_disk = json.load(open(path))
    on_disk["pending"] = [{"agent": "alpha", "agent_key": agent_key(n2, "beta"), "grant_ids": []}]
    on_disk["send_state"] = {"ck": "not a key", "n": 0}  # changed by another process, and not a sender key
    json.dump(on_disk, open(path, "w"))
    n1.step()
    n1.step()
    assert outcomes(n1, "group.key").count("error") == 1 and "cannot be loaded" in mirror(n1)
    assert not [f for f in os.listdir(os.path.join(n1.home, "groups")) if f.startswith("." + gid)]  # no temp files left


def test_a_first_join_persists_its_fan_out_and_spends_no_lookup_in_the_handler(tmp_path, hub, principal):
    """A first join puts every other member on the pending list and returns;
    the daemon's pending pass distributes the joiner's key in bounded
    batches off one directory read - the handler itself resolves nobody."""
    n1, n2, n3 = _nodes(tmp_path, hub, principal)
    g2 = _join_grant(n2, "beta", principal)
    gid = envelope.new_id("grp")
    strangers = ["ed25519:" + crypto.b64e(crypto.sign_pub(crypto.gen_signing_key())) for _ in range(5)]
    members = [{"agent_key": agent_key(n1, "alpha")}, {"agent_key": agent_key(n2, "beta")},
               {"agent_key": agent_key(n3, "gamma")}] + [{"agent_key": k} for k in strangers]
    n1.queue_send("alpha", agent_key(n2, "beta"), _key_body(n1, n2, gid, members), grant_ids=[g2["grant_id"]])
    pump([n1], 2)
    calls = {"card": 0}
    real_card = n2._peer_card

    def counting_card(key, fresh=False, directory=None):
        calls["card"] += 1
        return real_card(key, fresh, directory=directory)
    n2._peer_card = counting_card
    n2.PENDING_BATCH = 0  # no pending work this pass: what the handler itself looks up is what counts
    n2.step()
    assert outcomes(n2, "group.join") == ["ok"]
    assert calls["card"] == 1  # the sender's card, on receive; no member lookups in the join handler
    assert [p["agent_key"] for p in n2._group(gid)["pending"]] == [agent_key(n1, "alpha"), agent_key(n3, "gamma")] + strangers
    n2.PENDING_BATCH = nodemod.Node.PENDING_BATCH
    pump([n1, n2, n3], 6)
    assert n2.fp in n1._group(gid)["_recv"] if n1._group(gid) else True
    assert [p["agent_key"] for p in n2._group(gid)["pending"]] == strangers  # the registered members got the key


def test_a_pending_pass_resolves_every_member_from_its_one_directory_read(tmp_path, hub, principal):
    """Pending members are resolved from the snapshot the pass read, so a
    pass that outlives the directory cache still makes one hub request,
    however many members it distributes to."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send", "group.join"]})
    others = [make_node(tmp_path, "m%d" % i, hub.url, principal, {"a%d" % i: ["msg.send", "group.join"]}) for i in range(3)]
    gid = n1.create_group("alpha", [{"agent_key": agent_key(o, "a%d" % i)} for i, o in enumerate(others)], name="g")
    calls = {"dir": 0}
    real_dir = n1._directory

    def counting_dir(fresh=False):
        calls["dir"] += 1 if fresh else 0
        d = real_dir(fresh=fresh)
        n1._dir_cache = (0.0, None)  # the cache is always expired: only the snapshot can serve the pass
        return d
    n1._directory = counting_dir
    n1.step()
    assert calls["dir"] == 1 and n1._group(gid)["pending"] == []


def test_a_malformed_pending_list_is_that_groups_trouble_not_the_daemons(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send", "group.join"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send", "group.join"]})
    gid = n1.create_group("alpha", [{"agent_key": agent_key(n2, "beta")}], name="g")
    pump([n1, n2], 3)
    path = os.path.join(n1.home, "groups", gid + ".json")
    for bad in (1, [{"agent": [], "agent_key": agent_key(n2, "beta")}], [{"agent": "alpha"}]):
        on_disk = json.load(open(path))
        on_disk["pending"] = bad
        json.dump(on_disk, open(path, "w"))
        n1._bad_groups.discard(gid)
        n1.step()
        n1.step()
    assert outcomes(n1, "group.key").count("error") == 3 and "pending list" in mirror(n1)


def test_a_flush_pass_is_bounded_in_attempts_not_only_outcomes(tmp_path, hub, principal):
    """Control envelopes to a recipient the directory does not know are
    transient failures (no outcome); a pass still tries at most FLUSH_BATCH
    files, so an outage never costs one timeout per queued file before the
    poll runs."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send", "group.join"]})
    unknown = "ed25519:" + crypto.b64e(crypto.sign_pub(crypto.gen_signing_key()))
    for i in range(6):
        n1.queue_send("alpha", unknown, {"kind": "text", "text": "c%d" % i}, control=True)
    n1.FLUSH_BATCH = 2
    calls = {"card": 0}
    real = n1._peer_card

    def counting(key, fresh=False, directory=None):
        calls["card"] += 1
        return real(key, fresh, directory=directory)
    n1._peer_card = counting
    n1._flush_outbox()
    assert calls["card"] <= 2
    assert len([f for f in os.listdir(n1.outbox_dir) if f.endswith(".json")]) == 6  # nothing lost, all still queued


def test_params_that_cannot_be_canonicalized_join_nothing_and_spend_nothing(tmp_path, hub, principal):
    """A parameter that passes an unconstrained key's matching but cannot be
    hashed into the ledger (a NaN) is refused as a malformed action before
    any group state exists, so a join never escapes accounting. Exercised
    at the executor: a strict wire reader may refuse such a body earlier
    still."""
    n1, n2, n3 = _nodes(tmp_path, hub, principal)
    scope = [{"action": "group.join", "resource": "host:%s:groups" % n2.node_key, "params": {"keys": ["group_id", "x"]}}]
    g2 = issue_grant(n2, "beta", principal, max_uses=1, scope=scope)
    for bad in (float("nan"), float("inf")):
        gid = envelope.new_id("grp")
        body = _key_body(n1, n2, gid, [{"agent_key": agent_key(n1, "alpha")}])
        body["params"] = {"group_id": gid, "x": bad}
        env = {"msg_id": envelope.new_id("msg"), "grant_ids": [g2["grant_id"]], "from": agent_key(n1, "alpha")}
        assert n2._apply_grants(env, "beta", body) == "information-only"
    assert _groups(n2) == [] and outcomes(n2, "group.join") == [] and uses(n2, g2["grant_id"]) == 0
    assert [e["outcome"] for e in ledger_entries(n2) if e["action"] == "grant.check"] == ["malformed-action"] * 2

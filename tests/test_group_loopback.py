"""Group loopback: local members of a group receive the plaintext body
directly - never a sender-key-wrapped copy that the node's own receive
ratchet will reject as replayed/old once the send side has advanced
(plane-test-1 soak dead-lettered its whole loopback fanout)."""
from natively import crypto  # noqa: F401  (import parity with other tests)

from conftest import agent_key, inbox, issue_grant, make_node, outcomes, pump


def _join_grant(node, agent, principal):
    # a member joins a group only under a group.join grant on its own node
    # (review point 3, part 3): the remote members carry one
    return issue_grant(node, agent, principal, max_uses=5, scope=[{
        "action": "group.join", "resource": "host:%s:groups" % node.node_key, "params": {"keys": ["group_id"]}}])


def test_group_send_delivers_plaintext_to_local_members(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal,
                   {"alpha": ["msg.send"], "beta": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"gamma": ["msg.send", "group.join"]})
    jg = _join_grant(n2, "gamma", principal)
    members = [{"agent_key": agent_key(n1, "alpha")},
               {"agent_key": agent_key(n1, "beta")},
               {"agent_key": agent_key(n2, "gamma"), "grant_ids": [jg["grant_id"]]}]
    gid = n1.create_group("alpha", members, name="t")
    pump([n1, n2], 4)  # distribute keys
    for i in range(3):
        n1.group_send("alpha", gid, {"kind": "group_text", "text": "m%d" % i})
    pump([n1, n2], 6)
    # local member sees the plaintext body, attributed to the group
    # (the flush drains newest-first, so inbox order is not send order)
    recs = [r for r in inbox(n1, "beta") if r["body"].get("kind") == "group_text"]
    assert sorted(r["body"]["text"] for r in recs) == ["m0", "m1", "m2"]
    assert all(r["body"].get("group_id") == gid for r in recs)
    # remote member decrypts through the sender key as before
    remote = [r for r in inbox(n2, "gamma") if r["body"].get("kind") == "group_text"]
    assert sorted(r["body"]["text"] for r in remote) == ["m0", "m1", "m2"]
    # no loopback send may fail as replayed/old
    assert "error" not in outcomes(n1, "msg.send")


def test_group_send_to_unregistered_local_member_still_queues(tmp_path, hub, principal):
    # IdentityUnknown at group_send time (card not in the directory yet)
    # must keep queueing the remote wrap - the member may register later.
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"gamma": ["msg.send", "group.join"]}, start=False)
    jg = _join_grant(n2, "gamma", principal)
    gid = n1.create_group("alpha", [{"agent_key": agent_key(n2, "gamma"), "grant_ids": [jg["grant_id"]]}], name="t")
    n1.group_send("alpha", gid, {"kind": "group_text", "text": "hi"})
    pump([n1], 2)
    n2.start()  # registers now; the queued wrap resolves next pass
    pump([n1, n2], 6)
    assert [r["body"]["text"] for r in inbox(n2, "gamma")
            if r["body"].get("kind") == "group_text"] == ["hi"]


def test_group_key_superset_members_list_is_adopted(tmp_path, hub, principal):
    # member-add via redistribution: a group_key carrying a strict superset
    # of the local member list updates it; a shrink is ignored.
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send", "group.join"]})
    n3 = make_node(tmp_path, "n3", hub.url, principal, {"gamma": ["msg.send", "group.join"]})
    jg = _join_grant(n2, "beta", principal)
    two = [{"agent_key": agent_key(n1, "alpha")}, {"agent_key": agent_key(n2, "beta"), "grant_ids": [jg["grant_id"]]}]
    gid = n1.create_group("alpha", two, name="t")
    pump([n1, n2], 4)
    assert len(n2._group(gid)["members"]) == 2

    def redistribution(members):
        # a group_key is a group.join action under the member's grant (review point 3, part 3)
        g1 = n1._group(gid)
        return {"kind": "group_key", "action": "group.join", "resource": "host:%s:groups" % n2.node_key,
                "params": {"group_id": gid}, "group_id": gid, "group_name": "t",
                "sender_fp": n1.fp, "state": g1["_send"].state(), "members": members}
    # n1 adds n3 locally and redistributes the three-member list
    three = two + [{"agent_key": agent_key(n3, "gamma")}]
    g1 = n1._group(gid)
    g1["members"] = three
    n1._save_group(gid)
    n1.queue_send("alpha", agent_key(n2, "beta"), redistribution(three), grant_ids=[jg["grant_id"]])
    pump([n1, n2], 4)
    assert {m["agent_key"] for m in n2._group(gid)["members"]} == {m["agent_key"] for m in three}
    assert "updated" in outcomes(n2, "group.members")
    # a stale two-member redistribution must NOT shrink the list back
    n1.queue_send("alpha", agent_key(n2, "beta"), redistribution(two), grant_ids=[jg["grant_id"]])
    pump([n1, n2], 4)
    assert len(n2._group(gid)["members"]) == 3

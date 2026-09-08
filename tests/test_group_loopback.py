"""Group loopback: local members of a group receive the plaintext body
directly - never a sender-key-wrapped copy that the node's own receive
ratchet will reject as replayed/old once the send side has advanced
(plane-test-1 soak dead-lettered its whole loopback fanout)."""
from natively import crypto  # noqa: F401  (import parity with other tests)

from conftest import agent_key, inbox, make_node, outcomes, pump


def test_group_send_delivers_plaintext_to_local_members(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal,
                   {"alpha": ["msg.send"], "beta": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"gamma": ["msg.send"]})
    members = [{"agent_key": agent_key(n1, "alpha")},
               {"agent_key": agent_key(n1, "beta")},
               {"agent_key": agent_key(n2, "gamma")}]
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
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"gamma": ["msg.send"]}, start=False)
    gid = n1.create_group("alpha", [{"agent_key": agent_key(n2, "gamma")}], name="t")
    n1.group_send("alpha", gid, {"kind": "group_text", "text": "hi"})
    pump([n1], 2)
    n2.start()  # registers now; the queued wrap resolves next pass
    pump([n1, n2], 6)
    assert [r["body"]["text"] for r in inbox(n2, "gamma")
            if r["body"].get("kind") == "group_text"] == ["hi"]

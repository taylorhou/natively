"""Hub queue bounds are backpressure, not eviction (review 2026-09-07,
point 7): a queue at its quota refuses the next POST with 429 and nothing
accepted is discarded - the control envelope queued first survives any
chatter flood (plane-test-1 soak: group_key distributions evicted by relay
firehoses from capped queues); dedupe skips are honestly accounted."""
import json

from natively import envelope

from conftest import http, make_node


def _fake_env(agent_key, cls=None):
    e = {"msg_id": envelope.new_id("msg"), "type": "msg", "to": agent_key, "body": "x"}
    if cls:
        e["class"] = cls
    return e


def test_control_survives_data_flood_and_the_flood_is_refused_not_evicted(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    to = n2.agents["beta"]["card"]["agent_key"]
    ctl = _fake_env(to, "control")
    assert http("POST", hub.url + "/v1/msg", ctl)[0] == 200
    statuses = [http("POST", hub.url + "/v1/msg", _fake_env(to))[0] for _ in range(510)]
    cap = hub.state.QUEUE_MAX_MSGS
    assert statuses[:cap - 1] == [200] * (cap - 1) and statuses[cap - 1:] == [429] * (510 - cap + 1)
    # poll n2's queue raw: everything accepted is there, the control envelope first of all
    tok = n2._auth_token("poll", after=0)
    st, d = http("GET", hub.url + "/v1/poll/%s?after=0" % n2.fp, headers={"X-Natively-Auth": tok})
    assert st == 200
    ids = [it.get("env", it).get("msg_id") for it in d["messages"]]
    assert ctl["msg_id"] in ids and len(d["messages"]) == cap


def test_dedupe_is_honestly_accounted(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    to = n2.agents["beta"]["card"]["agent_key"]
    e = _fake_env(to)
    st, r1 = http("POST", hub.url + "/v1/msg", e)
    assert st == 200 and r1 == {"queued": 1, "deduped": 0}
    st, r2 = http("POST", hub.url + "/v1/msg", e)
    assert st == 200 and r2 == {"queued": 0, "deduped": 1}


def test_queue_send_marks_control_in_envelope(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    from conftest import agent_key
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "group_key", "x": 1}, control=True)
    import os, json as j
    fn = os.path.join(n1.home, "outbox", os.listdir(os.path.join(n1.home, "outbox"))[0])
    req = j.load(open(fn))
    assert req.get("control") is True

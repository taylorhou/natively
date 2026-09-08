"""Hub queue eviction is kind-aware, and dedupe skips are honestly
accounted (plane-test-1 soak: group_key distributions evicted by chatter
floods from capped queues; re-POSTs of known msg_ids returning
{"queued": 1} made 'hub accepted' evidence worthless)."""
import json

from natively import envelope
from natively.hub import _evict_to_cap

from conftest import http, make_node


def _fake_env(agent_key, cls=None):
    e = {"msg_id": envelope.new_id("msg"), "type": "msg", "to": agent_key, "body": "x"}
    if cls:
        e["class"] = cls
    return e


def test_evict_helper_prefers_data():
    q = [{"_class": "data", "i": i} for i in range(4)] + [{"_class": "control", "i": "c%d" % i} for i in range(3)]
    kept, dropped = _evict_to_cap(q, 5)
    assert len(kept) == 5 and len(dropped) == 2
    assert all(m["_class"] == "control" for m in kept[2:])  # all control survives
    assert [m["i"] for m in dropped] == [0, 1]  # oldest data first


def test_evict_helper_all_control_overflow():
    q = [{"_class": "control", "i": i} for i in range(7)]
    kept, dropped = _evict_to_cap(q, 5)
    assert [m["i"] for m in kept] == [2, 3, 4, 5, 6]  # bounded: oldest control goes


def test_control_survives_data_flood(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    to = n2.agents["beta"]["card"]["agent_key"]
    ctl = _fake_env(to, "control")
    assert http("POST", hub.url + "/v1/msg", ctl)[0] == 200
    for _ in range(510):
        assert http("POST", hub.url + "/v1/msg", _fake_env(to))[0] == 200
    # poll n2's queue raw: the control envelope must still be there
    tok = n2._auth_token("poll", after=0)
    st, d = http("GET", hub.url + "/v1/poll/%s?after=0" % n2.fp, headers={"X-Natively-Auth": tok})
    assert st == 200
    ids = [it.get("env", it).get("msg_id") for it in d["messages"]]
    assert ctl["msg_id"] in ids
    assert len(d["messages"]) == 500


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

"""An uncertain POST never becomes a second logical message (review
2026-09-07, point 9): the signed envelope is stored in the outbox request
before its first POST, and every retry sends the same bytes, which the
hub dedupes by msg_id."""
import json
import os
import urllib.error

from natively import node as nodemod

from conftest import agent_key, inbox, make_node, outcomes, pump


def test_a_post_whose_answer_was_lost_is_retried_as_the_same_envelope(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    real = n1._hub_req
    lost = {"on": True}

    def accepted_but_answer_lost(method, path, body=None, headers=None):
        r = real(method, path, body=body, headers=headers)
        if lost["on"] and path == "/v1/msg":
            lost["on"] = False
            raise urllib.error.URLError("connection reset after the hub took it")
        return r
    n1._hub_req = accepted_but_answer_lost
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "once"})
    n1.step()  # the POST landed, the answer did not: the file stays, with the envelope it carried
    (f,) = [x for x in os.listdir(n1.outbox_dir) if x.endswith(".json")]
    req = json.load(open(os.path.join(n1.outbox_dir, f)))
    mid = req["env"]["msg_id"]
    assert "retry" in outcomes(n1, "msg.send") and n1.state["unacked"] == {}
    n1.step()  # the retry: the same bytes, deduped by the hub
    assert list(n1.state["unacked"]) == [mid]
    assert [m["env"]["msg_id"] for m in hub.state.queues[n2.fp]] == [mid]  # one envelope, not two
    assert not [x for x in os.listdir(n1.outbox_dir) if x.endswith(".json")]
    pump([n2, n1], 4)
    assert [r["body"]["text"] for r in inbox(n2, "beta")] == ["once"]
    assert n1.state["unacked"] == {}


def test_a_moved_recipient_gets_a_fresh_ciphertext(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "where are you"})
    real = n1._hub_req

    def moved(method, path, body=None, headers=None):
        if path == "/v1/msg":
            raise urllib.error.HTTPError(hub.url + path, 409, "recipient moved", {}, None)
        return real(method, path, body=body, headers=headers)
    n1._hub_req = moved
    n1.step()
    (f,) = [x for x in os.listdir(n1.outbox_dir) if x.endswith(".json")]
    assert "env" not in json.load(open(os.path.join(n1.outbox_dir, f)))  # the stored envelope is dropped: a new one next pass
    n1._hub_req = real
    pump([n1, n2], 4)
    assert [r["body"]["text"] for r in inbox(n2, "beta")] == ["where are you"]

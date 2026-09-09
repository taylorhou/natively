"""The flush's send phase posts on parallel lanes (FLUSH_WORKERS), sharded
by bare recipient: per-recipient order - key before relay, enqueue order -
is exactly what the sequential pass gave, while sends to different
recipients overlap (the lane is the latency-bound ~1-RTT-per-POST part).
"""
import time
import urllib.error

from conftest import agent_key, inbox, make_node, pump


def test_per_recipient_order_survives_parallel_lanes(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n3 = make_node(tmp_path, "n3", hub.url, principal, {"gamma": ["msg.send"]})
    n1.FLUSH_WORKERS = 4
    beta, gamma = agent_key(n2, "beta"), agent_key(n3, "gamma")
    want = {beta: [], gamma: []}
    for i in range(8):  # interleaved production: b0 g0 b1 g1 ...
        for to in (beta, gamma):
            text = "%s-%d" % (to[-6:], i)
            n1.queue_send("alpha", to, {"kind": "text", "text": text})
            want[to].insert(0, text)  # the live window is newest-first by design (live latency wins the budget)
            time.sleep(0.002)  # outbox filenames sort by ms timestamp: space enqueues so sort order is enqueue order
    n1.step()  # one flush pass, 4 lanes, 2 shards
    pump([n2, n3, n1], 4)  # deliver + ack
    assert [r["body"]["text"] for r in inbox(n2, "beta")] == want[beta]
    assert [r["body"]["text"] for r in inbox(n3, "gamma")] == want[gamma]
    assert n1.state["unacked"] == {}  # everything acked, nothing stranded


def test_a_ctl_429_defers_the_rest_of_its_shard(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    posts = []

    def full(method, path, body=None, headers=None):
        posts.append(path)
        raise urllib.error.HTTPError(hub.url + path, 429, "recipient queue full", {}, None)
    n1._hub_req = full
    item = lambda f: (f, "/unused/" + f, {"to": "ed25519:rcpt"}, {"msg_id": "msg_" + f}, "fp", None)
    shard = [item("ctl_key.json"), item("out_r1.json"), item("out_r2.json")]
    res = n1._flush_post_shard(shard)
    assert [d for _, _, d in res] == [False, True, True]  # relays deferred behind their refused key
    assert len(posts) == 1  # the key was attempted once; the relays never left


def test_a_relay_429_does_not_defer_its_shard(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    posts = []

    def full(method, path, body=None, headers=None):
        posts.append(path)
        raise urllib.error.HTTPError(hub.url + path, 429, "recipient queue full", {}, None)
    n1._hub_req = full
    item = lambda f: (f, "/unused/" + f, {"to": "ed25519:rcpt"}, {"msg_id": "msg_" + f}, "fp", None)
    res = n1._flush_post_shard([item("out_r1.json"), item("out_r2.json")])
    assert [d for _, _, d in res] == [False, False]  # per-file backoff only, exactly as the sequential pass
    assert len(posts) == 2


def test_a_429_suppresses_the_whole_recipient_not_just_the_file(tmp_path, hub, principal):
    """The refusal is a property of the recipient's hub queue: one 429 waits
    every queued file to that recipient, so a capped (dead) recipient costs
    one probe per backoff instead of one POST per file per pass."""
    hub.state.QUEUE_MAX_MSGS = 1
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n3 = make_node(tmp_path, "n3", hub.url, principal, {"gamma": ["msg.send"]})
    beta, gamma = agent_key(n2, "beta"), agent_key(n3, "gamma")
    posts = []
    real = n1._hub_req
    def counting(method, path, body=None, headers=None):
        if path == "/v1/msg":
            posts.append(body)
        return real(method, path, body=body, headers=headers)
    n1._hub_req = counting
    n1.queue_send("alpha", beta, {"kind": "text", "text": "fills the queue"})
    n1.step()  # lands: beta's hub queue now holds 1 of 1
    assert len(hub.state.queues[n2.fp]) == 1
    n1.queue_send("alpha", beta, {"kind": "text", "text": "one"})
    n1.queue_send("alpha", beta, {"kind": "text", "text": "two"})
    n1.queue_send("alpha", gamma, {"kind": "text", "text": "elsewhere"})
    n1.step()  # both beta files attempt and 429 (per-file semantics in-pass); gamma lands
    assert len(hub.state.queues[n3.fp]) == 1
    rk = beta.split(":", 1)[1]
    assert n1._rcpt_backoff.get(rk, (0.0,))[0] > 0  # the refusal is remembered per recipient
    posts.clear()
    n1.step()  # suppressed: no beta attempts at all this pass
    assert posts == []
    assert len([f for f in __import__("os").listdir(n1.outbox_dir) if f.endswith(".json")]) == 2
    n1._rcpt_backoff.clear()  # simulate the wait expiring
    n1._backoff.clear()  # (the per-file waits from the same refusals)
    hub.state.QUEUE_MAX_MSGS = 10  # room for both waiting files
    pump([n2], 2)  # beta drains its queue
    n1.step()
    assert len(hub.state.queues[n2.fp]) == 2  # both waiting files landed once room returned
    assert n1._rcpt_backoff.get(rk) is None  # a landed send clears the recipient's verdict

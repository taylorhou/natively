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

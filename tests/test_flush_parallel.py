"""Backport branch (4c43849-based): the flush's send phase posts on
parallel lanes (FLUSH_WORKERS), sharded by bare recipient, plus 429
backpressure handling this build never had (its hub-era treated every
4xx as a permanent dead-letter; the production hub now answers full
queues with 429). This commit's in-test hub predates 429s, so refusal
paths are stubbed at _hub_req.
"""
import json
import os
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
    for i in range(8):
        for to in (beta, gamma):
            text = "%s-%d" % (to[-6:], i)
            n1.queue_send("alpha", to, {"kind": "text", "text": text})
            want[to].insert(0, text)  # the live window is newest-first by design
            time.sleep(0.002)  # filenames sort by ms: space enqueues so sort order is enqueue order
    n1.step()
    pump([n2, n3, n1], 4)
    assert [r["body"]["text"] for r in inbox(n2, "beta")] == want[beta]
    assert [r["body"]["text"] for r in inbox(n3, "gamma")] == want[gamma]
    assert n1.state["unacked"] == {}


def _item(f):
    return (f, "/unused/" + f, {"to": "ed25519:rcpt"}, {"msg_id": "msg_" + f}, "fp")


def test_a_ctl_429_defers_the_rest_of_its_shard(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    posts = []

    def full(method, path, body=None, headers=None):
        posts.append(path)
        raise urllib.error.HTTPError(hub.url + path, 429, "recipient queue full", {}, None)
    n1._hub_req = full
    res = n1._flush_post_shard([_item("ctl_a.json"), _item("out_b.json"), _item("out_c.json")])
    assert [d for _, _, d in res] == [False, True, True]
    assert len(posts) == 1  # the key was attempted once; the relays never left


def test_a_relay_429_does_not_defer_its_shard(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    posts = []

    def full(method, path, body=None, headers=None):
        posts.append(path)
        raise urllib.error.HTTPError(hub.url + path, 429, "recipient queue full", {}, None)
    n1._hub_req = full
    res = n1._flush_post_shard([_item("out_a.json"), _item("out_b.json")])
    assert [d for _, _, d in res] == [False, False]
    assert len(posts) == 2


def test_a_429_waits_the_whole_recipient_and_a_landed_send_clears_it(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["msg.send"]})
    n3 = make_node(tmp_path, "n3", hub.url, principal, {"gamma": ["msg.send"]})
    beta, gamma = agent_key(n2, "beta"), agent_key(n3, "gamma")
    real = n1._hub_req
    posts = []

    def refusing(method, path, body=None, headers=None):
        if path == "/v1/msg":
            posts.append(body)
            env = json.loads(body)
            if env.get("to_node") == n2.fp:
                raise urllib.error.HTTPError(hub.url + path, 429, "recipient queue full", {}, None)
        return real(method, path, body=body, headers=headers)
    n1._hub_req = refusing
    n1.queue_send("alpha", beta, {"kind": "text", "text": "one"})
    n1.queue_send("alpha", beta, {"kind": "text", "text": "two"})
    n1.queue_send("alpha", gamma, {"kind": "text", "text": "elsewhere"})
    n1.step()  # both beta files attempt and are refused (per-file semantics in-pass); gamma lands
    assert len(hub.state.queues.get(n3.fp, [])) == 1
    rk = beta.split(":", 1)[1]
    assert n1._rcpt_backoff.get(rk, (0.0,))[0] > 0
    posts.clear()
    n1.step()  # suppressed: no beta attempts at all this pass
    assert posts == []
    assert len([f for f in os.listdir(n1.outbox_dir) if f.endswith(".json")]) == 2
    n1._hub_req = real
    n1._rcpt_backoff.clear()  # the wait expires
    n1._backoff.clear()  # (the per-file waits from the same refusals)
    n1.step()
    assert len(hub.state.queues.get(n2.fp, [])) == 2  # both waiting files landed once room returned
    assert n1._rcpt_backoff.get(rk) is None  # a landed send clears the verdict


def test_a_pruned_recipient_costs_one_directory_recheck_per_pass_not_one_per_file(tmp_path, hub, principal, monkeypatch):
    """_peer_card re-checks a cached-directory miss against the hub with a
    fresh fetch; a backlog of files to a pruned recipient must share ONE
    such re-check per pass, not pay a round trip per file."""
    from natively import node as nodemod, crypto
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    ghost = "ed25519:" + crypto.b64e(crypto.sign_pub(crypto.gen_signing_key()))
    for i in range(5):
        n1.queue_send("alpha", ghost, {"kind": "text", "text": "g%d" % i})
    calls = {"dir": 0}
    real = nodemod._http

    def counting(method, url, **kw):
        if url.endswith("/v1/directory"):
            calls["dir"] += 1
        return real(method, url, **kw)
    monkeypatch.setattr(nodemod, "_http", counting)
    n1._flush_outbox()
    assert calls["dir"] <= 2  # cached miss + the fresh re-check of the first file; the rest share the verdict
    assert len([f for f in os.listdir(n1.outbox_dir) if f.endswith(".json")]) == 5  # all deferred, none lost

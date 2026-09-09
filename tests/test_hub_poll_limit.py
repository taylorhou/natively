"""The poll endpoint honors limit=: a node with receive-side batching gets
a page, not the whole waiting queue. Older nodes (no limit param) stay
uncapped."""
import json
import urllib.request

from conftest import agent_key, make_node, start_hub, Principal


def _poll(hub_url, fp, token, q):
    req = urllib.request.Request("%s/v1/poll/%s?%s" % (hub_url, fp, q),
                                 headers={"X-Natively-Auth": token})
    return json.loads(urllib.request.urlopen(req, timeout=10).read())


def test_poll_limit_pages_and_default_stays_uncapped(tmp_path):
    p = Principal()
    h = start_hub(tmp_path)
    try:
        n1 = make_node(tmp_path, "n1", h.url, p, {"alpha": ["msg.send"]})
        n2 = make_node(tmp_path, "n2", h.url, p, {"beta": ["msg.send"]})
        for i in range(5):
            n1.queue_send("alpha", agent_key(n2, "beta"), {"kind": "text", "text": "m%d" % i})
        n1.step()  # flush: 5 envelopes land in n2's hub queue
        d = _poll(h.url, n2.fp, n2._auth_token("poll", after=0), "after=0&limit=2")
        assert len(d["messages"]) == 2
        d = _poll(h.url, n2.fp, n2._auth_token("poll", after=0), "after=0")
        assert len(d["messages"]) == 5
    finally:
        h.close()

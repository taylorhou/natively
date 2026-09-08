"""Test harness: an in-process hub on a random port, nodes driven one
`step()` at a time, keys generated per test. Nothing touches the user's
home or a fixed port; nothing is left running after a test."""
import os
import sys
import json
import threading
import urllib.error
import urllib.request

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from natively import crypto, hub as hubmod, node as nodemod, envelope  # noqa: E402


class Hub:
    def __init__(self, state, server, thread):
        self.state = state
        self.server = server
        self.thread = thread
        self.url = "http://127.0.0.1:%d" % server.server_address[1]

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def start_hub(tmp_path, principal_roots=None, state_path=None):
    path = state_path or str(tmp_path / "hub" / "hub.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    st = hubmod.State(path, principal_roots=principal_roots)
    st.POLL_WAIT = 0.05
    srv = hubmod.make_server(0, st)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    return Hub(st, srv, t)


@pytest.fixture
def hub(tmp_path):
    h = start_hub(tmp_path)
    yield h
    h.close()


class Principal:
    def __init__(self):
        self.seed = crypto.gen_signing_key()
        self.pub = crypto.b64e(crypto.sign_pub(self.seed))


@pytest.fixture
def principal():
    return Principal()


def make_node(tmp_path, name, hub_url, principal, agents=(), roots=None, start=True):
    """A node home with the given agents (name -> caps), started (locked,
    prekeys published, registered) unless start=False."""
    home = str(tmp_path / name)
    nodemod.init_node(home, name, hub_url, principal.pub)
    if roots:
        with open(os.path.join(home, "principal.pub"), "w") as f:
            f.write("\n".join(roots) + "\n")
    for agent, caps in dict(agents).items():
        nodemod.add_agent(home, agent, principal.seed, list(caps))
    n = nodemod.Node(home)
    if start:
        n.start()
    return n


def agent_key(node, agent):
    return node.agents[agent]["card"]["agent_key"]


def pump(nodes, rounds=4):
    for _ in range(rounds):
        for n in nodes:
            n.step()


def inbox(node, agent):
    d = os.path.join(node.home, "inbox", agent)
    if not os.path.isdir(d):
        return []
    return [json.load(open(os.path.join(d, f))) for f in sorted(os.listdir(d))]


def ledger_entries(node):
    return list(node.ledger.entries())


def outcomes(node, action, classified=False):
    # outcome strings may carry a class suffix ("error:CryptoError"); tests
    # match the base outcome by default, pass classified=True for the raw
    # classed strings.
    def base(o):
        # only the error family carries a class suffix; other outcomes like
        # "acted:test.ping" keep their colon form.
        return o.split(":", 1)[0] if o.startswith("error:") else o
    return [(e["outcome"] if classified else base(e["outcome"]))
            for e in ledger_entries(node) if e["action"] == action]


def http(method, url, body=None, headers=None, raw=False):
    """(status, decoded body); 4xx/5xx come back as values, not exceptions."""
    data = body
    if body is not None and not isinstance(body, (bytes, bytearray)):
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/octet-stream" if raw else "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            b = r.read()
            return r.status, (b if raw else json.loads(b))
    except urllib.error.HTTPError as e:
        b = e.read()
        try:
            return e.code, json.loads(b)
        except Exception:
            return e.code, b


def signed(obj, seed):
    return envelope.sign_obj(obj, seed)


def resource(node, name="ping"):
    """A resource bound to `node`: host:<node-key>:<name>."""
    return "host:%s:%s" % (node.node_key, name)


def issue_grant(node, agent, principal, scope=None, max_uses=1, executor=None, **kw):
    """A principal-signed grant for `agent` on `node`, written under the
    node's grants/ as the CLI would. Default scope: test.ping on this node."""
    card = node.agents[agent]["card"]
    scope = scope or [{"action": "test.ping", "resource": resource(node), "params": {}}]
    g = envelope.make_grant(principal.seed, "p", card, executor or node.node_key, scope, "ping",
                            max_uses=max_uses, **kw)
    gdir = os.path.join(node.home, "grants")
    os.makedirs(gdir, exist_ok=True)
    json.dump(g, open(os.path.join(gdir, g["grant_id"] + ".json"), "w"))
    return g


def send_action(n_from, agent_from, n_to, agent_to, grant_ids, action="test.ping", res=None, params=None):
    n_from.queue_send(agent_from, agent_key(n_to, agent_to),
                      {"kind": "action", "action": action, "resource": res if res is not None else resource(n_to),
                       "params": {} if params is None else params, "text": action},
                      grant_ids=list(grant_ids))


def uses(node, gid):
    return node._grant_uses(gid)

"""Natively hub: store-and-forward transport (spec 7 adapter).

The hub is untrusted infrastructure: it routes and stores signed envelopes
and encrypted blobs, never plaintext. stdlib-only HTTP server so it runs
anywhere.

API (all JSON unless noted):
  PUT  /v1/prekey/<node_fp>   body: node-signed prekey bundle
  GET  /v1/prekey/<node_fp>
  POST /v1/register           {node_fp, agents: [{name, agent_key, card}], sig}
  GET  /v1/directory          -> {agents: {...}, nodes: {...}}
  POST /v1/msg                {envelope} -> {seq}
  GET  /v1/poll/<node_fp>?after=<seq>  (long-poll, timeout=25s)
  POST /v1/blob               raw ciphertext body -> {blob_id, size}
  GET  /v1/blob/<blob_id>     raw ciphertext
  GET  /v1/healthz
"""
import json
import threading
import time
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 64 * 1024 * 1024  # 64MB blobs/envelopes cap


class State:
    def __init__(self, path=None):
        self.lock = threading.Lock()
        self.path = path
        self.prekeys = {}       # node_fp -> bundle
        self.nodes = {}         # node_fp -> {name, agents}
        self.agent_dir = {}     # "name@nodefp" -> {agent_key, card, node_fp}
        self.agent_owner = {}   # agent_key -> node_fp
        self.queues = {}        # node_fp -> [envelope,...]
        self.seq = {}           # node_fp -> last seq
        self.blobs = {}         # blob_id -> bytes
        self.cond = threading.Condition(self.lock)
        if path and os.path.exists(path):
            self._load()

    def _load(self):
        try:
            d = json.load(open(self.path))
            self.prekeys = d.get("prekeys", {})
            self.nodes = d.get("nodes", {})
            self.agent_dir = d.get("agent_dir", {})
            self.agent_owner = d.get("agent_owner", {})
            self.queues = d.get("queues", {})
            self.seq = d.get("seq", {})
            self.blobs = {k: bytes.fromhex(v) for k, v in d.get("blobs_hex", {}).items()}
        except Exception as e:
            print("hub: state load failed, starting empty:", e)

    def save(self):
        if not self.path:
            return
        d = {"prekeys": self.prekeys, "nodes": self.nodes, "agent_dir": self.agent_dir,
             "agent_owner": self.agent_owner, "queues": self.queues, "seq": self.seq,
             "blobs_hex": {k: v.hex() for k, v in self.blobs.items()}}
        tmp = self.path + ".tmp"
        json.dump(d, open(tmp, "w"))
        os.replace(tmp, self.path)


def make_server(port: int, state: State):
    st = state

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                return None
            return self.rfile.read(n) if n else b""

        def _json(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def _raw(self, code, b, ctype="application/octet-stream"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        # ---- routing helpers ----
        def _route_node(self, env):
            to = env.get("to", "")
            if to.startswith("node:"):
                return to.split(":", 2)[1]
            if to.startswith("ed25519:"):
                return st.agent_owner.get(to.split(":", 1)[1])
            return None

        # ---- handlers ----
        def do_GET(self):
            p = self.path
            if p == "/v1/healthz":
                return self._json(200, {"ok": True, "ts": int(time.time())})
            if p == "/v1/directory":
                with st.lock:
                    return self._json(200, {"agents": st.agent_dir, "nodes": st.nodes})
            if p.startswith("/v1/prekey/"):
                fp = p.rsplit("/", 1)[1]
                with st.lock:
                    b = st.prekeys.get(fp)
                return self._json(200, b) if b else self._json(404, {"error": "no bundle"})
            if p.startswith("/v1/blob/"):
                bid = p.rsplit("/", 1)[1]
                with st.lock:
                    d = st.blobs.get(bid)
                return self._raw(200, d) if d is not None else self._json(404, {"error": "no blob"})
            if p.startswith("/v1/poll/"):
                rest = p[len("/v1/poll/"):]
                fp, _, q = rest.partition("?")
                after = 0
                for kv in q.split("&"):
                    if kv.startswith("after="):
                        after = int(kv[6:])
                deadline = time.time() + 5
                with st.cond:
                    while True:
                        q_list = st.queues.get(fp, [])
                        new = [e for e in q_list if e.get("_seq", 0) > after]
                        if new or time.time() > deadline:
                            out = new
                            last = q_list[-1]["_seq"] if q_list else after
                            break
                        st.cond.wait(timeout=5)
                return self._json(200, {"messages": out, "last_seq": last})
            return self._json(404, {"error": "not found"})

        def do_PUT(self):
            if self.path.startswith("/v1/prekey/"):
                fp = self.path.rsplit("/", 1)[1]
                b = self._body()
                if b is None:
                    return self._json(413, {"error": "too big"})
                try:
                    bundle = json.loads(b)
                except Exception:
                    return self._json(400, {"error": "bad json"})
                # verify bundle is signed by the node key it names
                from . import crypto, jcs
                nk = bundle.get("node_key", "").split(":", 1)[-1]
                sig = bundle.get("sig")
                obj = {k: v for k, v in bundle.items() if k != "sig"}
                if not nk or not sig or not crypto.verify(crypto.b64d(nk), jcs.canonicalize(obj), crypto.b64d(sig)):
                    return self._json(400, {"error": "bad bundle signature"})
                with st.lock:
                    st.prekeys[fp] = bundle
                    st.save()
                return self._json(200, {"ok": True})
            return self._json(404, {"error": "not found"})

        def do_POST(self):
            if self.path == "/v1/register":
                b = self._body()
                try:
                    reg = json.loads(b)
                except Exception:
                    return self._json(400, {"error": "bad json"})
                from . import crypto, jcs
                nk = reg.get("node_key", "").split(":", 1)[-1]
                obj = {k: v for k, v in reg.items() if k != "sig"}
                if not nk or not crypto.verify(crypto.b64d(nk), jcs.canonicalize(obj), crypto.b64d(reg.get("sig", ""))):
                    return self._json(400, {"error": "bad register signature"})
                fp = jcs.sha256(crypto.b64d(nk))[:32]
                with st.lock:
                    st.nodes[fp] = {"name": reg.get("name"), "node_key": reg["node_key"]}
                    for a in reg.get("agents", []):
                        st.agent_dir["%s@%s" % (a["name"], fp)] = {
                            "agent_key": a["agent_key"], "card": a["card"], "node_fp": fp}
                        st.agent_owner[a["agent_key"].split(":", 1)[1]] = fp
                    st.save()
                return self._json(200, {"ok": True, "node_fp": fp})
            if self.path == "/v1/msg":
                b = self._body()
                try:
                    env = json.loads(b)
                except Exception:
                    return self._json(400, {"error": "bad json"})
                if not env.get("msg_id") or not env.get("to"):
                    return self._json(400, {"error": "missing fields"})
                node_fp = self._route_node(env)
                # multi-recipient: "to" may be a list
                targets = []
                if isinstance(env.get("to"), list):
                    for t in env["to"]:
                        fp = st.agent_owner.get(t.split(":", 1)[1]) if t.startswith("ed25519:") else None
                        if fp:
                            targets.append(fp)
                elif node_fp:
                    targets = [node_fp]
                if not targets:
                    return self._json(404, {"error": "unknown recipient"})
                with st.cond:
                    for fp in targets:
                        # dedupe: a node re-POSTs unacked envelopes, so the
                        # same msg_id must never enqueue twice for one node
                        q = st.queues.setdefault(fp, [])
                        if any(m.get("env", {}).get("msg_id") == env.get("msg_id") for m in q):
                            continue
                        st.seq[fp] = st.seq.get(fp, 0) + 1
                        q.append(
                            {"env": env, "_seq": st.seq[fp], "_queued_for": fp})
                        if len(st.queues[fp]) > 5000:
                            st.queues[fp] = st.queues[fp][-5000:]
                    st.save()
                    st.cond.notify_all()
                return self._json(200, {"queued": len(targets)})
            if self.path == "/v1/blob":
                b = self._body()
                if b is None:
                    return self._json(413, {"error": "too big"})
                import hashlib
                bid = hashlib.sha256(b).hexdigest()[:32]
                with st.lock:
                    st.blobs[bid] = b
                    st.save()
                return self._json(200, {"blob_id": bid, "size": len(b)})
            return self._json(404, {"error": "not found"})

    return ThreadingHTTPServer(("0.0.0.0", port), H)


def run(port=8471, state_path=None):
    st = State(state_path)
    srv = make_server(port, st)
    print("natively hub listening on :%d" % port)
    srv.serve_forever()

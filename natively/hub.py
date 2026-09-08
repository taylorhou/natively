"""Natively hub: store-and-forward transport (spec 7 adapter).

The hub is untrusted infrastructure: it routes and stores signed envelopes
and encrypted blobs, never plaintext. stdlib-only HTTP server so it runs
anywhere.

API (all JSON unless noted):
  PUT  /v1/prekey/<node_fp>   body: node-signed prekey bundle
  GET  /v1/prekey/<node_fp>
  POST /v1/register           {node_key, name, ts, agents: [{name, agent_key, card}], sig}
  GET  /v1/directory          -> {agents: {...}, nodes: {...}}
  POST /v1/msg                {envelope} -> {seq}
  GET  /v1/poll/<node_fp>?after=<seq>  (long-poll, timeout=25s)
                              header X-Natively-Auth: node-signed poll token
  POST /v1/blob               raw ciphertext body -> {blob_id, size}; 413 over the cap
  GET  /v1/blob/<blob_id>     raw ciphertext (repeatable: a GET never consumes the blob)
  GET  /v1/healthz

Every JSON body is parsed with jcs.loads (review point 5): an object with
a duplicate key, or a number JSON cannot carry (NaN, Infinity, out of
range), is a 400, never a silently normalized object whose signature a
first-wins reader would judge differently.

Authentication (review 2026-09-07, point 1): a prekey bundle is stored only
under the fingerprint of the node key that signed it; a registration
carries a fresh `ts`, every agent card must be principal-signed and name
this node's key and the registered agent key, and an agent key already
owned by another node moves only with a card that supersedes the stored
one; a poll (which reads AND prunes the node's queue) carries a token
signed by the registered node key. `--principal-pub` restricts
registration to cards issued by those principals.
"""
import fcntl
import json
import shutil
import tempfile
import threading
import time
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import crypto, envelope, jcs

MAX_BODY = 64 * 1024 * 1024  # 64MB blobs/envelopes cap
REGISTER_WINDOW_S = 300      # a registration older/newer than this is replayed or misclocked
POLL_TOKEN_WINDOW_S = 120    # a poll token older/newer than this is refused


def fingerprint(node_key_b64: str) -> str:
    """Fingerprint of a node key: the first 32 hex of SHA-256 over the raw
    32-byte Ed25519 public key (the same derivation the node uses)."""
    return jcs.sha256(crypto.b64d(node_key_b64))[:32]


def _key_b64(prefixed) -> str:
    """'ed25519:<b64>' -> '<b64>'; anything else -> ''."""
    if not isinstance(prefixed, str) or not prefixed.startswith("ed25519:"):
        return ""
    return prefixed.split(":", 1)[1]


def _verify_signed(obj, key_b64) -> bool:
    """Signature check that never raises on malformed input."""
    try:
        if not isinstance(obj, dict) or not isinstance(obj.get("sig"), str) or not key_b64:
            return False
        return envelope.verify_obj(obj, key_b64)
    except Exception:
        return False


def _within(ts, window_s) -> bool:
    try:
        return abs(envelope.parse_iso(ts) - time.time()) <= window_s
    except Exception:
        return False


def _evict_to_cap(q, cap):
    """Kind-aware queue trim. Control envelopes (group_key distributions and
    other protocol control, marked class=control by the sender) are the
    irreplaceable traffic: a chatter flood must never evict them (plane-test-1
    soak: group_key distributions repeatedly evicted from capped queues by
    relay firehoses, silently bricking group membership). Evict oldest DATA
    first; evict control only when nothing else remains. Returns (kept,
    dropped)."""
    if len(q) <= cap:
        return q, []
    drop_n = len(q) - cap
    data_idx = [i for i, m in enumerate(q) if m.get("_class") != "control"]
    drop = set(data_idx[:drop_n])
    if len(drop) < drop_n:  # not enough data: oldest control takes the rest
        rest = [i for i in range(len(q)) if i not in drop]
        drop |= set(rest[:drop_n - len(drop)])
    return [m for i, m in enumerate(q) if i not in drop], [q[i] for i in sorted(drop)]


class State:
    POLL_WAIT = 5.0  # long-poll wait when the queue is empty

    def __init__(self, path=None, principal_roots=None):
        self.lock = threading.Lock()
        self.path = path
        # optional allowlist of principal public keys (b64): when set, only
        # cards issued by these principals register
        self.principal_roots = set(principal_roots or [])
        # blobs live on disk beside the state file; a hub started without a
        # state path (the default) still keeps them for its lifetime - in a
        # private directory of its own under the system temp dir (mode
        # 0700, never shared with another process or user) - instead of
        # dropping every upload silently
        self.blob_dir = (os.path.join(os.path.dirname(os.path.abspath(path)), "blobs") if path
                         else tempfile.mkdtemp(prefix="natively-hub-blobs-"))
        self._private_store = not path  # made by mkdtemp for this hub alone: removed when it closes
        self._blob_dir_ready = False
        self.prekeys = {}       # node_fp -> bundle
        self.nodes = {}         # node_fp -> {name, agents}
        self.agent_dir = {}     # "name@nodefp" -> {agent_key, card, node_fp}
        self.agent_owner = {}   # agent_key -> node_fp
        self.queues = {}        # node_fp -> [envelope,...]
        self.seq = {}           # node_fp -> last seq
        self.qids = {}          # node_fp -> set(msg_id) for O(1) dedupe
        self._last_save = 0.0
        self.conds = {}         # node_fp -> Condition: POST wakes only the target's pollers
        if path and os.path.exists(path):
            self._load()
        self._blob_store()      # the store is ready and within its cap before any request is served

    def _cond(self, fp):
        c = self.conds.get(fp)
        if c is None:
            c = self.conds[fp] = threading.Condition(self.lock)
        return c

    def _load(self):
        try:
            d = json.load(open(self.path))
            self.prekeys = d.get("prekeys", {})
            self.nodes = d.get("nodes", {})
            self.agent_dir = d.get("agent_dir", {})
            self.agent_owner = d.get("agent_owner", {})
            self.queues = d.get("queues", {})
            self.seq = d.get("seq", {})
            # load-time clamp: a bloated state file must not OOM the boot.
            # senders re-POST unacked envelopes, so deep backlog is recoverable.
            for fp, q in self.queues.items():
                self.queues[fp], _ = _evict_to_cap(q, 500)
            for fp, q in self.queues.items():
                self.qids[fp] = {m.get("env", {}).get("msg_id") for m in q}
            self._prune_directory()
        except Exception as e:
            print("hub: state load failed, starting empty:", e)

    def _prune_directory(self):
        """Persisted directory entries must still be registerable today:
        drop cards whose principal is outside this hub's root set (they
        registered before the allowlist existed) and cards past expiry.
        Node/prekey entries orphaned by the prune go too. Queues are left
        alone: senders re-POST unacked envelopes."""
        now = envelope.now_iso()
        dead = {}
        for name, e in self.agent_dir.items():
            card = e.get("card") or {}
            ref = _key_b64(card.get("principal_key_ref"))
            exp = card.get("expires_at")
            bad_root = bool(self.principal_roots) and ref not in self.principal_roots
            expired = isinstance(exp, str) and exp < now
            if bad_root or expired:
                dead[name] = e.get("node_fp")
        for name, fp in dead.items():
            e = self.agent_dir.pop(name, None)
            if e:
                self.agent_owner.pop(_key_b64(e.get("agent_key")), None)
        for fp in {fp for fp in dead.values() if fp}:
            if not any(v.get("node_fp") == fp for v in self.agent_dir.values()):
                self.nodes.pop(fp, None)
                self.prekeys.pop(fp, None)
        if dead:
            print("hub: pruned %d stale directory entries on load" % len(dead))

    BLOB_CAP = 64 * 1024 * 1024
    SAVE_INTERVAL = 2.0

    def _blob_path(self, bid):
        if not self.blob_dir or not envelope.safe_fp(bid):
            return None
        return os.path.join(self.blob_dir, bid)

    @staticmethod
    def _fsync_dir(d):
        fd = os.open(d, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    class _store_lock:
        """The store-wide lock (an flock on <store>/.lock): every writer of
        this directory - another State in this process, another hub
        process sharing the volume - serializes its uploads, its temp-file
        reclaim and its eviction, so nobody removes a file another writer
        is still publishing."""

        def __init__(self, d):
            self.d = d

        def __enter__(self):
            self.f = open(os.path.join(self.d, ".lock"), "w")
            fcntl.flock(self.f.fileno(), fcntl.LOCK_EX)
            return self

        def __exit__(self, *a):
            fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
            self.f.close()

    def _evict(self, protect=None):
        """Under the store lock: retire the oldest blobs (by upload time)
        until the store is within BLOB_CAP, never `protect` (the blob just
        written); the directory is fsynced when anything went."""
        d = self.blob_dir
        files = sorted((os.path.join(d, x) for x in os.listdir(d) if not x.startswith(".")),
                       key=lambda x: (os.path.getmtime(x), x))
        total = sum(os.path.getsize(x) for x in files)
        evicted = False
        for x in files:
            if total <= self.BLOB_CAP:
                break
            if x == protect:
                continue  # never the blob just written, whatever its mtime says
            total -= os.path.getsize(x)
            os.remove(x)
            evicted = True
        if evicted:
            self._fsync_dir(d)  # the retirements are durable too: a restart never comes back over the cap

    def _blob_store(self):
        """The store directory, private to this hub (0700) and durably
        created. On first use, under the store lock: leftover temp files
        from an upload that died mid-write are reclaimed, and the store is
        brought within its cap (an upload whose final fsync failed may
        have left it over)."""
        if self._blob_dir_ready:
            return
        d = self.blob_dir
        os.makedirs(d, mode=0o700, exist_ok=True)  # another State or process may be creating it right now
        # the parent is fsynced on every first use, created just now or
        # not: a parent fsync that failed on an earlier attempt is retried
        # here, never skipped because the directory happens to exist
        self._fsync_dir(os.path.dirname(os.path.abspath(d)))
        st = os.stat(d)
        if st.st_uid != os.getuid() or (st.st_mode & 0o077):
            raise PermissionError("blob store %s must be owned by this user and private (mode 0700)" % d)
        with self._store_lock(d):
            for x in os.listdir(d):
                if x.startswith(".blob."):
                    try:
                        os.remove(os.path.join(d, x))  # nobody else holds the lock: no upload is mid-flight
                    except OSError:
                        pass
            self._evict()
        self._blob_dir_ready = True

    def blob_put(self, bid, data) -> str:
        """Store a blob durably (temp file, every byte written and fsynced,
        rename, the directory fsynced) under its id. Returns '' or the
        reason it was refused. Blobs are content-addressed, so a second
        upload of the same bytes is the same blob. The store is bounded by
        BLOB_CAP: when the new blob would not fit, the OLDEST blobs (by
        upload time) are retired first, and never the one just written; a
        blob larger than the whole cap is refused."""
        p = self._blob_path(bid)
        if not p:
            return "bad blob id"
        if len(data) > self.BLOB_CAP:
            return "blob larger than the store"
        with self.lock:
            self._blob_store()
            with self._store_lock(self.blob_dir):
                fd, tmp = tempfile.mkstemp(dir=self.blob_dir, prefix=".blob.")
                try:
                    with os.fdopen(fd, "wb") as f:  # writes every byte, or raises
                        f.write(data)
                        f.flush()
                        os.fsync(f.fileno())
                    os.replace(tmp, p)
                except BaseException:
                    try:
                        os.remove(tmp)  # an upload that failed leaves nothing behind
                    except OSError:
                        pass
                    raise
                # the blob is published from here on: whatever fails after
                # this point, the cap is still enforced, then reported
                published_error = None
                try:
                    os.utime(p)  # a re-upload is a fresh copy: it lives as long as the newest
                    self._fsync_dir(self.blob_dir)  # the directory entry is durable, not only the bytes
                except OSError as e:
                    published_error = e
                self._evict(protect=p)
                if published_error is not None:
                    raise published_error
        return ""

    def blob_get(self, bid):
        """The blob's bytes, or None. A read does not consume it: the same
        blob can be fetched again by every recipient it was sent to, and by
        one recipient whose first download failed after the hub answered.
        Retention is the cap above, never the first GET."""
        p = self._blob_path(bid)
        if not p:
            return None
        self._blob_store()  # a hub that only serves downloads after a crash still reclaims and reconciles
        try:
            with open(p, "rb") as f:
                return f.read()
        except FileNotFoundError:
            return None

    def close(self):
        """A stateless hub's private store goes with it: nothing else can
        reach those blobs once the process is gone."""
        if self._private_store and os.path.isdir(self.blob_dir):
            shutil.rmtree(self.blob_dir, ignore_errors=True)

    def save(self, force=False):
        if not self.path:
            return
        import time
        now = time.time()
        if not force and now - self._last_save < self.SAVE_INTERVAL:
            return
        self._last_save = now
        d = {"prekeys": self.prekeys, "nodes": self.nodes, "agent_dir": self.agent_dir,
             "agent_owner": self.agent_owner, "queues": self.queues, "seq": self.seq}
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

        # ---- authentication helpers ----
        def _check_poll_token(self, fp, after):
            """Poll token: header X-Natively-Auth carrying base64 of the
            node-signed JSON {op: "poll", fp, after, ts, sig}. Returns an
            error string, or None when the token authenticates `fp`."""
            raw = self.headers.get("X-Natively-Auth")
            if not raw:
                return "poll token required"
            try:
                tok = jcs.loads(crypto.b64d(raw))
            except Exception:
                return "bad poll token"
            if not isinstance(tok, dict):
                return "bad poll token"
            with st.lock:
                node = st.nodes.get(fp)
            if not node:
                return "unknown node"
            if not _verify_signed(tok, _key_b64(node.get("node_key"))):
                return "bad poll token signature"
            if tok.get("op") != "poll" or tok.get("fp") != fp or tok.get("after") != after:
                return "poll token does not match request"
            if not _within(tok.get("ts"), POLL_TOKEN_WINDOW_S):
                return "poll token expired"
            return None

        def _card_for(self, agent_key_b64, owner_fp):
            for v in st.agent_dir.values():
                if v.get("node_fp") == owner_fp and _key_b64(v.get("agent_key")) == agent_key_b64:
                    return v.get("card")
            return None

        def _check_agent(self, a, node_key, fp):
            """One registered agent: a principal-signed card that names this
            node's key and the registered agent key. Returns an error
            string or None."""
            if not isinstance(a, dict):
                return "bad agent entry"
            name, key, card = a.get("name"), a.get("agent_key"), a.get("card")
            if not isinstance(name, str) or not name or "@" in name:
                return "bad agent name"
            if not _key_b64(key) or not isinstance(card, dict):
                return "bad agent entry"
            if card.get("agent_key") != key:
                return "card agent_key does not match registered agent key"
            if card.get("node_key") != node_key:
                return "card node_key is not the registering node"
            ref = _key_b64(card.get("principal_key_ref"))
            if st.principal_roots and ref not in st.principal_roots:
                return "card principal not in this hub's root set"
            # without a root set the hub trusts the principal the card
            # names: it is a directory, and the nodes pin their own roots
            if not ref or not envelope.verify_card(card, st.principal_roots or {ref}):
                return "card not verified"
            return None

        # ---- routing helpers ----
        def _route_node(self, env):
            """Owner node of the envelope's recipient. Called under st.lock:
            a registration replaces a node's ownership entries under the
            same lock, so routing never sees the gap."""
            to = env.get("to", "")
            if not isinstance(to, str):
                return None
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
                if not envelope.safe_fp(fp):
                    return self._json(400, {"error": "bad node fingerprint"})
                with st.lock:
                    b = st.prekeys.get(fp)
                return self._json(200, b) if b else self._json(404, {"error": "no bundle"})
            if p.startswith("/v1/blob/"):
                bid = p.rsplit("/", 1)[1]
                if not envelope.safe_fp(bid):
                    return self._json(400, {"error": "bad blob id"})
                d = st.blob_get(bid)  # a read, never a take: the blob stays for every recipient
                return self._raw(200, d) if d is not None else self._json(404, {"error": "no blob"})
            if p.startswith("/v1/poll/"):
                rest = p[len("/v1/poll/"):]
                fp, _, q = rest.partition("?")
                if not envelope.safe_fp(fp):
                    return self._json(400, {"error": "bad node fingerprint"})
                after = 0
                for kv in q.split("&"):
                    if kv.startswith("after="):
                        after = int(kv[6:])
                # a poll reads and prunes this node's queue: only the node
                # whose registered key signed the token may do that
                err = self._check_poll_token(fp, after)
                if err:
                    return self._json(401, {"error": err})
                deadline = time.time() + st.POLL_WAIT
                with st._cond(fp):
                    # seq skew self-heal (#15): a hub that rebooted from stale
                    # state has seq counters behind the nodes' cursors, and its
                    # queue entries are ghosts of messages the node already
                    # durably handled. Fast-forward to the node's cursor so new
                    # posts become visible again.
                    if after > st.seq.get(fp, 0):
                        st.seq[fp] = after
                        st.save()
                    while True:
                        q_list = st.queues.get(fp, [])
                        new = [e for e in q_list if e.get("_seq", 0) > after]
                        if new or time.time() > deadline:
                            out = new
                            last = q_list[-1]["_seq"] if q_list else after
                            break
                        st._cond(fp).wait(timeout=st.POLL_WAIT)
                    # prune: entries at or below the node's cursor are durably
                    # handled node-side (it saves state before the next poll)
                    if after and fp in st.queues:
                        keep = [e for e in st.queues[fp] if e.get("_seq", 0) > after]
                        if len(keep) != len(st.queues[fp]):
                            st.queues[fp] = keep
                            st.qids[fp] = {e.get("env", {}).get("msg_id") for e in keep}
                            st.save()
                return self._json(200, {"messages": out, "last_seq": last})
            return self._json(404, {"error": "not found"})

        def do_PUT(self):
            if self.path.startswith("/v1/prekey/"):
                fp = self.path.rsplit("/", 1)[1]
                b = self._body()  # read the body before any refusal: the connection is keep-alive
                if b is None:
                    return self._json(413, {"error": "too big"})
                if not envelope.safe_fp(fp):
                    return self._json(400, {"error": "bad node fingerprint"})
                try:
                    bundle = jcs.loads(b)
                except Exception:
                    return self._json(400, {"error": "bad json"})
                # verify bundle is signed by the node key it names, and that
                # this key's fingerprint is the path it is stored under:
                # nobody replaces another node's bundle with one of their own
                if not isinstance(bundle, dict):
                    return self._json(400, {"error": "bad bundle"})
                nk = _key_b64(bundle.get("node_key"))
                if not _verify_signed(bundle, nk):
                    return self._json(400, {"error": "bad bundle signature"})
                try:
                    if fingerprint(nk) != fp:
                        return self._json(400, {"error": "bundle node_key does not match path"})
                except Exception:
                    return self._json(400, {"error": "bad node_key"})
                with st.lock:
                    st.prekeys[fp] = bundle
                    st.save(force=True)
                return self._json(200, {"ok": True})
            return self._json(404, {"error": "not found"})

        def do_POST(self):
            if self.path == "/v1/register":
                b = self._body()
                try:
                    reg = jcs.loads(b)
                except Exception:
                    return self._json(400, {"error": "bad json"})
                if not isinstance(reg, dict):
                    return self._json(400, {"error": "bad register"})
                nk = _key_b64(reg.get("node_key"))
                if not _verify_signed(reg, nk):
                    return self._json(400, {"error": "bad register signature"})
                # a captured registration must not re-publish an old agent set
                if not _within(reg.get("ts"), REGISTER_WINDOW_S):
                    return self._json(400, {"error": "register ts outside window"})
                try:
                    fp = fingerprint(nk)
                except Exception:
                    return self._json(400, {"error": "bad node_key"})
                agents = reg.get("agents", [])
                if not isinstance(agents, list):
                    return self._json(400, {"error": "agents must be a list"})
                entries = {}
                for a in agents:
                    err = self._check_agent(a, reg["node_key"], fp)
                    if err:
                        return self._json(400, {"error": err})
                    entries["%s@%s" % (a["name"], fp)] = {
                        "agent_key": a["agent_key"], "card": a["card"], "node_fp": fp}
                with st.lock:
                    # registrations from one node apply in ts order: a
                    # captured earlier registration (still inside the
                    # window) must not roll the agent set back
                    prev = st.nodes.get(fp, {}).get("reg_ts")
                    if prev and envelope.parse_iso(reg["ts"]) <= envelope.parse_iso(prev):
                        return self._json(409, {"error": "registration not newer than the one on file"})
                    # an agent key another node owns moves only with a card
                    # that supersedes the one on file AND is issued by the
                    # same principal (spec 2): the previous principal's word
                    moved = []
                    for e in entries.values():
                        key = _key_b64(e["agent_key"])
                        owner = st.agent_owner.get(key)
                        if owner and owner != fp:
                            old = self._card_for(key, owner)
                            if (old is None or e["card"].get("supersedes") != envelope.obj_hash(old)
                                    or e["card"].get("principal_key_ref") != old.get("principal_key_ref")):
                                return self._json(409, {"error": "agent key owned by another node"})
                            moved.append((key, owner))
                    # replace this node's registration atomically: agents
                    # absent from the new set are gone from the directory,
                    # and a key that moved here leaves its old node's entry
                    for name in [n for n, v in st.agent_dir.items() if v.get("node_fp") == fp]:
                        del st.agent_dir[name]
                    for key in [k for k, v in st.agent_owner.items() if v == fp]:
                        del st.agent_owner[key]
                    for key, owner in moved:
                        for name in [n for n, v in st.agent_dir.items()
                                     if v.get("node_fp") == owner and _key_b64(v.get("agent_key")) == key]:
                            del st.agent_dir[name]
                    st.nodes[fp] = {"name": reg.get("name"), "node_key": reg["node_key"], "reg_ts": reg["ts"]}
                    for name, e in entries.items():
                        st.agent_dir[name] = e
                        st.agent_owner[_key_b64(e["agent_key"])] = fp
                    # persisted before the 200: the ts ordering must hold
                    # across a hub restart, not only until the next throttled save
                    st.save(force=True)
                return self._json(200, {"ok": True, "node_fp": fp})
            if self.path == "/v1/msg":
                b = self._body()
                try:
                    env = jcs.loads(b)
                except Exception:
                    return self._json(400, {"error": "bad json"})
                if not env.get("msg_id") or not env.get("to"):
                    return self._json(400, {"error": "missing fields"})
                with st.lock:
                    # route and enqueue under the one lock a registration
                    # replaces ownership under: no "unknown recipient" for
                    # an agent whose node is re-registering right now
                    node_fp = self._route_node(env)
                    # multi-recipient: "to" may be a list
                    targets = []
                    if isinstance(env.get("to"), list):
                        for t in env["to"]:
                            fp = st.agent_owner.get(t.split(":", 1)[1]) if isinstance(t, str) and t.startswith("ed25519:") else None
                            if fp:
                                targets.append(fp)
                    elif node_fp:
                        targets = [node_fp]
                    if not targets:
                        return self._json(404, {"error": "unknown recipient"})
                    # an envelope made for a node the recipient has since
                    # left is refused: routed on, it could never be read
                    to_node = env.get("to_node")
                    if to_node is not None and targets != [to_node]:
                        return self._json(409, {"error": "recipient moved", "node_fp": targets[0]})
                    queued = 0
                    deduped = 0
                    for fp in targets:
                        # dedupe: a node re-POSTs unacked envelopes, so the
                        # same msg_id must never enqueue twice for one node
                        ids = st.qids.setdefault(fp, set())
                        if env.get("msg_id") in ids:
                            deduped += 1  # honest accounting: a skip is not a queue
                            continue
                        q = st.queues.setdefault(fp, [])
                        st.seq[fp] = st.seq.get(fp, 0) + 1
                        q.append(
                            {"env": env, "_seq": st.seq[fp], "_queued_for": fp,
                             "_class": "control" if env.get("class") == "control" else "data"})
                        ids.add(env.get("msg_id"))
                        queued += 1
                        kept, dropped = _evict_to_cap(q, 500)
                        st.queues[fp] = kept
                        for m in dropped:
                            ids.discard(m.get("env", {}).get("msg_id"))
                    st.save()
                    for fp in targets:
                        st._cond(fp).notify_all()
                return self._json(200, {"queued": queued, "deduped": deduped})
            if self.path == "/v1/blob":
                b = self._body()
                if b is None:
                    return self._json(413, {"error": "too big"})
                import hashlib
                bid = hashlib.sha256(b).hexdigest()[:32]
                why = st.blob_put(bid, b)  # file store on the volume, not the json state
                if why:
                    return self._json(413, {"error": why})
                return self._json(200, {"blob_id": bid, "size": len(b)})
            return self._json(404, {"error": "not found"})

    return ThreadingHTTPServer(("0.0.0.0", port), H)


def run(port=8471, state_path=None, principal_roots=None):
    st = State(state_path, principal_roots=principal_roots)
    try:
        srv = make_server(port, st)  # inside the cleanup scope: a port already taken never leaks a private store
        print("natively hub listening on :%d" % port)
        srv.serve_forever()
    finally:
        st.close()

"""Natively node daemon (spec 8): enrollment, agent registry, transport poll
loop, envelope verification, e2e sessions (spec 9), ledger (spec 5).

Sessions are node-to-node (relays/hubs never see plaintext); agent identity
and authority ride inside as signed envelopes + cards + grants. A node runs
per machine; agents are local processes using the CLI.
"""
import calendar
import json
import os
import time
import threading
import http.client
import fcntl
import tempfile
import urllib.parse
import urllib.request
import urllib.error
from . import crypto, envelope, jcs
from .ledger import Ledger
from .revocation import Revocations, RevocationError, FeedUnavailable

P = 5  # poll interval seconds (spec 4 sizing: ack_deadline 2P+jitter, retries 2P/4P/8P)

# A send whose recipient is not in the hub directory waits - the agent
# may simply not have registered yet. But post-prune (#43) a dead
# identity never comes back, and an infinite deferral class churns the
# outbox forever (96 carried 24k such files on 2026-09-08). Deferrals
# are terminal after this many seconds.
DEFER_UNKNOWN_TTL = 1800

# A pairwise envelope that will not decrypt waits - the sessions may be
# mid-repair and the peer's next envelope can heal them. But a wedge like
# air's 2026-09-08 flood (pre-repair ciphertexts under dead chains) never
# heals, and an infinite failure class churns polls forever. Past this
# many seconds (anchored on the envelope's signed ts) a decrypt failure
# is terminal: ledgered, acked, dropped.
DEFER_DECRYPT_TTL = 1800


def home_dir() -> str:
    return os.environ.get("NATIVELY_HOME", os.path.expanduser("~/.natively"))


def _w600(path, data: bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, data)
    os.close(fd)


def _w600_replace(path, data: bytes):
    """Rewrite an existing private file in one step: the old content or
    the new, never a truncated one in between; durable before it is
    relied on."""
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    os.replace(tmp, path)
    dfd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _bare_key(k):
    """One form for a recipient key, prefixed or not: the wire recipient
    is the same either way, so holds and file records compare in one form."""
    return k.split(":", 1)[1] if isinstance(k, str) and k.startswith("ed25519:") else k


def _http(method, url, body=None, timeout=35, ctype="application/json", headers=None):
    req = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", ctype)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


class _HubConn:
    """HTTP/1.1 keep-alive connection to the hub for hot paths (flush, poll).

    urllib reopens TCP+TLS per call - on the outbox flush that is ~3-4 RTT
    per message, which caps a node's sequential send rate at the hub's
    round-trip time (measured ~145/min at ~140ms RTT during the plane-test-1
    soak, against a ~500/min local-work ceiling). Reusing one connection
    drops a send to ~1 RTT. Cold paths (register, directory, prekeys) stay
    on urllib: they run once per peer or per 5 min, not per message.
    Broken/closed connections are reopened once and the request retried;
    4xx responses surface as urllib.error.HTTPError so callers keep their
    status-code handling.
    """

    def __init__(self, hub, timeout=35):
        self.hub = hub
        self.timeout = timeout
        self._conn = None

    def _connect(self):
        u = urllib.parse.urlsplit(self.hub)
        if u.scheme == "https":
            self._conn = http.client.HTTPSConnection(u.hostname, u.port, timeout=self.timeout)
        else:
            self._conn = http.client.HTTPConnection(u.hostname, u.port, timeout=self.timeout)

    def close(self):
        try:
            if self._conn is not None:
                self._conn.close()
        finally:
            self._conn = None

    def request(self, method, path, body=None, ctype="application/json", headers=None):
        h = dict(headers or {})
        if body is not None:
            h["Content-Type"] = ctype
        for attempt in (0, 1):
            if self._conn is None:
                self._connect()
            try:
                self._conn.request(method, path, body=body, headers=h)
                r = self._conn.getresponse()
                data = r.read()  # must drain before the connection is reusable
                if r.status >= 400:
                    raise urllib.error.HTTPError(self.hub + path, r.status, r.reason, r.headers, None)
                return r.status, data
            except urllib.error.HTTPError:
                raise  # a real response arrived; the connection is fine
            except (http.client.HTTPException, OSError):
                self.close()
                if attempt:
                    raise


class IdentityError(Exception):
    """A peer's identity could not be bound to a principal-signed card."""


class RecipientMoved(Exception):
    """The hub now routes the recipient to another node than the one this
    ciphertext was made for: encrypt again against the fresh card."""


class IdentityUnknown(IdentityError):
    """The agent is not in the hub directory (yet): not a refusal, the
    peer may simply not have registered - a send waits, a receive is
    refused as unknown."""


class HubResponseError(OSError):
    """The hub answered, but not with a document this node accepts (a
    duplicate key, a non-object, not JSON at all). Nothing about the
    recipient is decided by it: the same class as the hub being
    unreachable - the send waits, the lookup is retried."""


def _lookup_failed(e) -> bool:
    """True when `e` is the hub being away or answering something this
    node refuses - a transport failure, a hub-side 5xx, HubResponseError -
    which decides nothing about an envelope. A 4xx answer, a disk error
    and a cryptographic failure are verdicts or local trouble, not this."""
    if isinstance(e, urllib.error.HTTPError):
        return e.code >= 500
    return isinstance(e, (HubResponseError, urllib.error.URLError, http.client.HTTPException))


class HandlingDeferred(Exception):
    """An inbound envelope could not be handled because the hub was away
    or refused (its directory, its prekey bundle) BEFORE anything was
    decided or executed for it: the receive loop leaves it unseen with the
    cursor before it, and the hub serves it again on the next poll. Raised
    only from the lookup phase - a failure after the envelope was
    decrypted or its action ran is never this."""


def node_fp_of(node_key_prefixed: str) -> str:
    return jcs.sha256(crypto.b64d(node_key_prefixed.split(":", 1)[1]))[:32]

def _oclass(e):
    """Ledger outcome class for an exception: fleet greps the JSONL (hash
    rows), so the error family must live in the outcome string, not only in
    the prose mirror."""
    return "error:" + type(e).__name__


class _GroupFileLock:
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.fh = open(self.path, "w")
        fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
        self.fh.close()
        return False



class _ReentrantGroupLock:
    """_GroupFileLock taken once per node per path: flock is per open file
    description, so a second open of the lock file inside the same process
    would wait on the first forever."""

    def __init__(self, node, path):
        self.node, self.path, self.inner = node, path, None

    def __enter__(self):
        held = self.node.__dict__.setdefault("_group_locks_held", {})
        if not held.get(self.path):
            self.inner = _GroupFileLock(self.path).__enter__()
        held[self.path] = held.get(self.path, 0) + 1
        return self

    def __exit__(self, *exc):
        held = self.node._group_locks_held
        held[self.path] -= 1
        if held[self.path] == 0:
            del held[self.path]
            self.inner.__exit__(*exc)
        return False


class Node:
    def __init__(self, home=None):
        self.home = home or home_dir()
        self.cfg = json.load(open(os.path.join(self.home, "config.json")))
        self.name = self.cfg["name"]
        self.hub = self.cfg["hub_url"].rstrip("/")
        self.node_seed = bytes.fromhex(open(os.path.join(self.home, "node.key")).read().strip())
        self.node_pub = crypto.sign_pub(self.node_seed)
        self.node_key = "ed25519:" + crypto.b64e(self.node_pub)
        self.fp = jcs.sha256(self.node_pub)[:32]
        self._hub_conn = None  # lazy _HubConn for hot paths (flush, poll, retry)
        self._backoff = {}     # outbox file -> (not before, delay): a send the hub asked to wait on (429)
        self._file_to = {}     # outbox file -> its recipient, learnt when the file is first read
        self.spk_sk = bytes.fromhex(open(os.path.join(self.home, "spk.key")).read().strip())
        # Pinned root set: principal.pub (one key per line, the first is the
        # node's own principal) plus principals/<name>.pub, one file per
        # further issuer the operator installs. A peer card, a grant or a
        # tombstone counts only when issued by one of these keys.
        roots = [ln.strip() for ln in open(os.path.join(self.home, "principal.pub")) if ln.strip()]
        if not roots:
            raise ValueError("principal.pub is empty: a node needs a pinned principal root")
        pdir = os.path.join(self.home, "principals")
        if os.path.isdir(pdir):
            for f in sorted(os.listdir(pdir)):
                if f.endswith(".pub"):
                    roots += [ln.strip() for ln in open(os.path.join(pdir, f)) if ln.strip()]
        for r in roots:
            try:
                envelope.key_bytes("ed25519:" + r)
            except ValueError:
                raise ValueError("pinned principal key is malformed: %r" % r)
        self.principal_pub = roots[0]
        self.principal_roots = set(roots)
        self._dir_cache = (0.0, None)
        self._bad_groups = set()  # groups whose file failed to load, ledgered once
        self._bad_agents = set()  # agents whose files failed to load, ledgered once
        self.revocations = Revocations(self.home, self.principal_roots)
        self.ledger = Ledger(os.path.join(self.home, "ledger.jsonl"))
        self.state_path = os.path.join(self.home, "state.json")
        self.state = self._load_state()
        self.sessions = {}   # peer_fp -> DRSession
        self.groups = {}     # gid -> group state
        self.agents = {}     # name -> {seed, card}
        self._load_agents()
        self.outbox_dir = os.path.join(self.home, "outbox")
        os.makedirs(self.outbox_dir, exist_ok=True)

    # ---------- persistence ----------
    def _load_state(self):
        p = self.state_path
        if os.path.exists(p):
            return json.load(open(p))
        return {"last_seq": 0, "unacked": {}, "seen": []}

    def _save_state(self):
        tmp = self.state_path + ".tmp"
        json.dump(self.state, open(tmp, "w"))
        os.replace(tmp, self.state_path)

    def _load_agents(self):
        adir = os.path.join(self.home, "agents")
        if not os.path.isdir(adir):
            return
        # rebuilt from the directory on every call: an agent whose files
        # are gone leaves the snapshot, so the next registration no longer
        # claims its key (a key that moved to another node would otherwise
        # make every later registration of this node a 409)
        agents = {}
        for f in os.listdir(adir):
            if f.endswith(".key"):
                name = f[:-4]
                cpath = os.path.join(adir, name + ".card.json")
                if not os.path.exists(cpath):
                    continue  # half-installed or half-removed: picked up when both files are there
                try:
                    seed = bytes.fromhex(open(os.path.join(adir, f)).read().strip())
                    card = jcs.loads(open(cpath, "rb").read())
                except (OSError, ValueError, RecursionError) as e:
                    # one agent's files that do not load are that agent's
                    # trouble: reported once, the daemon and the other
                    # agents go on
                    if name not in self._bad_agents:
                        self._bad_agents.add(name)
                        self.ledger.append("node:%s" % self.name, None, "agent.load", {"agent": name}, "error",
                                           "agent files cannot be loaded: %s" % e)
                    continue
                self._bad_agents.discard(name)
                agents[name] = {"seed": seed, "card": card}
        self.agents = agents

    def _session_path(self, direction, peer_fp):
        if not envelope.safe_fp(peer_fp):
            raise ValueError("bad peer fingerprint")
        return os.path.join(self.home, "sessions", direction + "_" + peer_fp + ".json")

    def _session(self, direction, peer_fp):
        key = direction + ":" + peer_fp
        if key in self.sessions:
            return self.sessions[key]
        p = self._session_path(direction, peer_fp)
        if os.path.exists(p):
            s = crypto.DRSession.from_state(json.load(open(p)))
            if s.hs_pending and s.agreement != crypto.X3DH_VERSION:
                # A handshake the peer never acknowledged, made under an
                # older key agreement: the peer (once on this code) derives
                # a different root from the same offer, so nothing sent on
                # this channel can ever be read. Start over on the next
                # send. An acknowledged channel is left alone - its root
                # has done its work, the chains carry on.
                os.unlink(p)
                self.ledger.append("node:%s" % self.name, None, "session.reinit",
                                   {"peer": peer_fp}, "ok",
                                   "unacknowledged handshake under agreement %s discarded; the next send starts one under %s"
                                   % (s.agreement, crypto.X3DH_VERSION))
                return None
            self.sessions[key] = s
            return s
        return None

    def _save_session(self, direction, peer_fp):
        s = self.sessions[direction + ":" + peer_fp]
        _w600(self._session_path(direction, peer_fp), json.dumps(s.to_state()).encode())

    def _group_lock(self, gid):
        """Serialize group-state read-modify-write across PROCESSES sharing
        this home. Reentrant within this Node: a join handler holding the
        lock fans out under it, and that path takes the lock again. node-run and bot processes each cache group state in
        memory; without the lock every group_send rewrote the file from
        stale cache - wiping keys other processes had installed and
        forking the shared sender ratchet (receivers then rejected one
        writer's envelopes as replayed/old). Found in the plane-test-1
        soak: distributions installed at 06:18Z were gone from disk at
        06:22Z behind bot chatter."""
        return _ReentrantGroupLock(self, self._group_path(gid) + ".lock")

    def _group_reload(self, gid):
        self.groups.pop(gid, None)
        return self._group(gid)

    def _group_path(self, gid):
        if not envelope.safe_id(gid, "grp"):
            raise ValueError("bad group id")
        return os.path.join(self.home, "groups", gid + ".json")

    def _group(self, gid):
        if gid in self.groups:
            return self.groups[gid]
        p = self._group_path(gid)
        if os.path.exists(p):
            g = json.load(open(p))
            g["_send"] = crypto.SenderKey.from_state(g["send_state"]) if g.get("send_state") else None
            g["_recv"] = {k: crypto.SenderKey.from_state(v) for k, v in g.get("recv_states", {}).items()}
            self.groups[gid] = g
            return g
        return None

    def _save_group(self, gid):
        """Write the group file atomically (a temp file beside it, fsync,
        rename): another process reading it - a daemon's pending refresh,
        a bot's group_send - sees the old file or the new one, never a
        truncated one in between."""
        g = self.groups[gid]
        g["send_state"] = g["_send"].state() if g.get("_send") else None
        g["recv_states"] = {k: v.state() for k, v in g.get("_recv", {}).items()}
        data = json.dumps({k: v for k, v in g.items() if not k.startswith("_")} | {"send_state": g["send_state"], "recv_states": g["recv_states"]}).encode()
        path = self._group_path(gid)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix="." + gid + ".")
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)

    # ---------- hub registration ----------
    def _auth_token(self, op, **fields):
        """Header value for a node-authenticated hub request: base64 of the
        node-signed JSON {op, fp, ts, ...fields}."""
        tok = envelope.sign_obj(dict(fields, op=op, fp=self.fp, ts=envelope.now_iso()), self.node_seed)
        return crypto.b64e(json.dumps(tok).encode())

    def publish_prekeys(self):
        bundle = {
            "node_key": "ed25519:" + crypto.b64e(self.node_pub),
            "name": self.name,
            "spk_x": crypto.b64e(crypto.x_pub(self.spk_sk)),
            "ts": envelope.now_iso(),
        }
        bundle["spk_sig"] = crypto.b64e(crypto.sign(self.node_seed, crypto.b64d(bundle["spk_x"])))
        bundle = envelope.sign_obj(bundle, self.node_seed)
        _http("PUT", "%s/v1/prekey/%s" % (self.hub, self.fp), json.dumps(bundle).encode())

    def register(self):
        # the hub applies one node's registrations in ts order (second
        # resolution): two in one second would refuse the second, so the
        # ts never repeats - across restarts too, it lives in state.json
        ts = max(int(time.time()), int(self.state.get("reg_ts", 0)) + 1)
        self.state["reg_ts"] = ts
        self._save_state()
        reg = {
            "node_key": "ed25519:" + crypto.b64e(self.node_pub),
            "name": self.name,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
            "agents": [{"name": n, "agent_key": a["card"]["agent_key"], "card": a["card"]}
                       for n, a in self.agents.items()],
        }
        reg = envelope.sign_obj(reg, self.node_seed)
        _http("POST", "%s/v1/register" % self.hub, json.dumps(reg).encode())

    # ---------- identity binding ----------
    def _directory(self, fresh=False):
        """Hub directory, cached for one second (the receive path consults
        it per envelope); fresh=True bypasses the cache."""
        ts, d = self._dir_cache
        if not fresh and d is not None and time.time() - ts < 1.0:
            return d
        _, b = _http("GET", "%s/v1/directory" % self.hub)
        try:
            d = jcs.loads(b)
        except ValueError as e:
            raise HubResponseError("directory response refused: %s" % e)
        if not isinstance(d, dict) or not isinstance(d.get("agents"), dict):
            raise HubResponseError("bad directory response")
        self._dir_cache = (time.time(), d)
        return d

    def _peer_card(self, agent_key, fresh=False, directory=None):
        """Bind an agent key to a principal-signed card and the node it
        resides on. The hub is untrusted: its directory is only a lookup;
        the card's own signature, its principal (pinned root set), its
        agent_key and its node_key decide. Returns (card, node_fp).
        fresh=True skips the cached directory copy; directory= resolves
        from that snapshot only (no hub request at all)."""
        key = agent_key.split(":", 1)[1] if agent_key.startswith("ed25519:") else agent_key
        entry = None
        for fresh in ((None,) if directory is not None else (True,) if fresh else (False, True)):
            # a miss in the cached copy is re-checked against the hub: a
            # peer that registered a moment ago is not an impostor
            for info in (directory if fresh is None else self._directory(fresh=fresh))["agents"].values():
                if isinstance(info, dict) and info.get("agent_key") == "ed25519:" + key:
                    entry = info
                    break
            if entry is not None:
                break
        if entry is None:
            raise IdentityUnknown("agent not in directory")
        card = entry.get("card")
        try:
            if not isinstance(card, dict) or card.get("agent_key") != "ed25519:" + key:
                raise IdentityError("card does not name this agent key")
            if not envelope.verify_card(card, self.principal_roots):
                raise IdentityError("card not verified under the pinned root set")
            fp = node_fp_of(card["node_key"])
        except IdentityError:
            raise
        except Exception as e:
            raise IdentityError("malformed card: %s" % e)
        return card, fp

    def _prekey_bundle(self, peer_fp):
        """The peer's prekey bundle, accepted only when signed by a node key
        whose fingerprint is peer_fp (the fp came from a verified card)."""
        _, b = _http("GET", "%s/v1/prekey/%s" % (self.hub, peer_fp))
        try:
            bundle = jcs.loads(b)
        except ValueError as e:
            raise HubResponseError("prekey response refused: %s" % e)
        try:
            nk = bundle["node_key"].split(":", 1)[1]
            if node_fp_of(bundle["node_key"]) != peer_fp:
                raise IdentityError("prekey bundle is not signed by the peer node")
            if not envelope.verify_obj(bundle, nk):
                raise IdentityError("prekey bundle signature invalid")
            if not crypto.verify(crypto.b64d(nk), crypto.b64d(bundle["spk_x"]), crypto.b64d(bundle["spk_sig"])):
                raise IdentityError("peer prekey sig invalid")
        except IdentityError:
            raise
        except Exception as e:
            raise IdentityError("malformed prekey bundle: %s" % e)
        return bundle

    # ---------- pairwise sessions (node-to-node) ----------
    # Directional channels (v0): each node initiates its OWN send channel to a
    # peer (X3DH initiator role) and keeps a separate responder channel for the
    # peer's initiated channel. Simultaneous initiation is then a non-event.
    # Within a channel the DH ratchet is static after setup; forward secrecy
    # comes from the symmetric chain, and channel re-init rotates DH roots.
    def _session_for_send(self, peer_fp):
        s = self._session("to", peer_fp)
        if s and s.send_chain is not None:
            # Re-attach the x3dh ephemeral until the peer's first ack proves
            # it decrypted us - a lost first ciphertext must not brick the pair.
            return s, (s.x3dh_ek if s.hs_pending else None)
        bundle = self._prekey_bundle(peer_fp)
        peer_spk_x = crypto.b64d(bundle["spk_x"])
        peer_node_pub = crypto.b64d(bundle["node_key"].split(":", 1)[1])
        root, ek = crypto.x3dh_initiator(self.node_seed, peer_node_pub, peer_spk_x)
        s = crypto.DRSession.init_initiator(root, peer_spk_x)
        s.x3dh_ek = ek
        s.hs_pending = True
        self.sessions["to:" + peer_fp] = s
        self._save_session("to", peer_fp)
        return s, ek  # ek travels with first ciphertext

    def _x3dh_responder_session(self, peer_fp, x3dh_ek_b64):
        bundle = self._prekey_bundle(peer_fp)
        peer_node_pub = crypto.b64d(bundle["node_key"].split(":", 1)[1])
        root = crypto.x3dh_responder(self.node_seed, self.spk_sk,
                                     crypto.ed_pk_to_x(peer_node_pub),
                                     crypto.b64d(x3dh_ek_b64))
        return crypto.DRSession.init_responder(root, self.spk_sk)

    def _session_for_recv(self, peer_fp, x3dh_ek_b64, dh_hdr):
        s = self._session("from", peer_fp)
        if s is None:
            if not x3dh_ek_b64:
                raise ValueError("no session and no x3dh ek")
            s = self._x3dh_responder_session(peer_fp, x3dh_ek_b64)
            self.sessions["from:" + peer_fp] = s
        return s

    @staticmethod
    def _carries_handshake(env, ek):
        """True when this outgoing envelope's pairwise wire re-attached the
        x3dh ephemeral `ek` - it was encrypted under that handshake."""
        try:
            wire = jcs.loads(crypto.b64d(env["body"]))  # the same strict reader as the receive side
            return isinstance(wire, dict) and wire.get("x3dh_ek") == crypto.b64e(ek)
        except Exception:
            return False

    def _enc_pairwise(self, peer_fp, plaintext_obj):
        s, ek = self._session_for_send(peer_fp)
        pt = json.dumps(plaintext_obj).encode()
        hdr, ct = s.encrypt(pt, aad=b"nv1-msg")
        wire = {"dh": hdr, "ct": crypto.b64e(ct)}
        if ek:
            wire["x3dh_ek"] = crypto.b64e(ek)
        self._save_session("to", peer_fp)
        return crypto.b64e(json.dumps(wire).encode())

    def _dec_pairwise(self, peer_fp, body_b64):
        wire = jcs.loads(crypto.b64d(body_b64))
        s = self._session_for_recv(peer_fp, wire.get("x3dh_ek"), wire["dh"])
        try:
            pt = s.decrypt(wire["dh"], crypto.b64d(wire["ct"]), aad=b"nv1-msg")
        except Exception:
            # a failed decryption commits nothing: the in-memory session is
            # dropped, so the next envelope reloads the last saved state
            # (the one every successful decryption wrote) - and a
            # handshake that never decrypted anything leaves no session at
            # all, so the peer's next x3dh_ek can start one
            self.sessions.pop("from:" + peer_fp, None)
            if wire.get("x3dh_ek"):
                # Heal-on-handshake: a peer that has never seen an ack keeps
                # re-attaching its x3dh ephemeral (hs_pending), but a
                # diverged saved session on this side made us ignore the
                # offer and fail forever - the air wedge of 2026-09-08. Try
                # the offered handshake from scratch and commit the fresh
                # session ONLY if it actually reads this envelope; a failed
                # probe changes nothing.
                s2 = self._x3dh_responder_session(peer_fp, wire["x3dh_ek"])
                pt2 = s2.decrypt(wire["dh"], crypto.b64d(wire["ct"]), aad=b"nv1-msg")
                body = jcs.loads(pt2)  # the same strict reader as the normal path, before anything is committed
                self.sessions["from:" + peer_fp] = s2
                self._save_session("from", peer_fp)
                self.ledger.append("node:%s" % self.name, None, "session.heal",
                                   {"peer": peer_fp}, "ok",
                                   "adopted peer's re-attached x3dh handshake after decrypt failure")
                return body
            raise
        self._save_session("from", peer_fp)
        return jcs.loads(pt)

    # ---------- groups ----------
    def _group_key_body(self, g, card):
        """A group_key body is an ACTION (group.join on the member's node,
        params naming the group): the member joins and distributes its
        own sender key only under a grant covering it; without one the
        body is information in its inbox and no group state changes.
        `card` is the member's resolved card (its node_key names the
        host the join is bound to)."""
        # the INITIAL state of this node's sender key, kept on the group
        # record: a member whose key waited on the directory (pending)
        # receives the same chain start as one addressed at creation, so
        # texts sent in between decrypt by fast-forward instead of being
        # refused as older than the state it was handed
        return {"kind": "group_key", "action": "group.join",
                "resource": "host:%s:groups" % card["node_key"], "params": {"group_id": g["group_id"]},
                "group_id": g["group_id"], "group_name": g.get("name", ""),
                "sender_fp": self.fp, "state": g["initial_state"], "members": g.get("members", [])}

    def create_group(self, creator_agent, members, name="", grant_ids=None):
        """members: [{"agent_key": ..., "grant_ids": [...]}, ...] - the grant
        ids a member holds for group.join on its node (grant_ids is the
        default for members that carry none)."""
        gid = envelope.new_id("grp")
        members = [dict(m, grant_ids=m.get("grant_ids") or list(grant_ids or [])) for m in members]
        send = crypto.SenderKey()
        # my sender key goes to each member node, pairwise-encrypted, from
        # the daemon's pending pass: the work is persisted with the group
        # itself, and the lookups happen in bounded batches off one
        # directory read, never one hub round trip per member inside this call
        g = {"group_id": gid, "name": name, "creator": creator_agent,
             "members": members, "_send": send, "_recv": {}, "initial_state": send.state(),
             "send_state": None, "recv_states": {},
             "pending": [{"agent": creator_agent, "agent_key": m["agent_key"], "grant_ids": m.get("grant_ids") or []}
                         for m in members]}
        self.groups[gid] = g
        self._save_group(gid)
        return gid

    PENDING_BATCH = 20  # pending key distributions attempted per pass

    def _pending_update(self, gid, fn):
        """Change a group's pending list under the group lock, on the state
        as it is on disk: another process (the CLI's group-create, a bot's
        group_send) may have advanced the sender ratchet or widened the
        member list since this daemon cached the group, and a save from
        the cache would rewind them (a sender counter rewound from 1 to 0
        makes the next message a replay). `fn(g)` mutates and returns
        whether anything changed."""
        with self._group_lock(gid):
            g = self._group_reload(gid)
            if g is not None and fn(g):
                self._save_group(gid)

    def _hold_group_keys(self, agent_name, gid, members):
        """Put every member on the group's pending list in one update (a
        member already there stays as it is)."""
        def add(g):
            pending = g.setdefault("pending", [])
            have = {p["agent_key"] for p in pending}
            changed = False
            for member in members:
                if member["agent_key"] in have:
                    continue
                pending.append({"agent": agent_name, "agent_key": member["agent_key"],
                                "grant_ids": member.get("grant_ids") or []})
                have.add(member["agent_key"])
                changed = True
            return changed
        self._pending_update(gid, add)

    def _hold_group_key(self, agent_name, gid, member):
        self._hold_group_keys(agent_name, gid, [member])

    def _release_group_key(self, gid, key):
        def drop(g):
            pending = g.get("pending", [])
            if not any(p["agent_key"] == key for p in pending):
                return False
            g["pending"] = [p for p in pending if p["agent_key"] != key]
            return True
        self._pending_update(gid, drop)

    def _distribute_group_key(self, agent_name, gid, member, directory=None):
        """Queue this agent's sender key for one member of `gid`, as a
        control envelope (the hub never evicts it under chatter pressure).
        The member's card is resolved before any group lock is taken, so a
        slow directory never holds other processes' group sends. A member
        the directory cannot resolve right now (not registered yet, a
        stale cache) is not a lost member: it goes on the group's
        `pending` list and the daemon retries it until it resolves. A
        member whose card is bad is ledgered and dropped."""
        key = member["agent_key"]
        try:
            card, _ = self._peer_card(key, directory=directory)
            self.queue_send(agent_name, key, self._group_key_body(self._group(gid), card),
                            grant_ids=member.get("grant_ids") or [], control=True)
        except IdentityUnknown:
            self._hold_group_key(agent_name, gid, member)
            return False
        except IdentityError as e:
            # a bad card is permanent: ledgered once, and the member leaves
            # the pending list so the next pass does not repeat the lookup
            self.ledger.append("agent:%s" % agent_name, None, "group.key",
                               {"group_id": gid, "to": key}, "error", "cannot address member: %s" % e)
            self._release_group_key(gid, key)
            return False
        except Exception:
            # the hub unreachable, a directory that is not the shape the
            # hub speaks: transient - the member waits, the daemon goes on
            self._hold_group_key(agent_name, gid, member)
            return False
        self._release_group_key(gid, key)
        return True

    def _retry_pending_group_keys(self):
        """Every pass: members whose key distribution waited on the
        directory are tried again - at most PENDING_BATCH per pass, and
        only members the directory names, judged from ONE directory read
        for the whole pass (a lookup per pending member would hold the
        flush, the poll and the acks behind every stalled request). The
        group files are read from disk, so a group the CLI created in
        another process, and pending entries it wrote, are seen too."""
        gdir = os.path.join(self.home, "groups")
        if not os.path.isdir(gdir):
            return
        pending = []
        for f in sorted(os.listdir(gdir)):
            gid = f[:-5] if f.endswith(".json") else None
            if not envelope.safe_id(gid, "grp"):
                continue
            try:
                with open(self._group_path(gid)) as fh:
                    on_disk = json.load(fh)
            except (OSError, ValueError):
                continue
            if not isinstance(on_disk, dict) or on_disk.get("send_state") is None:
                continue  # no sender key of ours to distribute
            raw_pending = on_disk.get("pending") or []
            if not isinstance(raw_pending, list) or not all(isinstance(p, dict) and isinstance(p.get("agent_key"), str)
                                                              and isinstance(p.get("agent"), str) for p in raw_pending):
                if gid not in self._bad_groups:
                    self._bad_groups.add(gid)
                    self.ledger.append("node:%s" % self.name, None, "group.key", {"group_id": gid}, "error",
                                       "group state cannot be loaded: pending list is not the shape this node writes")
                continue
            plist = [p for p in raw_pending if p["agent"] in self.agents]
            if (gid not in self.groups or gid in self._bad_groups
                    or self.groups[gid].get("pending", []) != (on_disk.get("pending") or [])):
                # not cached yet, or another process changed the pending
                # list (the disk is the truth): read under the group lock,
                # and a file that does not load is this group's trouble,
                # never the daemon's - ledgered once, retried every pass
                try:
                    with self._group_lock(gid):
                        self._group_reload(gid)
                except Exception as e:
                    if gid not in self._bad_groups:
                        self._bad_groups.add(gid)
                        self.ledger.append("node:%s" % self.name, None, "group.key", {"group_id": gid}, "error",
                                           "group state cannot be loaded: %s" % e)
                    continue
                self._bad_groups.discard(gid)
            pending += [(gid, p) for p in plist]
        if not pending:
            return
        try:
            snapshot = self._directory(fresh=True)
            known = {info.get("agent_key") for info in snapshot["agents"].values() if isinstance(info, dict)}
        except Exception:
            return  # the hub is away: the members stay pending, the pass goes on
        budget = self.PENDING_BATCH
        for gid, p in pending:
            if budget <= 0:
                return
            if p["agent_key"] not in known:
                continue  # still not registered: no lookup spent on it
            budget -= 1
            try:
                self._distribute_group_key(p["agent"], gid, p, directory=snapshot)  # the pass's one read, no request per member
            except Exception as e:
                # one member's trouble never stops the pass or the daemon
                self.ledger.append("node:%s" % self.name, None, "group.key", {"group_id": gid}, "error",
                                   "pending distribution failed: %s" % e)

    def group_send(self, from_agent, gid, body_obj):
        with self._group_lock(gid):
            return self._group_send_locked(from_agent, gid, body_obj)

    def _group_send_locked(self, from_agent, gid, body_obj):
        g = self._group_reload(gid)
        if not g or not g.get("_send"):
            raise ValueError("unknown group or no sender key")
        pt = json.dumps(body_obj).encode()
        n, ct = g["_send"].encrypt(pt, aad=b"nv1-grp:" + gid.encode())
        wire = {"kind": "group_msg", "group_id": gid, "n": n, "ct": crypto.b64e(ct),
                "sender_fp": self.fp}
        local_keys = {a["card"]["agent_key"] for a in self.agents.values()}
        for m in g["members"]:
            # Skip members whose card fails verification against the pinned
            # root set (retired principal, stale group file): queueing to
            # them only manufactures permanently-undeliverable outbox
            # entries. IdentityUnknown (not yet registered) still queues -
            # the recipient may simply not have registered yet.
            try:
                _, member_fp = self._peer_card(m["agent_key"])
            except IdentityUnknown:
                member_fp = None  # may simply not be registered yet: queue as usual
            except IdentityError as e:
                self.ledger.append("agent:%s" % from_agent, None, "group.send",
                                   {"group_id": gid, "member": m["agent_key"]},
                                   "member-skipped", "member skipped: %s" % e)
                continue
            if member_fp == self.fp or m["agent_key"] in local_keys:
                # Local member: queue the plaintext body directly instead of
                # wrapping it in my own sender key. A loopback copy decrypts
                # against my receive ratchet for MY OWN sender key, which the
                # send side has already advanced - under newest-first flush
                # ordering the delayed copies inevitably reject as
                # "replayed/old sender-key message" and dead-letter (hit in
                # the plane-test-1 soak). The plaintext never leaves the node
                # either way: inbox files are local plaintext by design.
                self.queue_send(from_agent, m["agent_key"], dict(body_obj, group_id=gid))
                continue
            self.queue_send(from_agent, m["agent_key"], {
                "kind": "group_relay", "wire": wire, "group_id": gid,
            }, inner_wire=wire)
        self._save_group(gid)

    # ---------- send path ----------
    def queue_send(self, from_agent, to_agent_key_b64, body_obj, grant_ids=None,
                   inner_wire=None, msg_type="msg", to_node_fp=None, control=False, in_reply_to=None):
        """Enqueue an outbound message. body_obj is plaintext JSON for pairwise
        (encrypted to recipient node); inner_wire carries pre-encrypted group
        payloads (node-encrypted wrapper only). control=True marks the envelope
        class=control (signed): the hub never evicts those under chatter
        pressure - use for group_key distributions and protocol control."""
        a = self.agents[from_agent]
        req = {"from_agent": from_agent, "to": to_agent_key_b64,
               "body_obj": body_obj, "grant_ids": grant_ids or [],
               "msg_type": msg_type, "queued_at": time.time(), "in_reply_to": in_reply_to}
        if control:
            req["control"] = True
        if to_node_fp:
            req["to_node_fp"] = to_node_fp
        # a control envelope (a group_key distribution) is named ctl_..., so
        # the flush can put every one of them ahead of the batch window
        # without opening a file: a relay never overtakes the key it
        # decrypts under, however deep the outbox
        fn = os.path.join(self.outbox_dir, ("ctl_" if control else "out_") + envelope.new_id("out")[4:] + ".json")
        _w600(fn, json.dumps(req).encode())
        return fn

    def _maybe_reregister(self):
        # re-register on agent-set change OR every 5 min: the hub's agent
        # directory is rebuilt from registrations, so a hub that restarts
        # heals without operator action (#14). Called from the run loop AND
        # inside the outbox flush: with a 10k+ backlog one flush pass takes
        # far longer than 300s, so a run-loop-only check effectively never
        # fires on busy nodes (break #18).
        if set(self.agents) == self._last_registered and time.time() - self._last_reg_time <= 300:
            return
        if int(time.time()) <= int(self.state.get("reg_ts", 0)):
            return  # the hub orders registrations by whole-second ts: wait for the clock, never run ahead of it
        try:
            self.publish_prekeys()  # hub may have lost them on a reboot
            self.register()
            self._last_registered = set(self.agents)
            self._last_reg_time = time.time()
        except Exception as e:
            self.ledger.append("node:%s" % self.name, None, "node.register",
                               {}, "retry", "register failed: %s" % e)

    def _hub_req(self, method, path, body=None, headers=None):
        """Hub call over a persistent keep-alive connection (hot paths only:
        flush sends, poll, retries). One TCP+TLS setup per node run instead
        of one per message. Cold paths stay on _http/urllib."""
        if self._hub_conn is None:
            self._hub_conn = _HubConn(self.hub)
        return self._hub_conn.request(method, path, body=body, headers=headers)

    FLUSH_BATCH = 400  # outcomes per pass
    LIVE_WINDOW = 300  # newest files sent first...
    DRAIN_SLICE = 100  # ...then a guaranteed slice of the oldest

    def _relay_waits_for_key(self, req, cache) -> bool:
        """A group_relay to a member still on the group's pending list would
        arrive before the member's key distribution (which is not even
        queued yet) and be refused as an unknown group: it waits in the
        outbox until the pending pass has queued the key."""
        body = req.get("body_obj")
        if not isinstance(body, dict) or body.get("kind") != "group_relay":
            return False
        gid = body.get("group_id")
        if gid not in cache:
            try:
                g = self._group(gid)
                cache[gid] = {p.get("agent_key") for p in (g or {}).get("pending", []) if isinstance(p, dict)}
            except Exception:
                cache[gid] = set()  # an unknown or unreadable group is not a reason to hold anything
        return req.get("to") in cache[gid]

    def _flush_outbox(self):
        dead = {}  # recipient -> permanent identity verdict, this pass
        pending_cache = {}  # group id -> the member keys whose key distribution is still pending, this pass
        dirty = False  # state changed; saved once at pass end, not per send
        outcomes = 0
        # Cap outcomes per pass: during a deep backlog the pass must not
        # starve the poll side - inbound latency matters more than drain
        # speed, and the remaining files are picked up next pass.
        FLUSH_BATCH = self.FLUSH_BATCH
        # Two-phase order. Live traffic is the newest files; dead backlog is
        # the oldest. Newest-first alone would starve the drain whenever
        # arrivals fill the cap; oldest-first makes live sends queue behind
        # thousands of verdict marks. So: a live window of the newest 300,
        # then a guaranteed oldest slice of 100 - live latency wins the
        # budget, the backlog drains at a steady floor.
        files = [f for f in sorted(os.listdir(self.outbox_dir)) if f.endswith(".json")]
        # a file the hub asked to wait on (429, Retry-After) is not
        # attempted before its time and spends none of this pass's budget:
        # a backpressured recipient never starves every other delivery.
        # Eligibility is decided BEFORE the windows below are cut, so a
        # deferred backlog never hides an eligible file in the middle.
        # And a recipient whose control envelope (a group key) is waiting
        # holds its later relays too: a relay must never overtake the key
        # it decrypts under, backpressure included.
        now = time.time()
        present = set(files)
        self._backoff = {f: v for f, v in self._backoff.items() if f in present}
        self._file_to = {f: v for f, v in self._file_to.items() if f in present}
        held_to = set()
        for f in files:
            if f.startswith("ctl_") and self._backoff.get(f, (0.0, 0.0))[0] > now:
                try:
                    held_to.add(_bare_key(json.load(open(os.path.join(self.outbox_dir, f))).get("to")))
                except (OSError, ValueError):
                    pass
        # a file whose recipient is known (read on an earlier pass) to be
        # held stays out of the windows and the attempt count altogether;
        # one not read yet is found held when it is read, and known after
        files = [f for f in files if self._backoff.get(f, (0.0, 0.0))[0] <= now
                 and not (not f.startswith("ctl_") and self._file_to.get(f) in held_to)]
        # Causal priority: a group_key distribution installs the receive
        # state later group_relay messages decrypt under. Newest-first alone
        # delivers a relay BEFORE its key when both were queued together
        # (group created, then immediately used) - the receiver consumes the
        # relay as unknown-group and the message is lost. Every control
        # envelope (named ctl_ by queue_send) goes ahead of the window, not
        # only ahead of the files that happened to fall inside it.
        ctl = [f for f in files if f.startswith("ctl_")]
        rest = [f for f in files if not f.startswith("ctl_")]
        order = ctl[::-1] + rest[-self.LIVE_WINDOW:][::-1] + rest[:-self.LIVE_WINDOW][:self.DRAIN_SLICE]
        attempts = 0
        for f in order:
            if outcomes >= FLUSH_BATCH or attempts >= FLUSH_BATCH:
                break  # attempts are bounded too: an outage must not spend one timeout per queued file before the poll
            if attempts and attempts % 200 == 0:
                self._maybe_reregister()
            path = os.path.join(self.outbox_dir, f)
            env = None
            try:
                req = json.load(open(path))
                self._file_to[f] = _bare_key(req.get("to"))
                if self._relay_waits_for_key(req, pending_cache):
                    continue  # its key distribution has not been queued yet: the file stays for a later pass
                if not f.startswith("ctl_") and _bare_key(req.get("to")) in held_to:
                    continue  # its recipient's control envelope is waiting on the hub: this file waits behind it (no attempt spent)
                attempts += 1
                if req["to"] in dead:
                    # a recipient already found permanently undeliverable in
                    # this pass (e.g. card principal not in the pinned root
                    # set): the verdict is deterministic, so every queued
                    # envelope to it is dead on arrival. Mark without
                    # re-resolving - a dead-fanout backlog drains in one pass.
                    self.ledger.append("node:%s" % self.name, None, "msg.send", {"file": f},
                                       "error:Identity", "send failed: recipient identity: %s (same-pass verdict)" % dead[req["to"]])
                    os.rename(path, path + ".err")
                    outcomes += 1
                    continue
                if req["from_agent"] not in self._last_registered:
                    # an agent added since the last successful registration:
                    # peers refuse (and consume) a message from a sender the
                    # directory does not carry yet, so it waits here
                    continue
                a = self.agents[req["from_agent"]]
                # the recipient's node is what its principal-signed card
                # says, never the hub's routing field. Unknown = not
                # registered yet: the send waits in the outbox.
                try:
                    _, peer_fp = self._peer_card(req["to"])
                except IdentityUnknown:
                    raise
                except IdentityError as e:
                    dead[req["to"]] = str(e)
                    raise ValueError("recipient identity: %s" % e)
                if peer_fp == self.fp:
                    # loopback: recipient agent is local - deliver in place;
                    # the relay never sees intra-node traffic at all.
                    to_key = req["to"].split(":")[-1]
                    agent_name = None
                    for nm, ag in self.agents.items():
                        if ag["card"]["agent_key"] == "ed25519:" + to_key:
                            agent_name = nm
                            break
                    if agent_name is None:
                        # the card in the directory cache names this node,
                        # but the agent is not here (it moved): never
                        # consume the send on a stale answer - re-resolve
                        # from the hub next pass
                        self._dir_cache = (0.0, None)
                        raise IdentityUnknown("recipient no longer on this node; re-resolving")
                    fake_env = {"msg_id": envelope.new_id("msg"), "ts": envelope.now_iso(),
                                "from": self.agents[req["from_agent"]]["card"]["agent_key"],
                                "grant_ids": req["grant_ids"]}
                    self._deliver_local(agent_name, fake_env, req["body_obj"])
                    os.unlink(path)
                    continue
                env = req.get("env")
                if not (isinstance(env, dict) and env.get("to_node") == peer_fp):
                    # a send the hub asked to wait on (429) kept the envelope
                    # it built in the request file: the same bytes go again,
                    # one ratchet step per message however many passes the
                    # hub refuses it. Only a recipient that moved gets a new
                    # ciphertext.
                    ct_b64 = self._enc_pairwise(peer_fp, req["body_obj"])
                    # to_node: the node this ciphertext is for. The hub refuses
                    # (409) when the recipient now lives elsewhere, so a card
                    # cached across a move never strands a message on the
                    # wrong node; the sender refreshes and re-encrypts.
                    extra = {"to": req["to"] if req["to"].startswith("ed25519:") else "ed25519:" + req["to"],
                             "to_node": peer_fp}
                    if req.get("control"):
                        extra["class"] = "control"
                    env = envelope.make_message(
                        a["card"]["agent_key"].split(":", 1)[1], req["to"].split(":", 1)[-1],
                        ct_b64, a["seed"], grant_ids=req["grant_ids"], in_reply_to=req.get("in_reply_to"),
                        msg_type=req["msg_type"], extra=extra)
                try:
                    self._hub_req("POST", "/v1/msg", json.dumps(env).encode())
                except urllib.error.HTTPError as e:
                    if e.code == 409:
                        self._dir_cache = (0.0, None)
                        raise RecipientMoved("recipient moved to another node; re-encrypting next pass")
                    if e.code == 404:
                        # the hub does not know the recipient right now (a
                        # re-registration gap, or not registered yet): wait,
                        # exactly as when the directory has no card for it
                        self._dir_cache = (0.0, None)
                        raise IdentityUnknown("recipient unknown to the hub")
                    raise
                # Acks never enter the retry table: an ack is an answer, not
                # a message - nobody acks an ack, so every ack entered here
                # retries 3x and dead-letters as a false UNDELIVERED (the
                # 2026-09-08 exchange failure class, mirrored on both
                # implementations).
                if env.get("type") != "ack":
                    self.state["unacked"][env["msg_id"]] = {
                        "env": env, "attempts": 1, "next": time.time() + 2 * P,
                        "peer_fp": peer_fp}
                dirty = True  # saved once at pass end; a crash costs at most a duplicate send, and apply is idempotent on msg_id
                gids = [g for g in (req.get("grant_ids") or []) if envelope.safe_id(g, "grt")]  # the row names a grant id or none
                self.ledger.append("agent:%s" % req["from_agent"], gids[0] if gids else None,
                                   "msg.send", {"to": req["to"], "msg_id": env["msg_id"]}, "queued",
                                   "sent %s to %s" % (req["body_obj"].get("kind", "msg"), req["to"]))
                os.unlink(path)
                if self.state.get("deferred_since", {}).pop(f, None) is not None:
                    dirty = True
                outcomes += 1
            except Exception as e:
                transient = isinstance(e, (urllib.error.URLError, TimeoutError, OSError, IdentityUnknown, RecipientMoved))
                if isinstance(e, urllib.error.HTTPError) and 400 <= e.code < 500 and e.code != 429:
                    transient = False  # 4xx is a permanent rejection, not a retry case - except 429, the hub asking for room
                if isinstance(e, urllib.error.HTTPError) and e.code == 429:
                    # the hub has no room for this recipient: wait what it
                    # says (Retry-After), doubling on every further refusal
                    # up to a minute; the file stays, other files go on
                    try:
                        asked = float((e.headers or {}).get("Retry-After", 0) or 0)
                    except (TypeError, ValueError):
                        asked = 0.0
                    prev = self._backoff.get(f, (0.0, 0.0))[1]
                    delay = min(60.0, max(asked, prev * 2, float(P)))
                    self._backoff[f] = (time.time() + delay, delay)
                    if isinstance(env, dict) and req.get("env") is not env:
                        req["env"] = env  # the envelope this pass built goes again as it is, next pass
                        _w600_replace(path, json.dumps(req).encode())
                    if f.startswith("ctl_"):
                        held_to.add(_bare_key(req.get("to")))  # from now on in this pass its relays wait behind it too
                    self.ledger.append("node:%s" % self.name, None, "msg.send", {"file": f},
                                       "retry", "send deferred %.0fs: %s" % (delay, e))
                    continue
                if transient and isinstance(e, IdentityUnknown):
                    # Recipient not in the directory: retryable while it
                    # may still register, terminal after DEFER_UNKNOWN_TTL
                    # (a pruned identity never resolves - #43 made this an
                    # infinite class; fleet measured +2.5k churning files
                    # in 30 min on 96).
                    ds = self.state.setdefault("deferred_since", {})
                    first = ds.get(f)
                    if first is None:
                        ds[f] = time.time()
                        dirty = True
                        self.ledger.append("node:%s" % self.name, None, "msg.send", {"file": f},
                                           "retry", "send deferred: %s" % e)
                    elif time.time() - first > DEFER_UNKNOWN_TTL:
                        ds.pop(f, None)
                        dirty = True
                        self.ledger.append("agent:%s" % req["from_agent"], None, "msg.send",
                                           {"file": f, "to": req.get("to")}, "recipient-unknown",
                                           "terminal: recipient not in the directory for >%ds" % DEFER_UNKNOWN_TTL)
                        os.rename(path, path + ".err")
                        outcomes += 1
                    else:
                        self.ledger.append("node:%s" % self.name, None, "msg.send", {"file": f},
                                           "retry", "send deferred: %s" % e)
                elif transient:
                    # hub down / network blip: leave in outbox, retry next pass
                    self.ledger.append("node:%s" % self.name, None, "msg.send", {"file": f},
                                       "retry", "send deferred: %s" % e)
                else:
                    self.ledger.append("node:%s" % self.name, None, "msg.send", {"file": f},
                                       _oclass(e), "send failed: %s" % e)
                    os.rename(path, path + ".err")
                    outcomes += 1
        if dirty:
            self._save_state()

    # ---------- receive path ----------
    def _handle_envelope(self, env):
        """Every envelope, whatever its type, takes this one path: shape,
        signature, local recipient, sender card, ONE decryption, then
        dispatch on type - an ack to _handle_ack (bound to the message it
        answers), everything else to the inbox and an ack back."""
        err = envelope.check_message_shape(env)
        if err:
            self.ledger.append("node:%s" % self.name, None, "msg.recv",
                               {"msg_id": env.get("msg_id") if envelope.safe_id(env.get("msg_id"), "msg") else None},
                               "rejected-malformed", "envelope refused: %s" % err)
            return
        if not envelope.verify_message(env):
            self.ledger.append("node:%s" % self.name, None, "msg.recv",
                               {"msg_id": env.get("msg_id")}, "rejected-bad-sig",
                               "bad envelope signature")
            return
        to_key = env["to"].split(":", 1)[-1]
        agent_name = None
        for n, a in self.agents.items():
            if a["card"]["agent_key"] == "ed25519:" + to_key:
                agent_name = n
                break
        if agent_name is None:
            self.ledger.append("node:%s" % self.name, None, "msg.recv",
                               {"msg_id": env["msg_id"], "to": to_key}, "undeliverable",
                               "no local agent for recipient key")
            return
        def resolve(fresh=False):
            # the hub away, or answering something this node refuses,
            # decides nothing about the envelope: handling is deferred and
            # the hub serves it again - it is never consumed on that
            try:
                return self._peer_card(env["from"], fresh=fresh)[1]
            except IdentityError:
                raise
            except Exception as e:
                if _lookup_failed(e):
                    raise HandlingDeferred(e)
                raise

        try:
            sender_fp = resolve()
        except IdentityError as e:
            self.ledger.append("node:%s" % self.name, None, "msg.recv",
                               {"msg_id": env["msg_id"], "from": env["from"]}, "rejected-bad-card",
                               "sender card not verified: %s" % e)
            return
        try:
            body = self._dec_pairwise(sender_fp, env["body"])
        except Exception as e:
            if _lookup_failed(e):
                # a fresh handshake needs the peer's prekey bundle: not
                # fetched or refused is a lookup failure, not a decryption
                # verdict. Only that: a session file this node cannot
                # write is local trouble and takes the generic boundary
                raise HandlingDeferred(e)
            # the sender may have moved to another node inside the
            # directory cache's lifetime: this ciphertext is then from the
            # new node's session. Re-resolve once, from the hub, and retry.
            try:
                fresh_fp = resolve(fresh=True)
            except IdentityError:
                fresh_fp = sender_fp
            if fresh_fp == sender_fp:
                self._decrypt_failed(env, agent_name, e)
                return
            try:
                body = self._dec_pairwise(fresh_fp, env["body"])
            except Exception as e2:
                if _lookup_failed(e2):
                    raise HandlingDeferred(e2)
                self._decrypt_failed(env, agent_name, e2)
                return
            sender_fp = fresh_fp  # the node this ciphertext really came from
        if not isinstance(body, dict):
            self.ledger.append("node:%s" % self.name, None, "msg.recv",
                               {"msg_id": env["msg_id"]}, "rejected-malformed", "body is not an object")
            return
        if env["type"] == "ack":
            self._handle_ack(env, body, sender_fp)
            return
        self._deliver_local(agent_name, env, body)
        self._ack(env, agent_name)

    @staticmethod
    def _check_group_key_body(body):
        """The first thing wrong with a group_key body, or None: a well-formed
        group id, a sender fingerprint, a sender-key state, a string name,
        and members that are objects naming an agent key (with grant ids
        as a list of identifiers when present)."""
        if not envelope.safe_id(body.get("group_id"), "grp"):
            return "group_id is not an identifier"
        if not envelope.safe_fp(body.get("sender_fp")):
            return "sender_fp is not a fingerprint"
        if not isinstance(body.get("group_name", ""), str):
            return "group_name is not a string"
        try:
            crypto.SenderKey.from_state(body.get("state"))
        except Exception:
            return "state is not a sender key"
        members = body.get("members")
        if not isinstance(members, list):
            return "members is not a list"
        for m in members:
            if not isinstance(m, dict) or not isinstance(m.get("agent_key"), str):
                return "a member does not name an agent key"
            try:
                envelope.key_bytes(m["agent_key"])
            except ValueError:
                return "a member's agent key is malformed"
            gids = m.get("grant_ids", [])
            if not isinstance(gids, list) or not all(envelope.safe_id(x, "grt") for x in gids):
                return "a member's grant ids are not identifiers"
        return None

    def _handle_group_key(self, agent_name, env, body):
        """Executor for group.join (reached only through _apply_grants):
        record the sender's key for the group and, on a first join,
        distribute this agent's own sender key to the other members."""
        gid = body.get("group_id")
        why = self._check_group_key_body(body)
        if why:
            # nothing is recorded and nothing queued for a body that is not
            # a complete group_key: the id names the group file, the state
            # must be a sender key, every member must be addressable
            self.ledger.append("agent:%s" % agent_name, None, "group.key",
                               {"msg_id": env["msg_id"]}, "rejected-malformed", why)
            return False
        with self._group_lock(gid):
            return self._handle_group_key_locked(agent_name, env, body)

    def _handle_group_key_locked(self, agent_name, env, body):
        gid = body["group_id"]
        sender_key = crypto.SenderKey.from_state(body["state"])
        first_join = self._group_reload(gid) is None
        changed = False
        if not first_join:
            # Member-add via redistribution: a group_key whose member list is
            # a STRICT SUPERSET of ours adopts it - the list is otherwise
            # frozen at join and there is no other add path (found in the
            # plane-test-1 soak: nmbp onboarded mid-group and existing
            # members never fanned out to it). Shrinks and rewrites are
            # ignored: a stale or hostile smaller list must never silently
            # drop members from our fan-out.
            g0 = self.groups[gid]
            body_keys = {m.get("agent_key") for m in body["members"]}
            local_keys = {m.get("agent_key") for m in g0.get("members", [])}
            if body_keys > local_keys:
                g0["members"] = body["members"]
                self._save_group(gid)
                self.ledger.append("agent:%s" % agent_name, None, "group.members",
                                   {"group_id": gid}, "updated",
                                   "members %d -> %d via redistribution" % (len(local_keys), len(body_keys)))
                changed = True
        # A re-delivered group_key (unacked retry, hub replay) carries the
        # sender's INITIAL ratchet state. Applying it rewinds our recv chain
        # and every newer group text then rejects as 'replayed/old'. Only
        # accept a key for a sender we have no state for - and a duplicate
        # changes nothing, so it is no join and spends no use.
        if not first_join and body["sender_fp"] in self.groups[gid]["_recv"]:
            self.ledger.append("agent:%s" % agent_name, None, "group.key",
                               {"msg_id": env.get("msg_id"), "sender": body.get("sender_fp")},
                               "ignored-duplicate", "already have recv key for this sender")
            return True if changed else "duplicate"  # a wider member list is a change; the same key alone is not
        if first_join:
            send = crypto.SenderKey()
            self.groups[gid] = {"group_id": gid, "name": body.get("group_name", ""),
                                "creator": body["sender_fp"], "members": body["members"],
                                "_send": send, "_recv": {}, "initial_state": send.state(),
                                "send_state": None, "recv_states": {}, "pending": []}
        self.groups[gid]["_recv"][body["sender_fp"]] = sender_key
        if first_join:
            # a joiner also speaks: MY sender key goes to the group from the
            # daemon's pending pass (bounded batches off one directory read
            # there; a lookup per member inside this handler would hold the
            # group lock through every hub timeout). The pending fan-out is
            # written in the same save as the receive key: a join is never
            # on disk half-done.
            g = self.groups[gid]
            my_key = "ed25519:" + crypto.b64e(crypto.sign_pub(self.agents[agent_name]["seed"]))
            g["pending"] = [{"agent": agent_name, "agent_key": m["agent_key"], "grant_ids": m.get("grant_ids") or []}
                            for m in g.get("members", []) if m["agent_key"].split(":")[-1] != my_key.split(":")[-1]]
        self._save_group(gid)
        self.ledger.append("agent:%s" % agent_name, None, "group.key",
                           {"msg_id": env.get("msg_id"), "sender": body.get("sender_fp")},
                           "ok", "installed recv key for sender %s" % body.get("sender_fp"))
        return True

    def _deliver_local(self, agent_name, env, body):
        kind = body.get("kind")
        if kind == "group_relay":
            wire = body["wire"]
            if not envelope.safe_id(wire.get("group_id"), "grp"):
                self.ledger.append("agent:%s" % agent_name, None, "group.recv",
                                   {"msg_id": env["msg_id"]}, "rejected-bad-id", "group_id is not an identifier")
                return
            g = self._group(wire["group_id"])
            if g is None:
                self.ledger.append("agent:%s" % agent_name, None, "group.recv",
                                   {"msg_id": env["msg_id"]}, "unknown-group", "no such group locally")
                return
            g2 = self.groups[wire["group_id"]]
            sk = g2["_recv"].get(wire.get("sender_fp"))
            if sk is None:
                self.ledger.append("agent:%s" % agent_name, None, "group.recv",
                                   {"msg_id": env["msg_id"]}, "no-sender-key", "missing sender key")
                return
            pt = sk.decrypt_at(wire["n"], crypto.b64d(wire["ct"]),
                               aad=b"nv1-grp:" + wire["group_id"].encode())
            body = jcs.loads(pt)
            self._save_group(wire["group_id"])
            kind = body.get("kind")
        outcome = "delivered"
        if env.get("grant_ids"):
            outcome = self._apply_grants(env, agent_name, body)
        # the inbox record is written once, after the verdict, and says
        # what became of the message: delivered (information), refused,
        # or acted:<action>
        filed = outcome if outcome.startswith("acted:") or outcome in ("delivered", "refused") else "refused"
        rec = {"msg_id": env["msg_id"], "ts": env["ts"], "from": env["from"],
               "agent": agent_name, "grant_ids": env.get("grant_ids", []), "body": body, "outcome": filed}
        ipath = os.path.join(self.home, "inbox", agent_name)
        os.makedirs(ipath, exist_ok=True)
        _w600(os.path.join(ipath, env["msg_id"] + ".json"), json.dumps(rec).encode())
        # the receive row names the first WELL-FORMED grant id, or none
        gids = [g for g in (env.get("grant_ids") or []) if envelope.safe_id(g, "grt")]
        self.ledger.append("agent:%s" % agent_name, gids[0] if gids else None,
                           "msg.recv", {"msg_id": env["msg_id"], "from": env["from"], "kind": kind},
                           outcome, "received %s from %s" % (kind, env["from"]))

    def _load_grant(self, gid):
        """The grant held locally under `gid`, or None. The file must carry
        the same grant_id as its name: accounting is under the signed id,
        never a path alias."""
        if not envelope.safe_id(gid, "grt"):
            return None
        gpath = os.path.join(self.home, "grants", gid + ".json")
        try:
            with open(gpath, "rb") as f:
                g = jcs.loads(f.read())
        except (OSError, ValueError, RecursionError):
            return None  # missing, unreadable or not strict JSON: not held; never an exception on the receive path
        if not isinstance(g, dict) or g.get("grant_id") != gid:
            return None
        return g

    def _grant_uses(self, gid, since=None, scope=None):
        """Executions ledgered under this grant: entries with outcome ok
        whose action is the executed one (never the grant.check rows), at
        or after `since` (epoch seconds) when given, under scope entry
        `scope` when given (an entry that recorded no scope counts for
        every scope). An execution under a delegation of this grant
        (a row whose `parent` is this id) spends this grant's budget too,
        against the parent scope entry the row names. Ledger timestamps
        are whole seconds, so a row is taken as up to one second later
        than written: a use never leaves a window early. The ledger is
        the one durable record of use, so accounting survives a lost
        state file; its per-grant index (rows filed under the grant they
        ran under and under the parent they spent) makes a check cost
        this grant's rows, not the lifetime ledger."""
        n = 0
        for e in self.ledger.rows_for_grant(gid):
            if e.get("outcome") != "ok" or e.get("action") == "grant.check":
                continue
            if e.get("grant_id") == gid:
                if scope is not None and "scope" in e and e["scope"] != scope:
                    continue
            elif e.get("parent") == gid:
                if scope is not None and "parent_scope" in e and e["parent_scope"] != scope:
                    continue
            else:
                continue
            if since is not None:
                try:
                    if envelope.parse_iso(e.get("ts")) + 1 <= since:
                        continue
                except ValueError:
                    pass  # a use whose age is unknown counts against every window: unknown never frees budget
            n += 1
        return n

    def _subject_card(self, grant):
        """The principal-signed card of a grant's subject: a local agent's
        when the key is here, else the directory's copy verified under the
        pinned roots. The card must be the one the grant names by hash and
        key. Raises IdentityError when it cannot be resolved (the check
        that needs it then fails closed)."""
        subj = grant.get("subject") if isinstance(grant.get("subject"), dict) else {}
        key = subj.get("key")
        if not isinstance(key, str) or not isinstance(subj.get("agent"), str):
            raise IdentityError("grant subject is malformed")
        card = None
        for a in self.agents.values():
            if a["card"].get("agent_key") == key:
                card = a["card"]
                break
        if card is None:
            try:
                card, _ = self._peer_card(key)
            except IdentityError:
                raise
            except Exception as e:  # the hub unreachable, a malformed directory: not resolvable now
                raise IdentityError("subject card not resolvable: %s" % e)
        elif not envelope.verify_card(card, self.principal_roots):
            # a local card is held to the same standard as one from the
            # directory: principal-signed under the pinned roots and unexpired
            raise IdentityError("subject card on file does not verify under the pinned roots")
        if envelope.obj_hash(card) != subj["agent"]:
            raise IdentityError("subject card on file is not the card the grant names")
        return card

    @staticmethod
    def _in_window(g, now):
        return envelope.parse_iso(g["not_before"]) <= now < envelope.parse_iso(g["expires_at"])

    def _apply_grants(self, env, agent_name, body):
        """Action path (spec 3, 4): the message asks for an action under the
        grants it lists. Each listed grant is checked in order - well
        formed and principal-signed, subject = the receiving agent (card
        hash AND key), executor = this node or that agent, a host-bound
        resource naming this node, scope covering action/resource/params, budget
        left (counted from the ledger) - and the FIRST grant that passes
        executes the action exactly once. Grants that fail are ledgered
        with the reason. v0 executes test.ping only; any other action is
        refused (spec 1: failure is shown)."""
        a = self.agents[agent_name]
        card = a["card"]
        action, resource, params = body.get("action"), body.get("resource"), body.get("params")
        if not isinstance(action, str) or not action or not isinstance(resource, str) or not isinstance(params, dict):
            self.ledger.append("agent:%s" % agent_name, None, "grant.check", {"msg_id": env["msg_id"]},
                               "malformed-action", "action, resource and params must be present and typed")
            return "information-only"
        try:
            jcs.canonicalize(params)  # what the ledger will hash: a NaN or an oversized number is refused here, not after state changed
        except (ValueError, TypeError):
            self.ledger.append("agent:%s" % agent_name, None, "grant.check", {"msg_id": env["msg_id"]},
                               "malformed-action", "params are not canonical JSON")
            return "information-only"
        seen_ids = set()
        for gid in env.get("grant_ids", []):
            # the id names the grant file: only the id grammar reaches a
            # path, and a grant is accounted under its own signed grant_id,
            # never under whatever alias the sender wrote
            if not envelope.safe_id(gid, "grt"):
                self.ledger.append("agent:%s" % agent_name, None, "grant.check",
                                   {"msg_id": env["msg_id"]}, "rejected-bad-id", "grant id is not an identifier")
                continue
            if gid in seen_ids:
                continue  # listed twice: one grant, one check, one use
            seen_ids.add(gid)
            g = self._load_grant(gid)
            if g is None:
                self.ledger.append("agent:%s" % agent_name, gid, "grant.check", {}, "unknown-grant",
                                   "grant %s not held locally under its own id" % gid)
                continue
            # issuer model (spec 3): receiver-principal iff the grant's
            # issuer also signs the receiving agent's card, i.e. IS this
            # node's own principal; any other pinned root is sender-side.
            # Whole canonical key references are compared, never a
            # prefix-stripped form.
            issuer = g.get("issuer") if isinstance(g.get("issuer"), dict) else {}
            issuer_model = ("receiver-principal" if issuer.get("key") == card.get("principal_key_ref")
                            else "sender-principal")
            # subject binding (spec 4 confused-deputy rule): hash AND key
            subj = g.get("subject") if isinstance(g.get("subject"), dict) else {}
            if subj.get("agent") != envelope.obj_hash(card) or subj.get("key") != card["agent_key"]:
                self.ledger.append("agent:%s" % agent_name, gid, "grant.check", {}, "wrong-subject",
                                   "grant subject is not the receiving agent - information only",
                                   issuer_model=issuer_model)
                continue
            # a delegated grant is verified against the parent it names,
            # which must be held here under its own id too
            try:
                parent = parent_card = None
                if isinstance(g.get("parent_grant"), str):
                    parent = self._load_grant(g["parent_grant"])
                if parent is not None:
                    envelope.check_grant_shape(parent)  # a malformed parent is refused before anything reads its fields
                    parent_card = self._subject_card(parent)
                envelope.verify_grant(g, self.principal_roots, subject_card=card, parent=parent,
                                      parent_subject_card=parent_card)
            except (envelope.GrantError, IdentityError) as e:
                self.ledger.append("agent:%s" % agent_name, gid, "grant.check", {}, "invalid", str(e),
                                   issuer_model=issuer_model)
                continue
            except Exception as e:
                # nothing a grant check raises may abort the message: the
                # grant is refused with the reason, the next grant is tried,
                # and the sender still gets its ack
                self.ledger.append("agent:%s" % agent_name, gid, "grant.check", {}, "error",
                                   "grant check failed: %s" % e, issuer_model=issuer_model)
                continue
            # audience: the executing node or the receiving agent (spec 3),
            # in the prefixed or the bare key form
            ek = str(g["audience"]["executor"]).split(":", 1)[-1]
            if ek not in (self.node_key.split(":", 1)[-1], card["agent_key"].split(":", 1)[-1]):
                self.ledger.append("agent:%s" % agent_name, gid, "grant.check", {}, "wrong-executor",
                                   "grant audience names a different executor", issuer_model=issuer_model)
                continue
            # the resource is an opaque label matched literally (spec 3);
            # one in the host:<node-key>:<name> form names a host, and that
            # host must be this node, so a host-bound grant is never
            # replayed against another machine that holds the same file
            parsed = envelope.parse_resource(resource)
            if parsed is not None and parsed[0] != self.node_key:
                self.ledger.append("agent:%s" % agent_name, gid, "grant.check", {"resource": resource},
                                   "wrong-host", "resource is bound to another host", issuer_model=issuer_model)
                continue
            covering = envelope.covering_entries(g, action, resource, params)
            if not covering:
                self.ledger.append("agent:%s" % agent_name, gid, "grant.check",
                                   {"action": action}, "out-of-scope", "refused",
                                   issuer_model=issuer_model)
                continue
            # the first covering entry that can run is the one charged, by
            # its own index (never a look-alike's): budget left in its own
            # window and, for a delegation, in the first parent entry it is
            # a subset of that still has budget (a spent parent entry does
            # not hide another that covers it); then the revocation check
            # for that entry - a feed unreadable past grace refuses an
            # entry without an offline allowance, and a later covering
            # entry whose allowance covers the copy's age may still run
            chosen = None
            why, why_outcome = "no covering entry with budget left", "exhausted"
            if "max_uses" in g:
                uses, budget = self._grant_uses(gid), g["max_uses"]
                candidates = list(covering) if uses < budget else []
                left = "%d/%d" % (uses + 1, budget)
                if not candidates:
                    why = "max_uses reached"
            else:
                candidates = []
                for scope_i, sc in covering:
                    w = sc["max_uses_per_window"]
                    uses, budget = self._grant_uses(gid, since=time.time() - w["window_s"], scope=scope_i), w["n"]
                    if uses < budget:
                        candidates.append((scope_i, sc))
                    else:
                        why = "%d uses in the last %ds" % (uses, w["window_s"])
            for scope_i, sc in candidates:
                if "max_uses" not in g:
                    w = sc["max_uses_per_window"]
                    left = "%d/%d per %ds" % (self._grant_uses(gid, since=time.time() - w["window_s"], scope=scope_i) + 1,
                                              w["n"], w["window_s"])
                # a delegation spends its parent's budget as well as its own,
                # so two children cannot multiply what the principal granted once
                parent_id = parent_i = None
                if parent is not None:
                    parent_id = parent["grant_id"]
                    containing = [i for i, psc in enumerate(parent["scope"]) if envelope.scope_entry_within(sc, psc)]
                    if not containing:
                        why, why_outcome = "no parent scope entry covers the delegated entry", "invalid"
                        continue
                    for i in containing:
                        if "max_uses" in parent:
                            p_uses, p_budget = self._grant_uses(parent_id), parent["max_uses"]
                            if p_uses < p_budget:
                                parent_i = i
                            else:
                                why, why_outcome = "parent grant %s max_uses reached (%d/%d)" % (parent_id, p_uses, p_budget), "exhausted"
                            break  # max_uses is the whole grant's budget: no entry has more
                        pw = parent["scope"][i]["max_uses_per_window"]
                        p_uses = self._grant_uses(parent_id, since=time.time() - pw["window_s"], scope=i)
                        if p_uses < pw["n"]:
                            parent_i = i
                            break
                        why, why_outcome = "parent grant %s: %d uses in the last %ds" % (parent_id, p_uses, pw["window_s"]), "exhausted"
                    if parent_i is None:
                        continue
                # revocation before every action (spec 6): the local feed plus
                # the feed the grant names, failing closed when unreadable
                # under this entry's offline allowance
                try:
                    self.revocations.check(g, card, sc, parent=parent, parent_card=parent_card)
                except FeedUnavailable as e:
                    why, why_outcome = str(e), "revoked"
                    continue  # another covering entry may carry an offline allowance
                except RevocationError as e:
                    why, why_outcome = str(e), "revoked"  # a revoked target, or an observation the disk refused: no entry runs
                    break
                except Exception as e:
                    why, why_outcome = "revocation check failed: %s" % e, "error"
                    break
                chosen = (scope_i, sc, parent_id, parent_i)
                break
            if chosen is None:
                self.ledger.append("agent:%s" % agent_name, gid, "grant.check", {}, why_outcome, why,
                                   issuer_model=issuer_model)
                continue
            scope_i, sc, parent_id, parent_i = chosen
            # the revocation check may have waited on a feed: the validity
            # windows are read again now, against the clock at execution
            now = time.time()
            if (not self._in_window(g, now) or not envelope.verify_card(card, self.principal_roots, now=now)
                    or (parent is not None and not self._in_window(parent, now))
                    or (parent_card is not None and not envelope.verify_card(parent_card, self.principal_roots, now=now))):
                self.ledger.append("agent:%s" % agent_name, gid, "grant.check", {}, "invalid",
                                   "grant, the receiving card, the parent or the parent's subject card left its validity window before execution",
                                   issuer_model=issuer_model)
                continue
            # the message's seen entry goes to disk before the action runs:
            # a crash between the two must not let the same msg_id, resent
            # with fresh ciphertext, execute again on the next start
            self._save_state()
            if action == "test.ping":
                self.ledger.append("agent:%s" % agent_name, gid, "test.ping", params, "ok", "pong (%s)" % left,
                                   scope=scope_i, parent=parent_id, parent_scope=parent_i, issuer_model=issuer_model)
                return "acted:test.ping"
            if action == "group.join":
                # the join resource is exactly this node's groups: a grant
                # for any other resource on this host covers no join
                if resource != "host:%s:groups" % self.node_key:
                    self.ledger.append("agent:%s" % agent_name, gid, "group.join", params, "wrong-resource",
                                       "group.join is only on host:<this node>:groups", issuer_model=issuer_model)
                    return "refused"
                if (body.get("kind") != "group_key" or body.get("group_id") != params.get("group_id")
                        or not envelope.safe_id(body.get("group_id"), "grp")):
                    self.ledger.append("agent:%s" % agent_name, gid, "group.join", params, "malformed",
                                       "group.join body does not name a well-formed group its params name", issuer_model=issuer_model)
                    return "refused"
                # the join runs first; the ok row (the use) is recorded only
                # for a join that happened, under the same accounting
                # metadata as every other execution
                joined = self._handle_group_key(agent_name, env, body)
                if joined == "duplicate":
                    self.ledger.append("agent:%s" % agent_name, gid, "group.join", params, "no-op",
                                       "already hold this sender's key for %s: nothing changed, no use spent" % params["group_id"], issuer_model=issuer_model)
                    return "delivered"
                if not joined:
                    return "refused"
                self.ledger.append("agent:%s" % agent_name, gid, "group.join", params, "ok",
                                   "joined %s (%s)" % (params["group_id"], left),
                                   scope=scope_i, parent=parent_id, parent_scope=parent_i, issuer_model=issuer_model)
                return "acted:group.join"
            self.ledger.append("agent:%s" % agent_name, gid, action, params, "unsupported",
                               "no v0 executor for action %s" % action, issuer_model=issuer_model)
            return "refused"
        return "information-only"

    def _decrypt_failed(self, env, agent_name, err):
        """A pairwise envelope this node cannot read right now. Ledger the
        failure and leave it unacked while it is young: sessions mid-repair
        can heal. Past DEFER_DECRYPT_TTL the failure is permanent - chains
        do not heal backward and the sender's own retries are long
        exhausted - so ack-and-drop: the sender and any app-level resend
        loop watching for the ack stop, and the drop is on the record.
        Age anchors on the envelope's signed ts, so a backlog predating
        this code drains on first sight instead of after another TTL."""
        now = time.time()
        mid = env.get("msg_id")
        reg = self.state.setdefault("dfail", {})
        rec = reg.get(mid)
        first = rec["first"] if rec else now
        try:
            ets = calendar.timegm(time.strptime(str(env.get("ts", "")),
                                                "%Y-%m-%dT%H:%M:%SZ"))
            if ets <= now + 60:
                first = min(first, ets)
        except (ValueError, TypeError, OverflowError):
            pass
        reg[mid] = {"first": first, "last": now, "err": _oclass(err)}
        if len(reg) > 5000:  # bound the register: oldest-first entries out
            for old_mid in sorted(reg, key=lambda m: reg[m]["first"])[:1000]:
                reg.pop(old_mid, None)
        if now - first <= DEFER_DECRYPT_TTL:
            self.ledger.append("node:%s" % self.name, None, "msg.recv",
                               {"msg_id": mid}, _oclass(err), "decrypt failed: %s" % err)
            self._save_state()
            return
        reg.pop(mid, None)
        self.ledger.append("agent:%s" % agent_name, None, "msg.recv",
                           {"msg_id": mid}, "terminal",
                           "undecryptable for >%ds: acked and dropped" % DEFER_DECRYPT_TTL)
        self._save_state()
        self._ack(env, agent_name)

    def _ack(self, env, agent_name):
        try:
            sender_key = env["from"]
            body = {"kind": "ack", "ack": env["msg_id"], "ledger_head": self.ledger.head()}
            self.queue_send(agent_name, sender_key, body, msg_type="ack", in_reply_to=env["msg_id"])
        except Exception as e:
            self.ledger.append("agent:%s" % agent_name, None, "ack.send",
                               {"msg_id": env["msg_id"]}, _oclass(e), str(e))

    def _handle_ack(self, env, body, sender_fp):
        """An ack (already verified and decrypted) clears an outstanding
        message only when it comes from the party that message was sent
        to: the ack's from = the message's to, the ack's to = the
        message's from, the sender's node = the node it was encrypted
        for, and in_reply_to (when present) = the message id."""
        mid = body.get("ack")
        if body.get("kind") != "ack" or not envelope.safe_id(mid, "msg"):
            self.ledger.append("node:%s" % self.name, None, "msg.ack",
                               {"msg_id": env["msg_id"]}, "rejected-malformed", "ack envelope without an ack body")
            return False
        rec = self.state["unacked"].get(mid)
        if rec is None:
            # A late ack met an empty unacked slot: the entry already
            # dead-lettered or was never ours. Ledger it (#48) so "peer never
            # answered" stays distinguishable from "answer arrived past the
            # deadline" when two ledgers are compared.
            self.ledger.append("node:%s" % self.name, None, "msg.ack-late",
                               {"msg_id": mid, "peer_head": body.get("ledger_head")}, "late",
                               "ack arrived with no unacked entry: %s" % mid)
            return False
        orig = rec["env"]
        if (orig["to"] != env["from"] or orig["from"] != env["to"] or rec.get("peer_fp") != sender_fp
                or (env.get("in_reply_to") is not None and env["in_reply_to"] != mid)):
            self.ledger.append("node:%s" % self.name, None, "msg.ack",
                               {"msg_id": mid, "from": env["from"]}, "rejected-wrong-party",
                               "ack for %s from a party it was not sent to" % mid)
            return False
        self.state["unacked"].pop(mid)
        self._save_state()
        s = self._session("to", sender_fp)
        if s and s.hs_pending and self._carries_handshake(orig, s.x3dh_ek):
            # only an ack for an envelope sent under THIS handshake proves
            # the peer holds this channel; an ack for a message from an
            # earlier, restarted channel (a terminal drop of something it
            # could never read) proves nothing about the current one
            s.hs_pending = False
            s.x3dh_ek = None
            self._save_session("to", sender_fp)
        self.ledger.append("node:%s" % self.name, None, "msg.ack",
                           {"msg_id": mid, "peer_head": body.get("ledger_head")}, "ok",
                           "acked %s" % mid)
        return True

    # ---------- retry engine (spec 4: retries at 2P, 4P, 8P) ----------
    def _retries(self):
        now = time.time()
        # Cap due retries per sweep and save state once at the end. The
        # sweep is sequential hub calls: an unacked backlog (dead peer,
        # hub outage) otherwise starves the flush and poll sides behind
        # minutes of retry POSTs - the same pathology FLUSH_BATCH caps on
        # the send side, and each dead-letter also rewrote the whole state
        # file. Break: 96's flush went dark ~20 min behind a ~27k unacked
        # sweep during the plane-test-1 soak, depth climbing the whole
        # time while the daemon looked "alive and clean".
        RETRY_BATCH = 100
        # Two backlog governors on top of the batch cap, from the 2026-09-08
        # post-wedge churn (96's unacked at ~60k and GROWING under live soak
        # traffic): the sweep is sequential hub POSTs, so at deep backlog the
        # per-step sweep time starves the poll side and acks arrive slower
        # than production adds - the table climbs although every entry in it
        # has a bounded lifetime. (1) Time-box the sweep: past the budget the
        # remaining due entries wait for the next step, so polling (and ack
        # intake) is never more than ~budget behind. (2) Depth-scaled
        # backoff: while the table is deep, due times stretch by depth /
        # BACKOFF_SCALE_DEPTH, so a 60k backlog retries each entry ~12x less
        # often - the flood's shadow drains at ack speed instead of
        # re-POSTing dead weight every few seconds.
        RETRY_SWEEP_BUDGET_S = 2.0
        BACKOFF_SCALE_DEPTH = 5000
        depth = len(self.state["unacked"])
        scale = max(1, depth // BACKOFF_SCALE_DEPTH)
        deadline = now + RETRY_SWEEP_BUDGET_S
        due = sorted((rec["next"], mid) for mid, rec in self.state["unacked"].items()
                     if now >= rec["next"])
        dirty = False
        for _, mid in due[:RETRY_BATCH]:
            if time.time() > deadline:
                break
            rec = self.state["unacked"].get(mid)
            if rec is None:
                continue
            rec["attempts"] += 1
            dirty = True
            if rec["attempts"] > 3:
                self.state["unacked"].pop(mid)
                self.ledger.append("node:%s" % self.name, None, "msg.undelivered",
                                   {"msg_id": mid}, "dead",
                                   "UNDELIVERED after 3 retries: %s (surface to principal)" % mid)
                continue
            try:
                self._hub_req("POST", "/v1/msg", json.dumps(rec["env"]).encode())
                rec["next"] = now + (2 ** rec["attempts"]) * P * scale
            except urllib.error.HTTPError as e:
                if e.code == 409:
                    # the recipient moved after this ciphertext was made:
                    # it can never be read where it is routed now
                    self.state["unacked"].pop(mid)
                    self.ledger.append("node:%s" % self.name, None, "msg.undelivered",
                                       {"msg_id": mid}, "dead",
                                       "UNDELIVERED: recipient moved to another node: %s (surface to principal)" % mid)
                    continue
                rec["next"] = now + (2 ** rec["attempts"]) * P * scale
                self.ledger.append("node:%s" % self.name, None, "msg.retry",
                                   {"msg_id": mid}, _oclass(e), str(e))
            except Exception as e:
                rec["next"] = now + (2 ** rec["attempts"]) * P * scale
        if dirty:
            self._save_state()

    # ---------- main loop ----------
    def run(self, once=False):
        self.start()
        while True:
            self.step()
            if once:
                return
            time.sleep(0.5)

    def start(self):
        """Lock the home, reconcile the hub cursor, publish and register."""
        # exclusive lock: two daemons on one home diverge session state
        import fcntl
        self._lockfd = open(os.path.join(self.home, "node.lock"), "w")
        try:
            fcntl.flock(self._lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise SystemExit("another natively node process holds %s - refusing to run" % self.home)
        # Hub switch: last_seq is hub-scoped. A different hub restarts its
        # sequence at 1, so a stale cursor would silently skip the whole
        # queue. Reset on hub change; unacked envelopes survive and re-send.
        if self.state.get("hub_url") != self.hub:
            self.state["hub_url"] = self.hub
            self.state["last_seq"] = 0
            self._save_state()
        # first registration through the same retrying path as every later
        # one: a hub that is down or refuses this second does not stop the
        # daemon, the next step tries again
        self._last_registered = set()
        self._last_reg_time = 0.0
        self._maybe_reregister()
        self.ledger.append("node:%s" % self.name, None, "node.start",
                           {"hub": self.hub, "fp": self.fp}, "ok",
                           "node %s (%s) online" % (self.name, self.fp))

    def stop(self):
        """Release the home lock (a later Node on this home may start)."""
        fd = getattr(self, "_lockfd", None)
        if fd is not None:
            fd.close()
            self._lockfd = None

    def step(self):
        """One pass: reload agents, flush the outbox, poll once, retry."""
        self._load_agents()  # hot-reload: agent-add must not need a daemon restart
        self._maybe_reregister()
        if not self._last_reg_time:
            return  # never registered with this hub yet: peers would refuse us, and the poll would 401
        self._retry_pending_group_keys()
        self._flush_outbox()
        try:
            after = self.state["last_seq"]
            _, b = self._hub_req("GET", "/v1/poll/%s?after=%d" % (self.fp, after),
                                 headers={"X-Natively-Auth": self._auth_token("poll", after=after)})
            d = jcs.loads(b)
            if not isinstance(d, dict) or not isinstance(d.get("messages", []), list):
                raise ValueError("bad poll response")
            for item in d.get("messages", []):
                if not isinstance(item, dict):
                    self.ledger.append("node:%s" % self.name, None, "msg.recv", {}, "rejected-malformed",
                                       "poll row is not an object")
                    continue
                env = item.get("env", item)  # tolerate legacy unwrapped rows
                seq = item.get("_seq", 0) if isinstance(item.get("_seq", 0), int) else 0
                if not isinstance(env, dict):
                    self.ledger.append("node:%s" % self.name, None, "msg.recv", {"seq": seq}, "rejected-malformed",
                                       "envelope is not an object")
                    self.state["last_seq"] = max(self.state["last_seq"], seq)
                    continue
                mid = env.get("msg_id")
                if not envelope.safe_id(mid, "msg"):
                    # a wire msg_id names the inbox file and the seen set:
                    # only the id grammar gets that far
                    self.ledger.append("node:%s" % self.name, None, "msg.recv",
                                       {"seq": seq}, "rejected-bad-id", "msg_id is not an identifier")
                    self.state["last_seq"] = max(self.state["last_seq"], seq)
                    continue
                if mid in self.state["seen"]:
                    self.state["last_seq"] = max(self.state["last_seq"], seq)
                    continue
                self.state["seen"].append(mid)
                if len(self.state["seen"]) > 5000:
                    self.state["seen"] = self.state["seen"][-5000:]
                try:
                    self._handle_envelope(env)
                except HandlingDeferred as e:
                    # the hub was away or refused while the sender's card
                    # or prekeys were looked up, before anything was
                    # decided or executed: the envelope is not seen and
                    # the cursor stays before it. The hub serves it again
                    # on the next poll; the rest of this page waits with
                    # it. A failure AFTER decryption or execution is not
                    # this class: it is ledgered below and the message
                    # stays seen, so nothing runs twice.
                    self.state["seen"].remove(mid)
                    self.ledger.append("node:%s" % self.name, None, "msg.recv",
                                       {"msg_id": mid}, "retry", "handling deferred, the next poll serves it again: %s" % e.args[0])
                    break
                except Exception as e:
                    # per-envelope boundary (#16): one poison message
                    # must never kill the loop or block the queue
                    self.ledger.append("node:%s" % self.name, None, "msg.recv",
                                       {"msg_id": mid}, _oclass(e), "handle failed: %s" % e)
                self.state["last_seq"] = max(self.state["last_seq"], seq)
            self._save_state()
        except (urllib.error.URLError, OSError, ValueError):
            # hub unreachable, or a poll response that is not the JSON
            # shape the hub speaks (a duplicate key, a non-object): the
            # next pass polls again; nothing in the queue is consumed
            pass
        self._retries()


def init_node(home, name, hub_url, principal_pub_b64):
    os.makedirs(home, exist_ok=True)
    _w600(os.path.join(home, "node.key"), crypto.gen_signing_key().hex().encode())
    _w600(os.path.join(home, "spk.key"), crypto.x_gen().hex().encode())
    _w600(os.path.join(home, "principal.pub"), principal_pub_b64.encode())
    json.dump({"name": name, "hub_url": hub_url, "enrolled_at": envelope.now_iso()},
              open(os.path.join(home, "config.json"), "w"), indent=2)
    n = Node(home)
    return n.fp


def add_agent(home, name, principal_seed: bytes, capabilities, ledger_url=""):
    n = Node(home)
    seed = crypto.gen_signing_key()
    card = envelope.make_card(seed, n.node_pub, principal_seed, capabilities,
                              ledger_url or "file://" + os.path.join(home, "ledger.jsonl"))
    adir = os.path.join(home, "agents")
    _w600(os.path.join(adir, name + ".key"), seed.hex().encode())
    _w600(os.path.join(adir, name + ".card.json"), json.dumps(card, indent=2).encode())
    return card["agent_key"]

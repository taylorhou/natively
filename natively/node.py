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
import urllib.parse
import urllib.request
import urllib.error
from . import crypto, envelope, jcs
from .ledger import Ledger

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


def _bare_key(k):
    """The bare base64 of an "ed25519:<b64>" agent key, or the string itself."""
    return k.split(":", 1)[1] if isinstance(k, str) and k.startswith("ed25519:") else k


def _diag(home, kind, fields):
    """Pass-timing rows, appended to diag.jsonl - deliberately NOT the
    chained ledger.jsonl: the ledger is the durable record of grant
    accounting and its rows are hash-chained, so telemetry has no place
    in it."""
    try:
        row = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "kind": kind}
        row.update(fields)
        with open(os.path.join(home, "diag.jsonl"), "a") as fh:
            fh.write(json.dumps(row, separators=(",", ":")) + "\n")
    except OSError:
        pass


def _fsize(p):
    try:
        return os.path.getsize(p)
    except OSError:
        return -1


def _w600(path, data: bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, data)
    os.close(fd)


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



class Node:
    FLUSH_BATCH = 800   # outcomes+dispatches per flush pass
    LIVE_WINDOW = 600   # newest eligible files sent first each pass
    DRAIN_SLICE = 200   # guaranteed oldest eligible slice per pass
    RECV_BATCH = 64     # inbound messages handled per step: the hub's poll
    # returns the whole waiting backlog with no page cap, and receive-path
    # work is ~0.3-0.6s per message (crypto + session save + ack + inbox
    # write) - an inbound flood otherwise monopolizes the loop for minutes
    # and the flush side starves (air, 2026-09-09: ms_poll 109-202s/step,
    # drain -23/min net against a 39k backlog)

    def __init__(self, home=None):
        self.home = home or home_dir()
        self.cfg = json.load(open(os.path.join(self.home, "config.json")))
        self.name = self.cfg["name"]
        self.hub = self.cfg["hub_url"].rstrip("/")
        self.node_seed = bytes.fromhex(open(os.path.join(self.home, "node.key")).read().strip())
        self.node_pub = crypto.sign_pub(self.node_seed)
        self.node_key = "ed25519:" + crypto.b64e(self.node_pub)
        self.fp = jcs.sha256(self.node_pub)[:32]
        self._hub_tls = threading.local()  # per-thread lazy _HubConn for hot paths (flush, poll, retry)
        self._backoff = {}     # outbox file -> (not before, delay): a send the hub asked to wait on (429)
        self._rcpt_backoff = {}  # bare recipient -> (not before, delay): the hub said THIS RECIPIENT's queue has
        # no room - every file to it waits, not only the one refused. Without it a capped recipient (a dead
        # node's queue at the hub's cap) re-costs one POST per file per backoff expiry, and under a deep
        # backlog that churn, not RTT, becomes the drain limiter (air, 2026-09-09).
        self._file_to = {}     # outbox file -> its bare recipient, learnt when the file is first read
        self._diag_save_ms = 0.0  # cumulative _save_state wall time, for pass timing
        self._file_kind = {}   # outbox file -> its body kind, learnt on first read (control ordering without re-reading 39k files per pass)
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
        _t = time.monotonic()
        tmp = self.state_path + ".tmp"
        json.dump(self.state, open(tmp, "w"))
        os.replace(tmp, self.state_path)
        self._diag_save_ms += (time.monotonic() - _t) * 1000.0

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
                seed = bytes.fromhex(open(os.path.join(adir, f)).read().strip())
                card = json.load(open(cpath))
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
            self.sessions[key] = s
            return s
        return None

    def _save_session(self, direction, peer_fp):
        s = self.sessions[direction + ":" + peer_fp]
        _w600(self._session_path(direction, peer_fp), json.dumps(s.to_state()).encode())

    def _group_lock(self, gid):
        """Serialize group-state read-modify-write across PROCESSES sharing
        this home. node-run and bot processes each cache group state in
        memory; without the lock every group_send rewrote the file from
        stale cache - wiping keys other processes had installed and
        forking the shared sender ratchet (receivers then rejected one
        writer's envelopes as replayed/old). Found in the plane-test-1
        soak: distributions installed at 06:18Z were gone from disk at
        06:22Z behind bot chatter."""
        return _GroupFileLock(self._group_path(gid) + ".lock")

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
        g = self.groups[gid]
        g["send_state"] = g["_send"].state() if g.get("_send") else None
        g["recv_states"] = {k: v.state() for k, v in g.get("_recv", {}).items()}
        _w600(self._group_path(gid), json.dumps({k: v for k, v in g.items() if not k.startswith("_")} | {"send_state": g["send_state"], "recv_states": g["recv_states"]}).encode())

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
        d = json.loads(b)
        if not isinstance(d, dict) or not isinstance(d.get("agents"), dict):
            raise ValueError("bad directory response")
        self._dir_cache = (time.time(), d)
        return d

    def _peer_card(self, agent_key, fresh=False):
        """Bind an agent key to a principal-signed card and the node it
        resides on. The hub is untrusted: its directory is only a lookup;
        the card's own signature, its principal (pinned root set), its
        agent_key and its node_key decide. Returns (card, node_fp).
        fresh=True skips the cached directory copy."""
        key = agent_key.split(":", 1)[1] if agent_key.startswith("ed25519:") else agent_key
        entry = None
        for fresh in ((True,) if fresh else (False, True)):
            # a miss in the cached copy is re-checked against the hub: a
            # peer that registered a moment ago is not an impostor
            for info in self._directory(fresh=fresh)["agents"].values():
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
        bundle = json.loads(b)
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
        root, ek = crypto.x3dh_initiator(self.node_seed, peer_spk_x)
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
        wire = json.loads(crypto.b64d(body_b64))
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
                self.sessions["from:" + peer_fp] = s2
                self._save_session("from", peer_fp)
                self.ledger.append("node:%s" % self.name, None, "session.heal",
                                   {"peer": peer_fp}, "ok",
                                   "adopted peer's re-attached x3dh handshake after decrypt failure")
                return json.loads(pt2)
            raise
        self._save_session("from", peer_fp)
        return json.loads(pt)

    # ---------- groups ----------
    def create_group(self, creator_agent, members, name=""):
        gid = envelope.new_id("grp")
        g = {"group_id": gid, "name": name, "creator": creator_agent,
             "members": members, "_send": crypto.SenderKey(), "_recv": {},
             "send_state": None, "recv_states": {}}
        self.groups[gid] = g
        self._save_group(gid)
        # distribute my sender key to each member node, pairwise-encrypted
        for m in members:
            self.queue_send(creator_agent, m["agent_key"], {
                "kind": "group_key", "group_id": gid, "group_name": name,
                "sender_fp": self.fp, "state": g["_send"].state(),
                "members": members,
            }, control=True)
        return gid

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
            if member_fp == self.fp:
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
                   inner_wire=None, msg_type="msg", to_node_fp=None, control=False):
        """Enqueue an outbound message. body_obj is plaintext JSON for pairwise
        (encrypted to recipient node); inner_wire carries pre-encrypted group
        payloads (node-encrypted wrapper only). control=True marks the envelope
        class=control (signed): the hub never evicts those under chatter
        pressure - use for group_key distributions and protocol control."""
        a = self.agents[from_agent]
        req = {"from_agent": from_agent, "to": to_agent_key_b64,
               "body_obj": body_obj, "grant_ids": grant_ids or [],
               "msg_type": msg_type, "queued_at": time.time()}
        if control:
            req["control"] = True
        if to_node_fp:
            req["to_node_fp"] = to_node_fp
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
        of one per message - per THREAD: flush lanes POST concurrently and
        one http.client connection is not thread-safe, so each lane keeps
        its own. Cold paths stay on _http/urllib."""
        conn = getattr(self._hub_tls, "conn", None)
        if conn is None:
            conn = self._hub_tls.conn = _HubConn(self.hub)
        return conn.request(method, path, body=body, headers=headers)

    FLUSH_WORKERS = 4  # parallel POST lanes in the send phase; a lane carries
    # whole recipient shards serially, so per-recipient order (key before
    # relay, backoff) is exactly what the sequential pass gave globally

    def _flush_outbox(self):
        _t0 = time.monotonic()
        _save0 = self._diag_save_ms
        dead = {}  # recipient -> permanent identity verdict, this pass
        unknown_rcpts = set()  # recipients already proven absent from the directory THIS PASS:
        # _peer_card re-checks a cached-directory miss against the hub (fresh fetch), so without
        # this set EVERY queued file to a pruned recipient costs one directory round trip per pass
        # - 200 ghost files in the drain slice meant 200 fetches x ~140ms ~= 28s of collect per
        # pass on air (2026-09-09), compounding with the 1s positive-cache TTL. A peer that
        # registers mid-pass is picked up next pass; the deferral path is unchanged.
        dirty = False  # state changed; saved once at pass end, not per send
        outcomes = 0
        # Cap outcomes per pass: during a deep backlog the pass must not
        # starve the poll side - inbound latency matters more than drain
        # speed, and the remaining files are picked up next pass.
        FLUSH_BATCH = self.FLUSH_BATCH
        # Two-phase order. Live traffic is the newest files; dead backlog is
        # the oldest. Newest-first alone would starve the drain whenever
        # arrivals fill the cap; oldest-first makes live sends queue behind
        # thousands of verdict marks. So: a live window of the newest
        # LIVE_WINDOW, then a guaranteed oldest slice of DRAIN_SLICE - live
        # latency wins the budget, the backlog drains at a steady floor.
        files = [f for f in sorted(os.listdir(self.outbox_dir)) if f.endswith(".json")]
        n_files = len(files)
        # Eligibility is decided BEFORE the windows are cut: a file the hub
        # asked to wait on (429, Retry-After), a recipient the hub refused
        # room for, and a relay whose key distribution is waiting all spend
        # none of this pass's budget - and a wedge of undrainable files can
        # never stall the oldest slice (air, 2026-09-09: the oldest 100
        # were all undrainable, so live traffic behind them starved).
        now = time.time()
        present = set(files)
        self._backoff = {f: v for f, v in self._backoff.items() if f in present}
        self._file_to = {f: v for f, v in self._file_to.items() if f in present}
        self._file_kind = {f: v for f, v in self._file_kind.items() if f in present}

        def _kind(f):
            # control ordering without re-reading a deep backlog every pass:
            # the kind is learnt once per file and cached for its lifetime
            if f.startswith("ctl_"):
                return "group_key"  # queue_send names control files ctl_
            if f not in self._file_kind:
                try:
                    with open(os.path.join(self.outbox_dir, f)) as fh:
                        self._file_kind[f] = json.load(fh).get("body_obj", {}).get("kind")
                except Exception:
                    self._file_kind[f] = None
            return self._file_kind[f]

        held_to = set()
        for f in files:
            if self._backoff.get(f, (0.0, 0.0))[0] > now and _kind(f) == "group_key":
                k = self._file_to.get(f)
                if k:
                    held_to.add(k)  # its relays wait behind the refused key
        files = [f for f in files if self._backoff.get(f, (0.0, 0.0))[0] <= now
                 and self._rcpt_backoff.get(self._file_to.get(f), (0.0,))[0] <= now
                 and not (self._file_to.get(f) in held_to and _kind(f) != "group_key")]
        order = files[-self.LIVE_WINDOW:][::-1] + files[:-self.LIVE_WINDOW][:self.DRAIN_SLICE]
        # Causal priority within the pass: a group_key distribution installs
        # the receive state later group_relay messages decrypt under. Pure
        # newest-first delivers a relay BEFORE its key when both were queued
        # together (group created, then immediately used) - the receiver
        # consumes the relay as unknown-group and the message is lost.
        # Distributions go first, stable within their recency order.
        order.sort(key=lambda f: 0 if _kind(f) == "group_key" else 1)
        n_eligible = len(files)
        _t1 = time.monotonic()
        # Collection phase (main thread): every per-file decision through
        # envelope build runs here single-threaded, exactly as the
        # sequential pass did. POST-ready files are sharded by bare
        # recipient: all of one recipient's files POST serially, in order,
        # on one lane, so a key distribution is never overtaken by a relay
        # that decrypts under it. Only the hub POST runs on the lanes: it is
        # the latency-bound part (~1 RTT per send with keep-alive - air
        # behind its NAT crossed the ~145/min ceiling on 2026-09-09), and
        # parallel lanes multiply it without any lane touching state.
        shards = {}
        shard_seq = []
        dispatched = 0
        for i, f in enumerate(order):
            if outcomes + dispatched >= FLUSH_BATCH:
                break
            if i and i % 200 == 0:
                self._maybe_reregister()
            path = os.path.join(self.outbox_dir, f)
            try:
                req = json.load(open(path))
                self._file_to[f] = _bare_key(req.get("to"))
                self._file_kind.setdefault(f, req.get("body_obj", {}).get("kind") if isinstance(req.get("body_obj"), dict) else None)
                if not req.get("control") and _bare_key(req.get("to")) in held_to:
                    continue  # its key distribution is waiting on the hub: this file waits behind it (no attempt spent)
                if self._rcpt_backoff.get(_bare_key(req.get("to")), (0.0,))[0] > now:
                    continue  # first read of a file to a refused recipient: it spends no budget either
                if req["to"] in unknown_rcpts:
                    raise IdentityUnknown("recipient absent from the directory (this pass)")
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
                    unknown_rcpts.add(req["to"])
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
                    ct_b64, a["seed"], grant_ids=req["grant_ids"],
                    msg_type=req["msg_type"], extra=extra)
                # POST-ready: queue on the recipient's shard lane. The lane
                # POSTs; _flush_apply records the outcome afterwards, on the
                # main thread, in per-recipient order.
                k = _bare_key(req["to"])
                if k not in shards:
                    shards[k] = []
                    shard_seq.append(k)
                shards[k].append((f, path, req, env, peer_fp))
                dispatched += 1
            except Exception as e:
                transient = isinstance(e, (urllib.error.URLError, TimeoutError, OSError, IdentityUnknown, RecipientMoved))
                if isinstance(e, urllib.error.HTTPError) and 400 <= e.code < 500 and e.code != 429:
                    transient = False  # 4xx is a permanent rejection, not a retry case - except 429, the hub asking for room
                if isinstance(e, urllib.error.HTTPError) and e.code == 429:
                    self._defer_429(f, req, e)
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
        _t2 = time.monotonic()
        _t3 = _t4 = _t2
        if shards:
            # Send phase: lanes POST their shards concurrently. A lane
            # reports (item, exception-or-None, deferred) per file, in shard
            # order; the main thread applies every outcome below, so all
            # ledger/state/backoff writes stay single-threaded and in
            # per-recipient order. A lane that dies strands its remaining
            # shards this pass: unposted files sit untouched on disk.
            seq = [shards[k] for k in shard_seq]
            nlanes = min(self.FLUSH_WORKERS, len(seq))
            results = [None] * len(seq)
            if nlanes <= 1:
                results[0] = self._flush_post_shard(seq[0])
            else:
                def _lane(wi):
                    for si in range(wi, len(seq), nlanes):
                        try:
                            results[si] = self._flush_post_shard(seq[si])
                        except Exception:
                            pass
                lanes = [threading.Thread(target=_lane, args=(wi,), daemon=True, name="flush-%d" % wi)
                         for wi in range(nlanes)]
                for t in lanes:
                    t.start()
                for t in lanes:
                    t.join()
            _t3 = time.monotonic()
            for shard_results in results:
                if not shard_results:
                    continue
                for item, exc, deferred in shard_results:
                    if deferred:
                        continue  # waits behind its key distribution, exactly as the held set held it
                    f, path, req, env, peer_fp = item
                    try:
                        o, d = self._flush_apply(f, path, req, env, peer_fp, exc)
                    except Exception:
                        o, d = 0, False  # a bookkeeping error leaves the file on disk: the next pass tries again
                    outcomes += o
                    dirty = dirty or d
            _t4 = time.monotonic()
        if dirty:
            self._save_state()
        _diag(self.home, "flush",
              {"files": n_files, "eligible": n_eligible, "order": len(order),
               "dispatched": dispatched, "outcomes": outcomes,
               "unacked": len(self.state["unacked"]),
               "deferred": len(self.state.get("deferred_since", {})),
               "state_bytes": _fsize(self.state_path),
               "ledger_bytes": _fsize(os.path.join(self.home, "ledger.jsonl")),
               "ms_setup": round((_t1 - _t0) * 1000),
               "ms_collect": round((_t2 - _t1) * 1000),
               "ms_send": round((_t3 - _t2) * 1000),
               "ms_apply": round((_t4 - _t3) * 1000),
               "ms_save": round(self._diag_save_ms - _save0)})

    def _defer_429(self, f, req, e):
        """The hub has no room for this recipient: wait what it says
        (Retry-After), doubling on every further refusal up to a minute.
        The refusal is a property of the recipient's hub queue, not of this
        file: every file to the recipient waits out the same verdict, so a
        capped recipient costs one probe per backoff, not one POST per file."""
        try:
            asked = float((e.headers or {}).get("Retry-After", 0) or 0)
        except (TypeError, ValueError):
            asked = 0.0
        prev = self._backoff.get(f, (0.0, 0.0))[1]
        delay = min(60.0, max(asked, prev * 2, float(P)))
        self._backoff[f] = (time.time() + delay, delay)
        rk = _bare_key(req.get("to"))
        rprev = self._rcpt_backoff.get(rk, (0.0, 0.0))[1]
        rdelay = min(60.0, max(asked, rprev * 2, float(P)))
        self._rcpt_backoff[rk] = (time.time() + rdelay, rdelay)
        self.ledger.append("node:%s" % self.name, None, "msg.send", {"file": f},
                           "retry", "send deferred %.0fs: %s" % (delay, e))

    def _flush_post_shard(self, items):
        """POST one recipient's files serially over the lane's own keep-alive
        connection (_hub_req is per-thread). Only the network call happens
        on the lane; every state mutation is applied afterwards by the main
        thread in _flush_apply, in this same order. A control envelope the
        hub refused room for (429) defers the rest of the shard: its relays
        must never overtake the key they decrypt under."""
        out = []
        deferred = False
        for item in items:
            f, path, req, env, peer_fp = item
            if deferred:
                out.append((item, None, True))
                continue
            try:
                self._hub_req("POST", "/v1/msg", json.dumps(env).encode())
                out.append((item, None, False))
            except urllib.error.HTTPError as e:
                out.append((item, e, False))
                if e.code == 429 and req.get("control"):
                    deferred = True
            except Exception as e:
                out.append((item, e, False))
        return out

    def _flush_apply(self, f, path, req, env, peer_fp, exc):
        """Main-thread bookkeeping for one posted send: exactly what the
        sequential pass did inline after its POST returned. Lanes POST and
        report; all state changes happen here. Returns (outcomes, dirty)
        for the pass counters."""
        outcomes = 0
        dirty = False
        if exc is None:
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
            self._rcpt_backoff.pop(_bare_key(req.get("to")), None)  # a send landed: the recipient's queue had room after all
            if self.state.get("deferred_since", {}).pop(f, None) is not None:
                dirty = True
            outcomes += 1
            return outcomes, dirty
        e = exc
        try:
            if isinstance(e, urllib.error.HTTPError) and e.code == 409:
                self._dir_cache = (0.0, None)
                raise RecipientMoved("recipient moved to another node; re-encrypting next pass")
            if isinstance(e, urllib.error.HTTPError) and e.code == 404:
                # the hub does not know the recipient right now (a
                # re-registration gap, or not registered yet): wait,
                # exactly as when the directory has no card for it
                self._dir_cache = (0.0, None)
                raise IdentityUnknown("recipient unknown to the hub")
            raise e
        except Exception as e:
            transient = isinstance(e, (urllib.error.URLError, TimeoutError, OSError, IdentityUnknown, RecipientMoved))
            if isinstance(e, urllib.error.HTTPError) and 400 <= e.code < 500 and e.code != 429:
                transient = False  # 4xx is a permanent rejection, not a retry case - except 429, the hub asking for room
            if isinstance(e, urllib.error.HTTPError) and e.code == 429:
                self._defer_429(f, req, e)
                return outcomes, dirty
            if transient and isinstance(e, IdentityUnknown):
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
        return outcomes, dirty

    # ---------- receive path ----------
    def _handle_envelope(self, env):
        if not envelope.safe_id(env.get("msg_id"), "msg"):
            self.ledger.append("node:%s" % self.name, None, "msg.recv", {}, "rejected-bad-id",
                               "msg_id is not an identifier")
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
        try:
            _, sender_fp = self._peer_card(env["from"])
        except IdentityError as e:
            self.ledger.append("node:%s" % self.name, None, "msg.recv",
                               {"msg_id": env["msg_id"], "from": env["from"]}, "rejected-bad-card",
                               "sender card not verified: %s" % e)
            return
        try:
            body = self._dec_pairwise(sender_fp, env["body"])
        except Exception as e:
            # the sender may have moved to another node inside the
            # directory cache's lifetime: this ciphertext is then from the
            # new node's session. Re-resolve once, from the hub, and retry.
            try:
                _, fresh_fp = self._peer_card(env["from"], fresh=True)
            except IdentityError:
                fresh_fp = sender_fp
            if fresh_fp == sender_fp:
                self._decrypt_failed(env, agent_name, e)
                return
            try:
                body = self._dec_pairwise(fresh_fp, env["body"])
            except Exception as e2:
                self._decrypt_failed(env, agent_name, e2)
                return
        kind = body.get("kind")
        if env.get("type") == "ack" and kind == "ack":
            # an ack read here (the preview in step() failed against the
            # cached node and the sender was re-resolved) clears its
            # message, it is never filed as a message of its own
            self._handle_ack(env, body)
            return
        if kind == "group_key":
            self._handle_group_key(agent_name, env, body, ack=True)
            return
        self._deliver_local(agent_name, env, body)
        self._ack(env, agent_name)

    def _handle_group_key(self, agent_name, env, body, ack=True):
        gid = body.get("group_id")
        if not envelope.safe_id(gid, "grp"):
            # a decrypted group_id names the group file: only the id grammar
            self.ledger.append("agent:%s" % agent_name, None, "group.key",
                               {"msg_id": env["msg_id"]}, "rejected-bad-id", "group_id is not an identifier")
            return
        with self._group_lock(gid):
            return self._handle_group_key_locked(agent_name, env, body, ack=ack)

    def _handle_group_key_locked(self, agent_name, env, body, ack=True):
        gid = body["group_id"]
        first_join = self._group_reload(gid) is None
        if first_join:
            self.groups[gid] = {"group_id": gid, "name": body.get("group_name", ""),
                                "creator": body.get("sender_fp"), "members": body.get("members", []),
                                "_send": crypto.SenderKey(), "_recv": {},
                                "send_state": None, "recv_states": {}}
        else:
            # Member-add via redistribution: a group_key whose member list is
            # a STRICT SUPERSET of ours adopts it - the list is otherwise
            # frozen at join and there is no other add path (found in the
            # plane-test-1 soak: nmbp onboarded mid-group and existing
            # members never fanned out to it). Shrinks and rewrites are
            # ignored: a stale or hostile smaller list must never silently
            # drop members from our fan-out.
            g0 = self.groups[gid]
            body_keys = {m.get("agent_key") for m in body.get("members", [])}
            local_keys = {m.get("agent_key") for m in g0.get("members", [])}
            if body_keys > local_keys:
                g0["members"] = body["members"]
                self._save_group(gid)
                self.ledger.append("agent:%s" % agent_name, None, "group.members",
                                   {"group_id": gid}, "updated",
                                   "members %d -> %d via redistribution" % (len(local_keys), len(body_keys)))
        # A re-delivered group_key (unacked retry, hub replay) carries the
        # sender's INITIAL ratchet state. Applying it rewinds our recv chain
        # and every newer group text then rejects as 'replayed/old'. Only
        # accept a key for a sender we have no state for.
        if body["sender_fp"] in self.groups[gid]["_recv"]:
            self.ledger.append("agent:%s" % agent_name, None, "group.key",
                               {"msg_id": env.get("msg_id"), "sender": body.get("sender_fp")},
                               "ignored-duplicate", "already have recv key for this sender")
        else:
            self.groups[gid]["_recv"][body["sender_fp"]] = crypto.SenderKey.from_state(body["state"])
            self._save_group(gid)
            self.ledger.append("agent:%s" % agent_name, None, "group.key",
                               {"msg_id": env.get("msg_id"), "sender": body.get("sender_fp")},
                               "ok", "installed recv key for sender %s" % body.get("sender_fp"))
        self.ledger.append("agent:%s" % agent_name, None, "group.join",
                           {"group_id": gid}, "ok", "joined group %s" % body.get("group_name", gid))
        if first_join:
            # a joiner also speaks: distribute MY sender key to the group
            g = self.groups[gid]
            my_key = "ed25519:" + crypto.b64e(crypto.sign_pub(self.agents[agent_name]["seed"]))
            for m in g.get("members", []):
                if m["agent_key"].split(":")[-1] == my_key.split(":")[-1]:
                    continue
                self.queue_send(agent_name, m["agent_key"], {
                    "kind": "group_key", "group_id": gid, "group_name": g.get("name", ""),
                    "sender_fp": self.fp, "state": g["_send"].state(),
                    "members": g.get("members", []),
                }, control=True)
        if ack:
            self._ack(env, agent_name)

    def _deliver_local(self, agent_name, env, body):
        kind = body.get("kind")
        if kind == "group_key":
            self._handle_group_key(agent_name, env, body, ack=False)
            return
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
            body = json.loads(pt)
            self._save_group(wire["group_id"])
            kind = body.get("kind")
        rec = {"msg_id": env["msg_id"], "ts": env["ts"], "from": env["from"],
               "agent": agent_name, "grant_ids": env.get("grant_ids", []), "body": body}
        ipath = os.path.join(self.home, "inbox", agent_name)
        os.makedirs(ipath, exist_ok=True)
        _w600(os.path.join(ipath, env["msg_id"] + ".json"), json.dumps(rec).encode())
        outcome = "delivered"
        if env.get("grant_ids"):
            outcome = self._apply_grants(env, agent_name, body)
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
        if not os.path.exists(gpath):
            return None
        try:
            g = json.load(open(gpath))
        except ValueError:
            return None
        if not isinstance(g, dict) or g.get("grant_id") != gid:
            return None
        return g

    def _grant_uses(self, gid, since=None, scope=None):
        """Executions ledgered under this grant: entries with outcome ok
        whose action is the executed one (never the grant.check rows), at
        or after `since` (epoch seconds) when given, under scope entry
        `scope` when given (an entry that recorded no scope counts for
        every scope). Ledger timestamps are whole seconds, so a row is
        taken as up to one second later than written: a use never leaves
        a window early. The ledger is the one durable record of use, so
        accounting survives a lost state file; its per-grant index makes
        a check cost this grant's rows, not the lifetime ledger."""
        n = 0
        for e in self.ledger.rows_for_grant(gid):
            if e.get("outcome") != "ok" or e.get("action") == "grant.check":
                continue
            if scope is not None and "scope" in e and e["scope"] != scope:
                continue
            if since is not None:
                try:
                    if envelope.parse_iso(e.get("ts")) + 1 <= since:
                        continue
                except ValueError:
                    pass  # a use whose age is unknown counts against every window: unknown never frees budget
            n += 1
        return n

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
            try:
                envelope.verify_grant(g, self.principal_roots, subject_card=card)
            except envelope.GrantError as e:
                self.ledger.append("agent:%s" % agent_name, gid, "grant.check", {}, "invalid", str(e),
                                   issuer_model=issuer_model)
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
            # the first covering entry with budget left is the one charged
            # (by its own index, never a look-alike's); an entry whose
            # window is spent does not hide a later entry that still covers
            chosen = None
            if "max_uses" in g:
                uses, budget = self._grant_uses(gid), g["max_uses"]
                if uses < budget:
                    chosen = covering[0]
                    left = "%d/%d" % (uses + 1, budget)
                else:
                    why = "max_uses reached"
            else:
                # a window belongs to its scope entry: uses under another
                # entry of the same grant do not count against it
                for scope_i, sc in covering:
                    w = sc["max_uses_per_window"]
                    uses, budget = self._grant_uses(gid, since=time.time() - w["window_s"], scope=scope_i), w["n"]
                    if uses < budget:
                        chosen = (scope_i, sc)
                        left = "%d/%d per %ds" % (uses + 1, budget, w["window_s"])
                        break
                    why = "%d uses in the last %ds" % (uses, w["window_s"])
            if chosen is None:
                self.ledger.append("agent:%s" % agent_name, gid, "grant.check", {}, "exhausted", why,
                                   issuer_model=issuer_model)
                continue
            scope_i, sc = chosen
            # the message's seen entry goes to disk before the action runs:
            # a crash between the two must not let the same msg_id, resent
            # with fresh ciphertext, execute again on the next start
            self._save_state()
            if action == "test.ping":
                self.ledger.append("agent:%s" % agent_name, gid, "test.ping", params, "ok", "pong (%s)" % left,
                                   scope=scope_i, issuer_model=issuer_model)
                return "acted:test.ping"
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
            self.queue_send(agent_name, sender_key, body, msg_type="ack")
        except Exception as e:
            self.ledger.append("agent:%s" % agent_name, None, "ack.send",
                               {"msg_id": env["msg_id"]}, _oclass(e), str(e))

    def _handle_ack(self, env, body):
        mid = body.get("ack")
        if mid in self.state["unacked"]:
            self.state["unacked"].pop(mid)
            self._save_state()
            try:
                _, peer_fp = self._peer_card(env["from"])
            except IdentityError:
                peer_fp = None
            if peer_fp:
                s = self._session("to", peer_fp)
                if s and s.hs_pending:
                    s.hs_pending = False
                    s.x3dh_ek = None
                    self._save_session("to", peer_fp)
            self.ledger.append("node:%s" % self.name, None, "msg.ack",
                               {"msg_id": mid, "peer_head": body.get("ledger_head")}, "ok",
                               "acked %s" % mid)
            return True
        # A late ack met an empty unacked slot: the entry already
        # dead-lettered or was never ours. Ledger it so "peer never
        # answered" stays distinguishable from "answer arrived past the
        # deadline" when two ledgers are compared.
        self.ledger.append("node:%s" % self.name, None, "msg.ack-late",
                           {"msg_id": mid, "peer_head": body.get("ledger_head")}, "late",
                           "ack arrived with no unacked entry: %s" % mid)
        return False

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
        due = sorted((rec["next"], mid) for mid, rec in self.state["unacked"].items()
                     if now >= rec["next"])
        dirty = False
        for _, mid in due[:RETRY_BATCH]:
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
                rec["next"] = now + (2 ** rec["attempts"]) * P
            except urllib.error.HTTPError as e:
                if e.code == 409:
                    # the recipient moved after this ciphertext was made:
                    # it can never be read where it is routed now
                    self.state["unacked"].pop(mid)
                    self.ledger.append("node:%s" % self.name, None, "msg.undelivered",
                                       {"msg_id": mid}, "dead",
                                       "UNDELIVERED: recipient moved to another node: %s (surface to principal)" % mid)
                    continue
                rec["next"] = now + (2 ** rec["attempts"]) * P
                self.ledger.append("node:%s" % self.name, None, "msg.retry",
                                   {"msg_id": mid}, _oclass(e), str(e))
            except Exception as e:
                rec["next"] = now + (2 ** rec["attempts"]) * P
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
        _s0 = time.monotonic()
        n_polled = -1
        self._load_agents()  # hot-reload: agent-add must not need a daemon restart
        self._maybe_reregister()
        if not self._last_reg_time:
            return  # never registered with this hub yet: peers would refuse us, and the poll would 401
        self._flush_outbox()
        _s1 = time.monotonic()
        try:
            after = self.state["last_seq"]
            _, b = self._hub_req("GET", "/v1/poll/%s?after=%d&limit=%d" % (self.fp, after, self.RECV_BATCH),
                                 headers={"X-Natively-Auth": self._auth_token("poll", after=after)})
            d = json.loads(b)
            _s1a = time.monotonic()
            batch = d.get("messages", [])
            n_polled = len(batch)
            # Handle at most RECV_BATCH per step; the hub prunes only at the
            # cursor, so the unhandled tail (seq > last_seq after the slice)
            # stays queued and comes back on the next poll.
            for item in batch[:self.RECV_BATCH]:
                env = item.get("env", item)  # tolerate legacy unwrapped rows
                seq = item.get("_seq", 0)
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
                body_preview = None
                if env.get("type") == "ack":
                    try:
                        _, sender_fp = self._peer_card(env["from"])
                        body_preview = self._dec_pairwise(sender_fp, env["body"])
                    except Exception:
                        body_preview = None
                    try:
                        if body_preview and body_preview.get("kind") == "ack":
                            self._handle_ack(env, body_preview)
                        else:
                            self._handle_envelope(env)
                    except Exception as e:
                        # per-envelope boundary (#16): one poison message
                        # must never kill the loop or block the queue
                        self.ledger.append("node:%s" % self.name, None, "msg.recv",
                                           {"msg_id": mid}, _oclass(e), "handle failed: %s" % e)
                else:
                    try:
                        self._handle_envelope(env)
                    except Exception as e:
                        self.ledger.append("node:%s" % self.name, None, "msg.recv",
                                           {"msg_id": mid}, _oclass(e), "handle failed: %s" % e)
                self.state["last_seq"] = max(self.state["last_seq"], seq)
            self._save_state()
        except (urllib.error.URLError, OSError) as e:
            pass
        _s2 = time.monotonic()
        self._retries()
        _diag(self.home, "step",
              {"ms_flush": round((_s1 - _s0) * 1000),
               "ms_poll": round((_s2 - _s1) * 1000),
               "ms_poll_fetch": round((_s1a - _s1) * 1000) if n_polled >= 0 else -1,
               "ms_poll_handle": round((_s2 - _s1a) * 1000) if n_polled >= 0 else -1,
               "ms_retry": round((time.monotonic() - _s2) * 1000),
               "polled": n_polled, "handled": min(n_polled, self.RECV_BATCH) if n_polled >= 0 else -1})


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

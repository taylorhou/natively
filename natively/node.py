"""Natively node daemon (spec 8): enrollment, agent registry, transport poll
loop, envelope verification, e2e sessions (spec 9), ledger (spec 5).

Sessions are node-to-node (relays/hubs never see plaintext); agent identity
and authority ride inside as signed envelopes + cards + grants. A node runs
per machine; agents are local processes using the CLI.
"""
import json
import os
import time
import threading
import urllib.request
import urllib.error
from . import crypto, envelope, jcs
from .ledger import Ledger

P = 5  # poll interval seconds (spec 4 sizing: ack_deadline 2P+jitter, retries 2P/4P/8P)


def home_dir() -> str:
    return os.environ.get("NATIVELY_HOME", os.path.expanduser("~/.natively"))


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


class Node:
    def __init__(self, home=None):
        self.home = home or home_dir()
        self.cfg = json.load(open(os.path.join(self.home, "config.json")))
        self.name = self.cfg["name"]
        self.hub = self.cfg["hub_url"].rstrip("/")
        self.node_seed = bytes.fromhex(open(os.path.join(self.home, "node.key")).read().strip())
        self.node_pub = crypto.sign_pub(self.node_seed)
        self.fp = jcs.sha256(self.node_pub)[:32]
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
        return {"last_seq": 0, "unacked": {}, "grant_uses": {}, "seen": []}

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
                seed = bytes.fromhex(open(os.path.join(adir, f)).read().strip())
                card = json.load(open(cpath))
                agents[name] = {"seed": seed, "card": card}
        self.agents = agents

    def _session_path(self, direction, peer_fp):
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

    def _group_path(self, gid):
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
            ref = card.get("principal_key_ref", "")
            if not isinstance(ref, str) or ref.split(":", 1)[-1] not in self.principal_roots:
                raise IdentityError("card principal not in the pinned root set")
            if not envelope.verify_card(card, ref.split(":", 1)[-1]):
                raise IdentityError("card signature invalid or card expired")
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

    def _session_for_recv(self, peer_fp, x3dh_ek_b64, dh_hdr):
        s = self._session("from", peer_fp)
        if s is None:
            if not x3dh_ek_b64:
                raise ValueError("no session and no x3dh ek")
            bundle = self._prekey_bundle(peer_fp)
            peer_node_pub = crypto.b64d(bundle["node_key"].split(":", 1)[1])
            root = crypto.x3dh_responder(self.node_seed, self.spk_sk,
                                         crypto.ed_pk_to_x(peer_node_pub),
                                         crypto.b64d(x3dh_ek_b64))
            s = crypto.DRSession.init_responder(root, self.spk_sk)
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
            })
        return gid

    def group_send(self, from_agent, gid, body_obj):
        g = self._group(gid)
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
                self._peer_card(m["agent_key"])
            except IdentityUnknown:
                pass
            except IdentityError as e:
                self.ledger.append("agent:%s" % from_agent, None, "group.send",
                                   {"group_id": gid, "member": m["agent_key"]},
                                   "member-skipped", "member skipped: %s" % e)
                continue
            self.queue_send(from_agent, m["agent_key"], {
                "kind": "group_relay", "wire": wire, "group_id": gid,
            }, inner_wire=wire)
        self._save_group(gid)

    # ---------- send path ----------
    def queue_send(self, from_agent, to_agent_key_b64, body_obj, grant_ids=None,
                   inner_wire=None, msg_type="msg", to_node_fp=None):
        """Enqueue an outbound message. body_obj is plaintext JSON for pairwise
        (encrypted to recipient node); inner_wire carries pre-encrypted group
        payloads (node-encrypted wrapper only)."""
        a = self.agents[from_agent]
        req = {"from_agent": from_agent, "to": to_agent_key_b64,
               "body_obj": body_obj, "grant_ids": grant_ids or [],
               "msg_type": msg_type, "queued_at": time.time()}
        if to_node_fp:
            req["to_node_fp"] = to_node_fp
        fn = os.path.join(self.outbox_dir, envelope.new_id("out") + ".json")
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

    def _flush_outbox(self):
        dead = {}  # recipient -> permanent identity verdict, this pass
        dirty = False  # state changed; saved once at pass end, not per send
        outcomes = 0
        # Cap outcomes per pass: during a deep backlog the pass must not
        # starve the poll side - inbound latency matters more than drain
        # speed, and the remaining files are picked up next pass.
        FLUSH_BATCH = 400
        for i, f in enumerate(sorted(os.listdir(self.outbox_dir))):
            if outcomes >= FLUSH_BATCH:
                break
            if i and i % 200 == 0:
                self._maybe_reregister()
            if not f.endswith(".json"):
                continue
            path = os.path.join(self.outbox_dir, f)
            try:
                req = json.load(open(path))
                if req["to"] in dead:
                    # a recipient already found permanently undeliverable in
                    # this pass (e.g. card principal not in the pinned root
                    # set): the verdict is deterministic, so every queued
                    # envelope to it is dead on arrival. Mark without
                    # re-resolving - a dead-fanout backlog drains in one pass.
                    self.ledger.append("node:%s" % self.name, None, "msg.send", {"file": f},
                                       "error", "send failed: recipient identity: %s (same-pass verdict)" % dead[req["to"]])
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
                ct_b64 = self._enc_pairwise(peer_fp, req["body_obj"])
                # to_node: the node this ciphertext is for. The hub refuses
                # (409) when the recipient now lives elsewhere, so a card
                # cached across a move never strands a message on the
                # wrong node; the sender refreshes and re-encrypts.
                env = envelope.make_message(
                    a["card"]["agent_key"].split(":", 1)[1], req["to"].split(":", 1)[-1],
                    ct_b64, a["seed"], grant_ids=req["grant_ids"],
                    msg_type=req["msg_type"], extra={"to": req["to"] if req["to"].startswith("ed25519:") else "ed25519:" + req["to"],
                                                     "to_node": peer_fp})
                try:
                    _http("POST", "%s/v1/msg" % self.hub, json.dumps(env).encode())
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
                self.state["unacked"][env["msg_id"]] = {
                    "env": env, "attempts": 1, "next": time.time() + 2 * P,
                    "peer_fp": peer_fp}
                dirty = True  # saved once at pass end; a crash costs at most a duplicate send, and apply is idempotent on msg_id
                self.ledger.append("agent:%s" % req["from_agent"], req["grant_ids"][0] if req["grant_ids"] else None,
                                   "msg.send", {"to": req["to"], "msg_id": env["msg_id"]}, "queued",
                                   "sent %s to %s" % (req["body_obj"].get("kind", "msg"), req["to"]))
                os.unlink(path)
                outcomes += 1
            except Exception as e:
                transient = isinstance(e, (urllib.error.URLError, TimeoutError, OSError, IdentityUnknown, RecipientMoved))
                if isinstance(e, urllib.error.HTTPError) and 400 <= e.code < 500:
                    transient = False  # 4xx is a permanent rejection, not a retry case
                if transient:
                    # hub down / network blip: leave in outbox, retry next pass
                    self.ledger.append("node:%s" % self.name, None, "msg.send", {"file": f},
                                       "retry", "send deferred: %s" % e)
                else:
                    self.ledger.append("node:%s" % self.name, None, "msg.send", {"file": f},
                                       "error", "send failed: %s" % e)
                    os.rename(path, path + ".err")
                    outcomes += 1
        if dirty:
            self._save_state()

    # ---------- receive path ----------
    def _handle_envelope(self, env):
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
                self.ledger.append("node:%s" % self.name, None, "msg.recv",
                                   {"msg_id": env["msg_id"]}, "error", "decrypt failed: %s" % e)
                return
            try:
                body = self._dec_pairwise(fresh_fp, env["body"])
            except Exception as e2:
                self.ledger.append("node:%s" % self.name, None, "msg.recv",
                                   {"msg_id": env["msg_id"]}, "error", "decrypt failed: %s" % e2)
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
        gid = body["group_id"]
        first_join = self._group(gid) is None
        if first_join:
            self.groups[gid] = {"group_id": gid, "name": body.get("group_name", ""),
                                "creator": body.get("sender_fp"), "members": body.get("members", []),
                                "_send": crypto.SenderKey(), "_recv": {},
                                "send_state": None, "recv_states": {}}
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
                })
        if ack:
            self._ack(env, agent_name)

    def _deliver_local(self, agent_name, env, body):
        kind = body.get("kind")
        if kind == "group_key":
            self._handle_group_key(agent_name, env, body, ack=False)
            return
        if kind == "group_relay":
            wire = body["wire"]
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
        self.ledger.append("agent:%s" % agent_name, (env.get("grant_ids") or [None])[0],
                           "msg.recv", {"msg_id": env["msg_id"], "from": env["from"], "kind": kind},
                           outcome, "received %s from %s" % (kind, env["from"]))

    def _apply_grants(self, env, agent_name, body):
        """Action path: a message with grant_ids asks for an action. v0
        supports test.ping only; everything else refuses (spec 1: failure
        is shown)."""
        acted = "information-only"
        for gid in env.get("grant_ids", []):
            gpath = os.path.join(self.home, "grants", gid + ".json")
            if not os.path.exists(gpath):
                self.ledger.append("agent:%s" % agent_name, gid, "grant.check", {}, "unknown-grant",
                                   "grant %s not held locally" % gid)
                continue
            g = json.load(open(gpath))
            try:
                # a grant counts when its issuer is any pinned root (own
                # principal.pub or an installed principals/<name>.pub) -
                # the cross-principal exchange case; verify against the
                # issuer named in the grant, never a fixed local key
                ik = g.get("issuer", {}).get("key", "").split(":", 1)[-1]
                if ik not in self.principal_roots:
                    raise envelope.GrantError("grant issuer not in the pinned root set")
                envelope.verify_grant(g, ik)
            except Exception as e:
                self.ledger.append("agent:%s" % agent_name, gid, "grant.check", {}, "invalid", str(e))
                continue
            # subject binding (spec 4 confused-deputy rule)
            subj_card = None
            for n, a in self.agents.items():
                if envelope.obj_hash(a["card"]) == g["subject"]["agent"]:
                    subj_card = (n, a)
                    break
            if subj_card is None or subj_card[0] != agent_name:
                self.ledger.append("agent:%s" % agent_name, gid, "grant.check", {}, "wrong-subject",
                                   "grant subject is not the receiving agent - information only")
                continue
            action = body.get("action")
            resource = body.get("resource", "")
            params = body.get("params", {})
            if not envelope.grant_covers(g, action, resource, params):
                self.ledger.append("agent:%s" % agent_name, gid, "grant.check",
                                   {"action": action}, "out-of-scope", "refused")
                continue
            uses = self.state["grant_uses"].get(gid, 0)
            if "max_uses" in g and uses >= g["max_uses"]:
                self.ledger.append("agent:%s" % agent_name, gid, "grant.check", {}, "exhausted", "max_uses reached")
                continue
            if action == "test.ping":
                self.state["grant_uses"][gid] = uses + 1
                self._save_state()
                self.ledger.append("agent:%s" % agent_name, gid, "test.ping", params, "ok",
                                   "pong (%d/%s)" % (uses + 1, g.get("max_uses", "-")))
                acted = "acted:test.ping"
            else:
                self.ledger.append("agent:%s" % agent_name, gid, action, params, "unsupported",
                                   "no v0 executor for action %s" % action)
        return acted

    def _ack(self, env, agent_name):
        try:
            sender_key = env["from"]
            body = {"kind": "ack", "ack": env["msg_id"], "ledger_head": self.ledger.head()}
            self.queue_send(agent_name, sender_key, body, msg_type="ack")
        except Exception as e:
            self.ledger.append("agent:%s" % agent_name, None, "ack.send",
                               {"msg_id": env["msg_id"]}, "error", str(e))

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
        return False

    # ---------- retry engine (spec 4: retries at 2P, 4P, 8P) ----------
    def _retries(self):
        now = time.time()
        for mid, rec in list(self.state["unacked"].items()):
            if now < rec["next"]:
                continue
            rec["attempts"] += 1
            if rec["attempts"] > 3:
                self.state["unacked"].pop(mid)
                self._save_state()
                self.ledger.append("node:%s" % self.name, None, "msg.undelivered",
                                   {"msg_id": mid}, "dead",
                                   "UNDELIVERED after 3 retries: %s (surface to principal)" % mid)
                continue
            try:
                _http("POST", "%s/v1/msg" % self.hub, json.dumps(rec["env"]).encode())
                rec["next"] = now + (2 ** rec["attempts"]) * P
            except urllib.error.HTTPError as e:
                if e.code == 409:
                    # the recipient moved after this ciphertext was made:
                    # it can never be read where it is routed now
                    self.state["unacked"].pop(mid)
                    self._save_state()
                    self.ledger.append("node:%s" % self.name, None, "msg.undelivered",
                                       {"msg_id": mid}, "dead",
                                       "UNDELIVERED: recipient moved to another node: %s (surface to principal)" % mid)
                    continue
                rec["next"] = now + (2 ** rec["attempts"]) * P
                self.ledger.append("node:%s" % self.name, None, "msg.retry",
                                   {"msg_id": mid}, "error", str(e))
            except Exception as e:
                rec["next"] = now + (2 ** rec["attempts"]) * P
                self.ledger.append("node:%s" % self.name, None, "msg.retry",
                                   {"msg_id": mid}, "error", str(e))
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
        self._flush_outbox()
        try:
            after = self.state["last_seq"]
            _, b = _http("GET", "%s/v1/poll/%s?after=%d" % (self.hub, self.fp, after),
                         headers={"X-Natively-Auth": self._auth_token("poll", after=after)})
            d = json.loads(b)
            for item in d.get("messages", []):
                env = item.get("env", item)  # tolerate legacy unwrapped rows
                seq = item.get("_seq", 0)
                mid = env.get("msg_id")
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
                                           {"msg_id": mid}, "error", "handle failed: %s" % e)
                else:
                    try:
                        self._handle_envelope(env)
                    except Exception as e:
                        self.ledger.append("node:%s" % self.name, None, "msg.recv",
                                           {"msg_id": mid}, "error", "handle failed: %s" % e)
                self.state["last_seq"] = max(self.state["last_seq"], seq)
            self._save_state()
        except (urllib.error.URLError, OSError) as e:
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

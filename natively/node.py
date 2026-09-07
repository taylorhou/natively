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


def _http(method, url, body=None, timeout=35, ctype="application/json"):
    req = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", ctype)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


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
        self.principal_pub = open(os.path.join(self.home, "principal.pub")).read().strip()
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
        for f in os.listdir(adir):
            if f.endswith(".key"):
                name = f[:-4]
                seed = bytes.fromhex(open(os.path.join(adir, f)).read().strip())
                card = json.load(open(os.path.join(adir, name + ".card.json")))
                self.agents[name] = {"seed": seed, "card": card}

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
        reg = {
            "node_key": "ed25519:" + crypto.b64e(self.node_pub),
            "name": self.name,
            "agents": [{"name": n, "agent_key": a["card"]["agent_key"], "card": a["card"]}
                       for n, a in self.agents.items()],
        }
        reg = envelope.sign_obj(reg, self.node_seed)
        _http("POST", "%s/v1/register" % self.hub, json.dumps(reg).encode())

    # ---------- pairwise sessions (node-to-node) ----------
    # Directional channels (v0): each node initiates its OWN send channel to a
    # peer (X3DH initiator role) and keeps a separate responder channel for the
    # peer's initiated channel. Simultaneous initiation is then a non-event.
    # Within a channel the DH ratchet is static after setup; forward secrecy
    # comes from the symmetric chain, and channel re-init rotates DH roots.
    def _session_for_send(self, peer_fp):
        s = self._session("to", peer_fp)
        if s and s.send_chain is not None:
            return s, None
        _, b = _http("GET", "%s/v1/prekey/%s" % (self.hub, peer_fp))
        bundle = json.loads(b)
        peer_spk_x = crypto.b64d(bundle["spk_x"])
        peer_node_pub = crypto.b64d(bundle["node_key"].split(":", 1)[1])
        if not crypto.verify(peer_node_pub, peer_spk_x, crypto.b64d(bundle["spk_sig"])):
            raise ValueError("peer prekey sig invalid")
        root, ek = crypto.x3dh_initiator(self.node_seed, peer_spk_x)
        s = crypto.DRSession.init_initiator(root, peer_spk_x)
        self.sessions["to:" + peer_fp] = s
        self._save_session("to", peer_fp)
        return s, ek  # ek travels with first ciphertext

    def _session_for_recv(self, peer_fp, x3dh_ek_b64, dh_hdr):
        s = self._session("from", peer_fp)
        if s is None:
            if not x3dh_ek_b64:
                raise ValueError("no session and no x3dh ek")
            _, b = _http("GET", "%s/v1/prekey/%s" % (self.hub, peer_fp))
            bundle = json.loads(b)
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
        pt = s.decrypt(wire["dh"], crypto.b64d(wire["ct"]), aad=b"nv1-msg")
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

    def _resolve_node(self, agent_key_b64):
        _, b = _http("GET", "%s/v1/directory" % self.hub)
        d = json.loads(b)
        for _, info in d["agents"].items():
            if info["agent_key"] == agent_key_b64 or info["agent_key"] == "ed25519:" + agent_key_b64:
                return info["node_fp"]
        return None

    def _flush_outbox(self):
        for f in sorted(os.listdir(self.outbox_dir)):
            if not f.endswith(".json"):
                continue
            path = os.path.join(self.outbox_dir, f)
            try:
                req = json.load(open(path))
                a = self.agents[req["from_agent"]]
                peer_fp = req.get("to_node_fp") or self._resolve_node(req["to"])
                if not peer_fp:
                    raise ValueError("recipient not in directory")
                ct_b64 = self._enc_pairwise(peer_fp, req["body_obj"])
                env = envelope.make_message(
                    a["card"]["agent_key"].split(":", 1)[1], req["to"].split(":", 1)[-1],
                    ct_b64, a["seed"], grant_ids=req["grant_ids"],
                    msg_type=req["msg_type"], extra={"to": req["to"] if req["to"].startswith("ed25519:") else "ed25519:" + req["to"]})
                _http("POST", "%s/v1/msg" % self.hub, json.dumps(env).encode())
                self.state["unacked"][env["msg_id"]] = {
                    "env": env, "attempts": 1, "next": time.time() + 2 * P,
                    "peer_fp": peer_fp}
                self._save_state()
                self.ledger.append("agent:%s" % req["from_agent"], req["grant_ids"][0] if req["grant_ids"] else None,
                                   "msg.send", {"to": req["to"], "msg_id": env["msg_id"]}, "queued",
                                   "sent %s to %s" % (req["body_obj"].get("kind", "msg"), req["to"]))
                os.unlink(path)
            except Exception as e:
                self.ledger.append("node:%s" % self.name, None, "msg.send", {"file": f},
                                   "error", "send failed: %s" % e)
                os.rename(path, path + ".err")

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
        sender_fp = self._resolve_node_by_key(env["from"].split(":", 1)[1]) or "unknown"
        try:
            body = self._dec_pairwise(sender_fp, env["body"])
        except Exception as e:
            self.ledger.append("node:%s" % self.name, None, "msg.recv",
                               {"msg_id": env["msg_id"]}, "error", "decrypt failed: %s" % e)
            return
        kind = body.get("kind")
        if kind == "group_relay":
            wire = body["wire"]
            g = self._group(wire["group_id"])
            if g is None:
                self.ledger.append("agent:%s" % agent_name, None, "group.recv",
                                   {"msg_id": env["msg_id"]}, "unknown-group", "no such group locally")
                return
            sender_node_fp = wire.get("sender_fp") or body.get("sender_fp") or sender_fp
            g2 = self.groups[wire["group_id"]]
            sk = g2["_recv"].get(sender_node_fp)
            if sk is None:
                self.ledger.append("agent:%s" % agent_name, None, "group.recv",
                                   {"msg_id": env["msg_id"]}, "no-sender-key", "missing sender key")
                return
            pt = sk.decrypt_at(wire["n"], crypto.b64d(wire["ct"]),
                               aad=b"nv1-grp:" + wire["group_id"].encode())
            body = json.loads(pt)
            self._save_group(wire["group_id"])
            kind = body.get("kind")
        if kind == "group_key":
            gid = body["group_id"]
            first_join = self._group(gid) is None
            already = (not first_join) and body["sender_fp"] in self.groups[gid]["_recv"]
            if first_join:
                self.groups[gid] = {"group_id": gid, "name": body.get("group_name", ""),
                                    "creator": body.get("sender_fp"), "members": body.get("members", []),
                                    "_send": crypto.SenderKey(), "_recv": {},
                                    "send_state": None, "recv_states": {}}
            self.groups[gid]["_recv"][body["sender_fp"]] = crypto.SenderKey.from_state(body["state"])
            self._save_group(gid)
            self.ledger.append("agent:%s" % agent_name, None, "group.join",
                               {"group_id": gid}, "ok", "joined group %s" % body.get("group_name", gid))
            if first_join:
                # a joiner also speaks: distribute MY sender key to the group
                g = self.groups[gid]
                my_key = a_key = "ed25519:" + crypto.b64e(crypto.sign_pub(self.agents[agent_name]["seed"]))
                for m in g.get("members", []):
                    if m["agent_key"].split(":")[-1] == my_key.split(":")[-1]:
                        continue
                    self.queue_send(agent_name, m["agent_key"], {
                        "kind": "group_key", "group_id": gid, "group_name": g.get("name", ""),
                        "sender_fp": self.fp, "state": g["_send"].state(),
                        "members": g.get("members", []),
                    })
            self._ack(env, agent_name)
            return
        # informational/action content: write inbox record
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
        self._ack(env, agent_name)

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
                envelope.verify_grant(g, self.principal_pub)
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
            self.ledger.append("node:%s" % self.name, None, "msg.ack",
                               {"msg_id": mid, "peer_head": body.get("ledger_head")}, "ok",
                               "acked %s" % mid)
            return True
        return False

    def _resolve_node_by_key(self, ed_b64):
        try:
            _, b = _http("GET", "%s/v1/directory" % self.hub)
            d = json.loads(b)
            for fp, info in d["nodes"].items():
                if info.get("node_key") == "ed25519:" + ed_b64:
                    return fp
            for _, info in d["agents"].items():
                if info.get("agent_key") == "ed25519:" + ed_b64:
                    return info["node_fp"]
        except Exception:
            pass
        return None

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
            except Exception as e:
                rec["next"] = now + (2 ** rec["attempts"]) * P
                self.ledger.append("node:%s" % self.name, None, "msg.retry",
                                   {"msg_id": mid}, "error", str(e))
        self._save_state()

    # ---------- main loop ----------
    def run(self, once=False):
        # exclusive lock: two daemons on one home diverge session state
        import fcntl
        self._lockfd = open(os.path.join(self.home, "node.lock"), "w")
        try:
            fcntl.flock(self._lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise SystemExit("another natively node process holds %s - refusing to run" % self.home)
        self.publish_prekeys()
        self.register()
        self.ledger.append("node:%s" % self.name, None, "node.start",
                           {"hub": self.hub, "fp": self.fp}, "ok",
                           "node %s (%s) online" % (self.name, self.fp))
        while True:
            self._flush_outbox()
            try:
                _, b = _http("GET", "%s/v1/poll/%s?after=%d" % (self.hub, self.fp, self.state["last_seq"]))
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
                            sender_fp = self._resolve_node_by_key(env["from"].split(":", 1)[1])
                            body_preview = self._dec_pairwise(sender_fp, env["body"])
                        except Exception:
                            body_preview = None
                        if body_preview and body_preview.get("kind") == "ack":
                            self._handle_ack(env, body_preview)
                        else:
                            self._handle_envelope(env)
                    else:
                        self._handle_envelope(env)
                    self.state["last_seq"] = max(self.state["last_seq"], seq)
                self._save_state()
            except (urllib.error.URLError, OSError) as e:
                pass
            self._retries()
            if once:
                return
            time.sleep(0.5)


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

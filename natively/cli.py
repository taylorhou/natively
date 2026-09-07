"""natively CLI: hub, node, agent, messaging, groups, blobs, ledger, bot."""
import argparse
import json
import os
import sys
import time

from . import crypto, envelope, jcs, revocation
from . import node as nodemod
from . import hub as hubmod


def _home(args):
    return os.path.abspath(args.home or nodemod.home_dir())


def _principal_seed(path):
    return bytes.fromhex(open(path).read().strip())


def cmd_principal_init(args):
    seed = crypto.gen_signing_key()
    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, seed.hex().encode()); os.close(fd)
    print("principal key written to", args.out)
    print("principal public key (pin this at every node):")
    print(crypto.b64e(crypto.sign_pub(seed)))


def cmd_hub(args):
    roots = [r.strip() for r in (args.principal_pub or "").split(",") if r.strip()]
    hubmod.run(port=args.port, state_path=args.state, principal_roots=roots)


def cmd_node_init(args):
    home = _home(args)
    fp = nodemod.init_node(home, args.name, args.hub, args.principal_pub)
    print("node initialized: name=%s fp=%s home=%s" % (args.name, fp, home))


def cmd_node_run(args):
    n = nodemod.Node(_home(args))
    print("node %s (%s) running against %s" % (n.name, n.fp, n.hub))
    n.run()


def cmd_agent_add(args):
    home = _home(args)
    key = nodemod.add_agent(home, args.name, _principal_seed(args.principal),
                            args.caps.split(",") if args.caps else ["test.ping", "msg.send"])
    print("agent %s added: %s" % (args.name, key))


def cmd_card_sign(args):
    # Sign a card for an agent keypair generated on ANOTHER node: the agent's
    # seed never leaves its home - only its public key crosses. Lets the
    # principal seed live on one durable box while agents run anywhere.
    agent_pub = crypto.b64d(args.agent_pub.split(":", 1)[-1])
    node_pub = crypto.b64d(args.node_pub.split(":", 1)[-1])
    card = envelope.make_card_for_pub(
        agent_pub, node_pub, _principal_seed(args.principal),
        args.caps.split(",") if args.caps else ["test.ping", "msg.send"],
        args.ledger_url or "")
    out = json.dumps(card, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(out)
        os.chmod(args.out, 0o600)
        print("card written to", args.out)
    else:
        print(out)


def cmd_directory(args):
    n = nodemod.Node(_home(args))
    import urllib.request
    d = json.loads(urllib.request.urlopen(n.hub + "/v1/directory", timeout=10).read())
    print(json.dumps(d, indent=2))


def cmd_send(args):
    n = nodemod.Node(_home(args))
    to_key = _resolve(n, args.to)
    body = {"kind": "text", "text": args.text}
    if args.action:
        body = {"kind": "action", "action": args.action,
                "resource": args.resource or "", "params": json.loads(args.params or "{}"),
                "text": args.text}
    grant_ids = args.grants.split(",") if args.grants else []
    fn = n.queue_send(args.frm, to_key, body, grant_ids=grant_ids)
    print("queued:", fn)


def cmd_blob(args):
    """Send a file attachment: encrypt blob, POST to hub, send reference."""
    n = nodemod.Node(_home(args))
    data = open(args.file, "rb")
    raw = data.read()
    data.close()
    import hashlib
    key = os.urandom(32)
    ct = crypto.aead_encrypt(key, raw)
    import urllib.request
    req = urllib.request.Request(n.hub + "/v1/blob", data=ct, method="POST")
    req.add_header("Content-Type", "application/octet-stream")
    resp = json.loads(urllib.request.urlopen(req, timeout=120).read())
    body = {"kind": "blob_ref", "blob_id": resp["blob_id"], "key": crypto.b64e(key),
            "sha256": hashlib.sha256(raw).hexdigest(), "name": os.path.basename(args.file),
            "size": len(raw)}
    to_key = _resolve(n, args.to)
    fn = n.queue_send(args.frm, to_key, body)
    print("blob %d bytes -> %s; msg queued: %s" % (len(raw), resp["blob_id"], fn))


def cmd_group_create(args):
    n = nodemod.Node(_home(args))
    members = []
    for m in args.members.split(","):
        m = m.strip()
        if m:
            members.append({"agent_key": _resolve(n, m)})
    gid = n.create_group(args.frm, members, name=args.name or "")
    print("group created:", gid)


def cmd_group_send(args):
    n = nodemod.Node(_home(args))
    body = {"kind": "group_text", "text": args.text}
    n.group_send(args.frm, args.gid, body)
    print("group message queued")


def cmd_group_blob(args):
    n = nodemod.Node(_home(args))
    raw = open(args.file, "rb").read()
    import hashlib, urllib.request
    key = os.urandom(32)
    ct = crypto.aead_encrypt(key, raw)
    req = urllib.request.Request(n.hub + "/v1/blob", data=ct, method="POST")
    req.add_header("Content-Type", "application/octet-stream")
    resp = json.loads(urllib.request.urlopen(req, timeout=120).read())
    body = {"kind": "group_blob_ref", "blob_id": resp["blob_id"], "key": crypto.b64e(key),
            "sha256": hashlib.sha256(raw).hexdigest(), "name": os.path.basename(args.file),
            "size": len(raw)}
    n.group_send(args.frm, args.gid, body)
    print("group blob queued: %s (%d bytes)" % (resp["blob_id"], len(raw)))


def cmd_groups(args):
    n = nodemod.Node(_home(args))
    gdir = os.path.join(n.home, "groups")
    if os.path.isdir(gdir):
        for f in sorted(os.listdir(gdir)):
            g = json.load(open(os.path.join(gdir, f)))
            print(g["group_id"], g.get("name", ""), "members:", len(g.get("members", [])))


def cmd_inbox(args):
    n = nodemod.Node(_home(args))
    idir = os.path.join(n.home, "inbox", args.agent)
    if not os.path.isdir(idir):
        print("(empty)")
        return
    files = sorted(os.listdir(idir))
    if args.tail:
        files = files[-args.tail:]
    for f in files:
        rec = json.load(open(os.path.join(idir, f)))
        b = rec["body"]
        kind = b.get("kind")
        txt = b.get("text") or ("blob:%s (%s bytes)" % (b.get("name"), b.get("size")) if "blob" in str(kind) else json.dumps(b)[:200])
        print("[%s] %s %s: %s" % (rec["ts"], rec["from"][:24], kind, txt))


def cmd_fetch_blob(args):
    """Fetch + decrypt a blob referenced in an inbox record."""
    n = nodemod.Node(_home(args))
    if not envelope.safe_id(args.msg_id, "msg"):
        raise SystemExit("not a message id: %s" % args.msg_id)
    rec = json.load(open(os.path.join(n.home, "inbox", args.agent, args.msg_id + ".json")))
    b = rec["body"]
    import urllib.request, hashlib
    ct = urllib.request.urlopen(n.hub + "/v1/blob/" + b["blob_id"], timeout=120).read()
    raw = crypto.aead_decrypt(crypto.b64d(b["key"]), ct)
    assert hashlib.sha256(raw).hexdigest() == b["sha256"], "blob hash mismatch"
    open(args.out, "wb").write(raw)
    print("wrote %d bytes to %s (sha256 verified)" % (len(raw), args.out))


def cmd_ledger(args):
    n = nodemod.Node(_home(args))
    if args.ledger_cmd == "head":
        print(n.ledger.head())
    elif args.ledger_cmd == "verify":
        ok = n.ledger.verify_chain()
        print("chain ok" if ok else "CHAIN BROKEN")
        sys.exit(0 if ok else 1)
    elif args.ledger_cmd == "tail":
        for e in list(n.ledger.entries())[-args.n:]:
            print(json.dumps(e))


def _write_grant(n, g):
    gdir = os.path.join(n.home, "grants")
    os.makedirs(gdir, exist_ok=True)
    json.dump(g, open(os.path.join(gdir, g["grant_id"] + ".json"), "w"), indent=2)


def _check_feed(n, url):
    """A feed no execution could read is refused at issuance, not at every
    action: the url must be a scheme this node reads, and the feed must
    be fetchable now and hold only tombstones that verify under this
    node's roots (an empty feed is fine). What it holds is kept in the
    node's revocation state, so a tombstone seen at issuance still counts
    if the feed is later truncated."""
    try:
        n.revocations.observe(url)
    except revocation.RevocationError as e:
        raise SystemExit("%s: %s" % (e, url))


def cmd_grant_issue(args):
    n = nodemod.Node(_home(args))
    pseed = _principal_seed(args.principal)
    card = json.load(open(os.path.join(n.home, "agents", args.agent + ".card.json")))
    scope = json.loads(open(args.scope).read()) if os.path.exists(args.scope) else json.loads(args.scope)
    if args.revocation_ledger:
        _check_feed(n, args.revocation_ledger)
    try:
        g = envelope.make_grant(pseed, args.principal_name, card,
                                "ed25519:" + crypto.b64e(n.node_pub), scope, args.statement,
                                max_uses=None if args.windowed else args.max_uses, ttl_s=args.ttl,
                                revocation_ledger=args.revocation_ledger or "")
        # refuse to write what the node would refuse: the same pinned root set the node executes under
        envelope.verify_grant(g, n.principal_roots, subject_card=card)
    except (ValueError, envelope.GrantError) as e:
        raise SystemExit("grant not signed: %s" % e)
    _write_grant(n, g)
    print("grant issued:", g["grant_id"])


def cmd_grant_delegate(args):
    """A local agent delegates a subset of a grant it holds (the parent,
    whose subject it is) to another local agent. Depth one."""
    n = nodemod.Node(_home(args))
    parent = n._load_grant(args.parent)
    if parent is None:
        raise SystemExit("parent grant %s not held here" % args.parent)
    seed = n.agents[args.frm]["seed"]
    card = json.load(open(os.path.join(n.home, "agents", args.to + ".card.json")))
    scope = json.loads(open(args.scope).read()) if os.path.exists(args.scope) else json.loads(args.scope)
    if parent["revocation"]["ledger"]:
        _check_feed(n, parent["revocation"]["ledger"])  # the child inherits the feed: it must still be readable
    g = envelope.make_delegated_grant(seed, parent, card, scope, args.statement,
                                      max_uses=None if args.windowed else args.max_uses, ttl_s=args.ttl)
    envelope.verify_grant(g, n.principal_roots, subject_card=card, parent=parent,
                          parent_subject_card=n._subject_card(parent))
    _write_grant(n, g)
    print("delegated grant issued:", g["grant_id"])


def cmd_revoke(args):
    """Append a tombstone to this node's local revocation feed. The target
    is a grant id, an agent card hash, an agent key or a principal key;
    the signer must be one of the node's pinned roots."""
    from . import revocation
    n = nodemod.Node(_home(args))
    t = revocation.make_tombstone(_principal_seed(args.principal), args.target, args.reason or "")
    if not revocation.verify_tombstone(t, n.principal_roots):
        raise SystemExit("signer is not one of this node's pinned roots")
    with open(n.revocations.local_path, "a") as f:
        f.write(json.dumps(t, separators=(",", ":")) + "\n")
    # the target goes into the shared observation store before this
    # reports success: a local feed later truncated or deleted un-revokes
    # nothing, and a daemon on this home sees it at its next check
    if args.target not in n.revocations.local_targets():
        raise SystemExit("tombstone written but not observed: %s" % args.target)
    print("revoked:", args.target)


def cmd_bot(args):
    """Stress bot: nonstop chatter + auto-replies (Taylor's break-it loop)."""
    import random
    n = nodemod.Node(_home(args))
    peers = [p.strip() for p in args.peers.split(",") if p.strip()]
    words = ("the quick brown fox jumps over the lazy dog pack my box with "
             "five dozen liquor jacks how vexingly quick daft zebras jump").split()
    idir = os.path.join(n.home, "inbox", args.agent)
    seen = set(os.listdir(idir)) if os.path.isdir(idir) else set()
    while True:
        try:
            # outbound chatter
            if peers and random.random() < args.peer_prob:
                txt = " ".join(random.choices(words, k=random.randint(3, 40)))
                to = _resolve(n, random.choice(peers))
                n.queue_send(args.agent, to, {"kind": "text", "text": "[%s] %s" % (args.agent, txt)})
            # group chatter
            gdir = os.path.join(n.home, "groups")
            if os.path.isdir(gdir) and random.random() < args.group_prob:
                for gf in os.listdir(gdir):
                    if not gf.endswith(".json"):
                        continue  # skip .lock files: gf[:-5] on one yields a
                        # mangled gid whose lock file nests .json.json... (#40)
                    if any(s in gf for s in args.group_skip):
                        continue  # soak stays off live exchange groups
                    txt = " ".join(random.choices(words, k=random.randint(3, 25)))
                    try:
                        n.group_send(args.agent, gf[:-5], {"kind": "group_text", "text": "[%s] %s" % (args.agent, txt)})
                    except Exception:
                        pass
            # replies to new inbox entries
            if os.path.isdir(idir):
                for f in sorted(os.listdir(idir)):
                    if f in seen or not f.endswith(".json"):
                        continue
                    seen.add(f)
                    try:
                        rec = json.load(open(os.path.join(idir, f)))
                        if rec["body"].get("kind") in ("text",) and peers:
                            reply = "ack:%s" % rec["msg_id"]
                            n.queue_send(args.agent, rec["from"], {"kind": "text", "text": reply})
                    except Exception:
                        pass
            # random attachment burst
            if peers and random.random() < args.blob_rate:
                size = random.choice([1024, 50 * 1024, 1024 * 1024, 5 * 1024 * 1024])
                blob = os.urandom(size)
                import hashlib, urllib.request
                key = os.urandom(32)
                ct = crypto.aead_encrypt(key, blob)
                req = urllib.request.Request(n.hub + "/v1/blob", data=ct, method="POST")
                req.add_header("Content-Type", "application/octet-stream")
                resp = json.loads(urllib.request.urlopen(req, timeout=120).read())
                to = _resolve(n, random.choice(peers))
                n.queue_send(args.agent, to, {"kind": "blob_ref", "blob_id": resp["blob_id"],
                             "key": crypto.b64e(key), "sha256": hashlib.sha256(blob).hexdigest(),
                             "name": "stress-%d.bin" % size, "size": size})
        except Exception as e:
            print("bot error:", e, file=sys.stderr)
        time.sleep(random.uniform(args.min_gap, args.max_gap))


def _resolve(n, addr):
    """name@nodefp or ed25519 key -> agent_key b64 (no prefix)."""
    if addr.startswith("ed25519:"):
        return addr
    if "@" in addr:
        import urllib.request
        d = json.loads(urllib.request.urlopen(n.hub + "/v1/directory", timeout=10).read())
        if addr in d["agents"]:
            return d["agents"][addr]["agent_key"]
        raise SystemExit("no such agent in directory: %s" % addr)
    # bare name: local agent
    if addr in n.agents:
        return n.agents[addr]["card"]["agent_key"]
    raise SystemExit("cannot resolve: %s" % addr)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="natively")
    ap.add_argument("--home")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("principal-init"); p.add_argument("--out", required=True); p.set_defaults(f=cmd_principal_init)
    p = sub.add_parser("hub"); p.add_argument("--port", type=int, default=8471); p.add_argument("--state"); p.add_argument("--principal-pub", help="comma-separated principal public keys (b64); when set, only cards they issued register"); p.set_defaults(f=cmd_hub)
    p = sub.add_parser("node-init"); p.add_argument("--name", required=True); p.add_argument("--hub", required=True); p.add_argument("--principal-pub", required=True); p.set_defaults(f=cmd_node_init)
    p = sub.add_parser("node-run"); p.set_defaults(f=cmd_node_run)
    p = sub.add_parser("agent-add"); p.add_argument("--name", required=True); p.add_argument("--principal", required=True); p.add_argument("--caps", default=""); p.set_defaults(f=cmd_agent_add)
    p = sub.add_parser("card-sign"); p.add_argument("--agent-pub", required=True); p.add_argument("--node-pub", required=True); p.add_argument("--principal", required=True); p.add_argument("--caps", default=""); p.add_argument("--ledger-url", default=""); p.add_argument("--out"); p.set_defaults(f=cmd_card_sign)
    p = sub.add_parser("directory"); p.set_defaults(f=cmd_directory)
    p = sub.add_parser("send"); p.add_argument("--from", dest="frm", required=True); p.add_argument("--to", required=True); p.add_argument("--text", required=True); p.add_argument("--action"); p.add_argument("--resource"); p.add_argument("--params"); p.add_argument("--grants"); p.set_defaults(f=cmd_send)
    p = sub.add_parser("blob"); p.add_argument("--from", dest="frm", required=True); p.add_argument("--to", required=True); p.add_argument("--file", required=True); p.set_defaults(f=cmd_blob)
    p = sub.add_parser("group-create"); p.add_argument("--from", dest="frm", required=True); p.add_argument("--members", required=True); p.add_argument("--name"); p.set_defaults(f=cmd_group_create)
    p = sub.add_parser("group-send"); p.add_argument("--from", dest="frm", required=True); p.add_argument("--gid", required=True); p.add_argument("--text", required=True); p.set_defaults(f=cmd_group_send)
    p = sub.add_parser("group-blob"); p.add_argument("--from", dest="frm", required=True); p.add_argument("--gid", required=True); p.add_argument("--file", required=True); p.set_defaults(f=cmd_group_blob)
    p = sub.add_parser("groups"); p.set_defaults(f=cmd_groups)
    p = sub.add_parser("inbox"); p.add_argument("--agent", required=True); p.add_argument("--tail", type=int); p.set_defaults(f=cmd_inbox)
    p = sub.add_parser("fetch-blob"); p.add_argument("--agent", required=True); p.add_argument("--msg-id", required=True); p.add_argument("--out", required=True); p.set_defaults(f=cmd_fetch_blob)
    p = sub.add_parser("ledger"); p.add_argument("ledger_cmd", choices=["head", "verify", "tail"]); p.add_argument("-n", type=int, default=10); p.set_defaults(f=cmd_ledger)
    p = sub.add_parser("grant-delegate"); p.add_argument("--from", dest="frm", required=True, help="local agent holding the parent grant"); p.add_argument("--to", required=True, help="local agent receiving the delegation"); p.add_argument("--parent", required=True); p.add_argument("--scope", required=True); p.add_argument("--statement", required=True); p.add_argument("--max-uses", type=int, default=1); p.add_argument("--windowed", action="store_true", help="the scope entries carry max_uses_per_window; the grant carries no max_uses"); p.add_argument("--ttl", type=int, default=86400); p.set_defaults(f=cmd_grant_delegate)
    p = sub.add_parser("revoke"); p.add_argument("--principal", required=True); p.add_argument("--target", required=True); p.add_argument("--reason"); p.set_defaults(f=cmd_revoke)
    p = sub.add_parser("grant-issue"); p.add_argument("--agent", required=True); p.add_argument("--principal", required=True); p.add_argument("--principal-name", default="principal"); p.add_argument("--scope", required=True); p.add_argument("--statement", required=True); p.add_argument("--max-uses", type=int, default=1); p.add_argument("--windowed", action="store_true", help="the scope entries carry max_uses_per_window; the grant carries no max_uses"); p.add_argument("--ttl", type=int, default=86400); p.add_argument("--revocation-ledger", help="feed URL (file:// or https://) of the principal's tombstones; the node's local feed is always consulted"); p.set_defaults(f=cmd_grant_issue)
    p = sub.add_parser("bot"); p.add_argument("--agent", required=True); p.add_argument("--peers", default=""); p.add_argument("--blob-rate", type=float, default=0.05); p.add_argument("--min-gap", type=float, default=0.2); p.add_argument("--max-gap", type=float, default=2.0); p.add_argument("--peer-prob", type=float, default=0.7); p.add_argument("--group-prob", type=float, default=0.3); p.add_argument("--group-skip", default=""); p.set_defaults(f=cmd_bot)

    args = ap.parse_args(argv)
    args.f(args)


if __name__ == "__main__":
    main()

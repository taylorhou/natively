"""Round-2 gate findings, node level: atomic replay + use limits (1), delegation
budgets (2), revoked cards through cached trust (6), grant attachments (7),
malformed input (9), regex constraints (10), ack signer (12), file export (13), JCS
conformance (15), wire size (16), key-directory separation (17), classification (19)."""

from __future__ import annotations

import base64
import fcntl
import json
import os
import time

import pytest

from natively import ack as ackmod
from natively import bundle as bundlemod
from natively import grant as grantmod
from natively import keys
from natively import message as msgmod
from natively import node as nodemod
from natively.adapters.local import LocalWire
from natively.errors import VerifyError
from natively.node import Node

from .conftest import Clock, make_node, uid

STATEMENT = "Write one file into the other side's scratch directory."


def latest(node):
    return node.ledger.entries()[-1]


def fs_write_scope(executor, name, regex="^[ -~\n]+$", **values):
    vals = {"content": {"regex": regex}} if regex else {}
    vals.update(values)
    return [
        {
            "action": "fs.write",
            "resource": executor.executor().resource_for(name),
            "params": {"keys": ["content"], "values": vals},
        }
    ]


@pytest.fixture
def pair(tmp_path):
    clock = Clock()
    reports: list[str] = []
    a = make_node(tmp_path, "a", clock, reports=reports)
    b = make_node(tmp_path, "b", clock, reports=reports)
    a.pin(b.principal.public, "b")
    b.pin(a.principal.public, "a")
    a.receive(b.compose_card())
    b.receive(a.compose_card())
    a.mark_lookup_ok()
    b.mark_lookup_ok()
    return a, b, clock, reports


def write_bundle(a, b, g, name, content="x\n"):
    return a.compose_action(
        b.card,
        action="fs.write",
        resource=b.executor().resource_for(name),
        params={"content": content},
        grant_ids=[g["grant_id"]],
    )


# ---- 1. atomic replay + use limits ---------------------------------------------------


def test_crash_between_execute_and_ledger_consumes_the_use(pair, monkeypatch):
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "x.txt"), principal_statement=STATEMENT
    )
    bundle = write_bundle(a, b, g, "x.txt")
    msg_id = bundle["object"]["msg_id"]
    real_append = b.ledger.append
    crashed = []

    def crash(**kw):
        if kw.get("outcome") == "applied" and not crashed:
            crashed.append(1)
            raise RuntimeError("power cut after the write")
        return real_append(**kw)

    monkeypatch.setattr(b.ledger, "append", crash)
    assert b.receive(bundle) == []  # no ack left the node
    assert (b.scratch_dir / "x.txt").read_text() == "x\n"  # the executor had run
    seen = json.loads((b.state / "seen.json").read_text())
    assert seen[msg_id] == {"status": "in_progress", "grant_id": g["grant_id"], "ts": b.ts()}
    assert latest(b)["outcome"] == "verify_failed:malformed" and latest(b)["msg_id"] == msg_id
    # the reservation counts as a use: a fresh message on the grant is refused
    assert b.grant_uses(g) == (1, None)
    (r,) = b.receive(write_bundle(a, b, g, "x.txt", "y\n"))
    assert r["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "grant.max_uses" in latest(b)["detail"]
    assert (b.scratch_dir / "x.txt").read_text() == "x\n"
    # a re-delivery of the interrupted message: failed:interrupted, ledgered once
    (r,) = b.receive(bundle)
    assert r["object"]["outcome"] == "failed:interrupted"
    hits = [
        e
        for e in b.ledger.entries()
        if e["msg_id"] == msg_id and e["outcome"] == "failed:interrupted"
    ]
    assert len(hits) == 1 and hits[0]["grant_id"] == g["grant_id"]
    (r2,) = b.receive(bundle)  # and again: the stored ack, no new entry
    assert r2["object"] == r["object"]
    assert (
        sum(
            1
            for e in b.ledger.entries()
            if e["msg_id"] == msg_id and e["outcome"] == "failed:interrupted"
        )
        == 1
    )
    assert b.grant_uses(g) == (1, None)
    assert b.ledger.verify() == b.ledger.head()


def test_crash_between_ledger_and_ack_rebuilds_the_ack(pair, monkeypatch):
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "y.txt"), principal_statement=STATEMENT
    )
    bundle = write_bundle(a, b, g, "y.txt")
    msg_id = bundle["object"]["msg_id"]
    real_sign = ackmod.sign
    crashed = []

    def crash(a_, kp):
        if not crashed:
            crashed.append(1)
            raise RuntimeError("power cut before the ack")
        return real_sign(a_, kp)

    monkeypatch.setattr(nodemod.ackmod, "sign", crash)
    assert b.receive(bundle) == []
    assert b.ledger.find_msg(msg_id)["outcome"] == "applied"
    assert json.loads((b.state / "seen.json").read_text())[msg_id]["status"] == "in_progress"
    (r,) = b.receive(bundle)  # the ack is rebuilt from the ledger entry, nothing re-applied
    assert r["object"]["outcome"] == "applied" and r["object"]["in_reply_to"] == msg_id
    assert b.grant_uses(g) == (1, None)
    assert (
        sum(1 for e in b.ledger.entries() if e["msg_id"] == msg_id and e["outcome"] == "applied")
        == 1
    )


def test_receive_holds_the_state_lock_while_the_executor_runs(pair, monkeypatch):
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "l.txt"), principal_statement=STATEMENT
    )
    observed = []
    real_executor = b.executor
    bundle = write_bundle(a, b, g, "l.txt")

    class Probe:
        def apply(self, action, resource, params):
            fd = os.open(b.state / ".lock", os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                observed.append("free")
            except BlockingIOError:
                observed.append("held")
            finally:
                os.close(fd)
            return real_executor().apply(action, resource, params)

    monkeypatch.setattr(b, "executor", lambda: Probe())
    (r,) = b.receive(bundle)
    assert r["object"]["outcome"] == "applied" and observed == ["held"]
    # released afterwards
    fd = os.open(b.state / ".lock", os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.close(fd)


def test_ledger_is_reread_from_disk_between_calls(pair):
    """Another process appending to the ledger is seen on the next use count."""
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "z.txt"), principal_statement=STATEMENT
    )
    assert b.grant_uses(g) == (0, None)
    other = nodemod.Ledger(b.ledger.path)  # a second handle, as a second process would hold
    other.append(
        ts=b.ts(),
        actor="other",
        grant_id=g["grant_id"],
        action="fs.write",
        params_hash=None,
        outcome="applied",
        msg_id=uid("msg"),
    )
    assert b.grant_uses(g) == (1, None)
    (r,) = b.receive(write_bundle(a, b, g, "z.txt"))
    assert "grant.max_uses" in latest(b)["detail"]


# ---- 2. delegation budgets -----------------------------------------------------------


def test_parent_budget_covers_every_child(tmp_path):
    clock = Clock()
    a = make_node(tmp_path, "a", clock)
    b = make_node(tmp_path, "b", clock)
    a.pin(b.principal.public, "b")
    b.pin(a.principal.public, "a")
    wire = LocalWire()
    wire.deliver(a, b, a.compose_card())
    wire.deliver(b, a, b.compose_card())
    b.mark_lookup_ok()
    parent = a.issue_grant(
        subject_card=a.card,
        audience=b.host.public,
        scope=fs_write_scope(b, "d.txt", regex="^[a-z\n]+$"),
        principal_statement="A may have B write d.txt twice in all.",
        max_uses=2,
    )

    def child():
        return a.delegate_grant(
            parent=parent,
            subject_card=b.card,
            principal_statement="one lowercase word",
            scope=[
                {
                    "action": "fs.write",
                    "resource": b.executor().resource_for("d.txt"),
                    "params": {
                        "keys": ["content"],
                        "values": {"content": {"regex": "^[a-z\n]+$", "in": ["ok\n"]}},
                    },
                }
            ],
            max_uses=1,
        )

    c1, c2, c3 = child(), child(), child()
    outcomes = []
    for c in (c1, c2, c3):
        replies = wire.deliver(a, b, write_bundle(a, b, c, "d.txt", "ok\n"))
        outcomes.append(replies[0]["object"]["outcome"])
    assert outcomes == ["applied", "applied", "refused:no_authorizing_grant"]
    assert "grant.parent.max_uses" in latest(b)["detail"]
    assert b.grant_uses(c3) == (0, None)  # the child itself is unused; the family is spent
    assert b.grant_uses(parent, family=True) == (2, None)


# ---- 6. revoked cards through cached trust -------------------------------------------


def test_revoked_cached_sender_is_refused(pair):
    a, b, clock, reports = pair
    r = a.revoke(cards=[a.card_hash], principal_statement="A's agent is retired.")
    b.receive(a.compose_revocation(r))
    assert b.card_for_key(a.agent.public) is None
    assert b.card_for_key(a.agent.public, include_revoked=True) is not None
    assert b.receive(a.compose_info(b.card, "still me?")) == []
    assert latest(b)["outcome"] == "verify_failed:message.sender.revoked"
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "r.txt"), principal_statement=STATEMENT
    )
    assert b.receive(write_bundle(a, b, g, "r.txt")) == []
    assert latest(b)["outcome"] == "verify_failed:message.sender.revoked"
    assert not (b.scratch_dir / "r.txt").exists()
    # an ack signed by the revoked agent is refused too
    bundle = b.compose_info(a.card, "hello?")
    b.outbox_record(bundle)
    (ack,) = a.receive(bundle)
    assert b.receive(ack) == []
    assert latest(b)["outcome"] == "verify_failed:ack.sender.revoked"
    assert b.outbox()[-1]["status"] == "pending"


def test_delegator_card_is_checked_against_its_own_principal(tmp_path):
    """root R issues a parent to delegator D (audience X's node); D delegates to X.
    D's card is under D's principal, not R's: a revocation by D's principal must bind."""
    clock = Clock()
    r = make_node(tmp_path, "r", clock)
    d = make_node(tmp_path, "d", clock)
    x = make_node(tmp_path, "x", clock)
    for n in (r, d, x):
        for other in (r, d, x):
            if other is not n:
                n.pin(other.principal.public, other.card["agent"]["name"])
    for n in (r, d):
        x.receive(n.compose_card())
        n.receive(x.compose_card())
    d.receive(r.compose_card())
    x.mark_lookup_ok()
    parent = r.issue_grant(
        subject_card=d.card,
        audience=x.host.public,
        scope=fs_write_scope(x, "del.txt", regex="^[a-z\n]+$"),
        principal_statement="D may have X write del.txt.",
        max_uses=3,
    )
    d.receive(bundlemod.make("card", r.card, grants=[parent]))
    child = d.delegate_grant(
        parent=parent,
        subject_card=x.card,
        principal_statement="one word",
        scope=[
            {
                "action": "fs.write",
                "resource": x.executor().resource_for("del.txt"),
                "params": {
                    "keys": ["content"],
                    "values": {"content": {"regex": "^[a-z\n]+$", "in": ["ok\n"]}},
                },
            }
        ],
        max_uses=1,
    )
    r.store_grant(child)  # R will present the child (the message sender need not be D)
    (rep,) = x.receive(write_bundle(r, x, child, "del.txt", "ok\n"))
    assert rep["object"]["outcome"] == "applied"
    # D's OWN principal revokes D's card; R (the grant root) has said nothing
    rev = d.revoke(cards=[d.card_hash], principal_statement="D's agent is retired.")
    x.receive(bundlemod.make("revocation", rev))
    child2 = d.delegate_grant(
        parent=parent,
        subject_card=x.card,
        principal_statement="one word again",
        scope=child["scope"],
        max_uses=1,
    )
    r.store_grant(child2)
    (rep,) = x.receive(write_bundle(r, x, child2, "del.txt", "ok\n"))
    assert rep["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "grant.delegator_revoked" in latest(x)["detail"]


# ---- 7. grant attachments -------------------------------------------------------------


def test_unauthenticated_attachment_is_never_stored(pair):
    a, b, clock, reports = pair
    stranger = keys.KeyPair.generate()
    g = grantmod.sign(
        grantmod.build(
            issuer={"principal": "nobody", "key": stranger.public},
            subject={"agent": b.card_hash, "key": b.agent.public},
            audience_executor=b.host.public,
            scope=fs_write_scope(b, "s.txt"),
            principal_statement="a stranger's word",
            issued_at=a.ts(),
            expires_at="2027-01-01T00:00:00Z",
        ),
        stranger,
    )
    replies = b.receive(
        bundlemod.make(
            "message", a.compose_info(b.card, "hi")["object"], cards=[a.card], grants=[g]
        )
    )
    assert replies[0]["object"]["outcome"] == "information"
    assert b.load_grant(g["grant_id"]) is None
    assert [e["outcome"] for e in b.ledger.entries()].count(
        "verify_failed:grant.issuer.unpinned"
    ) == 1


def test_tampered_attachment_is_not_substituted_by_the_cached_original(pair):
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "t.txt"),
        principal_statement=STATEMENT,
        max_uses=2,
    )
    (rep,) = b.receive(write_bundle(a, b, g, "t.txt", "one\n"))
    assert rep["object"]["outcome"] == "applied" and b.load_grant(g["grant_id"]) == g
    bundle = write_bundle(a, b, g, "t.txt", "two\n")
    bundle["grants"] = [{**g, "bonus": 1}]  # unknown constraint: fails verification
    (rep,) = b.receive(bundle)
    assert rep["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "attached copy failed verification" in latest(b)["detail"]
    assert (b.scratch_dir / "t.txt").read_text() == "one\n"
    assert b.load_grant(g["grant_id"]) == g and b.grant_uses(g) == (1, None)


# ---- 9. malformed input ---------------------------------------------------------------


def test_surrogates_and_bad_ids_are_verify_errors(pair):
    a, b, clock, reports = pair
    m = a.compose_info(b.card, "hi")["object"]
    with pytest.raises(VerifyError) as e:
        msgmod.verify({**m, "msg_id": "msg_" + "\udc80" * 26})
    assert e.value.reason == "message.msg_id.format"
    with pytest.raises(VerifyError) as e:
        msgmod.verify({**m, "from": "ed25519:\udc80"})
    assert e.value.reason == "message.canon"
    with pytest.raises(VerifyError) as e:
        grantmod.check_structure(
            {
                **a.issue_grant(
                    subject_card=b.card,
                    scope=fs_write_scope(b, "g.txt"),
                    principal_statement=STATEMENT,
                ),
                "grant_id": "grt_../../etc/passwd",
            }
        )
    assert e.value.reason == "grant.grant_id.format"
    with pytest.raises(VerifyError):
        b.load_grant("grt_../../etc/passwd")
    # through receive: ledgered, nothing raised, the node goes on
    assert (
        b.receive(bundlemod.make("message", {**m, "from": "ed25519:\udc80"}, cards=[a.card])) == []
    )
    assert latest(b)["outcome"] == "verify_failed:message.canon"
    assert b.receive(a.compose_info(b.card, "still here"))[0]["object"]["outcome"] == "information"


def test_deep_json_and_odd_shapes_never_stop_the_poll(pair, monkeypatch):
    a, b, clock, reports = pair
    deep = "[" * 10_000 + "]" * 10_000
    text = "X-Natively: v0\n" + base64.b64encode(deep.encode()).decode() + "\n"
    with pytest.raises(VerifyError) as e:
        bundlemod.decode(text)
    assert e.value.reason == "wire.json"
    nested = {"natively": "v0", "kind": "message", "object": {}, "cards": [], "grants": []}
    x = nested["object"]
    for _ in range(40):
        x["n"] = {}
        x = x["n"]
    assert b.receive(nested) == [] and latest(b)["outcome"] == "verify_failed:bundle.json"
    assert (
        b.receive(
            {
                "natively": "v0",
                "kind": "message",
                "object": {"msg_id": 5},
                "cards": [],
                "grants": [],
            }
        )
        == []
    )
    # anything that is not a VerifyError becomes verify_failed:malformed
    m = a.compose_info(b.card, "boom")

    def boom(_m):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(nodemod.msgmod, "decode_body", boom)
    assert b.receive(m) == []
    assert (
        latest(b)["outcome"] == "verify_failed:malformed"
        and latest(b)["msg_id"] == m["object"]["msg_id"]
    )
    monkeypatch.undo()
    assert b.receive(a.compose_info(b.card, "after"))[0]["object"]["outcome"] == "information"


# ---- 10. regex constraints ------------------------------------------------------------


def test_catastrophic_regex_is_refused_not_hung(pair):
    """A match that runs past REGEX_TIMEOUT_S is refused by name, never a hang. Round
    20: `(a|a)+` is outside the constraint language (a quantified group), so the
    shape is one the language ADMITS and the engine still cannot short-circuit —
    twenty `(\\w*|\\s*)` groups before `[bc]$` (44 atoms), on a value whose last
    character is in neither branch: without nested repetition the search is
    polynomial in the value, but its degree is the number of overlapping
    quantifiers, and 2 s pass on 32 bytes. The timeout is the operational bound
    at use; at receive and at load the cost is the parse and a compile of at most
    64 atoms."""
    a, b, clock, reports = pair
    slow = "^" + "(\\w*|\\s*)" * 20 + "[bc]$"
    assert grantmod.pattern_problem(slow) is None
    g = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "re.txt", regex=slow),
        principal_statement=STATEMENT,
    )
    t0 = time.monotonic()
    (rep,) = b.receive(write_bundle(a, b, g, "re.txt", "b" + "a" * 30 + "d"))
    assert rep["object"]["outcome"] == "refused:scope.regex_timeout"
    assert time.monotonic() - t0 < grantmod.REGEX_TIMEOUT_S + 5
    assert latest(b)["outcome"] == "refused" and "scope.regex_timeout" in latest(b)["detail"]
    # a quantified group is outside the constraint language — refused at issue by
    # name, nothing stored (round 19 bounded it; round 20 refuses the construct)
    with pytest.raises(ValueError) as e:
        a.issue_grant(
            subject_card=b.card,
            scope=fs_write_scope(b, "re2.txt", regex=r"(a+)+$"),
            principal_statement=STATEMENT,
        )
    assert "grant.constraint.pattern" in str(e.value) and "quantifier on a group" in str(e.value)
    g2 = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "re2.txt", regex=r"^a+$"),
        principal_statement=STATEMENT,
    )
    (rep,) = b.receive(write_bundle(a, b, g2, "re2.txt", "a" * 5000 + "b"))
    assert rep["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "does not match regex" in latest(b)["detail"]
    # a value over the executor's cap is refused before any match
    with pytest.raises(Exception) as e:
        grantmod.match_scope(g2, "fs.write", g2["scope"][0]["resource"], {"content": "a" * 70_000})
    assert "over" in str(e.value)


# ---- 12. ack signer -------------------------------------------------------------------


def test_only_the_recipient_may_ack(tmp_path):
    clock = Clock()
    a = make_node(tmp_path, "a", clock)
    b = make_node(tmp_path, "b", clock)
    c = make_node(tmp_path, "c", clock)
    for n in (a, b, c):
        for other in (a, b, c):
            if other is not n:
                n.pin(other.principal.public, other.card["agent"]["name"])
                n.receive(other.compose_card())
    bundle = a.compose_info(b.card, "for b")
    a.outbox_record(bundle)
    forged = ackmod.sign(
        ackmod.build(
            from_key=c.agent.public,
            to_key=a.agent.public,
            ts=c.ts(),
            in_reply_to=bundle["object"]["msg_id"],
            outcome="applied",
            ledger_head=c.ledger.head(),
            ledger_entry=c.ledger.head(),
        ),
        c.agent,
    )
    assert a.receive(bundlemod.make("ack", forged, cards=[c.card])) == []
    assert latest(a)["outcome"] == "verify_failed:ack.signer"
    assert a.outbox()[0]["status"] == "pending" and a.peer_head(c.agent.public) is None
    (real,) = b.receive(bundle)
    a.receive(real)
    assert a.outbox()[0]["status"] == "acked"


# ---- 13. file export is never retried -------------------------------------------------


def test_exported_message_is_never_resent(pair):
    a, b, clock, reports = pair
    bundle = a.compose_info(b.card, "by hand")
    a.outbox_record(bundle, transport_ref="file:x", status="exported")
    clock.tick(100 * a.poll_s)
    assert a.outbox_due() == [] and a.outbox()[-1]["status"] == "exported"
    (ack,) = b.receive(bundle)
    a.receive(ack)
    assert a.outbox()[-1]["status"] == "acked"


# ---- 15. JCS conformance --------------------------------------------------------------


def wire(text: str) -> str:
    return "X-Natively: v0\n" + base64.b64encode(text.encode()).decode() + "\n"


def test_duplicate_members_and_big_ints_are_rejected_at_parse(pair):
    a, b, clock, reports = pair
    m = a.compose_info(b.card, "dup")["object"]
    raw = json.dumps(bundlemod.make("message", m, cards=[a.card]))
    dup = raw.replace(
        '"to":', '"to": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "to":', 1
    )
    with pytest.raises(VerifyError) as e:
        bundlemod.decode(wire(dup))
    assert e.value.reason == "wire.json" and "duplicate" in e.value.detail
    for bad in (
        '{"natively":"v0","kind":"card","object":{"n":9007199254740993},"cards":[],"grants":[]}',
        '{"natively":"v0","kind":"card","object":{"n":NaN},"cards":[],"grants":[]}',
    ):
        with pytest.raises(VerifyError) as e:
            bundlemod.decode(wire(bad))
        assert e.value.reason == "wire.json"
    ok = bundlemod.decode(
        wire(
            '{"natively":"v0","kind":"card","object":{"n":9007199254740992},"cards":[],"grants":[]}'
        )
    )
    assert ok["object"]["n"] == 2**53
    body = base64.b64encode(b'{"type":"info","text":"a","text":"b"}').decode()
    with pytest.raises(VerifyError) as e:
        msgmod.decode_body({**m, "body": body})
    assert e.value.reason == "message.body.json"


# ---- 16. wire size --------------------------------------------------------------------


def test_wire_and_body_limits_are_on_decoded_bytes():
    head = '{"natively":"v0","kind":"card","object":{"pad":"'
    tail = '"},"cards":[],"grants":[]}'
    pad = bundlemod.MAX_WIRE_BYTES - len(head) - len(tail)
    exact = head + "x" * pad + tail
    assert len(exact.encode()) == bundlemod.MAX_WIRE_BYTES
    assert bundlemod.decode(wire(exact))["object"]["pad"] == "x" * pad
    with pytest.raises(VerifyError) as e:
        bundlemod.decode(wire(head + "x" * (pad + 1) + tail))
    assert e.value.reason == "wire.size"
    kp, other = keys.KeyPair.generate(), keys.KeyPair.generate()
    plain = b'{"type":"info","text":"' + b"y" * (msgmod.MAX_BODY_BYTES - 25) + b'"}'
    assert len(plain) == msgmod.MAX_BODY_BYTES
    m = msgmod.sign(
        {
            **msgmod.info(
                from_key=kp.public, to_key=other.public, ts="2026-09-07T07:00:00Z", text=""
            ),
            "body": base64.b64encode(plain).decode(),
        },
        kp,
    )
    msgmod.verify(m)
    over = msgmod.sign({**m, "body": base64.b64encode(plain[:-2] + b'y"}').decode()}, kp)
    with pytest.raises(VerifyError) as e:
        msgmod.verify(over)
    assert e.value.reason == "message.body.size"


# ---- 17. key directory separation -----------------------------------------------------


def test_keys_dir_may_not_live_in_state_scratch_or_package(tmp_path):
    root = tmp_path / "n"
    for kd, sd, sc in (
        (root / "state" / "keys", root / "state", root / "scratch"),
        (root / "scratch", root / "state", root / "scratch"),
        (root / "keys", root / "keys" / "state", root / "scratch"),
        (keys.PACKAGE_DIR / "never-created-keys", root / "state", root / "scratch"),
    ):
        with pytest.raises(ValueError):
            Node(state_dir=sd, keys_dir=kd, scratch_dir=sc)
        assert not kd.exists() and not sd.exists()
    # a symlink alias into the state dir is resolved
    (root / "state" / "k").mkdir(parents=True)
    (root / "alias").symlink_to(root / "state" / "k")
    with pytest.raises(ValueError):
        Node(state_dir=root / "state", keys_dir=root / "alias", scratch_dir=root / "scratch")
    with pytest.raises(ValueError):
        keys.check_separation(
            root / "state" / "k", state_dir=root / "state", scratch_dir=root / "scratch"
        )
    assert (
        keys.check_separation(root / "keys", state_dir=root / "state", scratch_dir=root / "scratch")
        == (root / "keys").resolve()
    )


# ---- 19. classification -------------------------------------------------------------


def test_classification_matches_the_readme(pair):
    a, b, clock, reports = pair
    # empty grant_ids with an action body: information, nothing executed
    m = msgmod.sign(
        msgmod.action(
            from_key=a.agent.public,
            to_key=b.agent.public,
            ts=a.ts(),
            action="fs.write",
            resource=b.executor().resource_for("info.txt"),
            params={"content": "x"},
            grant_ids=[],
        ),
        a.agent,
    )
    (rep,) = b.receive(bundlemod.make("message", m, cards=[a.card]))
    assert rep["object"]["outcome"] == "information" and not (b.scratch_dir / "info.txt").exists()
    assert latest(b)["outcome"] == "information"
    # non-empty grant_ids with an info body: refused
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "c.txt"), principal_statement=STATEMENT
    )
    m = msgmod.sign(
        msgmod.build(
            from_key=a.agent.public,
            to_key=b.agent.public,
            ts=a.ts(),
            body={"type": "info", "text": "not an action"},
            grant_ids=[g["grant_id"]],
        ),
        a.agent,
    )
    (rep,) = b.receive(bundlemod.make("message", m, cards=[a.card], grants=[g]))
    assert (
        rep["object"]["outcome"] == "refused:message.body.type"
        and latest(b)["outcome"] == "refused"
    )
    # a malformed body: refused and ledgered, whatever grant_ids says
    m = msgmod.sign(
        {
            **msgmod.info(from_key=a.agent.public, to_key=b.agent.public, ts=a.ts(), text=""),
            "body": base64.b64encode(b"\xff\xfe").decode(),
        },
        a.agent,
    )
    (rep,) = b.receive(bundlemod.make("message", m, cards=[a.card]))
    assert rep["object"]["outcome"] == "refused:message.body.json"
    # ledgered as a completion (refused, the reason in detail) so a lost ack for it
    # is rebuilt from the entry instead of the body being judged twice (round 3, F3)
    assert latest(b)["outcome"] == "refused" and latest(b)["detail"].startswith(
        "message.body.json:"
    )
    # a grant whose subject is another agent: refused with no_authorizing_grant, ledgered
    g_self = a.issue_grant(
        subject_card=a.card, scope=fs_write_scope(a, "mine.txt"), principal_statement=STATEMENT
    )
    (rep,) = b.receive(write_bundle(a, b, g_self, "mine.txt"))
    assert rep["object"]["outcome"] == "refused:no_authorizing_grant"
    assert latest(b)["outcome"] == "refused" and "grant.subject.agent" in latest(b)["detail"]
    assert not (b.scratch_dir / "mine.txt").exists()

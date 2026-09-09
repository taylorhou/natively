"""Round-3 gate findings (hw-rmhli): scratch-root identity (F1), recovery keyed to
inbound completions only (F2, F3), directory fsync (F4), embedded-parent identity
(F5), catch-up poll order (F6), the durable search cursor and held revocations (F7),
Gmail truncation (F8), prose repair before append (F9), one lock for every ledger
writer (F10), send failures (F11), replacement cards (F12), ULID overflow (F13),
non-finite numbers (F14), --dry-run over --out (F15), dropping a constrained
parameter in delegation (F16).

Test categories (see the README's residual paragraph): ORDERING — F4 (every fsync
recorded); FAILURE BEFORE — the prose-write failure (F9, second test), the send failures
(F11); RESTART RECOVERY — the crash-and-restart shapes of F2/F3 (an interrupted use, a
lost ack) and the lock test's second process (F10); the rest are behavioural (no
persistence failure)."""

from __future__ import annotations

import base64
import fcntl
import importlib.util
import json
import os
import stat
import threading
import time
from datetime import timedelta

import pytest
from ulid import ULID

from natively import ack as ackmod
from natively import bundle as bundlemod
from natively import card as cardmod
from natively import grant as grantmod
from natively import jsonsafe, keys
from natively import message as msgmod
from natively import node as nodemod
from natively.adapters.local import LocalWire
from natively.adapters.mail import (
    CATCHUP_FLOOR_S,
    CATCHUP_OVERLAP_S,
    GMAIL_API,
    WIRE_CHARS,
    MailWire,
    parse_thread_json,
)
from natively.errors import IntegrityError, StorageError, VerifyError
from natively.executor import Executor
from natively.ledger import Ledger, entry_hash
from natively.node import Node
from natively.objects import check_id, is_id, new_id

from .conftest import Clock, make_node, uid
from .test_cli import envs, run
from .test_hardening import STATEMENT, fs_write_scope, latest, wire, write_bundle
from .test_mail_adapter import FakeMail, pair_over_mail

KEY = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


@pytest.fixture
def pair(tmp_path):
    """Two nodes that trust each other, cards exchanged, lookups fresh (as in
    test_hardening)."""
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


def completions(node, msg_id):
    """Ledger entries that complete msg_id (the crash handler's own
    verify_failed:malformed entry for the interrupted receive is not one)."""
    return [
        e
        for e in node.ledger.entries()
        if e["msg_id"] == msg_id and e["outcome"] != "verify_failed:malformed"
    ]


def seen_of(node):
    p = node.state / "seen.json"
    return json.loads(p.read_text()) if p.exists() else {}


def held_revocations(node, rev_id):
    """The files held under revocations-pending/ for rev_id (one per body hash since
    round 4, MAJOR 2)."""
    return sorted((node.state / "revocations-pending").glob(f"{rev_id}-*.json"))


# ---- F1. the scratch root is the directory the node created, by identity ----------------


def test_scratch_root_swapped_for_a_symlink_between_receives_is_refused(pair):
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "one.txt"),
        principal_statement=STATEMENT,
        max_uses=3,
    )
    (r,) = b.receive(write_bundle(a, b, g, "one.txt", "first\n"))
    assert r["object"]["outcome"] == "applied"
    root = b.scratch_dir
    elsewhere = root.parent / "elsewhere"
    elsewhere.mkdir()
    root.rename(root.parent / "moved")
    root.symlink_to(elsewhere)
    (r,) = b.receive(write_bundle(a, b, g, "one.txt", "second\n"))  # a FRESH executor per receive
    assert r["object"]["outcome"] == "refused:executor.scratch"
    assert latest(b)["outcome"] == "refused" and "executor.scratch" in latest(b)["detail"]
    assert list(elsewhere.iterdir()) == []
    assert (root.parent / "moved" / "one.txt").read_text() == "first\n"
    # the recorded identity is the directory itself: moved back, it is the root again
    root.unlink()
    (root.parent / "moved").rename(root)
    (r,) = b.receive(write_bundle(a, b, g, "one.txt", "third\n"))
    assert r["object"]["outcome"] == "applied" and (root / "one.txt").read_text() == "third\n"
    # a different directory at the same path (same name, new inode) is refused too
    root.rename(root.parent / "moved")
    root.mkdir()
    (r,) = b.receive(write_bundle(a, b, g, "one.txt", "fourth\n"))
    assert r["object"]["outcome"] == "refused:executor.scratch"
    assert list(root.iterdir()) == []


def test_node_refuses_a_symlinked_scratch_root_at_construction(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "scratch").symlink_to(real)
    keys.generate_all(tmp_path / "keys")
    with pytest.raises(ValueError) as e:
        Node(
            state_dir=tmp_path / "state",
            keys_dir=tmp_path / "keys",
            scratch_dir=tmp_path / "scratch",
        )
    assert "scratch root" in str(e.value)
    ex = Executor(KEY, tmp_path / "plain")
    assert ex.root_identity == (
        os.stat(tmp_path / "plain").st_dev,
        os.stat(tmp_path / "plain").st_ino,
    )
    assert ex.scratch_root == tmp_path / "plain"  # the configured path, not resolved


# ---- F2. a peer's ack is never an inbound completion ------------------------------------


def test_unsolicited_ack_cannot_erase_an_interrupted_use(pair, monkeypatch):
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "u.txt"), principal_statement=STATEMENT
    )
    bundle = write_bundle(a, b, g, "u.txt")
    msg_id = bundle["object"]["msg_id"]
    real_append = b.ledger.append
    crashed = []

    def crash(**kw):
        if kw.get("outcome") == "applied" and not crashed:
            crashed.append(1)
            raise RuntimeError("power cut after the write")
        return real_append(**kw)

    monkeypatch.setattr(b.ledger, "append", crash)
    assert b.receive(bundle) == []
    assert seen_of(b)[msg_id]["status"] == "in_progress"
    # a signed ack from A naming that msg_id (B never sent such a message; no outbox
    # entry, so the signer check has nothing to bind it to): ledgered as an ack
    ack = ackmod.sign(
        ackmod.build(
            from_key=a.agent.public,
            to_key=b.agent.public,
            ts=a.ts(),
            in_reply_to=msg_id,
            outcome="information",
            ledger_head=a.ledger.head(),
            ledger_entry=a.ledger.head(),
        ),
        a.agent,
    )
    assert b.receive(bundlemod.make("ack", ack, cards=[a.card])) == []
    assert latest(b)["action"] == "out.ack" and latest(b)["msg_id"] == msg_id
    assert b.ledger.find_msg(msg_id) is None  # an ack entry is not a completion
    assert b.grant_uses(g) == (1, None)  # the reservation still counts
    (r,) = b.receive(write_bundle(a, b, g, "u.txt", "again\n"))
    assert r["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "grant.max_uses" in latest(b)["detail"]
    assert (b.scratch_dir / "u.txt").read_text() == "x\n"
    (r,) = b.receive(bundle)  # the interrupted message itself: failed, use consumed
    assert r["object"]["outcome"] == "failed:interrupted"
    assert b.ledger.verify() == b.ledger.head()


# ---- F3. any lost ack is rebuilt from the completion entry ------------------------------


def test_lost_ack_for_a_refusal_is_rebuilt_not_re_evaluated(pair, monkeypatch):
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "f.txt"), principal_statement=STATEMENT
    )
    bundle = write_bundle(a, b, g, "f.txt")
    msg_id = bundle["object"]["msg_id"]
    clock.tick(5 * b.poll_s + b.poll_s + 1)  # past max_check_interval_s + grace: stale
    real_sign = ackmod.sign
    crashed = []

    def crash(a_, kp):
        if not crashed:
            crashed.append(1)
            raise RuntimeError("power cut before the ack")
        return real_sign(a_, kp)

    monkeypatch.setattr(nodemod.ackmod, "sign", crash)
    assert b.receive(bundle) == []
    led = b.ledger.find_msg(msg_id)
    assert led["outcome"] == "refused" and "revocation.stale" in led["detail"]
    assert msg_id not in seen_of(b)  # no reservation (nothing ran), no ack
    b.mark_lookup_ok()  # freshness restored: a re-evaluation would now EXECUTE
    (r,) = b.receive(bundle)
    assert r["object"]["outcome"] == "refused:no_authorizing_grant"
    assert r["object"]["ledger_entry"] == entry_hash(led)
    assert not (b.scratch_dir / "f.txt").exists()
    assert len(completions(b, msg_id)) == 1
    assert any("ack was lost; rebuilding" in x for x in reports)
    (r2,) = b.receive(bundle)  # now the stored ack
    assert r2["object"] == r["object"]
    # information: same rule
    info = a.compose_info(b.card, "hi")
    crashed.clear()
    assert b.receive(info) == []
    (r,) = b.receive(info)
    assert r["object"]["outcome"] == "information"
    assert len(completions(b, info["object"]["msg_id"])) == 1
    # a malformed body: refused, ledgered as a completion, the same ack rebuilt
    m = msgmod.sign(
        {
            **msgmod.info(from_key=a.agent.public, to_key=b.agent.public, ts=a.ts(), text=""),
            "body": base64.b64encode(b"\xff\xfe").decode(),
        },
        a.agent,
    )
    bad = bundlemod.make("message", m, cards=[a.card])
    crashed.clear()
    assert b.receive(bad) == []
    (r,) = b.receive(bad)
    assert r["object"]["outcome"] == "refused:message.body.json"
    assert len(completions(b, m["msg_id"])) == 1


# ---- F4. renames are made durable with a directory fsync ---------------------------------


def test_state_writes_and_the_executor_fsync_the_directory(tmp_path, monkeypatch):
    events: list = []
    real_fsync, real_replace = os.fsync, os.replace

    def fsync(fd):
        events.append("dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
        real_fsync(fd)

    def replace(*a, **kw):
        events.append("replace")
        return real_replace(*a, **kw)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "replace", replace)
    nodemod._write_json(tmp_path / "seen.json", {"msg": {"status": "in_progress"}})
    assert events == ["file", "replace", "dir"]
    events.clear()
    ex = Executor(KEY, tmp_path / "scratch")
    ex.apply("fs.write", ex.resource_for("a.txt"), {"content": "x"})
    assert events == ["file", "replace", "dir"]
    assert (tmp_path / "scratch" / "a.txt").read_text() == "x"


# ---- F5. an embedded parent is held to the parent on file ---------------------------------


def test_embedded_parent_variant_cannot_lift_the_stored_parents_budget(tmp_path):
    clock = Clock()
    a = make_node(tmp_path, "a", clock)
    b = make_node(tmp_path, "b", clock)
    a.pin(b.principal.public, "b")
    b.pin(a.principal.public, "a")
    lw = LocalWire()
    lw.deliver(a, b, a.compose_card())
    lw.deliver(b, a, b.compose_card())
    b.mark_lookup_ok()
    parent = a.issue_grant(
        subject_card=a.card,
        audience=b.host.public,
        scope=fs_write_scope(b, "p.txt", regex="^[a-z\n]+$"),
        principal_statement="A may have B write p.txt once in all.",
        max_uses=1,
    )
    tighter = [
        {
            "action": "fs.write",
            "resource": b.executor().resource_for("p.txt"),
            "params": {
                "keys": ["content"],
                "values": {"content": {"regex": "^[a-z\n]+$", "in": ["ok\n"]}},
            },
        }
    ]

    def child(p):
        return a.delegate_grant(
            parent=p, subject_card=b.card, principal_statement="one word", scope=tighter
        )

    # B has never seen the parent on its own: the first legitimate child puts it on
    # file (under grants-embedded/: held to, never executable — round 4, MINOR 9)
    good1 = child(parent)
    assert b.load_grant_any(parent["grant_id"]) is None
    (r,) = lw.deliver(a, b, write_bundle(a, b, good1, "p.txt", "ok\n"))
    assert r["object"]["outcome"] == "applied"
    assert b.load_grant_any(parent["grant_id"]) == parent
    assert b.load_grant(parent["grant_id"]) is None
    # a validly re-signed parent VARIANT (same id, limit 99) embedded in a new child
    variant = grantmod.sign({**parent, "max_uses": 99}, a.principal)
    grantmod.authenticate(variant, pinned=b.pinned)
    bad = child(variant)
    (r,) = lw.deliver(a, b, write_bundle(a, b, bad, "p.txt", "ok\n"))
    assert r["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "attached copy failed verification" in latest(b)["detail"]
    assert [e["outcome"] for e in b.ledger.entries()].count("verify_failed:grant.id_conflict") == 1
    assert b.load_grant_any(parent["grant_id"]) == parent
    assert b.load_grant_any(bad["grant_id"]) is None
    # a second legitimate child: the family budget (one use) is spent
    good2 = child(parent)
    (r,) = lw.deliver(a, b, write_bundle(a, b, good2, "p.txt", "ok\n"))
    assert r["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "grant.parent.max_uses" in latest(b)["detail"]
    assert b.grant_uses(parent, family=True) == (1, None)


# ---- F6. a complete catch-up poll authorizes what it carried -----------------------------


def test_first_complete_poll_authorizes_the_actions_it_carries(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    a.import_card(b.card)  # B's card reached A out of band; B has never polled
    assert b.revocations.last_checked() is None
    wa.send(a.compose_card())
    g = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "catch.txt", regex=None),
        principal_statement="write catch.txt once",
    )
    wa.send(write_bundle(a, b, g, "catch.txt", "caught up\n"))
    s = wb.poll_once()
    assert s["applied"] == 2 and s["complete"] is True and s["replies"] == 1 and not s["errors"]
    assert (b.scratch_dir / "catch.txt").read_text() == "caught up\n"
    assert latest(b)["outcome"] == "applied"
    assert b.revocations.last_checked() == clock()
    # an INCOMPLETE first poll leaves the clock alone and the action fails closed
    a2, b2, wa2, wb2, fake2, _ = pair_over_mail(tmp_path / "two", clock)
    a2.import_card(b2.card)
    wa2.send(a2.compose_card())
    g2 = a2.issue_grant(
        subject_card=b2.card,
        scope=fs_write_scope(b2, "no.txt", regex=None),
        principal_statement="write no.txt once",
    )
    wa2.send(write_bundle(a2, b2, g2, "no.txt", "x\n"))
    fake2.endless_pages = True  # the search never stops paging: incomplete at the cap
    s = wb2.poll_once()
    assert s["applied"] == 2 and s["complete"] is False
    assert latest(b2)["outcome"] == "refused" and "revocation.never_checked" in latest(b2)["detail"]
    assert not (b2.scratch_dir / "no.txt").exists()


# ---- F7a. the search window is anchored to the last complete fetch ------------------------


def test_search_window_is_anchored_to_the_last_complete_fetch(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    t0 = clock()
    assert wa.cursor() is None
    assert wa.poll_once()["complete"] is True
    floor = int((t0 - timedelta(seconds=CATCHUP_FLOOR_S)).timestamp())
    assert fake.queries[-1] == f"subject:(Natively v0 wire) after:{floor}"
    assert wa.cursor() == t0
    # a five-day outage, then an INCOMPLETE fetch: the window reaches back to before
    # the outage and the cursor does not move
    clock.tick(5 * 24 * 3600)
    fake.endless_pages = True
    n = len(fake.queries)
    assert wa.poll_once()["complete"] is False
    # the pass's FIRST query is the whole window (round 21 halves an overflowing
    # slice, so the later queries of the pass carry `before:`)
    assert fake.queries[n] == (
        f"subject:(Natively v0 wire) "
        f"after:{int((t0 - timedelta(seconds=CATCHUP_OVERLAP_S)).timestamp())}"
    )
    assert wa.cursor() == t0
    fake.endless_pages = False
    assert wa.poll_once()["complete"] is True
    assert wa.cursor() == clock()
    # a fresh cursor still searches at least two days back
    clock.tick(3600)
    wa.poll_once()
    assert fake.queries[-1].endswith(
        f"after:{int((clock() - timedelta(seconds=CATCHUP_FLOOR_S)).timestamp())}"
    )
    # a failed fetch moves nothing
    cur = wa.cursor()
    clock.tick(3600)
    broken = MailWire(
        a, runner=lambda argv: __import__("subprocess").CompletedProcess(argv, 1, "", "x")
    )
    assert broken.poll_once()["errors"] and broken.cursor() == cur


# ---- F7b. a revocation from a not-yet-pinned principal is held and replayed --------------


def test_revocation_from_an_unpinned_principal_is_held_and_replayed_on_pin(tmp_path):
    clock = Clock()
    reports: list[str] = []
    a = make_node(tmp_path, "a", clock, reports=reports)
    b = make_node(tmp_path, "b", clock, reports=reports)
    a.pin(b.principal.public, "b")
    a.import_card(b.card)
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "rv.txt"), principal_statement=STATEMENT
    )
    rev = a.revoke(grants=[g["grant_id"]], principal_statement="never mind")
    assert b.receive(a.compose_revocation(rev)) == []  # B has not pinned A yet
    (held,) = held_revocations(b, rev["rev_id"])
    assert json.loads(held.read_text()) == rev
    assert latest(b)["action"] == "revocation.received" and latest(b)["outcome"] == "unpinned"
    assert b.revocations.grant_revoked_by(g["grant_id"], a.principal.public) is None
    assert any("held in revocations-pending" in x for x in reports)
    b.pin(a.principal.public, "a")
    assert not held.exists()
    assert (
        b.revocations.grant_revoked_by(g["grant_id"], a.principal.public)["rev_id"] == rev["rev_id"]
    )
    replay = [e for e in b.ledger.entries() if e["action"] == "revocation.replayed"]
    assert len(replay) == 1 and replay[0]["outcome"] == "recorded"
    b.mark_lookup_ok()
    (r,) = b.receive(write_bundle(a, b, g, "rv.txt"))
    assert r["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "grant.revoked" in latest(b)["detail"] and not (b.scratch_dir / "rv.txt").exists()
    # a revocation whose signature does not hold against the principal key it names
    # is refused at RECEIVE time (unpinned is untrusted, not unverifiable): nothing is
    # held, nothing replays at pin (round 4, MAJOR 2)
    c = make_node(tmp_path, "c", clock, reports=reports)
    forged = {**rev, "principal_statement": "tampered"}
    assert c.receive(bundlemod.make("revocation", forged)) == []
    assert latest(c)["outcome"] == "verify_failed:revocation.sig.invalid"
    assert held_revocations(c, rev["rev_id"]) == []
    c.pin(a.principal.public, "a")
    assert not any(e["action"] == "revocation.replayed" for e in c.ledger.entries())
    assert c.revocations.entries() == []


def test_over_mail_the_held_revocations_mail_is_seen_and_replayed_once(tmp_path):
    clock = Clock()
    a = make_node(tmp_path, "citadel-mayor", clock)
    b = make_node(tmp_path, "instinct", clock)
    a.config.update({"self_email": "taylor@houmanoids.com", "peer_email": "taylor@teale.com"})
    b.config.update(
        {
            "self_email": "taylor@teale.com",
            "peer_email": "taylor@houmanoids.com",
            "peer_addresses": ["taylor@houmanoids.com"],
        }
    )
    # the addresses a poll reads from come from config.json (the typed load, every
    # poll): the file carries what the node holds, as on a configured node
    a.save_config()
    b.save_config()
    a.pin(b.principal.public, "b")  # B does NOT pin A yet
    a.import_card(b.card)
    fake = FakeMail()
    wa = MailWire(a, runner=fake.runner_for("taylor@houmanoids.com"))
    wb = MailWire(b, runner=fake.runner_for("taylor@teale.com"))
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "m.txt"), principal_statement=STATEMENT
    )
    rev = a.revoke(grants=[g["grant_id"]], principal_statement="no")
    wa.send(a.compose_revocation(rev))
    s = wb.poll_once()
    assert s["applied"] == 1 and s["complete"] is True
    assert len(json.loads((b.state / "seen-mail.json").read_text())) == 1  # marked seen
    assert len(held_revocations(b, rev["rev_id"])) == 1
    b.pin(a.principal.public, "a")
    assert b.revocations.grant_revoked_by(g["grant_id"], a.principal.public) is not None
    assert wb.poll_once()["applied"] == 0  # nothing re-read, nothing re-applied
    assert [e["action"] for e in b.ledger.entries()].count("revocation.replayed") == 1


# ---- F8. the helper says when it cut a body; the adapter asks for the wrapped size --------


def _gmail_api():
    spec = importlib.util.spec_from_file_location("gmail_api", GMAIL_API)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_helper_flags_a_cut_body_and_the_adapter_asks_for_the_wrapped_size():
    api = _gmail_api()
    head = '{"natively":"v0","kind":"card","object":{"pad":"'
    tail = '"},"cards":[],"grants":[]}'
    pad = bundlemod.MAX_WIRE_BYTES - len(head) - len(tail)
    b = json.loads(head + "x" * pad + tail)
    text = bundlemod.encode(b)  # the largest bundle, wrapped, as it goes on the wire
    assert len(text) == bundlemod.MAX_WIRE_TEXT_CHARS == 708266  # the gate's figure
    m = {
        "id": "m1",
        "threadId": "t1",
        "labelIds": ["INBOX"],
        "payload": {
            "mimeType": "text/plain",
            "body": {"data": base64.urlsafe_b64encode(text.encode()).decode()},
            "headers": [
                {"name": "From", "value": "taylor@teale.com"},
                {"name": "Subject", "value": "Natively v0 wire"},
            ],
        },
    }
    row = api.msg_row(m, WIRE_CHARS)  # what the adapter asks for
    assert row["truncated"] is False
    assert bundlemod.decode(row["body"])["object"]["pad"] == "x" * pad
    old = api.msg_row(m, bundlemod.MAX_WIRE_B64_CHARS + 4096)  # round 2's --chars
    assert old["truncated"] is True
    with pytest.raises(VerifyError):
        bundlemod.decode(old["body"])
    n = len(text.strip())  # the helper's own slice (strip drops the trailing newline)
    assert api.msg_row(m, n)["truncated"] is False and api.msg_row(m, n - 1)["truncated"] is True
    assert n == bundlemod.MAX_WIRE_TEXT_CHARS - 1 < WIRE_CHARS
    (rm,) = parse_thread_json(json.dumps([{**old, "date": "", "to": "y"}]))
    assert rm.truncated is True and rm.gmail_id == "m1"
    (rm,) = parse_thread_json(json.dumps([{**row, "date": "", "to": "y"}]))
    assert rm.truncated is False


def test_truncated_peer_mail_is_a_terminal_rejection_never_re_fetched(tmp_path):
    """Since round 21 (Z4) a peer body the helper CUT at --chars is demonstrably over
    the wire's text bound — no bundle this node accepts is that long — so it is
    rejected ONCE by name (the ledger's wire.oversize row, the seen note), the fetch
    complete and the clocks moving; it is never fetched again, whatever the helper
    reports later. (Before round 21 the cut row was a transient fetch error, read
    again on every poll forever; a body the helper could not OBTAIN still is —
    tests/test_gate_round21.py.)"""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    reports: list[str] = []
    a.report = reports.append
    gid = fake.add("taylor@houmanoids.com", "taylor@teale.com", bundlemod.encode(b.compose_card()))
    fake.truncate.add(gid)
    s = wa.poll_once()
    assert s["applied"] == 0 and s["rejected"] == 1 and s["complete"] is True
    assert len(s["errors"]) == 1 and "rejected (wire.oversize)" in s["errors"][0]
    assert _seen_of(a)[gid].startswith("oversized:")
    assert a.revocations.last_checked() == clock() and wa.cursor() == clock()
    assert [e["action"] for e in a.ledger.entries() if e["action"].startswith("wire.")] == [
        "wire.oversize"
    ]
    assert any("rejected" in r and "never re-fetched" in r for r in reports)
    fake.truncate.clear()
    s = wa.poll_once()
    assert s["applied"] == 0 and s["rejected"] == 0 and s["complete"] is True
    assert a.card_for_key(b.agent.public) is None


def _seen_of(node):
    return json.loads((node.state / "seen-mail.json").read_text())


# ---- F9. the prose mirror is whole before another entry lands ----------------------------


def test_append_repairs_a_trailing_gap_first_and_refuses_an_interior_mismatch(
    tmp_path, monkeypatch
):
    led = Ledger(tmp_path / "l.jsonl")

    def app(action):
        return led.append(
            ts="2026-09-07T07:00:00Z",
            actor="a",
            grant_id=None,
            action=action,
            params_hash=None,
            outcome="information",
        )

    app("x")
    real = led._append_prose
    boom = []

    def fail_once(lines):
        if not boom:
            boom.append(1)
            raise OSError("disk full")
        return real(lines)

    monkeypatch.setattr(led, "_append_prose", fail_once)
    with pytest.raises(OSError):
        app("y")
    assert len(led.entries()) == 2 and len(led._prose_lines()) == 1
    app("z")  # the gap is regenerated BEFORE z is written: no interior mismatch
    assert len(led._prose_lines()) == 3 and led.verify() == led.head()
    assert led.repair() == 0
    # an interior mismatch: the append is refused and neither file changes
    lines = led.prose_path.read_text().splitlines()
    lines[0] = "the operator approved everything " + lines[0][-14:]
    led.prose_path.write_text("\n".join(lines) + "\n")
    before = (led.path.read_bytes(), led.prose_path.read_bytes())
    with pytest.raises(IntegrityError) as e:
        app("w")
    assert e.value.reason == "ledger.prose.mismatch" and "ledger repair" in e.value.detail
    assert (led.path.read_bytes(), led.prose_path.read_bytes()) == before


def test_receive_after_a_prose_write_failure_leaves_a_verifiable_ledger(pair, monkeypatch):
    a, b, clock, reports = pair
    real = b.ledger._append_prose
    boom = []

    def fail_once(lines):
        if not boom:
            boom.append(1)
            raise OSError("disk full")
        return real(lines)

    monkeypatch.setattr(b.ledger, "_append_prose", fail_once)
    info = a.compose_info(b.card, "hello")
    # the info.received append failed after its JSONL line: a LOCAL storage failure,
    # raised as StorageError (round 4, MAJOR 4) — not ledgered as malformed input,
    # since the ledger is what failed; the mirror is short by that one trailing line
    with pytest.raises(StorageError):
        b.receive(info)
    assert (
        latest(b)["action"] == "info.received" and latest(b)["msg_id"] == info["object"]["msg_id"]
    )
    with pytest.raises(IntegrityError) as e:
        b.ledger.verify()
    assert e.value.reason == "ledger.prose.count"
    assert len(b.ledger._prose_lines()) == len(b.ledger.entries()) - 1
    # the completion entry answers the re-delivery (nothing re-evaluated), and the
    # next append repairs the gap first, so everything verifies again
    (r,) = b.receive(info)
    assert r["object"]["outcome"] == "information"
    (r2,) = b.receive(a.compose_info(b.card, "again"))
    assert r2["object"]["outcome"] == "information"
    assert b.ledger.verify() == b.ledger.head()
    assert len(b.ledger._prose_lines()) == len(b.ledger.entries())


# ---- F10. one re-entrant lock for every ledger writer ------------------------------------


def _probe(node) -> str:
    fd = os.open(node.state / ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return "free"
    except BlockingIOError:
        return "held"
    finally:
        os.close(fd)


def test_lock_is_reentrant_and_every_ledger_writer_holds_it(pair, monkeypatch):
    a, b, clock, reports = pair
    with b._locked():
        with b._locked():
            assert b._lock_depth == 2 and _probe(b) == "held"
        assert b._lock_depth == 1 and _probe(b) == "held"
    assert b._lock_depth == 0 and _probe(b) == "free"
    events: list[str] = []
    real_flock = fcntl.flock

    def spy(fd, op):
        events.append("lock" if op == fcntl.LOCK_EX else "unlock")
        real_flock(fd, op)

    monkeypatch.setattr(nodemod.fcntl, "flock", spy)
    real_append = b.ledger.append

    def app(**kw):
        events.append(f"append:{kw['action']}")
        return real_append(**kw)

    monkeypatch.setattr(b.ledger, "append", app)
    b.revoke(grants=[uid("grt")], principal_statement="x")
    assert events == ["lock", "append:revocation.issued", "unlock"]
    events.clear()
    b.config["extensions"]["standing_denial"] = True
    b.save_config()  # round 19: the flags are read from config.json at every use
    events.clear()
    b.deny(deny=[{"action": "fs.write", "resource": "host:*:x"}], principal_statement="never")
    assert events == ["lock", "append:denial.issued", "unlock"]
    events.clear()
    b.mark_lookup_ok()
    assert events == ["lock", "unlock"]
    events.clear()
    bundle = b.compose_info(a.card, "x")
    msg_id = bundle["object"]["msg_id"]
    b.outbox_record(bundle)
    clock.tick(2 * b.poll_s)
    assert [x["msg_id"] for x in b.outbox_due()] == [msg_id]
    b.outbox_advance(msg_id)
    b.outbox_mark_acked(msg_id)
    assert events == ["lock", "unlock"] * 4
    events.clear()
    b.pin(keys.KeyPair.generate().public, "nobody")
    assert events == ["lock", "unlock"]
    events.clear()
    b.receive(a.compose_info(b.card, "in"))  # receive: one lock around every append
    assert events[0] == "lock" and events[-1] == "unlock" and events.count("lock") == 1
    assert any(x.startswith("append:") for x in events)


def test_two_node_instances_on_one_state_dir_serialize(pair):
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "s.txt"),
        principal_statement=STATEMENT,
        max_uses=2,
    )
    b2 = Node(
        state_dir=b.state,
        keys_dir=b.keys_dir,
        scratch_dir=b.scratch_dir,
        clock=clock,
        report=reports.append,
    )
    timeline: list[tuple[str, str, float]] = []

    class Slow:
        def __init__(self, tag, node):
            self.tag, self.inner = (
                tag,
                Executor(node.host.public, node.scratch_dir, node.scratch_identity),
            )

        def apply(self, *args):
            timeline.append((self.tag, "start", time.monotonic()))
            time.sleep(0.4)
            r = self.inner.apply(*args)
            timeline.append((self.tag, "end", time.monotonic()))
            return r

    one, two = write_bundle(a, b, g, "s.txt", "1\n"), write_bundle(a, b, g, "s.txt", "2\n")
    b.executor = lambda: Slow("one", b)
    b2.executor = lambda: Slow("two", b2)
    results: dict[str, list] = {}

    def go(tag, node, bundle):
        results[tag] = node.receive(bundle)

    t1 = threading.Thread(target=go, args=("one", b, one))
    t1.start()
    time.sleep(0.1)
    t2 = threading.Thread(target=go, args=("two", b2, two))
    t2.start()
    t1.join()
    t2.join()
    assert results["one"][0]["object"]["outcome"] == "applied"
    assert results["two"][0]["object"]["outcome"] == "applied"
    by = {(tag, what): t for tag, what, t in timeline}
    assert by[("one", "end")] <= by[("two", "start")]  # two waited for one's whole receive
    assert b.ledger.verify() == b.ledger.head() and b.grant_uses(g) == (2, None)
    assert (b.scratch_dir / "s.txt").read_text() == "2\n"


# ---- F11. a send failure is reported, counted, and never fatal ---------------------------


def test_send_failures_do_not_end_the_poll_and_acks_are_held_for_the_next_poll(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    reports: list[str] = []
    b.report = reports.append
    wa.send(a.compose_card())
    wb.send(b.compose_card())
    wb.poll_once()
    wa.poll_once()
    wa.send(a.compose_info(b.card, "one"))
    wa.send(a.compose_info(b.card, "two"))
    fake.fail_sends = True
    s = wb.poll_once()
    assert s["applied"] == 2 and s["replies"] == 0 and len(s["errors"]) == 2
    assert s["complete"] is True
    held = sorted((b.state / "pending-replies").glob("*.json"))
    assert len(held) == 2 and all(json.loads(p.read_text())["kind"] == "ack" for p in held)
    assert len(seen_of(b)) == 2  # both acks stored; the peer would get them on a re-send
    assert any("ack send failed, kept for the next poll" in r for r in reports)
    assert wa.poll_once()["applied"] == 0  # nothing reached A
    s = wb.poll_once()  # still down: the held acks stay held, errors reported again
    assert (
        s["replies"] == 0
        and len(s["errors"]) == 2
        and len(list((b.state / "pending-replies").glob("*.json"))) == 2
    )
    fake.fail_sends = False
    s = wb.poll_once()
    assert s["replies"] == 2 and not s["errors"]
    assert list((b.state / "pending-replies").glob("*.json")) == []
    s = wa.poll_once()
    assert s["applied"] == 2 and {x["status"] for x in a.outbox()} == {"acked"}


def test_failed_resend_spends_no_attempt(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    reports: list[str] = []
    a.report = reports.append
    wb.send(b.compose_card())
    wa.poll_once()
    P = a.poll_s
    wa.send(a.compose_info(b.card, "anyone?"))
    (x,) = a.outbox()
    msg_id, due = x["msg_id"], x["due"]
    clock.tick(2 * P)
    fake.fail_sends = True
    s = wa.poll_once()
    assert s["resent"] == 0 and len(s["errors"]) == 1 and msg_id in s["errors"][0]
    (x,) = a.outbox()
    assert x["attempts"] == 1 and x["due"] == due and x["status"] == "pending"
    assert any("attempt not counted" in r for r in reports)
    fake.fail_sends = False
    s = wa.poll_once()
    assert s["resent"] == 1
    (x,) = a.outbox()
    assert x["attempts"] == 2
    assert nodemod.parse(x["due"]) == clock() + timedelta(seconds=4 * P)
    # undelivered is reached by deadline, never by failed sends
    for tick in (4 * P, 8 * P):
        clock.tick(tick)
        wa.poll_once()
    fake.fail_sends = True
    clock.tick(16 * P)
    s = wa.poll_once()
    assert s["undelivered"] == 1 and a.outbox()[0]["status"] == "undelivered"
    assert a.outbox()[0]["attempts"] == 4


# ---- F12. a replacement card wins over a revoked one on the same agent key ---------------


def test_replacement_card_wins_over_a_revoked_one(pair, monkeypatch):
    a, b, clock, reports = pair
    old_hash = a.card_hash
    rev = a.revoke(cards=[old_hash], principal_statement="rotated")
    b.receive(a.compose_revocation(rev))
    assert b.receive(a.compose_info(b.card, "old")) == []
    assert latest(b)["outcome"] == "verify_failed:message.sender.revoked"
    clock.tick(1)
    new = a.make_card(agent_name="a", node_name="a-node", principal_name="a-principal (stand-in)")
    assert cardmod.card_hash(new) != old_hash and new["agent"]["key"] == a.agent.public
    b.receive(a.compose_card())
    real = b.trusted_cards

    def revoked_first(*, include_revoked=False):  # the listing order the round-2 code tripped on
        cs = real(include_revoked=include_revoked)
        return sorted(cs, key=lambda c: 0 if cardmod.card_hash(c) == old_hash else 1)

    monkeypatch.setattr(b, "trusted_cards", revoked_first)
    assert cardmod.card_hash(b.card_for_key(a.agent.public, include_revoked=True)) == old_hash
    assert b._sender_card(a.agent.public, "message") == new
    (r,) = b.receive(a.compose_info(b.card, "new"))
    assert r["object"]["outcome"] == "information"
    bundle = b.compose_info(a.card, "and you?")
    b.outbox_record(bundle)
    (ack,) = a.receive(bundle)
    b.receive(ack)
    assert b.outbox()[-1]["status"] == "acked"
    # with no unrevoked card at all, revoked is still the answer
    rev2 = a.revoke(cards=[cardmod.card_hash(new)], principal_statement="all of them")
    b.receive(a.compose_revocation(rev2))
    # A's principal is pinned on B: the revocation is recorded, in A's principal's name
    assert latest(b)["action"] == "revocation.received" and latest(b)["outcome"] == "recorded"
    assert latest(b)["actor"] == a.principal.public[:32] and rev2["rev_id"] in latest(b)["detail"]
    assert b.revocations.card_revoked_by(cardmod.card_hash(new), a.principal.public) is not None
    with pytest.raises(VerifyError) as e:
        b._sender_card(a.agent.public, "message")
    assert e.value.reason == "message.sender.revoked"


# ---- F13. ULID overflow ----------------------------------------------------------------


def test_ulid_first_character_is_bounded():
    top = "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"  # the maximum 128-bit value
    assert check_id("msg_" + top, "id", "msg_") == "msg_" + top
    assert ULID.from_str(top)
    for bad in ("8" + "0" * 25, "Z" * 26, "8ZZZZZZZZZZZZZZZZZZZZZZZZZ"):
        with pytest.raises(VerifyError) as e:
            check_id("msg_" + bad, "id", "msg_")
        assert e.value.reason == "id.format"
        assert not is_id("grt_" + bad, "grt_")
        with pytest.raises(ValueError):
            ULID.from_str(bad)
    for _ in range(200):
        check_id(new_id("ack"), "id", "ack_")


# ---- F14. non-finite numbers ----------------------------------------------------------


def test_nonfinite_numbers_are_rejected_at_parse(pair):
    a, b, clock, reports = pair
    for lit in ("1e999", "-1e999", "1E400"):
        doc = f'{{"natively":"v0","kind":"card","object":{{"n":{lit}}},"cards":[],"grants":[]}}'
        with pytest.raises(VerifyError) as e:
            bundlemod.decode(wire(doc))
        assert e.value.reason == "wire.json" and "finite" in e.value.detail
    assert jsonsafe.loads(b'{"n":1e300,"m":-2.5}', "x", max_bytes=100) == {"n": 1e300, "m": -2.5}
    m = a.compose_info(b.card, "x")["object"]
    body = base64.b64encode(
        b'{"type":"action","action":"fs.write","resource":"host:x","params":{"n":1e999}}'
    ).decode()
    m2 = msgmod.sign({**m, "body": body}, a.agent)
    with pytest.raises(VerifyError) as e:
        msgmod.decode_body(m2)
    assert e.value.reason == "message.body.json" and "finite" in e.value.detail
    (r,) = b.receive(bundlemod.make("message", m2, cards=[a.card]))
    assert r["object"]["outcome"] == "refused:message.body.json"
    assert latest(b)["outcome"] == "refused" and "message.body.json" in latest(b)["detail"]


# ---- F15. --dry-run wins over --out ---------------------------------------------------


def test_dry_run_wins_over_out(tmp_path, capsys):
    A, B = envs(tmp_path, "a"), envs(tmp_path, "b")
    for env, name in ((A, "citadel-mayor"), (B, "instinct")):
        assert run(env, "keygen", capsys=capsys)[0] == 0
        assert run(env, "card", "--agent-name", name, "--node-name", name, capsys=capsys)[0] == 0
    b_pub = (tmp_path / "b-keys" / "principal-standin.pub").read_text().strip()
    assert run(A, "pin", b_pub, "--name", "instinct-principal", capsys=capsys)[0] == 0
    fb = tmp_path / "b-card.txt"
    assert run(B, "send", "--card", "--out", str(fb), capsys=capsys)[0] == 0
    assert run(A, "poll", "--file", str(fb), capsys=capsys)[0] == 0
    out = tmp_path / "dry.txt"
    rc, o = run(
        A, "send", "--to", "instinct", "--info", "hi", "--dry-run", "--out", str(out), capsys=capsys
    )
    assert rc == 0 and o.out.startswith("DRY RUN") and "nothing recorded" in o.out
    assert bundlemod.decode(out.read_text())["kind"] == "message"  # written for inspection
    rc, o = run(A, "outbox", capsys=capsys)
    assert rc == 0 and o.out.strip() == ""  # nothing recorded, nothing to re-send
    assert not (tmp_path / "a-state" / "outbox.json").exists()
    # without --dry-run the same --out records the export, as before
    assert (
        run(A, "send", "--to", "instinct", "--info", "hi", "--out", str(out), capsys=capsys)[0] == 0
    )
    rc, o = run(A, "outbox", capsys=capsys)
    assert "exported" in o.out


# ---- F16. delegation may drop a constrained parameter ---------------------------------


def test_delegation_may_drop_a_constrained_parameter(pair):
    a, b, clock, reports = pair
    r = b.executor().resource_for("d.txt")
    parent = [
        {
            "action": "fs.write",
            "resource": r,
            "params": {"keys": ["content"], "values": {"content": {"regex": "^[a-z]+$"}}},
        }
    ]
    none = [{"action": "fs.write", "resource": r, "params": {"keys": [], "values": {}}}]
    kept = [{"action": "fs.write", "resource": r, "params": {"keys": ["content"], "values": {}}}]
    assert grantmod.is_strict_subset(none, parent)  # forbids the key: strictly tighter
    assert not grantmod.is_subset(kept, parent)  # keeps the key: must keep the constraint
    assert not grantmod.is_subset(parent, none)
    # through a real delegation: the chain verifies and the scope is what refuses
    pg = a.issue_grant(
        subject_card=a.card, audience=b.host.public, scope=parent, principal_statement="p"
    )
    child = a.delegate_grant(
        parent=pg, subject_card=b.card, scope=none, principal_statement="no parameters at all"
    )
    grantmod.verify(
        child,
        now=b.now(),
        subject_card=b.card,
        executor_keys=b.executor_keys,
        pinned=b.pinned,
    )
    (rep,) = b.receive(write_bundle(a, b, child, "d.txt", "abc"))
    assert rep["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "scope.no_match" in latest(b)["detail"] and "not_subset" not in latest(b)["detail"]

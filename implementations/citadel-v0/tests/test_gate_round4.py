"""Round-4 gate findings (hw-myvbh): crash consistency and durability ORDERING.
Post-commit executor failures consume the use (M1); a held revocation is verified
before it is held and never overwritten (M2); pin replays before it publishes trust,
and a startup sweep repairs the other order (M3); the feed and the sidecars are
durable before the cursor moves (M4); search pages are walked, with a cap (M5); the
CLI ledger verbs take the state lock (M6); outbound ledger entries have their own
namespace (m7); a chain may not repeat an id (m8); an embedded parent is never
executable (m9); an unterminated prose mirror (m10); pending replies flush before
the fetch and re-sends survive a fetch error (m11).

Test categories (see the README's residual paragraph): ORDERING — M4 (every fsync and
rename recorded, the order asserted), the state-write test in M1; FAILURE BEFORE — the
rename that raises before doing anything (M1, third test), the held-file and pin-write
failures in M2 and M3, m11; FAILURE AFTER — the directory fsync failing after the rename
(M1, first two tests); RESTART RECOVERY — the startup sweep (M3), the CLI verbs on a
crashed state (M6, m10); the rest are behavioural (no persistence failure)."""

from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import threading
import time

import pytest

from natively import ack as ackmod
from natively import bundle as bundlemod
from natively import cli as climod
from natively import grant as grantmod
from natively import message as msgmod
from natively import node as nodemod
from natively import revocation as revmod
from natively.adapters.mail import CATCHUP_FLOOR_S, MAX_PAGES, PAGE_CAP, SEARCH_MAX, MailWire
from natively.cli import main
from natively.errors import IntegrityError, PostCommitError
from natively.executor import Executor
from natively.ledger import OUT_ACK, OUT_SEND, Ledger, entry_hash
from natively.node import Node

from .conftest import Clock, make_node, uid
from .test_gate_round3 import KEY, _gmail_api, completions, held_revocations, pair, seen_of
from .test_hardening import STATEMENT, fs_write_scope, latest, write_bundle
from .test_mail_adapter import FakeMail, pair_over_mail

__all__ = ["pair"]  # the fixture is re-exported for this module's tests


def _fsync_raising_for(identity):
    """An os.fsync that fails for the directory whose (dev, ino) is `identity` and
    works everywhere else (the reservation's own directory fsync must succeed)."""
    real = os.fsync

    def fsync(fd):
        st = os.fstat(fd)
        if stat.S_ISDIR(st.st_mode) and (st.st_dev, st.st_ino) == identity:
            raise OSError(5, "Input/output error")
        real(fd)

    return fsync


def _replace_raising_for_dirfd():
    real = os.replace

    def replace(*a, **kw):
        if "src_dir_fd" in kw:
            raise OSError(28, "No space left on device")
        return real(*a, **kw)

    return replace


DEFAULT_REGEX = "^[ -~\n]+$"  # fs_write_scope's default (a literal newline: no \n escape)


def tighter_scope(b, name, content="ok\n"):
    """A strict subset of fs_write_scope(b, name): the same regex (a delegated regex
    must equal the parent's) plus an `in` constraint."""
    return fs_write_scope(b, name, content={"regex": DEFAULT_REGEX, "in": [content]})


def action_bundle(a, b, grant, name, content="ok\n", *, attach=True):
    """A message from A to B naming `grant` (any grant dict, whether or not A has it
    on file), the grant attached unless attach=False."""
    m = msgmod.sign(
        msgmod.action(
            from_key=a.agent.public,
            to_key=b.agent.public,
            ts=a.ts(),
            action="fs.write",
            resource=b.executor().resource_for(name),
            params={"content": content},
            grant_ids=[grant["grant_id"]],
        ),
        a.agent,
    )
    return bundlemod.make("message", m, cards=[a.card], grants=[grant] if attach else [])


# ---- M1. a failure AFTER the rename consumes the use -------------------------------------


def test_executor_distinguishes_pre_and_post_commit_failures(tmp_path, monkeypatch):
    ex = Executor(KEY, tmp_path / "scratch")
    monkeypatch.setattr(os, "fsync", _fsync_raising_for(ex.root_identity))
    with pytest.raises(PostCommitError) as e:
        ex.apply("fs.write", ex.resource_for("a.txt"), {"content": "x"})
    assert "directory fsync failed" in e.value.detail and isinstance(e.value.cause, OSError)
    assert (tmp_path / "scratch" / "a.txt").read_text() == "x"  # the side effect exists
    assert [p.name for p in (tmp_path / "scratch").iterdir()] == ["a.txt"]  # no temp left
    monkeypatch.undo()
    monkeypatch.setattr(os, "replace", _replace_raising_for_dirfd())
    with pytest.raises(OSError):  # before the rename: an ordinary failure
        ex.apply("fs.write", ex.resource_for("b.txt"), {"content": "y"})
    assert [p.name for p in (tmp_path / "scratch").iterdir()] == ["a.txt"]


def test_post_commit_fsync_failure_acks_failed_and_consumes_the_use(pair, monkeypatch):
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "pc.txt"),
        principal_statement=STATEMENT,
        max_uses=1,
    )
    bundle = write_bundle(a, b, g, "pc.txt", "landed\n")
    msg_id = bundle["object"]["msg_id"]
    monkeypatch.setattr(os, "fsync", _fsync_raising_for(b.scratch_identity))
    (r,) = b.receive(bundle)
    assert r["object"]["outcome"] == "failed:post_commit"
    assert (b.scratch_dir / "pc.txt").read_text() == "landed\n"
    led = latest(b)
    assert led["outcome"] == "failed:post_commit" and led["msg_id"] == msg_id
    assert led["grant_id"] == g["grant_id"] and "directory fsync failed" in led["detail"]
    assert any("failed AFTER committing" in x for x in reports)
    assert b.grant_uses(g) == (1, None)  # the use is spent
    assert seen_of(b)[msg_id]["ack"] == r["object"]  # the reservation became the ack
    monkeypatch.undo()
    (r2,) = b.receive(write_bundle(a, b, g, "pc.txt", "again\n"))
    assert r2["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "grant.max_uses" in latest(b)["detail"]
    assert (b.scratch_dir / "pc.txt").read_text() == "landed\n"
    (r3,) = b.receive(bundle)  # the stored ack, nothing re-run
    assert r3["object"] == r["object"]
    assert b.ledger.verify() == b.ledger.head()


def test_pre_commit_failure_stays_an_ordinary_failure(pair, monkeypatch):
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "pre.txt"),
        principal_statement=STATEMENT,
        max_uses=1,
    )
    monkeypatch.setattr(os, "replace", _replace_raising_for_dirfd())
    (r,) = b.receive(write_bundle(a, b, g, "pre.txt"))
    assert r["object"]["outcome"] == "failed:OSError"
    assert latest(b)["outcome"] == "failed" and not (b.scratch_dir / "pre.txt").exists()
    assert b.grant_uses(g) == (0, None)  # nothing happened: no use spent
    monkeypatch.undo()
    (r,) = b.receive(write_bundle(a, b, g, "pre.txt", "now\n"))
    assert r["object"]["outcome"] == "applied"


# ---- M2. a held revocation is verified first and never overwritten ---------------------


def _unpinned_pair(tmp_path, name_b="b", reports=None):
    """A trusts B; B has NOT pinned A. A has a grant out to B and revokes it."""
    clock = Clock()
    a = make_node(tmp_path, "a", clock, reports=reports)
    b = make_node(tmp_path, name_b, clock, reports=reports)
    a.pin(b.principal.public, "b")
    a.import_card(b.card)
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "h.txt"), principal_statement=STATEMENT
    )
    rev = a.revoke(grants=[g["grant_id"]], principal_statement="never mind")
    return a, b, g, rev, clock


def _assert_revoked_after_pin(a, b, g, rev):
    b.pin(a.principal.public, "a")
    assert (
        b.revocations.grant_revoked_by(g["grant_id"], a.principal.public)["rev_id"]
        == (rev["rev_id"])
    )
    assert held_revocations(b, rev["rev_id"]) == []
    b.receive(a.compose_card())
    b.mark_lookup_ok()
    (r,) = b.receive(write_bundle(a, b, g, "h.txt"))
    assert r["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "grant.revoked" in latest(b)["detail"] and not (b.scratch_dir / "h.txt").exists()


@pytest.mark.parametrize("order", ["valid-then-variant", "variant-then-valid"])
def test_unverified_variant_never_displaces_a_held_revocation(tmp_path, order):
    a, b, g, rev, clock = _unpinned_pair(tmp_path)
    variant = {**rev, "principal_statement": "tampered"}  # the signature no longer holds
    first, second = (rev, variant) if order == "valid-then-variant" else (variant, rev)
    assert b.receive(bundlemod.make("revocation", first)) == []
    assert b.receive(bundlemod.make("revocation", second)) == []
    (held,) = held_revocations(b, rev["rev_id"])
    assert json.loads(held.read_text()) == rev  # the valid body, whichever came first
    outcomes = [e["outcome"] for e in b.ledger.entries() if e["action"].startswith("revocation")]
    assert sorted(outcomes) == ["unpinned", "verify_failed:revocation.sig.invalid"]
    _assert_revoked_after_pin(a, b, g, rev)
    replays = [e for e in b.ledger.entries() if e["action"] == "revocation.replayed"]
    assert [e["outcome"] for e in replays] == ["recorded"]


def test_two_valid_bodies_for_one_rev_id_are_both_held_and_both_replayed(tmp_path):
    a, b, g, rev, clock = _unpinned_pair(tmp_path)
    again = revmod.sign({**rev, "principal_statement": "again, signed"}, a.principal)
    for r in (rev, again, rev):  # the same body twice is one file
        assert b.receive(bundlemod.make("revocation", r)) == []
    assert len(held_revocations(b, rev["rev_id"])) == 2
    _assert_revoked_after_pin(a, b, g, rev)
    replays = [e for e in b.ledger.entries() if e["action"] == "revocation.replayed"]
    # round 5 (F2): a second signed body under one (principal, rev_id) is a VARIANT,
    # recorded as its own entry (coverage only grows), never dropped as a duplicate
    assert sorted(e["outcome"] for e in replays) == ["recorded", "recorded:variant"]
    assert len(b.revocations.entries()) == 2


# ---- M3. replay before trust; a startup sweep for the other order -------------------------


def test_pin_replays_held_revocations_before_it_publishes_trust(tmp_path, monkeypatch):
    a, b, g, rev, clock = _unpinned_pair(tmp_path)
    assert b.receive(a.compose_revocation(rev)) == []
    assert len(held_revocations(b, rev["rev_id"])) == 1
    real = nodemod._write_json
    order: list[str] = []
    real_append = b.revocations.append

    def feed_append(r):
        order.append("feed")
        real_append(r)

    def crash_on_pin(p, v):
        if p.name == "pinned.json":
            order.append("pin")
            raise OSError(5, "power cut before the pin write")
        real(p, v)

    monkeypatch.setattr(b.revocations, "append", feed_append)
    monkeypatch.setattr(nodemod, "_write_json", crash_on_pin)
    with pytest.raises(OSError):
        b.pin(a.principal.public, "a")
    assert order == ["feed", "pin"]  # the feed landed first
    assert a.principal.public not in b.pinned  # trust was never published
    assert b.revocations.grant_revoked_by(g["grant_id"], a.principal.public) is not None
    assert held_revocations(b, rev["rev_id"]) == []
    assert latest(b)["action"] == "revocation.replayed" and latest(b)["outcome"] == "recorded"
    monkeypatch.undo()
    _assert_revoked_after_pin(a, b, g, rev)


def test_startup_sweep_replays_a_held_revocation_for_an_already_pinned_principal(tmp_path):
    reports: list[str] = []
    a, b, g, rev, clock = _unpinned_pair(tmp_path, reports=reports)
    assert b.receive(a.compose_revocation(rev)) == []
    (held,) = held_revocations(b, rev["rev_id"])
    # the other order, as a crash after the pin write would leave it: trust is on
    # disk, the held revocation was never replayed
    nodemod._write_json(
        b.state / "pinned.json",
        {**json.loads((b.state / "pinned.json").read_text()), a.principal.public: {"name": "a"}},
    )
    assert a.principal.public in b.pinned and held.exists()
    b2 = Node(
        state_dir=b.state,
        keys_dir=b.keys_dir,
        scratch_dir=b.scratch_dir,
        clock=clock,
        report=reports.append,
    )
    assert not held.exists()
    assert b2.revocations.grant_revoked_by(g["grant_id"], a.principal.public) is not None
    swept = [e for e in b2.ledger.entries() if e["action"] == "revocation.replayed"]
    assert len(swept) == 1 and swept[0]["outcome"] == "recorded"
    assert "startup sweep" in swept[0]["detail"]
    assert any("startup sweep" in x for x in reports)
    b2.receive(a.compose_card())
    b2.mark_lookup_ok()
    (r,) = b2.receive(write_bundle(a, b2, g, "h.txt"))
    assert r["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "grant.revoked" in latest(b2)["detail"] and not (b2.scratch_dir / "h.txt").exists()
    # a third instance finds nothing to sweep
    b3 = Node(state_dir=b.state, keys_dir=b.keys_dir, scratch_dir=b.scratch_dir, clock=clock)
    assert [e["action"] for e in b3.ledger.entries()].count("revocation.replayed") == 1


# ---- M4. durability before the cursor ------------------------------------------------------


def _record_durability(monkeypatch):
    events: list[str] = []
    real_fsync, real_replace = os.fsync, os.replace

    def fsync(fd):
        events.append("dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
        real_fsync(fd)

    def replace(*a, **kw):
        events.append("replace")
        return real_replace(*a, **kw)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "replace", replace)
    return events


def rev_entry(node):
    """The ledger entry the node's own revocation just appended (any completion serves
    as the entry an ack names)."""
    return node.ledger.entries()[-1]


def test_feed_append_and_every_sidecar_are_durable_in_order(tmp_path, monkeypatch):
    clock = Clock()
    a = make_node(tmp_path, "a", clock)
    fake = FakeMail()
    w = MailWire(a, runner=fake.runner_for("taylor@houmanoids.com"))
    events = _record_durability(monkeypatch)
    feed = revmod.RevocationFeed(tmp_path / "feed" / "revocations.jsonl")
    rev = a.revoke(grants=[grantmod.new_id("grt")], principal_statement="x")
    events.clear()
    feed.append(rev)
    assert events == ["file", "dir"]  # the line, then the directory entry
    assert feed.entries() == [rev]
    # a real reply (an ack of ours): a held reply is validated in full before it is
    # written, so only this node's ack to a message can be held at all
    mid = uid("msg")
    reply = a._ack({"msg_id": mid, "from": a.agent.public}, "information", "", rev_entry(a))
    for what, do in (
        ("check", lambda: feed.mark_checked(clock())),
        ("seen-mail", lambda: w._mark_seen("g1", "note")),
        ("cursor", w._advance_cursor),
        ("held reply", lambda: w._hold_reply(reply, mid)),
    ):
        events.clear()
        do()
        assert events == ["file", "replace", "dir"], what
    assert feed.last_checked() == clock() and w._seen() == {"g1": "note"}
    assert not (tmp_path / "feed" / "revocations.check.json.tmp").exists()


def test_feed_write_failure_leaves_the_mail_unseen_and_the_cursor_unmoved(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    reports: list[str] = []
    b.report = reports.append
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "fw.txt"), principal_statement=STATEMENT
    )
    rev = a.revoke(grants=[g["grant_id"]], principal_statement="no")
    wa.send(a.compose_revocation(rev))
    real = b.revocations.add
    b.revocations.add = lambda r, *, pinned: (_ for _ in ()).throw(OSError(28, "disk full"))
    s = wb.poll_once()
    assert s["applied"] == 0 and s["complete"] is False and s["storage_failures"] == 1
    assert any("storage failure" in e for e in s["errors"])
    assert wb.cursor() is None and b.revocations.last_checked() is None
    assert not (b.state / "seen-mail.json").exists()  # read again next poll
    assert b.revocations.entries() == []
    assert not any(e["outcome"] == "verify_failed:malformed" for e in b.ledger.entries())
    assert any("storage failure" in r and "read again next poll" in r for r in reports)
    b.revocations.add = real
    s = wb.poll_once()
    assert s["applied"] == 1 and s["complete"] is True and s["storage_failures"] == 0
    assert wb.cursor() == clock() and len(b.revocations.entries()) == 1


def test_replay_keeps_the_held_copy_when_the_feed_write_fails(tmp_path, monkeypatch):
    a, b, g, rev, clock = _unpinned_pair(tmp_path)
    assert b.receive(a.compose_revocation(rev)) == []
    (held,) = held_revocations(b, rev["rev_id"])
    monkeypatch.setattr(
        b.revocations, "append", lambda r: (_ for _ in ()).throw(OSError(5, "I/O error"))
    )
    with pytest.raises(OSError):
        b.pin(a.principal.public, "a")
    assert held.exists() and a.principal.public not in b.pinned
    assert b.revocations.entries() == []
    monkeypatch.undo()
    _assert_revoked_after_pin(a, b, g, rev)


def test_storage_failure_on_a_message_leaves_it_unseen_and_reserves_nothing(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    wa.send(a.compose_card())
    wb.poll_once()
    cursor_before = wb.cursor()
    clock.tick(60)
    wa.send(a.compose_info(b.card, "hello"))
    real = nodemod._write_json

    def fail_seen(p, v):
        if p.name == "seen.json":
            raise OSError(28, "disk full")
        real(p, v)

    nodemod._write_json = fail_seen
    try:
        s = wb.poll_once()
    finally:
        nodemod._write_json = real
    assert s["applied"] == 0 and s["storage_failures"] == 1 and s["replies"] == 0
    # the control bundles landed, so the lookup is fresh; the message's mail is unseen,
    # so the cursor stays where it was until it is applied
    assert s["complete"] is False and b.revocations.last_checked() == clock()
    assert wb.cursor() == cursor_before
    assert not (b.state / "seen.json").exists()
    assert len(json.loads((b.state / "seen-mail.json").read_text())) == 1  # the card only
    clock.tick(60)
    s = wb.poll_once()
    assert s["applied"] == 1 and s["replies"] == 1 and s["complete"] is True
    assert wb.cursor() == clock()


# ---- M5. search pages are walked to the end, with a cap -----------------------------------


def test_search_pages_are_walked_until_the_last_partial_page(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    wb.send(b.compose_card())
    fake.threads = 2 * SEARCH_MAX + 5  # two full pages, then a partial one
    s = wa.poll_once()
    assert s["applied"] == 1 and s["complete"] is True and not s["errors"]
    tokens = [
        argv[argv.index("--page-token") + 1] if "--page-token" in argv else None
        for argv in fake.searches
    ]
    assert tokens == [None, f"p{SEARCH_MAX}", f"p{2 * SEARCH_MAX}"]
    assert wa.cursor() == clock() and a.revocations.last_checked() == clock()
    got = wa.fetch()
    assert got.pages == 3 and got.threads == 2 * SEARCH_MAX + 5 and got.complete


def test_search_that_keeps_returning_full_pages_stops_at_the_cap(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    reports: list[str] = []
    a.report = reports.append
    wb.send(b.compose_card())
    fake.endless_pages = True
    after0 = wa.search_after()  # the window's start: no cursor, no record yet
    s = wa.poll_once()  # no exception, no spin
    assert s["applied"] == 1 and s["complete"] is False
    # round 21 (Z3): a slice that lists PAGE_CAP threads with more to come is read
    # and HALVED; with every page full forever each half overflows too, and the
    # pass ends on its call budget (MAX_PAGES), the page-cap fact named first
    assert len(fake.searches) == MAX_PAGES
    assert wa.cursor() is None and a.revocations.last_checked() is None
    assert any(
        "page cap" in r and str(PAGE_CAP) in r and "cursor not advanced" in r for r in reports
    )
    # round 21 (self-gate, finding 1): no slice completed, but the halving NARROWED
    # the span — recorded with the position unchanged (the window's start), so the
    # next pass narrows further instead of starting over
    rec = wa.scan_record()
    assert rec is not None and rec[0] == after0 and rec[1] < CATCHUP_FLOOR_S
    got = wa.fetch()
    assert got.complete is False and got.incomplete_why.startswith(f"page cap ({PAGE_CAP} threads")
    assert f"page cap ({MAX_PAGES} search pages)" in got.incomplete_why
    assert got.threads == PAGE_CAP and got.pages == MAX_PAGES and got.overflows >= 1
    assert got.progress is True and got.scanned_through == after0 and got.slice_s < rec[1]
    assert len(fake.searches) == 2 * MAX_PAGES  # bounded again


def test_stable_mailbox_larger_than_one_page_makes_progress_every_poll(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    wb.send(b.compose_card())
    fake.threads = SEARCH_MAX + 50  # the same 250 threads on every poll
    t0 = clock()
    s = wa.poll_once()
    assert s["complete"] is True and wa.cursor() == t0
    assert a.revocations.last_checked() == t0
    first_query = fake.queries[-1]
    clock.tick(3600)
    s = wa.poll_once()
    assert s["complete"] is True and wa.cursor() == clock()  # the cursor moved on
    assert a.revocations.last_checked() == clock()
    assert fake.queries[-1] != first_query  # a new window, not the same one again
    assert len(fake.searches) == 4  # two pages per poll


def test_gmail_api_search_paginates_additively(capsys):
    api = _gmail_api()
    calls: list[dict] = []

    class G:
        def get(self, path, **q):
            calls.append({"path": path, **q})
            if path == "threads":
                out = {"threads": [{"id": "t1"}, {"id": "t2"}]}
                if q.get("pageToken") != "last":
                    out["nextPageToken"] = "last"
                return out
            return {"messages": [{"payload": {"headers": []}}]}

    class A:
        query, max, page_token, ids_only = "subject:(x)", 200, None, False

    api.cmd_search(G(), A())
    lines = capsys.readouterr().out.splitlines()
    assert [ln.split()[0] for ln in lines] == ["thread", "thread", "next-page-token"]
    assert lines[-1] == "next-page-token last" and lines[0].startswith("thread t1 msgs=1 | ")
    assert calls[0] == {"path": "threads", "q": "subject:(x)", "maxResults": 200}
    A.page_token = "last"
    api.cmd_search(G(), A())
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 2 and all(ln.startswith("thread ") for ln in lines)  # unchanged text
    assert calls[3]["pageToken"] == "last"


# ---- M6. the CLI ledger verbs hold the state lock ------------------------------------------


def _drop_last_prose_line(led: Ledger) -> None:
    lines = led.prose_path.read_text(encoding="utf-8").splitlines()
    led.prose_path.write_text("".join(f"{ln}\n" for ln in lines[:-1]), encoding="utf-8")


def test_cli_repair_and_a_receive_never_both_write_the_gap(pair, monkeypatch):
    a, b, clock, reports = pair
    # the CLI's node exists BEFORE the poller's receive starts (its startup sweep
    # took and released the lock long ago): only the verb's own lock can serialize
    cli_node = Node(state_dir=b.state, keys_dir=b.keys_dir, scratch_dir=b.scratch_dir, clock=clock)
    monkeypatch.setattr(climod, "_node", lambda a_: cli_node)
    _drop_last_prose_line(b.ledger)  # a crash between the two ledger writes
    n_entries = len(b.ledger.entries())
    real_append_prose = b.ledger._append_prose
    timeline: dict[str, float] = {}

    def slow_append_prose(lines):  # the receive has SEEN the gap; now it writes, slowly
        time.sleep(0.4)
        real_append_prose(lines)
        timeline["receive_wrote"] = time.monotonic()

    monkeypatch.setattr(b.ledger, "_append_prose", slow_append_prose)
    argv = ["--state", str(b.state), "--keys", str(b.keys_dir), "--scratch", str(b.scratch_dir)]
    out = io.StringIO()
    result: dict[str, int] = {}

    def repair():
        with contextlib.redirect_stdout(out):
            result["rc"] = main([*argv, "ledger", "repair"])
        timeline["repair_done"] = time.monotonic()

    def receive():
        b.receive(a.compose_info(b.card, "while repairing"))
        timeline["receive_done"] = time.monotonic()

    t1 = threading.Thread(target=receive)
    t2 = threading.Thread(target=repair)
    t1.start()
    time.sleep(0.1)
    t2.start()
    t1.join()
    t2.join()
    assert result["rc"] == 0 and "0 trailing prose line(s) regenerated" in out.getvalue()
    assert timeline["repair_done"] >= timeline["receive_wrote"]  # repair waited for the lock
    assert len(b.ledger.entries()) == n_entries + 1
    assert len(b.ledger._prose_lines()) == n_entries + 1  # one line per entry, no double
    assert b.ledger.verify() == b.ledger.head()
    out2 = io.StringIO()
    with contextlib.redirect_stdout(out2):
        assert main([*argv, "ledger", "verify"]) == 0
    assert out2.getvalue().startswith("ledger ok")
    # and the mirror is exactly one prose line per entry, in order
    lines = b.ledger.prose_path.read_text(encoding="utf-8").splitlines()
    assert [ln[-13:-1] for ln in lines] == [entry_hash(e)[7:19] for e in b.ledger.entries()]


def test_cli_ledger_verbs_take_the_flock(pair, monkeypatch):
    a, b, clock, reports = pair
    events: list[str] = []
    real_flock = nodemod.fcntl.flock

    def spy(fd, op):
        events.append("lock" if op == nodemod.fcntl.LOCK_EX else "unlock")
        real_flock(fd, op)

    monkeypatch.setattr(nodemod.fcntl, "flock", spy)
    argv = ["--state", str(b.state), "--keys", str(b.keys_dir), "--scratch", str(b.scratch_dir)]
    for verb in ("verify", "repair"):
        events.clear()
        with contextlib.redirect_stdout(io.StringIO()):
            assert main([*argv, "ledger", verb]) == 0
        # the startup sweep's lock, then the verb's own
        assert events == ["lock", "unlock", "lock", "unlock"], verb


# ---- m7. outbound entries live in their own namespace ---------------------------------------


def test_find_msg_keys_on_the_outbound_namespace_not_on_action_names(tmp_path):
    led = Ledger(tmp_path / "l.jsonl")
    ts = "2026-09-07T07:00:00Z"
    for action, outcome, direction in (
        (OUT_ACK, "applied", "out"),
        (OUT_SEND, "undelivered", "out"),
        ("ack", "refused", "in"),
    ):
        led.append(
            ts=ts,
            actor="x",
            grant_id=None,
            action=action,
            params_hash=None,
            outcome=outcome,
            msg_id="msg_00000000000000000000000000",
            direction=direction,  # round 5 (F9): the discriminator, not the name
        )
    hit = led.find_msg("msg_00000000000000000000000000")
    assert hit["action"] == "ack" and hit["outcome"] == "refused"  # the inbound refusal
    assert OUT_ACK == "out.ack" and OUT_SEND == "out.send"


@pytest.mark.parametrize("name", ["ack", "send"])
def test_inbound_action_named_like_an_outbound_entry_is_refused_and_recoverable(
    tmp_path, name, monkeypatch
):
    clock = Clock()
    reports: list[str] = []
    a = make_node(tmp_path, "a", clock, reports=reports)
    b = make_node(tmp_path, "b", clock, reports=reports)
    # a card that lists the odd action as a capability, so the grant verifies and the
    # EXECUTOR is what refuses it
    b.make_card(
        agent_name="b",
        node_name="b-node",
        principal_name="b-principal (stand-in)",
        capabilities=[
            *b.default_capabilities(),
            {"action": name, "resource": f"host:{b.host.public}:*"},
        ],
    )
    a.pin(b.principal.public, "b")
    b.pin(a.principal.public, "a")
    a.receive(b.compose_card())
    b.receive(a.compose_card())
    b.mark_lookup_ok()
    resource = f"host:{b.host.public}:scratch/odd"
    g = a.issue_grant(
        subject_card=b.card,
        scope=[{"action": name, "resource": resource, "params": {"keys": [], "values": {}}}],
        principal_statement="try it",
    )
    bundle = a.compose_action(
        b.card, action=name, resource=resource, params={}, grant_ids=[g["grant_id"]]
    )
    msg_id = bundle["object"]["msg_id"]
    real_sign = ackmod.sign
    crashed = []

    def crash(a_, kp):
        if not crashed:
            crashed.append(1)
            raise RuntimeError("power cut before the ack")
        return real_sign(a_, kp)

    monkeypatch.setattr(nodemod.ackmod, "sign", crash)
    assert b.receive(bundle) == []  # refused by the executor, then the ack was lost
    led = b.ledger.find_msg(msg_id)
    assert led is not None and led["action"] == name and led["outcome"] == "refused"
    assert led["detail"].startswith("executor.unsupported")
    (r,) = b.receive(bundle)  # recovered from that entry, not re-evaluated
    assert r["object"]["outcome"] == "refused:executor.unsupported"
    assert r["object"]["ledger_entry"] == entry_hash(led)
    assert len(completions(b, msg_id)) == 1
    assert b.grant_uses(g) == (0, None)


def test_lost_ack_for_a_plain_failed_entry_is_rebuilt(pair, monkeypatch):
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "pf.txt"), principal_statement=STATEMENT
    )
    bundle = write_bundle(a, b, g, "pf.txt")
    msg_id = bundle["object"]["msg_id"]
    monkeypatch.setattr(os, "replace", _replace_raising_for_dirfd())  # an ordinary failure
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
    assert led["outcome"] == "failed" and led["detail"].startswith("OSError")
    (r,) = b.receive(bundle)
    assert r["object"]["outcome"] == "failed:OSError"
    assert r["object"]["ledger_entry"] == entry_hash(led)
    assert len(completions(b, msg_id)) == 1 and b.grant_uses(g) == (0, None)
    assert not (b.scratch_dir / "pf.txt").exists()  # nothing re-executed


# ---- m8. a chain may not repeat an id -----------------------------------------------------


def test_child_sharing_its_parents_id_is_refused_before_anything_is_written(pair):
    a, b, clock, reports = pair
    parent = a.issue_grant(
        subject_card=a.card,
        audience=b.host.public,
        scope=fs_write_scope(b, "id.txt"),
        principal_statement="A may pass this on",
        max_uses=2,
    )
    child = a.delegate_grant(
        parent=parent,
        subject_card=b.card,
        scope=tighter_scope(b, "id.txt"),
        principal_statement="ok only",
    )
    same_id = grantmod.sign({**child, "grant_id": parent["grant_id"]}, a.agent)  # validly signed
    grantmod.authenticate(same_id, pinned=b.pinned)
    (r,) = b.receive(action_bundle(a, b, same_id, "id.txt"))
    assert r["object"]["outcome"] == "refused:no_authorizing_grant"
    conflicts = [e for e in b.ledger.entries() if e["outcome"] == "verify_failed:grant.id_conflict"]
    assert (
        len(conflicts) == 1
        and "names both the grant and its embedded parent" in conflicts[0]["detail"]
    )
    assert b.load_grant_any(parent["grant_id"]) is None  # nothing stored, under either name
    assert not (b.scratch_dir / "id.txt").exists()
    # the ordinary chain: the child is stored, the parent embedded
    (r,) = b.receive(write_bundle(a, b, child, "id.txt", "ok\n"))
    assert r["object"]["outcome"] == "applied"
    assert b.load_grant(child["grant_id"]) == child
    assert (
        b.load_grant(parent["grant_id"]) is None and b.load_grant_any(parent["grant_id"]) == parent
    )


# ---- m9. an embedded parent is never executable ---------------------------------------------


def test_cached_embedded_parent_is_not_executable_until_it_arrives_top_level(pair):
    a, b, clock, reports = pair
    parent = a.issue_grant(  # self-bound to B: subject B, audience B's node
        subject_card=b.card,
        scope=fs_write_scope(b, "emb.txt"),
        principal_statement=STATEMENT,
        max_uses=3,
    )
    child = b.delegate_grant(  # B passes a subset on to A; A's message will carry the parent
        parent=parent,
        subject_card=a.card,
        scope=tighter_scope(b, "emb.txt"),
        principal_statement="ok only",
    )
    (r,) = b.receive(action_bundle(a, b, child, "emb.txt"))
    assert r["object"]["outcome"] == "refused:no_authorizing_grant"  # the child's subject is A
    assert "grant.subject.agent" in latest(b)["detail"]
    assert (b.state / "grants-embedded" / f"{parent['grant_id']}.json").exists()
    assert b.load_grant(parent["grant_id"]) is None
    # a message NAMING the cached parent without attaching it: not on file for execution
    (r,) = b.receive(action_bundle(a, b, parent, "emb.txt", attach=False))
    assert r["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "not attached and not on file" in latest(b)["detail"]
    assert not (b.scratch_dir / "emb.txt").exists()
    # the same parent delivered top-level (attached, addressed to this node): executable
    (r,) = b.receive(action_bundle(a, b, parent, "emb.txt"))
    assert r["object"]["outcome"] == "applied"
    assert b.load_grant(parent["grant_id"]) == parent
    assert (b.scratch_dir / "emb.txt").read_text() == "ok\n"


# ---- m10. an unterminated prose mirror -------------------------------------------------------


def test_unterminated_prose_line_is_repaired_when_correct_and_refused_when_wrong(tmp_path):
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
    app("y")
    text = led.prose_path.read_text(encoding="utf-8")
    led.prose_path.write_text(text[:-1], encoding="utf-8")  # the final newline never landed
    with pytest.raises(IntegrityError) as e:
        led.verify()
    assert e.value.reason == "ledger.prose.unterminated"
    app("z")  # the newline is put back first; z lands on its own line
    lines = led.prose_path.read_text(encoding="utf-8").split("\n")
    assert len(lines) == 4 and lines[-1] == "" and all(ln.count("[") == 1 for ln in lines[:3])
    assert led.verify() == led.head() and led.repair() == 0
    # repair terminates it too
    led.prose_path.write_text(led.prose_path.read_text(encoding="utf-8")[:-1], encoding="utf-8")
    assert led.repair() == 0 and led.verify() == led.head()
    # unterminated AND wrong: refused, nothing changes
    lines = led.prose_path.read_text(encoding="utf-8").splitlines()
    lines[-1] = "the operator approved everything " + lines[-1][-14:]
    led.prose_path.write_text("\n".join(lines), encoding="utf-8")
    before = (led.path.read_bytes(), led.prose_path.read_bytes())
    with pytest.raises(IntegrityError) as e:
        app("w")
    assert e.value.reason == "ledger.prose.mismatch" and "ledger repair" in e.value.detail
    with pytest.raises(IntegrityError) as e:
        led.repair()
    assert e.value.reason == "ledger.repair.refused"
    assert (led.path.read_bytes(), led.prose_path.read_bytes()) == before


def test_excess_prose_carries_the_restore_guidance(tmp_path):
    led = Ledger(tmp_path / "l.jsonl")
    led.append(
        ts="2026-09-07T07:00:00Z",
        actor="a",
        grant_id=None,
        action="x",
        params_hash=None,
        outcome="information",
    )
    with open(led.prose_path, "a", encoding="utf-8") as f:
        f.write("one line too many [000000000000]\n")
    for call, reason in (
        (led.sync_prose, "ledger.prose.mismatch"),
        (led.repair, "ledger.repair.refused"),
    ):
        with pytest.raises(IntegrityError) as e:
            call()
        assert e.value.reason == reason
        assert "2 prose lines for 1 entries" in e.value.detail
        assert "restore state/ledger.prose.txt" in e.value.detail
        assert "ledger repair" in e.value.detail


# ---- m11. pending replies first; re-sends survive a fetch error ------------------------------


def _stalled_search(fake, self_email, log):
    real = fake.runner_for(self_email)

    def run(argv):
        if argv[1].endswith("gmail-api.py") and argv[4] == "search":
            log.append("search")
            raise RuntimeError("search stalled")
        if argv[1].endswith("gmail-send.py"):
            log.append("send")
        return real(argv)

    return run


def test_pending_replies_flush_before_the_fetch_and_resends_survive_a_fetch_error(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    wa.send(a.compose_card())
    wb.send(b.compose_card())
    wb.poll_once()
    wa.poll_once()
    wa.send(a.compose_info(b.card, "one"))
    fake.fail_sends = True
    s = wb.poll_once()
    assert s["applied"] == 1 and s["replies"] == 0 and len(s["errors"]) == 1
    assert len(list((b.state / "pending-replies").glob("*.json"))) == 1
    fake.fail_sends = False
    log: list[str] = []
    stalled_b = MailWire(b, runner=_stalled_search(fake, "taylor@teale.com", log))
    s = stalled_b.poll_once()
    assert s["replies"] == 1 and any("stalled" in e for e in s["errors"])
    assert log == ["send", "search"]  # the held ack left BEFORE the fetch was attempted
    assert list((b.state / "pending-replies").glob("*.json")) == []
    assert s["complete"] is False and b.revocations.last_checked() is not None  # untouched
    # the ack reaches A on its next poll; then a due re-send goes out on A's side even
    # though A's fetch fails
    assert wa.poll_once()["applied"] == 1 and a.outbox()[-1]["status"] == "acked"
    P = a.poll_s
    wa.send(a.compose_info(b.card, "two"))
    (x,) = [x for x in a.outbox() if x["status"] == "pending"]
    clock.tick(2 * P)
    log_a: list[str] = []
    stalled_a = MailWire(a, runner=_stalled_search(fake, "taylor@houmanoids.com", log_a))
    s = stalled_a.poll_once()
    assert s["resent"] == 1 and any("stalled" in e for e in s["errors"])
    assert log_a == ["search", "send"]
    (x2,) = [y for y in a.outbox() if y["msg_id"] == x["msg_id"]]
    assert x2["attempts"] == 2 and x2["status"] == "pending"
    # undelivered is reached through a failed fetch as well
    for tick in (4 * P, 8 * P, 16 * P):
        clock.tick(tick)
        stalled_a.poll_once()
    assert [y["status"] for y in a.outbox() if y["msg_id"] == x["msg_id"]] == ["undelivered"]

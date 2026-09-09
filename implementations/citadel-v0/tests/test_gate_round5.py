"""Round-5 gate findings (hw-444xk): the fourth cross-model gate's report, crash
consistency and durability ORDERING under failure injection. Every test asserts that
what a peer can observe — a use count, a seen mark, a cursor, a trust decision — never
runs ahead of what is durable; the tests are of four kinds, and not every one injects
a failure after visibility (the round-6 correction of an earlier overstatement):

  ORDERING (every fsync recorded, the order of files asserted): F8 first test, F12;
  FAILURE BEFORE (one persistence step replaced by an immediate exception, nothing
    became visible, the retry asserted): F2 second test (the second candidate's feed
    append replaced by an exception, same instance), F4, F8 second test, F11 (all five);
  FAILURE AFTER (the effect became visible, its barrier or a later step failed, then
    the retry on the same instance): F1 both tests (the rename landed, then the close
    or the directory fsync failed — the second test records no fsync order, it asserts
    the error that propagates), F3 (both), F9 (the refusal entry landed, the ack step
    crashed);
  RESTART RECOVERY (a NEW instance — a fresh Node, a fresh feed handle, a CLI process —
    over the state directory the last one left, the old instance discarded): F5 first
    test only (a fresh feed handle, then a second Node, then the CLI).
  F5 second, third and fourth tests, and F10, are framing tests on hand-staged files (a
  torn tail or a whitespace tail written by hand; no syscall failed, no restart claimed);
  F6 and F7 are transport bounds (no persistence failure at all). Corrected in round 7 (H)
  after the sixth gate.

F1  a close failure after the rename is post-commit and never masks the fsync error;
F2  the feed's identity is (principal, rev_id, body): variants are recorded, principals
    never collide, held replay keeps each candidate until ITS append returned;
F3  a retry after a half-synced feed append / held file syncs again before "duplicate";
F4  a control phase that did not land defers every ack and message this poll;
F5  a torn local feed is IntegrityError (storage), never malformed peer input; repair;
F6  repeated or empty search pages end the fetch as nonprogressing, within a bound;
F7  thread bodies come in chunks, a failed chunk leaves the fetch incomplete;
F8  the denial store is durable (file, directory) before the ledger entry;
F9  inbound out.* actions are refused and their lost acks recovered (direction field);
F10 a whitespace-only prose tail is refused; an empty ledger with an empty mirror verifies;
F11 OSError while ledgering a refusal, and in every adapter-owned write, is contained;
F12 ledger append and repair sync the directory too."""

from __future__ import annotations

import itertools
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from natively import bundle as bundlemod
from natively import keys
from natively import revocation as revmod
from natively.adapters.mail import MAX_PAGES, NONPROGRESSING, THREAD_CHUNK, MailWire
from natively.cli import main
from natively.errors import IntegrityError, PostCommitError, StorageError, VerifyError
from natively.executor import Executor
from natively.ledger import GENESIS, Ledger, entry_hash
from natively.node import Node

from .conftest import Clock, make_node, uid
from .test_gate_round3 import KEY, _gmail_api, completions, held_revocations, pair, seen_of
from .test_gate_round4 import _fsync_raising_for, _unpinned_pair
from .test_hardening import STATEMENT, fs_write_scope, latest, write_bundle
from .test_mail_adapter import pair_over_mail

__all__ = ["pair"]  # the fixture is re-exported for this module's tests

TS = "2026-09-07T07:00:00Z"


def _ino(p: Path) -> tuple[int, int]:
    st = os.stat(p)
    return (st.st_dev, st.st_ino)


def _record_syncs(monkeypatch) -> list[tuple[str, tuple[int, int]]]:
    """Every os.fsync as ("file" | "dir", (dev, ino)), so a test can say WHICH file was
    synced and in which order, not only that something was."""
    events: list[tuple[str, tuple[int, int]]] = []
    real = os.fsync

    def fsync(fd):
        st = os.fstat(fd)
        events.append(("dir" if stat.S_ISDIR(st.st_mode) else "file", (st.st_dev, st.st_ino)))
        real(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    return events


def _raise(exc):
    def fn(*a, **kw):
        raise exc

    return fn


def _rev(kp: keys.KeyPair, grants: list[str], statement: str = "stop"):
    return revmod.sign(
        revmod.build(principal_key=kp.public, ts=TS, grants=grants, principal_statement=statement),
        kp,
    )


def _line(r) -> str:
    return json.dumps(r, ensure_ascii=False, separators=(",", ":"))


def _seen_mail(node) -> dict:
    p = node.state / "seen-mail.json"
    return json.loads(p.read_text()) if p.exists() else {}


# ---- F1. a close failure after the rename ---------------------------------------------------


def _close_raising_for_dir(identity):
    """An os.close that closes the descriptor and THEN reports failure, for the
    directory whose (dev, ino) is `identity` (the executor's scratch root); every
    other descriptor closes normally."""
    real = os.close

    def close(fd):
        try:
            st = os.fstat(fd)
        except OSError:
            return real(fd)
        real(fd)
        if stat.S_ISDIR(st.st_mode) and (st.st_dev, st.st_ino) == identity:
            raise OSError(5, "Input/output error on close")
        return None

    return close


def test_close_failure_after_the_rename_is_post_commit_and_consumes_the_use(pair, monkeypatch):
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "cl.txt"),
        principal_statement=STATEMENT,
        max_uses=1,
    )
    bundle = write_bundle(a, b, g, "cl.txt", "landed\n")
    msg_id = bundle["object"]["msg_id"]
    monkeypatch.setattr(os, "close", _close_raising_for_dir(b.scratch_identity))
    (r,) = b.receive(bundle)
    monkeypatch.undo()
    assert r["object"]["outcome"] == "failed:post_commit"
    assert (b.scratch_dir / "cl.txt").read_text() == "landed\n"  # the side effect exists
    led = latest(b)
    assert led["outcome"] == "failed:post_commit" and led["msg_id"] == msg_id
    assert "closing the directory descriptor failed" in led["detail"]
    assert "directory fsync failed" not in led["detail"]  # the fsync itself succeeded
    assert any("failed AFTER committing" in x for x in reports)
    assert b.grant_uses(g) == (1, None)  # the use reads consumed
    assert seen_of(b)[msg_id]["ack"] == r["object"]
    (r2,) = b.receive(write_bundle(a, b, g, "cl.txt", "again\n"))
    assert r2["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "grant.max_uses" in latest(b)["detail"]
    assert (b.scratch_dir / "cl.txt").read_text() == "landed\n"
    (r3,) = b.receive(bundle)  # the stored ack, nothing re-run
    assert r3["object"] == r["object"]


def test_close_failure_never_masks_the_directory_fsync_failure(tmp_path, monkeypatch):
    ex = Executor(KEY, tmp_path / "scratch")
    monkeypatch.setattr(os, "fsync", _fsync_raising_for(ex.root_identity))
    monkeypatch.setattr(os, "close", _close_raising_for_dir(ex.root_identity))
    with pytest.raises(PostCommitError) as e:
        ex.apply("fs.write", ex.resource_for("a.txt"), {"content": "x"})
    d = e.value.detail
    assert "directory fsync failed" in d and "then closing the directory descriptor failed" in d
    assert d.index("directory fsync failed") < d.index("closing the directory descriptor")
    # the ORIGINAL error is the cause; the close error rode along in the detail
    assert isinstance(e.value.cause, OSError) and "on close" not in str(e.value.cause)
    assert e.value.__cause__ is e.value.cause
    assert (tmp_path / "scratch" / "a.txt").read_text() == "x"
    assert [p.name for p in (tmp_path / "scratch").iterdir()] == ["a.txt"]
    # the close failure alone, after a successful fsync: post-commit too
    monkeypatch.undo()
    monkeypatch.setattr(os, "close", _close_raising_for_dir(ex.root_identity))
    with pytest.raises(PostCommitError) as e:
        ex.apply("fs.write", ex.resource_for("b.txt"), {"content": "y"})
    assert e.value.detail.startswith("'b.txt' was replaced but closing the directory descriptor")
    assert "on close" in str(e.value.cause)
    assert (tmp_path / "scratch" / "b.txt").read_text() == "y"


# ---- F2. the feed's identity is (principal, rev_id, body) -----------------------------------


def test_feed_identity_is_principal_rev_id_and_body(tmp_path):
    p1, p2 = keys.KeyPair.generate(), keys.KeyPair.generate()
    pinned = {p1.public, p2.public}
    feed = revmod.RevocationFeed(tmp_path / "rev.jsonl")
    g1, g2, g3 = uid("grt"), uid("grt"), uid("grt")
    r1 = _rev(p1, [g1])
    # one rev_id, two signed bodies revoking DIFFERENT grants: both recorded
    r2 = revmod.sign({**r1, "revokes": {"cards": [], "grants": [g2]}}, p1)
    assert r2["rev_id"] == r1["rev_id"]
    assert feed.add(r1, pinned=pinned) == "recorded"
    assert feed.add(r2, pinned=pinned) == "recorded:variant"
    assert feed.grant_revoked_by(g1, p1.public)["rev_id"] == r1["rev_id"]
    assert feed.grant_revoked_by(g2, p1.public)["rev_id"] == r1["rev_id"]  # the union
    # the same body twice is a duplicate, whichever of the two
    assert feed.add(r1, pinned=pinned) == "duplicate"
    assert feed.add(r2, pinned=pinned) == "duplicate"
    assert len(feed.entries()) == 2
    # another principal signing the same rev_id: its own entry, never a collision
    r3 = revmod.sign(
        {**r1, "principal": {"key": p2.public}, "revokes": {"cards": [], "grants": [g3]}}, p2
    )
    assert feed.add(r3, pinned=pinned) == "recorded"
    assert feed.grant_revoked_by(g3, p2.public)["rev_id"] == r1["rev_id"]
    assert feed.grant_revoked_by(g3, p1.public) is None  # p2's word revokes nothing of p1's
    assert feed.grant_revoked_by(g1, p2.public) is None
    assert len(feed.entries()) == 3
    assert feed.identity(r1)[:2] == feed.identity(r2)[:2] != feed.identity(r3)[:2]
    assert len({feed.identity(r) for r in (r1, r2, r3)}) == 3


def test_held_replay_deletes_each_candidate_only_after_its_own_append(tmp_path, monkeypatch):
    a, b, g, rev, clock = _unpinned_pair(tmp_path)
    g2 = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "h2.txt"), principal_statement=STATEMENT
    )
    rev2 = revmod.sign({**rev, "revokes": {"cards": [], "grants": [g2["grant_id"]]}}, a.principal)
    for r in (rev, rev2):
        assert b.receive(bundlemod.make("revocation", r)) == []
    held = held_revocations(b, rev["rev_id"])
    assert len(held) == 2
    bodies = [json.loads(f.read_text()) for f in held]  # the replay order (sorted names)
    real_append = b.revocations.append

    def append(r):
        if r == bodies[1]:
            raise OSError(5, "I/O error on the second candidate's append")
        real_append(r)

    monkeypatch.setattr(b.revocations, "append", append)
    with pytest.raises(OSError):
        b.pin(a.principal.public, "a")
    assert a.principal.public not in b.pinned  # trust never published
    # per candidate: the first's copy went after ITS append returned, the second's stays
    assert not held[0].exists() and held[1].exists()
    assert b.revocations.entries() == [bodies[0]]
    monkeypatch.undo()
    b.pin(a.principal.public, "a")
    assert held_revocations(b, rev["rev_id"]) == []
    assert len(b.revocations.entries()) == 2
    for gid in (g["grant_id"], g2["grant_id"]):
        assert b.revocations.grant_revoked_by(gid, a.principal.public) is not None
    replays = [e for e in b.ledger.entries() if e["action"] == "revocation.replayed"]
    assert sorted(e["outcome"] for e in replays) == ["recorded", "recorded:variant"]
    b.receive(a.compose_card())
    b.mark_lookup_ok()
    for grant, name in ((g, "h.txt"), (g2, "h2.txt")):
        (r,) = b.receive(write_bundle(a, b, grant, name))
        assert r["object"]["outcome"] == "refused:no_authorizing_grant"
        assert "grant.revoked" in latest(b)["detail"] and not (b.scratch_dir / name).exists()


# ---- F3. a retry after a half-synced write syncs again before "duplicate" ------------------


def test_feed_retry_after_a_half_synced_append_syncs_before_reporting_duplicate(
    tmp_path, monkeypatch
):
    kp = keys.KeyPair.generate()
    feed = revmod.RevocationFeed(tmp_path / "feed" / "revocations.jsonl")
    rev = _rev(kp, [uid("grt")])
    events: list[tuple[str, tuple[int, int]]] = []
    state = {"failed": False}
    real = os.fsync

    def fsync(fd):
        st = os.fstat(fd)
        kind = "dir" if stat.S_ISDIR(st.st_mode) else "file"
        key = (st.st_dev, st.st_ino)
        if kind == "file" and feed.path.exists() and key == _ino(feed.path) and not state["failed"]:
            state["failed"] = True  # the line is written; its barrier fails
            raise OSError(5, "Input/output error")
        events.append((kind, key))
        real(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    with pytest.raises(OSError):
        feed.add(rev, pinned={kp.public})
    assert feed.entries() == [rev]  # visible...
    assert events == []  # ...and nothing about it was synced
    assert feed.add(rev, pinned={kp.public}) == "duplicate"
    # the retry re-established the barrier, file then directory, before it answered
    assert events == [("file", _ino(feed.path)), ("dir", _ino(feed.path.parent))]
    assert feed.entries() == [rev]


def test_held_revocation_retry_after_a_half_synced_hold_syncs_again(tmp_path, monkeypatch):
    a, b, g, rev, clock = _unpinned_pair(tmp_path)
    pending = b.state / "revocations-pending"
    pending.mkdir(exist_ok=True)
    monkeypatch.setattr(os, "fsync", _fsync_raising_for(_ino(pending)))
    with pytest.raises(StorageError):  # the rename landed; the directory barrier did not
        b.receive(a.compose_revocation(rev))
    (held,) = held_revocations(b, rev["rev_id"])
    assert json.loads(held.read_text()) == rev
    assert not any(e["action"] == "revocation.received" for e in b.ledger.entries())
    monkeypatch.undo()
    events = _record_syncs(monkeypatch)
    assert b.receive(a.compose_revocation(rev)) == []  # the retry: the file already exists
    i = events.index(("file", _ino(held)))
    assert events[i + 1] == ("dir", _ino(pending))  # synced again, file then directory
    last_ledger = max(j for j, ev in enumerate(events) if ev == ("file", _ino(b.ledger.path)))
    assert last_ledger > i  # and only then the revocation.received entry
    assert [e["outcome"] for e in b.ledger.entries() if e["action"] == "revocation.received"] == [
        "unpinned"
    ]
    assert len(held_revocations(b, rev["rev_id"])) == 1  # one file, never a second copy


# ---- F4. a control phase that did not land defers the action phase ---------------------------


def test_failed_control_write_defers_the_action_it_revokes(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    reports: list[str] = []
    b.report = reports.append
    wa.send(a.compose_card())
    wb.send(b.compose_card())
    wb.poll_once()
    wa.poll_once()
    fresh, cursor = b.revocations.last_checked(), wb.cursor()
    assert fresh == clock() and cursor == clock()
    clock.tick(60)  # the clock still reads fresh (limit 5P + P)
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "rv.txt"), principal_statement=STATEMENT
    )
    wa.send(write_bundle(a, b, g, "rv.txt"))
    rev = a.revoke(grants=[g["grant_id"]], principal_statement="no")
    wa.send(a.compose_revocation(rev))
    real = b.revocations.add
    b.revocations.add = _raise(OSError(28, "disk full"))
    s = wb.poll_once()
    assert s["applied"] == 0 and s["deferred"] == 1 and s["storage_failures"] == 1
    assert s["complete"] is False and s["replies"] == 0
    assert any("control phase did not land" in e and "deferred" in e for e in s["errors"])
    assert any("control phase did not land" in r for r in reports)
    assert not (b.scratch_dir / "rv.txt").exists()  # the action did not execute
    assert not any(e["action"] == "fs.write" for e in b.ledger.entries())
    assert seen_of(b) == {}  # not even reserved
    assert len(_seen_mail(b)) == 1  # the card from the first poll; both new mails unseen
    assert b.revocations.last_checked() == fresh and wb.cursor() == cursor
    b.revocations.add = real
    clock.tick(60)
    s = wb.poll_once()
    assert s["applied"] == 2 and s["deferred"] == 0 and s["complete"] is True
    assert s["replies"] == 1 and s["storage_failures"] == 0
    assert not (b.scratch_dir / "rv.txt").exists()
    e = [e for e in b.ledger.entries() if e["action"] == "fs.write"][-1]
    assert e["outcome"] == "refused" and "grant.revoked" in e["detail"]
    assert b.revocations.last_checked() == clock() and wb.cursor() == clock()
    assert len(_seen_mail(b)) == 3


# ---- F5. a torn local feed is local corruption, never malformed peer input --------------------


def test_torn_feed_tail_is_local_corruption_repaired_by_the_verb(tmp_path, capsys):
    clock = Clock()
    n = make_node(tmp_path, "n", clock)
    rev = n.revoke(grants=[uid("grt")], principal_statement="ok")
    torn = _line(rev)[:40].encode()  # a crash mid-write: a partial object, no newline
    with open(n.revocations.path, "ab") as f:
        f.write(torn)
    feed = revmod.RevocationFeed(n.revocations.path)  # across a restart: a fresh handle
    with pytest.raises(IntegrityError) as e:
        feed.load()
    assert e.value.reason == "feed.torn" and "feed repair" in str(e.value)
    assert isinstance(e.value, StorageError) and not isinstance(e.value, VerifyError)
    with pytest.raises(IntegrityError):
        feed.entries()
    with pytest.raises(IntegrityError):  # append refuses while the file is torn
        feed.append(_rev(n.principal, [uid("grt")]))
    assert n.revocations.path.read_bytes().endswith(torn)
    # a node starts on a torn feed; its first feed write is the storage failure it is
    n2 = Node(state_dir=n.state, keys_dir=n.keys_dir, scratch_dir=n.scratch_dir, clock=clock)
    with pytest.raises(IntegrityError):
        n2.revoke(grants=[uid("grt")], principal_statement="x")
    argv = ["--state", str(n.state), "--keys", str(n.keys_dir), "--scratch", str(n.scratch_dir)]
    assert main([*argv, "feed", "verify"]) == 2
    assert "feed.torn" in capsys.readouterr().err
    before = len(n.ledger)
    assert main([*argv, "feed", "repair"]) == 0
    out = capsys.readouterr().out
    assert out.startswith(f"feed repaired: {len(torn)} torn byte(s) truncated; 1 revocation(s)")
    led = latest(n)
    assert len(n.ledger) == before + 1 and led["action"] == "feed.repaired"
    assert f"{len(torn)} bytes" in led["detail"]
    assert revmod.RevocationFeed(n.revocations.path).load() == ([rev], False)
    rev2 = n2.revoke(grants=[uid("grt")], principal_statement="after repair")  # appends again
    assert [e["rev_id"] for e in n.revocations.entries()] == [rev["rev_id"], rev2["rev_id"]]
    assert main([*argv, "feed", "repair"]) == 0  # nothing torn: nothing ledgered
    assert "0 torn byte(s)" in capsys.readouterr().out
    assert [e["action"] for e in n.ledger.entries()].count("feed.repaired") == 1
    assert main([*argv, "feed", "verify"]) == 0
    assert capsys.readouterr().out.startswith("feed ok: 2 revocation(s)")


def test_feed_repair_refuses_when_an_earlier_line_does_not_parse(tmp_path):
    kp = keys.KeyPair.generate()
    feed = revmod.RevocationFeed(tmp_path / "rev.jsonl")
    r1 = _rev(kp, [uid("grt")])
    feed.path.write_bytes(_line(r1).encode() + b"\n{not json}\n" + _line(r1)[:10].encode())
    before = feed.path.read_bytes()
    with pytest.raises(IntegrityError) as e:
        feed.repair()
    assert e.value.reason == "feed.corrupt" and "line 2" in str(e.value)
    assert feed.path.read_bytes() == before  # nothing truncated
    with pytest.raises(IntegrityError) as e:
        feed.load()
    assert e.value.reason == "feed.corrupt"


def test_complete_final_object_short_of_its_newline_gets_it_back_on_append(tmp_path):
    kp = keys.KeyPair.generate()
    feed = revmod.RevocationFeed(tmp_path / "rev.jsonl")
    r1, r2 = _rev(kp, [uid("grt")]), _rev(kp, [uid("grt")])
    feed.path.write_bytes(_line(r1).encode())  # the newline never landed
    assert feed.load() == ([r1], True)
    assert feed.repair() == 0  # not torn: nothing to truncate
    assert feed.add(r2, pinned={kp.public}) == "recorded"
    raw = feed.path.read_bytes()
    assert raw.endswith(b"\n") and raw.count(b"\n") == 2  # one object per line
    assert [json.loads(ln) for ln in raw.splitlines()] == [r1, r2]
    assert feed.load() == ([r1, r2], False)


def test_peer_revocation_arriving_on_a_torn_feed_stays_unseen(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    reports: list[str] = []
    b.report = reports.append
    wa.send(a.compose_card())
    wb.poll_once()
    fresh = b.revocations.last_checked()
    gid = uid("grt")
    rev = a.revoke(grants=[gid], principal_statement="x")
    wa.send(a.compose_revocation(rev))
    with open(b.revocations.path, "ab") as f:
        f.write(b'{"rev_id": "rev_')  # power loss inside an earlier append
    s = wb.poll_once()
    assert s["applied"] == 0 and s["storage_failures"] == 1 and s["complete"] is False
    assert any("feed.torn" in e for e in s["errors"])
    assert not any(e["outcome"] == "verify_failed:malformed" for e in b.ledger.entries())
    assert len(_seen_mail(b)) == 1  # the card only: the revocation's mail is read again
    assert b.revocations.last_checked() == fresh  # not refreshed on an incomplete poll
    assert b.revocations.repair() > 0
    s = wb.poll_once()
    assert s["applied"] == 1 and s["complete"] is True and s["storage_failures"] == 0
    assert b.revocations.grant_revoked_by(gid, a.principal.public)["rev_id"] == rev["rev_id"]
    assert len(_seen_mail(b)) == 2


# ---- F6. nonprogressing pagination ends the fetch, within a bound --------------------------


def _search_override(fake, self_email, page_fn):
    """The fake's runner with every search page answered by page_fn(token)."""
    real = fake.runner_for(self_email)

    def run(argv):
        if Path(argv[1]).name == "gmail-api.py" and argv[4] == "search":
            fake.searches.append(argv)
            token = argv[argv.index("--page-token") + 1] if "--page-token" in argv else None
            return subprocess.CompletedProcess(argv, 0, page_fn(token), "")
        return real(argv)

    return run


def test_repeated_page_and_token_end_the_fetch_as_nonprogressing(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    reports: list[str] = []
    a.report = reports.append
    wb.send(b.compose_card())
    w = MailWire(
        a,
        runner=_search_override(
            fake, "taylor@houmanoids.com", lambda tok: "thread t1\nnext-page-token pX\n"
        ),
    )
    got = w.fetch()  # no exception, no spin
    assert got.complete is False and got.incomplete_why == NONPROGRESSING
    assert got.pages == 2 and got.threads == 1 and len(fake.searches) == 2
    assert [m.gmail_id for m in got.mails] == ["g1"]
    s = w.poll_once()
    assert s["applied"] == 1 and s["complete"] is False and not s["storage_failures"]
    assert w.cursor() is None and a.revocations.last_checked() is None
    assert any(NONPROGRESSING in r and "cursor not advanced" in r for r in reports)
    assert len(fake.searches) == 4 <= 2 * MAX_PAGES


def test_empty_pages_with_fresh_tokens_end_the_fetch_as_nonprogressing(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    reports: list[str] = []
    a.report = reports.append
    n = itertools.count()
    w = MailWire(
        a,
        runner=_search_override(
            fake, "taylor@houmanoids.com", lambda tok: f"next-page-token p{next(n)}\n"
        ),
    )
    got = w.fetch()
    assert got.complete is False and got.incomplete_why == NONPROGRESSING
    assert got.pages == 2 and got.threads == 0 and got.chunks == 0
    s = w.poll_once()
    assert s["applied"] == 0 and s["complete"] is False and not s["errors"]
    assert w.cursor() is None and a.revocations.last_checked() is None
    assert any(NONPROGRESSING in r for r in reports)
    assert len(fake.searches) == 4


def test_search_calls_are_bounded_even_when_every_page_adds_one_id(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    wb.send(b.compose_card())
    state = {"i": 0}

    def page(tok):
        if tok is None:  # a new search sequence starts at page one again
            state["i"] = 0
        state["i"] += 1
        return f"thread t{state['i']}\nnext-page-token p{state['i']}\n"

    w = MailWire(a, runner=_search_override(fake, "taylor@houmanoids.com", page))
    got = w.fetch()
    assert got.complete is False and got.pages == MAX_PAGES and got.threads == MAX_PAGES
    assert got.incomplete_why == f"page cap ({MAX_PAGES} search pages)"
    assert len(fake.searches) == MAX_PAGES
    s = w.poll_once()
    assert s["applied"] == 1 and s["complete"] is False and w.cursor() is None


# ---- F7. thread bodies in chunks; a failed chunk leaves the fetch incomplete -----------------


def _chunk_limited(fake, self_email, calls, *, timeout_call=None):
    """The fake's runner, refusing a `thread` call for more than THREAD_CHUNK ids (rc 1)
    and timing out on call number `timeout_call`."""
    real = fake.runner_for(self_email)

    def run(argv):
        if Path(argv[1]).name == "gmail-api.py" and argv[4] == "thread":
            ids = argv[5 : argv.index("--chars")]
            calls.append(len(ids))
            if len(ids) > THREAD_CHUNK:
                return subprocess.CompletedProcess(argv, 1, "", f"{len(ids)} ids at once")
            if timeout_call is not None and len(calls) == timeout_call:
                raise subprocess.TimeoutExpired(argv, 120)
        return real(argv)

    return run


def test_thread_bodies_are_requested_in_chunks_no_larger_than_the_chunk_size(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    wb.send(b.compose_card())
    fake.threads = 2 * THREAD_CHUNK + 7
    calls: list[int] = []
    w = MailWire(a, runner=_chunk_limited(fake, "taylor@houmanoids.com", calls))
    with pytest.raises(RuntimeError, match="ids at once"):  # the fake does refuse over-size
        w._thread_chunk([f"t{i}" for i in range(THREAD_CHUNK + 1)])
    calls.clear()
    got = w.fetch()
    assert got.complete and got.chunks == 3 and got.threads == 2 * THREAD_CHUNK + 7
    assert calls == [THREAD_CHUNK, THREAD_CHUNK, 7]
    s = w.poll_once()
    assert s["applied"] == 1 and s["complete"] is True and w.cursor() == clock()


def test_a_timed_out_chunk_leaves_the_fetch_incomplete_and_the_others_applied(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    reports: list[str] = []
    a.report = reports.append
    card = bundlemod.encode(b.compose_card())
    me, peer = "taylor@houmanoids.com", "taylor@teale.com"
    g1 = fake.add(me, peer, card, thread="t1")  # chunk 1
    g2 = fake.add(me, peer, card, thread=f"t{THREAD_CHUNK + 10}")  # chunk 2
    g3 = fake.add(me, peer, card, thread=f"t{2 * THREAD_CHUNK + 3}")  # chunk 3
    fake.threads = 2 * THREAD_CHUNK + 7
    calls: list[int] = []
    w = MailWire(a, runner=_chunk_limited(fake, me, calls, timeout_call=2))
    s = w.poll_once()
    assert calls == [THREAD_CHUNK, THREAD_CHUNK, 7]  # chunk 3 was still asked for
    assert s["applied"] == 2 and s["fetched"] == 2 and s["complete"] is False
    assert any("chunk 2 of 3 failed" in e and "TimeoutExpired" in e for e in s["errors"])
    assert any("chunk 2 of 3 failed" in r and "fetch incomplete" in r for r in reports)
    assert set(_seen_mail(a)) == {g1, g3}  # the successful chunks' mails, marked one by one
    assert w.cursor() is None and a.revocations.last_checked() is None
    # the next poll, the helper healthy: the same window, only the unseen mail applied
    calls.clear()
    w2 = MailWire(a, runner=_chunk_limited(fake, me, calls))
    s = w2.poll_once()
    assert calls == [THREAD_CHUNK, THREAD_CHUNK, 7]
    assert s["applied"] == 1 and s["fetched"] == 3 and s["complete"] is True
    assert set(_seen_mail(a)) == {g1, g2, g3}
    assert w2.cursor() == clock() and a.revocations.last_checked() == clock()


def test_gmail_api_search_ids_only_skips_the_metadata_requests(capsys):
    api = _gmail_api()
    calls: list[dict] = []

    class G:
        def get(self, path, **q):
            calls.append({"path": path, **q})
            if path == "threads":
                return {"threads": [{"id": "t1"}, {"id": "t2"}], "nextPageToken": "last"}
            return {"messages": [{"payload": {"headers": []}}]}

    class A:
        query, max, page_token, ids_only = "subject:(x)", 200, None, True

    api.cmd_search(G(), A())
    lines = capsys.readouterr().out.splitlines()
    assert lines == ["thread t1", "thread t2", "next-page-token last"]
    assert [c["path"] for c in calls] == ["threads"]  # no per-thread request
    A.ids_only = False
    api.cmd_search(G(), A())
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("thread t1 msgs=1 | ") and lines[-1] == "next-page-token last"
    assert [c["path"] for c in calls[1:]] == ["threads", "threads/t1", "threads/t2"]


# ---- F8. the denial store is durable before the ledger entry ---------------------------------

DENY = [{"action": "fs.write", "resource": "host:*:customers/*"}]


def test_denial_store_is_durable_before_the_ledger_entry(tmp_path, monkeypatch):
    clock = Clock()
    reports: list[str] = []
    n = make_node(tmp_path, "n", clock, extensions={"standing_denial": True}, reports=reports)
    events = _record_syncs(monkeypatch)
    d = n.deny(deny=DENY, principal_statement="never")
    state = _ino(n.state)
    assert events == [
        ("file", _ino(n.denials.path)),  # the enforcing record, its line...
        ("dir", state),  # ...and its directory entry
        ("file", _ino(n.ledger.path)),  # only then the ledger entry
        ("dir", state),
        ("file", _ino(n.ledger.prose_path)),
        ("dir", state),
    ]
    assert latest(n)["action"] == "denial.issued" and n.denials.entries() == [d]
    assert any(f"{d['denial_id']} recorded" in r for r in reports)


def test_denial_store_failure_leaves_no_ledger_entry_and_is_reported(tmp_path, monkeypatch):
    clock = Clock()
    reports: list[str] = []
    n = make_node(tmp_path, "n", clock, extensions={"standing_denial": True}, reports=reports)
    before = len(n.ledger)
    monkeypatch.setattr(n.denials, "append", _raise(OSError(28, "disk full")))
    with pytest.raises(StorageError) as e:
        n.deny(deny=DENY, principal_statement="never")
    assert "disk full" in e.value.detail
    assert len(n.ledger) == before
    assert not any(e["action"] == "denial.issued" for e in n.ledger.entries())
    assert n.denials.entries() == []
    assert any("NOT recorded" in r and "nothing ledgered" in r for r in reports)
    assert not any("recorded" in r and "NOT" not in r for r in reports)
    monkeypatch.undo()
    d = n.deny(deny=DENY, principal_statement="never")
    assert n.denials.entries() == [d] and latest(n)["action"] == "denial.issued"


# ---- F9. inbound out.* actions are refused; direction is the discriminator -------------------


@pytest.mark.parametrize("name", ["out.ack", "out.send"])
def test_inbound_out_namespace_action_is_refused_and_its_lost_ack_recovered(
    pair, name, monkeypatch
):
    from natively import ack as ackmod
    from natively import node as nodemod

    a, b, clock, reports = pair
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
    crashed: list[int] = []

    def crash(a_, kp):
        if not crashed:
            crashed.append(1)
            raise RuntimeError("power cut before the ack")
        return real_sign(a_, kp)

    monkeypatch.setattr(nodemod.ackmod, "sign", crash)
    assert b.receive(bundle) == []  # refused, then the ack was lost
    led = b.ledger.find_msg(msg_id)
    assert led is not None and led["action"] == name and led["direction"] == "in"
    assert led["outcome"] == "refused" and led["detail"].startswith("executor.unsupported")
    assert "reserved out.* namespace" in led["detail"]
    (r,) = b.receive(bundle)  # answered from the refusal entry, nothing re-evaluated
    assert r["object"]["outcome"] == "refused:executor.unsupported"
    assert r["object"]["ledger_entry"] == entry_hash(led)
    assert len(completions(b, msg_id)) == 1
    assert b.grant_uses(g) == (0, None)  # no use consumed, no reservation ever made
    assert "status" not in seen_of(b).get(msg_id, {})
    assert b.ledger.verify() == b.ledger.head()


# ---- F10. a whitespace-only prose tail; an empty ledger -------------------------------------


def _mk_ledger(path: Path, n: int = 2) -> Ledger:
    led = Ledger(path)
    for i in range(n):
        led.append(
            ts=TS, actor="a", grant_id=None, action=f"x{i}", params_hash=None, outcome="information"
        )
    return led


@pytest.mark.parametrize("tail", ["   ", "\n   ", "\t"])
def test_whitespace_only_prose_tail_is_refused_not_repaired(tmp_path, tail):
    led = _mk_ledger(tmp_path / "l.jsonl")
    with open(led.prose_path, "a", encoding="utf-8") as f:
        f.write(tail)  # after the final newline: a physical line that matches no entry
    before = led.prose_path.read_bytes()
    with pytest.raises(IntegrityError) as e:
        led.verify()
    assert e.value.reason == "ledger.prose.unterminated"
    for call, reason in (
        (led.sync_prose, "ledger.prose.mismatch"),
        (led.repair, "ledger.repair.refused"),
    ):
        with pytest.raises(IntegrityError) as e:
            call()
        assert e.value.reason == reason and "prose lines for 2 entries" in e.value.detail
        assert "restore state/ledger.prose.txt" in e.value.detail
    with pytest.raises(IntegrityError) as e:  # an append is refused too
        led.append(
            ts=TS, actor="a", grant_id=None, action="z", params_hash=None, outcome="information"
        )
    assert e.value.reason == "ledger.prose.mismatch"
    assert led.prose_path.read_bytes() == before and len(led) == 2
    # terminated, the whitespace line is still a line that matches no entry
    led.prose_path.write_bytes(before + b"\n")
    with pytest.raises(IntegrityError) as e:
        led.verify()
    assert e.value.reason == "ledger.prose.count"


def test_empty_ledger_with_an_empty_mirror_verifies(tmp_path):
    led = Ledger(tmp_path / "l.jsonl")
    assert led.verify() == GENESIS  # no files at all
    led.prose_path.write_text("", encoding="utf-8")
    assert led.verify() == GENESIS and led.repair() == 0 and led.sync_prose() == 0
    led.path.write_text("", encoding="utf-8")
    assert led.verify() == GENESIS and len(led) == 0
    led.prose_path.write_text("   ", encoding="utf-8")  # a whitespace line with no entry
    with pytest.raises(IntegrityError) as e:
        led.verify()
    assert e.value.reason == "ledger.prose.unterminated"
    with pytest.raises(IntegrityError) as e:
        led.repair()
    assert (
        e.value.reason == "ledger.repair.refused"
        and "1 prose lines for 0 entries" in e.value.detail
    )


# ---- F11. storage-error containment: the refusal ledgering and every adapter write ----------


def test_oserror_while_ledgering_a_refusal_is_a_storage_failure(node, monkeypatch):
    reports: list[str] = []
    node.report = reports.append
    bad = {"natively": "v0", "kind": "message", "object": 5, "cards": [], "grants": []}
    before = len(node.ledger)
    monkeypatch.setattr(node.ledger, "append", _raise(OSError(28, "disk full")))
    with pytest.raises(StorageError) as e:  # the refusal's own ledger write failed
        node.receive(bad)
    assert "disk full" in e.value.detail
    assert len(node.ledger) == before
    assert any("storage failure" in r and "read again next poll" in r for r in reports)
    monkeypatch.undo()
    assert node.receive(bad) == []  # the retry ledgers the refusal
    assert (
        latest(node)["outcome"] == "verify_failed:bundle.object" and len(node.ledger) == before + 1
    )


def test_seen_file_failure_after_a_receive_leaves_the_mail_unseen_and_runs_the_outbox(
    tmp_path, monkeypatch
):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    wb.send(b.compose_info(a.card, "ping"))  # b has a send out; a never answers here
    wa.send(a.compose_card())
    clock.tick(2 * b.poll_s)  # b's re-send is due
    monkeypatch.setattr(wb, "_mark_seen", _raise(OSError(28, "disk full")))
    s = wb.poll_once()
    assert s["applied"] == 1 and s["storage_failures"] == 1 and s["complete"] is False
    assert s["resent"] == 1  # the poll went on to the outbox step
    assert any("storage failure writing the seen file for mail" in e for e in s["errors"])
    assert _seen_mail(b) == {} and wb.cursor() is None
    assert b.card_for_key(a.agent.public) is not None  # the receive itself landed
    monkeypatch.undo()
    s = wb.poll_once()
    assert s["applied"] == 1 and s["complete"] is True and len(_seen_mail(b)) == 1


def test_cursor_write_failure_is_reported_and_the_poll_goes_on(tmp_path, monkeypatch):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    wa.send(a.compose_card())
    monkeypatch.setattr(wb, "_advance_cursor", _raise(OSError(5, "Input/output error")))
    s = wb.poll_once()
    assert s["applied"] == 1 and s["complete"] is False and s["storage_failures"] == 1
    assert any("storage failure writing the cursor" in e for e in s["errors"])
    assert wb.cursor() is None and b.revocations.last_checked() == clock()  # control landed
    monkeypatch.undo()
    clock.tick(60)
    s = wb.poll_once()
    assert s["complete"] is True and wb.cursor() == clock()


def test_ignored_and_undecodable_mail_writes_are_inside_the_boundary(tmp_path, monkeypatch):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    me = "taylor@houmanoids.com"
    fake.add(me, "Someone <stranger@example.com>", "x")  # ignored (sender)
    fake.add(me, "taylor@teale.com", "not a wire body")  # from a peer, undecodable
    monkeypatch.setattr(wa, "_ledger_undecodable", _raise(OSError(5, "Input/output error")))
    s = wa.poll_once()
    assert s["ignored"] == 1 and s["storage_failures"] == 1 and s["complete"] is False
    assert any("the ledger line for undecodable mail" in e for e in s["errors"])
    assert list(_seen_mail(a).values()) == ["ignored:sender"]  # the stray is seen, the other not
    assert not any(e["action"] == "wire.decode" for e in a.ledger.entries())
    monkeypatch.undo()
    monkeypatch.setattr(wa, "_mark_seen", _raise(OSError(28, "disk full")))
    s = wa.poll_once()
    assert s["ignored"] == 0 and s["storage_failures"] == 1 and s["complete"] is False
    assert any("the seen file for undecodable mail" in e for e in s["errors"])
    assert [e["action"] for e in a.ledger.entries()].count("wire.decode") == 1
    assert list(_seen_mail(a).values()) == ["ignored:sender"]
    monkeypatch.undo()
    s = wa.poll_once()
    assert s["storage_failures"] == 0 and s["complete"] is True
    # read again (its seen mark never landed), so ledgered again: the mark is the dedup
    assert [e["action"] for e in a.ledger.entries()].count("wire.decode") == 2
    assert sorted(_seen_mail(a).values()) == ["ignored:sender", "undecodable:wire.header"]
    fake.add(me, "Another <other@example.com>", "y")
    monkeypatch.setattr(wa, "_mark_seen", _raise(OSError(28, "disk full")))
    s = wa.poll_once()
    assert s["ignored"] == 1 and s["storage_failures"] == 1 and s["complete"] is False
    assert any("the seen file for ignored mail" in e for e in s["errors"])
    monkeypatch.undo()
    s = wa.poll_once()
    assert s["ignored"] == 1 and s["complete"] is True  # counted again: it was never seen


def test_held_reply_writes_are_inside_the_boundary(tmp_path, monkeypatch):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    reports: list[str] = []
    b.report = reports.append
    wa.send(a.compose_card())
    wb.send(b.compose_card())
    wb.poll_once()
    wa.poll_once()
    wa.send(a.compose_info(b.card, "one"))
    # A: the hold fails: reported, counted, nothing held, and (round 6, F4: the
    # reply is held BEFORE the seen mark) the mail stays unseen, nothing is sent
    fake.fail_sends = True
    monkeypatch.setattr(wb, "_hold_reply", _raise(OSError(28, "disk full")))
    seen_before = dict(_seen_mail(b))
    s = wb.poll_once()
    assert s["applied"] == 1 and s["replies"] == 0 and s["storage_failures"] == 1
    assert any("storage failure writing a held reply" in e for e in s["errors"])
    assert s["complete"] is False and _seen_mail(b) == seen_before
    assert wb._pending_replies() == []
    monkeypatch.undo()
    # the peer re-sends; both copies are read (the first was never marked seen) and
    # answered with the stored ack; that send fails, so the one ack is held
    clock.tick(2 * a.poll_s)
    fake.fail_sends = False
    assert wa.poll_once()["resent"] == 1
    fake.fail_sends = True
    s = wb.poll_once()
    assert s["applied"] == 2 and s["replies"] == 0 and s["storage_failures"] == 0
    (held,) = wb._pending_replies()
    # B: the held reply is sent but its removal fails: reported, the file stays, and
    # the same ack simply goes out once more next poll
    fake.fail_sends = False
    real_unlink = Path.unlink

    def unlink(self, missing_ok=False):
        if self.parent == wb.pending_dir:
            raise OSError(5, "Input/output error")
        return real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", unlink)
    s = wb.poll_once()
    assert s["replies"] == 1 and s["storage_failures"] == 1
    assert any("the removal of sent held reply" in e for e in s["errors"])
    assert wb._pending_replies() == [held]
    monkeypatch.undo()
    s = wb.poll_once()
    assert s["replies"] == 1 and s["storage_failures"] == 0 and wb._pending_replies() == []
    assert wa.poll_once()["applied"] >= 1 and a.outbox()[-1]["status"] == "acked"


# ---- F12. ledger append and repair sync the directory too -----------------------------------


def test_ledger_first_append_syncs_both_files_and_the_directory(tmp_path, monkeypatch):
    d = tmp_path / "led"
    led = Ledger(d / "l.jsonl")
    events = _record_syncs(monkeypatch)
    led.append(ts=TS, actor="a", grant_id=None, action="x", params_hash=None, outcome="information")
    assert events == [
        ("file", _ino(led.path)),
        ("dir", _ino(d)),  # the new file's entry is durable before the prose is written
        ("file", _ino(led.prose_path)),
        ("dir", _ino(d)),
    ]
    assert led.verify() == led.head()


def test_ledger_repair_and_sync_prose_sync_the_mirror_and_its_directory(tmp_path, monkeypatch):
    led = _mk_ledger(tmp_path / "l.jsonl", 2)
    lines = led.prose_path.read_text(encoding="utf-8").splitlines()
    led.prose_path.write_text("".join(f"{ln}\n" for ln in lines[:-1]), encoding="utf-8")
    events = _record_syncs(monkeypatch)
    jsonl, prose, d = _ino(led.path), _ino(led.prose_path), _ino(tmp_path)
    # round 7 (B): the JSONL (file, directory) is synced BEFORE every mirror write, so
    # a regenerated prose line can never outlive the entry it mirrors
    assert led.repair() == 1  # the crash between the two writes
    assert events == [("file", jsonl), ("dir", d), ("file", prose), ("dir", d)]
    events.clear()
    led.prose_path.write_bytes(led.prose_path.read_bytes()[:-1])  # the newline never landed
    assert led.repair() == 0
    assert events == [("file", jsonl), ("dir", d), ("file", prose), ("dir", d)]
    events.clear()
    led.prose_path.write_text("".join(f"{ln}\n" for ln in lines[:-1]), encoding="utf-8")
    led.append(ts=TS, actor="a", grant_id=None, action="z", params_hash=None, outcome="information")
    assert events == [
        ("file", jsonl),  # the gap, repaired first: the JSONL it mirrors synced first
        ("dir", d),
        ("file", prose),
        ("dir", d),
        ("file", jsonl),  # then the new entry
        ("dir", d),
        ("file", prose),
        ("dir", d),
    ]
    assert led.verify() == led.head()

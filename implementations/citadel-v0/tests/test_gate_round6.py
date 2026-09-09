"""Round-6 gate findings (hw-20p75): the fifth cross-model gate's report. The class is
unchanged — retries and recoveries that treat VISIBLE bytes as DURABLE state — plus
three new shapes: a rename that takes effect and then reports failure (F2), a legacy
ledger without the direction field (F6), and a feed repair that reopens authorization
before the held revocations it blocked were replayed (F5).

Test categories (every module in this suite classifies its tests the same way):
  ORDERING          — every fsync is recorded and the order of files is asserted;
  FAILURE BEFORE    — a persistence step fails before anything became visible;
  FAILURE AFTER     — the syscall at step N fails AFTER its effect became visible, the
                      process retries or restarts (an unsynced tail may be gone);
  RESTART RECOVERY  — a fresh Node / process starts on what the last one left.
The category is named at each section head. What is asserted is always what a peer
can observe: a use count, a seen mark, a pending reply, an authorization.

F1  rebuilding an ack re-establishes the ledger barrier before the reservation is
    released (first test: FAILURE AFTER, then RESTART RECOVERY on a second Node; second
    test: FAILURE AFTER and ORDERING on the same instance);
F2  an exception from os.replace is classified by identity: committed, uncommitted, or
    uncertain — never by the exception (FAILURE AFTER, FAILURE BEFORE);
F3  every read and write of the adapter's own state is inside the storage boundary
    (FAILURE BEFORE: each call replaced by an immediate exception);
F4  a reply is held durably before the seen mark; a hold that fails leaves the mail
    unseen; a send that fails is flushed next poll (FAILURE AFTER, FAILURE BEFORE);
F5  a skipped startup sweep leaves a durable marker; nothing is authorized until the
    held revocations replayed (RESTART RECOVERY);
F6  a legacy ledger (no direction field) verifies, repairs, and recovers a lost ack
    (first test: framing on a hand-written legacy ledger, no failure injected; second
    test: RESTART RECOVERY, a second Node over the rewritten state);
F7  the denial store validates its framing, refuses a torn tail, repairs it, and a
    duplicate retry re-establishes the barrier (the duplicate test: FAILURE AFTER and
    ORDERING; the torn-tail test: RESTART RECOVERY over a hand-staged file — a fresh
    store handle, then CLI verbs invoked in-process (main(), each constructing a fresh
    Node; no subprocess is exercised); the earlier-line
    refusal and the corrupt-store receive tests: framing on hand-staged files, same
    instance, no syscall failed);
F8  repair retries re-establish the barrier and finish the audit (FAILURE AFTER);
F9  every local parser failure is IntegrityError (oversized integers, deep nesting);
F10 the README's residual states and these categories (documentation; no test)."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from natively import denial as denialmod
from natively import keys
from natively import revocation as revmod
from natively.adapters.mail import MailWire
from natively.cli import main
from natively.errors import IntegrityError, PostCommitError, StorageError, VerifyError
from natively.executor import Executor
from natively.ledger import GENESIS, Ledger, entry_hash, prose_line
from natively.node import REPLAY_MARKER, Node

from .conftest import Clock, make_node, uid
from .test_gate_round3 import KEY, completions, held_revocations, pair, seen_of
from .test_gate_round4 import _unpinned_pair
from .test_gate_round5 import _ino, _line, _raise, _record_syncs, _rev, _seen_mail
from .test_hardening import STATEMENT, fs_write_scope, latest, write_bundle
from .test_mail_adapter import pair_over_mail

__all__ = ["pair"]  # the fixture is re-exported for this module's tests

TS = "2026-09-07T07:00:00Z"


def _file_fsync_failing_for(path: Path, state: dict | None = None):
    """An os.fsync that fails for the FILE at `path` (never for a directory), so the
    bytes are visible and unsynced; `state["failed"]` counts the failures."""
    state = state if state is not None else {}
    state.setdefault("failed", 0)
    real = os.fsync

    def fsync(fd):
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode) and path.exists() and (st.st_dev, st.st_ino) == _ino(path):
            state["failed"] += 1
            raise OSError(5, "Input/output error")
        real(fd)

    return fsync


def _drop_last_line(path: Path) -> None:
    """Simulate the power loss: the unsynced tail (the last line) never landed."""
    data = path.read_bytes()
    head, _, _tail = data[:-1].rpartition(b"\n")
    path.write_bytes(head + b"\n" if head else b"")


def _one_use_grant(a, b, name):
    return a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, name),
        principal_statement=STATEMENT,
        max_uses=1,
    )


# ---- F1. the rebuilt ack re-establishes the ledger barrier (FAILURE AFTER, RESTART) --------


def _completion_visible_but_unsynced(pair, monkeypatch, name="f1.txt"):
    """The executor ran, the completion line is visible in ledger.jsonl, its file
    fsync failed: a StorageError, the reservation stays, no prose line, no ack."""
    a, b, clock, reports = pair
    g = _one_use_grant(a, b, name)
    bundle = write_bundle(a, b, g, name, "landed\n")
    msg_id = bundle["object"]["msg_id"]
    state = {}
    monkeypatch.setattr(os, "fsync", _file_fsync_failing_for(b.ledger.path, state))
    with pytest.raises(StorageError):
        b.receive(bundle)
    assert state["failed"] == 1
    assert (b.scratch_dir / name).read_text() == "landed\n"
    assert seen_of(b)[msg_id] == {"status": "in_progress", "grant_id": g["grant_id"], "ts": TS}
    assert b.ledger.path.read_bytes().rstrip(b"\n").endswith(b"}")
    assert json.loads(b.ledger.path.read_bytes().splitlines()[-1])["msg_id"] == msg_id
    assert len(b.ledger.prose_path.read_text().splitlines()) == len(b.ledger.entries()) - 1
    return a, b, g, bundle, msg_id, state


def test_rebuilt_ack_is_refused_while_the_ledger_barrier_fails_and_the_reservation_stays(
    pair, monkeypatch
):
    a, b, g, bundle, msg_id, state = _completion_visible_but_unsynced(pair, monkeypatch)
    with pytest.raises(StorageError):  # redelivery: the barrier (the ledger fsync) fails again
        b.receive(bundle)
    assert state["failed"] == 2
    assert "ack" not in seen_of(b)[msg_id]  # no stored ack: the reservation was not released
    monkeypatch.undo()
    _drop_last_line(b.ledger.path)  # the power loss removes the unsynced completion
    b2 = Node(state_dir=b.state, keys_dir=b.keys_dir, scratch_dir=b.scratch_dir, clock=Clock())
    assert b2.ledger.verify() == b2.ledger.head()
    assert completions(b2, msg_id) == []
    assert seen_of(b2)[msg_id]["status"] == "in_progress"  # the last durable use record
    assert b2.grant_uses(g) == (1, None)  # still one use: the reservation counts
    (r,) = b2.receive(bundle)  # answered failed:interrupted, the use stays consumed
    assert r["object"]["outcome"] == "failed:interrupted"
    assert b2.grant_uses(g) == (1, None)
    (r2,) = b2.receive(write_bundle(a, b2, g, "f1b.txt", "again\n"))
    assert r2["object"]["outcome"] == "refused:no_authorizing_grant"


def test_rebuilt_ack_after_a_successful_barrier_yields_one_use_and_a_stored_ack(pair, monkeypatch):
    a, b, g, bundle, msg_id, state = _completion_visible_but_unsynced(pair, monkeypatch)
    monkeypatch.undo()
    events = _record_syncs(monkeypatch)
    (r,) = b.receive(bundle)  # redelivery: the barrier succeeds, then the ack is stored
    assert r["object"]["outcome"] == "applied"
    led, prose, state_dir = _ino(b.ledger.path), _ino(b.ledger.prose_path), _ino(b.state)
    # the JSONL and the mirror fsynced (file, directory), the missing prose line
    # regenerated, and only then the seen file (the ack) written
    i = events.index(("file", led))
    assert events[i : i + 4] == [
        ("file", led),
        ("dir", state_dir),
        ("file", prose),
        ("dir", state_dir),
    ]
    i_prose_write = events.index(("file", prose), i + 4)
    seen_writes = [j for j, ev in enumerate(events) if ev == ("file", _ino(b.state / "seen.json"))]
    assert seen_writes and min(seen_writes) > i_prose_write
    assert b.ledger.verify() == b.ledger.head()
    assert len(completions(b, msg_id)) == 1 and b.grant_uses(g) == (1, None)
    assert seen_of(b)[msg_id]["ack"] == r["object"]
    assert any("ack was lost; rebuilding" in x for x in pair[3])


# ---- F2. an os.replace exception is decided by identity (FAILURE AFTER / BEFORE) ------------


def _replace_that_takes_effect_then_raises():
    real = os.replace

    def replace(*a, **kw):
        if "src_dir_fd" in kw:
            real(*a, **kw)  # the destination changed...
            raise OSError(5, "Input/output error")  # ...then the syscall reports failure
        return real(*a, **kw)

    return replace


def _replace_that_loses_the_temp_then_raises():
    real = os.replace

    def replace(src, dst, *a, **kw):
        if "src_dir_fd" in kw:
            os.unlink(src, dir_fd=kw["src_dir_fd"])  # neither name settles it
            raise OSError(5, "Input/output error")
        return real(src, dst, *a, **kw)

    return replace


def test_executor_classifies_a_rename_that_took_effect_as_post_commit(tmp_path, monkeypatch):
    ex = Executor(KEY, tmp_path / "scratch")
    monkeypatch.setattr(os, "replace", _replace_that_takes_effect_then_raises())
    with pytest.raises(PostCommitError) as e:
        ex.apply("fs.write", ex.resource_for("a.txt"), {"content": "x"})
    assert "rename reported failure" in e.value.detail and isinstance(e.value.cause, OSError)
    assert (tmp_path / "scratch" / "a.txt").read_text() == "x"
    assert [p.name for p in (tmp_path / "scratch").iterdir()] == ["a.txt"]  # no temp left


def test_executor_keeps_a_rename_that_did_nothing_an_ordinary_failure(tmp_path, monkeypatch):
    ex = Executor(KEY, tmp_path / "scratch")
    (tmp_path / "scratch" / "b.txt").write_text("old")  # an older destination, another inode
    real = os.replace
    monkeypatch.setattr(
        os,
        "replace",
        lambda *a, **kw: (
            (_ for _ in ()).throw(OSError(28, "No space left on device"))
            if "src_dir_fd" in kw
            else real(*a, **kw)
        ),
    )
    with pytest.raises(OSError) as e:
        ex.apply("fs.write", ex.resource_for("b.txt"), {"content": "new"})
    assert not isinstance(e.value, PostCommitError)
    assert (tmp_path / "scratch" / "b.txt").read_text() == "old"  # untouched
    assert [p.name for p in (tmp_path / "scratch").iterdir()] == ["b.txt"]  # the temp removed


def test_executor_fails_closed_when_the_rename_result_is_uncertain(tmp_path, monkeypatch):
    ex = Executor(KEY, tmp_path / "scratch")
    monkeypatch.setattr(os, "replace", _replace_that_loses_the_temp_then_raises())
    with pytest.raises(PostCommitError) as e:
        ex.apply("fs.write", ex.resource_for("c.txt"), {"content": "x"})
    assert "rename result uncertain" in e.value.detail
    assert list((tmp_path / "scratch").iterdir()) == []


def test_ambiguous_rename_consumes_the_use_at_the_node(pair, monkeypatch):
    a, b, clock, reports = pair
    g = _one_use_grant(a, b, "amb.txt")
    bundle = write_bundle(a, b, g, "amb.txt", "landed\n")
    msg_id = bundle["object"]["msg_id"]
    monkeypatch.setattr(os, "replace", _replace_that_takes_effect_then_raises())
    (r,) = b.receive(bundle)
    assert r["object"]["outcome"] == "failed:post_commit"
    assert (b.scratch_dir / "amb.txt").read_text() == "landed\n"
    led = latest(b)
    assert led["outcome"] == "failed:post_commit" and led["msg_id"] == msg_id
    assert "rename reported failure" in led["detail"]
    assert b.grant_uses(g) == (1, None)  # the use is spent
    monkeypatch.undo()
    (r2,) = b.receive(write_bundle(a, b, g, "amb.txt", "again\n"))
    assert r2["object"]["outcome"] == "refused:no_authorizing_grant"
    assert (b.scratch_dir / "amb.txt").read_text() == "landed\n"
    # the uncertain shape at the node: the same accounting
    g2 = _one_use_grant(a, b, "unc.txt")
    monkeypatch.setattr(os, "replace", _replace_that_loses_the_temp_then_raises())
    (r3,) = b.receive(write_bundle(a, b, g2, "unc.txt"))
    assert r3["object"]["outcome"] == "failed:post_commit"
    assert "rename result uncertain" in latest(b)["detail"] and b.grant_uses(g2) == (1, None)


def test_pre_replacement_failure_still_consumes_nothing(pair, monkeypatch):
    """The round-4 claim, kept: a rename that raised before doing anything."""
    a, b, clock, reports = pair
    g = _one_use_grant(a, b, "pre.txt")
    real = os.replace
    monkeypatch.setattr(
        os,
        "replace",
        lambda *a, **kw: (
            (_ for _ in ()).throw(OSError(28, "No space left on device"))
            if "src_dir_fd" in kw
            else real(*a, **kw)
        ),
    )
    (r,) = b.receive(write_bundle(a, b, g, "pre.txt"))
    assert r["object"]["outcome"] == "failed:OSError"
    assert latest(b)["outcome"] == "failed" and b.grant_uses(g) == (0, None)
    assert not (b.scratch_dir / "pre.txt").exists()


# ---- F3. every adapter read and write is inside the boundary (FAILURE BEFORE) ---------------


def _connected_over_mail(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    wa.send(a.compose_card())
    wb.send(b.compose_card())
    wb.poll_once()
    wa.poll_once()
    return a, b, wa, wb, fake, clock


def _with_a_due_resend(wire, node, peer_card, clock):
    """`node` has a message out whose re-send is due: the outbox step has work."""
    wire.send(node.compose_info(peer_card, "anyone?"))
    clock.tick(2 * node.poll_s)


def test_freshness_persistence_failure_is_counted_and_the_cursor_stays(tmp_path, monkeypatch):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    _with_a_due_resend(wb, b, a.card, clock)
    wa.send(a.compose_card())
    monkeypatch.setattr(b, "mark_lookup_ok", _raise(OSError(5, "Input/output error")))
    s = wb.poll_once()
    assert s["applied"] == 1 and s["storage_failures"] == 1 and s["complete"] is False
    assert any("storage failure writing the freshness sidecar" in e for e in s["errors"])
    assert b.revocations.last_checked() is None and wb.cursor() is None
    assert s["resent"] == 1  # the outbox step ran
    monkeypatch.undo()
    s = wb.poll_once()
    assert s["complete"] is True and wb.cursor() == clock()
    assert b.revocations.last_checked() == clock()


def test_pending_reply_read_failure_leaves_the_file_and_runs_the_outbox(tmp_path, monkeypatch):
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "one"))
    fake.fail_sends = True
    wb.poll_once()
    (held,) = wb._pending_replies()
    fake.fail_sends = False
    _with_a_due_resend(wb, b, a.card, clock)
    real = Path.read_bytes

    def read_bytes(self):
        if self == held:
            raise OSError(5, "Input/output error")
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    cursor_before = wb.cursor()
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["replies"] == 0
    assert any("storage failure reading held reply" in e for e in s["errors"])
    assert wb._pending_replies() == [held]  # left in place
    assert s["resent"] == 1  # the outbox step ran
    # round 7 (D): a flush failure is folded into completeness — the cursor stays
    assert s["complete"] is False and wb.cursor() == cursor_before != clock()
    monkeypatch.undo()
    s = wb.poll_once()
    assert s["replies"] == 1 and wb._pending_replies() == []
    assert s["complete"] is True and wb.cursor() == clock()


def test_seen_file_read_failure_ends_the_apply_half_and_runs_the_outbox(tmp_path, monkeypatch):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    _with_a_due_resend(wb, b, a.card, clock)
    wa.send(a.compose_card())
    monkeypatch.setattr(wb, "_seen", _raise(OSError(5, "Input/output error")))
    s = wb.poll_once()
    assert s["fetched"] == 0 and s["applied"] == 0 and s["storage_failures"] == 1
    assert s["complete"] is False and fake.searches == []  # nothing fetched
    assert any("storage failure reading the seen file" in e for e in s["errors"])
    assert s["resent"] == 1  # the outbox step still ran
    assert b.card_for_key(a.agent.public) is None
    monkeypatch.undo()
    s = wb.poll_once()
    assert s["applied"] == 1 and s["complete"] is True
    # a seen file of ours that does not parse is the same storage failure
    _with_a_due_resend(wb, b, a.card, clock)
    wb.seen_path.write_text("{not json")
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["applied"] == 0 and s["resent"] == 1
    assert any("IntegrityError" in e and "state.corrupt" in e for e in s["errors"])


def test_outbox_listing_failure_is_counted_and_the_poll_returns(tmp_path, monkeypatch):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    _with_a_due_resend(wb, b, a.card, clock)
    wa.send(a.compose_card())
    monkeypatch.setattr(b, "outbox_due", _raise(OSError(5, "Input/output error")))
    s = wb.poll_once()
    assert s["applied"] == 1 and s["storage_failures"] == 1 and s["resent"] == 0
    assert any("storage failure reading the outbox" in e for e in s["errors"])
    # round 7: the outbox bookkeeping is persistence of ours, counted BEFORE the
    # completeness decision — the fetch-and-apply half landed whole, the pass did not
    assert s["complete"] is False and wb.cursor() is None
    monkeypatch.undo()
    s = wb.poll_once()
    assert s["resent"] == 1 and s["complete"] is True and wb.cursor() == clock()


def test_outbox_advance_failure_on_one_entry_does_not_stop_the_others(tmp_path, monkeypatch):
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wb.send(b.compose_info(a.card, "one"))
    wb.send(b.compose_info(a.card, "two"))
    first = b.outbox()[0]["msg_id"]
    clock.tick(2 * b.poll_s)
    real = b.outbox_advance

    def advance(msg_id):
        if msg_id == first:
            raise OSError(5, "Input/output error")
        return real(msg_id)

    monkeypatch.setattr(b, "outbox_advance", advance)
    s = wb.poll_once()
    assert s["resent"] == 2 and s["storage_failures"] == 1  # both left the box
    assert any("storage failure writing the attempt count" in e for e in s["errors"])
    attempts = {x["msg_id"]: x["attempts"] for x in b.outbox()}
    assert attempts[first] == 1 and set(attempts.values()) == {1, 2}


def test_outbox_mark_undelivered_failure_on_one_entry_does_not_stop_the_others(
    tmp_path, monkeypatch
):
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wb.send(b.compose_info(a.card, "one"))
    wb.send(b.compose_info(a.card, "two"))
    first = b.outbox()[0]["msg_id"]
    for tick in (2, 4, 8, 16):
        clock.tick(tick * b.poll_s)
        wb.poll_once()
    assert {x["status"] for x in b.outbox()} == {"undelivered"}
    # again, with the first mark failing
    wb.send(b.compose_info(a.card, "three"))
    wb.send(b.compose_info(a.card, "four"))
    third = [x for x in b.outbox() if x["status"] == "pending"][0]["msg_id"]
    for tick in (2, 4, 8):
        clock.tick(tick * b.poll_s)
        wb.poll_once()
    clock.tick(16 * b.poll_s)
    real = b.outbox_mark_undelivered

    def mark(msg_id):
        if msg_id == third:
            raise OSError(5, "Input/output error")
        return real(msg_id)

    monkeypatch.setattr(b, "outbox_mark_undelivered", mark)
    s = wb.poll_once()
    assert s["undelivered"] == 1 and s["storage_failures"] == 1
    assert any("storage failure writing the undelivered mark" in e for e in s["errors"])
    status = {x["msg_id"]: x["status"] for x in b.outbox()}
    assert status[third] == "pending" and list(status.values()).count("undelivered") == 3
    assert first != third
    monkeypatch.undo()
    s = wb.poll_once()
    assert s["undelivered"] == 1 and {x["status"] for x in b.outbox()} == {"undelivered"}


# ---- F4. the reply is held before the seen mark (FAILURE AFTER / BEFORE) ---------------------


def _dir_fsync_failing_after_the_replacement_of(path: Path, monkeypatch):
    """The directory fsync that follows the rename INTO `path` fails (the replacement
    is visible, its barrier is not); every other fsync and rename works."""
    real_replace, real_fsync = os.replace, os.fsync
    armed = {"on": False}

    def replace(src, dst, *a, **kw):
        real_replace(src, dst, *a, **kw)
        if Path(dst) == path:
            armed["on"] = True

    def fsync(fd):
        st = os.fstat(fd)
        key = (st.st_dev, st.st_ino)
        if armed["on"] and stat.S_ISDIR(st.st_mode) and key == _ino(path.parent):
            armed["on"] = False
            raise OSError(5, "Input/output error")
        real_fsync(fd)

    monkeypatch.setattr(os, "replace", replace)
    monkeypatch.setattr(os, "fsync", fsync)


def test_seen_mark_visible_but_its_directory_fsync_failed_the_next_poll_flushes_the_reply(
    tmp_path, monkeypatch
):
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "one"))
    sends_before = len(fake.sends)
    _dir_fsync_failing_after_the_replacement_of(wb.seen_path, monkeypatch)
    s = wb.poll_once()
    assert s["applied"] == 1 and s["replies"] == 0 and s["storage_failures"] == 1
    assert s["complete"] is False and any("the seen file for mail" in e for e in s["errors"])
    assert len(_seen_mail(b)) == 2  # the seen mark became visible (the rename landed)
    (held,) = wb._pending_replies()  # the reply was held BEFORE the mark
    assert json.loads(held.read_text())["kind"] == "ack"
    assert len(fake.sends) == sends_before  # nothing sent this poll
    monkeypatch.undo()
    s = wb.poll_once()  # the next poll skips the seen id and flushes the held reply
    assert s["replies"] == 1 and s["applied"] == 0 and wb._pending_replies() == []
    s = wa.poll_once()
    assert s["applied"] == 1 and a.outbox()[-1]["status"] == "acked"


def test_hold_failure_leaves_the_mail_unseen_and_the_poll_incomplete(tmp_path, monkeypatch):
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "one"))
    events = _record_syncs(monkeypatch)
    monkeypatch.setattr(wb, "_hold_reply", _raise(OSError(28, "disk full")))
    seen_before = dict(_seen_mail(b))
    s = wb.poll_once()
    assert s["applied"] == 1 and s["replies"] == 0 and s["storage_failures"] == 1
    assert s["complete"] is False and _seen_mail(b) == seen_before  # NOT marked seen
    assert wb.cursor() is not None and any("a held reply for mail" in e for e in s["errors"])
    assert ("file", _ino(wb.seen_path)) not in events[events.index(("file", _ino(b.ledger.path))) :]
    assert wb._pending_replies() == [] and len(fake.inbox.get("taylor@houmanoids.com", [])) == 1
    monkeypatch.undo()
    s = wb.poll_once()  # read again, answered from the stored ack, held, marked, sent
    assert s["applied"] == 1 and s["replies"] == 1 and s["complete"] is True
    assert len(_seen_mail(b)) == 2 and wb._pending_replies() == []


def test_send_failure_with_a_successful_hold_sends_next_poll_and_deletes_the_copy(tmp_path):
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    reports: list[str] = []
    b.report = reports.append
    wa.send(a.compose_info(b.card, "one"))
    fake.fail_sends = True
    s = wb.poll_once()
    assert s["applied"] == 1 and s["replies"] == 0 and s["storage_failures"] == 0
    assert s["complete"] is True  # a transport failure is not a persistence failure
    (held,) = wb._pending_replies()
    assert any("kept for the next poll" in r and held.name in r for r in reports)
    assert len(_seen_mail(b)) == 2  # the mark landed (the reply is safe under pending-replies/)
    fake.fail_sends = False
    s = wb.poll_once()
    assert s["replies"] == 1 and s["applied"] == 0 and wb._pending_replies() == []
    assert wa.poll_once()["applied"] == 1 and a.outbox()[-1]["status"] == "acked"


def test_a_reply_is_held_before_the_seen_mark_and_deleted_after_the_send(tmp_path, monkeypatch):
    """ORDERING: hold (file, dir), seen mark (file, dir), then the send."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "one"))
    events = _record_syncs(monkeypatch)
    sends_before = len(fake.sends)
    s = wb.poll_once()
    assert s["replies"] == 1
    pending = wb.pending_dir
    i_hold = next(i for i, ev in enumerate(events) if ev[0] == "dir" and ev[1] == _ino(pending))
    i_seen = events.index(("file", _ino(wb.seen_path)))
    assert i_hold < i_seen and events[i_seen + 1] == ("dir", _ino(b.state))
    assert len(fake.sends) == sends_before + 1 and wb._pending_replies() == []


# ---- F5. a skipped sweep leaves a marker; nothing authorized until replayed (RESTART) --------


def _pinned_held_torn(tmp_path, reports=None):
    """B trusts A on disk (the crash-after-pin order), A's revocation of g is held
    under B's revocations-pending/, and B's feed is torn."""
    a, b, g, rev, clock = _unpinned_pair(tmp_path, reports=reports)
    assert b.receive(a.compose_revocation(rev)) == []
    (held,) = held_revocations(b, rev["rev_id"])
    p = b.state / "pinned.json"
    p.write_text(json.dumps({**json.loads(p.read_text()), a.principal.public: {"name": "a"}}))
    with open(b.revocations.path, "ab") as f:
        f.write(b'{"rev_id": "rev_')  # power loss inside an earlier append
    return a, b, g, rev, held, clock


def _running(b, clock, reports):
    return Node(
        state_dir=b.state,
        keys_dir=b.keys_dir,
        scratch_dir=b.scratch_dir,
        clock=clock,
        report=reports.append,
    )


def test_repair_by_another_process_does_not_reopen_authorization_before_the_replay(tmp_path):
    reports: list[str] = []
    a, b, g, rev, held, clock = _pinned_held_torn(tmp_path, reports)
    b2 = _running(b, clock, reports)  # the sweep is skipped: the marker is written
    marker = b.state / REPLAY_MARKER
    assert json.loads(marker.read_text())["principals"] == [a.principal.public]
    assert held.exists() and any("nothing is authorized" in r for r in reports)
    # before the repair: every receive that reads the feed is a storage failure
    with pytest.raises(IntegrityError):
        b2.receive(a.compose_card())
    # the feed is repaired by ANOTHER process (the raw truncation, no replay): the
    # running node sees a healthy feed, the marker still stands
    assert revmod.RevocationFeed(b.revocations.path).repair() > 0
    assert held.exists() and marker.exists()
    b2.receive(a.compose_card())
    b2.mark_lookup_ok()
    (r,) = b2.receive(write_bundle(a, b2, g, "h.txt"))
    # the node replays the held revocation itself before authorizing, so the covered
    # grant is refused as revoked and the marker is gone
    assert r["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "grant.revoked" in latest(b2)["detail"] and not (b2.scratch_dir / "h.txt").exists()
    assert not held.exists() and not marker.exists()
    replayed = [e for e in b2.ledger.entries() if e["action"] == "revocation.replayed"]
    assert len(replayed) == 1 and "replay before authorizing" in replayed[0]["detail"]
    # an unrelated grant applies once the marker is gone
    g2 = a.issue_grant(
        subject_card=b2.card, scope=fs_write_scope(b2, "ok.txt"), principal_statement=STATEMENT
    )
    (r2,) = b2.receive(write_bundle(a, b2, g2, "ok.txt", "fine\n"))
    assert r2["object"]["outcome"] == "applied"


def test_action_is_a_storage_failure_while_the_replay_cannot_run(tmp_path, monkeypatch):
    reports: list[str] = []
    a, b, g, rev, held, clock = _pinned_held_torn(tmp_path, reports)
    b2 = _running(b, clock, reports)
    marker = b.state / REPLAY_MARKER
    assert revmod.RevocationFeed(b.revocations.path).repair() > 0
    b2.receive(a.compose_card())
    b2.mark_lookup_ok()
    # the replay attempt itself finds the feed torn again (another crash): the
    # storage failure it is (round 12), raised through — nothing ledgered, nothing
    # acked, nothing applied, the marker stays; never a verdict the peer keeps
    monkeypatch.setattr(
        b2, "_replay_pending_revocations", _raise(IntegrityError("feed.torn", "still torn"))
    )
    g2 = a.issue_grant(
        subject_card=b2.card, scope=fs_write_scope(b2, "ok.txt"), principal_statement=STATEMENT
    )
    bundle = write_bundle(a, b2, g2, "ok.txt", "fine\n")
    n = len(b2.ledger)
    with pytest.raises(IntegrityError) as e:
        b2.receive(bundle)
    assert e.value.reason == "feed.torn" and len(b2.ledger) == n
    assert not (b2.scratch_dir / "ok.txt").exists() and b2._seen() == {}
    assert marker.exists() and held.exists()
    monkeypatch.undo()
    # the mail was never seen: the SAME message is evaluated again — the replay
    # runs first, then the action applies (g2 is not revoked)
    (r3,) = b2.receive(bundle)
    assert r3["object"]["outcome"] == "applied"
    assert not marker.exists() and not held.exists()
    assert b2.revocations.grant_revoked_by(g["grant_id"], a.principal.public) is not None


def test_feed_repair_verb_replays_under_the_lock_and_removes_the_marker(tmp_path, capsys):
    reports: list[str] = []
    a, b, g, rev, held, clock = _pinned_held_torn(tmp_path, reports)
    marker = b.state / REPLAY_MARKER
    argv = ["--state", str(b.state), "--keys", str(b.keys_dir), "--scratch", str(b.scratch_dir)]
    assert main([*argv, "feed", "repair"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("feed repaired: 16 torn byte(s) truncated; 1 revocation(s)")
    assert not marker.exists() and not held.exists()
    actions = [e["action"] for e in b.ledger.entries()]
    assert actions.index("feed.repaired") < actions.index("revocation.replayed")
    replayed = [e for e in b.ledger.entries() if e["action"] == "revocation.replayed"]
    assert "feed repaired" in replayed[0]["detail"]
    b3 = _running(b, clock, reports)
    assert not marker.exists()
    b3.receive(a.compose_card())
    b3.mark_lookup_ok()
    (r,) = b3.receive(write_bundle(a, b3, g, "h.txt"))
    assert r["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "grant.revoked" in latest(b3)["detail"]


def test_a_sweep_that_can_replay_clears_a_stale_marker(tmp_path):
    reports: list[str] = []
    a, b, g, rev, held, clock = _pinned_held_torn(tmp_path, reports)
    _running(b, clock, reports)
    marker = b.state / REPLAY_MARKER
    assert marker.exists()
    assert revmod.RevocationFeed(b.revocations.path).repair() > 0
    b3 = _running(b, clock, reports)  # a restart on the repaired feed: the sweep replays
    assert not marker.exists() and not held.exists()
    assert b3.revocations.grant_revoked_by(g["grant_id"], a.principal.public) is not None


# ---- F6. a legacy ledger without the direction field (RESTART RECOVERY) --------------------


def _legacy_entry(prev: str, **kw) -> dict:
    e = {
        "ts": TS,
        "actor": "a",
        "grant_id": None,
        "action": "x",
        "params_hash": None,
        "outcome": "information",
        "prev_hash": prev,
        "msg_id": None,
        "detail": "",
    }
    e.update(kw)
    return e


def _legacy_prose(e: dict, h: str) -> str:
    """The prose line exactly as the pre-direction ledger wrote it: the "->" arrow."""
    g = f" under {e['grant_id']}" if e["grant_id"] else " (no grant)"
    m = f" msg {e['msg_id']}" if e.get("msg_id") else ""
    d = f" — {e['detail']}" if e.get("detail") else ""
    return f"{e['ts']}  {e['actor']}: {e['action']}{g}{m} -> {e['outcome']}{d} [{h[7:19]}]"


def _write_legacy_ledger(path: Path, entries: list[dict]) -> None:
    lines, prose, prev = [], [], GENESIS
    for e in entries:
        e = {**e, "prev_hash": prev}
        h = entry_hash(e)
        lines.append(json.dumps(e, ensure_ascii=False, separators=(",", ":")))
        prose.append(_legacy_prose(e, h))
        prev = h
    path.write_text("".join(ln + "\n" for ln in lines), encoding="utf-8")
    path.with_suffix(".prose.txt").write_text("".join(ln + "\n" for ln in prose), encoding="utf-8")


def test_legacy_ledger_verifies_repairs_and_finds_its_completions(tmp_path):
    msg_id = uid("msg")
    entries = [
        _legacy_entry(GENESIS),
        _legacy_entry(
            GENESIS, action="fs.write", outcome="refused", msg_id=msg_id, detail="denied: no"
        ),
    ]
    _write_legacy_ledger(tmp_path / "l.jsonl", entries)
    led = Ledger(tmp_path / "l.jsonl")
    assert led.verify() == led.head()  # historical hashes and the mirror as written
    assert all("direction" not in e for e in led.entries())
    assert led.find_msg(msg_id)["outcome"] == "refused"  # a legacy entry is inbound
    assert led.repair() == 0
    # the mirror short by the legacy line is regenerated exactly as it was
    lines = led.prose_path.read_text().splitlines()
    led.prose_path.write_text(lines[0] + "\n")
    assert led.repair() == 1
    assert led.prose_path.read_text().splitlines() == lines
    assert led.verify() == led.head()
    for e in led.entries():
        assert prose_line(e, entry_hash(e)) == _legacy_prose(e, entry_hash(e))
    # a mixed ledger: legacy first, then new entries with the field
    led.append(ts=TS, actor="a", grant_id=None, action="y", params_hash=None, outcome="information")
    led.append(
        ts=TS,
        actor="a",
        grant_id=None,
        action="out.ack",
        params_hash=None,
        outcome="applied",
        msg_id=msg_id,
        direction="out",
    )
    assert led.verify() == led.head()
    assert [e.get("direction") for e in led.entries()] == [None, None, "in", "out"]
    assert led.find_msg(msg_id)["outcome"] == "refused"  # never the outbound entry
    # a legacy entry may lack direction, but nothing else; and a bad value is refused
    bad = Ledger(tmp_path / "bad.jsonl")
    e = {k: v for k, v in _legacy_entry(GENESIS).items() if k != "detail"}
    bad.path.write_text(json.dumps(e) + "\n")
    with pytest.raises(IntegrityError) as ex:
        bad.verify()
    assert ex.value.reason == "ledger.entry.fields"
    bad.path.write_text(json.dumps({**_legacy_entry(GENESIS), "direction": "sideways"}) + "\n")
    with pytest.raises(IntegrityError) as ex:
        bad.verify()
    assert ex.value.reason == "ledger.entry.fields"


def _strip_direction(node) -> None:
    """Rewrite the node's ledger as a pre-direction ledger (the field removed from
    every entry, the chain recomputed, the mirror as that version wrote it)."""
    entries = [{k: v for k, v in e.items() if k != "direction"} for e in node.ledger.entries()]
    _write_legacy_ledger(node.ledger.path, entries)
    node.ledger._entries = None


def test_lost_ack_for_a_legacy_refusal_is_rebuilt_not_re_evaluated(pair):
    a, b, clock, reports = pair
    g = _one_use_grant(a, b, "leg.txt")
    rev = a.revoke(grants=[g["grant_id"]], principal_statement="no")
    b.receive(a.compose_revocation(rev))
    bundle = write_bundle(a, b, g, "leg.txt")
    msg_id = bundle["object"]["msg_id"]
    (r,) = b.receive(bundle)
    assert r["object"]["outcome"] == "refused:no_authorizing_grant"
    # the state an older node left: a legacy ledger, the ack lost
    _strip_direction(b)
    seen = seen_of(b)
    del seen[msg_id]
    (b.state / "seen.json").write_text(json.dumps(seen))
    b2 = Node(state_dir=b.state, keys_dir=b.keys_dir, scratch_dir=b.scratch_dir, clock=clock)
    assert b2.ledger.verify() == b2.ledger.head()
    # even with the refusal's condition cleared, the answer is the legacy refusal
    b2.revocations.path.write_text("")
    b2.mark_lookup_ok()
    n = len(b2.ledger)
    (r2,) = b2.receive(bundle)
    assert r2["object"]["outcome"] == "refused:no_authorizing_grant"
    assert len(b2.ledger) == n and not (b2.scratch_dir / "leg.txt").exists()
    assert b2.grant_uses(g) == (0, None)


# ---- F7. the denial store's framing (FAILURE AFTER, ORDERING) --------------------------------

DENY = [{"action": "fs.write", "resource": "host:*:customers/*"}]


def _denial(kp: keys.KeyPair, statement="never"):
    return denialmod.sign(
        denialmod.build(principal_key=kp.public, ts=TS, deny=DENY, principal_statement=statement),
        kp,
    )


def test_interrupted_denial_append_is_framed_on_the_next_add(tmp_path):
    kp = keys.KeyPair.generate()
    store = denialmod.DenialStore(tmp_path / "denials.jsonl")
    d1, d2 = _denial(kp), _denial(kp, "also never")
    store.path.write_bytes(_line(d1).encode())  # the newline never landed
    assert store.load() == ([d1], True)
    assert store.repair() == 0  # not torn
    assert store.add(d2, pinned={kp.public}) is True
    raw = store.path.read_bytes()
    assert raw.endswith(b"\n") and raw.count(b"\n") == 2  # one object per line
    assert [json.loads(ln) for ln in raw.splitlines()] == [d1, d2]
    assert store.entries() == [d1, d2]
    assert (
        store.denied(
            action="fs.write",
            resource="host:x:customers/1",
            card_hash="sha256:" + "0" * 64,
            principal_key=kp.public,
        )
        == d1
    )


def test_torn_denial_tail_is_refused_then_repaired_by_the_verb(tmp_path, capsys):
    clock = Clock()
    n = make_node(tmp_path, "n", clock, extensions={"standing_denial": True})
    d = n.deny(deny=DENY, principal_statement="never")
    torn = _line(d)[:37].encode()
    with open(n.denials.path, "ab") as f:
        f.write(torn)
    store = denialmod.DenialStore(n.denials.path)
    with pytest.raises(IntegrityError) as e:
        store.load()
    assert e.value.reason == "denial.torn" and "denial repair" in str(e.value)
    assert isinstance(e.value, StorageError) and not isinstance(e.value, VerifyError)
    with pytest.raises(IntegrityError):
        store.denied(action="fs.write", resource="r", card_hash="sha256:x", principal_key="k")
    with pytest.raises(IntegrityError):  # append refuses while the file is torn
        store.append(_denial(n.principal))
    with pytest.raises(IntegrityError):  # so does the issuing verb: a storage failure
        n.deny(deny=DENY, principal_statement="again")
    assert not any(e["detail"].startswith("again") for e in n.ledger.entries())
    argv = ["--state", str(n.state), "--keys", str(n.keys_dir), "--scratch", str(n.scratch_dir)]
    assert main([*argv, "denial", "verify"]) == 2
    assert "denial.torn" in capsys.readouterr().err
    before = len(n.ledger)
    assert main([*argv, "denial", "repair"]) == 0
    out = capsys.readouterr().out
    assert out.startswith(f"denial store repaired: {len(torn)} torn byte(s) truncated; 1 denial(s)")
    led = latest(n)
    assert len(n.ledger) == before + 1 and led["action"] == "denial.repaired"
    assert f"{len(torn)} bytes" in led["detail"] and "denials.jsonl" in led["detail"]
    assert not (n.state / "denial-repair-pending.json").exists()
    assert store.load() == ([d], False)
    assert main([*argv, "denial", "repair"]) == 0  # nothing torn: nothing ledgered
    assert "0 torn byte(s)" in capsys.readouterr().out
    assert [e["action"] for e in n.ledger.entries()].count("denial.repaired") == 1
    assert main([*argv, "denial", "verify"]) == 0
    assert capsys.readouterr().out.startswith("denial store ok: 1 denial(s)")


def test_denial_repair_refuses_when_an_earlier_line_does_not_parse(tmp_path):
    kp = keys.KeyPair.generate()
    store = denialmod.DenialStore(tmp_path / "denials.jsonl")
    d1 = _denial(kp)
    store.path.write_bytes(_line(d1).encode() + b"\n{not json}\n" + _line(d1)[:10].encode())
    before = store.path.read_bytes()
    with pytest.raises(IntegrityError) as e:
        store.repair()
    assert e.value.reason == "denial.corrupt" and "line 2" in str(e.value)
    assert store.path.read_bytes() == before


def test_duplicate_denial_retry_syncs_before_reporting_false(tmp_path, monkeypatch):
    kp = keys.KeyPair.generate()
    store = denialmod.DenialStore(tmp_path / "d" / "denials.jsonl")
    d = _denial(kp)
    events: list[tuple[str, tuple[int, int]]] = []
    state = {"failed": False}
    real = os.fsync

    def fsync(fd):
        st = os.fstat(fd)
        kind = "dir" if stat.S_ISDIR(st.st_mode) else "file"
        key = (st.st_dev, st.st_ino)
        if (
            kind == "file"
            and store.path.exists()
            and key == _ino(store.path)
            and not state["failed"]
        ):
            state["failed"] = True  # the line is written; its barrier fails
            raise OSError(5, "Input/output error")
        events.append((kind, key))
        real(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    with pytest.raises(OSError):
        store.add(d, pinned={kp.public})
    assert store.entries() == [d] and events == []  # visible, nothing synced
    assert store.add(d, pinned={kp.public}) is False
    assert events == [("file", _ino(store.path)), ("dir", _ino(store.path.parent))]
    # identity is the triple: a different body under the same denial_id is recorded
    variant = denialmod.sign({**d, "principal_statement": "changed"}, kp)
    assert store.add(variant, pinned={kp.public}) is True
    assert [e["principal_statement"] for e in store.entries()] == ["never", "changed"]
    assert store.identity(d)[:2] == store.identity(variant)[:2]


def test_receive_on_a_corrupt_denial_store_leaves_the_mail_unseen(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    b.config["extensions"]["standing_denial"] = True
    b.save_config()
    wa.send(a.compose_card())
    wb.send(b.compose_card())
    wb.poll_once()
    wa.poll_once()
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "dn.txt"), principal_statement=STATEMENT
    )
    wa.send(write_bundle(a, b, g, "dn.txt"))
    b.denials.path.write_bytes(b'{"denial_id": "dny_')  # a torn store
    s = wb.poll_once()
    assert s["applied"] == 0 and s["storage_failures"] == 1 and s["complete"] is False
    assert any("denial.torn" in e for e in s["errors"])
    assert not any(e["outcome"] == "verify_failed:malformed" for e in b.ledger.entries())
    assert len(_seen_mail(b)) == 1 and seen_of(b) == {}  # unseen, nothing reserved
    assert not (b.scratch_dir / "dn.txt").exists()
    assert b.repair_denials() > 0
    s = wb.poll_once()
    assert s["applied"] == 1 and s["complete"] is True
    assert (b.scratch_dir / "dn.txt").exists()


# ---- F8. repair retries re-establish the barrier and finish the audit (FAILURE AFTER) --------


def _torn_feed_node(tmp_path):
    clock = Clock()
    n = make_node(tmp_path, "n", clock)
    rev = n.revoke(grants=[uid("grt")], principal_statement="ok")
    torn = _line(rev)[:40].encode()
    with open(n.revocations.path, "ab") as f:
        f.write(torn)
    return n, rev, torn


def test_feed_truncation_visible_but_unsynced_is_synced_and_audited_on_retry(tmp_path, monkeypatch):
    n, rev, torn = _torn_feed_node(tmp_path)
    marker = n.state / "feed-repair-pending.json"
    monkeypatch.setattr(os, "fsync", _file_fsync_failing_for(n.revocations.path))
    with pytest.raises(OSError):  # the truncation is visible; its fsync failed
        n.repair_feed()
    assert revmod.RevocationFeed(n.revocations.path).load() == ([rev], False)
    assert json.loads(marker.read_text())["bytes"] == len(torn)  # the intent, before
    assert not any(e["action"] == "feed.repaired" for e in n.ledger.entries())
    monkeypatch.undo()
    events = _record_syncs(monkeypatch)
    # the retry resumes the intent: the feed is already at the cut point, so the
    # barrier is re-established and the audit written; the return value counts only
    # the bytes THIS run truncated (round 7, C: 0 on a pure resume)
    marker_ino = _ino(marker)
    assert n.repair_feed() == 0
    feed = _ino(n.revocations.path)
    # the marker found is fsynced first (it may be visible and unsynced), then the
    # feed's barrier again
    assert events[0] == ("file", marker_ino) and events[1] == ("dir", _ino(n.state))
    assert events[2] == ("file", feed) and events[3] == ("dir", _ino(n.state))
    (audit,) = [e for e in n.ledger.entries() if e["action"] == "feed.repaired"]
    assert f"{len(torn)} bytes" in audit["detail"] and not marker.exists()
    assert n.repair_feed() == 0  # and nothing more to audit
    assert [e["action"] for e in n.ledger.entries()].count("feed.repaired") == 1


def test_feed_truncation_whose_ledger_append_failed_keeps_the_audit_intent(tmp_path, monkeypatch):
    n, rev, torn = _torn_feed_node(tmp_path)
    marker = n.state / "feed-repair-pending.json"
    monkeypatch.setattr(n.ledger, "append", _raise(OSError(28, "disk full")))
    with pytest.raises(OSError):
        n.repair_feed()
    assert revmod.RevocationFeed(n.revocations.path).load() == ([rev], False)  # truncated
    assert marker.exists()  # the intent survives
    monkeypatch.undo()
    assert n.repair_feed() == 0  # the audit from the marker; nothing truncated by THIS run
    (audit,) = [e for e in n.ledger.entries() if e["action"] == "feed.repaired"]
    assert f"{len(torn)} bytes" in audit["detail"] and not marker.exists()


def test_mirror_repair_visible_but_unsynced_is_synced_on_retry(tmp_path, monkeypatch):
    led = Ledger(tmp_path / "l.jsonl")
    for i in range(2):
        led.append(
            ts=TS, actor="a", grant_id=None, action=f"x{i}", params_hash=None, outcome="information"
        )
    lines = led.prose_path.read_text().splitlines()
    led.prose_path.write_text(lines[0] + "\n")
    monkeypatch.setattr(os, "fsync", _file_fsync_failing_for(led.prose_path))
    with pytest.raises(OSError):  # the line is visible; its fsync failed
        led.repair()
    assert led.prose_path.read_text().splitlines() == lines
    monkeypatch.undo()
    events = _record_syncs(monkeypatch)
    assert led.repair() == 0  # nothing to write: the barrier is re-established instead
    assert events == [
        ("file", _ino(led.path)),
        ("dir", _ino(tmp_path)),
        ("file", _ino(led.prose_path)),
        ("dir", _ino(tmp_path)),
    ]
    assert led.verify() == led.head()


def test_feed_repair_on_a_clean_feed_syncs_it(tmp_path, monkeypatch):
    kp = keys.KeyPair.generate()
    feed = revmod.RevocationFeed(tmp_path / "rev.jsonl")
    feed.add(_rev(kp, [uid("grt")]), pinned={kp.public})
    events = _record_syncs(monkeypatch)
    assert feed.repair() == 0
    assert events == [("file", _ino(feed.path)), ("dir", _ino(tmp_path))]


# ---- F9. every local parser failure is IntegrityError -----------------------------------------

BIG_INT = b"1" * 5000  # past the interpreter's int-string conversion limit: ValueError
DEEP = b"[" * 100000 + b"]" * 100000  # nesting past the recursion limit: RecursionError


@pytest.mark.parametrize("payload", [BIG_INT, DEEP], ids=["oversized-int", "deep-nesting"])
def test_local_parser_failures_are_integrity_errors(tmp_path, payload):
    feed = revmod.RevocationFeed(tmp_path / "rev.jsonl")
    feed.path.write_bytes(payload + b"\n")
    with pytest.raises(IntegrityError) as e:
        feed.load()
    assert e.value.reason == "feed.corrupt"
    store = denialmod.DenialStore(tmp_path / "denials.jsonl")
    store.path.write_bytes(payload + b"\n")
    with pytest.raises(IntegrityError) as e:
        store.entries()
    assert e.value.reason == "denial.corrupt"
    led = Ledger(tmp_path / "l.jsonl")
    led.path.write_bytes(payload + b"\n")
    with pytest.raises(IntegrityError) as e:
        led.entries()
    assert e.value.reason == "ledger.corrupt" and not isinstance(e.value, VerifyError)
    clock = Clock()
    n = make_node(tmp_path, "n", clock)
    (n.state / "seen.json").write_bytes(payload)
    with pytest.raises(IntegrityError) as e:
        n._seen()
    assert e.value.reason == "state.corrupt" and "seen.json" in str(e.value)
    w = MailWire(n, runner=lambda argv: None)
    w.seen_path.write_bytes(payload)
    with pytest.raises(IntegrityError):
        w._seen()
    w.cursor_path.write_bytes(payload)
    with pytest.raises(IntegrityError):
        w.cursor()
    (n.state / "revocations.check.json").write_bytes(payload)
    with pytest.raises(IntegrityError):
        n.revocations.last_checked()


def test_a_torn_feed_from_a_deep_value_is_still_torn(tmp_path):
    kp = keys.KeyPair.generate()
    feed = revmod.RevocationFeed(tmp_path / "rev.jsonl")
    feed.add(_rev(kp, [uid("grt")]), pinned={kp.public})
    # round 20 (the prefix rule): a torn tail is a strict prefix of one RECORD — an
    # object that opens and never closes — so the deep value sits inside one
    # (`[[[[` alone is bytes this node never wrote: feed.corrupt)
    feed.path.write_bytes(feed.path.read_bytes() + b'{"revokes":' + DEEP[:1000])
    with pytest.raises(IntegrityError) as e:
        feed.load()
    assert e.value.reason == "feed.torn"
    feed.path.write_bytes(feed.path.read_bytes()[: -len(DEEP[:1000]) - 11] + DEEP[:1000])
    with pytest.raises(IntegrityError) as e:
        feed.load()
    assert e.value.reason == "feed.corrupt" and "does not begin with an object" in str(e.value)


def test_corrupt_local_state_through_receive_is_a_storage_failure(pair):
    a, b, clock, reports = pair
    (b.state / "seen.json").write_bytes(BIG_INT)
    n = len(b.ledger)
    with pytest.raises(StorageError):
        b.receive(a.compose_info(b.card, "hello"))
    assert len(b.ledger) == n  # nothing ledgered as malformed

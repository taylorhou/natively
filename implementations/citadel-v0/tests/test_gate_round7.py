"""Round-7 gate findings (hw-2bb8q): the sixth cross-model gate's report. The class is
unchanged — one syscall fails AFTER its effect became visible (or one enumeration
fails silently), then the process retries or restarts — and every test asserts what a
peer can observe: an authorization, a use count, a held reply, a cursor, an audit
entry.

Test categories (as in the round-5 and round-6 modules):
  ORDERING          — every fsync is recorded and the order of files is asserted;
  FAILURE BEFORE    — a persistence step fails before anything became visible;
  FAILURE AFTER     — the syscall at step N fails AFTER its effect became visible, the
                      process retries or restarts (an unsynced tail may be gone);
  RESTART RECOVERY  — a fresh Node / process starts on what the last one left.

A   no state directory is enumerated with Path.glob: an unreadable revocations-pending/
    is a storage failure, never "nothing held" — the startup sweep writes the marker,
    the repair verb leaves it, the authorization path refuses by name; an unreadable
    pending-replies/ is counted and freezes the cursor (RESTART RECOVERY, FAILURE AFTER);
B   the JSONL barrier precedes every mirror write; a mirror longer than the JSONL is
    refused, and the repair verb truncates it and ledgers ledger.mirror_truncated
    (FAILURE AFTER, RESTART RECOVERY, ORDERING);
C   the repair verb is a resumable state machine driven by the intent marker: a crash
    at every step resumes without a second truncation or a second audit, for the feed,
    the denial store and the ledger mirror alike (FAILURE AFTER, RESTART RECOVERY);
D   a corrupt held reply is never deleted: moved aside, counted, ledgered — and, since
    round 7b, nothing automatic rebuilds or sends from it (FAIL CLOSED: the cursor stays
    frozen until `natively pending` resolves it); those tests live in test_gate_round7b.py;
E   the cursor read is inside the storage boundary: a storage failure there skips the
    fetch half, the outbox still runs, fetch_failures stays 0 (FAILURE BEFORE);
F   the temp descriptor is owned before its identity is read: an identity lookup that
    fails leaves no descriptor open and no temp name (FAILURE BEFORE);
G   every CLI state reader reports a parse fault as IntegrityError with the path, exit 2;
H   the README's recovery claims and the round-5/6 classifications (documentation)."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from natively import node as nodemod
from natively import revocation as revmod
from natively.cli import main
from natively.durable import list_dir
from natively.errors import IntegrityError, PostCommitError, StorageError
from natively.executor import Executor
from natively.ledger import entry_hash, prose_line
from natively.node import REPLAY_MARKER, Node
from natively.objects import is_id

from .conftest import Clock, make_node, uid
from .test_gate_round3 import KEY, held_revocations, pair
from .test_gate_round4 import _unpinned_pair
from .test_gate_round5 import _ino, _line, _mk_ledger, _raise, _record_syncs
from .test_gate_round6 import (
    _connected_over_mail,
    _dir_fsync_failing_after_the_replacement_of,
    _drop_last_line,
    _file_fsync_failing_for,
    _pinned_held_torn,
    _running,
    _torn_feed_node,
    _with_a_due_resend,
)
from .test_hardening import STATEMENT, fs_write_scope, latest, write_bundle
from .test_mail_adapter import pair_over_mail

__all__ = ["pair"]  # the fixture is re-exported for this module's tests

TS = "2026-09-07T07:00:00Z"


def _scandir_failing_for(path: Path, monkeypatch, state: dict | None = None) -> dict:
    """An os.scandir that raises PermissionError for the directory at `path` (every
    other directory enumerates normally); `state["failed"]` counts the refusals.
    Path.glob swallows exactly this error into an empty listing."""
    state = state if state is not None else {}
    state.setdefault("failed", 0)
    real = os.scandir

    def scandir(p=".", *a, **kw):
        if Path(p) == path:
            state["failed"] += 1
            raise PermissionError(13, "Permission denied")
        return real(p, *a, **kw)

    monkeypatch.setattr(os, "scandir", scandir)
    return state


def _argv(n: Node) -> list[str]:
    return ["--state", str(n.state), "--keys", str(n.keys_dir), "--scratch", str(n.scratch_dir)]


# ---- A. an unreadable state directory is a storage failure, never "nothing held" -------------
#      (RESTART RECOVERY: a fresh node over the held state; FAILURE BEFORE: the enumeration
#       itself fails — no persistence syscall took effect and then reported failure)


def _pinned_held_healthy(tmp_path, reports):
    """B trusts A on disk (the crash-after-pin order), A's revocation of g is held under
    B's revocations-pending/, and B's feed is healthy: only the enumeration can fail."""
    a, b, g, rev, clock = _unpinned_pair(tmp_path, reports=reports)
    assert b.receive(a.compose_revocation(rev)) == []
    (held,) = held_revocations(b, rev["rev_id"])
    p = b.state / "pinned.json"
    p.write_text(json.dumps({**json.loads(p.read_text()), a.principal.public: {"name": "a"}}))
    return a, b, g, rev, held, clock


def test_unreadable_held_directory_at_startup_writes_the_marker_and_blocks(tmp_path, monkeypatch):
    reports: list[str] = []
    a, b, g, rev, held, clock = _pinned_held_healthy(tmp_path, reports)
    pending = b.state / "revocations-pending"
    state = _scandir_failing_for(pending, monkeypatch)
    b2 = _running(b, clock, reports)  # the sweep cannot enumerate: the marker is written
    marker = b.state / REPLAY_MARKER
    assert state["failed"] >= 1 and marker.exists() and held.exists()
    m = json.loads(marker.read_text())
    assert a.principal.public in m["principals"] and "PermissionError" in m["why"]
    assert any("nothing is authorized" in r and "PermissionError" in r for r in reports)
    b2.receive(a.compose_card())
    b2.mark_lookup_ok()
    # under the marker the replay is attempted first; its enumeration fails again:
    # a storage failure (round 12: nothing ledgered, nothing acked), the marker stays
    n = len(b2.ledger)
    with pytest.raises(StorageError) as e:
        b2.receive(write_bundle(a, b2, g, "h.txt"))
    assert "PermissionError" in str(e.value) and len(b2.ledger) == n
    assert marker.exists() and held.exists() and not (b2.scratch_dir / "h.txt").exists()
    monkeypatch.undo()
    # readable again: the replay runs, the covered grant is refused as revoked, the
    # marker and the held copy are gone
    (r2,) = b2.receive(write_bundle(a, b2, g, "h.txt"))
    assert r2["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "grant.revoked" in latest(b2)["detail"] and not (b2.scratch_dir / "h.txt").exists()
    assert not marker.exists() and not held.exists()
    assert b2.revocations.grant_revoked_by(g["grant_id"], a.principal.public) is not None


def test_unreadable_held_directory_during_feed_repair_leaves_the_marker(
    tmp_path, monkeypatch, capsys
):
    reports: list[str] = []
    a, b, g, rev, held, clock = _pinned_held_torn(tmp_path, reports)
    b2 = _running(b, clock, reports)  # the sweep is skipped on the torn feed: marker
    marker = b.state / REPLAY_MARKER
    assert marker.exists()
    state = _scandir_failing_for(b.state / "revocations-pending", monkeypatch)
    with pytest.raises(PermissionError):
        b2.repair_feed()  # the truncation and its audit landed; the replay's listing failed
    assert state["failed"] == 1
    assert revmod.RevocationFeed(b.revocations.path).load() == ([], False)  # repaired
    assert [e["action"] for e in b2.ledger.entries()].count("feed.repaired") == 1
    assert marker.exists() and held.exists()  # the marker is NOT cleared on the truncation
    # the CLI verb the same: exit 1, the marker stays
    assert main([*_argv(b), "feed", "repair"]) == 1
    assert "Permission denied" in capsys.readouterr().err
    assert marker.exists() and held.exists()
    b2.receive(a.compose_card())
    b2.mark_lookup_ok()
    with pytest.raises(StorageError) as e:  # round 12: a storage failure, unseen
        b2.receive(write_bundle(a, b2, g, "h.txt"))
    assert "PermissionError" in str(e.value)
    assert marker.exists() and held.exists() and not (b2.scratch_dir / "h.txt").exists()
    monkeypatch.undo()
    assert b2.repair_feed() == 0  # clean feed; now the replay runs and the marker goes
    assert not marker.exists() and not held.exists()
    assert [e["action"] for e in b2.ledger.entries()].count("feed.repaired") == 1
    (r2,) = b2.receive(write_bundle(a, b2, g, "h.txt"))
    assert r2["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "grant.revoked" in latest(b2)["detail"]


def test_unreadable_held_directory_under_the_marker_is_a_storage_failure(tmp_path, monkeypatch):
    reports: list[str] = []
    a, b, g, rev, held, clock = _pinned_held_torn(tmp_path, reports)
    b2 = _running(b, clock, reports)
    marker = b.state / REPLAY_MARKER
    assert revmod.RevocationFeed(b.revocations.path).repair() > 0  # another process
    b2.receive(a.compose_card())
    b2.mark_lookup_ok()
    g2 = a.issue_grant(
        subject_card=b2.card, scope=fs_write_scope(b2, "ok.txt"), principal_statement=STATEMENT
    )
    state = _scandir_failing_for(b.state / "revocations-pending", monkeypatch)
    n = len(b2.ledger)
    with pytest.raises(StorageError) as e:  # round 12: a storage failure, nothing ledgered
        b2.receive(write_bundle(a, b2, g2, "ok.txt", "fine\n"))
    assert state["failed"] == 1
    assert "PermissionError" in str(e.value) and len(b2.ledger) == n
    assert marker.exists() and held.exists() and not (b2.scratch_dir / "ok.txt").exists()
    monkeypatch.undo()
    (r2,) = b2.receive(write_bundle(a, b2, g2, "ok.txt", "fine\n"))
    assert r2["object"]["outcome"] == "applied"
    assert not marker.exists() and not held.exists()
    assert b2.revocations.grant_revoked_by(g["grant_id"], a.principal.public) is not None
    (r3,) = b2.receive(write_bundle(a, b2, g, "h.txt"))
    assert r3["object"]["outcome"] == "refused:no_authorizing_grant"


def test_unreadable_pending_replies_is_counted_and_freezes_the_cursor(tmp_path, monkeypatch):
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "one"))
    fake.fail_sends = True
    wb.poll_once()
    (held,) = wb._pending_replies()
    fake.fail_sends = False
    _with_a_due_resend(wb, b, a.card, clock)
    cursor_before = wb.cursor()
    state = _scandir_failing_for(wb.pending_dir, monkeypatch)
    sends_before = len(fake.sends)
    s = wb.poll_once()
    assert state["failed"] == 1
    assert s["storage_failures"] == 1 and s["replies"] == 0 and s["complete"] is False
    assert any("storage failure reading the aside held replies" in e for e in s["errors"])
    assert wb.cursor() == cursor_before != clock()  # frozen
    assert s["resent"] == 1 and len(fake.sends) == sends_before + 1  # the outbox step only
    assert held.exists()  # nothing sent from that listing, nothing deleted
    monkeypatch.undo()
    s = wb.poll_once()
    assert s["replies"] == 1 and s["complete"] is True and wb.cursor() == clock()
    assert not held.exists()


def test_no_state_directory_is_enumerated_with_glob_or_iterdir():
    src = Path(__file__).resolve().parents[1] / "natively"
    offenders = []
    for f in sorted(src.rglob("*.py")):
        text = f.read_text(encoding="utf-8")
        for needle in (".glob(", ".rglob(", ".iterdir(", "os.listdir("):
            if needle in text:
                offenders.append(f"{f.name}: {needle}")
    assert offenders == []


# ---- B. the JSONL barrier precedes every mirror write; excess prose is truncated ------------
#      (FAILURE AFTER: the JSONL fsync fails after the line is visible; RESTART RECOVERY:
#       a fresh instance on the state the power cut left; ORDERING)


def test_prose_beyond_the_jsonl_is_refused_then_truncated_and_audited_by_the_verb(
    tmp_path, monkeypatch, capsys
):
    clock = Clock()
    n = make_node(tmp_path, "n", clock)
    led = n.ledger
    for i in range(2):  # a ledger with history
        led.append(
            ts=TS, actor="a", grant_id=None, action=f"s{i}", params_hash=None, outcome="information"
        )
    before = len(led)
    # 1. an append whose JSONL fsync fails AFTER the line became visible
    monkeypatch.setattr(os, "fsync", _file_fsync_failing_for(led.path))
    with pytest.raises(OSError):
        led.append(
            ts=TS, actor="a", grant_id=None, action="x", params_hash=None, outcome="information"
        )
    assert len(led.entries()) == before + 1
    mirror = led.prose_path.read_text(encoding="utf-8")
    assert len(mirror.splitlines()) == before  # the mirror is short by the unsynced entry
    # 2. repair (and the pre-append sync) while the JSONL cannot be synced: the storage
    # error stops it and the mirror is untouched
    with pytest.raises(OSError):
        led.repair()
    with pytest.raises(OSError):
        led.sync_prose()
    assert led.prose_path.read_text(encoding="utf-8") == mirror
    monkeypatch.undo()
    # 3. what an older repair (or a hand) did: the prose line for the unsynced entry
    last = led.entries()[-1]
    extra = prose_line(last, entry_hash(last)) + "\n"
    led.prose_path.write_text(mirror + extra, encoding="utf-8")
    # 4. the power loss removes the unsynced JSONL tail
    _drop_last_line(led.path)
    # 5. a fresh instance: verify and repair refuse (the mirror exceeds the ledger), an
    # append refuses too; JSONL entries are never invented from prose
    n2 = Node(state_dir=n.state, keys_dir=n.keys_dir, scratch_dir=n.scratch_dir, clock=clock)
    assert len(n2.ledger.entries()) == before
    with pytest.raises(IntegrityError) as e:
        n2.ledger.verify()
    assert e.value.reason == "ledger.prose.count"
    with pytest.raises(IntegrityError) as e:
        n2.ledger.repair()
    assert e.value.reason == "ledger.repair.refused"
    with pytest.raises(IntegrityError) as e:
        n2.ledger.append(
            ts=TS, actor="a", grant_id=None, action="y", params_hash=None, outcome="information"
        )
    assert e.value.reason == "ledger.prose.mismatch"
    assert main([*_argv(n), "ledger", "verify"]) == 2
    assert "ledger.prose.count" in capsys.readouterr().err
    # 6. the repair verb truncates the mirror to the JSONL's length and audits it
    events = _record_syncs(monkeypatch)
    assert main([*_argv(n), "ledger", "repair"]) == 0
    out = capsys.readouterr().out
    assert f"{len(extra)} byte(s) of prose beyond the JSONL truncated" in out
    n3 = Node(state_dir=n.state, keys_dir=n.keys_dir, scratch_dir=n.scratch_dir, clock=clock)
    assert n3.ledger.verify() == n3.ledger.head()
    audit = n3.ledger.entries()[-1]
    assert audit["action"] == "ledger.mirror_truncated" and audit["outcome"] == "recorded"
    assert f"{len(extra)} bytes" in audit["detail"] and "intent rpr_" in audit["detail"]
    assert len(n3.ledger.entries()) == before + 1  # the audit is the only new entry
    assert not (n.state / "ledger-repair-pending.json").exists()
    prose_lines = n3.ledger.prose_path.read_text(encoding="utf-8").splitlines()
    assert prose_lines[:before] == mirror.splitlines() and len(prose_lines) == before + 1
    # ORDERING: the JSONL barrier first (the source of truth), then the mirror
    # truncation (file, then directory), then the audit's JSONL write
    i_cut = events.index(("file", _ino(led.prose_path)))
    assert events[i_cut + 1] == ("dir", _ino(n.state))
    assert events.index(("file", _ino(led.path))) < i_cut
    assert ("file", _ino(led.path)) in events[i_cut + 2 :]
    assert main([*_argv(n), "ledger", "repair"]) == 0  # nothing more: no second audit
    assert "beyond the JSONL" not in capsys.readouterr().out
    assert [e["action"] for e in n3.ledger.entries()].count("ledger.mirror_truncated") == 1


def test_every_mirror_repair_branch_syncs_the_jsonl_before_the_mirror(tmp_path, monkeypatch):
    led = _mk_ledger(tmp_path / "l.jsonl", 2)
    lines = led.prose_path.read_text(encoding="utf-8").splitlines()
    whole = led.prose_path.read_bytes()
    jsonl, prose, d = _ino(led.path), _ino(led.prose_path), _ino(tmp_path)
    barrier_then_mirror = [("file", jsonl), ("dir", d), ("file", prose), ("dir", d)]
    for call, expect in ((led.repair, 1), (led.sync_prose, 1)):
        # a missing trailing line
        led.prose_path.write_text(lines[0] + "\n", encoding="utf-8")
        events = _record_syncs(monkeypatch)
        assert call() == expect and events == barrier_then_mirror
        assert led.prose_path.read_bytes() == whole
        # a missing newline
        led.prose_path.write_bytes(whole[:-1])
        events.clear()
        assert call() == 0 and events == barrier_then_mirror
        assert led.prose_path.read_bytes() == whole
        monkeypatch.undo()
    # a whitespace tail: refused, nothing synced, nothing written
    led.prose_path.write_bytes(whole + b"   ")
    events = _record_syncs(monkeypatch)
    with pytest.raises(IntegrityError) as e:
        led.repair()
    assert e.value.reason == "ledger.repair.refused" and events == []
    assert led.prose_path.read_bytes() == whole + b"   "
    monkeypatch.undo()
    # the JSONL barrier failing: nothing is written to the mirror, in either branch
    for staged in (whole[: whole.index(b"\n") + 1], whole[:-1]):
        for call in (led.repair, led.sync_prose):
            led.prose_path.write_bytes(staged)
            monkeypatch.setattr(os, "fsync", _file_fsync_failing_for(led.path))
            with pytest.raises(OSError):
                call()
            assert led.prose_path.read_bytes() == staged
            monkeypatch.undo()
    led.prose_path.write_bytes(whole)
    assert led.verify() == led.head()


def test_ledger_repair_verb_on_a_whole_mirror_writes_nothing(tmp_path, monkeypatch):
    clock = Clock()
    n = make_node(tmp_path, "n", clock)
    n.ledger.append(
        ts=TS, actor="a", grant_id=None, action="s", params_hash=None, outcome="information"
    )
    before = (n.ledger.path.read_bytes(), n.ledger.prose_path.read_bytes(), len(n.ledger))
    events = _record_syncs(monkeypatch)
    assert n.repair_ledger() == (0, 0, 0)
    assert ("file", _ino(n.ledger.prose_path)) in events and ("file", _ino(n.ledger.path)) in events
    assert (n.ledger.path.read_bytes(), n.ledger.prose_path.read_bytes(), len(n.ledger)) == before
    assert not (n.state / "ledger-repair-pending.json").exists()


# ---- C. the repair verb is a resumable state machine (FAILURE AFTER, RESTART RECOVERY) -------


def _torn_denial_node(tmp_path):
    clock = Clock()
    n = make_node(tmp_path, "n", clock, extensions={"standing_denial": True})
    d = n.deny(deny=[{"action": "fs.write", "resource": "*"}], principal_statement="no")
    torn = _line(d)[:40].encode()
    with open(n.denials.path, "ab") as f:
        f.write(torn)
    return n, d, torn


def _excess_mirror_node(tmp_path):
    """A node whose mirror has one prose line beyond the JSONL (the B sequence)."""
    clock = Clock()
    n = make_node(tmp_path, "n", clock)
    for i in range(2):
        n.ledger.append(
            ts=TS, actor="a", grant_id=None, action=f"s{i}", params_hash=None, outcome="information"
        )
    e = n.ledger.append(
        ts=TS, actor="a", grant_id=None, action="x", params_hash=None, outcome="information"
    )
    _drop_last_line(n.ledger.path)  # the unsynced JSONL tail is gone; its prose line stays
    n.ledger._entries = None
    torn = (prose_line(e, entry_hash(e)) + "\n").encode()
    return n, e, torn


class _Store:
    """One store under repair: how to make it torn, how to run the verb, what the
    audit is called, and how to tell it is clean."""

    def __init__(self, what, make, repair, audit, path, clean):
        self.what, self.make, self.repair, self.audit, self.path, self.clean = (
            what,
            make,
            repair,
            audit,
            path,
            clean,
        )


STORES = [
    _Store(
        "feed",
        lambda t: _torn_feed_node(t)[::2],
        lambda n: n.repair_feed(),
        "feed.repaired",
        lambda n: n.revocations.path,
        lambda n: revmod.RevocationFeed(n.revocations.path).load()[1] is False,
    ),
    _Store(
        "denial",
        lambda t: _torn_denial_node(t)[::2],
        lambda n: n.repair_denials(),
        "denial.repaired",
        lambda n: n.denials.path,
        lambda n: n.denials.load()[1] is False,
    ),
    _Store(
        "ledger",
        lambda t: _excess_mirror_node(t)[::2],
        lambda n: n.repair_ledger()[0],
        "ledger.mirror_truncated",
        lambda n: n.ledger.prose_path,
        lambda n: n.ledger.verify() == n.ledger.head(),
    ),
]


def _audits(n, action):
    return [e for e in n.ledger.entries() if e["action"] == action]


@pytest.mark.parametrize("st", STORES, ids=[s.what for s in STORES])
def test_crash_after_the_intent_with_the_tail_still_torn_truncates_once(tmp_path, monkeypatch, st):
    n, torn = st.make(tmp_path)
    marker = n.state / f"{st.what}-repair-pending.json"
    path = st.path(n)
    raw_before = path.read_bytes()
    monkeypatch.setattr(Node, "_drive_repair", _raise(OSError(5, "power cut after the intent")))
    with pytest.raises(OSError):
        st.repair(n)
    intent = json.loads(marker.read_text())
    assert intent["step"] == "intent" and intent["bytes"] == len(torn)
    assert intent["truncate_to"] == len(raw_before) - len(torn)
    assert is_id(intent["intent_id"], "rpr_")
    assert path.read_bytes() == raw_before and _audits(n, st.audit) == []  # nothing touched
    monkeypatch.undo()
    reports: list[str] = []
    n.report = reports.append
    assert st.repair(n) == len(torn)  # the resume truncates: THIS run cut the bytes
    assert any("resuming" in r and "step 'intent'" in r for r in reports)
    got = path.read_bytes()
    cut = raw_before[: -len(torn)]
    # the file is the clean prefix; the ledger mirror then gains the audit's own prose line
    assert st.clean(n) and got.startswith(cut)
    assert got == cut or (st.what == "ledger" and got.count(b"\n") == cut.count(b"\n") + 1)
    (audit,) = _audits(n, st.audit)
    assert (
        f"intent {intent['intent_id']}" in audit["detail"]
        and f"{len(torn)} bytes" in audit["detail"]
    )
    assert audit["params_hash"] == intent["tail_sha256"]
    assert not marker.exists()
    assert st.repair(n) == 0 and len(_audits(n, st.audit)) == 1  # nothing more


@pytest.mark.parametrize("st", STORES, ids=[s.what for s in STORES])
def test_crash_after_the_truncation_before_the_audit_audits_once(tmp_path, monkeypatch, st):
    n, torn = st.make(tmp_path)
    marker = n.state / f"{st.what}-repair-pending.json"
    monkeypatch.setattr(n.ledger, "append", _raise(OSError(28, "disk full")))
    with pytest.raises(OSError):
        st.repair(n)
    assert st.clean(n) and json.loads(marker.read_text())["step"] == "truncated"
    assert _audits(n, st.audit) == []
    monkeypatch.undo()
    n2 = Node(state_dir=n.state, keys_dir=n.keys_dir, scratch_dir=n.scratch_dir, clock=n.clock)
    st_repair = {"feed": Node.repair_feed, "denial": Node.repair_denials}.get(st.what)
    got = st_repair(n2) if st_repair else n2.repair_ledger()[0]
    assert got == 0  # a pure resume: nothing truncated by this run
    (audit,) = _audits(n2, st.audit)
    assert f"{len(torn)} bytes" in audit["detail"] and not marker.exists()
    assert st.clean(n2)


@pytest.mark.parametrize("st", STORES, ids=[s.what for s in STORES])
def test_crash_after_the_audit_before_the_marker_deletion_never_audits_twice(
    tmp_path, monkeypatch, st
):
    n, torn = st.make(tmp_path)
    marker = n.state / f"{st.what}-repair-pending.json"
    real_unlink = Path.unlink

    def unlink(self, missing_ok=False):
        if self == marker:
            raise OSError(5, "Input/output error")
        return real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", unlink)
    with pytest.raises(OSError):
        st.repair(n)
    intent = json.loads(marker.read_text())
    (audit,) = _audits(n, st.audit)
    assert intent["step"] == "audited" and intent["audit_hash"] == entry_hash(audit)
    assert st.clean(n)
    monkeypatch.undo()
    assert st.repair(n) == 0  # only the marker is deleted
    assert len(_audits(n, st.audit)) == 1 and not marker.exists()
    assert st.repair(n) == 0 and len(_audits(n, st.audit)) == 1


@pytest.mark.parametrize("st", STORES, ids=[s.what for s in STORES])
def test_repair_with_no_marker_and_a_clean_file_returns_zero_and_writes_nothing(
    tmp_path, monkeypatch, st
):
    n, torn = st.make(tmp_path)
    assert st.repair(n) == len(torn)
    path = st.path(n)
    before = (path.read_bytes(), n.ledger.path.read_bytes(), n.ledger.prose_path.read_bytes())
    events = _record_syncs(monkeypatch)
    assert st.repair(n) == 0
    barrier = [("file", _ino(path)), ("dir", _ino(n.state))]  # the barrier, never a bare 0
    if st.what == "ledger":  # the JSONL first, then the mirror
        barrier = [("file", _ino(n.ledger.path)), ("dir", _ino(n.state)), *barrier]
    assert events[: len(barrier)] == barrier
    assert (
        path.read_bytes(),
        n.ledger.path.read_bytes(),
        n.ledger.prose_path.read_bytes(),
    ) == before
    assert not (n.state / f"{st.what}-repair-pending.json").exists()


def test_an_intent_whose_tail_no_longer_matches_is_refused_and_kept(tmp_path):
    n, rev, torn = _torn_feed_node(tmp_path)
    marker = n.state / "feed-repair-pending.json"
    raw = n.revocations.path.read_bytes()
    marker.write_text(
        json.dumps(
            {
                "step": "intent",
                "file": "revocations.jsonl",
                "truncate_to": len(raw) - len(torn),
                "bytes": len(torn),
                "tail_sha256": "sha256:" + "0" * 64,  # not these bytes
                "intent_id": uid("rpr"),
                "ts": TS,
            }
        )
    )
    with pytest.raises(IntegrityError) as e:
        n.repair_feed()
    assert e.value.reason == "feed.repair.intent_mismatch"
    assert n.revocations.path.read_bytes() == raw and marker.exists()
    assert _audits(n, "feed.repaired") == []
    marker.write_text("{not an intent")
    with pytest.raises(IntegrityError) as e:
        n.repair_feed()
    assert e.value.reason == "state.corrupt"
    marker.write_text('{"file": "revocations.jsonl", "bytes": 40}')  # an older tool's marker
    with pytest.raises(IntegrityError) as e:
        n.repair_feed()
    assert e.value.reason == "feed.repair.intent_corrupt" and marker.exists()


# ---- D. a corrupt held reply is never deleted: the fail-closed contract's tests (quarantine,
#      re-delivery, the pending verbs) live in test_gate_round7b.py ------------------------------


# ---- E. the cursor read is inside the storage boundary (FAILURE BEFORE) --------------------


@pytest.mark.parametrize("how", ["unreadable", "corrupt"])
def test_cursor_read_failure_is_a_storage_failure_that_skips_the_fetch(tmp_path, monkeypatch, how):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    wb._advance_cursor()
    _with_a_due_resend(wb, b, a.card, clock)
    wa.send(a.compose_card())
    if how == "unreadable":
        real = Path.read_bytes

        def read_bytes(self):
            if self == wb.cursor_path:
                raise OSError(5, "Input/output error")
            return real(self)

        monkeypatch.setattr(Path, "read_bytes", read_bytes)
    else:
        wb.cursor_path.write_text("{not json")
    searches_before = len(fake.searches)
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["fetch_failures"] == 0
    assert s["fetched"] == 0 and s["applied"] == 0 and s["complete"] is False
    assert len(fake.searches) == searches_before  # nothing fetched
    assert s["resent"] == 1  # the outbox step ran
    assert any("storage failure reading the cursor" in e for e in s["errors"])
    if how == "corrupt":
        assert any("IntegrityError" in e and "state.corrupt" in e for e in s["errors"])
        assert any(str(wb.cursor_path) in e for e in s["errors"])
    assert b.card_for_key(a.agent.public) is None
    monkeypatch.undo()
    if how == "corrupt":
        wb.cursor_path.unlink()
    s = wb.poll_once()
    assert s["applied"] == 1 and s["complete"] is True and s["storage_failures"] == 0


def test_a_wire_failure_is_a_fetch_failure_not_a_storage_failure(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    _with_a_due_resend(wb, b, a.card, clock)
    real = wb.run

    def broken(argv):
        if Path(argv[1]).name == "gmail-api.py":
            return subprocess.CompletedProcess(argv, 1, "", "quota")
        return real(argv)

    wb.run = broken
    s = wb.poll_once()
    assert s["fetch_failures"] == 1 and s["storage_failures"] == 0 and s["complete"] is False
    assert s["resent"] == 1


# ---- F. the temp descriptor is owned before its identity is read (FAILURE BEFORE) ----------


def _open_fds() -> set[int]:
    d = "/dev/fd" if os.path.isdir("/dev/fd") else "/proc/self/fd"
    return {int(x) for x in os.listdir(d)}


@pytest.mark.parametrize("step", ["fstat", "fdopen"])
def test_identity_lookup_failure_leaves_no_descriptor_and_no_temp_name(tmp_path, monkeypatch, step):
    ex = Executor(KEY, tmp_path / "scratch")
    closed: list[int] = []
    real_close = os.close

    def close(fd):
        closed.append(fd)
        real_close(fd)

    monkeypatch.setattr(os, "close", close)
    if step == "fstat":
        real_fstat = os.fstat

        def fstat(fd):
            st = real_fstat(fd)
            if not stat.S_ISDIR(st.st_mode):
                raise OSError(5, "Input/output error")  # the temp file's identity
            return st

        monkeypatch.setattr(os, "fstat", fstat)
    else:
        monkeypatch.setattr(os, "fdopen", _raise(OSError(24, "Too many open files")))
    before = _open_fds()
    with pytest.raises(OSError) as e:
        ex.apply("fs.write", ex.resource_for("f.txt"), {"content": "x"})
    assert not isinstance(e.value, PostCommitError)  # nothing was committed
    assert _open_fds() <= before  # no descriptor left open: not the temp's, not the root's
    assert list((tmp_path / "scratch").iterdir()) == []  # the temp name is gone
    assert closed  # the root descriptor was closed through os.close
    monkeypatch.undo()
    assert ex.apply("fs.write", ex.resource_for("f.txt"), {"content": "x"})["outcome"] == "applied"


# ---- G. every CLI state reader normalizes parser faults ---------------------------------------


@pytest.mark.parametrize(
    "payload", ["1" * 5000, "[" * 100000], ids=["oversized-int", "deep-nesting"]
)
@pytest.mark.parametrize("site", ["cards", "ack"])
def test_cli_state_readers_report_corruption_as_integrity_errors(tmp_path, capsys, payload, site):
    n = make_node(tmp_path, "n", Clock())
    if site == "cards":
        p = n.state / "cards-pending" / ("a" * 64 + ".json")
        cmd = ["cards"]
    else:
        p = n.state / "seen.json"
        cmd = ["ack", uid("msg")]
    p.write_text(payload)
    assert main([*_argv(n), *cmd]) == 2
    err = capsys.readouterr().err
    assert "natively: state.corrupt" in err and str(p) in err
    assert "Traceback" not in err


def test_cli_reads_no_state_file_with_json_loads():
    src = (Path(__file__).resolve().parents[1] / "natively" / "cli.py").read_text(encoding="utf-8")
    assert "json.loads(" not in src and "json.load(" not in src


# ---- H. documentation: the README's recovery claims (no automated test) ----------------------


def test_readme_states_the_corrected_recovery_claims():
    raw = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
    readme = " ".join(raw.split())  # the prose wraps; the claims are checked unwrapped
    assert "failed:interrupted` applies only when no completion entry exists" in readme
    assert "no mail replay" in readme
    assert "ledger.mirror_truncated" in readme and "natively pending" in readme
    assert "revocation.held_corrupt" in readme and "feed.repair_pending" in readme


def test_readme_test_count_matches_a_real_collection():
    """The README's count line is the number a real collection gives, not a typed one."""
    pkg = Path(__file__).resolve().parents[1]
    raw = (pkg / "README.md").read_text(encoding="utf-8")
    m = re.search(r'pytest \| tail -1[^"]*"(\d+) passed', raw)
    assert m, "the README count line is missing"
    out = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-o",
            "addopts=",
            "-p",
            "no:cacheprovider",
        ],
        cwd=pkg,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    collected = re.search(r"(\d+) tests? collected", out)
    assert collected, out[-300:]
    assert int(m.group(1)) == int(collected.group(1))


# ---- self-gate round 7 findings 1–9: within-stage failures of the new machinery ---------------
#      (FAILURE AFTER: a step's bytes are visible and its barrier failed; RESTART RECOVERY:
#       a fresh Node on the state left)


def _ledger_fsync_failing_after(ledger_path: Path, n_ok: int, monkeypatch) -> dict:
    """The FILE fsync of the ledger JSONL fails from the (n_ok + 1)th call on (every
    other fsync works): the bytes of that append are visible and unsynced."""
    state = {"ok": 0, "failed": 0}
    real = os.fsync

    def fsync(fd):
        st = os.fstat(fd)
        if (
            not stat.S_ISDIR(st.st_mode)
            and ledger_path.exists()
            and (st.st_dev, st.st_ino) == _ino(ledger_path)
        ):
            if state["ok"] >= n_ok:
                state["failed"] += 1
                raise OSError(5, "Input/output error")
            state["ok"] += 1
        real(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    return state


@pytest.mark.parametrize("recovered", ["kept", "dropped"])
@pytest.mark.parametrize("st", STORES, ids=[s.what for s in STORES])
def test_a_found_audit_is_promoted_only_after_the_ledger_barrier(
    tmp_path, monkeypatch, st, recovered
):
    n, torn = st.make(tmp_path)
    marker = n.state / f"{st.what}-repair-pending.json"
    # the ledger store fsyncs the JSONL once before the cut (B); the audit's append
    # is the next JSONL fsync — THAT one fails, after the bytes became visible
    state = _ledger_fsync_failing_after(n.ledger.path, 1 if st.what == "ledger" else 0, monkeypatch)
    with pytest.raises(OSError):  # the audit is visible, its barrier failed
        st.repair(n)
    assert state["failed"] == 1
    assert json.loads(marker.read_text())["step"] == "truncated"
    assert st.what == "ledger" or st.clean(n)  # (the ledger's own mirror is short: below)
    assert len(_audits(n, st.audit)) == 1
    assert len(n.ledger.prose_path.read_text().splitlines()) == len(n.ledger.entries()) - 1
    # the retry finds the audit; the ledger barrier (the same fsync) fails again:
    # nothing is promoted, the marker stays at "truncated"
    with pytest.raises(OSError):
        st.repair(n)
    assert state["failed"] >= 2
    assert json.loads(marker.read_text())["step"] == "truncated" and marker.exists()
    monkeypatch.undo()
    if recovered == "dropped":
        # the power loss removes the unsynced audit (its prose line was never written,
        # the JSONL barrier precedes it); the resume writes it again, once
        _drop_last_line(n.ledger.path)
        n.ledger._entries = None
        assert _audits(n, st.audit) == []
    events = _record_syncs(monkeypatch)
    assert st.repair(n) == 0
    assert ("file", _ino(n.ledger.path)) in events  # the barrier (or the append) synced it
    (audit,) = _audits(n, st.audit)
    assert f"{len(torn)} bytes" in audit["detail"] and not marker.exists()
    assert n.ledger.verify() == n.ledger.head()


@pytest.mark.parametrize("st", STORES, ids=[s.what for s in STORES])
def test_a_visible_unsynced_intent_is_synced_before_anything_is_cut(tmp_path, monkeypatch, st):
    n, torn = st.make(tmp_path)
    marker = n.state / f"{st.what}-repair-pending.json"
    path = st.path(n)
    raw = path.read_bytes()
    _dir_fsync_failing_after_the_replacement_of(marker, monkeypatch)
    with pytest.raises(OSError):  # the intent is visible; its directory fsync failed
        st.repair(n)
    assert json.loads(marker.read_text())["step"] == "intent" and path.read_bytes() == raw
    monkeypatch.undo()
    marker_ino = _ino(marker)
    events = _record_syncs(monkeypatch)
    assert st.repair(n) == len(torn)  # the resume cuts (this run), after the marker's barrier
    i_marker = events.index(("file", marker_ino))
    assert events[i_marker + 1] == ("dir", _ino(n.state))
    assert i_marker < events.index(("file", _ino(path)))  # before the cut's barrier
    assert st.clean(n) and len(_audits(n, st.audit)) == 1 and not marker.exists()


def test_writers_refuse_while_a_feed_repair_intent_is_open_and_the_resume_finishes(
    tmp_path, monkeypatch
):
    reports: list[str] = []
    a, b, g, rev, held, clock = _pinned_held_torn(tmp_path, reports)
    b2 = _running(b, clock, reports)  # the sweep is skipped (torn): replay marker
    marker = b.state / "feed-repair-pending.json"
    real = nodemod._write_json

    def write_json(p, v):  # the truncation landed; the step write did not
        if p == marker and isinstance(v, dict) and v.get("step") == "truncated":
            raise OSError(5, "Input/output error")
        real(p, v)

    monkeypatch.setattr(nodemod, "_write_json", write_json)
    with pytest.raises(OSError):
        b2.repair_feed()
    monkeypatch.undo()
    intent = json.loads(marker.read_text())
    assert intent["step"] == "intent" and held.exists()
    feed_raw = b.revocations.path.read_bytes()
    assert revmod.RevocationFeed(b.revocations.path).load() == ([], False)  # clean
    # a fresh node: the startup replay must NOT append past the cut point
    b3 = _running(b, clock, reports)
    replay = b.state / REPLAY_MARKER
    assert replay.exists() and "feed.repair_pending" in json.loads(replay.read_text())["why"]
    assert b.revocations.path.read_bytes() == feed_raw and held.exists()
    # a peer revocation, natively revoke and the authorization path all refuse
    with pytest.raises(IntegrityError) as e:
        b3.receive(a.compose_revocation(rev))
    assert e.value.reason == "feed.repair_pending"
    with pytest.raises(IntegrityError):
        b3.revoke(grants=[uid("grt")], principal_statement="x")
    b3.receive(a.compose_card())
    b3.mark_lookup_ok()
    with pytest.raises(IntegrityError) as e:  # round 12: a storage failure, unseen
        b3.receive(write_bundle(a, b3, g, "h.txt"))
    assert e.value.reason == "feed.repair_pending"
    assert b.revocations.path.read_bytes() == feed_raw
    # the verb resumes: at the cut point already, audits once, replays, clears
    assert b3.repair_feed() == 0
    assert not marker.exists() and not replay.exists() and not held.exists()
    assert len(_audits(b3, "feed.repaired")) == 1
    assert b3.revocations.grant_revoked_by(g["grant_id"], a.principal.public) is not None
    (r2,) = b3.receive(write_bundle(a, b3, g, "h.txt"))
    assert r2["object"]["outcome"] == "refused:no_authorizing_grant"
    rev2 = b3.revoke(grants=[uid("grt")], principal_statement="after")  # writers work again
    assert b3.revocations.grant_revoked_by(rev2["revokes"]["grants"][0], b3.principal.public)


def test_deny_refuses_while_a_denial_repair_intent_is_open(tmp_path, monkeypatch):
    n, d, torn = _torn_denial_node(tmp_path)
    monkeypatch.setattr(Node, "_drive_repair", _raise(OSError(5, "power cut after the intent")))
    with pytest.raises(OSError):
        n.repair_denials()
    monkeypatch.undo()
    before = len(n.ledger)
    with pytest.raises(IntegrityError) as e:
        n.deny(deny=[{"action": "info", "resource": "*"}], principal_statement="no")
    assert e.value.reason == "denial.repair_pending" and len(n.ledger) == before
    assert n.repair_denials() == len(torn)
    n.deny(deny=[{"action": "info", "resource": "*"}], principal_statement="later")
    assert [x["principal_statement"] for x in n.denials.entries()] == ["no", "later"]


def test_ledger_repair_is_reachable_when_the_startup_replay_cannot_ledger(tmp_path, capsys):
    reports: list[str] = []
    a, b, g, rev, held, clock = _pinned_held_healthy(tmp_path, reports)
    for i in range(2):
        b.ledger.append(
            ts=TS, actor="a", grant_id=None, action=f"s{i}", params_hash=None, outcome="information"
        )
    with open(b.ledger.prose_path, "a", encoding="utf-8") as f:
        f.write("a prose line whose entry never became durable [000000000000]\n")
    feed = b.revocations.path
    feed_before = feed.read_bytes() if feed.exists() else None
    b2 = _running(b, clock, reports)  # the ledger's check refuses the replay: the node constructs
    replay = b.state / REPLAY_MARKER
    assert replay.exists() and "ledger.prose.mismatch" in json.loads(replay.read_text())["why"]
    assert held.exists()  # deleted only after ITS ledger entry; that never landed
    # round 15 (U5): the check runs BEFORE the feed line, so the feed is untouched too
    assert (feed.read_bytes() if feed.exists() else None) == feed_before
    assert b2.revocations.grant_revoked_by(g["grant_id"], a.principal.public) is None
    assert main([*_argv(b), "ledger", "repair"]) == 0  # the repair verb runs on that node
    assert "beyond the JSONL truncated" in capsys.readouterr().out
    b3 = _running(b, clock, reports)  # the sweep replays now (the first time): the marker goes
    assert not replay.exists() and not held.exists()
    assert b3.ledger.verify() == b3.ledger.head()
    assert b3.revocations.grant_revoked_by(g["grant_id"], a.principal.public) is not None
    replayed = [e["outcome"] for e in b3.ledger.entries() if e["action"] == "revocation.replayed"]
    assert replayed == ["recorded"]


def _held_ack_over_mail(tmp_path, n=1):
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    reports: list[str] = []
    b.report = reports.append
    for i in range(n):
        wa.send(a.compose_info(b.card, f"m{i}"))
    fake.fail_sends = True
    wb.poll_once()
    held = wb._pending_replies()
    fake.fail_sends = False
    return a, b, wa, wb, fake, clock, held, reports


def test_a_cursor_with_a_bad_timestamp_is_a_storage_failure_not_a_crash(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    _with_a_due_resend(wb, b, a.card, clock)
    wa.send(a.compose_card())
    for bad in ('{"last_complete_fetch": "garbageZ"}', "[]", '{"last_complete_fetch": 5}'):
        wb.cursor_path.write_text(bad)
        s = wb.poll_once()
        assert s["storage_failures"] == 1 and s["fetch_failures"] == 0 and s["applied"] == 0
        assert s["complete"] is False
        assert any("state.corrupt" in e and str(wb.cursor_path) in e for e in s["errors"])
        with pytest.raises(IntegrityError):
            wb.cursor()
    wb.cursor_path.unlink()
    assert wb.poll_once()["applied"] == 1


def _one_use_grant_r7(a, b, name):
    return a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, name),
        principal_statement=STATEMENT,
        max_uses=1,
    )


def test_a_freshness_sidecar_with_a_bad_timestamp_is_a_storage_failure(pair):
    a, b, clock, reports = pair
    g = _one_use_grant_r7(a, b, "fs.txt")
    b.revocations.check_path.write_text('{"last_checked": "nope"}')
    before = len(b.ledger)
    with pytest.raises(IntegrityError) as e:
        b.receive(write_bundle(a, b, g, "fs.txt"))
    assert e.value.reason == "state.corrupt" and str(b.revocations.check_path) in str(e.value)
    assert not (b.scratch_dir / "fs.txt").exists() and len(b.ledger) == before
    assert b.grant_uses(g) == (0, None)  # the check precedes the reservation: nothing consumed
    b.mark_lookup_ok()
    (r,) = b.receive(write_bundle(a, b, g, "fs.txt"))
    assert r["object"]["outcome"] == "applied"


def test_list_dir_propagates_a_failure_while_iterating(tmp_path, monkeypatch):
    d = tmp_path / "held"
    d.mkdir()
    (d / "a.json").write_text("{}")
    real = os.scandir

    class Cut:
        def __init__(self, it):
            self.it = it

        def __enter__(self):
            return self

        def __exit__(self, *a):
            self.it.close()

        def __iter__(self):
            yield from self.it
            raise FileNotFoundError(2, "the directory vanished while it was being read")

    monkeypatch.setattr(os, "scandir", lambda p=".": Cut(real(p)) if Path(p) == d else real(p))
    with pytest.raises(FileNotFoundError):
        list_dir(d, ".json")
    monkeypatch.undo()
    assert list_dir(d, ".json") == [d / "a.json"]
    assert list_dir(tmp_path / "absent") == []  # only an absent directory is empty


def test_mirror_truncation_stops_when_the_jsonl_barrier_fails(tmp_path, monkeypatch):
    n, e, torn = _excess_mirror_node(tmp_path)
    before = n.ledger.prose_path.read_bytes()
    monkeypatch.setattr(os, "fsync", _file_fsync_failing_for(n.ledger.path))
    with pytest.raises(OSError):
        n.repair_ledger()
    assert n.ledger.prose_path.read_bytes() == before  # untouched
    assert not (n.state / "ledger-repair-pending.json").exists()
    assert _audits(n, "ledger.mirror_truncated") == []
    monkeypatch.undo()
    assert n.repair_ledger() == (len(torn), 0, 0)
    assert n.ledger.verify() == n.ledger.head()


# ---- self-gate round 7b findings N1–N7 -------------------------------------------------------


def test_ledger_appends_refuse_while_a_mirror_repair_intent_stands(tmp_path, monkeypatch):
    reports: list[str] = []
    a, b, g, rev, held, clock = _pinned_held_healthy(tmp_path, reports)
    for i in range(2):
        b.ledger.append(
            ts=TS, actor="a", grant_id=None, action=f"s{i}", params_hash=None, outcome="information"
        )
    b.ledger.append(
        ts=TS, actor="a", grant_id=None, action="x", params_hash=None, outcome="information"
    )
    _drop_last_line(b.ledger.path)  # the mirror is one line longer than the JSONL
    b.ledger._entries = None
    marker = b.state / "ledger-repair-pending.json"
    real = nodemod._write_json

    def write_json(p, v):  # the cut landed; the step write did not
        if p == marker and isinstance(v, dict) and v.get("step") == "truncated":
            raise OSError(5, "Input/output error")
        real(p, v)

    monkeypatch.setattr(nodemod, "_write_json", write_json)
    with pytest.raises(OSError):
        b.repair_ledger()
    monkeypatch.undo()
    assert json.loads(marker.read_text())["step"] == "intent"
    mirror = b.ledger.prose_path.read_bytes()
    jsonl = b.ledger.path.read_bytes()
    # the mirror is whole now, so an ordinary append WOULD land past the cut point:
    # every ledger writer refuses instead, as a storage failure
    with pytest.raises(IntegrityError) as e:
        b.ledger.append(
            ts=TS, actor="a", grant_id=None, action="y", params_hash=None, outcome="information"
        )
    assert e.value.reason == "ledger.repair_pending"
    with pytest.raises(IntegrityError):  # a receive: nothing ledgered, the mail stays unseen
        b.receive(a.compose_card())
    b2 = _running(b, clock, reports)  # the startup replay cannot ledger: the replay marker
    replay = b.state / REPLAY_MARKER
    assert replay.exists() and "ledger.repair_pending" in json.loads(replay.read_text())["why"]
    assert held.exists() and b.ledger.path.read_bytes() == jsonl
    assert b.ledger.prose_path.read_bytes() == mirror
    # the verb resumes (already at the cut point), audits — its own append passes the
    # gate — and the marker goes; then appends work and the sweep replays
    assert b2.repair_ledger() == (0, 0, 0)
    assert not marker.exists() and len(_audits(b2, "ledger.mirror_truncated")) == 1
    b2.ledger.append(
        ts=TS, actor="a", grant_id=None, action="z", params_hash=None, outcome="information"
    )
    b3 = _running(b, clock, reports)
    assert not replay.exists() and not held.exists()
    assert b3.ledger.verify() == b3.ledger.head()


@pytest.mark.parametrize("st", STORES[:2], ids=[s.what for s in STORES[:2]])
@pytest.mark.parametrize("stop_at", ["truncated", "audited"])
def test_writers_refuse_at_every_step_the_marker_shows(tmp_path, monkeypatch, st, stop_at):
    n, torn = st.make(tmp_path)
    marker = n.state / f"{st.what}-repair-pending.json"
    if stop_at == "truncated":
        monkeypatch.setattr(n.ledger, "append", _raise(OSError(28, "disk full")))
    else:
        real_remove = Path.unlink

        def remove(self, missing_ok=False):
            if self == marker:
                raise OSError(5, "Input/output error")
            return real_remove(self, missing_ok=missing_ok)

        monkeypatch.setattr(Path, "unlink", remove)
    with pytest.raises(OSError):
        st.repair(n)
    monkeypatch.undo()
    assert json.loads(marker.read_text())["step"] == stop_at and st.clean(n)
    raw = st.path(n).read_bytes()
    # a later step may be visible and unsynced: the store stays closed to writers
    # until the marker is gone
    with pytest.raises(IntegrityError) as e:
        if st.what == "feed":
            n.revoke(grants=[uid("grt")], principal_statement="x")
        else:
            n.deny(deny=[{"action": "info", "resource": "*"}], principal_statement="x")
    assert e.value.reason == f"{st.what}.repair_pending" and f"step {stop_at!r}" in e.value.detail
    assert st.path(n).read_bytes() == raw
    assert st.repair(n) == 0 and not marker.exists()
    if st.what == "feed":
        n.revoke(grants=[uid("grt")], principal_statement="after")
    else:
        n.deny(deny=[{"action": "info", "resource": "*"}], principal_statement="after")
    assert len(st.path(n).read_bytes()) > len(raw)


def test_a_present_null_sidecar_is_corruption_not_absence(tmp_path):
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    _with_a_due_resend(wb, b, a.card, clock)
    wa.send(a.compose_card())
    wb.cursor_path.write_text("null")
    with pytest.raises(IntegrityError) as e:
        wb.cursor()
    assert e.value.reason == "state.corrupt" and str(wb.cursor_path) in str(e.value)
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["applied"] == 0 and s["resent"] == 1
    os.remove(wb.cursor_path)
    assert wb.cursor() is None and wb.poll_once()["applied"] == 1
    b.revocations.check_path.write_text("null")
    with pytest.raises(IntegrityError) as e:
        b.revocations.last_checked()
    assert e.value.reason == "state.corrupt" and str(b.revocations.check_path) in str(e.value)
    os.remove(b.revocations.check_path)
    assert b.revocations.last_checked() is None


# ---- self-gate round 7c findings 1–6 --------------------------------------------------------


@pytest.mark.parametrize("damage", ["null", "signature"])
def test_a_held_revocation_that_no_longer_parses_or_verifies_keeps_the_gate(tmp_path, damage):
    reports: list[str] = []
    a, b, g, rev, held, clock = _pinned_held_healthy(tmp_path, reports)
    original = held.read_bytes()
    if damage == "null":
        held.write_text("null")
    else:
        r = json.loads(original)
        r["sig"] = ("B" if r["sig"][0] != "B" else "C") + r["sig"][1:]
        held.write_text(json.dumps(r))
    damaged = held.read_bytes()
    b2 = _running(b, clock, reports)  # the sweep: local corruption, never "nothing held"
    replay = b.state / REPLAY_MARKER
    assert replay.exists() and "revocation.held_corrupt" in json.loads(replay.read_text())["why"]
    assert held.read_bytes() == damaged  # kept, never deleted
    assert b2.revocations.entries() == []  # nothing invented, nothing replayed
    b2.receive(a.compose_card())
    b2.mark_lookup_ok()
    with pytest.raises(IntegrityError) as e:  # round 12: a storage failure, unseen
        b2.receive(write_bundle(a, b2, g, "h.txt"))
    assert e.value.reason == "revocation.held_corrupt"
    assert not (b2.scratch_dir / "h.txt").exists() and held.exists()
    with pytest.raises(IntegrityError) as e:  # the repair verb refuses too; the marker stays
        b2.repair_feed()
    assert e.value.reason == "revocation.held_corrupt" and replay.exists()
    held.write_bytes(original)  # restored by hand: the next start replays it
    b3 = _running(b, clock, reports)
    assert not replay.exists() and not held.exists()
    assert b3.revocations.grant_revoked_by(g["grant_id"], a.principal.public) is not None
    (r2,) = b3.receive(write_bundle(a, b3, g, "h.txt"))
    assert r2["object"]["outcome"] == "refused:no_authorizing_grant"


def test_pin_refuses_a_corrupt_held_copy_and_publishes_no_trust(tmp_path):
    a, b, g, rev, clock = _unpinned_pair(tmp_path)
    assert b.receive(a.compose_revocation(rev)) == []
    (held,) = held_revocations(b, rev["rev_id"])
    held.write_text("[]")
    with pytest.raises(IntegrityError) as e:
        b.pin(a.principal.public, "a")
    assert e.value.reason == "revocation.held_corrupt" and str(held) in str(e.value)
    assert a.principal.public not in b.pinned and held.exists()


def _redelivered(a, wa, clock):
    """The peer re-sends its message (its ack never arrived): a second mail, a new
    Gmail id, the same msg_id."""
    clock.tick(2 * a.poll_s)
    assert wa.poll_once()["resent"] == 1


def _seen_mail_r7(node) -> dict:
    p = node.state / "seen-mail.json"
    return json.loads(p.read_text()) if p.exists() else {}


def test_fdopen_failure_with_a_failing_close_still_removes_the_temp_name(tmp_path, monkeypatch):
    ex = Executor(KEY, tmp_path / "scratch")
    real_close = os.close

    def close(fd):  # closes, then reports failure, for every non-directory descriptor
        st = os.fstat(fd)
        real_close(fd)
        if not stat.S_ISDIR(st.st_mode):
            raise OSError(5, "Input/output error on close")

    monkeypatch.setattr(os, "fdopen", _raise(OSError(24, "Too many open files")))
    monkeypatch.setattr(os, "close", close)
    before = _open_fds()
    with pytest.raises(OSError) as e:
        ex.apply("fs.write", ex.resource_for("f.txt"), {"content": "x"})
    assert not isinstance(e.value, PostCommitError)
    assert _open_fds() <= before
    assert list((tmp_path / "scratch").iterdir()) == []  # the temp name is gone
    monkeypatch.undo()
    assert ex.apply("fs.write", ex.resource_for("f.txt"), {"content": "x"})["outcome"] == "applied"


# ---- self-gate round 7d findings Q1–Q4 --------------------------------------------------------


@pytest.mark.parametrize("damage", ["empty-principal", "null-key", "damaged-key"])
def test_a_held_copy_with_a_damaged_principal_never_passes_the_filter(tmp_path, damage):
    reports: list[str] = []
    a, b, g, rev, held, clock = _pinned_held_healthy(tmp_path, reports)
    r = json.loads(held.read_text())
    if damage == "empty-principal":
        r["principal"] = {}
    elif damage == "null-key":
        r["principal"]["key"] = None
    else:  # a damaged key names nobody pinned; the signature no longer verifies either
        k = r["principal"]["key"]
        r["principal"]["key"] = k[:-3] + ("AAA" if not k.endswith("AAA") else "BBB")
    held.write_text(json.dumps(r))
    damaged = held.read_bytes()
    b2 = _running(b, clock, reports)
    replay = b.state / REPLAY_MARKER
    assert replay.exists() and "revocation.held_corrupt" in json.loads(replay.read_text())["why"]
    assert held.read_bytes() == damaged
    with pytest.raises(IntegrityError) as e:
        b2.repair_feed()
    assert e.value.reason == "revocation.held_corrupt" and replay.exists()
    b2.receive(a.compose_card())
    b2.mark_lookup_ok()
    with pytest.raises(IntegrityError) as e:  # round 12: a storage failure, unseen
        b2.receive(write_bundle(a, b2, g, "h.txt"))
    assert e.value.reason == "revocation.held_corrupt"
    # pin on an unpinned node with the same damage publishes no trust either
    a2, c, g2, rev2, clock2 = _unpinned_pair(tmp_path / "second", name_b="c")
    assert c.receive(a2.compose_revocation(rev2)) == []
    (held2,) = held_revocations(c, rev2["rev_id"])
    held2.write_text(json.dumps(r))
    with pytest.raises(IntegrityError):
        c.pin(a2.principal.public, "a")
    assert a2.principal.public not in c.pinned and held2.exists()

"""Round 7b (hw-hrcms): the held-reply recovery simplified to FAIL CLOSED — the mayor's
ruling on the round-7 design pause. A corrupt held reply is kept, counted and recorded,
and NOTHING automatic rebuilds or sends from a damaged source; a human resolves it with
the `natively pending` verbs. Two invariants hold by construction: "never lost" (the copy
stays, the cursor freezes until resolved) and "never sent wrong or after cancellation"
(no automatic send from any source that did not pass the ordinary validated hold path).

Test categories (as in the round-5 to round-7 modules):
  ORDERING          — every fsync / removal / audit is recorded and the order asserted;
  FAILURE BEFORE    — a persistence step fails before anything became visible;
  FAILURE AFTER     — the syscall at step N fails AFTER its effect became visible, the
                      process retries or restarts (an unsynced tail may be gone);
  RESTART RECOVERY  — a fresh Node / a CLI invocation (a fresh Node in this interpreter)
                      starts on what the last one left.

1   QUARANTINE ONLY: a held reply that does not parse, is not a bundle, or does not
    verify (structure, signature, our key, in_reply_to = the name's msg_id) is moved
    aside under the ULID-stamped name, counted once, ledgered pending_reply.corrupt once,
    and nothing is rebuilt or sent; every later poll counts it again, the cursor frozen;
2   the automatic recovery is gone: no per-poll gate, no reconstruct-and-send, no
    .reconstructed promotion inside a poll, no discard automation outside the verb;
3   RE-DELIVERY goes through the ordinary path only: the stored ack, validated, held
    before the seen mark and sent; a damaged stored ack is seen.corrupt (the mail
    unseen, nothing sent, the poll incomplete) and is never sent by any path;
4   the VERBS: pending list (held / corrupt / reconstructed / discarded), pending repair
    [NAME] from a validated source only (the stored ack, else the ledger completion;
    holds, never sends; a conflict or no source refuses by name), pending discard NAME
    [--with-held] (the record first, the canonical held reply durable on its own before
    the aside, resumable from the record, a second discard appends nothing);
R1  an older unresolved aside plus a newer damaged canonical: two asides, nothing sent,
    one count each;
R2  the two-file removal survives a failed barrier between the files;
R3  a damaged stored ack is never sent by any path (the re-delivery, `natively ack`,
    the repair verb)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from natively import ack as ackmod
from natively import bundle as bundlemod
from natively.adapters import mail as mailmod
from natively.adapters.mail import MailWire
from natively.cli import main
from natively.errors import IntegrityError
from natively.ledger import Ledger

from .conftest import uid
from .test_gate_round3 import seen_of
from .test_gate_round5 import _raise
from .test_gate_round6 import _connected_over_mail, _drop_last_line
from .test_gate_round7 import (
    _argv,
    _held_ack_over_mail,
    _ledger_fsync_failing_after,
    _redelivered,
    _seen_mail_r7,
)

PEER = "taylor@houmanoids.com"  # where b's sends land
STAMP = "corrupt-20260907T070000Z-01ARZ3NDEKTSV4RRFFQ69G5FAV"


def _acks_out(fake, since: int) -> list[dict]:
    """The ack objects that LEFT b's box (landed in the peer's inbox) after row `since`."""
    rows = fake.inbox.get(PEER, [])[since:]
    return [bundlemod.decode(row["body"])["object"] for row in rows]


def _inbox_len(fake) -> int:
    return len(fake.inbox.get(PEER, []))


def _row(status: str, name: str) -> str:
    """One `pending list` line, as the CLI formats it."""
    return f"{status:<14} {name}"


def _actions(node) -> list[str]:
    return [e["action"] for e in node.ledger.entries()]


def _damage_stored_ack(node, msg_id: str, how: str) -> None:
    """A stored ack that READS as an object but is not this node's reply: seen.corrupt
    at the re-delivery. (A stored ack that is not an object at all is refused one
    step earlier, by the typed seen loader — state.corrupt; round 9 covers it.)"""
    seen = seen_of(node)
    if how == "signature":
        sig = seen[msg_id]["ack"]["sig"]
        seen[msg_id]["ack"]["sig"] = ("B" if sig[0] != "B" else "C") + sig[1:]
    else:
        assert how == "in-reply-to"
        seen[msg_id]["ack"]["in_reply_to"] = uid("msg")
    (node.state / "seen.json").write_text(json.dumps(seen))


def _quarantined(tmp_path, n=1):
    """b holds n acks (their sends failed); the first is corrupted and the next poll
    moves it aside. Returns everything plus the aside copy and its msg_id."""
    a, b, wa, wb, fake, clock, held, reports = _held_ack_over_mail(tmp_path, n=n)
    p = held[0]
    msg_id, _ = MailWire.parse_held_name(p.name)
    p.write_bytes(b"{")
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False
    asides = wb._aside_replies()
    (aside,) = [x for x in asides if x.name.startswith(p.name)]
    assert wb._unresolved(aside)
    return a, b, wa, wb, fake, clock, aside, msg_id, reports


# ---- 1. quarantine only: aside + count + ledger + frozen cursor + no send + no rebuild --------


@pytest.mark.parametrize(
    "damage", ["parse-failure", "non-bundle", "empty-object", "signature", "in-reply-to"]
)
def test_a_corrupt_held_reply_is_quarantined_counted_ledgered_and_never_sent(tmp_path, damage):
    a, b, wa, wb, fake, clock, held, reports = _held_ack_over_mail(tmp_path, n=2)
    p, other = held
    msg_id, kind = MailWire.parse_held_name(p.name)
    assert kind == "ack" and p.name == f"{msg_id}.ack.json"
    if damage == "parse-failure":
        raw = b'{"kind": "ack", "object": {'
    elif damage == "non-bundle":
        raw = b'{"ack_id": "loose"}'
    else:
        r = json.loads(p.read_text())
        if damage == "empty-object":
            r = {"kind": "ack", "object": {}}
        elif damage == "signature":
            sig = r["object"]["sig"]
            r["object"]["sig"] = ("B" if sig[0] != "B" else "C") + sig[1:]
        else:  # a valid ack, ours, for the OTHER message under this name
            r = json.loads(other.read_text())
        raw = json.dumps(r).encode()
    p.write_bytes(raw)
    stored_before = seen_of(b)[msg_id]["ack"]
    clock.tick(5)
    cursor_before = wb.cursor()
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False
    assert wb.cursor() == cursor_before != clock()
    assert s["replies"] == 1  # the OTHER held reply went out; nothing for msg_id
    out = _acks_out(fake, inbox_before)
    assert len(out) == 1 and out[0]["in_reply_to"] != msg_id
    assert any("not a valid held reply" in e and p.name in e for e in s["errors"])
    (aside,) = wb._aside_replies()
    assert aside.name.startswith(p.name + ".corrupt-") and wb._unresolved(aside)
    assert aside.read_bytes() == raw  # preserved, never deleted
    assert not p.exists() and wb._pending_replies() == []  # nothing rebuilt under the name
    entries = b.ledger.entries()
    (c,) = [e for e in entries if e["action"] == "pending_reply.corrupt"]
    assert c["msg_id"] == msg_id and c["direction"] == "out"
    assert wb._audit_key(aside.name) in c["detail"]
    assert "pending_reply.reconstructed" not in _actions(b)
    assert seen_of(b)[msg_id]["ack"] == stored_before  # the stored ack untouched
    assert b.ledger.find_msg(msg_id)["outcome"] == "information"  # the completion untouched
    assert b.ledger.verify() == b.ledger.head()
    # every later poll counts it again: the cursor stays frozen, nothing goes out
    clock.tick(5)
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False and s["replies"] == 0
    assert wb.cursor() == cursor_before and _inbox_len(fake) == inbox_before
    assert any("still aside and unresolved" in e and aside.name in e for e in s["errors"])
    assert _actions(b).count("pending_reply.corrupt") == 1
    assert wb._unresolved(aside) and aside.read_bytes() == raw
    # the peer is still waiting for that ack (only the other message was acked)
    assert wa.poll_once()["applied"] == 1
    assert {x["msg_id"]: x["status"] for x in a.outbox()}[msg_id] == "pending"


def test_an_aside_copy_freezes_the_cursor_across_a_restart_until_the_operator_decides(
    tmp_path, capsys
):
    """RESTART RECOVERY: a fresh wire over the state the last one left."""
    a, b, wa, wb, fake, clock, aside, msg_id, reports = _quarantined(tmp_path)
    wb2 = MailWire(b, runner=fake.runner_for("taylor@teale.com"))
    clock.tick(5)
    cursor_before = wb2.cursor()
    inbox_before = _inbox_len(fake)
    s = wb2.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False and s["replies"] == 0
    assert wb2.cursor() == cursor_before and _inbox_len(fake) == inbox_before
    assert wb2._unresolved(aside) and _actions(b).count("pending_reply.corrupt") == 1
    argv = _argv(b)
    assert main([*argv, "pending", "list"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("corrupt") and aside.name in out and msg_id in out
    assert main([*argv, "pending", "discard", aside.name]) == 0
    assert "discarded" in capsys.readouterr().out and not aside.exists()
    led = b.ledger.entries()[-1]
    assert led["action"] == "pending_reply.discarded" and led["msg_id"] == msg_id
    assert led["direction"] == "out" and wb2._audit_key(aside.name) in led["detail"]
    assert MailWire.DROPS_HELD not in led["detail"]
    clock.tick(5)
    s = wb2.poll_once()
    assert s["storage_failures"] == 0 and s["complete"] is True and wb2.cursor() == clock()
    assert _inbox_len(fake) == inbox_before  # nothing was ever sent for the dropped copy


def test_the_quarantine_audit_that_failed_is_written_on_the_next_poll_once_and_nothing_rebuilt(
    tmp_path, monkeypatch
):
    """FAILURE BEFORE (the audit append raises): the copy is aside and unaudited; the
    next poll writes the audit once; no rebuild, no send, on either pass."""
    a, b, wa, wb, fake, clock, (held,), reports = _held_ack_over_mail(tmp_path)
    msg_id, _ = MailWire.parse_held_name(held.name)
    held.write_text("{")
    monkeypatch.setattr(b.ledger, "append", _raise(OSError(28, "disk full")))
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["storage_failures"] >= 2 and s["complete"] is False and s["replies"] == 0
    (aside,) = wb._aside_replies()
    assert wb._unresolved(aside) and not held.exists()
    actions = _actions(b)
    assert actions and not any(x.startswith("pending_reply") for x in actions)
    monkeypatch.undo()
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["replies"] == 0 and s["complete"] is False
    assert wb._unresolved(aside) and not held.exists() and _inbox_len(fake) == inbox_before
    assert _actions(b).count("pending_reply.corrupt") == 1
    assert "pending_reply.reconstructed" not in _actions(b)
    (c,) = [e for e in b.ledger.entries() if e["action"] == "pending_reply.corrupt"]
    assert c["msg_id"] == msg_id and wb._audit_key(aside.name) in c["detail"]
    assert wb.poll_once()["storage_failures"] == 1  # and again, until a verb decides


def test_a_quarantine_whose_directory_fsync_failed_after_the_move_is_audited_next_poll(
    tmp_path, monkeypatch
):
    """FAILURE AFTER: the rename landed, its directory fsync failed. The aside copy is
    visible and unaudited; the next poll counts it and writes the audit once."""
    a, b, wa, wb, fake, clock, (held,), reports = _held_ack_over_mail(tmp_path)
    held.write_bytes(b"{")
    real = mailmod.fsync_dir
    state = {"n": 0}

    def fsync_dir(d):
        if Path(d) == wb.pending_dir and state["n"] == 0:
            state["n"] += 1
            raise OSError(5, "Input/output error")
        real(d)

    monkeypatch.setattr(mailmod, "fsync_dir", fsync_dir)
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert state["n"] == 1 and s["storage_failures"] == 2 and s["complete"] is False
    (aside,) = wb._aside_replies()
    assert wb._unresolved(aside) and not held.exists()
    assert "pending_reply.corrupt" not in _actions(b)
    monkeypatch.undo()
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["replies"] == 0 and _inbox_len(fake) == inbox_before
    assert _actions(b).count("pending_reply.corrupt") == 1 and wb._unresolved(aside)


@pytest.mark.parametrize("where", ["aside-name", "validation"])
def test_quarantine_and_validation_reads_are_inside_the_boundary(tmp_path, monkeypatch, where):
    """FAILURE BEFORE: the aside name cannot be chosen / the validation raises: counted,
    the copy left in place, the outbox still ran; the retry quarantines or sends."""
    from .test_gate_round6 import _with_a_due_resend

    a, b, wa, wb, fake, clock, (held,), reports = _held_ack_over_mail(tmp_path)
    _with_a_due_resend(wb, b, a.card, clock)
    if where == "aside-name":
        held.write_text("{")
        monkeypatch.setattr(wb, "_aside_path", _raise(PermissionError(13, "Permission denied")))
    else:
        monkeypatch.setattr(wb, "_held_reply_problem", _raise(OSError(5, "Input/output error")))
    sends_before = len(fake.sends)
    s = wb.poll_once()
    assert s["storage_failures"] >= 1 and s["complete"] is False and s["replies"] == 0
    assert held.exists() and wb._aside_replies() == []
    assert s["resent"] == 1 and len(fake.sends) == sends_before + 1
    monkeypatch.undo()
    s = wb.poll_once()
    if where == "aside-name":
        assert s["replies"] == 0 and len(wb._aside_replies()) == 1 and not held.exists()
    else:
        assert s["replies"] == 1 and wb._pending_replies() == []
        assert wa.poll_once()["applied"] >= 1


def test_audit_keys_are_exact_not_substrings(tmp_path):
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "one"))
    assert wb.poll_once()["replies"] == 1 and wa.poll_once()["applied"] == 1
    msg_id = a.outbox()[-1]["msg_id"]
    wb.pending_dir.mkdir(exist_ok=True)
    first = wb.pending_dir / f"{msg_id}.ack.json.{STAMP}"
    second = wb.pending_dir / f"{first.name}-2"
    first.write_text("{")
    second.write_text("{")
    # the second copy's audit exists; the first's does not — and must not be found
    wb._ledger_pending_once(
        "pending_reply.corrupt", msg_id, "held reply x did not parse", second.name
    )
    assert wb._find_pending_entry("pending_reply.corrupt", second.name) is not None
    assert wb._find_pending_entry("pending_reply.corrupt", first.name) is None
    s = wb.poll_once()
    assert s["storage_failures"] == 2 and s["replies"] == 0
    corrupt = [e for e in b.ledger.entries() if e["action"] == "pending_reply.corrupt"]
    assert len(corrupt) == 2
    assert {wb._audit_key(first.name) in e["detail"] for e in corrupt} == {True, False}
    assert all(wb._unresolved(x) for x in wb._aside_replies()) and len(wb._aside_replies()) == 2
    assert "pending_reply.reconstructed" not in _actions(b)


# ---- 3. re-delivery: the ordinary path only ---------------------------------------------------


def test_a_redelivery_with_a_valid_stored_ack_is_answered_while_the_aside_freezes_the_cursor(
    tmp_path,
):
    a, b, wa, wb, fake, clock, aside, msg_id, reports = _quarantined(tmp_path)
    _redelivered(a, wa, clock)
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["applied"] == 1 and s["replies"] == 1
    assert s["storage_failures"] == 1 and s["complete"] is False  # the aside still counts
    (out,) = _acks_out(fake, inbox_before)
    assert out == seen_of(b)[msg_id]["ack"] and out["in_reply_to"] == msg_id
    ackmod.verify(out)
    assert wb._pending_replies() == [] and wb._unresolved(aside)
    assert "pending_reply.reconstructed" not in _actions(b)
    assert _actions(b).count("pending_reply.corrupt") == 1
    assert wa.poll_once()["applied"] == 1 and a.outbox()[-1]["status"] == "acked"
    # the aside copy is still the operator's: counted until resolved
    assert wb.poll_once()["storage_failures"] == 1


@pytest.mark.parametrize("how", ["signature", "in-reply-to"])
def test_a_redelivery_with_a_damaged_stored_ack_is_seen_corrupt_and_nothing_is_sent(
    tmp_path, how, capsys
):
    """R3: a damaged stored ack is never sent by any path — the re-delivery, `natively
    ack`, the repair verb. Round 13: the stored acks anchor the ledger's tail, so a
    damaged one is seen.corrupt at the ledger's full check and NOTHING is rebuilt
    over it (the completion it anchored can no longer be told from an edited one):
    the repair verb counts a storage failure and leaves the copy unresolved; the
    operator restores seen.json, and the stored ack, validated, serves."""
    a, b, wa, wb, fake, clock, aside, msg_id, reports = _quarantined(tmp_path)
    sound = seen_of(b)[msg_id]["ack"]
    _damage_stored_ack(b, msg_id, how)
    damaged = seen_of(b)[msg_id]["ack"]
    _redelivered(a, wa, clock)
    seen_mail_before = len(_seen_mail_r7(b))
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["applied"] == 0 and s["replies"] == 0 and _inbox_len(fake) == inbox_before
    assert s["storage_failures"] == 2 and s["complete"] is False  # the aside + the receive
    assert any("seen.corrupt" in e and str(b.state / "seen.json") in e for e in s["errors"])
    assert len(_seen_mail_r7(b)) == seen_mail_before  # the re-delivery stays unseen
    assert wb._pending_replies() == [] and wb._unresolved(aside)
    assert seen_of(b)[msg_id]["ack"] == damaged  # the poll repaired nothing
    # `natively ack MSG_ID` refuses it too
    assert main([*_argv(b), "ack", msg_id]) == 2
    err = capsys.readouterr().err
    assert "seen.corrupt" in err and _inbox_len(fake) == inbox_before
    # the repair verb refuses too: the ledger's full check (the stored acks
    # authenticated, round 13) runs before a completion is read — seen.corrupt, a
    # storage failure of the verb, nothing rebuilt, the copy unresolved
    assert main([*_argv(b), "pending", "repair"]) == 1
    cap = capsys.readouterr()
    assert "0 rebuilt, 0 unresolvable, 0 refused, 0 discard(s) finished, 1 storage failure(s)" in (
        cap.out
    )
    assert "seen.corrupt" in cap.err and msg_id in cap.err and "restore state/seen.json" in cap.err
    assert seen_of(b)[msg_id]["ack"] == damaged and wb._unresolved(aside)
    assert "pending_reply.reconstructed" not in _actions(b)
    assert _inbox_len(fake) == inbox_before  # the verb never sends
    # restored by hand: the repair verb rebuilds from the stored ack (validated)
    seen = seen_of(b)
    seen[msg_id]["ack"] = sound
    (b.state / "seen.json").write_text(json.dumps(seen))
    assert main([*_argv(b), "pending", "repair"]) == 0
    out = capsys.readouterr().out
    assert f"rebuilt      {aside.name}" in out and "1 rebuilt, 0 unresolvable" in out
    assert _inbox_len(fake) == inbox_before
    assert seen_of(b)[msg_id]["ack"] == sound
    ackmod.verify(sound)
    (r,) = [e for e in b.ledger.entries() if e["action"] == "pending_reply.reconstructed"]
    assert "the stored ack" in r["detail"] and r["msg_id"] == msg_id
    # the next poll: the held rebuilt reply goes out, and the re-delivery is answered
    s = wb.poll_once()
    assert s["replies"] == 2 and s["applied"] == 1 and s["complete"] is True
    out = _acks_out(fake, inbox_before)
    assert len(out) == 2 and all(o == sound for o in out)
    assert wa.poll_once()["applied"] >= 1 and a.outbox()[-1]["status"] == "acked"
    assert b.ledger.verify() == b.ledger.head()


def test_a_redelivery_never_consults_the_aside_copies(tmp_path, monkeypatch):
    """The re-delivery's reply is the stored ack: the aside copies are not read (a
    directory listing failure during the apply half changes nothing about it)."""
    a, b, wa, wb, fake, clock, aside, msg_id, reports = _quarantined(tmp_path)
    _redelivered(a, wa, clock)
    real = os.scandir
    calls = {"n": 0}

    def scandir(p=".", *a_, **kw):
        if Path(p) == wb.pending_dir:
            calls["n"] += 1
        return real(p, *a_, **kw)

    monkeypatch.setattr(os, "scandir", scandir)
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert calls["n"] == 2  # the flush's two listings (asides, held); none in the apply
    assert s["applied"] == 1 and s["replies"] == 1 and _inbox_len(fake) == inbox_before + 1
    assert wb._unresolved(aside)


def test_a_redelivery_whose_canonical_name_still_holds_the_damaged_file_refuses_the_hold(
    tmp_path, monkeypatch
):
    """FAILURE BEFORE (the quarantine's move cannot name its aside): the damaged file
    keeps the canonical name; the re-delivery's hold refuses to overwrite it
    (pending_reply.conflict, the mail unseen, nothing sent); once the move works the
    copy is quarantined and the re-delivery answered from the stored ack."""
    a, b, wa, wb, fake, clock, (held,), reports = _held_ack_over_mail(tmp_path)
    msg_id, _ = MailWire.parse_held_name(held.name)
    corrupt = b"{"
    held.write_bytes(corrupt)
    _redelivered(a, wa, clock)
    monkeypatch.setattr(wb, "_aside_path", _raise(PermissionError(13, "Permission denied")))
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["complete"] is False and _inbox_len(fake) == inbox_before
    assert held.read_bytes() == corrupt and wb._aside_replies() == []
    assert any("pending_reply.conflict" in e for e in s["errors"])
    assert s["applied"] == 1 and len(_seen_mail_r7(b)) == 2  # the dup mail unseen
    monkeypatch.undo()
    s = wb.poll_once()
    assert s["applied"] == 1 and s["replies"] == 1 and s["complete"] is False
    (aside,) = wb._aside_replies()
    assert wb._unresolved(aside) and aside.read_bytes() == corrupt
    (out,) = _acks_out(fake, inbox_before)
    assert out == seen_of(b)[msg_id]["ack"]
    assert _actions(b).count("pending_reply.corrupt") == 1
    assert "pending_reply.reconstructed" not in _actions(b)
    assert wa.poll_once()["applied"] == 1 and a.outbox()[-1]["status"] == "acked"


# ---- 4. the verbs: pending list / repair / discard ---------------------------------------------


def test_pending_repair_from_a_valid_stored_ack_holds_and_the_next_poll_sends(tmp_path, capsys):
    a, b, wa, wb, fake, clock, aside, msg_id, reports = _quarantined(tmp_path)
    corrupt = aside.read_bytes()
    inbox_before = _inbox_len(fake)
    assert main([*_argv(b), "pending", "repair"]) == 0
    out = capsys.readouterr().out
    assert f"rebuilt      {aside.name}" in out
    assert (
        "1 rebuilt, 0 unresolvable, 0 refused, 0 discard(s) finished, 0 storage failure(s)" in out
    )
    assert _inbox_len(fake) == inbox_before  # the verb never sends
    (held,) = wb._pending_replies()
    assert held.name == f"{msg_id}.ack.json"
    assert json.loads(held.read_text())["object"] == seen_of(b)[msg_id]["ack"]
    done = aside.with_name(aside.name + ".reconstructed")
    assert not aside.exists() and done.read_bytes() == corrupt
    actions = _actions(b)
    assert actions.count("pending_reply.corrupt") == 1
    assert actions.count("pending_reply.reconstructed") == 1
    assert actions.index("pending_reply.corrupt") < actions.index("pending_reply.reconstructed")
    (r,) = [e for e in b.ledger.entries() if e["action"] == "pending_reply.reconstructed"]
    assert r["msg_id"] == msg_id and "the stored ack" in r["detail"]
    assert wb._audit_key(done.name) in r["detail"]
    assert main([*_argv(b), "pending", "list"]) == 0
    listed = capsys.readouterr().out
    assert _row("held", held.name) in listed and _row("reconstructed", done.name) in listed
    # the next poll validates and sends it through the ordinary path; then complete
    clock.tick(5)
    s = wb.poll_once()
    assert s["replies"] == 1 and s["complete"] is True and wb.cursor() == clock()
    (out_ack,) = _acks_out(fake, inbox_before)
    assert out_ack["in_reply_to"] == msg_id and wb._pending_replies() == []
    assert wa.poll_once()["applied"] == 1 and a.outbox()[-1]["status"] == "acked"
    # a named repair of a resolved copy re-establishes its mark's barrier, nothing else
    assert main([*_argv(b), "pending", "repair", done.name]) == 0
    assert f"resolved     {done.name}" in capsys.readouterr().out
    assert main([*_argv(b), "pending", "repair", aside.name]) == 1  # the unmarked name is gone
    assert "not an aside copy" in capsys.readouterr().err


@pytest.mark.parametrize("stored", ["damaged", "absent"])
def test_pending_repair_from_the_ledger_completion_when_the_stored_ack_cannot_serve(
    tmp_path, capsys, stored
):
    """The ledger completion serves ONLY when no ack is stored (no anchor for that
    message). A damaged stored ack (round 13: the stored acks are the authenticated
    anchors of the chain's tail) is seen.corrupt at the ledger's full check the
    rebuild runs first — a storage failure of the verb, nothing rebuilt, the copy
    unresolved, the stored ack untouched; the operator restores seen.json and the
    stored ack, validated, serves."""
    a, b, wa, wb, fake, clock, aside, msg_id, reports = _quarantined(tmp_path)
    inbox_before = _inbox_len(fake)
    if stored == "damaged":
        sound = seen_of(b)[msg_id]["ack"]
        _damage_stored_ack(b, msg_id, "signature")
        damaged = seen_of(b)[msg_id]["ack"]
        assert main([*_argv(b), "pending", "repair", aside.name]) == 1
        cap = capsys.readouterr()  # the CLI's own Node reports to stderr
        assert "0 rebuilt" in cap.out and "1 storage failure(s)" in cap.out
        # round 14: the anchored ledger check precedes the discard-record lookup, so
        # the damaged stored ack is seen.corrupt at that first read of the verb —
        # before any source is tried, the same name and msg_id
        assert f"the discard record of {aside.name}" in cap.err
        assert "trying the ledger completion" not in cap.err
        assert "seen.corrupt" in cap.err and msg_id in cap.err
        assert seen_of(b)[msg_id]["ack"] == damaged and wb._unresolved(aside)
        assert wb._pending_replies() == [] and _inbox_len(fake) == inbox_before
        assert "pending_reply.reconstructed" not in _actions(b)
        seen = seen_of(b)
        seen[msg_id]["ack"] = sound  # restored by hand
        (b.state / "seen.json").write_text(json.dumps(seen))
        source = "the stored ack"
    else:
        seen = seen_of(b)
        del seen[msg_id]  # the older seen file: no stored ack, no anchor
        (b.state / "seen.json").write_text(json.dumps(seen))
        source = "the ledger completion"
    assert main([*_argv(b), "pending", "repair", aside.name]) == 0
    cap = capsys.readouterr()
    assert "1 rebuilt" in cap.out
    assert _inbox_len(fake) == inbox_before
    stored_now = seen_of(b)[msg_id]["ack"]  # stored again by the rebuild (the barrier first)
    assert stored_now["in_reply_to"] == msg_id and stored_now["outcome"] == "information"
    ackmod.verify(stored_now)
    (held,) = wb._pending_replies()
    assert json.loads(held.read_text())["object"] == stored_now
    (r,) = [e for e in b.ledger.entries() if e["action"] == "pending_reply.reconstructed"]
    assert source in r["detail"]
    s = wb.poll_once()
    assert s["replies"] == 1 and s["complete"] is True
    assert wa.poll_once()["applied"] == 1 and a.outbox()[-1]["status"] == "acked"
    assert b.ledger.verify() == b.ledger.head()


def test_pending_repair_is_refused_by_name_when_no_validated_source_exists(tmp_path, capsys):
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wb.pending_dir.mkdir(exist_ok=True)
    orphan = wb.pending_dir / f"{uid('msg')}.ack.json.{STAMP}"
    orphan.write_text("{")  # a copy no completion answers for
    inbox_before = _inbox_len(fake)
    for _ in range(2):  # a second run appends nothing
        assert main([*_argv(b), "pending", "repair"]) == 1
        out = capsys.readouterr().out
        assert f"unresolvable {orphan.name}" in out and "pending_reply.unresolvable" in out
        assert (
            "0 rebuilt, 1 unresolvable, 0 refused, 0 discard(s) finished, 0 storage failure(s)"
            in out
        )
        assert orphan.exists() and wb._unresolved(orphan) and wb._pending_replies() == []
        assert _actions(b).count("pending_reply.corrupt") == 1  # the audit first, once
        assert "pending_reply.reconstructed" not in _actions(b)
    assert _inbox_len(fake) == inbox_before
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False
    assert main([*_argv(b), "pending", "discard", orphan.name]) == 0
    assert not orphan.exists() and wb.poll_once()["complete"] is True


def test_pending_repair_refuses_a_conflicting_canonical_file_and_leaves_both(tmp_path, capsys):
    a, b, wa, wb, fake, clock, aside, msg_id, reports = _quarantined(tmp_path)
    canonical = wb.pending_dir / wb.held_name_of(aside)
    canonical.write_text('{"kind": "ack", "object": {}}')  # a DIFFERENT file under the name
    other = canonical.read_bytes()
    assert main([*_argv(b), "pending", "repair"]) == 1
    out = capsys.readouterr().out
    assert f"refused      {aside.name}" in out and "pending_reply.conflict" in out
    assert "0 rebuilt, 0 unresolvable, 1 refused" in out
    assert aside.exists() and wb._unresolved(aside) and canonical.read_bytes() == other
    assert "pending_reply.reconstructed" not in _actions(b)
    # the next poll quarantines the conflicting file too (R1's shape); then repair works
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert len(wb._aside_replies()) == 2 and s["replies"] == 0 and s["storage_failures"] == 2
    assert _inbox_len(fake) == inbox_before
    assert main([*_argv(b), "pending", "repair"]) == 0
    assert "2 rebuilt" in capsys.readouterr().out
    asides = wb._aside_replies()
    assert len(asides) == 2 and all(not wb._unresolved(x) for x in asides)
    assert len(wb._pending_replies()) == 1
    s = wb.poll_once()
    assert s["replies"] == 1 and s["complete"] is True


def test_pending_repair_writes_the_missing_corruption_audit_first(tmp_path, capsys):
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "one"))
    assert wb.poll_once()["replies"] == 1 and wa.poll_once()["applied"] == 1
    msg_id = a.outbox()[-1]["msg_id"]
    wb.pending_dir.mkdir(exist_ok=True)
    aside = wb.pending_dir / f"{msg_id}.ack.json.{STAMP}"
    aside.write_text("{")  # a copy moved aside by a pass that died before its audit
    assert main([*_argv(b), "pending", "repair"]) == 0
    assert "1 rebuilt, 0 unresolvable" in capsys.readouterr().out
    actions = _actions(b)
    assert actions.index("pending_reply.corrupt") < actions.index("pending_reply.reconstructed")
    assert not aside.exists() and aside.with_name(aside.name + ".reconstructed").exists()
    assert (wb.pending_dir / f"{msg_id}.ack.json").exists()
    assert wb.poll_once()["replies"] == 1


@pytest.mark.parametrize("recovered", ["kept", "dropped"])
def test_a_reconstruction_audit_visible_but_unsynced_is_promoted_only_after_the_barrier(
    tmp_path, monkeypatch, recovered, capsys
):
    """FAILURE AFTER: the repair verb's reconstruction audit is visible, its fsync
    failed. The copy stays unresolved (counted); the held reply it made is a valid
    obligation the next poll sends through the ordinary path; the re-run promotes the
    found audit only after the ledger barrier — or writes it once when the power loss
    removed it."""
    a, b, wa, wb, fake, clock, aside, msg_id, reports = _quarantined(tmp_path)
    # the found corrupt audit's barrier is the first JSONL fsync of the verb; the
    # reconstruction audit's is the second — THAT one fails after the bytes landed
    state = _ledger_fsync_failing_after(b.ledger.path, 1, monkeypatch)
    inbox_before = _inbox_len(fake)
    assert main([*_argv(b), "pending", "repair"]) == 1
    out = capsys.readouterr()
    assert state["failed"] == 1 and "0 rebuilt" in out.out and "1 storage failure(s)" in out.out
    assert wb._unresolved(aside) and _inbox_len(fake) == inbox_before
    held = wb.pending_dir / wb.held_name_of(aside)
    assert held.exists() and json.loads(held.read_text())["object"] == seen_of(b)[msg_id]["ack"]
    assert _actions(b).count("pending_reply.reconstructed") == 1
    # the re-run (the barrier still failing): the found audit is not promoted
    assert main([*_argv(b), "pending", "repair"]) == 1
    capsys.readouterr()
    assert state["failed"] >= 2 and wb._unresolved(aside)
    assert _actions(b).count("pending_reply.reconstructed") == 1
    monkeypatch.undo()
    if recovered == "dropped":
        _drop_last_line(b.ledger.path)  # the power loss removes the unsynced audit
        b.ledger._entries = None
        assert _actions(b).count("pending_reply.reconstructed") == 0
    assert main([*_argv(b), "pending", "repair"]) == 0
    assert f"rebuilt      {aside.name}" in capsys.readouterr().out
    assert not wb._unresolved(next(iter(wb._aside_replies())))
    assert _actions(b).count("pending_reply.reconstructed") == 1
    assert _actions(b).count("pending_reply.corrupt") == 1
    assert _inbox_len(fake) == inbox_before  # still nothing sent by the verb
    s = wb.poll_once()
    assert s["replies"] == 1 and s["complete"] is True
    assert b.ledger.verify() == b.ledger.head()
    assert wa.poll_once()["applied"] == 1 and a.outbox()[-1]["status"] == "acked"


def test_a_failed_resolved_mark_is_retried_by_the_verb_without_a_second_audit(
    tmp_path, monkeypatch, capsys
):
    """FAILURE BEFORE the mark (the rename to .reconstructed raises): the hold and the
    audit stand; the re-run finds the audit, re-establishes the barrier, and marks."""
    a, b, wa, wb, fake, clock, aside, msg_id, reports = _quarantined(tmp_path)
    real = os.replace

    def replace(src, dst, *a_, **kw):
        if str(dst).endswith(".reconstructed"):
            raise OSError(5, "Input/output error")
        return real(src, dst, *a_, **kw)

    monkeypatch.setattr(os, "replace", replace)
    assert main([*_argv(b), "pending", "repair"]) == 1
    out = capsys.readouterr().out
    assert "0 rebuilt" in out and "1 storage failure(s)" in out
    assert wb._unresolved(aside) and (wb.pending_dir / wb.held_name_of(aside)).exists()
    monkeypatch.undo()
    assert main([*_argv(b), "pending", "repair"]) == 0
    assert f"rebuilt      {aside.name}" in capsys.readouterr().out
    assert not aside.exists() and aside.with_name(aside.name + ".reconstructed").exists()
    assert _actions(b).count("pending_reply.reconstructed") == 1
    assert _actions(b).count("pending_reply.corrupt") == 1
    assert wb.poll_once()["replies"] == 1


@pytest.mark.parametrize("when", ["opening", "iterating"])
def test_pending_repair_contains_a_listing_failure(tmp_path, monkeypatch, capsys, when):
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wb.pending_dir.mkdir(exist_ok=True)
    (wb.pending_dir / f"{uid('msg')}.ack.json.{STAMP}").write_text("{")
    real = os.scandir
    if when == "opening":

        def scandir(p=".", *a_, **kw):
            if Path(p) == wb.pending_dir:
                raise OSError(5, "Input/output error")
            return real(p, *a_, **kw)

    else:

        class Cut:
            def __init__(self, it):
                self.it = it

            def __enter__(self):
                return self

            def __exit__(self, *a_):
                self.it.close()

            def __iter__(self):
                yield from self.it
                raise OSError(5, "Input/output error")

        def scandir(p=".", *a_, **kw):
            return Cut(real(p, *a_, **kw)) if Path(p) == wb.pending_dir else real(p, *a_, **kw)

    monkeypatch.setattr(os, "scandir", scandir)
    assert main([*_argv(b), "pending", "repair"]) == 1
    out = capsys.readouterr()
    assert (
        "0 rebuilt, 0 unresolvable, 0 refused, 0 discard(s) finished, 1 storage failure(s)"
        in out.out
    )
    assert "storage failure reading the aside held replies" in out.err
    assert "Traceback" not in out.err


def _with_a_canonical_too(tmp_path):
    """An unresolved aside AND a valid canonical held reply for the same message (the
    peer re-sent; the send of the stored ack failed, so it is held)."""
    a, b, wa, wb, fake, clock, aside, msg_id, reports = _quarantined(tmp_path)
    _redelivered(a, wa, clock)
    fake.fail_sends = True
    s = wb.poll_once()
    fake.fail_sends = False
    assert s["applied"] == 1 and s["replies"] == 0
    held = wb.pending_dir / wb.held_name_of(aside)
    assert held.exists() and wb._unresolved(aside)
    return a, b, wa, wb, fake, clock, aside, held, msg_id


def test_pending_discard_records_first_then_removes_the_canonical_durably_before_the_aside(
    tmp_path, monkeypatch, capsys
):
    """ORDERING by call-order recording: the record, the canonical unlink, its directory
    fsync, the aside unlink, its directory fsync; without --with-held a standing
    canonical refuses the discard (nothing recorded, nothing removed)."""
    a, b, wa, wb, fake, clock, aside, held, msg_id = _with_a_canonical_too(tmp_path)
    before = len(b.ledger)
    assert main([*_argv(b), "pending", "discard", aside.name]) == 1
    err = capsys.readouterr().err
    assert "--with-held" in err and held.name in err
    assert aside.exists() and held.exists() and len(b.ledger) == before
    events: list[tuple[str, str]] = []
    real_append = Ledger.append  # the CLI builds its own Node: patch the class
    real_remove = Path.unlink
    real_fsync_dir = mailmod.fsync_dir

    def append(self, **kw):
        events.append(("ledger", kw["action"]))
        return real_append(self, **kw)

    def remove(self, missing_ok=False):
        if self.parent == wb.pending_dir:
            events.append(("unlink", self.name))
        return real_remove(self, missing_ok=missing_ok)

    def fsync_dir(d):
        events.append(("fsync", Path(d).name))
        return real_fsync_dir(d)

    monkeypatch.setattr(Ledger, "append", append)
    monkeypatch.setattr(Path, "unlink", remove)
    monkeypatch.setattr(mailmod, "fsync_dir", fsync_dir)
    assert main([*_argv(b), "pending", "discard", aside.name, "--with-held"]) == 0
    monkeypatch.undo()
    assert "its held reply removed" in capsys.readouterr().out
    assert events == [
        ("ledger", "pending_reply.discarded"),
        ("unlink", held.name),
        ("fsync", wb.pending_dir.name),
        ("unlink", aside.name),
        ("fsync", wb.pending_dir.name),
    ]
    assert not held.exists() and not aside.exists()
    (d,) = [e for e in b.ledger.entries() if e["action"] == "pending_reply.discarded"]
    assert MailWire.DROPS_HELD in d["detail"] and d["msg_id"] == msg_id
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()  # nothing of the cancelled obligation goes out
    assert s["replies"] == 0 and _inbox_len(fake) == inbox_before and s["complete"] is True
    # a second discard of the finished name appends nothing
    assert main([*_argv(b), "pending", "discard", aside.name, "--with-held"]) == 0
    assert "already on record" in capsys.readouterr().out
    assert _actions(b).count("pending_reply.discarded") == 1


@pytest.mark.parametrize("finisher", ["repair", "discard"])
@pytest.mark.parametrize("when", ["before", "after"])
@pytest.mark.parametrize("step", ["the canonical", "the aside"])
def test_pending_discard_is_resumed_from_its_record(
    tmp_path, monkeypatch, capsys, step, when, finisher
):
    """FAILURE BEFORE / FAILURE AFTER a removal step, the record durable: `before`
    — the removal raised and nothing changed; `after` — the removal LANDED and then
    the call reported failure (the visible-then-failed shape), for the canonical and
    for the aside. The poll removes nothing and counts whatever is still on disk as a
    discard on record; then the finisher — `pending repair` (an unfinished discard is
    finished from its record, never rebuilt) or `pending discard NAME` again — finds
    what is already gone a finished step, removes the rest, appends no second record."""
    a, b, wa, wb, fake, clock, aside, held, msg_id = _with_a_canonical_too(tmp_path)
    real_remove = Path.unlink
    victim = held if step == "the canonical" else aside

    def remove(self, missing_ok=False):
        if self == victim:
            if when == "after":
                real_remove(self, missing_ok=missing_ok)  # the effect lands ...
            raise OSError(5, "Input/output error")  # ... and the call reports failure
        return real_remove(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", remove)
    assert main([*_argv(b), "pending", "discard", aside.name, "--with-held"]) == 1
    assert "Input/output error" in capsys.readouterr().err
    monkeypatch.undo()
    (d,) = [e for e in b.ledger.entries() if e["action"] == "pending_reply.discarded"]
    assert MailWire.DROPS_HELD in d["detail"] and wb._audit_key(aside.name) in d["detail"]
    held_stands = step == "the canonical" and when == "before"
    aside_stands = not (step == "the aside" and when == "after")
    assert held.exists() == held_stands and aside.exists() == aside_stands
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    if aside_stands:
        # the aside counted and named as a discard on record; the poll removes nothing
        assert s["storage_failures"] == 1 and s["complete"] is False
        assert any("removal did not finish" in e and aside.name in e for e in s["errors"])
        assert aside.exists()
    else:
        assert s["storage_failures"] == 0 and s["complete"] is True  # nothing left to count
    if held_stands:
        # A canonical held reply still standing (the crash came before its removal) is
        # a genuine ack that passed the validated hold path: the flush sends it as it
        # sends every held reply — the accepted residual of record-first (the peer
        # dedups); the finisher then finds it gone, a finished step.
        assert s["replies"] == 1 and _inbox_len(fake) == inbox_before + 1 and not held.exists()
        (out,) = _acks_out(fake, inbox_before)
        assert out == seen_of(b)[msg_id]["ack"]
        inbox_before += 1
    else:
        assert s["replies"] == 0 and _inbox_len(fake) == inbox_before and not held.exists()
    assert main([*_argv(b), "pending", "list"]) == 0
    assert (_row("discarded", aside.name) in capsys.readouterr().out) == aside_stands
    events: list[tuple[str, bool]] = []  # (name, existed) per removal under pending-replies/

    def record(self, missing_ok=False):
        if self.parent == wb.pending_dir:
            events.append((self.name, self.exists()))
        return real_remove(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", record)
    if finisher == "repair":
        assert main([*_argv(b), "pending", "repair"]) == 0
        out = capsys.readouterr().out
        assert "0 rebuilt" in out and "0 refused" in out
        assert (f"discarded    {aside.name}" in out) == aside_stands
        assert f"{int(aside_stands)} discard(s) finished" in out
    else:
        assert main([*_argv(b), "pending", "discard", aside.name]) == 0  # no flag: the record says
        assert "already on record" in capsys.readouterr().out
    monkeypatch.undo()
    if aside_stands or finisher == "discard":
        # the canonical is already gone: a finished step, never an error; then the aside
        assert events == [(held.name, False), (aside.name, aside_stands)]
    else:
        assert events == []  # nothing on disk for the repair verb to finish
    assert not aside.exists() and not held.exists()
    assert "pending_reply.reconstructed" not in _actions(b)
    assert _actions(b).count("pending_reply.discarded") == 1
    # whichever verb finished it, the other appends nothing and removes nothing
    other = ["pending", "discard", aside.name] if finisher == "repair" else ["pending", "repair"]
    assert main([*_argv(b), *other]) == 0
    assert _actions(b).count("pending_reply.discarded") == 1
    assert wb.poll_once()["complete"] is True and _inbox_len(fake) == inbox_before


def test_the_two_file_removal_survives_a_failed_barrier_between_the_files(
    tmp_path, monkeypatch, capsys
):
    """R2, FAILURE AFTER: the canonical unlink is visible, its directory fsync failed:
    the aside (the evidence of the decision) is still there; the re-run repeats the
    barrier for the already-absent canonical and removes the aside after its own."""
    a, b, wa, wb, fake, clock, aside, held, msg_id = _with_a_canonical_too(tmp_path)
    real = mailmod.fsync_dir
    state = {"n": 0}

    def fsync_dir(d):
        if Path(d) == wb.pending_dir and state["n"] == 0:
            state["n"] += 1
            raise OSError(5, "Input/output error")
        real(d)

    monkeypatch.setattr(mailmod, "fsync_dir", fsync_dir)
    assert main([*_argv(b), "pending", "discard", aside.name, "--with-held"]) == 1
    capsys.readouterr()
    assert state["n"] == 1 and not held.exists() and aside.exists()
    events: list[tuple[str, str]] = []
    real_remove = Path.unlink

    def remove(self, missing_ok=False):
        if self.parent == wb.pending_dir:
            events.append(("unlink", self.name, self.exists()))
        return real_remove(self, missing_ok=missing_ok)

    def fsync_dir2(d):
        events.append(("fsync", Path(d).name))
        return real(d)

    monkeypatch.setattr(mailmod, "fsync_dir", fsync_dir2)
    monkeypatch.setattr(Path, "unlink", remove)
    assert main([*_argv(b), "pending", "discard", aside.name, "--with-held"]) == 0
    monkeypatch.undo()
    assert events == [
        ("unlink", held.name, False),  # already gone: a finished step, never an error
        ("fsync", wb.pending_dir.name),
        ("unlink", aside.name, True),
        ("fsync", wb.pending_dir.name),
    ]
    assert not aside.exists() and _actions(b).count("pending_reply.discarded") == 1
    inbox_before = _inbox_len(fake)
    assert wb.poll_once()["complete"] is True and _inbox_len(fake) == inbox_before


def test_a_quarantine_identity_is_never_reused_after_a_discard(tmp_path, capsys):
    a, b, wa, wb, fake, clock, aside, msg_id, reports = _quarantined(tmp_path)
    assert main([*_argv(b), "pending", "discard", aside.name]) == 0
    capsys.readouterr()
    assert wb._aside_replies() == []
    # the SAME clock second: a damaged file under the canonical name again
    held = wb.pending_dir / wb.held_name_of(aside)
    held.write_text("{")
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    (second,) = wb._aside_replies()
    assert second.name != aside.name and wb._unresolved(second)
    assert second.name.rsplit("-", 1)[0] == aside.name.rsplit("-", 1)[0]  # same name + stamp
    assert s["storage_failures"] == 1 and s["replies"] == 0 and _inbox_len(fake) == inbox_before
    # the old discard record is NOT taken for the new copy: listed corrupt, repairable
    assert main([*_argv(b), "pending", "list"]) == 0
    assert _row("corrupt", second.name) in capsys.readouterr().out
    assert _actions(b).count("pending_reply.corrupt") == 2
    assert main([*_argv(b), "pending", "repair"]) == 0
    assert "1 rebuilt" in capsys.readouterr().out
    assert _actions(b).count("pending_reply.reconstructed") == 1
    assert wb.poll_once()["replies"] == 1
    assert wa.poll_once()["applied"] == 1 and a.outbox()[-1]["status"] == "acked"


# ---- R1. an older unresolved aside plus a newer damaged canonical --------------------------


def test_an_older_aside_plus_a_newer_damaged_canonical_are_two_asides_and_nothing_is_sent(
    tmp_path,
):
    a, b, wa, wb, fake, clock, aside, held, msg_id = _with_a_canonical_too(tmp_path)
    held.write_bytes(b'{"kind": "ack", "object": {}}')  # the canonical reply damaged too
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    asides = wb._aside_replies()
    assert len(asides) == 2 and all(wb._unresolved(x) for x in asides)
    assert s["storage_failures"] == 2 and s["replies"] == 0 and s["complete"] is False
    assert not held.exists() and _inbox_len(fake) == inbox_before
    corrupt = [e for e in b.ledger.entries() if e["action"] == "pending_reply.corrupt"]
    assert len(corrupt) == 2 and len({e["detail"] for e in corrupt}) == 2
    assert "pending_reply.reconstructed" not in _actions(b)
    s = wb.poll_once()  # one count each, every poll, nothing sent
    assert s["storage_failures"] == 2 and s["replies"] == 0 and _inbox_len(fake) == inbox_before
    assert len(corrupt) == len(
        [e for e in b.ledger.entries() if e["action"] == "pending_reply.corrupt"]
    )
    # the operator: both rebuilt from the one stored ack (the second hold lands on the
    # same bytes), one held reply, sent once by the next poll
    assert main([*_argv(b), "pending", "repair"]) == 0
    asides = wb._aside_replies()
    assert len(asides) == 2 and all(not wb._unresolved(x) for x in asides)
    assert len(wb._pending_replies()) == 1
    assert _actions(b).count("pending_reply.reconstructed") == 2
    s = wb.poll_once()
    assert s["replies"] == 1 and s["complete"] is True and _inbox_len(fake) == inbox_before + 1
    assert wa.poll_once()["applied"] == 1 and a.outbox()[-1]["status"] == "acked"


# ---- the node's stored-reply validation (the source every path shares) ------------------------


def test_stored_reply_validates_like_a_held_reply(tmp_path):
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "one"))
    assert wb.poll_once()["replies"] == 1
    msg_id = a.outbox()[-1]["msg_id"]
    r, why = b.stored_reply(msg_id)
    assert why is None and r["kind"] == "ack" and r["object"] == seen_of(b)[msg_id]["ack"]
    assert b.reply_problem(r, msg_id, "ack") is None
    assert b.reply_problem(r, uid("msg"), "ack").startswith("in_reply_to")
    assert "ack" in b.reply_problem(r, msg_id, "card")
    assert b.stored_reply(uid("msg")) == (None, None)
    _damage_stored_ack(b, msg_id, "signature")
    r, why = b.stored_reply(msg_id)
    assert r is None and "ack.sig" in why
    with pytest.raises(IntegrityError) as e:
        b.receive(bundlemod.make("message", a.outbox()[-1]["bundle"]["object"], cards=[a.card]))
    assert e.value.reason == "seen.corrupt" and str(b.state / "seen.json") in str(e.value)


# ---- the self-gate's three findings (one round, fixed inside the family) ---------------------


@pytest.mark.parametrize("damage", ["agent-key", "name-binding"])
def test_repair_never_signs_for_a_key_from_a_card_that_does_not_verify(tmp_path, capsys, damage):
    """Finding 1: the completion source names the recipient by the actor's card ON FILE;
    a card whose agent key was damaged while its name survived must never become a
    validly signed ack to nobody. Every card read is verified and bound to its file
    name first; a damaged one is local corruption (card.corrupt), a storage failure."""
    a, b, wa, wb, fake, clock, aside, msg_id, reports = _quarantined(tmp_path)
    seen = seen_of(b)
    del seen[msg_id]  # no stored ack: the ledger completion is the only source
    (b.state / "seen.json").write_text(json.dumps(seen))
    (card_file,) = [
        f
        for f in (b.state / "cards").iterdir()
        if json.loads(f.read_text())["agent"]["name"] == "citadel-mayor"
    ]
    c = json.loads(card_file.read_text())
    if damage == "agent-key":
        k = c["agent"]["key"]
        c["agent"]["key"] = k[:-3] + ("AAA" if not k.endswith("AAA") else "BBB")
        card_file.write_text(json.dumps(c))
    else:  # a sound card under the wrong name
        card_file.rename(card_file.with_name("0" * 64 + ".json"))
    inbox_before = _inbox_len(fake)
    assert main([*_argv(b), "pending", "repair"]) == 1
    out = capsys.readouterr()
    assert "0 rebuilt" in out.out and "1 storage failure(s)" in out.out
    assert "card.corrupt" in out.err and str(b.state / "cards") in out.err
    assert wb._unresolved(aside) and wb._pending_replies() == []
    assert msg_id not in seen_of(b) and "pending_reply.reconstructed" not in _actions(b)
    s = wb.poll_once()
    assert s["replies"] == 0 and _inbox_len(fake) == inbox_before and s["complete"] is False


@pytest.mark.parametrize("when", ["before", "after"])
def test_an_unfinished_discard_of_a_reconstructed_copy_freezes_the_cursor(
    tmp_path, monkeypatch, capsys, when
):
    """Finding 2: a discard on record is counted for EVERY aside copy, the marked ones
    too — a `.reconstructed` copy whose --with-held removal died after the canonical
    went is still an unfinished decision on disk (`before`: the aside removal raised;
    `after`: it landed, then reported failure — nothing is left to count, and the
    verbs find a finished step). `pending repair` finishes it from the record (the
    record is checked before the suffix decides anything); it is never rebuilt."""
    a, b, wa, wb, fake, clock, aside, msg_id, reports = _quarantined(tmp_path)
    assert main([*_argv(b), "pending", "repair"]) == 0
    capsys.readouterr()
    (done,) = wb._aside_replies()
    held = wb.pending_dir / wb.held_name_of(done)
    assert not wb._unresolved(done) and held.exists()
    real_remove = Path.unlink

    def remove(self, missing_ok=False):
        if self == done:
            if when == "after":
                real_remove(self, missing_ok=missing_ok)
            raise OSError(5, "Input/output error")
        return real_remove(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", remove)
    assert main([*_argv(b), "pending", "discard", done.name, "--with-held"]) == 1
    capsys.readouterr()
    monkeypatch.undo()
    assert not held.exists() and done.exists() == (when == "before")
    (d,) = [e for e in b.ledger.entries() if e["action"] == "pending_reply.discarded"]
    assert MailWire.DROPS_HELD in d["detail"]
    clock.tick(5)
    cursor_before = wb.cursor()
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["replies"] == 0 and _inbox_len(fake) == inbox_before
    if when == "before":
        assert s["storage_failures"] == 1 and s["complete"] is False
        assert any("removal did not finish" in e and done.name in e for e in s["errors"])
        assert wb.cursor() == cursor_before and done.exists()
        assert main([*_argv(b), "pending", "list"]) == 0
        assert _row("discarded", done.name) in capsys.readouterr().out
    else:
        assert s["complete"] is True and wb.cursor() == clock()
    assert main([*_argv(b), "pending", "repair"]) == 0  # finished from the record, not resolved
    out = capsys.readouterr().out
    assert f"{int(when == 'before')} discard(s) finished" in out and "resolved" not in out
    assert not done.exists() and _actions(b).count("pending_reply.discarded") == 1
    assert _actions(b).count("pending_reply.reconstructed") == 1  # the earlier repair's
    assert main([*_argv(b), "pending", "discard", done.name]) == 0  # already on record
    assert _actions(b).count("pending_reply.discarded") == 1
    clock.tick(5)
    s = wb.poll_once()
    assert s["complete"] is True and wb.cursor() == clock() and _inbox_len(fake) == inbox_before


def test_a_visible_mark_whose_barrier_failed_is_re_established_by_the_verb(
    tmp_path, monkeypatch, capsys
):
    """Finding 3, FAILURE AFTER: the rename to .reconstructed landed, its directory
    fsync failed. The copy looks finished; the bulk run and the named run alike
    repeat the directory barrier (ORDERING: the fsync of pending-replies/ recorded)."""
    from .test_gate_round5 import _ino, _record_syncs

    a, b, wa, wb, fake, clock, aside, msg_id, reports = _quarantined(tmp_path)
    real = mailmod.fsync_dir
    state = {"n": 0}

    def fsync_dir(d):
        if Path(d) == wb.pending_dir and state["n"] == 0:
            state["n"] += 1
            raise OSError(5, "Input/output error")
        real(d)

    monkeypatch.setattr(mailmod, "fsync_dir", fsync_dir)
    assert main([*_argv(b), "pending", "repair"]) == 1
    out = capsys.readouterr()
    assert state["n"] == 1 and "0 rebuilt" in out.out and "1 storage failure(s)" in out.out
    monkeypatch.undo()
    done = aside.with_name(aside.name + ".reconstructed")
    assert done.exists() and not aside.exists()  # visible, its barrier never returned
    assert _actions(b).count("pending_reply.reconstructed") == 1
    for argv in ([*_argv(b), "pending", "repair"], [*_argv(b), "pending", "repair", done.name]):
        events = _record_syncs(monkeypatch)
        assert main(argv) == 0
        monkeypatch.undo()
        assert ("dir", _ino(wb.pending_dir)) in events
        assert "0 storage failure(s)" in capsys.readouterr().out
    assert _actions(b).count("pending_reply.reconstructed") == 1
    assert _actions(b).count("pending_reply.corrupt") == 1
    s = wb.poll_once()
    assert s["replies"] == 1 and s["complete"] is True

"""Gate round 12 (hw-axfqd): the eleventh cross-model gate report (2 MAJOR + 3 MINOR)
and the Fable read of round 11 (1 MINOR), one ruling each.

R1  A physical line that is empty or whitespace-only in a file of ours is corruption,
    never skipped: ledger.corrupt / feed.corrupt / denial.corrupt naming the path and
    the physical line, in every reader (the loaders, check_prefix, torn_tail,
    terminate_tail, the repair and verify verbs, the pin). The ONLY element any reader
    skips is the synthetic empty string after the final newline. A whitespace-only
    unterminated tail is corruption by the same name, never "an entry short of its
    newline" and never a torn tail to cut; a blank line in the prose mirror is a
    mirror mismatch by its name. Repair cuts no blank line; the operator restores.
R2  The ledger's full integrity check — chain, framing, every entry's shape, the prose
    mirror compared through the head, the repair guard — is the FIRST ledger read of
    every receive (`Ledger.check_intact` in `Node._receive`): before authorization
    counts uses, before a reservation is written, before the executor runs. A last
    completion edited (its chain link intact) or a mirror edited instead is a storage
    failure by name: the executor never called, no reservation, the mail unseen.
R3  At step "audited" a resumed repair validates the COMPLETE store and the ledger in
    full with the recorded audit entry (its id and hash; the last entry for the
    ledger's own intents) before the marker goes; a failure refuses by name with the
    marker and the file exactly as found.
R4  A reply carries no grants: reply_problem refuses a non-empty grants field
    (reply.grants_not_allowed), so check_reply, check_outgoing, MailWire.send,
    LocalWire.deliver and the CLI ack --out forms all refuse it (reply.invalid); every
    other kind's attached grants cross the shared document check at check_outgoing.
R5  A storage failure during the held-revocation replay at authorization is raised
    through — the mail unseen, nothing ledgered, nothing acked, re-evaluated after
    the feed is repaired; the revocation.replay_pending refusal is gone (every cause
    was a fault in a file of ours).
R6  A mirror repair whose own audit append tore the JSONL's tail is recoverable: a
    subordinate tail stage under the nested marker ledger-repair-pending.tail.json
    cuts (or terminates) that tail under the standing mirror intent's protection, with
    the same validate-before-mutate discipline and the same audit, then the mirror
    repair resumes to exactly one mirror audit; a torn tail that is not this ledger's
    is refused by name with both markers standing.
R7  Every torn-tail test for the feed and the denial store runs with and without the
    terminating newline (the round-11 test is parametrised); the README count is read
    from a real collection (the round-7 test pins it); the identity baseline is carried
    in the READY mail.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from natively.adapters.local import LocalWire
from natively.canon import hash_of, sha256_hex
from natively.cli import main
from natively.errors import IntegrityError, StorageError, VerifyError
from natively.ledger import entry_hash
from natively.node import LEDGER_TAIL_MARKER, REPLAY_MARKER, Node
from natively.objects import new_id

from .conftest import Clock, make_node, uid
from .test_gate_round6 import _connected_over_mail
from .test_gate_round7 import _argv
from .test_gate_round7b import _acks_out, _actions, _inbox_len
from .test_gate_round8 import _unseen_mail_ids
from .test_gate_round9 import _no_transport
from .test_gate_round10 import _tear_mirror, _with_history_over_mail
from .test_gate_round11 import (
    _break_chain,
    _damage_record,
    _pin_refuses,
    _revoked_grant_over_mail,
    _store_line,
    _write_marker,
)
from .test_hardening import STATEMENT, fs_write_scope, write_bundle

PKG = Path(__file__).resolve().parents[1] / "natively"
NEWLINE = pytest.mark.parametrize("terminated", [True, False], ids=["newline", "no-newline"])
BLANK = b" " * 8


def _serialize(e: dict) -> bytes:
    return json.dumps(e, ensure_ascii=False, separators=(",", ":")).encode()


def _storage_failure_poll(b, wb, fake, path: Path, reason: str, line: int, name: str) -> None:
    """One poll over a store with a blank physical line: a storage failure naming the
    file and the physical line, the mail unseen, nothing executed, nothing ledgered,
    never authorized, no reservation written."""
    # the files as bytes: the ledger itself may be the corrupt store here
    files = (b.ledger.path, b.ledger.prose_path, b.state / "seen.json")
    before = [f.read_bytes() if f.exists() else None for f in files]
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False and s["applied"] == 0
    assert any(reason in x and str(path) in x and f"line {line}" in x for x in s["errors"])
    assert len(_unseen_mail_ids(fake, b, wb)) == 1 and _inbox_len(fake) == inbox_before
    assert [f.read_bytes() if f.exists() else None for f in files] == before
    assert not (b.scratch_dir / name).exists()


def _blank_store(sound: bytes, where: str, terminated: bool) -> tuple[bytes, int]:
    """The store's bytes with a blank physical line, and that line's number: the
    signed record replaced with spaces, or a blank line after it."""
    if where == "record":
        return BLANK + (b"\n" if terminated else b""), 1
    return sound + BLANK + (b"\n" if terminated else b""), sound.count(b"\n") + 1


# ---- R1. a blank physical line is corruption in every reader (FAILURE BEFORE) ---------------


@NEWLINE
@pytest.mark.parametrize("where", ["record", "trailing"])
def test_a_stored_revocation_replaced_by_whitespace_is_corruption_never_skipped(
    tmp_path, capsys, where, terminated
):
    """R1, the feed: the signed revocation replaced with spaces (or a blank line
    after it), with and without the terminating newline. The action it forbids is
    a storage failure naming the feed and the physical line (feed.corrupt, never
    feed.torn, never a VerifyError), never authorized; the loader, torn_tail, the
    verify verb and the pin refuse by name; the repair verb refuses by name with
    the file untouched and no intent; restored, the retry is refused as revoked."""
    a, b, wa, wb, fake, clock, rec = _revoked_grant_over_mail(tmp_path)
    feed = b.revocations.path
    original = feed.read_bytes()
    blank, line = _blank_store(original, where, terminated)
    feed.write_bytes(blank)
    for read in (b.revocations.entries, b.revocations.torn_tail, b.revocations.load):
        with pytest.raises(IntegrityError) as e:
            read()
        assert e.value.reason == "feed.corrupt" and not isinstance(e.value, VerifyError)
        assert str(feed) in str(e.value) and f"line {line}" in str(e.value)
    with pytest.raises(IntegrityError) as e:
        b.revocations.check_prefix(len(blank))
    assert e.value.reason == "feed.corrupt" and f"line {line}" in str(e.value)
    _storage_failure_poll(b, wb, fake, feed, "feed.corrupt", line, "r.txt")
    assert main([*_argv(b), "feed", "verify"]) == 2
    err = capsys.readouterr().err
    assert "feed.corrupt" in err and str(feed) in err and f"line {line}" in err
    _pin_refuses(b, capsys, "feed.corrupt", feed)
    assert main([*_argv(b), "feed", "repair"]) == 2
    err = capsys.readouterr().err
    assert "feed.corrupt" in err and "feed.torn" not in err and f"line {line}" in err
    assert feed.read_bytes() == blank and not (b.state / "feed-repair-pending.json").exists()
    assert _actions(b).count("feed.repaired") == 0
    feed.write_bytes(original)
    assert main([*_argv(b), "feed", "verify"]) == 0
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["storage_failures"] == 0 and s["complete"] is True and s["replies"] == 1
    (ack,) = _acks_out(fake, inbox_before)
    assert ack["outcome"] == "refused:no_authorizing_grant"
    assert "grant.revoked" in b.ledger.entries()[-1]["detail"]
    assert not (b.scratch_dir / "r.txt").exists() and _unseen_mail_ids(fake, b, wb) == set()


def _denied_write_over_mail(tmp_path):
    """b with standing denials on; b's own denial of every fs.write on file (one
    record); a grant from a for a write; the write in b's inbox, unread."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    b.config["extensions"]["standing_denial"] = True
    b.save_config()
    d = b.deny(deny=[{"action": "fs.write", "resource": "*"}], principal_statement="never")
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "d.txt"), principal_statement=STATEMENT
    )
    wa.send(write_bundle(a, b, g, "d.txt"))
    (rec,) = b.denials.entries()
    assert rec["denial_id"] == d["denial_id"]
    return a, b, wa, wb, fake, clock, rec


@NEWLINE
@pytest.mark.parametrize("where", ["record", "trailing"])
def test_a_stored_denial_replaced_by_whitespace_is_corruption_never_skipped(
    tmp_path, capsys, where, terminated
):
    """R1, the denial store: the same shape — denial.corrupt naming the store and
    the physical line at every reader and verb, never authorized, the file
    untouched by repair; restored, the retry is refused as denied."""
    a, b, wa, wb, fake, clock, rec = _denied_write_over_mail(tmp_path)
    store = b.denials.path
    original = store.read_bytes()
    blank, line = _blank_store(original, where, terminated)
    store.write_bytes(blank)
    for read in (b.denials.entries, b.denials.torn_tail, b.denials.load):
        with pytest.raises(IntegrityError) as e:
            read()
        assert e.value.reason == "denial.corrupt" and not isinstance(e.value, VerifyError)
        assert str(store) in str(e.value) and f"line {line}" in str(e.value)
    with pytest.raises(IntegrityError) as e:
        b.denials.check_prefix(len(blank))
    assert e.value.reason == "denial.corrupt" and f"line {line}" in str(e.value)
    _storage_failure_poll(b, wb, fake, store, "denial.corrupt", line, "d.txt")
    assert main([*_argv(b), "denial", "verify"]) == 2
    err = capsys.readouterr().err
    assert "denial.corrupt" in err and str(store) in err and f"line {line}" in err
    _pin_refuses(b, capsys, "denial.corrupt", store)
    assert main([*_argv(b), "denial", "repair"]) == 2
    err = capsys.readouterr().err
    assert "denial.corrupt" in err and "denial.torn" not in err and f"line {line}" in err
    assert store.read_bytes() == blank and not (b.state / "denial-repair-pending.json").exists()
    assert _actions(b).count("denial.repaired") == 0
    store.write_bytes(original)
    assert main([*_argv(b), "denial", "verify"]) == 0
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["storage_failures"] == 0 and s["complete"] is True and s["replies"] == 1
    (ack,) = _acks_out(fake, inbox_before)
    assert ack["outcome"] == "refused:denied"
    assert not (b.scratch_dir / "d.txt").exists() and _unseen_mail_ids(fake, b, wb) == set()


def _one_use_applied_over_mail(tmp_path, max_uses: int = 1):
    """a and b connected; a's grant to b of `max_uses` writes applied once (b's
    last ledger entry is that applied completion); a second write under it in b's
    inbox, unread; a counter on b's executor."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    g = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "u.txt"),
        principal_statement=STATEMENT,
        max_uses=max_uses,
    )
    wa.send(write_bundle(a, b, g, "u.txt"))
    s = wb.poll_once()
    assert s["applied"] == 1 and s["replies"] == 1 and wa.poll_once()["applied"] == 1
    assert b.ledger.entries()[-1]["outcome"] == "applied"
    assert (b.scratch_dir / "u.txt").read_text() == "x\n"
    wa.send(write_bundle(a, b, g, "u.txt", "again\n"))
    calls = _count_executions(b)
    return a, b, wa, wb, fake, clock, g, calls


def _count_executions(node) -> dict[str, int]:
    """Every executor `node` builds counts its apply calls here."""
    real = node.executor
    box = {"calls": 0}

    def executor():
        ex = real()
        apply = ex.apply

        def counted(*args, **kw):
            box["calls"] += 1
            return apply(*args, **kw)

        ex.apply = counted
        return ex

    node.executor = executor
    return box


@NEWLINE
@pytest.mark.parametrize("where", ["record", "trailing"])
def test_a_ledger_completion_replaced_by_whitespace_is_corruption_never_a_free_use(
    tmp_path, capsys, where, terminated
):
    """R1, the ledger: the applied completion of a one-use grant replaced with
    spaces, with and without its newline. Every reader is ledger.corrupt naming the
    path and the physical line (never ledger.truncated, never "an entry short of
    its newline"): the second use is a storage failure — the executor never called,
    no reservation, the mail unseen; verify exits 2 by name; repair refuses by name
    with both files untouched, no intent, nothing terminated; restored, the retry
    is refused as used up."""
    a, b, wa, wb, fake, clock, g, calls = _one_use_applied_over_mail(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    whole, prose = jsonl.read_bytes(), mirror.read_bytes()
    lines = whole.split(b"\n")[:-1]
    if where == "record":
        line = len(lines)
        blank = b"\n".join([*lines[:-1], BLANK]) + (b"\n" if terminated else b"")
    else:  # a blank line after the completion: the whole file refused all the same
        line = len(lines) + 1
        blank = whole + BLANK + (b"\n" if terminated else b"")
    jsonl.write_bytes(blank)
    readers = [
        b.ledger.entries,
        b.ledger.check_intact,
        b.ledger.verify,
        b.ledger.torn_tail,
        lambda: b.ledger.check_prefix(len(blank)),
    ]
    if not terminated:
        readers.append(b.ledger.terminate_tail)  # never "an entry short of its newline"
    for read in readers:
        with pytest.raises(IntegrityError) as e:
            read()
        assert e.value.reason == "ledger.corrupt" and not isinstance(e.value, VerifyError)
        assert str(jsonl) in str(e.value) and f"line {line}" in str(e.value)
    if terminated:
        assert b.ledger.terminate_tail() is False  # nothing unterminated: nothing to do
    assert jsonl.read_bytes() == blank  # terminate_tail wrote nothing
    _storage_failure_poll(b, wb, fake, jsonl, "ledger.corrupt", line, "never.txt")
    assert calls["calls"] == 0 and (b.scratch_dir / "u.txt").read_text() == "x\n"
    assert jsonl.read_bytes() == blank and mirror.read_bytes() == prose
    if where == "trailing" and not terminated:
        # the receive's storage failure is the loader's own (the whitespace tail),
        # not ledger.truncated: never "an entry short of its newline"
        assert not any("ledger.truncated" in x for x in wb.poll_once()["errors"])
    assert main([*_argv(b), "ledger", "verify"]) == 2
    err = capsys.readouterr().err
    assert "ledger.corrupt" in err and str(jsonl) in err and f"line {line}" in err
    _pin_refuses(b, capsys, "ledger.corrupt", jsonl)  # the pin ledgers: refused by name
    assert main([*_argv(b), "ledger", "repair"]) == 2
    err = capsys.readouterr().err
    assert "ledger.corrupt" in err and "ledger.truncated" not in err and "terminated" not in err
    assert jsonl.read_bytes() == blank and mirror.read_bytes() == prose
    assert not (b.state / "ledger-repair-pending.json").exists()
    jsonl.write_bytes(whole)
    assert main([*_argv(b), "ledger", "verify"]) == 0
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["storage_failures"] == 0 and s["complete"] is True and s["replies"] == 1
    (ack,) = _acks_out(fake, inbox_before)
    assert ack["outcome"] == "refused:no_authorizing_grant"
    assert "grant.max_uses" in b.ledger.entries()[-1]["detail"]
    assert calls["calls"] == 0 and (b.scratch_dir / "u.txt").read_text() == "x\n"


def test_a_blank_line_in_the_prose_mirror_is_a_mismatch_by_name(tmp_path, capsys):
    """R1, the mirror: the last prose line replaced with spaces (with its newline,
    and without it: the unterminated replacement) is
    ledger.prose.mismatch at the receive (a storage failure, the mail unseen) and at
    verify; a blank line APPENDED (terminated, or a whitespace-only unterminated
    tail) is more prose than entries, the same names at the receive and at verify;
    in every case repair refuses (ledger.repair.refused: a blank line is never
    removable excess) with the mirror untouched and no intent; restored, the retry
    applies."""
    a, b, wa, wb, fake, clock = _with_history_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "hello"))
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    whole, prose = jsonl.read_bytes(), mirror.read_bytes()
    lines = prose.split(b"\n")[:-1]
    for damaged in (
        b"\n".join([*lines[:-1], BLANK]) + b"\n",  # the last line blank
        b"\n".join([*lines[:-1], BLANK]),  # the last line blank, its newline gone too
        prose + BLANK + b"\n",  # a blank line beyond the entries
        prose + BLANK,  # a whitespace-only unterminated tail beyond the entries
        prose + b"\n",  # an empty line beyond the entries
    ):
        mirror.write_bytes(damaged)
        with pytest.raises(IntegrityError) as e:
            b.ledger.check_intact()
        assert e.value.reason == "ledger.prose.mismatch" and str(mirror) in str(e.value)
        s = wb.poll_once()
        assert s["storage_failures"] == 1 and s["complete"] is False and s["applied"] == 0
        assert any("ledger.prose.mismatch" in x and str(mirror) in x for x in s["errors"])
        assert len(_unseen_mail_ids(fake, b, wb)) == 1
        assert jsonl.read_bytes() == whole and mirror.read_bytes() == damaged
        assert main([*_argv(b), "ledger", "verify"]) == 2
        assert "ledger.prose." in capsys.readouterr().err
        assert main([*_argv(b), "ledger", "repair"]) == 2
        err = capsys.readouterr().err
        assert "ledger.repair.refused" in err and str(mirror) in err
        assert mirror.read_bytes() == damaged and jsonl.read_bytes() == whole
        assert not (b.state / "ledger-repair-pending.json").exists()
        assert _actions(b).count("ledger.mirror_truncated") == 0
        mirror.write_bytes(prose)
    s = wb.poll_once()
    assert s["applied"] == 1 and s["replies"] == 1 and s["complete"] is True


def test_only_the_synthetic_element_after_the_final_newline_is_skipped():
    """R1: the one shared line reader passes over exactly the artefact of splitting
    a terminated file, and nothing else — an empty file, a terminated file, an
    unterminated file; a blank line anywhere, a whitespace-only unterminated tail
    and a doubled newline are corruption naming the physical line."""
    from natively.durable import physical_lines

    p = Path("/x/store.jsonl")
    assert list(physical_lines(b"", p, "r")) == []
    assert list(physical_lines(b"{}\n", p, "r")) == [(1, b"{}")]
    assert list(physical_lines(b"{}\n{}", p, "r")) == [(1, b"{}"), (2, b"{}")]
    for data, line in ((b"{}\n\n", 2), (b"\n{}\n", 1), (b"{}\n \n{}\n", 2), (b"{}\n  ", 2)):
        with pytest.raises(IntegrityError) as e:
            list(physical_lines(data, p, "store.corrupt"))
        assert e.value.reason == "store.corrupt" and f"{p} line {line}" in str(e.value)


# ---- R2. the ledger and its mirror verified before use accounting and execution (ORDERING) ---


def _edit_last_completion(b, edit: str) -> None:
    """The last completion's outcome turned from applied to failed in the JSONL
    (its incoming chain link intact: the loader still passes) with the mirror
    unchanged — or the mirror's line edited instead, the JSONL unchanged."""
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    if edit == "jsonl":
        lines = jsonl.read_bytes().split(b"\n")[:-1]
        e = json.loads(lines[-1])
        assert e["outcome"] == "applied"
        e["outcome"] = "failed"
        jsonl.write_bytes(b"\n".join([*lines[:-1], _serialize(e)]) + b"\n")
        b.ledger.entries()  # the loader passes: the chain link into the entry holds
    else:
        lines = mirror.read_bytes().split(b"\n")[:-1]
        assert b" -> applied" in lines[-1]
        lines[-1] = lines[-1].replace(b" -> applied", b" -> failed", 1)
        mirror.write_bytes(b"\n".join(lines) + b"\n")


@pytest.mark.parametrize("uses", ["one-use", "uses-left"])
@pytest.mark.parametrize("edit", ["jsonl", "mirror"])
def test_a_tampered_last_completion_is_a_storage_failure_before_any_execution(
    tmp_path, capsys, edit, uses
):
    """R2: the last completion's outcome edited from applied to failed with the
    mirror unchanged (or the mirror edited instead): the loader alone still passes
    and would count zero uses, but the full check is the first ledger read of the
    receive — a storage failure by name (ledger.prose.mismatch), the executor never
    called, no reservation on disk, the mail unseen, nothing ledgered; the file
    restored, the retry is refused as used up (one-use) or applies exactly once
    (uses left)."""
    max_uses = 1 if uses == "one-use" else 2
    a, b, wa, wb, fake, clock, g, calls = _one_use_applied_over_mail(tmp_path, max_uses)
    msg_id = a.outbox()[-1]["msg_id"]
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    whole, prose = jsonl.read_bytes(), mirror.read_bytes()
    _edit_last_completion(b, edit)
    tampered = (jsonl.read_bytes(), mirror.read_bytes())
    assert b.ledger.uses(g["grant_id"]) == (0 if edit == "jsonl" else 1)  # the loader alone
    with pytest.raises(IntegrityError) as e:
        b.ledger.check_intact()
    assert e.value.reason == "ledger.prose.mismatch" and str(mirror) in str(e.value)
    entries_before, inbox_before = len(b.ledger.entries()), _inbox_len(fake)
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False and s["applied"] == 0
    assert any("ledger.prose.mismatch" in x and str(mirror) in x for x in s["errors"])
    assert calls["calls"] == 0 and (b.scratch_dir / "u.txt").read_text() == "x\n"
    assert msg_id not in b._seen()  # no reservation, no ack
    assert len(_unseen_mail_ids(fake, b, wb)) == 1 and _inbox_len(fake) == inbox_before
    assert (jsonl.read_bytes(), mirror.read_bytes()) == tampered
    assert len(b.ledger.entries()) == entries_before
    assert main([*_argv(b), "ledger", "verify"]) == 2
    assert "ledger.prose.mismatch" in capsys.readouterr().err
    jsonl.write_bytes(whole)
    mirror.write_bytes(prose)
    assert main([*_argv(b), "ledger", "verify"]) == 0
    s = wb.poll_once()
    assert s["storage_failures"] == 0 and s["complete"] is True and s["replies"] == 1
    (ack,) = _acks_out(fake, inbox_before)
    if uses == "one-use":
        assert ack["outcome"] == "refused:no_authorizing_grant"
        assert "grant.max_uses" in b.ledger.entries()[-1]["detail"]
        assert calls["calls"] == 0 and (b.scratch_dir / "u.txt").read_text() == "x\n"
    else:
        assert ack["outcome"] == "applied"
        assert calls["calls"] == 1 and (b.scratch_dir / "u.txt").read_text() == "again\n"
        assert [e["msg_id"] for e in b.ledger.entries()].count(msg_id) == 1
    assert b.ledger.uses(g["grant_id"]) == max_uses
    assert _unseen_mail_ids(fake, b, wb) == set()


def test_the_full_check_is_the_first_ledger_read_of_every_receive(tmp_path, monkeypatch):
    """R2, the ordering itself: on a receive of every kind, `check_intact` runs
    before any other ledger read (find_msg, uses, head, entries) and before the
    reservation write; a check that fails stops the receive inside the storage
    boundary."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "o.txt"), principal_statement=STATEMENT
    )
    order: list[str] = []
    ledger = b.ledger
    for name in ("check_intact", "entries", "find_msg", "uses", "head"):
        real = getattr(ledger, name)

        def logged(*args, _real=real, _name=name, **kw):
            order.append(_name)
            return _real(*args, **kw)

        monkeypatch.setattr(ledger, name, logged)
    real_reserve = b._reserve

    def reserve(*args, **kw):
        order.append("reserve")
        return real_reserve(*args, **kw)

    monkeypatch.setattr(b, "_reserve", reserve)
    for bundle in (
        write_bundle(a, b, g, "o.txt"),
        a.compose_info(b.card, "hi"),
        a.compose_card(),
        a.compose_revocation(a.revoke(grants=[uid("grt")], principal_statement="x")),
    ):
        order.clear()
        b.receive(bundle)
        assert order and order[0] == "check_intact", (bundle["kind"], order)
        if bundle["kind"] == "message" and bundle["object"].get("grant_ids"):
            assert order.index("check_intact") < order.index("uses") < order.index("reserve")

    def failing():
        raise IntegrityError("ledger.chain", "injected")

    monkeypatch.setattr(ledger, "check_intact", failing)
    n = len(b.ledger.entries())
    with pytest.raises(IntegrityError) as e:
        b.receive(a.compose_info(b.card, "again"))
    assert e.value.reason == "ledger.chain" and len(b.ledger.entries()) == n


# ---- R3. the audited step validates the complete store and the recorded audit --------------
#      (RESTART RECOVERY)


def _repaired_store(tmp_path, store: str):
    """A node whose `store` had a torn tail and was repaired by its verb to
    completion: the audit entry is the ledger's last entry, no marker stands.
    Returns (node, the store's path, the verb, the audit action, the audit entry,
    the intent record rebuilt at step "audited")."""
    n = make_node(tmp_path, "n", Clock(), extensions={"standing_denial": True})
    if store == "feed":
        n.revoke(grants=[uid("grt")], principal_statement="ok")
        path, verb, action, fname = n.revocations.path, "feed", "feed.repaired", "revocations.jsonl"
    elif store == "denial":
        n.deny(deny=[{"action": "info", "resource": "*"}], principal_statement="no")
        path, verb, action, fname = n.denials.path, "denial", "denial.repaired", "denials.jsonl"
    else:
        n.revoke(grants=[uid("grt")], principal_statement="ok")
        path, verb, action, fname = n.ledger.path, "ledger", "ledger.tail_truncated", "ledger.jsonl"
    sound = path.read_bytes()
    torn = sound[:40] if store != "ledger" else b'{"ts": "2026-09-07T07:00:00Z", "actor": "'
    path.write_bytes(sound + torn)
    assert main([*_argv(n), verb, "repair"]) == 0
    audit = n.ledger.entries()[-1]
    assert audit["action"] == action and _actions(n).count(action) == 1
    intent_id = audit["detail"].split("intent ")[-1].strip()
    intent = {
        "step": "audited",
        "file": fname,
        "truncate_to": len(sound),
        "bytes": len(torn),
        "tail_sha256": audit["params_hash"],
        "intent_id": intent_id,
        "ts": n.ts(),
        "audit_hash": entry_hash(audit),
    }
    assert intent["tail_sha256"] == "sha256:" + sha256_hex(torn)
    return n, path, verb, action, audit, intent


@NEWLINE
@pytest.mark.parametrize("store", ["feed", "denial", "ledger"])
def test_an_audited_repair_with_a_torn_audit_suffix_keeps_its_marker(
    tmp_path, capsys, store, terminated
):
    """R3: the marker at step "audited"; the ledger's audit line torn (the store's
    own bytes sound: the prefix check passes) — without its newline
    (ledger.truncated) and, round 13, with it (ledger.corrupt: a line that does not
    parse and ends in its newline is corruption). The resume exits 2 by name with
    the marker present and every file byte-identical; the ledger restored, the
    resume completes, the marker goes, no second audit."""
    n, path, verb, action, audit, intent = _repaired_store(tmp_path, store)
    jsonl, mirror = n.ledger.path, n.ledger.prose_path
    whole, prose = jsonl.read_bytes(), mirror.read_bytes()
    marker = n.state / f"{verb}-repair-pending.json"
    marker.write_text(json.dumps(intent), encoding="utf-8")
    jsonl.write_bytes(whole[:-10] + (b"\n" if terminated else b""))  # the audit line torn
    mirror.write_bytes(b"".join(prose.splitlines(keepends=True)[:-1]))  # its prose never landed
    before = (path.read_bytes(), jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes())
    assert main([*_argv(n), verb, "repair"]) == 2
    err = capsys.readouterr().err
    assert ("ledger.corrupt" if terminated else "ledger.truncated") in err and str(jsonl) in err
    assert (
        path.read_bytes(),
        jsonl.read_bytes(),
        mirror.read_bytes(),
        marker.read_bytes(),
    ) == before
    assert json.loads(marker.read_text())["step"] == "audited"
    jsonl.write_bytes(whole)
    mirror.write_bytes(prose)
    assert main([*_argv(n), verb, "repair"]) == 0
    assert not marker.exists() and _actions(n).count(action) == 1
    assert n.ledger.entries()[-1] == audit
    assert main([*_argv(n), "ledger", "verify"]) == 0


@NEWLINE
@pytest.mark.parametrize("store", ["feed", "denial"])
def test_an_audited_repair_over_a_store_torn_past_its_cut_point_keeps_its_marker(
    tmp_path, capsys, store, terminated
):
    """R3, the store itself: at step "audited" the feed (the denial store) has a
    line past the cut point — without its newline and with it. Since round 21 the
    resume validates the PERMITTED SUFFIX for the step before anything else: after
    the cut ran nothing of ours writes to the store while the marker stands, so
    any bytes past the cut point are <store>.repair.refused by name (round-20
    gate, finding 2), exit 2, the marker present, the file identical; the bytes
    removed by hand, the resume completes and the marker goes. (Before round 21
    the prefix check passed and the WHOLE-store check refused as <store>.torn /
    <store>.corrupt; the refusal moved earlier and took the resume's name.)"""
    n, path, verb, action, audit, intent = _repaired_store(tmp_path, store)
    sound = path.read_bytes()
    marker = n.state / f"{verb}-repair-pending.json"
    marker.write_text(json.dumps(intent), encoding="utf-8")
    path.write_bytes(sound + b'{"torn": ' + (b"\n" if terminated else b""))
    before = (path.read_bytes(), marker.read_bytes())
    assert main([*_argv(n), verb, "repair"]) == 2
    err = capsys.readouterr().err
    assert f"{store}.repair.refused" in err and str(path) in err and "past the intent" in err
    assert (path.read_bytes(), marker.read_bytes()) == before
    path.write_bytes(sound)
    assert main([*_argv(n), verb, "repair"]) == 0
    assert not marker.exists() and _actions(n).count(action) == 1


@pytest.mark.parametrize("store", ["feed", "denial", "ledger"])
def test_an_audited_repair_whose_audit_is_missing_or_not_last_keeps_its_marker(
    tmp_path, capsys, store
):
    """R3: at step "audited" the ledger holds no audit entry for the intent (the
    ledger restored from before it), or — for the ledger's own intent, whose marker
    admits no other append — the audit is not the last entry, or its hash is not the
    recorded one: <store>.repair.intent_mismatch, the marker present."""
    n, path, verb, action, audit, intent = _repaired_store(tmp_path, store)
    jsonl, mirror = n.ledger.path, n.ledger.prose_path
    whole, prose = jsonl.read_bytes(), mirror.read_bytes()
    marker = n.state / f"{verb}-repair-pending.json"
    marker.write_text(json.dumps(intent), encoding="utf-8")
    # the audit gone (the ledger from before it, its prose line too)
    jsonl.write_bytes(b"".join(whole.splitlines(keepends=True)[:-1]))
    mirror.write_bytes(b"".join(prose.splitlines(keepends=True)[:-1]))
    assert main([*_argv(n), verb, "repair"]) == 2
    err = capsys.readouterr().err
    assert f"{verb}.repair.intent_mismatch" in err and "no " + action in err
    assert marker.exists()
    jsonl.write_bytes(whole)
    mirror.write_bytes(prose)
    # the recorded hash is not the audit's
    marker.write_text(json.dumps({**intent, "audit_hash": "sha256:" + "0" * 64}))
    assert main([*_argv(n), verb, "repair"]) == 2
    assert f"{verb}.repair.intent_mismatch" in capsys.readouterr().err and marker.exists()
    marker.write_text(json.dumps(intent), encoding="utf-8")
    if store == "ledger":
        # an entry after the audit while the marker stands: not this machine's
        n._repair_active = "ledger"
        n.ledger.append(
            ts=n.ts(), actor="x", grant_id=None, action="s", params_hash=None, outcome="information"
        )
        n._repair_active = None
        assert main([*_argv(n), verb, "repair"]) == 2
        assert "not the ledger's last entry" in capsys.readouterr().err and marker.exists()
        jsonl.write_bytes(whole)
        mirror.write_bytes(prose)
    assert main([*_argv(n), verb, "repair"]) == 0
    assert not marker.exists() and _actions(n).count(action) == 1


@NEWLINE
@pytest.mark.parametrize("store", ["feed", "denial"])
def test_a_repair_arriving_at_audited_in_one_run_validates_the_whole_store_first(
    tmp_path, capsys, store, terminated
):
    """R3, the same-run path: the marker at step "truncated" (the cut landed, the
    audit not yet) and the store torn past its cut point. Since round 21 the
    resume refuses BEFORE the audit — <store>.repair.refused by name, nothing
    appended, the marker still at "truncated" with no audit hash, the file
    untouched (round-20 gate, finding 2: before, the audit was appended and the
    marker advanced to "audited" first, and only the whole-store check refused, so
    a restart saw an audit claiming a completed truncation over a store still
    corrupt); the bytes removed by hand, the resume finishes with exactly one
    audit of this intent."""
    n, path, verb, action, audit, intent = _repaired_store(tmp_path, store)
    sound = path.read_bytes()
    marker = n.state / f"{verb}-repair-pending.json"
    # the machine's own audit is on the ledger already; this intent is a NEW one
    intent = {**intent, "step": "truncated", "intent_id": new_id("rpr")}
    intent.pop("audit_hash")
    marker.write_text(json.dumps(intent), encoding="utf-8")
    path.write_bytes(sound + b'{"torn": ' + (b"\n" if terminated else b""))
    torn = path.read_bytes()
    before_marker = marker.read_bytes()
    assert main([*_argv(n), verb, "repair"]) == 2
    err = capsys.readouterr().err
    assert f"{store}.repair.refused" in err and str(path) in err and "past the intent" in err
    assert path.read_bytes() == torn and _actions(n).count(action) == 1
    assert marker.read_bytes() == before_marker
    assert json.loads(marker.read_text())["step"] == "truncated"
    path.write_bytes(sound)
    assert main([*_argv(n), verb, "repair"]) == 0
    assert not marker.exists() and _actions(n).count(action) == 2
    assert f"intent {intent['intent_id']}" in n.ledger.entries()[-1]["detail"]


# ---- the self-gate's in-family findings, fixed in-family ------------------------------------


@NEWLINE
@pytest.mark.parametrize("store", ["feed", "denial", "ledger"])
def test_a_leading_blank_line_before_a_torn_tail_is_refused_before_any_cut(
    tmp_path, capsys, store, terminated
):
    """Self-gate 2 (R1): a file that is one blank physical line and then a torn
    partial tail (b"\\n{"), and one blank line then a whole ledger entry short of its
    newline: the tail split keeps the separator, so line 1 is refused by name
    (<store>.corrupt line 1) by torn_tail, terminate_tail and the repair verb —
    nothing cut, nothing terminated, no intent, no audit. With the terminating
    newline (round 13) the same line 1 is the store's corrupt reason at every
    reader and repair refuses the same way; terminate_tail has nothing to do."""
    n = make_node(tmp_path, "n", Clock(), extensions={"standing_denial": True})
    if store == "feed":
        n.revoke(grants=[uid("grt")], principal_statement="ok")
        obj, path = n.revocations, n.revocations.path
    elif store == "denial":
        n.deny(deny=[{"action": "info", "resource": "*"}], principal_statement="no")
        obj, path = n.denials, n.denials.path
    else:
        n.revoke(grants=[uid("grt")], principal_statement="ok")
        obj, path = n.ledger, n.ledger.path
    sound = path.read_bytes()
    marker = n.state / f"{store}-repair-pending.json"
    end = b"\n" if terminated else b""
    variants = [b"\n{" + end, b"  \n{" + end]
    if store == "ledger":
        variants.append(b"\n" + sound.rstrip(b"\n") + end)  # a whole entry after a blank line
    for data in variants:
        path.write_bytes(data)
        readers = [obj.torn_tail]
        if store == "ledger" and not terminated:
            readers.append(obj.terminate_tail)
        for read in readers:
            with pytest.raises(IntegrityError) as e:
                read()
            assert e.value.reason == f"{store}.corrupt" and "line 1" in str(e.value)
        if store == "ledger" and terminated:
            assert obj.terminate_tail() is False  # nothing unterminated: nothing written
        assert path.read_bytes() == data
        assert main([*_argv(n), store, "repair"]) == 2
        err = capsys.readouterr().err
        assert f"{store}.corrupt" in err and "line 1" in err
        assert path.read_bytes() == data and not marker.exists()
    path.write_bytes(sound)
    assert (
        _actions(n).count(f"{store}.repaired" if store != "ledger" else "ledger.tail_truncated")
        == 0
    )


@pytest.mark.parametrize("hash_value", ["absent", "null", "not-a-hash"])
@pytest.mark.parametrize("store", ["feed", "denial", "ledger"])
def test_an_audited_marker_without_its_audit_hash_is_refused(tmp_path, capsys, store, hash_value):
    """Self-gate 3 (R3): an audited marker whose audit_hash is absent, null or not a
    hash is refused by the typed intent loader (<store>.repair.intent_corrupt): the
    marker and every file untouched, nothing removed; every writer of that store
    refuses while it stands."""
    n, path, verb, action, audit, intent = _repaired_store(tmp_path, store)
    if hash_value == "absent":
        intent.pop("audit_hash")
    elif hash_value == "null":
        intent["audit_hash"] = None
    else:
        intent["audit_hash"] = "sha256:short"
    marker = n.state / f"{verb}-repair-pending.json"
    marker.write_text(json.dumps(intent), encoding="utf-8")
    before = (path.read_bytes(), n.ledger.path.read_bytes(), marker.read_bytes())
    assert main([*_argv(n), verb, "repair"]) == 2
    err = capsys.readouterr().err
    assert f"{verb}.repair.intent_corrupt" in err and str(marker) in err
    assert (path.read_bytes(), n.ledger.path.read_bytes(), marker.read_bytes()) == before
    with pytest.raises(IntegrityError) as e:  # every writer of that store refuses by name
        if store == "denial":
            n.deny(deny=[{"action": "info", "resource": "*"}], principal_statement="blocked")
        else:
            n.revoke(grants=[uid("grt")], principal_statement="blocked")
    assert e.value.reason == f"{verb}.repair.intent_corrupt"
    marker.write_text(json.dumps({**intent, "audit_hash": entry_hash(audit)}), encoding="utf-8")
    assert main([*_argv(n), verb, "repair"]) == 0
    assert not marker.exists() and _actions(n).count(action) == 1


def _tail_stage_after_its_audit(tmp_path, nested: bool):
    """A JSONL-tail stage whose cut landed and whose audit append ran to the end:
    the tail audit is the last entry, its prose line the mirror's last, the marker
    (nested under a standing mirror intent at "truncated", or the ledger's own) at
    step "truncated" as a crash inside that append would leave it. Returns
    (b, the tail intent, its marker, the mirror intent's marker or None)."""
    if nested:
        a, b, wa, wb, fake, clock, mirror_intent, mirror_marker = _mirror_repair_at_truncated(
            tmp_path
        )
        _torn_audit(b, mirror_intent, "inside")
    else:
        a, b, wa, wb, fake, clock = _with_history_over_mail(tmp_path)
        mirror_marker = None
        with open(b.ledger.path, "ab") as f:
            f.write(b'{"ts": "2026-09-07T07:00:00Z", "actor": "')
    jsonl = b.ledger.path
    torn = b.ledger.torn_tail()
    assert torn
    cut_to = jsonl.stat().st_size - len(torn)
    jsonl.write_bytes(jsonl.read_bytes()[:cut_to])
    intent = {
        "step": "truncated",
        "file": "ledger.jsonl",
        "truncate_to": cut_to,
        "bytes": len(torn),
        "tail_sha256": "sha256:" + sha256_hex(torn),
        "intent_id": new_id("rpr"),
        "ts": b.ts(),
    }
    b._repair_active = "ledger"  # the machine's own audit append
    b.ledger.append(
        ts=b.ts(),
        actor="solo",
        grant_id=None,
        action="ledger.tail_truncated",
        params_hash=intent["tail_sha256"],
        outcome="recorded",
        detail=f"truncated a torn partial last line — again; intent {intent['intent_id']}",
        intent_id=intent["intent_id"],
    )
    b._repair_active = None
    marker = b.state / (LEDGER_TAIL_MARKER if nested else "ledger-repair-pending.json")
    marker.write_text(json.dumps(intent), encoding="utf-8")
    return b, intent, marker, mirror_marker


@pytest.mark.parametrize(
    "tear", ["jsonl-torn", "jsonl-unterminated", "prose-torn", "prose-ascii-torn"]
)
@pytest.mark.parametrize("nested", [False, True], ids=["own-marker", "nested"])
def test_a_tail_stage_recovers_a_tear_inside_its_own_audit_append(tmp_path, capsys, nested, tear):
    """Self-gate 4 (R6): the tail stage's own audit append interrupted — the audit
    line torn, the audit entry whole short of only its newline, the audit's prose
    line torn inside a multibyte character or (round 13, S5) after an ASCII prefix
    — under the ledger's own marker and under the nested marker beneath a standing
    mirror intent. The resume mends its own tear (cut again, terminated, the
    mirror cut back to its sound lines, or the prose line regenerated) and
    finishes: exactly one tail audit, one mirror audit when nested, every marker
    gone, verify exit 0."""
    b, intent, marker, mirror_marker = _tail_stage_after_its_audit(tmp_path, nested)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    whole, prose = jsonl.read_bytes(), mirror.read_bytes()
    if tear == "jsonl-torn":
        jsonl.write_bytes(whole[:-25])
        mirror.write_bytes(b"".join(prose.splitlines(keepends=True)[:-1]))
    elif tear == "jsonl-unterminated":
        jsonl.write_bytes(whole[:-1])
        mirror.write_bytes(b"".join(prose.splitlines(keepends=True)[:-1]))
    elif tear == "prose-ascii-torn":
        lines = prose.splitlines(keepends=True)
        mirror.write_bytes(b"".join(lines[:-1]) + lines[-1][:20])  # the timestamp, no newline
    else:
        _tear_mirror(mirror, "tail")
    with pytest.raises(IntegrityError) as e:
        b.receive(b.compose_card())  # nothing appends while a marker stands
    assert e.value.reason == "ledger.repair_pending"
    assert main([*_argv(b), "ledger", "repair"]) == 0
    capsys.readouterr()
    assert not marker.exists() and not (b.state / LEDGER_TAIL_MARKER).exists()
    assert mirror_marker is None or not mirror_marker.exists()
    assert _actions(b).count("ledger.tail_truncated") == 1
    assert _actions(b).count("ledger.mirror_truncated") == (1 if nested else 0)
    (tail_audit,) = [e for e in b.ledger.entries() if e["action"] == "ledger.tail_truncated"]
    assert f"intent {intent['intent_id']}" in tail_audit["detail"]
    assert main([*_argv(b), "ledger", "verify"]) == 0
    assert main([*_argv(b), "ledger", "repair"]) == 0  # idempotent: nothing more
    capsys.readouterr()
    assert _actions(b).count("ledger.tail_truncated") == 1


def test_the_full_check_precedes_the_envelope_and_leaves_no_cache_behind(tmp_path):
    """Self-gate R2 minors: a bundle that is not even an envelope meets the ledger's
    full check first (a damaged ledger is the storage failure, never the refusal's
    append); and a check that fails leaves no cached entries behind (the next read
    comes from disk)."""
    a, b, wa, wb, fake, clock = _with_history_over_mail(tmp_path)
    jsonl = b.ledger.path
    whole = jsonl.read_bytes()
    reports: list[str] = []
    b.report = reports.append
    _edit_last_completion_outcome(b)
    with pytest.raises(IntegrityError) as e:
        b.receive({"natively": "v0", "kind": "bogus", "object": {}, "cards": [], "grants": []})
    assert e.value.reason == "ledger.prose.mismatch"
    assert any("storage failure while applying" in r for r in reports)
    assert not any("ledgering the refusal" in r for r in reports)
    assert b.ledger._entries is None  # nothing cached past the failed check
    jsonl.write_bytes(whole)
    b.ledger.check_intact()  # from disk: the restored file, not a stale cache
    assert b.ledger._entries is None
    assert b.ledger.verify() == b.ledger.head()


def _edit_last_completion_outcome(b) -> None:
    """The last entry's outcome edited in the JSONL (its chain link intact); the
    mirror unchanged, so the full check refuses and the loader alone does not."""
    jsonl = b.ledger.path
    lines = jsonl.read_bytes().split(b"\n")[:-1]
    e = json.loads(lines[-1])
    e["outcome"] = "refused" if e["outcome"] != "refused" else "failed"
    jsonl.write_bytes(b"\n".join([*lines[:-1], _serialize(e)]) + b"\n")


# ---- R4. a reply carries no grants (FAILURE BEFORE: nothing leaves) ------------------------


def test_a_reply_carrying_grants_is_refused_at_every_outgoing_boundary(
    tmp_path, monkeypatch, capsys
):
    """R4: a sound stored ack with grants [{}] is refused by reply_problem
    (reply.grants_not_allowed), by check_reply and check_outgoing (reply.invalid),
    by MailWire.send (nothing transmitted), by LocalWire.deliver (nothing recorded,
    logged or delivered) and by the CLI ack --out and ack --dry-run --out forms
    (exit 2, no file, zero transport calls); a message with a malformed attached
    grant is refused at check_outgoing; a sound message with its sound grant passes."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "one"))
    assert wb.poll_once()["replies"] == 1
    msg_id = a.outbox()[-1]["msg_id"]
    r, why = b.stored_reply(msg_id)
    assert why is None and b.reply_problem(r, msg_id, "ack") is None
    bad = {**r, "grants": [{}]}
    assert "reply.grants_not_allowed" in b.reply_problem(bad, msg_id, "ack")
    for check in (b.check_reply, b.check_outgoing):
        with pytest.raises(IntegrityError) as e:
            check(bad)
        assert e.value.reason == "reply.invalid" and "reply.grants_not_allowed" in str(e.value)
        assert "nothing sent" in str(e.value)
    sends_before, outbox_before = len(fake.sends), len(b.outbox())
    with pytest.raises(IntegrityError) as e:
        wb.send(bad)
    assert e.value.reason == "reply.invalid" and len(fake.sends) == sends_before
    wire = LocalWire()
    with pytest.raises(IntegrityError) as e:
        wire.deliver(b, a, bad)
    assert e.value.reason == "reply.invalid" and wire.log == []
    assert len(b.outbox()) == outbox_before
    # the CLI: the stored reply's outgoing copy carries grants AFTER the validation
    # that read it (the round-10 wrapper technique)
    real = Node.stored_reply

    def with_grants(self, *args, **kw):
        out, problem = real(self, *args, **kw)
        return ({**out, "grants": [{}]} if isinstance(out, dict) else out), problem

    monkeypatch.setattr(Node, "stored_reply", with_grants)
    transport = _no_transport(monkeypatch)
    out = tmp_path / "ack.txt"
    for form in (["--out", str(out)], ["--dry-run", "--out", str(out)]):
        assert main([*_argv(b), "ack", msg_id, *form]) == 2
        err = capsys.readouterr().err
        assert "reply.invalid" in err and "reply.grants_not_allowed" in err
        assert "nothing sent" in err and not out.exists()
    assert transport == []
    monkeypatch.undo()
    # every other kind: attached grants cross the shared document check
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "f.txt"), principal_statement=STATEMENT
    )
    m = write_bundle(a, b, g, "f.txt")
    assert m["grants"] == [g] and a.check_outgoing(m) is m
    with pytest.raises(IntegrityError) as e:
        a.check_outgoing({**m, "grants": [{}]})
    assert e.value.reason == "message.invalid" and "grants[0]" in str(e.value)


# ---- R5. a feed fault during the held-revocation replay is a storage failure ---------------
#      (FAILURE BEFORE, RESTART RECOVERY)


def test_a_feed_fault_during_the_held_revocation_replay_stays_a_storage_failure(tmp_path):
    """R5: a held revocation of the grant in hand (a startup sweep that met a
    corrupt feed left the replay marker) plus a damaged feed record: the action is
    a storage failure naming the feed and the line (feed.corrupt), the mail unseen,
    nothing executed, nothing ledgered, nothing acked, the marker and the held copy
    standing; the feed restored, the retry replays the held revocation and is
    refused as revoked (grant.revoked in the refusal detail). No named refusal
    exists for the state any more."""
    assert "revocation.replay_pending" not in (PKG / "node.py").read_text(encoding="utf-8")
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    g = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "h.txt"),
        principal_statement=STATEMENT,
        max_uses=3,
    )
    other = a.revoke(grants=[uid("grt")], principal_statement="unrelated")
    wa.send(a.compose_revocation(other))
    assert wb.poll_once()["complete"] is True
    (rec,) = b.revocations.entries()
    rev = a.revoke(grants=[g["grant_id"]], principal_statement="no more")
    held = b.state / "revocations-pending" / f"{rev['rev_id']}-{hash_of(rev)[7:19]}.json"
    held.parent.mkdir(exist_ok=True)
    held.write_text(json.dumps(rev), encoding="utf-8")
    feed = b.revocations.path
    original = feed.read_bytes()
    feed.write_bytes(_store_line(_damage_record(rec, "sig-damaged")))
    with b._locked():
        b._startup_sweep()  # the sweep meets feed.corrupt: the replay marker
    marker = b.state / REPLAY_MARKER
    assert json.loads(marker.read_text())["principals"] == [a.principal.public]
    wa.send(write_bundle(a, b, g, "h.txt"))
    msg_id = a.outbox()[-1]["msg_id"]
    _storage_failure_poll(b, wb, fake, feed, "feed.corrupt", 1, "h.txt")
    assert marker.exists() and held.exists() and msg_id not in b._seen()
    assert not any("replay_pending" in e["detail"] for e in b.ledger.entries())
    feed.write_bytes(original)
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["storage_failures"] == 0 and s["complete"] is True and s["replies"] == 1
    (ack,) = _acks_out(fake, inbox_before)
    assert ack["outcome"] == "refused:no_authorizing_grant"
    assert "grant.revoked" in b.ledger.entries()[-1]["detail"]
    assert not marker.exists() and not held.exists()
    assert _actions(b).count("revocation.replayed") == 1
    assert not (b.scratch_dir / "h.txt").exists() and _unseen_mail_ids(fake, b, wb) == set()
    assert b.revocations.grant_revoked_by(g["grant_id"], a.principal.public) is not None


def test_the_replay_failure_is_raised_through_receive_as_the_storage_class(tmp_path, monkeypatch):
    """R5, at the node: with the marker standing, the replay's IntegrityError and
    its OSError both leave `receive` as storage failures (the OSError wrapped as
    StorageError), nothing ledgered, no reservation; the failure gone, the same
    bundle is evaluated again and applies (the grant is not revoked)."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "ok.txt"), principal_statement=STATEMENT
    )
    (b.state / REPLAY_MARKER).write_text(
        json.dumps({"principals": [a.principal.public], "why": "test", "ts": b.ts()})
    )
    b.mark_lookup_ok()
    bundle = write_bundle(a, b, g, "ok.txt")
    for exc, cls in (
        (IntegrityError("feed.torn", "still torn"), IntegrityError),
        (PermissionError(13, "Permission denied"), StorageError),
    ):

        def failing(*args, _exc=exc, **kw):
            raise _exc

        monkeypatch.setattr(b, "_replay_pending_revocations", failing)
        n = len(b.ledger)
        with pytest.raises(cls) as e:
            b.receive(bundle)
        assert type(exc).__name__ in str(e.value) or getattr(e.value, "reason", "") == "feed.torn"
        assert len(b.ledger) == n and bundle["object"]["msg_id"] not in b._seen()
        assert (b.state / REPLAY_MARKER).exists() and not (b.scratch_dir / "ok.txt").exists()
        monkeypatch.undo()
    (r,) = b.receive(bundle)
    assert r["object"]["outcome"] == "applied" and not (b.state / REPLAY_MARKER).exists()


# ---- R6. a torn JSONL tail under a standing mirror intent (RESTART RECOVERY) ----------------


def _mirror_repair_at_truncated(tmp_path):
    """The round-11 shape one step on: a torn mirror tail, the mirror cut to the
    intent's cut point, the marker at step "truncated" — the moment the audit
    append starts. Returns (a, b, wa, wb, fake, clock, intent, marker)."""
    a, b, wa, wb, fake, clock = _with_history_over_mail(tmp_path)
    mirror = b.ledger.prose_path
    _tear_mirror(mirror, "tail")
    tail = b.ledger.excess_prose()
    size = mirror.stat().st_size
    intent = {
        "step": "truncated",
        "file": "ledger.prose.txt",
        "truncate_to": size - len(tail),
        "bytes": len(tail),
        "tail_sha256": "sha256:" + sha256_hex(tail),
        "intent_id": new_id("rpr"),
        "ts": b.ts(),
    }
    mirror.write_bytes(mirror.read_bytes()[: intent["truncate_to"]])
    return a, b, wa, wb, fake, clock, intent, _write_marker(b, intent)


def _torn_audit(b, intent: dict, how: str) -> None:
    """The mirror repair's own audit append torn: the machine run to completion
    under `intent`, then the JSONL's audit line cut short (`inside`), the whole
    audit entry short of only its newline (`unterminated`), or a torn partial line
    that is not the audit at all, before any audit landed (`before`); the mirror
    marker put back at step "truncated" as the crash left it."""
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    marker = b.state / "ledger-repair-pending.json"
    if how == "before":
        e = json.loads(jsonl.read_bytes().split(b"\n")[-2])
        torn = _serialize({**e, "detail": "an append torn before its newline"})[:30]
        with open(jsonl, "ab") as f:
            f.write(torn)
        return
    assert main([*_argv(b), "ledger", "repair"]) == 0
    assert not marker.exists() and _actions(b).count("ledger.mirror_truncated") == 1
    whole, prose = jsonl.read_bytes(), mirror.read_bytes()
    jsonl.write_bytes(whole[:-1] if how == "unterminated" else whole[:-20])
    mirror.write_bytes(b"".join(prose.splitlines(keepends=True)[:-1]))
    _write_marker(b, intent)


@pytest.mark.parametrize("how", ["before", "inside", "unterminated"])
def test_a_mirror_repair_whose_audit_tore_the_jsonl_tail_completes(tmp_path, capsys, how):
    """R6, the double fault in both orderings and the whole-entry case: the tear
    lands before the audit entry (a torn partial line, no audit yet), inside the
    audit line, or the audit landed short of only its newline. `ledger repair`
    completes: the torn tail cut under the nested marker and ledgered once
    (ledger.tail_truncated, "under a standing mirror repair") — or terminated,
    nothing cut — then exactly one mirror audit; both markers gone; verify exit 0;
    the next receive applies."""
    a, b, wa, wb, fake, clock, intent, marker = _mirror_repair_at_truncated(tmp_path)
    _torn_audit(b, intent, how)
    nested = b.state / LEDGER_TAIL_MARKER
    assert marker.exists() and not nested.exists()
    with pytest.raises(IntegrityError) as e:
        b.ledger.check()
    assert e.value.reason == "ledger.truncated"
    assert main([*_argv(b), "ledger", "repair"]) == 0
    out = capsys.readouterr().out
    assert not marker.exists() and not nested.exists()
    assert _actions(b).count("ledger.mirror_truncated") == 1
    if how == "unterminated":
        assert _actions(b).count("ledger.tail_truncated") == 0 and "torn byte(s)" not in out
    else:
        assert _actions(b).count("ledger.tail_truncated") == 1 and "torn byte(s)" in out
        (tail_audit,) = [e for e in b.ledger.entries() if e["action"] == "ledger.tail_truncated"]
        assert "under a standing mirror repair" in tail_audit["detail"]
    assert f"intent {intent['intent_id']}" in b.ledger.entries()[-1]["detail"]
    assert main([*_argv(b), "ledger", "verify"]) == 0
    wa.send(a.compose_info(b.card, "after"))
    assert wb.poll_once()["applied"] == 1


@pytest.mark.parametrize("nested_step", ["intent", "truncated", "audited"])
def test_a_power_loss_between_the_nested_cut_and_the_mirror_completion_resumes(
    tmp_path, capsys, nested_step
):
    """R6, RESTART RECOVERY: the nested tail stage interrupted at each of its steps
    under the standing mirror intent — the intent recorded (the tail still there),
    the tail cut (no audit yet), the tail audit landed (the marker not yet gone).
    The resume finishes the nested stage exactly once (one tail audit) and the
    mirror repair once (one mirror audit); both markers gone; verify exit 0."""
    a, b, wa, wb, fake, clock, intent, marker = _mirror_repair_at_truncated(tmp_path)
    _torn_audit(b, intent, "inside")
    jsonl = b.ledger.path
    torn = b.ledger.torn_tail()
    assert torn
    nested_intent = {
        "step": nested_step,
        "file": "ledger.jsonl",
        "truncate_to": jsonl.stat().st_size - len(torn),
        "bytes": len(torn),
        "tail_sha256": "sha256:" + sha256_hex(torn),
        "intent_id": new_id("rpr"),
        "ts": b.ts(),
    }
    if nested_step in ("truncated", "audited"):
        jsonl.write_bytes(jsonl.read_bytes()[: nested_intent["truncate_to"]])
    if nested_step == "audited":
        b._repair_active = "ledger"  # the machine's own append, as the crash left it
        audit = b.ledger.append(
            ts=b.ts(),
            actor="solo",
            grant_id=None,
            action="ledger.tail_truncated",
            params_hash=nested_intent["tail_sha256"],
            outcome="recorded",
            detail=f"truncated; intent {nested_intent['intent_id']}",
            intent_id=nested_intent["intent_id"],
        )
        b._repair_active = None
        nested_intent["audit_hash"] = entry_hash(audit)
    nested = b.state / LEDGER_TAIL_MARKER
    nested.write_text(json.dumps(nested_intent), encoding="utf-8")
    # nothing appends while either marker stands
    with pytest.raises(IntegrityError) as e:
        b.receive(a.compose_info(b.card, "blocked"))
    assert e.value.reason == "ledger.repair_pending"
    assert main([*_argv(b), "ledger", "repair"]) == 0
    capsys.readouterr()
    assert not marker.exists() and not nested.exists()
    assert _actions(b).count("ledger.tail_truncated") == 1
    assert _actions(b).count("ledger.mirror_truncated") == 1
    (tail_audit,) = [e for e in b.ledger.entries() if e["action"] == "ledger.tail_truncated"]
    assert f"intent {nested_intent['intent_id']}" in tail_audit["detail"]
    assert main([*_argv(b), "ledger", "verify"]) == 0


@pytest.mark.parametrize("nested_standing", [False, True], ids=["fresh", "nested-marker"])
def test_a_torn_tail_that_is_not_this_ledgers_is_refused_with_both_markers_standing(
    tmp_path, capsys, nested_standing
):
    """R6: under the mirror intent the torn tail's prefix is not this ledger's chain
    (broken at line 2): refused by name (ledger.chain), the JSONL, the mirror and
    every marker byte-identical — no nested marker created on a fresh run, both
    markers standing when one already exists."""
    a, b, wa, wb, fake, clock, intent, marker = _mirror_repair_at_truncated(tmp_path)
    _torn_audit(b, intent, "inside")
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    nested = b.state / LEDGER_TAIL_MARKER
    if nested_standing:
        torn = b.ledger.torn_tail()
        nested.write_text(
            json.dumps(
                {
                    "step": "intent",
                    "file": "ledger.jsonl",
                    "truncate_to": jsonl.stat().st_size - len(torn),
                    "bytes": len(torn),
                    "tail_sha256": "sha256:" + sha256_hex(torn),
                    "intent_id": new_id("rpr"),
                    "ts": b.ts(),
                }
            ),
            encoding="utf-8",
        )
    _break_chain(jsonl)
    before = (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes())
    nested_before = nested.read_bytes() if nested_standing else None
    assert main([*_argv(b), "ledger", "repair"]) == 2
    err = capsys.readouterr().err
    assert "ledger.chain" in err and str(jsonl) in err
    assert (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes()) == before
    assert nested.exists() == nested_standing
    if nested_standing:
        assert nested.read_bytes() == nested_before
    assert b'"ledger.tail_truncated"' not in jsonl.read_bytes()  # no audit (the bytes above)


@NEWLINE
@pytest.mark.parametrize("step", ["intent", "audited"])
def test_a_torn_tail_at_any_other_mirror_step_is_not_this_machines(
    tmp_path, capsys, step, terminated
):
    """R6: the audit append runs only at step "truncated", so a mirror intent at
    "intent" or "audited" was written over a whole JSONL that nothing of ours has
    written since: a torn tail there is refused by name (ledger.truncated; with
    its newline, round 13, ledger.corrupt) with nothing written and no nested
    marker."""
    a, b, wa, wb, fake, clock, intent, marker = _mirror_repair_at_truncated(tmp_path)
    _torn_audit(b, intent, "before")
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    if terminated:
        with open(jsonl, "ab") as f:
            f.write(b"\n")
    intent = {**intent, "step": step}
    if step == "audited":
        intent["audit_hash"] = "sha256:" + "0" * 64
    _write_marker(b, intent)
    before = (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes())
    assert main([*_argv(b), "ledger", "repair"]) == 2
    assert ("ledger.corrupt" if terminated else "ledger.truncated") in capsys.readouterr().err
    assert (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes()) == before
    assert not (b.state / LEDGER_TAIL_MARKER).exists()


def test_a_nested_marker_without_its_mirror_intent_is_refused_by_name(tmp_path, capsys):
    """R6: the nested marker exists only beside a mirror intent; found alone (or
    beside a tail intent) it is ledger.repair.intent_mismatch with nothing written,
    and every append refuses while it stands."""
    a, b, wa, wb, fake, clock = _with_history_over_mail(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    nested = b.state / LEDGER_TAIL_MARKER
    nested.write_text(
        json.dumps(
            {
                "step": "intent",
                "file": "ledger.jsonl",
                "truncate_to": jsonl.stat().st_size,
                "bytes": 3,
                "tail_sha256": "sha256:" + sha256_hex(b"abc"),
                "intent_id": new_id("rpr"),
                "ts": b.ts(),
            }
        ),
        encoding="utf-8",
    )
    before = (jsonl.read_bytes(), mirror.read_bytes(), nested.read_bytes())
    with pytest.raises(IntegrityError) as e:
        b.receive(a.compose_info(b.card, "blocked"))
    assert e.value.reason == "ledger.repair_pending" and LEDGER_TAIL_MARKER in str(e.value)
    assert main([*_argv(b), "ledger", "repair"]) == 2
    err = capsys.readouterr().err
    assert "ledger.repair.intent_mismatch" in err and LEDGER_TAIL_MARKER in err
    assert (jsonl.read_bytes(), mirror.read_bytes(), nested.read_bytes()) == before
    nested.unlink()
    assert main([*_argv(b), "ledger", "repair"]) == 0
    capsys.readouterr()
    assert main([*_argv(b), "ledger", "verify"]) == 0

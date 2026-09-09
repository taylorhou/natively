"""Round 8 (hw-h9ci6): the seventh cross-model gate's findings on the whole package —
one MAJOR outside the fail-closed flush and three MINOR — each fixed as ruled.

M1  ONE validation (`Node.reply_problem`) runs on EVERY reply before it is held and
    again before it is sent, on the same-poll path and the flush alike: a reply that
    fails is never held (pending_reply.invalid, a storage failure ledgered once with
    the msg_id; the mail stays unseen, nothing is sent, the poll incomplete) and the
    direct send never sends what fails. The root cause — the self card read — is
    closed at the source: `self.card.json` is loaded through the card module's full
    verification (structure, both signatures) and bound to this node's own keys, at
    construction and before every ack; one that fails is IntegrityError
    card.self_corrupt naming the path — a storage failure: receive refuses, nothing is
    acked, the mail stays unseen; the flush sends nothing. (The self card file
    carries no stated hash — the signed card IS the file — so the hash binding is
    realised as the key binding: a sound card of another identity has another hash
    and is refused for its keys.)
M2  `pending repair` checks the discard record BEFORE the suffix decides anything: a
    copy discarded on record and still on disk is an unfinished discard, finished
    from its record (the same resumable path the discard verb takes), reported
    `discarded`, never rebuilt — see test_gate_round7b (the discard tests).
M3  a storage error while a candidate source is READ (the seen state, the self card)
    is a storage failure of the verb — reported by name with the path, counted, the
    copy left unresolved — never a fallthrough to the next source; only a source
    that reads cleanly but fails validation falls through.
M4  the visible-then-failed shape on every removal step of the discard tests — see
    test_gate_round7b — and here on the repair verb's two writes: the canonical hold
    and the stored-ack replacement (FAILURE AFTER: the effect lands, the call
    reports failure; the retry finds a finished step and audits once).

The self-gate of this round (one round, BLOCK: 1 major + 3 minor, all inside M1/M3,
fixed after it): every OUTGOING boundary a reply crosses validates it once more
(`Node.check_reply`: the wire's send, `poll --file --out`, the in-process transport —
reply.invalid, nothing leaves); a reply is held under the id of the REQUEST it answers
(never a name derived from the reply, so a reply of any shape is refused inside the
boundary); the receive-time card.self_corrupt refusal reaches the report stream; a
rebuilt ack reads the self card before anything is signed or the seen file written.

Categories as in the earlier round modules: ORDERING, FAILURE BEFORE, FAILURE AFTER,
RESTART RECOVERY (a CLI invocation builds a fresh Node)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from natively import PROTOCOL_VERSION
from natively import bundle as bundlemod
from natively import node as nodemod
from natively.adapters import mail as mailmod
from natively.adapters.local import LocalWire
from natively.adapters.mail import MailWire
from natively.cli import main
from natively.errors import IntegrityError
from natively.node import Node

from .conftest import Clock, make_node, uid
from .test_gate_round3 import seen_of
from .test_gate_round5 import _raise
from .test_gate_round6 import _connected_over_mail
from .test_gate_round7 import _argv, _held_ack_over_mail
from .test_gate_round7b import _acks_out, _actions, _inbox_len, _quarantined

SELF = "self.card.json"
DAMAGE = ["torn", "empty-list", "signature", "hash"]


def _flip(sig: str) -> str:
    return ("B" if sig[0] != "B" else "C") + sig[1:]


def _damaged_self_card(node, how: str, tmp_path, clock) -> bytes:
    """Damage `node`'s self card one of four ways; returns the original bytes.
    `torn`: not JSON at all (a torn tail); `empty-list`: valid JSON that is not a
    card; `signature`: the principal signature damaged; `hash`: a SOUND card of
    another identity (it verifies; its hash is not this node's card's, and its keys
    are not this node's keys)."""
    p = node.state / SELF
    original = p.read_bytes()
    if how == "torn":
        p.write_text("{")
    elif how == "empty-list":
        p.write_text("[]")
    elif how == "signature":
        c = json.loads(original)
        c["sig"] = _flip(c["sig"])
        p.write_text(json.dumps(c))
    else:
        other = make_node(tmp_path, "someone-else", clock)
        p.write_bytes((other.state / SELF).read_bytes())
    return original


def _unseen_mail_ids(fake, node, wire) -> set[str]:
    """The gmail ids in `node`'s inbox that its wire has NOT marked seen."""
    rows = fake.inbox.get(wire.self_email, [])
    return {r["id"] for r in rows} - set(wire._seen())


# ---- M1. the self card: verified at construction, before every ack, before every send -------


@pytest.mark.parametrize("damage", DAMAGE)
def test_a_damaged_self_card_refuses_receive_nothing_acked_the_mail_unseen(tmp_path, damage):
    """A message arrives while the self card is damaged: card.self_corrupt names the
    path; nothing is ledgered for the message, nothing held, nothing sent, the mail
    stays unseen, the poll is incomplete; a fresh Node refuses to construct and every
    CLI verb exits 2. The card restored, the next poll answers exactly as before."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    reports: list[str] = []
    b.report = reports.append
    wa.send(a.compose_info(b.card, "hello"))
    msg_id = a.outbox()[-1]["msg_id"]
    original = _damaged_self_card(b, damage, tmp_path, clock)
    path = str(b.state / SELF)
    inbox_before = _inbox_len(fake)
    unseen_before = _unseen_mail_ids(fake, b, wb)
    assert len(unseen_before) == 1
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False
    assert s["applied"] == 0 and s["replies"] == 0 and _inbox_len(fake) == inbox_before
    assert any("card.self_corrupt" in e and path in e for e in s["errors"])
    # the refusal reaches the operator's report stream too, once, with its path
    assert [r for r in reports if "card.self_corrupt" in r and path in r and "storage failure" in r]
    assert sum("card.self_corrupt" in r for r in reports) == 1
    assert b.ledger.find_msg(msg_id) is None and msg_id not in seen_of(b)
    assert wb._pending_replies() == [] and wb._aside_replies() == []
    assert _unseen_mail_ids(fake, b, wb) == unseen_before
    with pytest.raises(IntegrityError) as e:  # RESTART RECOVERY: refused at construction
        Node(state_dir=b.state, keys_dir=b.keys_dir, scratch_dir=b.scratch_dir, clock=clock)
    assert e.value.reason == "card.self_corrupt" and path in str(e.value)
    with pytest.raises(IntegrityError) as e:
        _ = b.card
    assert e.value.reason == "card.self_corrupt"
    assert main([*_argv(b), "pending", "list"]) == 2
    (b.state / SELF).write_bytes(original)
    s = wb.poll_once()
    assert s["applied"] == 1 and s["replies"] == 1 and s["complete"] is True
    assert _inbox_len(fake) == inbox_before + 1 and _unseen_mail_ids(fake, b, wb) == set()
    assert wa.poll_once()["applied"] == 1 and a.outbox()[-1]["status"] == "acked"


def test_the_cli_refuses_every_verb_on_a_damaged_self_card_and_names_the_path(tmp_path, capsys):
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    _damaged_self_card(b, "signature", tmp_path, clock)
    for argv in (["card", "--show"], ["pending", "list"], ["pending", "repair"], ["poll"]):
        assert main([*_argv(b), *argv]) == 2
        err = capsys.readouterr().err
        assert "card.self_corrupt" in err and str(b.state / SELF) in err


@pytest.mark.parametrize("damage", DAMAGE)
def test_a_damaged_self_card_stops_the_flush_the_held_reply_left_in_place(tmp_path, damage):
    """The flush path: a sound reply held from an earlier poll (its send failed) is
    validated again before it goes out, and the validation begins with this node's
    own card — damaged, it is a storage failure of the validation: the held copy is
    left in place (never quarantined, never sent), counted, the poll incomplete. The
    card restored, the next poll sends it."""
    a, b, wa, wb, fake, clock, held, reports = _held_ack_over_mail(tmp_path)
    (p,) = held
    original = _damaged_self_card(b, damage, tmp_path, clock)
    path = str(b.state / SELF)
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False and s["replies"] == 0
    assert _inbox_len(fake) == inbox_before
    assert any(
        f"the validation of held reply {p.name}" in e and "card.self_corrupt" in e and path in e
        for e in s["errors"]
    )
    assert p.exists() and wb._aside_replies() == []
    assert "pending_reply.corrupt" not in _actions(b)
    (b.state / SELF).write_bytes(original)
    s = wb.poll_once()
    assert s["replies"] == 1 and s["complete"] is True and not p.exists()
    assert wa.poll_once()["applied"] == 1 and a.outbox()[-1]["status"] == "acked"


@pytest.mark.parametrize("damage", ["empty-list", "signature", "hash"])
def test_a_held_reply_staged_by_hand_with_a_damaged_card_is_quarantined_never_sent(
    tmp_path, damage
):
    """The flush path, the envelope itself damaged: a held reply staged by hand whose
    envelope carries a card that is not a card (`[]`), a card with a damaged
    signature, or only another identity's card fails the ONE validation (the
    envelope's cards are verified in full, one of them must be this agent's) and is
    quarantined: never sent, never deleted, counted, ledgered pending_reply.corrupt."""
    a, b, wa, wb, fake, clock, held, reports = _held_ack_over_mail(tmp_path)
    (p,) = held
    r = json.loads(p.read_text())
    if damage == "empty-list":
        r["cards"] = [[]]
    elif damage == "signature":
        r["cards"][0]["sig"] = _flip(r["cards"][0]["sig"])
    else:
        r["cards"] = [a.card]
    p.write_text(json.dumps(r))
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False and s["replies"] == 0
    assert _inbox_len(fake) == inbox_before and not p.exists()
    (aside,) = wb._aside_replies()
    assert wb._unresolved(aside) and aside.name.startswith(p.name)
    assert _actions(b).count("pending_reply.corrupt") == 1
    why = {
        "empty-list": "bundle.cards",
        "signature": "cards[0]: card.sig",
        "hash": "no card for this agent",
    }[damage]
    assert any(why in e and p.name in e for e in s["errors"])


def test_reply_problem_verifies_the_envelopes_cards(tmp_path):
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "one"))
    assert wb.poll_once()["replies"] == 1
    msg_id = a.outbox()[-1]["msg_id"]
    r, why = b.stored_reply(msg_id)
    assert why is None and b.reply_problem(r, msg_id, "ack") is None
    assert b.reply_problem({**r, "cards": [[]]}, msg_id, "ack").startswith("bundle.cards")
    assert b.reply_problem({**r, "cards": [{}]}, msg_id, "ack").startswith("cards[0]: card.")
    damaged = json.loads(json.dumps(b.card))
    damaged["sig"] = _flip(damaged["sig"])
    assert "cards[0]: card.sig" in b.reply_problem({**r, "cards": [damaged]}, msg_id, "ack")
    assert b.reply_problem({**r, "cards": [a.card]}, msg_id, "ack") == (
        "the envelope carries no card for this agent"
    )
    assert b.reply_problem({**r, "cards": [a.card, b.card]}, msg_id, "ack") is None


def test_an_ack_this_node_cannot_verify_is_never_stored_or_held_ack_self_invalid(
    tmp_path, monkeypatch
):
    """The same-poll path: an ack this node signs that does not verify (the signing
    damaged as it is made) is refused BEFORE it is stored — ack.self_invalid, a
    storage failure of the receive (round 13: the stored acks anchor the ledger's
    tail, so an ack that fails verification is never one of them): nothing stored
    in seen.json, nothing held or sent, the mail unseen, the poll incomplete; the
    completion stands. The re-read next poll finds the completion, rebuilds the ack,
    refuses it again and appends nothing; the signing sound again, the rebuilt ack
    is stored (it verifies) and the reply goes out."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    reports: list[str] = []
    b.report = reports.append
    wa.send(a.compose_info(b.card, "hello"))
    msg_id = a.outbox()[-1]["msg_id"]
    real_sign = nodemod.ackmod.sign

    def bad_sign(obj, kp):
        signed = real_sign(obj, kp)
        return {**signed, "sig": _flip(signed["sig"])}

    monkeypatch.setattr(nodemod.ackmod, "sign", bad_sign)
    inbox_before = _inbox_len(fake)
    unseen_before = _unseen_mail_ids(fake, b, wb)
    seen_before = _seen_bytes(b)
    s = wb.poll_once()
    assert s["applied"] == 0  # the receive is the storage failure: the ack never made
    assert s["storage_failures"] == 1 and s["complete"] is False and s["replies"] == 0
    assert _inbox_len(fake) == inbox_before
    assert wb._pending_replies() == [] and wb._aside_replies() == []
    assert any("ack.self_invalid" in e and "ack.sig" in e and msg_id in e for e in s["errors"])
    assert _unseen_mail_ids(fake, b, wb) == unseen_before
    assert _seen_bytes(b) == seen_before  # nothing stored
    assert b.ledger.find_msg(msg_id) is not None  # the completion stands
    assert "pending_reply.invalid" not in _actions(b)
    n = len(b.ledger.entries())
    s = wb.poll_once()  # the re-read: the completion answers, the rebuilt ack refused again
    assert s["applied"] == 0 and s["storage_failures"] == 1 and s["replies"] == 0
    assert _inbox_len(fake) == inbox_before and len(b.ledger.entries()) == n
    assert _seen_bytes(b) == seen_before
    assert any("but its ack was lost; rebuilding" in r for r in reports)
    assert _unseen_mail_ids(fake, b, wb) == unseen_before
    monkeypatch.undo()
    s = wb.poll_once()
    assert s["applied"] == 1 and s["replies"] == 1 and s["complete"] is True
    assert len(b.ledger.entries()) == n  # rebuilt from the completion, nothing re-evaluated
    nodemod.ackmod.verify(seen_of(b)[msg_id]["ack"])
    assert _unseen_mail_ids(fake, b, wb) == set()
    assert wa.poll_once()["applied"] == 1 and a.outbox()[-1]["status"] == "acked"


def test_the_direct_send_validates_again_and_never_sends_what_fails(tmp_path, monkeypatch, capsys):
    """The same-poll path, after the hold and the seen mark: the reply is validated
    once more (the same check) before its direct send; one that fails then is
    quarantined like a held copy the flush refuses — never sent, never deleted — and
    the operator's repair from the stored ack (validated) sends it next poll."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "hello"))
    msg_id = a.outbox()[-1]["msg_id"]
    calls: list[str] = []

    def problem(self, r, p):
        calls.append(p.name)
        return "injected: the reply changed between the hold and the send"

    monkeypatch.setattr(MailWire, "_held_reply_problem", problem)
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    monkeypatch.undo()
    assert calls == [f"{msg_id}.ack.json"]  # nothing to flush: the one call is the send's
    assert s["applied"] == 1 and s["replies"] == 0 and _inbox_len(fake) == inbox_before
    assert s["storage_failures"] == 1 and s["complete"] is False
    (aside,) = wb._aside_replies()
    assert wb._unresolved(aside) and wb._pending_replies() == []
    assert _actions(b).count("pending_reply.corrupt") == 1
    assert _unseen_mail_ids(fake, b, wb) == set()  # seen: the held copy was the obligation
    s = wb.poll_once()  # frozen until the operator decides; nothing rebuilt or sent
    assert s["applied"] == 0 and s["storage_failures"] == 1 and s["replies"] == 0
    assert main([*_argv(b), "pending", "repair"]) == 0
    assert "1 rebuilt" in capsys.readouterr().out
    assert wb.poll_once()["replies"] == 1 and _inbox_len(fake) == inbox_before + 1
    (sent,) = _acks_out(fake, inbox_before)
    assert sent == seen_of(b)[msg_id]["ack"]
    assert wa.poll_once()["applied"] == 1 and a.outbox()[-1]["status"] == "acked"


# ---- M3. a source that cannot be READ is the verb's storage failure, never a fallthrough -----


@pytest.mark.parametrize("failure", ["oserror", "integrity"])
def test_pending_repair_reports_a_seen_state_read_failure_by_name_and_resolves_nothing(
    tmp_path, monkeypatch, capsys, failure
):
    """The stored ack is sound but its read fails (an OSError; a seen file of ours
    that does not parse): refused by name with the path, counted; the copy stays
    unresolved, nothing held, nothing sent, the stored ack never replaced from the
    completion. The read sound again, the stored ack is the source."""
    a, b, wa, wb, fake, clock, aside, msg_id, reports = _quarantined(tmp_path)
    stored_before = seen_of(b)[msg_id]["ack"]
    seen_path = b.state / "seen.json"
    exc = (
        OSError(5, "Input/output error", str(seen_path))
        if failure == "oserror"
        else IntegrityError("state.corrupt", f"{seen_path}: Expecting value")
    )
    monkeypatch.setattr(Node, "_seen", _raise(exc))
    inbox_before = _inbox_len(fake)
    assert main([*_argv(b), "pending", "repair"]) == 1
    out = capsys.readouterr()
    monkeypatch.undo()
    assert "0 rebuilt" in out.out and "0 unresolvable" in out.out
    assert "1 storage failure(s)" in out.out
    # round 14: the seen file is read FIRST by the anchored ledger check that precedes
    # the discard-record lookup (the stored acks anchor the chain), so the failure
    # surfaces at that first read — the same class, the same name, the same path
    assert f"the discard record of {aside.name}" in out.err and str(seen_path) in out.err
    assert ("Input/output error" if failure == "oserror" else "state.corrupt") in out.err
    assert wb._unresolved(aside) and aside.exists() and wb._pending_replies() == []
    assert seen_of(b)[msg_id]["ack"] == stored_before
    assert "pending_reply.reconstructed" not in _actions(b)
    s = wb.poll_once()
    assert s["replies"] == 0 and _inbox_len(fake) == inbox_before and s["complete"] is False
    assert main([*_argv(b), "pending", "repair"]) == 0
    out = capsys.readouterr()
    assert "1 rebuilt" in out.out and "rebuilt from the stored ack" in out.err
    assert wb.poll_once()["replies"] == 1
    (sent,) = _acks_out(fake, inbox_before)
    assert sent == stored_before


@pytest.mark.parametrize("stored", ["present", "absent", "reservation"])
def test_pending_repair_with_a_damaged_self_card_is_a_storage_failure_by_name(
    tmp_path, capsys, monkeypatch, stored
):
    """The self card read is a source read too: the CLI's fresh Node refuses at
    construction (exit 2, nothing changed); a live node's verb counts it by name
    against the copy — never a fallthrough to the completion — and whatever the seen
    state holds for the message (the stored ack, nothing, a bare reservation) it is
    left byte for byte as it was: the self card is read before anything is signed or
    the seen file written."""
    a, b, wa, wb, fake, clock, aside, msg_id, reports = _quarantined(tmp_path)
    seen_path = b.state / "seen.json"
    if stored != "present":
        seen = seen_of(b)
        if stored == "absent":
            del seen[msg_id]
        else:
            seen[msg_id] = {"status": "in_progress", "grant_id": uid("grt"), "ts": b.ts()}
        seen_path.write_text(json.dumps(seen))
    seen_before = seen_path.read_bytes()
    original = _damaged_self_card(b, "signature", tmp_path, clock)
    path = str(b.state / SELF)
    assert main([*_argv(b), "pending", "repair"]) == 2
    err = capsys.readouterr().err
    assert "card.self_corrupt" in err and path in err
    assert seen_path.read_bytes() == seen_before
    s = wb.repair_pending()
    assert s["rebuilt"] == [] and s["unresolvable"] == [] and s["storage_failures"] == 1
    assert any(
        f"the source for held reply {aside.name}" in e and "card.self_corrupt" in e and path in e
        for e in s["errors"]
    )
    assert wb._unresolved(aside) and wb._pending_replies() == []
    assert seen_path.read_bytes() == seen_before
    assert "pending_reply.reconstructed" not in _actions(b)
    (b.state / SELF).write_bytes(original)
    assert main([*_argv(b), "pending", "repair"]) == 0
    out = capsys.readouterr()
    if stored == "reservation":
        # a reservation and a completion: the completion answers (the use stays consumed)
        assert "1 rebuilt" in out.out and "the ledger completion" in out.err
    else:
        assert "1 rebuilt" in out.out


# ---- M4 (the repair verb's writes). FAILURE AFTER: the effect lands, the call fails ---------


def test_repair_hold_visible_then_failed_is_finished_by_the_retry_with_one_audit(
    tmp_path, monkeypatch, capsys
):
    """The canonical hold LANDS (the file is visible) and the write reports failure:
    the run counts it and goes no further (no audit, no mark). The retry validates
    the same source, lands the same bytes under the same name (never a conflict),
    audits once, marks; the next poll sends it once."""
    a, b, wa, wb, fake, clock, aside, msg_id, reports = _quarantined(tmp_path)
    held = wb.pending_dir / wb.held_name_of(aside)
    real = mailmod._write_json

    def write_json(p, obj):
        real(p, obj)
        if Path(p) == held:
            raise OSError(5, "Input/output error")

    monkeypatch.setattr(mailmod, "_write_json", write_json)
    assert main([*_argv(b), "pending", "repair"]) == 1
    out = capsys.readouterr()
    monkeypatch.undo()
    assert "0 rebuilt" in out.out and "1 storage failure(s)" in out.out
    assert f"the rebuilt held reply for {msg_id}" in out.err
    assert held.exists() and wb._unresolved(aside)  # visible; the run went no further
    assert "pending_reply.reconstructed" not in _actions(b)
    assert main([*_argv(b), "pending", "repair"]) == 0
    assert "1 rebuilt" in capsys.readouterr().out
    assert _actions(b).count("pending_reply.reconstructed") == 1
    assert _actions(b).count("pending_reply.corrupt") == 1
    assert not aside.exists() and aside.with_name(aside.name + ".reconstructed").exists()
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["replies"] == 1 and s["complete"] is True and _inbox_len(fake) == inbox_before + 1
    assert wa.poll_once()["applied"] == 1 and a.outbox()[-1]["status"] == "acked"


def test_repair_stored_ack_replacement_visible_then_failed_is_the_retrys_source(
    tmp_path, monkeypatch, capsys
):
    """The completion source stores its rebuilt ack (the seen file LANDS) and the
    write reports failure: a storage failure by name, nothing held, nothing marked.
    The retry finds the stored ack — validated — as its source, holds it, audits
    once; the ack that goes out is the one stored."""
    a, b, wa, wb, fake, clock, aside, msg_id, reports = _quarantined(tmp_path)
    seen_path = b.state / "seen.json"
    seen = seen_of(b)
    del seen[msg_id]  # the completion is the only source
    seen_path.write_text(json.dumps(seen))
    real = nodemod._write_json

    def write_json(p, obj):
        real(p, obj)
        if Path(p) == seen_path:
            raise OSError(5, "Input/output error")

    monkeypatch.setattr(nodemod, "_write_json", write_json)
    assert main([*_argv(b), "pending", "repair"]) == 1
    out = capsys.readouterr()
    monkeypatch.undo()
    assert "0 rebuilt" in out.out and "1 storage failure(s)" in out.out
    assert f"the source for held reply {aside.name}" in out.err and "Input/output error" in out.err
    assert "ack" in seen_of(b)[msg_id]  # the replacement is visible ...
    assert wb._pending_replies() == [] and wb._unresolved(aside)  # ... nothing held or marked
    assert "pending_reply.reconstructed" not in _actions(b)
    assert main([*_argv(b), "pending", "repair"]) == 0
    out = capsys.readouterr()
    assert "1 rebuilt" in out.out and "rebuilt from the stored ack" in out.err
    assert _actions(b).count("pending_reply.reconstructed") == 1
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["replies"] == 1 and s["complete"] is True
    (sent,) = _acks_out(fake, inbox_before)
    assert sent == seen_of(b)[msg_id]["ack"]
    assert wa.poll_once()["applied"] == 1 and a.outbox()[-1]["status"] == "acked"


# ---- the self-gate's findings (one round; fixed inside M1 and M3) -----------------------------


def _seen_bytes(node) -> bytes | None:
    """The seen file's bytes, None when it was never written."""
    p = node.state / "seen.json"
    return p.read_bytes() if p.exists() else None


def _bad_sign(monkeypatch):
    """Every ack this process signs from now on carries a damaged signature."""
    real_sign = nodemod.ackmod.sign

    def bad_sign(obj, kp):
        signed = real_sign(obj, kp)
        return {**signed, "sig": _flip(signed["sig"])}

    monkeypatch.setattr(nodemod.ackmod, "sign", bad_sign)


def test_the_wire_send_refuses_a_reply_that_fails_validation(tmp_path):
    """Finding 1 (major): the outgoing boundary. `MailWire.send` runs the ONE
    validation on every ack it is handed: one that fails is never encoded, never
    transmitted, never recorded in the outbox — IntegrityError reply.invalid."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "one"))
    assert wb.poll_once()["replies"] == 1
    msg_id = a.outbox()[-1]["msg_id"]
    r, why = b.stored_reply(msg_id)
    assert why is None
    sends_before, outbox_before = len(fake.sends), len(b.outbox())
    for damaged in (
        {**r, "object": {**r["object"], "sig": _flip(r["object"]["sig"])}},
        {**r, "cards": [[]]},
        {**r, "cards": [a.card]},
        {**r, "object": []},
    ):
        with pytest.raises(IntegrityError) as e:
            wb.send(damaged)
        assert e.value.reason == "reply.invalid" and "nothing sent" in str(e.value)
    assert len(fake.sends) == sends_before and len(b.outbox()) == outbox_before
    with pytest.raises(IntegrityError):
        b.check_reply(damaged)
    assert b.check_reply(r) is r
    wb.send(r, resend=True)  # the sound one goes
    assert len(fake.sends) == sends_before + 1


def test_poll_file_refuses_to_export_or_send_an_invalid_reply(tmp_path, monkeypatch, capsys):
    """Finding 1 (major): `natively poll --file` crosses the same boundary — a reply
    that fails is neither written to --out nor handed to the wire (exit 2); the
    message itself was applied (its completion stands). An ack damaged as it is
    signed is refused one step earlier, before it is stored (ack.self_invalid,
    round 13), so nothing is stored for the first message. The send form is
    exercised on a FRESH message: receive produces a sound reply, the reply is
    damaged at the outgoing boundary only, and the boundary refuses it
    (reply.invalid) — zero transport calls, no output file."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    m = a.compose_info(b.card, "by file")
    msg_id = m["object"]["msg_id"]
    f = tmp_path / "msg.txt"
    f.write_text(bundlemod.encode(m), encoding="utf-8")
    out = tmp_path / "ack.txt"
    _bad_sign(monkeypatch)
    seen_before = _seen_bytes(b)
    assert main([*_argv(b), "poll", "--file", str(f), "--out", str(out)]) == 2
    err = capsys.readouterr().err
    assert "ack.self_invalid" in err and "ack.sig" in err and "nothing stored, nothing sent" in err
    assert not out.exists() and b.ledger.find_msg(msg_id) is not None
    assert _seen_bytes(b) == seen_before  # nothing stored
    monkeypatch.undo()
    # the send form, on a fresh message: the reply receive returns is sound and
    # stored; only the copy handed to the boundary is damaged
    m2 = a.compose_info(b.card, "by file, sent")
    msg2 = m2["object"]["msg_id"]
    f2 = tmp_path / "msg2.txt"
    f2.write_text(bundlemod.encode(m2), encoding="utf-8")
    real_receive = Node.receive

    def receive_then_damage(self, bundle):
        return [
            {**r, "object": {**r["object"], "sig": _flip(r["object"]["sig"])}}
            for r in real_receive(self, bundle)
        ]

    transport: list[list[str]] = []

    def runner(argv):
        transport.append(argv)
        raise AssertionError("the transport was called")

    monkeypatch.setattr(Node, "receive", receive_then_damage)
    monkeypatch.setattr(mailmod, "default_runner", runner)
    files_before = sorted(p.name for p in tmp_path.iterdir())
    assert main([*_argv(b), "poll", "--file", str(f2)]) == 2  # the send form refuses
    err = capsys.readouterr().err
    assert "reply.invalid" in err and "ack.sig" in err and "nothing sent" in err
    assert transport == [] and sorted(p.name for p in tmp_path.iterdir()) == files_before
    assert b.ledger.find_msg(msg2) is not None  # applied; the completion stands
    assert b.stored_reply(msg2)[1] is None  # the stored ack is sound: only the copy was damaged
    monkeypatch.undo()
    # the FIRST run stored nothing: `natively ack` has nothing to send and says why;
    # the same file polled again is a re-delivery, answered from the completion
    assert main([*_argv(b), "ack", msg_id]) == 1
    assert "no ack is stored" in capsys.readouterr().err
    assert main([*_argv(b), "poll", "--file", str(f), "--out", str(out)]) == 0
    assert out.exists() and b.stored_reply(msg_id)[1] is None


def test_the_local_wire_refuses_an_invalid_reply(tmp_path, monkeypatch):
    """Finding 1 (major): the in-process transport crosses the boundary too — the
    sender never receives a reply that fails, and its message stays unacked."""
    clock = Clock()
    a = make_node(tmp_path, "a", clock)
    b = make_node(tmp_path, "b", clock)
    a.pin(b.principal.public, "b")
    b.pin(a.principal.public, "a")
    lw = LocalWire()
    lw.deliver(a, b, a.compose_card())
    lw.deliver(b, a, b.compose_card())
    a.mark_lookup_ok()
    b.mark_lookup_ok()
    assert lw.deliver(a, b, a.compose_info(b.card, "sound")) != []  # the ordinary path
    assert a.outbox()[-1]["status"] == "acked"
    # an ack damaged as it is signed is refused before it is stored (ack.self_invalid,
    # round 13): the sender receives nothing, its message stays unacked
    _bad_sign(monkeypatch)
    m = a.compose_info(b.card, "hello")
    seen_before = _seen_bytes(b)
    with pytest.raises(IntegrityError) as e:
        lw.deliver(a, b, m)
    assert e.value.reason == "ack.self_invalid"
    assert a.outbox()[-1]["msg_id"] == m["object"]["msg_id"]
    assert a.outbox()[-1]["status"] != "acked" and _seen_bytes(b) == seen_before
    assert lw.log.count(("b", "a", "ack")) == 1  # the sound exchange's only
    monkeypatch.undo()
    # a reply damaged AFTER receive (a sound one stored) is refused at the boundary
    real_receive = Node.receive

    def receive_then_damage(self, bundle):
        return [
            {**r, "object": {**r["object"], "sig": _flip(r["object"]["sig"])}}
            for r in real_receive(self, bundle)
        ]

    monkeypatch.setattr(Node, "receive", receive_then_damage)
    m2 = a.compose_info(b.card, "hello again")
    with pytest.raises(IntegrityError) as e:
        lw.deliver(a, b, m2)
    assert e.value.reason == "reply.invalid"
    assert a.outbox()[-1]["msg_id"] == m2["object"]["msg_id"]
    assert a.outbox()[-1]["status"] != "acked"
    assert lw.log.count(("b", "a", "ack")) == 1  # the refused ones never logged
    assert b.stored_reply(m2["object"]["msg_id"])[1] is None  # the stored ack is sound


def test_a_reply_of_an_unexpected_shape_is_refused_at_the_hold_inside_the_boundary(
    tmp_path, monkeypatch
):
    """Finding 2 (minor): the held name comes from the REQUEST, so a reply whose
    object is not even an object is refused by the validation inside the storage
    boundary — counted, ledgered pending_reply.invalid under the message's id, the
    mail unseen — never an exception out of the poll."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "hello"))
    msg_id = a.outbox()[-1]["msg_id"]
    shapes = [
        {"natively": PROTOCOL_VERSION, "kind": "ack", "object": [], "cards": [], "grants": []},
        {"natively": PROTOCOL_VERSION, "kind": "ack", "object": {}, "cards": [], "grants": []},
        [],
        None,
    ]
    real_receive = b.receive
    for shape in shapes:
        monkeypatch.setattr(b, "receive", lambda bundle, shape=shape: [shape])
        inbox_before = _inbox_len(fake)
        unseen_before = _unseen_mail_ids(fake, b, wb)
        s = wb.poll_once()
        assert s["storage_failures"] == 1 and s["complete"] is False and s["replies"] == 0
        assert any("pending_reply.invalid" in e and msg_id in e for e in s["errors"])
        assert _inbox_len(fake) == inbox_before and _unseen_mail_ids(fake, b, wb) == unseen_before
        assert wb._pending_replies() == [] and wb._aside_replies() == []
    (inv,) = [e for e in b.ledger.entries() if e["action"] == "pending_reply.invalid"]
    assert inv["msg_id"] == msg_id and wb._invalid_key(f"{msg_id}.ack.json") in inv["detail"]
    monkeypatch.setattr(b, "receive", real_receive)
    assert wb.poll_once()["replies"] == 1  # the real reply goes, held under the same name
    assert wa.poll_once()["applied"] == 1 and a.outbox()[-1]["status"] == "acked"

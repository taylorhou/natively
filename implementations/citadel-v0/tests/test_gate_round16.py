"""Round 16: the fifteenth gate's one MAJOR and two MINORs plus the Fable read's one
MINOR, a ruling each (V1 to V4), pinned.

V1  a standing MIRROR intent at step "truncated": the JSONL's last physical line that
    carries this intent's id (terminated, or short of only its newline) is bound to the
    marker — the ONE binding every found audit crosses (`_bind_visible_audit` ->
    `_bind_audit`: the audit of the store the marker names, the marker's tail hash) —
    BEFORE the termination newline and before any subordinate tail-stage work; a
    mismatch refuses by name with the JSONL, the mirror and the marker byte-identical,
    twice. Before, the newline was written first (round 15 bound the audit only inside
    the mirror stage's own truncated step; :778 covered the ledger's OWN tail marker).
V2  the repair verb's FRESH run over a JSONL short of only its newline with a mirror
    that does not DECODE: refused by the name round 13 gave an undecodable prose line
    (ledger.mirror_corrupt), BEFORE any JSONL write, both files byte-identical twice,
    no marker, no intent invented. Before, it was taken as case (a) and the newline
    written over it with nothing standing to finish anything.
V3  every automatic reply the in-process wire feeds back crosses the RECEIVER's
    outgoing boundary (`check_outgoing`: the reply validation plus the wire's size
    bound) before it is logged or delivered: an oversized ack is ack.invalid, a storage
    failure, nothing logged as sent, nothing delivered. Before, `check_reply` alone ran
    there and a correctly signed ack over 512 KiB was logged and delivered.
V4  the terminated sibling of the mend case — the last JSONL entry landed WITH its
    newline and the machine's own prose write then tore after an ASCII prefix, no
    intent standing — is mended under a finishing intent of the termination shape
    (bytes 0, the entry bound by the hash of its bytes, mirror_to the cut point),
    written FIRST; the mend, one audit and the marker's removal follow under it; a
    failure after the marker write resumes under the intent with exactly one audit;
    the multibyte sibling keeps its one-run repair; a strict prefix of an EARLIER
    entry's line is still refused (ledger.prose.mismatch). Before, the fresh run, every
    append and every receive refused it, a hand edit the only way out.

Kinds: FAILURE AFTER (V4 the injected failures after the marker write), RESTART
RECOVERY (V1 the standing mirror intent; V4 the retry over the standing intent),
framing (V2 the undecodable mirror; V4 the earlier-entry prefix), boundary (V3)."""

from __future__ import annotations

import json

import pytest

import natively.bundle as bundlemod
import natively.node as nodemod
from natively.adapters.local import LocalWire
from natively.canon import sha256_hex
from natively.cli import main
from natively.errors import IntegrityError
from natively.ledger import Ledger
from natively.objects import is_id

from .conftest import Clock, make_node
from .test_gate_round7 import _argv
from .test_gate_round10 import _with_history_over_mail
from .test_gate_round12 import _mirror_repair_at_truncated, _serialize, _torn_audit
from .test_gate_round13 import _no_markers
from .test_gate_round15 import MIRROR_AUDIT, TAIL_AUDIT, _audits, _entry_line, _fresh_mend_shape

# ---- V1. the mirror intent's visible audit is bound before the termination newline -------------


@pytest.mark.parametrize("fault", ["wrong-hash", "other-store"])
def test_a_mirror_intents_visible_audit_is_bound_before_the_termination_newline(
    tmp_path, capsys, fault
):
    """V1, the mirror entry point of round 15's :778 (RESTART RECOVERY): a mirror intent
    standing at "truncated" with its audit VISIBLE as the JSONL's last line, short of
    only its newline — the marker's tail hash not the audit's (`wrong-hash`), or the
    line under this intent's id a denial.repaired record, another store's audit
    (`other-store`): ledger.repair.intent_mismatch naming both hashes, or the action
    found and the audit expected, twice, with the JSONL, the mirror and the marker
    byte-identical; nothing terminated, nothing appended. Before, `repair_ledger`
    wrote the audit's newline first and the binding ran only inside the mirror stage's
    own truncated step, so the first refusal left the JSONL changed. The marker's hash
    restored (or the foreign line removed), the resume completes with exactly one
    mirror audit; verify exits 0. With `_bind_visible_audit` a no-op this test fails
    (the newline is written)."""
    a, b, wa, wb, fake, clock, intent, marker = _mirror_repair_at_truncated(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    before = (jsonl.read_bytes(), mirror.read_bytes())
    if fault == "wrong-hash":
        _torn_audit(b, intent, "unterminated")  # the audit landed, short of only its newline
        wrong = {**intent, "tail_sha256": "sha256:" + sha256_hex(b"other")}
        marker.write_text(json.dumps(wrong), encoding="utf-8")
        needles = (wrong["tail_sha256"], intent["tail_sha256"])
    else:
        b._repair_active = "ledger"  # another store's audit under this intent's id
        b.ledger.append(
            ts=b.ts(),
            actor="solo",
            grant_id=None,
            action="denial.repaired",
            params_hash=intent["tail_sha256"],
            outcome="recorded",
            detail=f"truncated {intent['bytes']} bytes; intent {intent['intent_id']}",
            intent_id=intent["intent_id"],
        )
        b._repair_active = None
        whole, prose = jsonl.read_bytes(), mirror.read_bytes()
        jsonl.write_bytes(whole[:-1])
        mirror.write_bytes(b"".join(prose.splitlines(keepends=True)[:-1]))
        needles = ("denial.repaired", MIRROR_AUDIT)
    assert not jsonl.read_bytes().endswith(b"\n")
    files = (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes())
    for _retry in range(2):
        assert main([*_argv(b), "ledger", "repair"]) == 2
        out, err = capsys.readouterr()
        assert "ledger.repair.intent_mismatch" in err, err
        assert all(n in err for n in needles), err
        assert "terminated" not in err and "truncated" not in out
        assert (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes()) == files, fault
    assert json.loads(marker.read_text())["step"] == "truncated"
    if fault == "wrong-hash":
        marker.write_text(json.dumps(intent), encoding="utf-8")
    else:
        jsonl.write_bytes(before[0])
        mirror.write_bytes(before[1])
    assert main([*_argv(b), "ledger", "repair"]) == 0
    assert _no_markers(b) and _audits(b) == (0, 1)
    assert main([*_argv(b), "ledger", "verify"]) == 0


# ---- V2. an undecodable mirror on a fresh run is refused before any write --------------------


@pytest.mark.parametrize("shape", ["torn-multibyte", "bad-byte"])
def test_an_undecodable_mirror_on_a_fresh_run_is_refused_before_any_write(tmp_path, capsys, shape):
    """V2 (framing): the last JSONL entry short of only its newline, no marker, and a
    mirror that does not decode — its last line torn INSIDE a multibyte character
    (`torn-multibyte`), or a stray byte before a whole last line (`bad-byte`):
    ledger.mirror_corrupt naming the mirror, twice, with the JSONL and the mirror
    byte-identical, no marker written, nothing appended, no termination intent. Before,
    `fresh_mend_point` returned None on the decoding failure and the newline was written
    with nothing standing to finish anything. The mirror restored, the same shape is
    case (a): terminated without an intent, no audit, verify exit 0."""
    b, whole, prose, head = _fresh_mend_shape(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    last = prose.split(b"\n")[:-1][-1]
    if shape == "torn-multibyte":
        multibyte = next(i for i, c in enumerate(last) if c >= 0x80)
        bad = head + last[: multibyte + 1]
    else:
        bad = head + b"\xff" + last + b"\n"
    mirror.write_bytes(bad)
    torn = jsonl.read_bytes()
    assert not torn.endswith(b"\n")
    for _retry in range(2):
        assert main([*_argv(b), "ledger", "repair"]) == 2
        out, err = capsys.readouterr()
        assert "ledger.mirror_corrupt" in err and str(mirror) in err, err
        assert "terminated" not in err and "intent" not in err and "truncated" not in out
        assert jsonl.read_bytes() == torn and mirror.read_bytes() == bad, shape
        assert _no_markers(b)
    mirror.write_bytes(prose)  # restored: case (a), the mirror whole
    assert main([*_argv(b), "ledger", "repair"]) == 0
    err = capsys.readouterr().err
    assert "terminated" in err and "intent" not in err
    assert _no_markers(b) and _audits(b) == (0, 0)
    assert jsonl.read_bytes() == whole and mirror.read_bytes() == prose
    assert main([*_argv(b), "ledger", "verify"]) == 0


# ---- V3. automatic local replies cross the receiver's outgoing boundary ----------------------


def test_an_oversized_automatic_local_reply_is_refused_at_the_receivers_boundary(
    tmp_path, monkeypatch
):
    """V3 (boundary), round 15's oversized-bundle test extended to the automatic local
    reply path: an ack whose valid card is duplicated past MAX_WIRE_BYTES — sound to
    `check_reply` (the signature, the card, the in_reply_to all hold) — is ack.invalid at
    `check_outgoing` directly, and at the in-process wire it is refused BEFORE it is
    logged or delivered: no (receiver, sender, ack) row in the log, the sender's receive
    never called, the message still pending in the sender's outbox. Before, `deliver`
    ran `check_reply` alone on replies and the ack went through. The same message
    delivered again, the reply at its real size crosses and the message is acked."""
    clock = Clock()
    a = make_node(tmp_path, "a", clock)
    b = make_node(tmp_path, "b", clock)
    a.pin(b.principal.public, "b")
    b.pin(a.principal.public, "a")
    wire = LocalWire()
    wire.deliver(a, b, a.compose_card())
    wire.deliver(b, a, b.compose_card())
    m = a.compose_info(b.card, "big")
    msg_id = m["object"]["msg_id"]
    copies = bundlemod.MAX_WIRE_BYTES // len(_serialize(b.card)) + 2
    real, inflated, delivered = b.receive, [], []

    def receive(bundle):
        inflated.extend({**r, "cards": r["cards"] * copies} for r in real(bundle))
        return list(inflated)

    monkeypatch.setattr(b, "receive", receive)
    monkeypatch.setattr(a, "receive", lambda bundle: delivered.append(bundle))
    with pytest.raises(IntegrityError) as e:
        wire.deliver(a, b, m)
    assert e.value.reason == "ack.invalid" and "bytes, over" in str(e.value)
    assert len(inflated) == 1 and len(_serialize(inflated[0])) > bundlemod.MAX_WIRE_BYTES
    names = (a.card["agent"]["name"], b.card["agent"]["name"])
    assert wire.log[-1] == (*names, "message") and (names[1], names[0], "ack") not in wire.log
    assert delivered == [] and a.outbox_entry(msg_id)["status"] == "pending"
    # directly: the reply validation alone passes it; the outgoing boundary refuses it
    assert b.check_reply(inflated[0]) is inflated[0]
    with pytest.raises(IntegrityError) as e:
        b.check_outgoing(inflated[0])
    assert e.value.reason == "ack.invalid" and "bytes, over" in str(e.value)
    monkeypatch.undo()
    replies = wire.deliver(a, b, m)  # the transport's duplicate: the stored ack, its real size
    assert [r["kind"] for r in replies] == ["ack"] and wire.log[-1] == (names[1], names[0], "ack")
    assert a.outbox_entry(msg_id)["status"] == "acked"


# ---- V4. the terminated sibling of the mend case is mended under a finishing intent ----------


def _terminated_mend_shape(tmp_path, prefix_len: int = 20):
    """The Fable read's shape (section D): b's last JSONL entry whole WITH its newline,
    no marker, the mirror's last line a non-blank strict prefix (`prefix_len` ASCII
    bytes) of that entry's prose — the machine's own prose write torn one write
    boundary after the mend case. Returns (b, the JSONL, the whole mirror, the mirror's
    whole lines before the torn one)."""
    a, b, wa, wb, fake, clock = _with_history_over_mail(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    whole, prose = jsonl.read_bytes(), mirror.read_bytes()
    lines = prose.split(b"\n")[:-1]
    head = b"".join(prose.splitlines(keepends=True)[:-1])
    mirror.write_bytes(head + lines[-1][:prefix_len])
    assert whole.endswith(b"\n") and _no_markers(b) and len(lines[-1]) > prefix_len
    return b, whole, prose, head


@pytest.mark.parametrize("prefix_len", [1, 20])
def test_the_terminated_sibling_of_the_mend_case_completes_in_one_run(tmp_path, capsys, prefix_len):
    """V4, no failure: the shape above repaired in one run — a finishing intent written
    first (the report says so; nothing to terminate), the mend, exactly one tail audit
    (its intent_id an rpr_ id in full, its params_hash the last entry's hash, its detail
    saying nothing cut), no marker left, the JSONL byte-identical, the mirror whole,
    verify exit 0, a second run idempotent, the next append landing. Before, the fresh
    run refused (ledger.repair.refused) and so did every append."""
    b, whole, prose, head = _terminated_mend_shape(tmp_path, prefix_len)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    assert main([*_argv(b), "ledger", "repair"]) == 0
    out, err = capsys.readouterr()
    assert "finishing intent" in err and "regenerated" in err and "repaired" in out
    assert "terminated under intent" not in err  # the newline was there: nothing to terminate
    assert _no_markers(b)
    assert jsonl.read_bytes().startswith(whole) and mirror.read_bytes().startswith(prose)
    assert _audits(b) == (1, 0)
    audit = b.ledger.entries()[-1]
    assert audit["action"] == TAIL_AUDIT and is_id(audit["intent_id"], "rpr_")
    assert audit["params_hash"] == "sha256:" + sha256_hex(_entry_line(whole))
    assert "nothing cut" in audit["detail"] and f"intent {audit['intent_id']}" in audit["detail"]
    assert main([*_argv(b), "ledger", "verify"]) == 0
    assert main([*_argv(b), "ledger", "repair"]) == 0  # idempotent
    assert _audits(b) == (1, 0) and _no_markers(b)
    b.receive(b.compose_card())  # the next append lands
    assert b.ledger.verify() == b.ledger.head()


@pytest.mark.parametrize("where", ["at-intent", "before-mend"])
def test_a_failure_after_the_finishing_intent_resumes_under_it_and_completes(
    tmp_path, capsys, monkeypatch, where
):
    """V4, FAILURE AFTER then RESTART RECOVERY: the run fails right after the marker is
    written (`terminate_tail` raising at the intent step, before it could find nothing
    to terminate) or after the marker advanced and before the mend
    (`mend_torn_prose_tail` raising). The marker stands at its step — file ledger.jsonl,
    bytes 0, the last entry's offset and hash, the mirror cut point — with the JSONL and
    the mirror byte-identical, and nothing appends over it; the retry finds the intent,
    completes the mend, appends exactly one audit, removes the marker; verify exits 0;
    a further run is idempotent."""
    b, whole, prose, head = _terminated_mend_shape(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    marker = b.state / "ledger-repair-pending.json"
    torn_mirror = mirror.read_bytes()
    seen: dict = {}
    if where == "at-intent":

        def terminate_tail(self, **kw):
            seen["marker"] = json.loads(marker.read_text())  # the intent already stands
            raise OSError(5, "Input/output error")

        monkeypatch.setattr(Ledger, "terminate_tail", terminate_tail)
        step = "intent"
    else:

        def mend(self):
            seen["marker"] = json.loads(marker.read_text())
            raise OSError(5, "Input/output error")

        monkeypatch.setattr(Ledger, "mend_torn_prose_tail", mend)
        step = "truncated"
    assert main([*_argv(b), "ledger", "repair"]) == 1
    capsys.readouterr()
    monkeypatch.undo()
    intent = json.loads(marker.read_text())
    assert intent["step"] == step and intent["file"] == "ledger.jsonl" and intent["bytes"] == 0
    assert seen["marker"]["intent_id"] == intent["intent_id"] and seen["marker"]["step"] == step
    entry = _entry_line(whole)
    assert intent["truncate_to"] == len(whole) - 1 - len(entry)
    assert intent["tail_sha256"] == "sha256:" + sha256_hex(entry)
    assert intent["mirror_to"] == len(head) and is_id(intent["intent_id"], "rpr_")
    assert jsonl.read_bytes() == whole and mirror.read_bytes() == torn_mirror
    with pytest.raises(IntegrityError) as e:  # nothing appends while the marker stands
        b.receive(b.compose_card())
    assert e.value.reason == "ledger.repair_pending"
    assert _audits(b) == (0, 0)
    assert main([*_argv(b), "ledger", "repair"]) == 0  # the retry finds the intent
    out, err = capsys.readouterr()
    assert "resuming" in err and "regenerated" in err
    assert _no_markers(b) and main([*_argv(b), "ledger", "verify"]) == 0
    assert _audits(b) == (1, 0)
    assert jsonl.read_bytes().startswith(whole) and mirror.read_bytes().startswith(prose)
    assert main([*_argv(b), "ledger", "repair"]) == 0 and _audits(b) == (1, 0)


def test_the_multibyte_sibling_keeps_its_one_run_repair(tmp_path, capsys, monkeypatch):
    """V4, the sibling one byte later pinned: the same terminated JSONL with the mirror's
    last line torn INSIDE a multibyte character (the em dash before the detail) is
    repaired in one run as before — the mirror stage's own intent (file ledger.prose.txt,
    bytes > 0), never a finishing intent of the tail stage, one mirror audit, no tail
    audit, the line regenerated, verify exit 0."""
    b, whole, prose, head = _terminated_mend_shape(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    last = prose.split(b"\n")[:-1][-1]
    multibyte = next(i for i, c in enumerate(last) if c >= 0x80)
    mirror.write_bytes(head + last[: multibyte + 1])
    markers: list[dict] = []
    real = nodemod._write_json

    def spy(path, v):
        if path.name.startswith("ledger-repair-pending"):
            markers.append(dict(v))
        return real(path, v)

    monkeypatch.setattr(nodemod, "_write_json", spy)
    assert main([*_argv(b), "ledger", "repair"]) == 0
    out, err = capsys.readouterr()
    assert "finishing intent" not in err and "termination intent" not in err
    assert markers and all(m["file"] == "ledger.prose.txt" and m["bytes"] > 0 for m in markers)
    assert _audits(b) == (0, 1) and _no_markers(b)
    assert jsonl.read_bytes().startswith(whole) and mirror.read_bytes().startswith(prose)
    assert main([*_argv(b), "ledger", "verify"]) == 0


def test_a_strict_prefix_of_an_earlier_entrys_line_on_a_terminated_jsonl_is_refused(
    tmp_path, capsys
):
    """V4, round 13's rule kept: the terminated JSONL with the mirror ending in a strict
    prefix of the SECOND-TO-LAST entry's line and the last entry's line missing is not
    a tear of this machine's — ledger.prose.mismatch naming the line, twice, both files
    byte-identical, no marker, no audit; the mirror restored to the last entry's prefix,
    the mend completes."""
    b, whole, prose, head = _terminated_mend_shape(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    lines = prose.split(b"\n")[:-1]
    bad = b"".join(prose.splitlines(keepends=True)[:-2]) + lines[-2][:20]
    mirror.write_bytes(bad)
    for _retry in range(2):
        assert main([*_argv(b), "ledger", "repair"]) == 2
        out, err = capsys.readouterr()
        assert "ledger.prose.mismatch" in err and "not of the entry landed last" in err, err
        assert "intent" not in err and "truncated" not in out and "regenerated" not in err
        assert jsonl.read_bytes() == whole and mirror.read_bytes() == bad
        assert _no_markers(b)
    assert _audits(b) == (0, 0)
    mirror.write_bytes(head + lines[-1][:20])
    assert main([*_argv(b), "ledger", "repair"]) == 0
    assert _no_markers(b) and _audits(b) == (1, 0)
    assert main([*_argv(b), "ledger", "verify"]) == 0


# ---- the round's self-gate: one MINOR, fixed in-family ------------------------------------------


@pytest.mark.parametrize("how", ["terminated", "unterminated"])
@pytest.mark.parametrize("action", [[], {}], ids=["list", "dict"])
def test_a_visible_line_that_is_not_an_entry_is_refused_by_the_ledgers_name_before_binding(
    tmp_path, capsys, how, action
):
    """Self-gate MINOR: the JSONL's last line under a standing mirror intent's id whose
    action is a list or a dict (not an entry of ours) — terminated or short of only its
    newline — is ledger.corrupt by name ("action is not a string", the ledger's own
    refusal for such a line at the load) at the binding, directly and through the verb,
    twice, with the JSONL, the mirror and the marker byte-identical. Before, the raw
    object reached the store lookup and raised TypeError there — fail closed, but
    unnamed."""
    a, b, wa, wb, fake, clock, intent, marker = _mirror_repair_at_truncated(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    _torn_audit(b, intent, "unterminated")  # the audit landed, short of only its newline
    whole = jsonl.read_bytes()
    audit = json.loads(whole.split(b"\n")[-1])
    assert audit["intent_id"] == intent["intent_id"]
    line = _serialize({**audit, "action": action})
    jsonl.write_bytes(
        whole.rpartition(b"\n")[0] + b"\n" + line + (b"\n" if how == "terminated" else b"")
    )
    files = (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes())
    with pytest.raises(IntegrityError) as e:
        b._bind_visible_audit("ledger", MIRROR_AUDIT, intent)
    assert e.value.reason == "ledger.corrupt" and "action is not a string" in str(e.value)
    for _retry in range(2):
        assert main([*_argv(b), "ledger", "repair"]) == 2
        out, err = capsys.readouterr()
        assert "ledger.corrupt" in err and "action is not a string" in err, err
        assert "TypeError" not in err and "terminated" not in err and "truncated" not in out
        assert (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes()) == files, how
    assert json.loads(marker.read_text())["step"] == "truncated"

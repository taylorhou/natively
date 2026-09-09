"""Round 17: the round-16 Fable read's three MINOR findings, a ruling each (W1 to W3),
pinned.

W1  a found audit of the ledger's OWN intent that is not the ledger's last entry — a
    chained entry hand-appended past it while the marker stood at "truncated" — refuses
    ledger.repair.intent_mismatch by name INSIDE the lookup every found audit crosses
    (`_repair_audit`), before the barrier and before the marker is promoted to "audited":
    the JSONL, the mirror and the marker byte-identical, twice, the marker still at
    "truncated". Before, the rule ran only at step "audited" (`_audit_identity`), so the
    first refusal left the marker one step past where the crash left it.
W2  the termination audit's one detail is true for both termination shapes: "its newline
    put back where an append had stopped short of it, or already there" — the terminated
    sibling never had a newline put back; a resume at "truncated" cannot know which run
    wrote it, so one covering text is the resumable choice. The needle "nothing cut" kept;
    the README carries the same words.
W3  a termination intent at step "intent" requires the bytes past its cut point to be
    EXACTLY the bound line (hash = tail_sha256) or that line plus its newline; a whole
    chained entry past the bound entry (short of only its newline, or terminated) refuses
    ledger.repair.intent_mismatch by name with nothing written, nothing terminated and the
    marker unchanged. At step "truncated" the one entry allowed past the bound one is this
    stage's own audit (whole, short of only its newline, or torn). Before, the whole
    foreign line passed the chain and the mirror check and was terminated under an intent
    whose hash names another entry, the audit saying "terminated the last entry".

Kinds: RESTART RECOVERY (W1 the standing mirror intent; W3 the standing termination
intent at both steps), framing (W3 the foreign entry), a durable record's text (W2)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from natively.canon import sha256_hex
from natively.cli import main
from natively.ledger import Ledger, entry_hash
from natively.objects import is_id

from .test_gate_round7 import _argv
from .test_gate_round11 import _write_marker
from .test_gate_round12 import _mirror_repair_at_truncated, _serialize, _tail_stage_after_its_audit
from .test_gate_round13 import _no_markers
from .test_gate_round15 import TAIL_AUDIT, _audits, _entry_line, _fresh_mend_shape
from .test_gate_round16 import _terminated_mend_shape

NEEDLE_W2 = "its newline put back where an append had stopped short of it, or already there"


def _foreign_entry(whole: bytes, detail: str) -> bytes:
    """A whole entry chained onto the JSONL `whole` (newline-terminated) as it stands,
    serialized WITHOUT its newline — what a hand or a foreign tool appends past the
    machine's bound line while a marker stands (nothing of ours appends then)."""
    last = json.loads(_entry_line(whole).decode("utf-8"))
    return _serialize(
        {
            "ts": "2026-09-08T11:00:00Z",
            "actor": "foreign",
            "grant_id": None,
            "action": "note",
            "params_hash": None,
            "outcome": "information",
            "prev_hash": entry_hash(last),
            "msg_id": None,
            "detail": detail,
            "direction": "in",
        }
    )


def _intent_left_at(b, monkeypatch, capsys, method: str) -> dict:
    """The repair verb's run over the shape already on disk failed inside `method`
    (an I/O error) right after the marker write that precedes it; the marker stands
    at the step the crash left. Returns the intent as recorded."""

    def fail(self, *a, **kw):
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(Ledger, method, fail)
    assert main([*_argv(b), "ledger", "repair"]) == 1
    capsys.readouterr()
    monkeypatch.undo()
    return json.loads((b.state / "ledger-repair-pending.json").read_text())


# ---- W1. the found audit's last-entry rule runs before the barrier and the promotion -------


def test_a_found_audit_that_is_not_the_last_entry_is_refused_before_the_barrier_and_promotion(
    tmp_path, capsys
):
    """W1, probe P1 of the round-16 read (RESTART RECOVERY): a mirror intent's audit
    landed and a chained entry was hand-appended past it while the marker stood at
    "truncated". The resume finds the audit by its id and refuses
    ledger.repair.intent_mismatch naming "not the ledger's last entry" — twice, with the
    JSONL, the mirror and the marker byte-identical and the marker still at "truncated".
    Before, the found audit was barriered and promoted to "audited" first, and the
    step-audited rule refused with the marker one step past where the crash left it. The
    foreign entry removed, the resume completes with exactly one mirror audit and verify
    exit 0. The round's mutation disables the shared `_refuse_displaced_audit` helper (a
    no-op at both call sites: the lookup in `_repair_audit` and the chain binding in
    `_bind_visible_audit`), and this test then fails (the marker at "audited" after run
    1). Taking the rule out of the lookup ALONE is masked here: since the round-17
    self-gate's F1 the binding reads the chain as the file stands and refuses first, so
    this test still refuses twice. The lookup's own rule is pinned on its own by round
    15's test_the_audit_lookup_matches_the_id_field_exactly_and_binds_the_tail_hash, which
    calls `_repair_audit` directly (the earlier of two tail audits refused by name)."""
    a, b, wa, wb, fake, clock, intent, marker = _mirror_repair_at_truncated(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    assert main([*_argv(b), "ledger", "repair"]) == 0  # the machine completes: the audit lands
    capsys.readouterr()
    assert not marker.exists() and _audits(b) == (0, 1)
    done = (jsonl.read_bytes(), mirror.read_bytes())
    b.ledger.append(  # not this machine's: an entry past the audit, then the marker as left
        ts=b.ts(),
        actor="foreign",
        grant_id=None,
        action="note",
        params_hash=None,
        outcome="information",
        detail="a foreign append past the audit while the marker stood",
    )
    assert b.ledger.entries()[-1]["action"] == "note"
    marker = _write_marker(b, intent)
    files = (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes())
    for _retry in range(2):
        assert main([*_argv(b), "ledger", "repair"]) == 2
        out, err = capsys.readouterr()
        assert json.loads(marker.read_text())["step"] == "truncated"  # never promoted
        assert (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes()) == files
        assert "ledger.repair.intent_mismatch" in err and "not the ledger's last entry" in err
        assert "nothing barriered, promoted or removed" in err
    jsonl.write_bytes(done[0])
    mirror.write_bytes(done[1])
    assert main([*_argv(b), "ledger", "repair"]) == 0
    assert _no_markers(b) and _audits(b) == (0, 1)
    assert main([*_argv(b), "ledger", "verify"]) == 0


# ---- W2. the termination audit's detail is true for both termination shapes ----------------


@pytest.mark.parametrize("shape", ["mend", "terminated"])
def test_the_termination_audits_detail_is_true_for_both_shapes(tmp_path, capsys, shape):
    """W2: the mend case (the newline put back) and its terminated sibling (the newline
    already there) each leave one tail audit whose detail says "terminated the last
    entry", "its newline put back where an append had stopped short of it, or already
    there" and "nothing cut" — one text true of both, since a resume at "truncated"
    cannot know whether an earlier run wrote the newline. The report says which shape
    ran; the README carries the same words."""
    if shape == "mend":
        b, whole, prose, head = _fresh_mend_shape(tmp_path)
    else:
        b, whole, prose, head = _terminated_mend_shape(tmp_path)
    assert main([*_argv(b), "ledger", "repair"]) == 0
    out, err = capsys.readouterr()
    assert ("terminated under intent" in err) == (shape == "mend")
    assert _no_markers(b) and _audits(b) == (1, 0)
    audit = b.ledger.entries()[-1]
    assert audit["action"] == TAIL_AUDIT and is_id(audit["intent_id"], "rpr_")
    assert "terminated the last entry" in audit["detail"]
    assert NEEDLE_W2 in audit["detail"] and "nothing cut" in audit["detail"]
    assert main([*_argv(b), "ledger", "verify"]) == 0
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
    assert NEEDLE_W2 in " ".join(readme.split())  # the README wraps the phrase


# ---- W3. the termination intent binds exactly the bound line at step intent ----------------


@pytest.mark.parametrize("terminated", [False, True], ids=["short-of-newline", "terminated"])
def test_a_termination_intent_at_step_intent_refuses_a_whole_foreign_entry_past_its_entry(
    tmp_path, capsys, monkeypatch, terminated
):
    """W3, probe P4 of the round-16 read (RESTART RECOVERY + framing): a termination
    intent standing at step "intent" (the run failed inside `terminate_tail`, right
    after the marker write), then a WHOLE chained entry hand-appended past the bound
    entry — short of only its newline, or with it. The resume refuses
    ledger.repair.intent_mismatch by name, twice, with the JSONL, the mirror and the
    marker byte-identical: nothing terminated, no audit, no prose line for the foreign
    entry. Before, the foreign line passed the chain and the mirror check and was
    terminated under an intent whose hash names another entry (rc 0, the audit saying
    "terminated the last entry"). The foreign entry removed, the resume completes with
    exactly one audit and verify exit 0. With the exact-bytes rule removed this test
    fails (rc 0 and the foreign line terminated)."""
    b, whole, prose, head = _terminated_mend_shape(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    marker = b.state / "ledger-repair-pending.json"
    intent = _intent_left_at(b, monkeypatch, capsys, "terminate_tail")
    assert intent["step"] == "intent" and intent["bytes"] == 0
    assert intent["tail_sha256"] == "sha256:" + sha256_hex(_entry_line(whole))
    foreign = _foreign_entry(whole, "a foreign append past the bound entry")
    with open(jsonl, "ab") as f:
        f.write(foreign + (b"\n" if terminated else b""))
    files = (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes())
    for _retry in range(2):
        assert main([*_argv(b), "ledger", "repair"]) == 2
        out, err = capsys.readouterr()
        assert "ledger.repair.intent_mismatch" in err, err
        assert "past the termination intent's entry" in err and "before any step" in err
        assert "terminated under intent" not in err and "regenerated" not in err
        assert (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes()) == files
        assert json.loads(marker.read_text())["step"] == "intent"
    assert b"ledger.tail_truncated" not in jsonl.read_bytes()
    jsonl.write_bytes(whole)  # the foreign entry removed
    assert main([*_argv(b), "ledger", "repair"]) == 0
    out, err = capsys.readouterr()
    assert "resuming" in err and "regenerated" in err
    assert _no_markers(b) and _audits(b) == (1, 0)
    assert jsonl.read_bytes().startswith(whole) and mirror.read_bytes().startswith(prose)
    assert main([*_argv(b), "ledger", "verify"]) == 0


@pytest.mark.parametrize("shape", ["alone", "terminated"])
def test_the_two_legitimate_shapes_at_step_intent_still_complete(
    tmp_path, capsys, monkeypatch, shape
):
    """W3, the shapes the rule admits: the bound line alone (the mend case, the run
    failed before its newline was put back) and the bound line plus its newline (the
    terminated sibling) — each resumes at step "intent" and completes with exactly one
    audit, no marker, verify exit 0; the report says whether a newline was written."""
    if shape == "alone":
        b, whole, prose, head = _fresh_mend_shape(tmp_path)
    else:
        b, whole, prose, head = _terminated_mend_shape(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    intent = _intent_left_at(b, monkeypatch, capsys, "terminate_tail")
    assert intent["step"] == "intent"
    assert jsonl.read_bytes() == (whole[:-1] if shape == "alone" else whole)
    assert main([*_argv(b), "ledger", "repair"]) == 0
    out, err = capsys.readouterr()
    assert "resuming" in err and ("terminated under intent" in err) == (shape == "alone")
    assert _no_markers(b) and _audits(b) == (1, 0)
    assert jsonl.read_bytes().startswith(whole) and mirror.read_bytes().startswith(prose)
    assert main([*_argv(b), "ledger", "verify"]) == 0


@pytest.mark.parametrize("terminated", [False, True], ids=["short-of-newline", "terminated"])
def test_a_termination_intent_at_step_truncated_admits_only_its_own_audit_past_its_entry(
    tmp_path, capsys, monkeypatch, terminated
):
    """W3 at step "truncated" (RESTART RECOVERY + framing): the intent's newline step
    done, the run failed inside the mend; then a whole chained entry that is NOT this
    stage's audit hand-appended past the bound entry. The resume refuses
    ledger.repair.intent_mismatch by name, twice, byte-identical, the marker still at
    "truncated", no audit appended after the foreign line. The foreign entry removed,
    the resume completes with exactly one audit and verify exit 0."""
    b, whole, prose, head = _terminated_mend_shape(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    marker = b.state / "ledger-repair-pending.json"
    intent = _intent_left_at(b, monkeypatch, capsys, "mend_torn_prose_tail")
    assert intent["step"] == "truncated" and jsonl.read_bytes() == whole
    foreign = _foreign_entry(whole, "a foreign append past the bound entry at truncated")
    with open(jsonl, "ab") as f:
        f.write(foreign + (b"\n" if terminated else b""))
    files = (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes())
    for _retry in range(2):
        assert main([*_argv(b), "ledger", "repair"]) == 2
        out, err = capsys.readouterr()
        assert "ledger.repair.intent_mismatch" in err, err
        assert "not this stage's one audit" in err and "None" in err
        assert "terminated under intent" not in err and "regenerated" not in err
        assert (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes()) == files
        assert json.loads(marker.read_text())["step"] == "truncated"
    assert b"ledger.tail_truncated" not in jsonl.read_bytes()
    jsonl.write_bytes(whole)
    assert main([*_argv(b), "ledger", "repair"]) == 0
    assert _no_markers(b) and _audits(b) == (1, 0)
    assert mirror.read_bytes().startswith(prose)
    assert main([*_argv(b), "ledger", "verify"]) == 0


# ---- the round-17 self-gate's three MINORs, fixed in-family --------------------------------


@pytest.mark.parametrize("shape", ["unterminated", "torn-prose"])
def test_a_displaced_mirror_audit_is_refused_before_the_termination_and_the_mends(
    tmp_path, capsys, shape
):
    """Self-gate finding 1 (RESTART RECOVERY): W1's shape on the mirror path with a write
    still ahead of the lookup's rule — the foreign entry past the audit short of only its
    newline (`repair_ledger` terminated it before the mirror stage refused), or terminated
    with its prose line torn after an ASCII prefix (the mirror stage's mend regenerated it
    first). The visible-audit binding now reads the chain as the file stands and refuses
    the displaced audit before either write: rc 2 twice, all three files byte-identical,
    the marker still at "truncated", no newline written, nothing regenerated. The foreign
    entry removed, the resume completes with exactly one mirror audit."""
    a, b, wa, wb, fake, clock, intent, marker = _mirror_repair_at_truncated(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    assert main([*_argv(b), "ledger", "repair"]) == 0
    capsys.readouterr()
    done = (jsonl.read_bytes(), mirror.read_bytes())
    b.ledger.append(
        ts=b.ts(),
        actor="foreign",
        grant_id=None,
        action="note",
        params_hash=None,
        outcome="information",
        detail="a foreign append past the audit while the marker stood",
    )
    whole, prose = jsonl.read_bytes(), mirror.read_bytes()
    if shape == "unterminated":
        jsonl.write_bytes(whole[:-1])  # the foreign entry short of only its newline
    else:
        lines = prose.split(b"\n")[:-1]
        mirror.write_bytes(b"".join(prose.splitlines(keepends=True)[:-1]) + lines[-1][:20])
    marker = _write_marker(b, intent)
    files = (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes())
    for _retry in range(2):
        assert main([*_argv(b), "ledger", "repair"]) == 2
        out, err = capsys.readouterr()
        assert json.loads(marker.read_text())["step"] == "truncated"
        assert (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes()) == files, shape
        assert "ledger.repair.intent_mismatch" in err and "not the ledger's last entry" in err
        assert "lacked only its newline" not in err and "regenerated" not in err
    jsonl.write_bytes(done[0])
    mirror.write_bytes(done[1])
    assert main([*_argv(b), "ledger", "repair"]) == 0
    assert _no_markers(b) and _audits(b) == (0, 1)
    assert main([*_argv(b), "ledger", "verify"]) == 0


def test_a_torn_tail_past_a_complete_termination_audit_is_refused(tmp_path, capsys, monkeypatch):
    """Self-gate finding 2 (framing): a termination intent at "truncated" whose audit
    landed WHOLE, then a torn tail appended past it. The audit's append ran once, so the
    tear is not this machine's: ledger.repair.intent_mismatch by name twice, all three
    files byte-identical, nothing cut. Before, the torn bytes were cut as the audit's own
    tear and the audit reused. The torn bytes removed, the resume completes with that one
    audit."""
    b, whole, prose, head = _terminated_mend_shape(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    marker = b.state / "ledger-repair-pending.json"
    intent = _intent_left_at(b, monkeypatch, capsys, "terminate_tail")
    assert main([*_argv(b), "ledger", "repair"]) == 0  # the machine completes: one audit
    capsys.readouterr()
    assert _no_markers(b) and _audits(b) == (1, 0)
    done = (jsonl.read_bytes(), mirror.read_bytes())
    with open(jsonl, "ab") as f:
        f.write(b'{"foreign":')
    marker.write_text(json.dumps({**intent, "step": "truncated"}), encoding="utf-8")
    files = (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes())
    for _retry in range(2):
        assert main([*_argv(b), "ledger", "repair"]) == 2
        out, err = capsys.readouterr()
        assert (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes()) == files
        assert "ledger.repair.intent_mismatch" in err and "torn tail" in err, err
        assert "landed whole" in err and "cut again" not in err
    jsonl.write_bytes(done[0])
    assert main([*_argv(b), "ledger", "repair"]) == 0
    assert _no_markers(b) and _audits(b) == (1, 0)
    assert main([*_argv(b), "ledger", "verify"]) == 0


@pytest.mark.parametrize("nested", [False, True], ids=["own-marker", "nested"])
def test_a_cut_intent_at_step_truncated_admits_only_its_own_audit_past_its_cut_point(
    tmp_path, capsys, nested
):
    """Self-gate finding 3 (RESTART RECOVERY + framing): a CUT intent (bytes > 0, the
    ledger's own marker or the nested one under a standing mirror intent) at "truncated",
    the cut done, no audit yet, and a whole chained entry that is not this stage's audit
    past the cut point. The same rule the termination intent has: ledger.repair.intent_mismatch
    by name twice, every file and marker byte-identical. Before, the foreign entry was kept,
    its prose regenerated and the audit appended after it. The stage's own audit put back
    in its place, the resume completes with exactly one tail audit."""
    b, intent, marker, mirror_marker = _tail_stage_after_its_audit(tmp_path, nested)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    done = (jsonl.read_bytes(), mirror.read_bytes())
    prefix = done[0][: intent["truncate_to"]]
    assert prefix.endswith(b"\n")
    jsonl.write_bytes(
        prefix + _foreign_entry(prefix, "a foreign append past the cut point") + b"\n"
    )
    mirror.write_bytes(b"".join(done[1].splitlines(keepends=True)[:-1]))
    markers = [marker] + ([mirror_marker] if mirror_marker is not None else [])
    files = (jsonl.read_bytes(), mirror.read_bytes(), *[m.read_bytes() for m in markers])
    for _retry in range(2):
        assert main([*_argv(b), "ledger", "repair"]) == 2
        out, err = capsys.readouterr()
        assert (
            jsonl.read_bytes(),
            mirror.read_bytes(),
            *[m.read_bytes() for m in markers],
        ) == files
        assert "ledger.repair.intent_mismatch" in err and "not this stage's one audit" in err
        assert "cut point" in err and "regenerated" not in err
        assert json.loads(marker.read_text())["step"] == "truncated"
    assert b"ledger.tail_truncated" not in jsonl.read_bytes()
    jsonl.write_bytes(done[0])
    mirror.write_bytes(done[1])
    assert main([*_argv(b), "ledger", "repair"]) == 0
    assert _no_markers(b) and _audits(b)[0] == 1
    assert main([*_argv(b), "ledger", "verify"]) == 0

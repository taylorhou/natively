"""Round 18: the round-17 codex gate's two MINOR findings, a ruling each (X1, X2), pinned.

X1  on the MIRROR path at step "truncated", the binding of the visible audit reads the
    chain as the file stands; every entry there under the intent's id is bound by action
    AND hash (`_bind_audit`) before its displacement is judged, and torn bytes past an
    audit that landed whole refuse ledger.repair.intent_mismatch by name BEFORE the
    subordinate tail stage is entered: nothing cut, nothing appended, the JSONL, the
    mirror and the marker byte-identical, twice, the marker still at "truncated". Before,
    the chain scan ignored the torn tail and judged displacement only: the subordinate
    stage cut those bytes as the audit's own tear and appended its tail audit after the
    mirror audit, and the mirror stage then refused that displacement on every retry —
    stuck, with a cut and an append on the first run. A matching entry whose hash does
    not bind, or whose action is another store's audit, refuses the same way by name.
X2  a description only: the W1 test's mutation note (tests/test_gate_round17.py) names
    what the round's mutation script disables — the shared `_refuse_displaced_audit`
    helper at both call sites — and the direct-lookup pin that stays separate (round 15,
    test_the_audit_lookup_matches_the_id_field_exactly_and_binds_the_tail_hash). No test
    here; the lookup-only mutation is masked by the binding and the round-15 test catches
    it.

Kinds: RESTART RECOVERY (X1 the standing mirror intent), framing (X1 the torn tail)."""

from __future__ import annotations

import json

import pytest

from natively.canon import sha256_hex
from natively.cli import main
from natively.node import LEDGER_TAIL_MARKER

from .test_gate_round7 import _argv
from .test_gate_round11 import _write_marker
from .test_gate_round12 import _mirror_repair_at_truncated, _serialize
from .test_gate_round13 import _no_markers
from .test_gate_round15 import TAIL_AUDIT, _audits

TORN = b'{"foreign":'


def _completed_mirror_repair(tmp_path, capsys):
    """The round-12 shape run to completion: the mirror audit is the ledger's last
    entry, whole and terminated, no marker. Returns (b, intent, done) with `done` the
    (JSONL, mirror) bytes of the finished repair."""
    a, b, wa, wb, fake, clock, intent, marker = _mirror_repair_at_truncated(tmp_path)
    assert main([*_argv(b), "ledger", "repair"]) == 0
    capsys.readouterr()
    assert _no_markers(b) and _audits(b) == (0, 1)
    return b, intent, (b.ledger.path.read_bytes(), b.ledger.prose_path.read_bytes())


def _refused_twice_unchanged(b, marker, capsys) -> list[tuple[str, str]]:
    """`ledger repair` exits 2 twice with the JSONL, the mirror and the marker
    byte-identical, the marker still at "truncated", no nested marker written, no
    tail audit appended (the bytes are identical) and no cut reported. Returns the (out,
    err) of each run."""
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    nested = b.state / LEDGER_TAIL_MARKER
    files = (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes())
    runs = []
    for _retry in range(2):
        assert main([*_argv(b), "ledger", "repair"]) == 2
        out, err = capsys.readouterr()
        assert (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes()) == files
        assert not nested.exists()
        assert json.loads(marker.read_text())["step"] == "truncated"
        assert "ledger.repair.intent_mismatch" in err, err
        assert "torn byte(s)" not in out and "under a standing mirror repair" not in err
        runs.append((out, err))
    return runs


# ---- X1. torn bytes past the complete mirror audit refuse before the nested repair ---------


def test_a_torn_tail_past_the_complete_mirror_audit_is_refused_before_the_nested_repair(
    tmp_path, capsys
):
    """X1, the gate's shape (RESTART RECOVERY + framing): a mirror intent's audit landed
    whole and terminated, then torn bytes were appended past it, and the marker stands at
    "truncated". The audit's append ran once, so the tear is not this machine's: refused
    by name twice with nothing cut, nothing appended, no nested marker, all three files
    byte-identical. Before, the subordinate tail stage cut the bytes and appended its audit
    after the mirror audit, and the mirror stage then refused the displacement on every
    retry. The torn bytes removed, the resume completes with that one mirror audit."""
    b, intent, done = _completed_mirror_repair(tmp_path, capsys)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    with open(jsonl, "ab") as f:
        f.write(TORN)
    marker = _write_marker(b, intent)
    for _out, err in _refused_twice_unchanged(b, marker, capsys):
        assert "torn tail" in err and "landed whole" in err and str(len(TORN)) in err
        assert "not the ledger's last entry" not in err and "names tail hash" not in err
    jsonl.write_bytes(done[0])
    assert main([*_argv(b), "ledger", "repair"]) == 0
    assert _no_markers(b) and _audits(b) == (0, 1)
    assert (jsonl.read_bytes(), mirror.read_bytes()) == done
    assert main([*_argv(b), "ledger", "verify"]) == 0


@pytest.mark.parametrize("torn", [True, False], ids=["behind-a-torn-tail", "visible"])
def test_a_mirror_audit_whose_hash_does_not_bind_is_refused_by_the_chain_binding(
    tmp_path, capsys, torn
):
    """X1, the wrong-hash variant: the marker's tail hash is not the one the audit
    recorded. Behind a torn tail the visible-tail binding sees no audit (the last
    physical line is the torn bytes), so the chain binding is what refuses — by name,
    naming both hashes, before the torn tail is judged and before the nested repair;
    with the audit visible the same refusal comes from either binding (round 15 pinned
    the visible one). Twice, byte-identical, nothing cut, nothing appended. The marker
    put right and the torn bytes removed, the resume completes."""
    b, intent, done = _completed_mirror_repair(tmp_path, capsys)
    jsonl = b.ledger.path
    if torn:
        with open(jsonl, "ab") as f:
            f.write(TORN)
    wrong = {**intent, "tail_sha256": "sha256:" + sha256_hex(b"other")}
    marker = _write_marker(b, wrong)
    for _out, err in _refused_twice_unchanged(b, marker, capsys):
        assert "names tail hash" in err and wrong["tail_sha256"] in err, err
        assert intent["tail_sha256"] in err and "torn tail" not in err
    jsonl.write_bytes(done[0])
    marker.write_text(json.dumps(intent), encoding="utf-8")
    assert main([*_argv(b), "ledger", "repair"]) == 0
    assert _no_markers(b) and _audits(b) == (0, 1)
    assert main([*_argv(b), "ledger", "verify"]) == 0


def test_a_chain_entry_under_the_intents_id_with_another_stores_action_is_refused(tmp_path, capsys):
    """X1, the action half of the binding: the last entry carries the mirror intent's
    id and its tail hash but is a ledger.tail_truncated record (the audit of the
    JSONL, not of the mirror the marker names), hidden behind a torn tail. Refused by
    name twice naming the record's action, byte-identical, nothing cut, nothing
    appended. Before, the scan bound nothing and the nested stage cut and appended."""
    b, intent, done = _completed_mirror_repair(tmp_path, capsys)
    jsonl = b.ledger.path
    lines = done[0].split(b"\n")
    assert lines[-1] == b""
    audit = json.loads(lines[-2].decode("utf-8"))
    assert audit["intent_id"] == intent["intent_id"]
    forged = _serialize({**audit, "action": TAIL_AUDIT})
    jsonl.write_bytes(b"\n".join(lines[:-2]) + b"\n" + forged + b"\n" + TORN)
    marker = _write_marker(b, intent)
    for _out, err in _refused_twice_unchanged(b, marker, capsys):
        assert f"is a {TAIL_AUDIT!r} record" in err and "torn tail" not in err, err
    jsonl.write_bytes(done[0])
    assert main([*_argv(b), "ledger", "repair"]) == 0
    assert _no_markers(b) and _audits(b) == (0, 1)
    assert main([*_argv(b), "ledger", "verify"]) == 0


def test_the_mirror_audits_own_torn_append_is_still_cut_under_the_nested_stage(tmp_path, capsys):
    """X1, the shape the rule leaves alone: no audit landed yet and the JSONL's tail
    is a torn partial line (the mirror audit's own append interrupted). Nothing in the
    chain carries the intent's id, so the binding refuses nothing: the subordinate tail
    stage cuts the bytes, ledgers them once, and the mirror audit then lands — the
    round-12 double fault, unchanged."""
    a, b, wa, wb, fake, clock, intent, marker = _mirror_repair_at_truncated(tmp_path)
    with open(b.ledger.path, "ab") as f:
        f.write(TORN)
    assert main([*_argv(b), "ledger", "repair"]) == 0
    out = capsys.readouterr().out
    assert "torn byte(s)" in out
    assert _no_markers(b) and _audits(b) == (1, 1)
    assert main([*_argv(b), "ledger", "verify"]) == 0

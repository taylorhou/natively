"""Round 15: the fourteenth gate's three MAJORs and the Fable read's two observations,
a ruling each (U1 to U5), pinned.

U1  the helper's --json path: a part whose mimeType is not a NON-EMPTY string — "" as
    well as missing or non-string — is unavailable at any depth, the reason naming the
    part; the adapter round trip (unseen, nothing ledgered, the clocks unmoved; the
    mimeType restored, the same mail applies); the text dump unchanged.
U2  the repair verb's FRESH run over a whole last JSONL entry short of only its newline
    decides the mirror's state BEFORE any write: (a) a mirror consistent with the
    completed chain — terminated as before, no marker; (b) the mirror's last line a
    non-blank strict prefix of that entry's prose — a TERMINATION intent for the
    ledger's own tail stage is written FIRST (bytes 0, the entry bound by hash, the
    mirror cut point recorded), then the newline, the mend, the audit and the marker's
    removal under it, a failure after the newline resumed under that intent; (c)
    anything else refused by name with both files byte-identical and no marker.
U3  the typed loader validates a repair intent's id IN FULL; the audit lookup matches
    the intent id by EQUALITY on the audit's own intent_id field, never by the detail's
    text; a found audit is bound to the marker's tail hash and store name before it is
    trusted.
U4  one undelivered audit per outbox transition: the audit is looked up by its key
    (msg_id, the attempt count it names) before it is appended, so a retry after a
    failed outbox write appends nothing.
U5  the startup sweep (every replay of a held revocation) runs the ledger's full check
    BEFORE the first feed line lands: a failing check leaves the feed untouched, named
    in the replay marker.

Kinds: FAILURE AFTER (U2 the injected failures after the newline; U4 the injected
outbox write failure), RESTART RECOVERY (U2 the retry over the standing intent; U5 a
fresh Node over the state the last one left), framing (U1, U2 (c), U3 the staged
markers).

The round's one self-gate (BLOCK: four MAJORs, two MINORs), each fixed in-family and
pinned at the end of this module: (1) the helper checks the WHOLE part tree before a
body is selected, so a damaged part after the first text found is an incomplete fetch
too; (2) an audit visible on the JSONL is bound to the marker BEFORE any mend writes;
(3) an entry under the intent's id with another store's action is a mismatch, never
"absent"; (4) the undelivered status waits for the ledger barrier over the audit it
found; (minor 1) the root part is named in the mimeType reason; (minor 2) a bundle
over the wire's size bound is <kind>.invalid at the outgoing boundary, a storage
failure, never a transport failure at the send."""

from __future__ import annotations

import json

import pytest

import natively.bundle as bundlemod
import natively.node as nodemod
from natively.adapters.mail import WIRE_CHARS
from natively.canon import sha256_hex
from natively.cli import main
from natively.errors import IntegrityError
from natively.ledger import OUT_SEND, Ledger, entry_hash
from natively.node import REPLAY_MARKER
from natively.objects import is_id, new_id

from .conftest import Clock, make_node
from .test_gate_round5 import _ino, _record_syncs
from .test_gate_round6 import _connected_over_mail, _drop_last_line, _running
from .test_gate_round7 import _argv, _ledger_fsync_failing_after, _pinned_held_healthy
from .test_gate_round7b import _actions
from .test_gate_round8 import _unseen_mail_ids
from .test_gate_round10 import _with_history_over_mail
from .test_gate_round11 import _write_marker
from .test_gate_round12 import _mirror_repair_at_truncated, _serialize, _tail_stage_after_its_audit
from .test_gate_round13 import (
    _b64url,
    _gmail_api,
    _gmail_message,
    _no_markers,
    _unmoved,
    _wire_text,
)
from .test_gate_round14 import WIRE, _complete, _never, _unavailable

TAIL_AUDIT = "ledger.tail_truncated"
MIRROR_AUDIT = "ledger.mirror_truncated"


def _audits(b) -> tuple[int, int]:
    acts = _actions(b)
    return acts.count(TAIL_AUDIT), acts.count(MIRROR_AUDIT)


# ---- U1. an empty mimeType is never "not a text part" (framing + the adapter) ---------------


def test_a_child_part_with_an_empty_mimetype_is_unavailable_at_any_depth(tmp_path):
    """U1: a child part whose mimeType is "" and whose body carries data, at depth 1 and
    at depth 2, is an INCOMPLETE FETCH on the --json path, the reason naming the part
    (its partId); so is every other non-string or empty value. The text dump yields ""
    for the shape as before. Through the adapter: the mail unseen, nothing ledgered,
    the clocks unmoved; the mimeType restored, the same mail applies. Before, the
    empty string was passed over as "not a text part" and the row went out complete
    and empty (round-14 gate, finding 1)."""
    api = _gmail_api()
    m = _gmail_message("g-emptymime", WIRE, inline=True)
    m["payload"]["parts"][0]["mimeType"] = ""  # depth 1, the body data present
    _unavailable(api.msg_row(m, WIRE_CHARS, _never), "empty or missing mimeType", "partId 0")
    assert api.body_of(m["payload"]) == ""  # the text dump, unchanged
    m["payload"]["parts"][0]["mimeType"] = "text/plain"
    _complete(api.msg_row(m, WIRE_CHARS, _never), WIRE.strip())
    m["payload"]["parts"] = [  # depth 2
        {
            "partId": "0",
            "mimeType": "multipart/alternative",
            "body": {"size": 0},
            "parts": [
                {
                    "partId": "0.0",
                    "mimeType": "",
                    "body": {"size": len(WIRE), "data": _b64url(WIRE)},
                }
            ],
        }
    ]
    _unavailable(api.msg_row(m, WIRE_CHARS, _never), "empty or missing mimeType", "partId 0.0")
    assert api.body_of(m["payload"]) == ""
    for bad in (None, 0, False, [], {}, 7):
        m["payload"]["parts"][0]["parts"][0]["mimeType"] = bad
        _unavailable(api.msg_row(m, WIRE_CHARS, _never), "empty or missing mimeType", "partId 0.0")
    m["payload"]["parts"][0]["parts"][0]["mimeType"] = "text/plain"
    _complete(api.msg_row(m, WIRE_CHARS, _never), WIRE.strip())
    # the adapter round trip
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wire = _wire_text(a, b, "whole")
    m = _gmail_message("g-emptymime-2", wire, inline=True)
    m["payload"]["parts"][0]["mimeType"] = ""
    row = api.msg_row(m, WIRE_CHARS, _never)
    _unavailable(row, "empty or missing mimeType", "partId 0")
    fake.inbox.setdefault("taylor@teale.com", []).append(row)
    before, entries = _unmoved(b, wb), len(b.ledger.entries())
    s = wb.poll_once()
    assert s["applied"] == 0 and s["complete"] is False and s["storage_failures"] == 0
    assert any("could not be obtained" in x and "g-emptymime-2" in x for x in s["errors"])
    assert _unmoved(b, wb) == before and len(b.ledger.entries()) == entries
    assert _unseen_mail_ids(fake, b, wb) == {"g-emptymime-2"}
    m["payload"]["parts"][0]["mimeType"] = "text/plain"
    fake.inbox["taylor@teale.com"][-1] = api.msg_row(m, WIRE_CHARS, _never)
    s = wb.poll_once()
    assert s["applied"] == 1 and s["complete"] is True
    assert b.ledger.entries()[-1]["detail"] == "whole"


# ---- U2. the fresh run decides the mirror before any write ----------------------------------


def _fresh_mend_shape(tmp_path, prefix_len: int = 20):
    """The round-14 gate's reported shape: b's last JSONL entry whole short of only its
    newline, no marker, the mirror's last line a non-blank strict prefix (`prefix_len`
    ASCII bytes: the timestamp) of that entry's prose. Returns (b, the JSONL as it was,
    the mirror as it was, the mirror's whole lines before the torn one)."""
    a, b, wa, wb, fake, clock = _with_history_over_mail(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    whole, prose = jsonl.read_bytes(), mirror.read_bytes()
    lines = prose.split(b"\n")[:-1]
    head = b"".join(prose.splitlines(keepends=True)[:-1])
    jsonl.write_bytes(whole[:-1])
    mirror.write_bytes(head + lines[-1][:prefix_len])
    assert _no_markers(b) and len(lines[-1]) > prefix_len
    return b, whole, prose, head


def _entry_line(whole: bytes) -> bytes:
    """The bytes of the last entry of `whole` (a newline-terminated JSONL)."""
    return whole[:-1].split(b"\n")[-1]


def test_the_fresh_mend_case_completes_in_one_run_under_a_termination_intent(tmp_path, capsys):
    """U2 (b), no failure: the shape above repaired in one run — a termination intent
    written first (the report says so), the newline, the mend, exactly one tail audit
    (its intent_id an rpr_ id in full, its params_hash the terminated entry's hash, its
    detail saying terminated and mended, nothing cut), no marker left, verify exit 0,
    a second run idempotent. Before, the newline was written and the run failed on
    the mirror with no intent to finish the mend (round-14 gate, finding 2)."""
    b, whole, prose, head = _fresh_mend_shape(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    assert main([*_argv(b), "ledger", "repair"]) == 0
    out, err = capsys.readouterr()
    assert "termination intent" in err and "terminated under intent" in err
    assert "regenerated" in err and "repaired" in out
    assert _no_markers(b)
    assert jsonl.read_bytes().startswith(whole) and mirror.read_bytes().startswith(prose)
    assert _audits(b) == (1, 0)
    audit = b.ledger.entries()[-1]
    assert audit["action"] == TAIL_AUDIT and is_id(audit["intent_id"], "rpr_")
    assert audit["params_hash"] == "sha256:" + sha256_hex(_entry_line(whole))
    assert "terminated the last entry" in audit["detail"] and "nothing cut" in audit["detail"]
    assert f"intent {audit['intent_id']}" in audit["detail"]
    assert main([*_argv(b), "ledger", "verify"]) == 0
    assert main([*_argv(b), "ledger", "repair"]) == 0  # idempotent
    assert _audits(b) == (1, 0) and _no_markers(b)


@pytest.mark.parametrize("where", ["after-newline", "before-mend"])
def test_a_failure_after_the_newline_resumes_under_the_intent_and_completes(
    tmp_path, capsys, monkeypatch, where
):
    """U2 (b), FAILURE AFTER then RESTART RECOVERY: the run fails right after the newline
    landed (`terminate_tail` raising after its write; the intent already stands at
    that moment, recorded from inside the patched write) or after the marker advanced
    and before the mend (`mend_torn_prose_tail` raising). The marker stands at its
    step — file ledger.jsonl, bytes 0, the entry's hash, the mirror cut point — and
    nothing appends over it; the retry finds the intent, completes the mend, appends
    exactly one audit, removes the marker; verify exits 0; a further run is idempotent."""
    b, whole, prose, head = _fresh_mend_shape(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    marker = b.state / "ledger-repair-pending.json"
    torn_mirror = mirror.read_bytes()
    seen: dict = {}
    if where == "after-newline":
        real = Ledger.terminate_tail

        def terminate_tail(self, **kw):
            seen["marker"] = json.loads(marker.read_text())  # the intent BEFORE the newline
            assert real(self, **kw) is True and jsonl.read_bytes() == whole
            raise OSError(5, "Input/output error")  # after the newline write

        monkeypatch.setattr(Ledger, "terminate_tail", terminate_tail)
        step = "intent"
    else:

        def mend(self):
            seen["marker"] = json.loads(marker.read_text())
            raise OSError(5, "Input/output error")  # before the mend

        monkeypatch.setattr(Ledger, "mend_torn_prose_tail", mend)
        step = "truncated"
    assert main([*_argv(b), "ledger", "repair"]) == 1  # the OSError, one line
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


REFUSED = {
    "non-prefix": (b"zzz", "ledger.prose.mismatch"),
    "blank-partial": (b"   ", "ledger.prose.mismatch"),
    "unicode-blank-partial": ("  ".encode(), "ledger.prose.mismatch"),
    "whole-mismatch": (b"zzz\n", "ledger.prose.mismatch"),
    "blank-beyond": (None, "ledger.repair.refused"),
    "earlier-prefix": (None, "ledger.prose.mismatch"),
}


@pytest.mark.parametrize("shape", list(REFUSED), ids=list(REFUSED))
def test_every_other_mirror_shape_is_refused_with_both_files_byte_identical(
    tmp_path, capsys, shape
):
    """U2 (c): the same unterminated entry, the mirror in a shape that is neither
    consistent with the completed chain nor the mend case — a non-prefix partial line,
    a blank or Unicode-blank partial line, a whole line that is not the entry's, a blank
    line beyond the entries (not the excess the rule allows), a strict prefix of an
    EARLIER entry's line with the last entries' lines missing — is refused by name,
    twice, with the JSONL and the mirror byte-identical, no newline written and no
    marker written. The mend case put back, the repair completes."""
    b, whole, prose, head = _fresh_mend_shape(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    lines = prose.split(b"\n")[:-1]
    tail, reason = REFUSED[shape]
    if shape == "blank-beyond":
        bad = prose + b"  \n"
    elif shape == "earlier-prefix":
        bad = b"".join(prose.splitlines(keepends=True)[:-2]) + lines[-2][:20]
    else:
        bad = head + tail
    mirror.write_bytes(bad)
    torn = jsonl.read_bytes()
    assert not torn.endswith(b"\n")
    for _retry in range(2):
        assert main([*_argv(b), "ledger", "repair"]) == 2
        out, err = capsys.readouterr()
        assert reason in err and str(mirror) in err, err
        if shape == "earlier-prefix":
            assert "not of the entry the missing newline completes" in err
        assert "interrupted write" not in err and "termination intent" not in err  # no newline
        assert "truncated" not in out and "regenerated" not in err
        assert jsonl.read_bytes() == torn and mirror.read_bytes() == bad
        assert _no_markers(b)
    mirror.write_bytes(head + lines[-1][:20])
    assert main([*_argv(b), "ledger", "repair"]) == 0
    assert _no_markers(b) and main([*_argv(b), "ledger", "verify"]) == 0 and _audits(b) == (1, 0)


CONSISTENT = ["whole", "missing-line", "short-of-newline", "excess-line"]


@pytest.mark.parametrize("shape", CONSISTENT, ids=CONSISTENT)
def test_a_mirror_consistent_with_the_completed_chain_is_terminated_without_an_intent(
    tmp_path, capsys, monkeypatch, shape
):
    """U2 (a): the same unterminated entry with a mirror the newline's result already
    agrees with — whole, short by the entry's line, ending in that line short of only
    its newline, or beyond the entries by one non-blank line (the excess the ledger's
    own rule allows; the mirror stage cuts it under ITS intent) — is terminated as
    before: no termination intent is ever written (every marker write is recorded),
    no tail audit; verify exits 0."""
    b, whole, prose, head = _fresh_mend_shape(tmp_path)
    mirror = b.ledger.prose_path
    excess = b"an older tool's line for an entry that never became durable [000000000000]\n"
    mirror.write_bytes(
        {
            "whole": prose,
            "missing-line": head,
            "short-of-newline": prose[:-1],
            "excess-line": prose + excess,
        }[shape]
    )
    markers: list[dict] = []
    real = nodemod._write_json

    def spy(path, v):
        if path.name.startswith("ledger-repair-pending"):
            markers.append(dict(v))
        return real(path, v)

    monkeypatch.setattr(nodemod, "_write_json", spy)
    assert main([*_argv(b), "ledger", "repair"]) == 0
    out, err = capsys.readouterr()
    assert "terminated" in err and "termination intent" not in err
    assert all(m["file"] == "ledger.prose.txt" for m in markers)
    assert bool(markers) is (shape == "excess-line")
    assert all(m["bytes"] > 0 for m in markers)
    assert _audits(b) == (0, int(shape == "excess-line"))
    assert _no_markers(b) and main([*_argv(b), "ledger", "verify"]) == 0
    assert b.ledger.path.read_bytes().startswith(whole)


def test_a_termination_intent_binds_the_entry_and_the_mirror_cut_point_on_resume(
    tmp_path, capsys, monkeypatch
):
    """U2 (b), the standing termination intent validated before any step: the entry at
    its cut point edited (its hash no longer the recorded one), the recorded mirror cut
    point moved, a torn tail appended past the entry before any step ran, and the cut
    point in the marker moved to another line — each refused by name
    (ledger.repair.intent_mismatch or ledger.prose.mismatch), the marker standing at
    "intent", both files byte-identical, no audit; the marker restored, the resume
    completes."""
    b, whole, prose, head = _fresh_mend_shape(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    marker = b.state / "ledger-repair-pending.json"

    def terminate_tail(self, **kw):
        raise OSError(5, "Input/output error")  # the intent stands, nothing else ran

    monkeypatch.setattr(Ledger, "terminate_tail", terminate_tail)
    assert main([*_argv(b), "ledger", "repair"]) == 1
    capsys.readouterr()
    monkeypatch.undo()
    intent = json.loads(marker.read_text())
    assert intent["step"] == "intent" and intent["bytes"] == 0
    torn_jsonl, torn_mirror = jsonl.read_bytes(), mirror.read_bytes()
    assert torn_jsonl == whole[:-1]
    entry = json.loads(_entry_line(whole))
    edited = torn_jsonl[: intent["truncate_to"]] + _serialize({**entry, "detail": "edited"})
    cases = {
        # the entry at the cut point is one a stored ack anchors: the anchor check names it
        "entry-edited": (edited, torn_mirror, intent, "ledger.head.mismatch"),
        "hash-mismatch": (
            torn_jsonl,
            torn_mirror,
            {**intent, "tail_sha256": "sha256:" + sha256_hex(b"other")},
            "ledger.repair.intent_mismatch",
        ),
        "cut-point-moved": (torn_jsonl, torn_mirror, {**intent, "mirror_to": 1}, "ledger.prose"),
        "cut-point-earlier": (
            torn_jsonl,
            torn_mirror,
            {**intent, "mirror_to": head.rfind(b"\n", 0, len(head) - 1) + 1},
            "ledger.prose.mismatch",
        ),
        "no-cut-point": (
            torn_jsonl,
            torn_mirror,
            {k: v for k, v in intent.items() if k != "mirror_to"},
            "ledger.repair.intent_mismatch",
        ),
        "torn-tail-before-any-step": (
            whole + b'{"ts": "2026',
            torn_mirror,
            intent,
            "ledger.repair.intent_mismatch",
        ),
    }
    for name, (j, m, i, reason) in cases.items():
        jsonl.write_bytes(j)
        mirror.write_bytes(m)
        marker.write_text(json.dumps(i), encoding="utf-8")
        files = (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes())
        for _retry in range(2):
            assert main([*_argv(b), "ledger", "repair"]) == 2, name
            err = capsys.readouterr().err
            assert reason in err, (name, err)
            assert (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes()) == files, name
        assert b"ledger.tail_truncated" not in jsonl.read_bytes()
    jsonl.write_bytes(torn_jsonl)
    mirror.write_bytes(torn_mirror)
    marker.write_text(json.dumps(intent), encoding="utf-8")
    assert main([*_argv(b), "ledger", "repair"]) == 0
    assert _no_markers(b) and main([*_argv(b), "ledger", "verify"]) == 0 and _audits(b) == (1, 0)


# ---- U3. the intent id in full; the audit matched by equality and bound -----------------------


SHORT_IDS = ["rpr_", "rpr_01ARZ3NDEKTSV4RRFFQ69G5F", "rpr_01ARZ3NDEKTSV4RRFFQ69G5FAVXX", "rpr_x"]


@pytest.mark.parametrize("stage", ["own", "nested", "mirror"])
@pytest.mark.parametrize("short", SHORT_IDS)
def test_a_marker_whose_id_is_not_an_rpr_id_in_full_is_refused_at_the_load(
    tmp_path, capsys, stage, short
):
    """U3: a marker at step "truncated" (the ledger's own tail marker, the nested one,
    the mirror's) whose intent id is `rpr_`, a shorter or a longer string, or not the
    alphabet: refused at the typed load by name (ledger.repair.intent_corrupt naming
    the file and "in full"), twice; nothing promoted, the marker and both files
    byte-identical, the audits unchanged, nothing appends over it. Before, the
    shortened id matched an older repair's audit by substring and the machine promoted
    that audit's hash and removed the marker (round-14 gate, finding 3). The id put
    back, the resume completes."""
    if stage == "mirror":
        a, b, wa, wb, fake, clock, intent, marker = _mirror_repair_at_truncated(tmp_path)
    else:
        b, intent, marker, _mirror_marker = _tail_stage_after_its_audit(
            tmp_path, nested=stage == "nested"
        )
    good = marker.read_bytes()
    marker.write_text(json.dumps({**intent, "intent_id": short}), encoding="utf-8")
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    files = (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes())
    audits = _audits(b)
    for _retry in range(2):
        assert main([*_argv(b), "ledger", "repair"]) == 2
        err = capsys.readouterr().err
        assert "ledger.repair.intent_corrupt" in err and str(marker) in err, err
        assert "in full" in err and repr(short) in err
        assert (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes()) == files
    with pytest.raises(IntegrityError) as e:  # nothing appends over a marker that cannot be read
        b.receive(b.compose_card())
    # the nested case: the standing mirror marker is met first (a repair is pending)
    assert e.value.reason == (
        "ledger.repair_pending" if stage == "nested" else "ledger.repair.intent_corrupt"
    )
    assert _audits(b) == audits and (jsonl.read_bytes(), mirror.read_bytes()) == files[:2]
    marker.write_bytes(good)
    assert main([*_argv(b), "ledger", "repair"]) == 0
    assert _no_markers(b) and main([*_argv(b), "ledger", "verify"]) == 0


def test_the_audit_lookup_matches_the_id_field_exactly_and_binds_the_tail_hash(
    tmp_path, capsys, monkeypatch
):
    """U3: two tail repairs whose intent ids share 27 of 30 characters each leave an
    audit carrying its intent_id as a FIELD. A marker at "truncated" for the second
    finds exactly the second's audit (the machine promotes it and completes without a
    new audit); a marker naming the second's id with another tail hash is
    ledger.repair.intent_mismatch naming both hashes, twice, the marker standing at
    "truncated", nothing promoted, both files byte-identical; a marker naming a store
    the audit does not record is refused the same way; and an audit whose DETAIL
    carries an id but whose field is another's is not that intent's audit (the lookup
    reads the field, never the text)."""
    a, b, wa, wb, fake, clock = _with_history_over_mail(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    base = "rpr_01ARZ3NDEKTSV4RRFFQ69G5F"
    ids = iter([f"{base}AA", f"{base}AB"])
    monkeypatch.setattr(
        nodemod, "new_id", lambda prefix: next(ids) if prefix == "rpr" else new_id(prefix)
    )
    torn: dict[str, tuple[int, bytes]] = {}
    for tag in ("AA", "AB"):
        cut_to = jsonl.stat().st_size
        bytes_ = b'{"ts": "2026-09-07T07:00:00Z", "actor": "' + tag.encode()
        with open(jsonl, "ab") as f:
            f.write(bytes_)
        torn[tag] = (cut_to, bytes_)
        assert main([*_argv(b), "ledger", "repair"]) == 0
        capsys.readouterr()
    monkeypatch.undo()
    audits = [e for e in b.ledger.entries() if e["action"] == TAIL_AUDIT]
    assert [e["intent_id"] for e in audits] == [f"{base}AA", f"{base}AB"]
    assert all(is_id(e["intent_id"], "rpr_") for e in audits)
    assert all(f"intent {e['intent_id']}" in e["detail"] for e in audits)
    assert main([*_argv(b), "ledger", "verify"]) == 0

    def marker_for(tag: str) -> dict:
        cut_to, bytes_ = torn[tag]
        return {
            "step": "truncated",
            "file": "ledger.jsonl",
            "truncate_to": cut_to,
            "bytes": len(bytes_),
            "tail_sha256": "sha256:" + sha256_hex(bytes_),
            "intent_id": f"{base}{tag}",
            "ts": b.ts(),
        }

    # the exact match: AB's audit, the ledger's last entry, is found by its id field;
    # AA's audit is matched by its id too, but for the ledger's own intents the lookup
    # refuses a found audit that is not the last entry (round 17, W1: the rule runs
    # inside the binding, before the barrier and the promotion) — never a wrong audit
    found = b._repair_audit("ledger", TAIL_AUDIT, marker_for("AB"))
    assert found is not None and entry_hash(found) == entry_hash(audits[1])
    with pytest.raises(IntegrityError) as e:
        b._repair_audit("ledger", TAIL_AUDIT, marker_for("AA"))
    assert e.value.reason == "ledger.repair.intent_mismatch"
    assert "not the ledger's last entry" in str(e.value)
    intent = marker_for("AB")
    wrong = {**intent, "tail_sha256": "sha256:" + sha256_hex(b"other")}
    with pytest.raises(IntegrityError) as e:
        b._repair_audit("ledger", TAIL_AUDIT, wrong)
    assert e.value.reason == "ledger.repair.intent_mismatch"
    assert wrong["tail_sha256"] in str(e.value) and intent["tail_sha256"] in str(e.value)
    with pytest.raises(IntegrityError) as e:  # the store name is bound too
        b._repair_audit("ledger", TAIL_AUDIT, {**intent, "file": "ledger.prose.txt"})
    assert e.value.reason == "ledger.repair.intent_mismatch"
    # through the machine: the wrong tail hash, refused by name twice, nothing promoted
    marker = _write_marker(b, wrong)
    files = (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes())
    for _retry in range(2):
        assert main([*_argv(b), "ledger", "repair"]) == 2
        err = capsys.readouterr().err
        assert "ledger.repair.intent_mismatch" in err and wrong["tail_sha256"] in err, err
        assert (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes()) == files
    assert json.loads(marker.read_text())["step"] == "truncated"
    # the right hash: the exact match is promoted and the machine completes, no new audit
    marker.write_text(json.dumps(intent), encoding="utf-8")
    assert main([*_argv(b), "ledger", "repair"]) == 0
    assert _no_markers(b) and _audits(b) == (2, 0) and main([*_argv(b), "ledger", "verify"]) == 0
    # containment is not identity: the text names AC, the field says AA
    other = f"{base}AC"
    b.ledger.append(
        ts=b.ts(),
        actor="solo",
        grant_id=None,
        action=TAIL_AUDIT,
        params_hash=intent["tail_sha256"],
        outcome="recorded",
        detail=f"a record whose text mentions intent {other}",
        intent_id=f"{base}AA",
    )
    assert b._repair_audit("ledger", TAIL_AUDIT, {**intent, "intent_id": other}) is None
    assert main([*_argv(b), "ledger", "verify"]) == 0


def test_the_ledger_refuses_an_entry_whose_intent_id_field_is_not_an_id_in_full(tmp_path):
    """U3, the field at the load: an audit entry on file whose intent_id is `rpr_` (or
    any other non-id) is ledger.entry.fields naming the line at every read; the
    append refuses to write one (ValueError); an entry without the field hashes and
    verifies as before."""
    n = make_node(tmp_path, "n", Clock())
    n.ledger.append(
        ts=n.ts(), actor="n", grant_id=None, action="s", params_hash=None, outcome="information"
    )
    ok = n.ledger.append(
        ts=n.ts(),
        actor="n",
        grant_id=None,
        action=TAIL_AUDIT,
        params_hash="sha256:" + "0" * 64,
        outcome="recorded",
        detail="x",
        intent_id=new_id("rpr"),
    )
    assert "intent_id" not in n.ledger.entries()[0] and n.ledger.verify() == n.ledger.head()
    with pytest.raises(ValueError):
        n.ledger.append(
            ts=n.ts(),
            actor="n",
            grant_id=None,
            action=TAIL_AUDIT,
            params_hash=None,
            outcome="recorded",
            intent_id="rpr_",
        )
    lines = n.ledger.path.read_bytes().split(b"\n")[:-1]
    for short in SHORT_IDS:
        lines[-1] = _serialize({**ok, "intent_id": short})
        n.ledger.path.write_bytes(b"\n".join(lines) + b"\n")
        with pytest.raises(IntegrityError) as e:
            n.ledger.entries()
        assert e.value.reason == "ledger.entry.fields" and "line 2" in str(e.value)
        assert "in full" in str(e.value)


# ---- U4. one undelivered audit per transition (FAILURE AFTER) ---------------------------------


def test_a_failed_outbox_write_after_the_undelivered_audit_leaves_one_audit_on_the_retry(
    tmp_path, monkeypatch
):
    """U4: the outbox write fails after the undelivered audit was appended (the durable
    JSON writer raising for outbox.json): the entry stays pending, one audit on the
    ledger. The retry finds that audit by its key (the msg_id and the attempt count it
    names), appends nothing, and writes the terminal status: one audit, the outbox
    undelivered, verify clean; a further call is a no-op. Before, the retry appended a
    second out.send line (round-14 Fable read, section E)."""
    clock = Clock()
    a = make_node(tmp_path, "a", clock)
    b = make_node(tmp_path, "b", clock)
    a.pin(b.principal.public, "b")
    a.receive(b.compose_card())
    bundle = a.compose_info(b.card, "are you there")
    msg_id = bundle["object"]["msg_id"]
    a.outbox_record(bundle, transport_ref="gmail:1")
    real = nodemod._write_json

    def failing(path, v):
        if path.name == "outbox.json":
            raise OSError(5, "Input/output error")  # after the audit, before the status
        return real(path, v)

    def undelivered() -> list[dict]:
        return [
            e
            for e in a.ledger.entries()
            if e["action"] == OUT_SEND and e["outcome"] == "undelivered" and e["msg_id"] == msg_id
        ]

    monkeypatch.setattr(nodemod, "_write_json", failing)
    with pytest.raises(OSError):
        a.outbox_mark_undelivered(msg_id)
    monkeypatch.undo()
    assert len(undelivered()) == 1 and a.outbox()[0]["status"] == "pending"
    assert a.outbox_mark_undelivered(msg_id) is True  # the retry
    assert len(undelivered()) == 1 and a.outbox()[0]["status"] == "undelivered"
    assert undelivered()[0]["detail"] == "no ack after 1 attempts"
    assert a.ledger.verify() == a.ledger.head()
    assert a.outbox_mark_undelivered(msg_id) is False and len(undelivered()) == 1
    assert a.outbox_due() == []


# ---- U5. the sweep checks the ledger before any feed line (RESTART RECOVERY) ------------------


def test_the_startup_sweep_checks_the_ledger_before_any_feed_line(tmp_path):
    """U5: B trusts A on disk with A's revocation held (the crash-after-pin order), and
    B's last ledger entry is a completion a stored ack anchors. That completion edited
    (its chain link intact, its mirror line removed): a fresh Node over the state runs
    the ledger's check BEFORE the replay's feed line — the feed byte-identical, the
    held copy standing, the replay marker naming ledger.head.mismatch, nothing
    authorized (the revocation is not on the feed yet). The ledger restored, the next
    start replays it: one feed line, the marker and the held copy gone. Before, the
    feed line landed and only the ledger entry's append refused (round-14 Fable read,
    section E). The node still constructs over the damaged ledger: `natively ledger
    repair` needs one (round 7)."""
    reports: list[str] = []
    a, b, g, rev, held, clock = _pinned_held_healthy(tmp_path, reports)
    assert b.receive(a.compose_card()) == []
    b.mark_lookup_ok()
    (ack,) = b.receive(a.compose_info(b.card, "anchored"))
    assert ack["kind"] == "ack"
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    whole, prose = jsonl.read_bytes(), mirror.read_bytes()
    lines = whole.split(b"\n")[:-1]
    last = json.loads(lines[-1])
    assert last["direction"] == "in" and b._seen()[last["msg_id"]]["ack"]["ledger_entry"] == (
        entry_hash(last)
    )
    jsonl.write_bytes(b"\n".join([*lines[:-1], _serialize({**last, "detail": "edited"})]) + b"\n")
    mirror.write_bytes(b"".join(prose.splitlines(keepends=True)[:-1]))
    feed = b.revocations.path
    feed_before = feed.read_bytes() if feed.exists() else None
    b2 = _running(b, clock, reports)
    marker = b.state / REPLAY_MARKER
    why = json.loads(marker.read_text())["why"]
    assert "ledger.head.mismatch" in why and str(jsonl) in why
    assert json.loads(marker.read_text())["principals"] == [a.principal.public]
    assert (feed.read_bytes() if feed.exists() else None) == feed_before  # the feed untouched
    assert held.exists()
    assert any("ledger.head.mismatch" in r and "nothing is authorized" in r for r in reports)
    assert b2.revocations.grant_revoked_by(g["grant_id"], a.principal.public) is None
    assert jsonl.read_bytes() != whole  # still damaged: nothing of the ledger was touched
    jsonl.write_bytes(whole)
    mirror.write_bytes(prose)
    b3 = _running(b, clock, reports)
    assert not marker.exists() and not held.exists()
    assert b3.revocations.grant_revoked_by(g["grant_id"], a.principal.public) is not None
    assert feed.read_bytes().count(b"\n") == (feed_before or b"").count(b"\n") + 1
    replayed = [e for e in b3.ledger.entries() if e["action"] == "revocation.replayed"]
    assert [e["outcome"] for e in replayed] == ["recorded"]
    assert b3.ledger.verify() == b3.ledger.head()


# ---- the round-15 self-gate: four MAJORs and two MINORs, fixed in-family --------------------


def test_a_readable_part_before_a_damaged_one_is_still_an_incomplete_fetch(tmp_path):
    """Self-gate finding 1: body_of returns the first text it finds, so a sibling after
    it — and that sibling's children — never met the mimeType check: a readable
    text/plain part followed by a multipart sibling whose nested child carries mimeType
    "" went out as a complete row, was ledgered and marked seen. The WHOLE part tree is
    checked before a body is selected (`check_parts`): the row is an incomplete fetch
    naming the damaged part; so is a later multipart sibling with no children, a later
    part with no mimeType at all, and a later part that is not a JSON object. The text
    dump is unchanged (the first text). Through the adapter: unseen, nothing ledgered,
    the clocks unmoved; the mimeType restored, the same mail applies."""
    api = _gmail_api()
    later = {
        "partId": "1",
        "mimeType": "multipart/alternative",
        "body": {"size": 0},
        "parts": [{"partId": "1.0", "mimeType": "", "body": {"size": 5, "data": _b64url("hello")}}],
    }
    m = _gmail_message("g-later", WIRE, inline=True, extra_parts=(later,))
    _unavailable(api.msg_row(m, WIRE_CHARS, _never), "empty or missing mimeType", "partId 1.0")
    assert api.body_of(m["payload"]) == WIRE  # the text dump: the first text, as before
    for damaged, needle in (
        ({"partId": "1", "mimeType": "multipart/mixed", "body": {"size": 0}}, "carries no parts"),
        ({"partId": "1", "body": {"size": 5, "data": _b64url("hello")}}, "(partId 1) carries"),
        ("not a part", "is not a JSON object"),
    ):
        m["payload"]["parts"][1] = damaged
        _unavailable(api.msg_row(m, WIRE_CHARS, _never), needle)
        assert api.body_of(m["payload"]) == WIRE
    m["payload"]["parts"][1] = later
    later["parts"][0]["mimeType"] = "text/plain"
    _complete(api.msg_row(m, WIRE_CHARS, _never), WIRE.strip())
    # the adapter round trip
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wire = _wire_text(a, b, "whole")
    later["parts"][0]["mimeType"] = ""
    m = _gmail_message("g-later-2", wire, inline=True, extra_parts=(later,))
    row = api.msg_row(m, WIRE_CHARS, _never)
    _unavailable(row, "empty or missing mimeType", "partId 1.0")
    fake.inbox.setdefault("taylor@teale.com", []).append(row)
    before, entries = _unmoved(b, wb), len(b.ledger.entries())
    s = wb.poll_once()
    assert s["applied"] == 0 and s["complete"] is False and s["storage_failures"] == 0
    assert any("could not be obtained" in x and "g-later-2" in x for x in s["errors"])
    assert _unmoved(b, wb) == before and len(b.ledger.entries()) == entries
    assert _unseen_mail_ids(fake, b, wb) == {"g-later-2"}
    later["parts"][0]["mimeType"] = "text/plain"
    fake.inbox["taylor@teale.com"][-1] = api.msg_row(m, WIRE_CHARS, _never)
    s = wb.poll_once()
    assert s["applied"] == 1 and s["complete"] is True
    assert b.ledger.entries()[-1]["detail"] == "whole"


def test_the_root_part_is_named_in_the_mimetype_reason():
    """Self-gate minor 1: a root payload whose mimeType is empty or missing is unavailable
    with the reason naming it — "the payload part", with its partId when it carries one
    (Gmail serves the root with partId "", which alone named nothing). Before, the root
    was intercepted before `_part_ref` ran. The text dump is unchanged."""
    api = _gmail_api()
    for bad in ("", None, 0):
        m = _gmail_message("g-root", WIRE, inline=True)
        m["payload"]["mimeType"] = bad
        row = api.msg_row(m, WIRE_CHARS, _never)
        _unavailable(row, "the payload part carries an empty or missing mimeType")
        assert "partId" not in row["body_unavailable"]
        m["payload"]["partId"] = ""
        row = api.msg_row(m, WIRE_CHARS, _never)
        _unavailable(row, "the payload part carries")
        assert "partId" not in row["body_unavailable"]
        m["payload"]["partId"] = "root"
        _unavailable(api.msg_row(m, WIRE_CHARS, _never), "the payload part (partId root) carries")
        assert api.body_of(m["payload"]) == WIRE
    del m["payload"]["mimeType"]
    _unavailable(
        api.msg_row(m, WIRE_CHARS, _never),
        "the payload part (partId root) carries an empty or missing mimeType",
    )


@pytest.mark.parametrize("shape", ["audit-unterminated", "audit-prose-missing", "audit-prose-torn"])
def test_a_visible_audit_is_bound_to_the_marker_before_any_mend_writes(tmp_path, capsys, shape):
    """Self-gate finding 2: the tail stage at "truncated" with its audit VISIBLE on the
    JSONL — whole short of only its newline, or terminated with its prose line missing
    or torn after an ASCII prefix — and the marker's tail hash not the audit's:
    ledger.repair.intent_mismatch naming both hashes, twice, with the JSONL, the mirror
    and the marker byte-identical; nothing appended. Before, `_mend_own_audit_tear`
    wrote the newline and `_mend_prose_tear` regenerated the prose line, and only then
    the lookup refused. The marker's hash restored, the resume mends and completes: one
    audit, verify exit 0."""
    b, intent, marker, _ = _tail_stage_after_its_audit(tmp_path, nested=False)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    whole, prose = jsonl.read_bytes(), mirror.read_bytes()
    lines = prose.splitlines(keepends=True)
    if shape == "audit-unterminated":
        jsonl.write_bytes(whole[:-1])
        mirror.write_bytes(b"".join(lines[:-1]))
    elif shape == "audit-prose-missing":
        mirror.write_bytes(b"".join(lines[:-1]))
    else:
        mirror.write_bytes(b"".join(lines[:-1]) + lines[-1][:20])  # the timestamp, no newline
    wrong = {**intent, "tail_sha256": "sha256:" + sha256_hex(b"other")}
    marker.write_text(json.dumps(wrong), encoding="utf-8")
    files = (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes())
    for _retry in range(2):
        assert main([*_argv(b), "ledger", "repair"]) == 2
        err = capsys.readouterr().err
        assert "ledger.repair.intent_mismatch" in err, err
        assert wrong["tail_sha256"] in err and intent["tail_sha256"] in err, err
        assert (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes()) == files, shape
    marker.write_text(json.dumps(intent), encoding="utf-8")
    assert main([*_argv(b), "ledger", "repair"]) == 0
    assert _no_markers(b) and _audits(b) == (1, 0)
    assert main([*_argv(b), "ledger", "verify"]) == 0


def test_an_entry_under_the_intents_id_with_another_stores_action_is_a_mismatch(tmp_path, capsys):
    """Self-gate finding 3: a denial.repaired entry carrying a ledger-tail intent's exact
    id is not "absent" — `_repair_audit` matches the id FIRST and binds the action after:
    ledger.repair.intent_mismatch naming the action found and the audit expected,
    directly and through the machine (twice, the marker standing at "truncated", both
    files byte-identical, no audit appended). Before, the action was filtered first,
    the entry skipped, a second audit appended under the id and the marker promoted and
    removed."""
    a, b, wa, wb, fake, clock = _with_history_over_mail(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    with open(jsonl, "ab") as f:
        f.write(b'{"ts": "2026-09-07T07:00:00Z", "actor": "')
    torn = b.ledger.torn_tail()
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
    b.ledger.append(  # another store's audit, this intent's id in its field
        ts=b.ts(),
        actor="solo",
        grant_id=None,
        action="denial.repaired",
        params_hash=intent["tail_sha256"],
        outcome="recorded",
        detail=f"truncated {len(torn)} bytes; intent {intent['intent_id']}",
        intent_id=intent["intent_id"],
    )
    with pytest.raises(IntegrityError) as e:
        b._repair_audit("ledger", TAIL_AUDIT, intent)
    assert e.value.reason == "ledger.repair.intent_mismatch"
    assert "denial.repaired" in str(e.value) and TAIL_AUDIT in str(e.value)
    marker = _write_marker(b, intent)
    files = (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes())
    for _retry in range(2):
        assert main([*_argv(b), "ledger", "repair"]) == 2
        err = capsys.readouterr().err
        assert "ledger.repair.intent_mismatch" in err and "denial.repaired" in err, err
        assert (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes()) == files
    assert json.loads(marker.read_text())["step"] == "truncated"
    assert _audits(b) == (0, 0)


@pytest.mark.parametrize("recovered", ["kept", "dropped"])
def test_the_undelivered_status_waits_for_the_barrier_of_the_audit_it_found(
    tmp_path, monkeypatch, recovered
):
    """Self-gate finding 4 (FAILURE AFTER): the undelivered audit's append fails at the
    JSONL's fsync after its bytes became visible — the status is not written, the entry
    stays pending. The retry finds the visible audit; the ledger barrier (the same
    fsync) fails again: the status is still not written. The fsync restored, the next
    call syncs the ledger file (the barrier) before the status lands: one audit, the
    status undelivered, verify clean — or, the power loss having removed the unsynced
    audit, appends it once more. Before, the found audit went unbarriered and the
    durable status could outlive it."""
    clock = Clock()
    a = make_node(tmp_path, "a", clock)
    b = make_node(tmp_path, "b", clock)
    a.pin(b.principal.public, "b")
    a.receive(b.compose_card())
    bundle = a.compose_info(b.card, "are you there")
    msg_id = bundle["object"]["msg_id"]
    a.outbox_record(bundle, transport_ref="gmail:1")

    def undelivered() -> list[dict]:
        return [
            e
            for e in a.ledger.entries()
            if e["action"] == OUT_SEND and e["outcome"] == "undelivered" and e["msg_id"] == msg_id
        ]

    state = _ledger_fsync_failing_after(a.ledger.path, 0, monkeypatch)
    with pytest.raises(OSError):  # the audit is visible, its barrier failed
        a.outbox_mark_undelivered(msg_id)
    assert state["failed"] == 1 and len(undelivered()) == 1
    assert a.outbox()[0]["status"] == "pending"
    with pytest.raises(OSError):  # the retry finds it; the barrier fails: no status
        a.outbox_mark_undelivered(msg_id)
    assert state["failed"] >= 2 and a.outbox()[0]["status"] == "pending"
    assert len(undelivered()) == 1
    monkeypatch.undo()
    if recovered == "dropped":
        _drop_last_line(a.ledger.path)
        a.ledger._entries = None
        assert undelivered() == []
    events = _record_syncs(monkeypatch)
    assert a.outbox_mark_undelivered(msg_id) is True
    assert ("file", _ino(a.ledger.path)) in events  # the barrier (or the append) synced it
    assert len(undelivered()) == 1 and a.outbox()[0]["status"] == "undelivered"
    assert a.ledger.verify() == a.ledger.head()
    assert a.outbox_mark_undelivered(msg_id) is False and len(undelivered()) == 1


def test_an_oversized_bundle_is_a_storage_failure_at_the_outgoing_boundary(tmp_path):
    """Self-gate minor 2: a signed message whose attached cards (valid, duplicated) push
    the encoded bundle over MAX_WIRE_BYTES is <kind>.invalid at `check_outgoing` —
    directly; at the wire's send (nothing transmitted, the outbox untouched); and on
    the re-send path of a poll, a storage failure of the poll (counted, the entry kept,
    no attempt spent, the poll never complete). Before, `bundle.encode` raised
    ValueError inside the send and the wire classed it as a transport failure: nothing
    counted, the entry due forever."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    m = a.compose_info(b.card, "big")
    copies = bundlemod.MAX_WIRE_BYTES // len(_serialize(a.card)) + 2
    big = {**m, "cards": m["cards"] * copies}
    assert len(_serialize(big)) > bundlemod.MAX_WIRE_BYTES
    with pytest.raises(IntegrityError) as e:
        a.check_outgoing(big)
    assert e.value.reason == "message.invalid" and "bytes, over" in str(e.value)
    sends, outbox = len(fake.sends), a.outbox()
    with pytest.raises(IntegrityError) as e:
        wa.send(big)
    assert e.value.reason == "message.invalid"
    assert len(fake.sends) == sends and a.outbox() == outbox
    # on the retry schedule (a transport took the first send): due, refused, counted
    a.outbox_record(big, transport_ref="gmail:big")
    clock.tick(2 * a.poll_s)
    s = wa.poll_once()
    assert s["storage_failures"] == 1 and s["resent"] == 0 and s["complete"] is False
    assert any("message.invalid" in x and big["object"]["msg_id"] in x for x in s["errors"])
    entry = a.outbox_entry(big["object"]["msg_id"])
    assert entry["status"] == "pending" and entry["attempts"] == 1
    assert len(fake.sends) == sends

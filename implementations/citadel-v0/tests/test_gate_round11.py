"""Gate round 11 (hw-hw3c9): the tenth cross-model gate report, two MAJOR and one
MINOR, all in one family — a local file of ours read as if it were peer input, or
trusted without the check that made it ours.

Q1  Every framing or encoding fault in a file of OURS is local corruption — an
    IntegrityError, so a storage failure — never a VerifyError: the ledger loader maps
    an unterminated JSONL tail (ledger.truncated), a torn multibyte character or a
    line that is not an entry (ledger.corrupt) and a chain fault (ledger.chain) to
    IntegrityError naming the path and the byte offset or line; the mirror's faults
    likewise. receive refuses inside the storage boundary (nothing ledgered, nothing
    acknowledged, the mail unseen, the poll incomplete, storage_failures counted);
    ledger verify names the fault; ledger repair restores an unterminated tail (a
    whole entry short of its newline terminated, a torn partial line cut by the
    intent machine and ledgered ledger.tail_truncated) and refuses by name when the
    part before it is not this ledger's chain. Previously ledger.truncated was a
    VerifyError: receive took it for a peer failure and its refusal append raised the
    same error out of the poll.
Q2  A revocation or a denial ON FILE was verified before it was stored, so every load
    verifies each record as a DOCUMENT (the structure with every key and signature
    field of its type, the signature under the principal key the record names);
    any failure is feed.corrupt / denial.corrupt naming the path and the line, a
    storage failure at authorization, at the pin and at the check verbs — never a
    record enforcement skips. Previously a stored principal key replaced by a string
    that is not a key still loaded, enforcement skipped the record, and a revoked or
    denied action became authorized.
Q3  Every resumed step of the repair machine validates the store it stands on (the
    JSONL's chain and framing for the ledger) BEFORE any mutation of the file or the
    marker: a JSONL that fails leaves the mirror and the marker exactly as found and
    refuses by name, the intent standing for a later run. Previously a resume
    truncated the mirror and advanced the marker before it read the JSONL.
"""

from __future__ import annotations

import ast
import base64
import json
from pathlib import Path

import pytest

from natively import bundle as bundlemod
from natively import denial as denialmod
from natively import keys
from natively import revocation as revmod
from natively.canon import sha256_hex
from natively.cli import main
from natively.errors import IntegrityError, VerifyError
from natively.ledger import entry_hash
from natively.objects import new_id, signed

from .conftest import Clock, make_node, uid
from .test_gate_round6 import _connected_over_mail
from .test_gate_round7 import _argv
from .test_gate_round7b import _acks_out, _actions, _inbox_len
from .test_gate_round8 import _flip, _unseen_mail_ids
from .test_gate_round9 import _outcomes
from .test_gate_round10 import _tear_mirror, _with_history_over_mail
from .test_hardening import STATEMENT, fs_write_scope, write_bundle

PKG = Path(__file__).resolve().parents[1] / "natively"
TAILS = ["torn", "torn-no-prose", "whole-entry"]
RECORD_DAMAGE = ["key-not-a-key", "sig-damaged", "sig-other-key"]
STEPS = ["intent", "truncated", "audited"]


def _damage_record(rec: dict, how: str) -> dict:
    """One stored record (a revocation, a denial) damaged in place: its principal
    key a string that is not a key, its signature flipped, or its signature a real
    one under ANOTHER key (the body unchanged)."""
    if how == "key-not-a-key":
        return {**rec, "principal": {"key": "ed25519:!"}}
    if how == "sig-damaged":
        return {**rec, "sig": _flip(rec["sig"])}
    body = {k: v for k, v in rec.items() if k != "sig"}
    return signed(body, keys.KeyPair.generate())


def _store_line(rec: dict) -> bytes:
    return json.dumps(rec, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"


def _break_chain(jsonl: Path) -> bytes:
    """Entry 1's prev_hash replaced: the chain fails at line 2. Returns the original."""
    original = jsonl.read_bytes()
    lines = original.split(b"\n")
    e = json.loads(lines[1])
    e["prev_hash"] = "sha256:" + "1" * 64
    lines[1] = json.dumps(e, ensure_ascii=False, separators=(",", ":")).encode()
    jsonl.write_bytes(b"\n".join(lines))
    return original


def _write_marker(node, intent: dict) -> Path:
    marker = node.state / "ledger-repair-pending.json"
    marker.write_text(json.dumps(intent), encoding="utf-8")
    return marker


def _with_ackless_tail_over_mail(tmp_path):
    """`_with_history_over_mail`, then a revocation from a recorded by b: b's LAST
    ledger entry (revocation.received) is one no stored ack anchors. The entry a
    fixture tears must be such a one: an ack is stored only after its entry's
    append returned durable, so a torn tail an ack anchors is a state the real
    sequence never produces — and round 13 refuses it (ledger.head.mismatch)."""
    a, b, wa, wb, fake, clock = _with_history_over_mail(tmp_path)
    wa.send(a.compose_revocation(a.revoke(grants=[uid("grt")], principal_statement="x")))
    assert wb.poll_once()["applied"] == 1
    assert b.ledger.entries()[-1]["action"] == "revocation.received"
    return a, b, wa, wb, fake, clock


# ---- Q1. an unterminated JSONL tail is a storage failure, named, repaired ------------------


@pytest.mark.parametrize(
    "how,terminated",
    [
        ("torn", False),
        ("torn", True),
        ("torn-no-prose", False),
        ("torn-no-prose", True),
        ("whole-entry", False),
    ],
    ids=["torn", "torn-newline", "torn-no-prose", "torn-no-prose-newline", "whole-entry"],
)
def test_an_unterminated_jsonl_tail_is_a_counted_storage_failure_then_repaired(
    tmp_path, capsys, how, terminated
):
    """Q1: the JSONL's last line lacks its newline — a torn partial line (with the
    mirror line an older tool wrote for it, or without), or a whole entry short of
    only its newline. receive is a counted storage failure with NO exception out of
    the poll, nothing ledgered, the mail unseen; `ledger verify` exits 2 naming the
    path and the byte offset (ledger.truncated, an IntegrityError, never a
    VerifyError); `ledger repair` restores it — the torn line cut and audited once
    (ledger.tail_truncated), the whole entry terminated with nothing cut — and the
    retry applies. The torn line WITH its newline (round 13) is ledger.corrupt
    naming the line: the same storage failure, verify 2, and repair refuses by
    name with nothing cut and no intent; restored by hand, the retry applies."""
    a, b, wa, wb, fake, clock = _with_ackless_tail_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "hello"))
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    whole, prose = jsonl.read_bytes(), mirror.read_bytes()
    entries = len(b.ledger.entries())
    if how == "whole-entry":
        jsonl.write_bytes(whole[:-1])
    else:
        jsonl.write_bytes(whole[:-10] + (b"\n" if terminated else b""))
        if how == "torn-no-prose":  # the append died mid-write: no prose line for it
            mirror.write_bytes(b"".join(mirror.read_bytes().splitlines(keepends=True)[:-1]))
    torn, torn_mirror = jsonl.read_bytes(), mirror.read_bytes()
    offset = torn.rstrip(b"\n").rfind(b"\n") + 1
    line = torn.rstrip(b"\n").count(b"\n") + 1
    reason = "ledger.corrupt" if terminated else "ledger.truncated"
    where = f"line {line}" if terminated else f"byte offset {offset}"
    inbox_before = _inbox_len(fake)
    with pytest.raises(IntegrityError) as e:
        b.ledger.entries()
    assert e.value.reason == reason and not isinstance(e.value, VerifyError)
    assert str(jsonl) in str(e.value) and where in str(e.value)
    s = wb.poll_once()  # no exception out of the poll
    assert s["storage_failures"] == 1 and s["complete"] is False and s["applied"] == 0
    (err,) = [x for x in s["errors"] if reason in x]
    assert str(jsonl) in err and where in err
    assert len(_unseen_mail_ids(fake, b, wb)) == 1 and _inbox_len(fake) == inbox_before
    assert jsonl.read_bytes() == torn and mirror.read_bytes() == torn_mirror
    assert wb._pending_replies() == []
    assert main([*_argv(b), "ledger", "verify"]) == 2
    err = capsys.readouterr().err
    assert reason in err and str(jsonl) in err and where in err
    if terminated:
        # corruption, never a torn tail: refused by name, nothing cut, no intent
        assert main([*_argv(b), "ledger", "repair"]) == 2
        err = capsys.readouterr().err
        assert "ledger.corrupt" in err and "ledger.truncated" not in err and where in err
        assert jsonl.read_bytes() == torn and mirror.read_bytes() == torn_mirror
        assert not (b.state / "ledger-repair-pending.json").exists()
        assert b'"ledger.tail_truncated"' not in torn
        jsonl.write_bytes(whole)  # restored by hand
        mirror.write_bytes(prose)
        assert main([*_argv(b), "ledger", "verify"]) == 0
        assert _actions(b).count("ledger.tail_truncated") == 0
        s = wb.poll_once()
        assert s["applied"] == 1 and s["replies"] == 1 and s["complete"] is True
        return
    assert main([*_argv(b), "ledger", "repair"]) == 0
    out = capsys.readouterr().out
    assert "ledger repaired" in out
    if how == "whole-entry":
        assert "truncated" not in out and _actions(b).count("ledger.tail_truncated") == 0
        assert jsonl.read_bytes() == whole and len(b.ledger.entries()) == entries
    else:
        assert "torn byte(s) of the JSONL's last line truncated (ledger.tail_truncated)" in out
        assert _actions(b).count("ledger.tail_truncated") == 1
        assert len(b.ledger.entries()) == entries  # the torn entry cut, the audit added
        assert b.ledger.entries()[-1]["params_hash"] == "sha256:" + sha256_hex(torn[offset:])
    head = b.ledger.verify()
    assert main([*_argv(b), "ledger", "verify"]) == 0 and head in capsys.readouterr().out
    assert not (b.state / "ledger-repair-pending.json").exists()
    s = wb.poll_once()
    assert s["applied"] == 1 and s["replies"] == 1 and s["complete"] is True
    assert wa.poll_once()["applied"] == 1 and a.outbox()[-1]["status"] == "acked"


@pytest.mark.parametrize("terminated", [True, False], ids=["newline", "no-newline"])
def test_a_refusal_ledgered_over_a_damaged_ledger_stays_inside_the_storage_boundary(
    tmp_path, terminated
):
    """Q1: a bundle refused BEFORE anything else was read meets the ledger for the
    first time at its own refusal append — over a JSONL whose tail is torn, with or
    without its newline. Through `receive` directly (the envelope refused: the path
    the tenth gate named), the refusal's append is a storage failure raised as such
    (an IntegrityError, never a VerifyError out of the boundary), reported, nothing
    written. Over mail (the attached card refused), the poll counts a storage
    failure, no exception, the mail unseen; the ledger repaired, the retry ledgers
    the refusal and the mail is seen."""
    a, b, wa, wb, fake, clock = _with_history_over_mail(tmp_path)
    jsonl = b.ledger.path
    whole = jsonl.read_bytes()
    jsonl.write_bytes(whole + b'{"ts": "x\xe2\x80"}' + (b"\n" if terminated else b""))
    torn = jsonl.read_bytes()
    # round 20 (the prefix rule): a damaged character in the MIDDLE of the line is
    # corruption with or without the newline — the bytes after it are not a strict
    # prefix of one record of ours (before, ledger.truncated without the newline)
    reason = "ledger.corrupt"
    reports: list[str] = []
    b.report = reports.append
    bogus = {"natively": "v0", "kind": "bogus", "object": {}, "cards": [], "grants": []}
    with pytest.raises(IntegrityError) as e:
        b.receive(bogus)
    assert e.value.reason == reason and not isinstance(e.value, VerifyError)
    # round 12: the ledger's full check is the first read of the receive, before the
    # envelope is judged, so the storage failure is reported there (the same class,
    # the same name, the path named), never at the refusal's append
    assert any("storage failure" in r and reason in r and str(jsonl) in r for r in reports)
    assert jsonl.read_bytes() == torn
    # over mail: a message whose attached card no longer verifies is refused at the
    # card, and THAT refusal's append is the first ledger read of the poll
    m = a.compose_info(b.card, "hello")
    card = m["cards"][0]
    sig = next(k for k in card if k.endswith("sig"))
    hostile = {**m, "cards": [{**card, sig: _flip(card[sig])}]}
    fake.add(wb.self_email, wa.self_email, bundlemod.encode(hostile))
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False and s["applied"] == 0
    assert any(reason in x and str(jsonl) in x for x in s["errors"])
    assert len(_unseen_mail_ids(fake, b, wb)) == 1 and jsonl.read_bytes() == torn
    jsonl.write_bytes(whole)
    assert main([*_argv(b), "ledger", "verify"]) == 0
    s = wb.poll_once()
    assert s["storage_failures"] == 0 and s["complete"] is True
    assert _unseen_mail_ids(fake, b, wb) == set()
    assert any(o.startswith("verify_failed:card.") for o in _outcomes(b))


@pytest.mark.parametrize("terminated", [True, False], ids=["newline", "no-newline"])
def test_the_repair_verb_refuses_an_unterminated_tail_over_a_chain_that_is_not_this_ledgers(
    tmp_path, capsys, terminated
):
    """Q1: a torn tail (with or without its newline, round 13) over a part whose
    chain is broken is refused by the chain's name (ledger.chain), nothing cut,
    nothing written, no intent left."""
    a, b, wa, wb, fake, clock = _with_ackless_tail_over_mail(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    whole = jsonl.read_bytes()
    jsonl.write_bytes(whole[:-10] + (b"\n" if terminated else b""))
    _break_chain(jsonl)
    torn, torn_mirror = jsonl.read_bytes(), mirror.read_bytes()
    assert main([*_argv(b), "ledger", "repair"]) == 2
    err = capsys.readouterr().err
    assert "ledger.chain" in err and str(jsonl) in err
    assert jsonl.read_bytes() == torn and mirror.read_bytes() == torn_mirror
    assert not (b.state / "ledger-repair-pending.json").exists()


def test_a_resumed_tail_repair_validates_the_chain_before_it_cuts(tmp_path, capsys):
    """Q1/Q3: an intent for the JSONL's tail stands; the chain before the cut point
    is broken. The resume refuses by name (ledger.chain) with the JSONL, the mirror
    and the marker exactly as found; the chain restored, the resume cuts, audits once
    and finishes."""
    a, b, wa, wb, fake, clock = _with_ackless_tail_over_mail(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    whole = jsonl.read_bytes()
    jsonl.write_bytes(whole[:-10])
    cut = whole[:-10]
    tail = b.ledger.torn_tail()
    assert tail == cut[cut.rfind(b"\n") + 1 :]
    intent = {
        "step": "intent",
        "file": "ledger.jsonl",
        "truncate_to": len(whole[:-10]) - len(tail),
        "bytes": len(tail),
        "tail_sha256": "sha256:" + sha256_hex(tail),
        "intent_id": new_id("rpr"),
        "ts": b.ts(),
    }
    marker = _write_marker(b, intent)
    _break_chain(jsonl)
    before = (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes())
    assert main([*_argv(b), "ledger", "repair"]) == 2
    assert "ledger.chain" in capsys.readouterr().err
    assert (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes()) == before
    # the chain restored: the resume cuts the recorded tail and audits once
    jsonl.write_bytes(whole[:-10])
    assert main([*_argv(b), "ledger", "repair"]) == 0
    assert _actions(b).count("ledger.tail_truncated") == 1 and not marker.exists()
    assert f"intent {intent['intent_id']}" in b.ledger.entries()[-1]["detail"]
    assert main([*_argv(b), "ledger", "verify"]) == 0


@pytest.mark.parametrize("terminated", [True, False], ids=["newline", "no-newline"])
@pytest.mark.parametrize("store", ["feed", "denial"])
def test_a_torn_feed_or_denial_tail_without_its_newline_is_named_at_its_read_site(
    tmp_path, capsys, store, terminated
):
    """Q1: the same shape on the revocation feed and the denial store — a torn
    partial last line, without its newline and (round 12) with it — at the
    authorization read: a counted storage failure naming the path (<store>.torn
    without the newline; <store>.corrupt with it — a line that does not parse and
    ends in its newline is corruption, never a torn tail), the mail unseen, nothing
    executed; the verify verb exits 2 naming the path; the repair verb cuts the torn
    tail and refuses the corrupt line by name with the file untouched (the operator
    restores it); the retry applies."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    if store == "denial":
        b.config["extensions"]["standing_denial"] = True
        b.save_config()
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "t.txt"), principal_statement=STATEMENT
    )
    wa.send(write_bundle(a, b, g, "t.txt"))
    obj = b.revocations if store == "feed" else b.denials
    partial = b'{"rev_id": "rev_' if store == "feed" else b'{"denial_id": "dny_'
    obj.path.write_bytes(partial + (b"\n" if terminated else b""))
    torn = obj.path.read_bytes()
    reason = f"{store}.{'corrupt' if terminated else 'torn'}"
    with pytest.raises(IntegrityError) as e:
        obj.entries()
    assert e.value.reason == reason and str(obj.path) in str(e.value)
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False and s["applied"] == 0
    assert any(reason in x and str(obj.path) in x for x in s["errors"])
    assert len(_unseen_mail_ids(fake, b, wb)) == 1 and obj.path.read_bytes() == torn
    assert not (b.scratch_dir / "t.txt").exists()
    assert "verify_failed:malformed" not in _outcomes(b)
    assert main([*_argv(b), store, "verify"]) == 2
    err = capsys.readouterr().err
    assert reason in err and str(obj.path) in err
    if terminated:
        # corruption, not a torn tail: refused by name, the file untouched, no intent
        assert main([*_argv(b), store, "repair"]) == 2
        err = capsys.readouterr().err
        assert reason in err and f"{store}.torn" not in err and str(obj.path) in err
        assert obj.path.read_bytes() == torn
        assert not (b.state / f"{store}-repair-pending.json").exists()
        assert _actions(b).count(f"{store}.repaired") == 0
        obj.path.unlink()  # restored by hand: the store held nothing before the damage
    else:
        assert main([*_argv(b), store, "repair"]) == 0
        assert _actions(b).count(f"{store}.repaired") == 1
    assert main([*_argv(b), store, "verify"]) == 0
    s = wb.poll_once()
    assert s["applied"] == 1 and s["complete"] is True
    assert (b.scratch_dir / "t.txt").read_text() == "x\n"


def _verify_error_raisers(tree: ast.AST) -> set[str]:
    """The enclosing functions in which a module raises VerifyError."""
    out: set[str] = set()
    stack: list[str] = ["<module>"]

    def visit(node: ast.AST) -> None:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            stack.append(node.name)
            for child in ast.iter_child_nodes(node):
                visit(child)
            stack.pop()
            return
        if isinstance(node, ast.Raise) and node.exc is not None:
            f = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
            if getattr(f, "id", None) == "VerifyError":
                out.add(stack[-1])
        for child in ast.iter_child_nodes(node):
            visit(child)

    visit(tree)
    return out


def test_the_loaders_raise_no_verify_error_while_reading_a_file_of_ours():
    """Q1 guard: the three JSONL loaders raise VerifyError only where they judge
    PEER input (a revocation's or a denial's structure and rooting at receipt) or a
    policy at use (the feed's freshness); the ledger, which reads no peer input,
    raises none. Every fault met while READING a file of ours is an IntegrityError."""
    expected = {
        "ledger.py": set(),
        # round 19 (third self-gate run): the freshness verdict moved into check_fresh, the
        # pure half assert_fresh and the pre-executor recheck call
        "revocation.py": {"check_structure", "verify", "check_fresh"},
        "denial.py": {"check_structure", "verify"},
    }
    for name, allowed in expected.items():
        tree = ast.parse((PKG / name).read_text(encoding="utf-8"))
        assert _verify_error_raisers(tree) == allowed, name


# ---- Q2. stored revocations and denials are verified as documents at every load --------------


def _revoked_grant_over_mail(tmp_path):
    """a and b connected; a's grant to b revoked by a's principal, the revocation on
    b's feed (one record); an action under the revoked grant in b's inbox, unread."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    g = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "r.txt"),
        principal_statement=STATEMENT,
        max_uses=4,
    )
    rev = a.revoke(grants=[g["grant_id"]], principal_statement="no more")
    wa.send(a.compose_revocation(rev))
    assert wb.poll_once()["complete"] is True
    (rec,) = b.revocations.entries()
    assert rec["rev_id"] == rev["rev_id"]
    wa.send(write_bundle(a, b, g, "r.txt"))
    return a, b, wa, wb, fake, clock, rec


def _refused_by_storage(b, wb, fake, path: Path, reason: str, name: str) -> None:
    """One poll over a store whose record no longer verifies: a storage failure
    naming the file and the line, the mail unseen, nothing executed, nothing
    ledgered, never authorized."""
    entries_before, inbox_before = len(b.ledger), _inbox_len(fake)
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False and s["applied"] == 0
    assert any(reason in x and str(path) in x and "line 1" in x for x in s["errors"])
    assert len(_unseen_mail_ids(fake, b, wb)) == 1 and _inbox_len(fake) == inbox_before
    assert len(b.ledger) == entries_before and not (b.scratch_dir / name).exists()
    assert "verify_failed:malformed" not in _outcomes(b)


def _pin_refuses(b, capsys, reason: str, path: Path) -> None:
    """`natively pin` over the store: exit 2 naming the file, trust not published."""
    pinned_before = (b.state / "pinned.json").read_bytes()
    key = keys.KeyPair.generate().public
    assert main([*_argv(b), "pin", key, "--name", "someone"]) == 2
    err = capsys.readouterr().err
    assert reason in err and str(path) in err
    assert (b.state / "pinned.json").read_bytes() == pinned_before and key not in b.pinned


@pytest.mark.parametrize("how", RECORD_DAMAGE)
def test_a_damaged_stored_revocation_is_a_storage_failure_never_an_authorization(
    tmp_path, capsys, how
):
    """Q2: the stored revocation's principal key replaced by a string that is not a
    key, its signature damaged, or its signature under another key. The action the
    revocation forbids is a storage failure naming the feed and the line (feed.corrupt)
    — never authorized, the mail unseen, nothing executed; `feed verify` and `pin`
    refuse by name; the file put back, the retry is refused as revoked; a sound record
    still enforces."""
    a, b, wa, wb, fake, clock, rec = _revoked_grant_over_mail(tmp_path)
    feed = b.revocations.path
    original = feed.read_bytes()
    feed.write_bytes(_store_line(_damage_record(rec, how)))
    with pytest.raises(IntegrityError) as e:
        b.revocations.entries()
    assert e.value.reason == "feed.corrupt" and str(feed) in str(e.value)
    assert "line 1" in str(e.value) and "not a revocation" in str(e.value)
    assert not isinstance(e.value, VerifyError)
    _refused_by_storage(b, wb, fake, feed, "feed.corrupt", "r.txt")
    assert main([*_argv(b), "feed", "verify"]) == 2
    err = capsys.readouterr().err
    assert "feed.corrupt" in err and str(feed) in err and "line 1" in err
    _pin_refuses(b, capsys, "feed.corrupt", feed)
    # the record restored: the sound revocation enforces, the action is refused
    feed.write_bytes(original)
    assert main([*_argv(b), "feed", "verify"]) == 0
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()  # the bundle is handled (a refusal, acknowledged), not authorized
    assert s["storage_failures"] == 0 and s["complete"] is True and s["replies"] == 1
    (ack,) = _acks_out(fake, inbox_before)
    assert ack["outcome"] == "refused:no_authorizing_grant"
    assert "grant.revoked" in b.ledger.entries()[-1]["detail"]
    assert not (b.scratch_dir / "r.txt").exists() and _unseen_mail_ids(fake, b, wb) == set()


@pytest.mark.parametrize("how", RECORD_DAMAGE)
def test_a_damaged_stored_denial_is_a_storage_failure_never_an_authorization(tmp_path, capsys, how):
    """Q2: the same three damages on the standing denial that forbids the action:
    denial.corrupt naming the store and the line, never authorized, the mail unseen;
    `denial verify` and `pin` refuse by name; the file put back, the retry is
    refused as denied."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    b.config["extensions"]["standing_denial"] = True
    b.save_config()
    d = b.deny(deny=[{"action": "fs.write", "resource": "*"}], principal_statement="never")
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "d.txt"), principal_statement=STATEMENT
    )
    wa.send(write_bundle(a, b, g, "d.txt"))
    store = b.denials.path
    original = store.read_bytes()
    (rec,) = b.denials.entries()
    assert rec["denial_id"] == d["denial_id"]
    store.write_bytes(_store_line(_damage_record(rec, how)))
    with pytest.raises(IntegrityError) as e:
        b.denials.entries()
    assert e.value.reason == "denial.corrupt" and str(store) in str(e.value)
    assert "line 1" in str(e.value) and "not a denial" in str(e.value)
    assert not isinstance(e.value, VerifyError)
    _refused_by_storage(b, wb, fake, store, "denial.corrupt", "d.txt")
    assert main([*_argv(b), "denial", "verify"]) == 2
    err = capsys.readouterr().err
    assert "denial.corrupt" in err and str(store) in err and "line 1" in err
    _pin_refuses(b, capsys, "denial.corrupt", store)
    store.write_bytes(original)
    assert main([*_argv(b), "denial", "verify"]) == 0
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()  # the bundle is handled (a refusal, acknowledged), not authorized
    assert s["storage_failures"] == 0 and s["complete"] is True and s["replies"] == 1
    (ack,) = _acks_out(fake, inbox_before)
    assert ack["outcome"] == "refused:denied"
    assert not (b.scratch_dir / "d.txt").exists() and _unseen_mail_ids(fake, b, wb) == set()


def test_the_structure_checks_type_every_key_and_signature_field():
    """Q2: a revocation's and a denial's check_structure refuse a principal key that
    does not decode and a signature that is not a base64 string of 64 bytes, by name
    — at receipt on peer input (a VerifyError) and so, through the loaders, on a
    file of ours; check_document adds the signature under the named key."""
    kp = keys.KeyPair.generate()
    r = revmod.sign(
        revmod.build(principal_key=kp.public, ts="2026-09-07T07:00:00Z", grants=[uid("grt")]), kp
    )
    d = denialmod.sign(
        denialmod.build(
            principal_key=kp.public,
            ts="2026-09-07T07:00:00Z",
            deny=[{"action": "*", "resource": "*"}],
            principal_statement="never",
        ),
        kp,
    )
    short = base64.b64encode(b"\x00" * 63).decode("ascii")
    for what, obj, mod in (("revocation", r, revmod), ("denial", d, denialmod)):
        mod.check_document(obj)
        bad = {
            f"{what}.principal.key.format": [
                {**obj, "principal": {"key": "ed25519:!"}},
                {**obj, "principal": {"key": "ed25519:"}},
                {**obj, "principal": {"key": "ed25519:AAAA"}},
            ],
            f"{what}.sig.format": [{**obj, "sig": []}, {**obj, "sig": 5}, {**obj, "sig": short}],
        }
        for reason, variants in bad.items():
            for v in variants:
                with pytest.raises(VerifyError) as e:
                    mod.check_structure(v)
                assert e.value.reason == reason, (what, reason, e.value.reason)
        for v in (_damage_record(obj, "sig-damaged"), _damage_record(obj, "sig-other-key")):
            mod.check_structure(v)  # the structure holds
            with pytest.raises(VerifyError) as e:
                mod.check_document(v)
            assert e.value.reason == f"{what}.sig.invalid"


# ---- Q3. a resumed mirror repair validates the JSONL before any mutation --------------------


@pytest.mark.parametrize("step", STEPS)
def test_a_resumed_mirror_repair_validates_the_jsonl_before_any_mutation(tmp_path, capsys, step):
    """Q3: a torn mirror with a standing intent at each step, and the JSONL's chain
    broken: the verb refuses by the JSONL's name (ledger.chain), the mirror bytes and
    the marker bytes identical before and after, the intent standing; the JSONL
    restored, the resumed repair completes with exactly one audit."""
    a, b, wa, wb, fake, clock = _with_history_over_mail(tmp_path)
    jsonl, mirror = b.ledger.path, b.ledger.prose_path
    _tear_mirror(mirror, "tail")
    tail = b.ledger.excess_prose()
    assert tail
    size = mirror.stat().st_size
    intent = {
        "step": "intent",
        "file": "ledger.prose.txt",
        "truncate_to": size - len(tail),
        "bytes": len(tail),
        "tail_sha256": "sha256:" + sha256_hex(tail),
        "intent_id": new_id("rpr"),
        "ts": b.ts(),
    }
    if step in ("truncated", "audited"):
        # the cut happened (an earlier run): the mirror at the cut point
        mirror.write_bytes(mirror.read_bytes()[: intent["truncate_to"]])
        intent["step"] = "truncated"
    if step == "audited":
        # the audit landed too (before the marker: the guard refuses appends over it)
        audit = b.ledger.append(
            ts=b.ts(),
            actor="solo",
            grant_id=None,
            action="ledger.mirror_truncated",
            params_hash=intent["tail_sha256"],
            outcome="recorded",
            detail=f"truncated {len(tail)} bytes; intent {intent['intent_id']}",
            intent_id=intent["intent_id"],
        )
        intent = {**intent, "step": "audited", "audit_hash": entry_hash(audit)}
    marker = _write_marker(b, intent)
    whole = _break_chain(jsonl)
    before = (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes())
    assert main([*_argv(b), "ledger", "repair"]) == 2
    err = capsys.readouterr().err
    assert "ledger.chain" in err and str(jsonl) in err
    assert (jsonl.read_bytes(), mirror.read_bytes(), marker.read_bytes()) == before
    assert json.loads(marker.read_text())["step"] == step
    # the JSONL restored: the resume finishes from its step, one audit in all
    jsonl.write_bytes(whole)
    assert main([*_argv(b), "ledger", "repair"]) == 0
    assert _actions(b).count("ledger.mirror_truncated") == 1 and not marker.exists()
    assert main([*_argv(b), "ledger", "verify"]) == 0
    wa.send(a.compose_info(b.card, "after"))
    assert wb.poll_once()["applied"] == 1


@pytest.mark.parametrize("terminated", [True, False], ids=["newline", "no-newline"])
@pytest.mark.parametrize("store", ["feed", "denial"])
def test_a_resumed_feed_or_denial_repair_validates_the_sound_part_before_it_cuts(
    tmp_path, capsys, store, terminated
):
    """Q3, the same rule for the feed and the denial store: an intent stands for a
    torn tail; the sound part before the cut point holds a record that no longer
    verifies. The resume refuses by name (<store>.corrupt, the line named) with the
    file and the marker exactly as found; the record restored, the resume cuts.
    With the newline (round 13) no intent can stand — a line that ends in its
    newline and does not parse is corruption, never a torn tail: the repair verb
    refuses by name (line 1 while the record is damaged, line 2 once restored)
    with the file untouched, no intent, no audit; the line removed by hand, the
    store verifies."""
    n = make_node(tmp_path, "n", Clock(), extensions={"standing_denial": True})
    if store == "feed":
        n.revoke(grants=[uid("grt")], principal_statement="ok")
        obj, verb = n.revocations, "feed"
    else:
        n.deny(deny=[{"action": "info", "resource": "*"}], principal_statement="no")
        obj, verb = n.denials, "denial"
    sound = obj.path.read_bytes()
    rec = json.loads(sound)
    marker = n.state / f"{store}-repair-pending.json"
    if terminated:
        junk = sound[:40] + b"\n"
        for damaged, line in ((_store_line(_damage_record(rec, "sig-damaged")), 1), (sound, 2)):
            obj.path.write_bytes(damaged + junk)
            with pytest.raises(IntegrityError) as e:
                obj.torn_tail()
            assert e.value.reason == f"{store}.corrupt" and f"line {line}" in str(e.value)
            assert main([*_argv(n), verb, "repair"]) == 2
            err = capsys.readouterr().err
            assert (
                f"{store}.corrupt" in err and f"line {line}" in err and f"{store}.torn" not in err
            )
            assert obj.path.read_bytes() == damaged + junk and not marker.exists()
            assert _actions(n).count(f"{store}.repaired") == 0
        obj.path.write_bytes(sound)  # the line removed by hand
        assert main([*_argv(n), verb, "verify"]) == 0
        return
    torn = sound[:40]  # a torn copy of the record, no newline
    obj.path.write_bytes(sound + torn)
    assert obj.torn_tail() == torn
    intent = {
        "step": "intent",
        "file": obj.path.name,
        "truncate_to": len(sound),
        "bytes": len(torn),
        "tail_sha256": "sha256:" + sha256_hex(torn),
        "intent_id": new_id("rpr"),
        "ts": n.ts(),
    }
    marker.write_text(json.dumps(intent), encoding="utf-8")
    obj.path.write_bytes(_store_line(_damage_record(rec, "sig-damaged")) + torn)
    before = (obj.path.read_bytes(), marker.read_bytes())
    assert main([*_argv(n), verb, "repair"]) == 2
    err = capsys.readouterr().err
    assert f"{store}.corrupt" in err and str(obj.path) in err and "line 1" in err
    assert (obj.path.read_bytes(), marker.read_bytes()) == before
    obj.path.write_bytes(sound + torn)
    assert main([*_argv(n), verb, "repair"]) == 0
    assert obj.path.read_bytes() == sound and not marker.exists()
    assert _actions(n).count(f"{store}.repaired") == 1


# ---- the self-gate's four findings (all inside Q1-Q3), fixed in-family ------------------------


@pytest.mark.parametrize("store", ["feed", "denial"])
def test_a_whole_record_that_fails_its_document_check_is_never_cut_as_a_torn_tail(
    tmp_path, capsys, store
):
    """Self-gate 1: a complete record short of only its newline whose signature is
    damaged is corruption (<store>.corrupt, the line named), never a torn tail —
    load refuses, torn_tail raises, the repair verb exits 2 with the file and the
    restriction untouched and no intent left. A sound one is accepted and never cut."""
    n = make_node(tmp_path, "n", Clock(), extensions={"standing_denial": True})
    if store == "feed":
        n.revoke(grants=[uid("grt")], principal_statement="ok")
        obj = n.revocations
    else:
        n.deny(deny=[{"action": "info", "resource": "*"}], principal_statement="no")
        obj = n.denials
    sound = obj.path.read_bytes()
    rec = json.loads(sound)
    marker = n.state / f"{store}-repair-pending.json"
    # sound, short of only its newline: accepted, nothing cut, the newline back on repair
    obj.path.write_bytes(sound[:-1])
    (loaded,) = obj.entries()
    assert loaded == rec and obj.torn_tail() == b""
    assert main([*_argv(n), store, "repair"]) == 0
    assert obj.path.read_bytes() == sound[:-1] and not marker.exists()
    # damaged, short of only its newline — and with it (round 13, the newline
    # matrix): corruption either way, kept, never cut, no intent
    terminated = _store_line(_damage_record(rec, "sig-damaged"))
    for damaged in (terminated[:-1], terminated):
        obj.path.write_bytes(damaged)
        for read in (obj.entries, obj.torn_tail):
            with pytest.raises(IntegrityError) as e:
                read()
            assert e.value.reason == f"{store}.corrupt" and "line 1" in str(e.value)
            assert str(obj.path) in str(e.value)
        assert main([*_argv(n), store, "repair"]) == 2
        err = capsys.readouterr().err
        assert f"{store}.corrupt" in err and f"{store}.torn" not in err
        assert obj.path.read_bytes() == damaged and not marker.exists()
        assert _actions(n).count(f"{store}.repaired") == 0


def test_a_whole_object_on_the_jsonl_tail_that_is_not_the_next_entry_is_never_cut(tmp_path, capsys):
    """Self-gate 1, the ledger: an unterminated last line that is a complete JSON
    object but not the next entry of this chain (a wrong prev_hash) is corruption
    (ledger.corrupt), never a torn write: nothing cut, nothing terminated, no intent."""
    a, b, wa, wb, fake, clock = _with_history_over_mail(tmp_path)
    jsonl = b.ledger.path
    whole = jsonl.read_bytes()
    e = json.loads(whole.split(b"\n")[-2])
    e["prev_hash"] = "sha256:" + "2" * 64
    jsonl.write_bytes(whole + json.dumps(e, separators=(",", ":")).encode())
    torn = jsonl.read_bytes()
    for read in (b.ledger.torn_tail, b.ledger.terminate_tail):
        with pytest.raises(IntegrityError) as ex:
            read()
        assert ex.value.reason == "ledger.corrupt" and "whole object" in str(ex.value)
    assert main([*_argv(b), "ledger", "repair"]) == 2
    assert "ledger.corrupt" in capsys.readouterr().err
    assert jsonl.read_bytes() == torn and not (b.state / "ledger-repair-pending.json").exists()


@pytest.mark.parametrize("step", ["truncated", "audited"])
@pytest.mark.parametrize("store", ["feed", "denial", "ledger"])
def test_a_resumed_repair_refuses_a_file_shorter_than_its_cut_point_at_every_step(
    tmp_path, capsys, store, step
):
    """Self-gate 2: at the steps after the cut, a store shorter than the intent's
    cut point (records lost since the intent) is refused by name (<store>.corrupt,
    'shorter than'), the marker and the file exactly as found — never accepted as
    already cut, never a marker removed over lost restrictions."""
    n = make_node(tmp_path, "n", Clock(), extensions={"standing_denial": True})
    if store == "feed":
        n.revoke(grants=[uid("grt")], principal_statement="ok")
        path, fname = n.revocations.path, "revocations.jsonl"
    elif store == "denial":
        n.deny(deny=[{"action": "info", "resource": "*"}], principal_statement="no")
        path, fname = n.denials.path, "denials.jsonl"
    else:
        n.revoke(grants=[uid("grt")], principal_statement="ok")  # one ledger entry
        path, fname = n.ledger.path, "ledger.jsonl"
    sound = path.read_bytes()
    intent = {
        "step": step,
        "file": fname,
        "truncate_to": len(sound),
        "bytes": 40,
        "tail_sha256": "sha256:" + sha256_hex(b"x" * 40),
        "intent_id": new_id("rpr"),
        "ts": n.ts(),
    }
    if step == "audited":  # round 12: an audited marker carries its audit hash
        intent["audit_hash"] = "sha256:" + "0" * 64
    marker = n.state / f"{store}-repair-pending.json"
    marker.write_text(json.dumps(intent), encoding="utf-8")
    path.write_bytes(sound[: len(sound) // 2])  # records lost since the intent
    before = (path.read_bytes(), marker.read_bytes())
    assert main([*_argv(n), store, "repair"]) == 2
    err = capsys.readouterr().err
    assert f"{store}.corrupt" in err and "shorter than" in err and str(path) in err
    assert (path.read_bytes(), marker.read_bytes()) == before


def test_an_entry_with_a_timestamp_that_does_not_parse_is_corruption_at_the_load(tmp_path, capsys):
    """Self-gate 3: a ledger entry on file whose ts does not parse is
    ledger.entry.fields at the LOAD (the path and the line named) — at
    authorization a storage failure, the mail unseen, never a use count's
    VerifyError turned into no_authorizing_grant and acknowledged; the file put
    back, the retry applies."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    g = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "t.txt"),
        principal_statement=STATEMENT,
        max_uses=3,
    )
    wa.send(write_bundle(a, b, g, "t.txt"))
    assert wb.poll_once()["applied"] == 1 and wa.poll_once()["applied"] == 1
    wa.send(write_bundle(a, b, g, "t.txt", content="y\n"))
    jsonl = b.ledger.path
    whole = jsonl.read_bytes()
    lines = whole.split(b"\n")
    e = json.loads(lines[-2])  # the last entry: its hash is stored nowhere, the chain holds
    e["ts"] = "not a time"
    lines[-2] = json.dumps(e, ensure_ascii=False, separators=(",", ":")).encode()
    jsonl.write_bytes(b"\n".join(lines))
    with pytest.raises(IntegrityError) as ex:
        b.ledger.entries()
    assert ex.value.reason == "ledger.entry.fields" and f"line {len(lines) - 1}" in str(ex.value)
    assert str(jsonl) in str(ex.value) and "ts" in str(ex.value)
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False and s["applied"] == 0
    assert any("ledger.entry.fields" in x for x in s["errors"])
    assert len(_unseen_mail_ids(fake, b, wb)) == 1 and _inbox_len(fake) == inbox_before
    assert (b.scratch_dir / "t.txt").read_text() == "x\n"
    assert main([*_argv(b), "ledger", "verify"]) == 2 and "ledger.entry.fields" in (
        capsys.readouterr().err
    )
    jsonl.write_bytes(whole)
    s = wb.poll_once()
    assert s["applied"] == 1 and s["replies"] == 1 and s["complete"] is True
    assert (b.scratch_dir / "t.txt").read_text() == "y\n"
    assert not any("no_authorizing_grant" in o for o in _outcomes(b))


@pytest.mark.parametrize("depth", [300, 100_000], ids=["parses", "recursion"])
def test_an_entry_with_a_deeply_nested_unknown_field_is_corruption_never_an_escape(tmp_path, depth):
    """Self-gate 4: a ledger line carrying an unknown field nested deep — one the
    parser accepts (refused as ledger.entry.fields before anything is hashed) and
    one past the recursion limit (ledger.corrupt at the parse) — is corruption at
    the load, a counted storage failure at the poll, never a RecursionError out of
    hashing or out of the poll."""
    a, b, wa, wb, fake, clock = _with_history_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "hello"))
    jsonl = b.ledger.path
    whole = jsonl.read_bytes()
    last = json.loads(whole.split(b"\n")[-2])
    e = {**last, "prev_hash": entry_hash(last), "x": None}
    nested = "[" * depth + "]" * depth
    line = json.dumps(e, separators=(",", ":")).replace('"x":null', '"x":' + nested)
    jsonl.write_bytes(whole + line.encode() + b"\n")
    with pytest.raises(IntegrityError) as ex:
        b.ledger.entries()
    assert ex.value.reason in ("ledger.entry.fields", "ledger.corrupt")
    assert str(jsonl) in str(ex.value) and not isinstance(ex.value, VerifyError)
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False and s["applied"] == 0
    assert any(ex.value.reason in x for x in s["errors"])
    assert len(_unseen_mail_ids(fake, b, wb)) == 1
    jsonl.write_bytes(whole)
    assert wb.poll_once()["applied"] == 1

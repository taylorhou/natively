"""Gate round 10 (hw-njl0a): the ninth cross-model gate report, three MAJOR and one
MINOR, each on an edge the ninth round's rule did not reach.

P1  A grant ON FILE was authenticated before it was stored, so anything about the
    document that no longer holds is local corruption, never a refusal: the loader
    verifies the document in full on every read (structure with every field of its
    type, the signatures under the keys it names, the embedded parent likewise).
    Previously a cached grant whose sig was an empty list passed the loader and the
    message naming it was refused no_authorizing_grant — acknowledged, the mail seen,
    and the restored file replayed that refusal.
P2  Every text read the package performs on its own files decodes with a failure
    mapped to that file's corruption reason; the prose mirror's is
    ledger.mirror_corrupt naming the path and the byte offset; a UnicodeDecodeError
    is not reachable above the loaders (a guard walks the package's AST). The ledger
    repair verb rebuilds a torn mirror from the JSONL when the JSONL verifies.
P3  Every export of a bundle crosses the ONE outgoing boundary (`Node.check_outgoing`:
    a reply through check_reply, every other kind through its own check) before it is
    encoded or written, in the --out and --dry-run --out forms alike, and at the
    wire's send. Previously `ack --out` wrote a reply damaged after the validation
    that read it, with exit 0.
P4  The staged wire body's removal records its own failure whatever the transport
    did: a transport failure beside a cleanup failure is ONE storage failure naming
    both, counted, the cursor frozen, the transport accounting unchanged.
"""

from __future__ import annotations

import ast
import base64
import json
import subprocess
from pathlib import Path

import pytest

from natively import bundle as bundlemod
from natively import grant as grantmod
from natively import message as msgmod
from natively.adapters import mail as mailmod
from natively.cli import main
from natively.errors import IntegrityError, StorageError, VerifyError
from natively.node import Node

from .conftest import uid
from .test_gate_round3 import seen_of
from .test_gate_round6 import _connected_over_mail
from .test_gate_round7 import _argv, _held_ack_over_mail
from .test_gate_round7b import _acks_out, _actions, _inbox_len
from .test_gate_round8 import _flip, _unseen_mail_ids
from .test_gate_round9 import _no_transport, _outcomes
from .test_hardening import STATEMENT, fs_write_scope, pair, write_bundle

__all__ = ["pair"]  # the fixture is re-exported for this module's tests

PKG = Path(__file__).resolve().parents[1] / "natively"
SIG_DAMAGE = ["sig-empty-list", "sig-wrong-length", "sig-damaged"]
WHERE = ["grant", "parent"]
EM_DASH = "—".encode()  # e2 80 94: the prose line's " — " before a detail


# ---- P1. a grant on file is verified in full at every load --------------------------------


def _damage_sig(g: dict, how: str) -> dict:
    if how == "sig-empty-list":
        return {**g, "sig": []}
    if how == "sig-wrong-length":
        return {**g, "sig": base64.b64encode(b"\x00" * 63).decode("ascii")}
    return {**g, "sig": _flip(g["sig"])}


def _damaged(g: dict, how: str, where: str) -> dict:
    if where == "grant":
        return _damage_sig(g, how)
    return {**g, "parent_grant": _damage_sig(g["parent_grant"], how)}


def _naming_only(a, b, gid: str, name: str) -> dict:
    """An action bundle that NAMES the grant and attaches nothing: the receiver
    judges its cached copy alone."""
    m = msgmod.sign(
        msgmod.action(
            from_key=a.agent.public,
            to_key=b.card["agent"]["key"],
            ts=a.ts(),
            action="fs.write",
            resource=b.executor().resource_for(name),
            params={"content": "y\n"},
            grant_ids=[gid],
        ),
        a.agent,
    )
    return bundlemod.make("message", m, cards=[a.card])


def _attaching(a, b, g: dict, name: str) -> dict:
    """An action bundle that attaches the grant object `g` as given."""
    m = _naming_only(a, b, g["grant_id"], name)
    return {**m, "grants": [g]}


def _cached_grant_over_mail(tmp_path, where: str):
    """a and b connected over mail; b holds an executable grant from a on file —
    a root grant (where='grant'), or a depth-one delegation whose parent is
    embedded in the child's file (where='parent') — after one applied use."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    if where == "grant":
        g = a.issue_grant(
            subject_card=b.card,
            scope=fs_write_scope(b, "f.txt"),
            principal_statement=STATEMENT,
            max_uses=4,
        )
    else:
        # a's principal roots a grant to a's OWN agent for b's executor; a delegates
        # a strictly tighter scope to b; b stores the child (the parent embedded)
        parent = a.issue_grant(
            subject_card=a.card,
            scope=fs_write_scope(b, "f.txt", regex=None),
            principal_statement=STATEMENT,
            max_uses=4,
            audience=b.host.public,
        )
        g = a.delegate_grant(
            parent=parent,
            subject_card=b.card,
            scope=fs_write_scope(b, "f.txt"),
            principal_statement=STATEMENT,
        )
    wa.send(write_bundle(a, b, g, "f.txt"))
    s = wb.poll_once()
    assert s["applied"] == 1 and s["replies"] == 1 and s["complete"] is True
    assert (b.scratch_dir / "f.txt").read_text() == "x\n"
    assert wa.poll_once()["applied"] == 1
    return a, b, wa, wb, fake, clock, g


@pytest.mark.parametrize("where", WHERE)
@pytest.mark.parametrize("how", SIG_DAMAGE)
def test_a_damaged_cached_grant_is_corruption_at_the_poll_never_a_refusal(tmp_path, how, where):
    """P1: the cached grant's signature (or its embedded parent's) is an empty list,
    a string of the wrong length, or damaged; the message names the grant and
    attaches nothing. receive is a storage failure — nothing ledgered, nothing
    acknowledged, the mail unseen, storage_failures 1, complete False, the path in
    the errors, never no_authorizing_grant; the file put back, the retry applies."""
    a, b, wa, wb, fake, clock, g = _cached_grant_over_mail(tmp_path, where)
    stored = b.state / "grants" / f"{g['grant_id']}.json"
    original = stored.read_bytes()
    stored.write_text(json.dumps(_damaged(g, how, where)), encoding="utf-8")
    wa.send(_naming_only(a, b, g["grant_id"], "f.txt"))  # inside the scope; a second use
    inbox_before, entries_before = _inbox_len(fake), len(b.ledger)
    # the loader itself, by name
    with pytest.raises(IntegrityError) as e:
        b.load_grant(g["grant_id"])
    assert e.value.reason == "state.corrupt" and str(stored) in str(e.value)
    assert "sig" in str(e.value)
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False and s["applied"] == 0
    assert any("state.corrupt" in x and str(stored) in x for x in s["errors"])
    assert len(_unseen_mail_ids(fake, b, wb)) == 1  # the mail stays unseen
    assert _inbox_len(fake) == inbox_before and len(b.ledger) == entries_before
    assert not any("no_authorizing_grant" in o for o in _outcomes(b))
    assert "verify_failed:malformed" not in _outcomes(b)
    assert (b.scratch_dir / "f.txt").read_text() == "x\n"  # the first write, untouched
    stored.write_bytes(original)
    s = wb.poll_once()
    assert s["applied"] == 1 and s["replies"] == 1 and s["complete"] is True
    assert (b.scratch_dir / "f.txt").read_text() == "y\n"  # the retry applied the action
    (ack,) = _acks_out(fake, inbox_before)
    assert ack["outcome"] == "applied"


@pytest.mark.parametrize("where", WHERE)
@pytest.mark.parametrize("how", SIG_DAMAGE)
def test_the_same_damage_arriving_as_an_attachment_is_refused_as_peer_input(tmp_path, how, where):
    """P1: the identical damage on the ATTACHED copy is a verify failure at receipt
    (a refusal on peer input): ledgered, the message refused no_authorizing_grant
    and acknowledged, the mail seen, no storage failure; the sound cached copy is
    never substituted for a refused attachment."""
    a, b, wa, wb, fake, clock, g = _cached_grant_over_mail(tmp_path, where)
    hostile = _attaching(a, b, _damaged(g, how, where), "f.txt")
    with pytest.raises(IntegrityError) as e:  # a's own outgoing boundary refuses it (P3)
        wa.send(hostile)
    assert e.value.reason == "message.invalid" and "grants[0].grant" in str(e.value)
    fake.add(wb.self_email, wa.self_email, bundlemod.encode(hostile))  # past that boundary
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()
    assert s["storage_failures"] == 0 and s["complete"] is True and s["applied"] == 1
    assert _unseen_mail_ids(fake, b, wb) == set()
    (ack,) = _acks_out(fake, inbox_before)
    assert ack["outcome"] == "refused:no_authorizing_grant"
    outcomes = _outcomes(b)
    assert any(o.startswith("verify_failed:grant.") and "sig" in o for o in outcomes)
    assert "refused" in outcomes and "verify_failed:malformed" not in outcomes
    assert "attached copy failed verification" in b.ledger.entries()[-1]["detail"]
    assert (b.scratch_dir / "f.txt").read_text() == "x\n"  # nothing executed
    assert b.load_grant(g["grant_id"]) == g  # the cached copy is untouched and sound


def test_the_structure_check_names_every_signature_and_key_field_type(pair):
    """P1: check_structure refuses a signature that is not a base64 string of 64
    bytes and a key or hash field that does not decode, by name — at receipt on peer
    input (a VerifyError) and so, through the loader, on a file of ours."""
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "f.txt"), principal_statement=STATEMENT
    )
    grantmod.check_structure(g)
    bad = {
        "grant.sig.format": [{**g, "sig": []}, {**g, "sig": 5}, {**g, "sig": "not base64!"}],
        "grant.issuer.key.format": [{**g, "issuer": {**g["issuer"], "key": "ed25519:zz"}}],
        "grant.subject.agent.format": [{**g, "subject": {**g["subject"], "agent": "sha256:x"}}],
        "grant.subject.key.format": [{**g, "subject": {**g["subject"], "key": "ed25519:"}}],
        "grant.audience.executor.format": [{**g, "audience": {"executor": "ed25519:AAAA"}}],
        "grant.parent_grant.format": [{**g, "parent_grant": []}],
    }
    for reason, variants in bad.items():
        for v in variants:
            with pytest.raises(VerifyError) as e:
                grantmod.check_structure(v)
            assert e.value.reason == reason, (reason, e.value.reason)
    short = {**g, "sig": base64.b64encode(b"\x00" * 63).decode("ascii")}
    with pytest.raises(VerifyError) as e:
        grantmod.check_structure(short)
    assert e.value.reason == "grant.sig.format" and "64 bytes" in e.value.detail
    # the document check: a sound structure whose signature does not verify
    with pytest.raises(VerifyError) as e:
        grantmod.check_document({**g, "sig": _flip(g["sig"])})
    assert e.value.reason == "grant.sig.invalid"
    grantmod.check_document(g)


# ---- P2. every text read of our own files maps to that file's corruption reason ------------


def _with_history_over_mail(tmp_path):
    """a and b connected, b's ledger holding three entries whose prose carries a
    detail (an em dash: card.received, two info.received), nothing pending."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "one"))
    wa.send(a.compose_info(b.card, "two"))
    assert wb.poll_once()["applied"] == 2 and wa.poll_once()["applied"] == 2
    assert len(b.ledger.entries()) == 3
    return a, b, wa, wb, fake, clock


def _tear_mirror(mirror: Path, where: str) -> int:
    """Tear the prose mirror inside a multibyte character (the em dash of a detail):
    at the tail (the last line cut mid-character, no newline) or in the middle (the
    first line's em dash short by one byte, the rest intact). Returns the byte
    offset where decoding fails."""
    data = mirror.read_bytes()
    lines = data.split(b"\n")[:-1]
    assert len(lines) >= 3 and all(EM_DASH in ln for ln in lines[:1] + lines[-1:])
    if where == "tail":
        last_start = len(data) - len(lines[-1]) - 1
        off = last_start + lines[-1].index(EM_DASH)
        torn = data[: off + 2]  # e2 80, the 94 and everything after it lost
        mirror.write_bytes(torn)
        return off
    off = lines[0].index(EM_DASH)
    torn = lines[0][:off] + EM_DASH[:2] + lines[0][off + 3 :]  # e2 80 then a space
    mirror.write_bytes(b"\n".join([torn, *lines[1:]]) + b"\n")
    return off


@pytest.mark.parametrize("where", ["tail", "middle"])
def test_a_torn_prose_mirror_is_a_counted_storage_failure_then_repaired(tmp_path, capsys, where):
    """P2: a mirror torn inside a multibyte character: receive is a counted storage
    failure with no exception out of the poll, nothing ledgered, the mail unseen;
    `ledger verify` names the path and the byte offset (ledger.mirror_corrupt);
    `ledger repair` rebuilds the mirror from the JSONL (the bytes from the damaged
    line on truncated and audited, the lines regenerated); the retry applies."""
    a, b, wa, wb, fake, clock = _with_history_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "hello"))
    mirror = b.ledger.prose_path
    off = _tear_mirror(mirror, where)
    torn = mirror.read_bytes()
    jsonl_before = b.ledger.path.read_bytes()
    inbox_before = _inbox_len(fake)
    s = wb.poll_once()  # no exception out of the poll
    assert s["storage_failures"] == 1 and s["complete"] is False and s["applied"] == 0
    (err,) = [x for x in s["errors"] if "ledger.mirror_corrupt" in x]
    assert str(mirror) in err and f"byte offset {off}" in err
    assert len(_unseen_mail_ids(fake, b, wb)) == 1 and _inbox_len(fake) == inbox_before
    assert b.ledger.path.read_bytes() == jsonl_before and mirror.read_bytes() == torn
    assert wb._pending_replies() == []
    # the verb names it the same way; the append path refuses the same way
    assert main([*_argv(b), "ledger", "verify"]) == 2
    e = capsys.readouterr().err
    assert "ledger.mirror_corrupt" in e and str(mirror) in e and f"byte offset {off}" in e
    with pytest.raises(IntegrityError) as ex:
        b.ledger.verify()
    assert ex.value.reason == "ledger.mirror_corrupt"
    with pytest.raises(IntegrityError) as ex:
        b.ledger.append(
            ts=b.ts(), actor="x", grant_id=None, action="x", params_hash=None, outcome="information"
        )
    assert ex.value.reason == "ledger.mirror_corrupt" and mirror.read_bytes() == torn
    # the repair verb: the damaged tail cut (audited once), every line regenerated
    n_entries = len(b.ledger.entries())
    assert main([*_argv(b), "ledger", "repair"]) == 0
    out = capsys.readouterr().out
    assert "ledger repaired" in out and "truncated (ledger.mirror_truncated)" in out
    assert _actions(b).count("ledger.mirror_truncated") == 1
    assert len(b.ledger.entries()) == n_entries + 1
    head = b.ledger.verify()
    assert main([*_argv(b), "ledger", "verify"]) == 0 and head in capsys.readouterr().out
    lines = mirror.read_text(encoding="utf-8").split("\n")[:-1]
    assert len(lines) == n_entries + 1 and all(EM_DASH.decode() in ln for ln in lines[:1])
    s = wb.poll_once()
    assert s["applied"] == 1 and s["replies"] == 1 and s["complete"] is True
    assert wa.poll_once()["applied"] == 1 and a.outbox()[-1]["status"] == "acked"


def test_the_repair_verb_refuses_a_torn_mirror_when_the_jsonl_is_damaged_too(tmp_path, capsys):
    """P2: both sides damaged — the JSONL chain broken AND the mirror torn — the repair
    verb refuses by the JSONL's name (ledger.chain), nothing is written to either."""
    a, b, wa, wb, fake, clock = _with_history_over_mail(tmp_path)
    mirror = b.ledger.prose_path
    _tear_mirror(mirror, "middle")
    torn = mirror.read_bytes()
    lines = b.ledger.path.read_bytes().split(b"\n")
    e = json.loads(lines[1])
    e["prev_hash"] = "sha256:" + "1" * 64
    lines[1] = json.dumps(e, ensure_ascii=False, separators=(",", ":")).encode()
    b.ledger.path.write_bytes(b"\n".join(lines))
    jsonl = b.ledger.path.read_bytes()
    assert main([*_argv(b), "ledger", "repair"]) == 2
    assert "ledger.chain" in capsys.readouterr().err
    assert mirror.read_bytes() == torn and b.ledger.path.read_bytes() == jsonl
    assert not (b.state / "ledger-repair-pending.json").exists()


def test_the_repair_verb_refuses_a_torn_mirror_whose_sound_lines_are_not_this_ledgers(
    tmp_path, capsys
):
    """P2: a torn mirror whose whole line before the damage is not its entry's prose
    is not this ledger's mirror: ledger.repair.refused, nothing written."""
    a, b, wa, wb, fake, clock = _with_history_over_mail(tmp_path)
    mirror = b.ledger.prose_path
    _tear_mirror(mirror, "tail")
    data = mirror.read_bytes()
    first, rest = data.split(b"\n", 1)
    mirror.write_bytes(b"edited by hand" + first[14:] + b"\n" + rest)
    torn = mirror.read_bytes()
    assert main([*_argv(b), "ledger", "repair"]) == 2
    assert "ledger.repair.refused" in capsys.readouterr().err
    assert mirror.read_bytes() == torn
    assert not (b.state / "ledger-repair-pending.json").exists()


@pytest.mark.parametrize("terminated", [True, False], ids=["newline", "no-newline"])
def test_a_torn_multibyte_character_in_a_jsonl_line_or_a_state_file_is_corruption(
    tmp_path, terminated
):
    """P2: the same shape on one JSONL store line (the ledger, the feed, the denial
    store) and on one JSON state file (seen.json), each at its own read site: the
    file's corruption reason, an IntegrityError, a storage failure of the poll —
    never an exception out of the poll, never malformed peer input. With the torn
    line's newline and without it (round 11: an unterminated tail is the file's
    truncated/torn reason, an IntegrityError like the rest, never a VerifyError)."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "hello"))
    torn_line = b'{"ts": "x\xe2\x80"}' + (b"\n" if terminated else b"")
    # the ledger: ledger.corrupt at its own load. Round 20 (the prefix rule): the
    # damaged character sits in the MIDDLE of the line, with a whole record's bytes
    # after it, so the unterminated shape is not a strict prefix of one record of
    # ours either — corruption by name, never a torn write to cut (before, a decode
    # failure anywhere read as a tear: ledger.truncated / feed.torn / denial.torn)
    ledger = b.ledger.path
    whole = ledger.read_bytes()
    ledger.write_bytes(whole + torn_line)
    reason = "ledger.corrupt"
    with pytest.raises(IntegrityError) as e:
        b.ledger.entries()
    assert e.value.reason == reason and str(ledger) in str(e.value)
    assert not isinstance(e.value, VerifyError)
    assert not terminated or "UnicodeDecodeError" in str(e.value)
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False
    assert any(reason in x for x in s["errors"])
    assert len(_unseen_mail_ids(fake, b, wb)) == 1
    ledger.write_bytes(whole)
    # the feed and the denial store: feed.corrupt / denial.corrupt at their loads,
    # with and without the newline (the prefix rule, round 20)
    for store, what in ((b.revocations, "feed"), (b.denials, "denial")):
        store.path.write_bytes(torn_line)
        with pytest.raises(IntegrityError) as e:
            store.load()
        assert e.value.reason == f"{what}.corrupt"
        assert "UnicodeDecodeError" in str(e.value) and str(store.path) in str(e.value)
        store.path.unlink()
    # a state file: state.corrupt naming the path, at the typed loader
    seen = b.state / "seen.json"
    seen.write_bytes(torn_line)
    with pytest.raises(IntegrityError) as e:
        b._seen()
    assert e.value.reason == "state.corrupt" and str(seen) in str(e.value)
    assert "UnicodeDecodeError" in str(e.value)
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False
    assert any("state.corrupt" in x and str(seen) in x for x in s["errors"])
    assert "verify_failed:malformed" not in _outcomes(b)
    seen.unlink()
    s = wb.poll_once()
    assert s["applied"] == 1 and s["replies"] == 1 and s["complete"] is True


def _text_reads(tree: ast.AST) -> list[tuple[str, str]]:
    """(enclosing function, what) for every text-producing read in a module: a
    bytes .decode(...) call (no argument, or a constant encoding — a module's
    decode(text) takes a name), a .read_text(...) call, a builtin open() or an
    os.fdopen() in a text mode that reads (os.open yields a descriptor, bytes)."""
    out: list[tuple[str, str]] = []
    stack: list[str] = ["<module>"]

    def mode_of(call: ast.Call) -> str:
        for kw in call.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                return str(kw.value.value)
        if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant):
            return str(call.args[1].value)
        return "r"  # open's default: text, read

    def visit(node: ast.AST) -> None:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            stack.append(node.name)
            for child in ast.iter_child_nodes(node):
                visit(child)
            stack.pop()
            return
        if isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            is_bytes_decode = name == "decode" and (
                not node.args or isinstance(node.args[0], ast.Constant)
            )
            is_builtin_open = name == "open" and isinstance(f, ast.Name)
            if is_bytes_decode or name == "read_text":
                out.append((stack[-1], name))
            elif is_builtin_open or name == "fdopen":
                m = mode_of(node)
                if "b" not in m and ("r" in m or "+" in m):
                    out.append((stack[-1], f"open:{m}"))
        for child in ast.iter_child_nodes(node):
            visit(child)

    visit(tree)
    return out


def test_no_text_read_of_a_file_of_ours_escapes_the_loaders():
    """P2 guard: every text-producing read in the package is one of these, by
    enclosing function; anything new fails here until it maps a decoding failure to
    its file's corruption reason (or is documented as not a file of ours)."""
    expected = {
        # our own files: a decoding failure is that file's corruption reason
        # round 19: every parse of a file of ours (a state file, a line of the ledger,
        # the feed or the denial store) runs through durable.parse_local — the one
        # decode, the one duplicate-member rule; the callers name the file
        ("durable.py", "parse_local", "decode"),
        ("durable.py", "is_blank_line", "decode"),  # inside its own try: undecodable is never blank
        # round 20: the prefix rule decodes the longest valid prefix inside its own try
        ("durable.py", "torn_text_problem", "decode"),
        ("ledger.py", "_decode_mirror", "decode"),  # ledger.mirror_corrupt (+ offset)
        ("ledger.py", "excess_prose", "decode"),  # the repair path, inside its own try
        ("ledger.py", "_undecodable_tail", "decode"),  # bytes before the offending byte
        ("ledger.py", "cut_undecodable_tail", "decode"),  # the resumed repair, inside its try
        ("ledger.py", "check_mirror", "decode"),  # the resumed stage's check, inside its try
        ("ledger.py", "terminated_mend_point", "decode"),  # the fresh run's decision, in its try
        # peer input: a decoding failure is a VerifyError on the bundle
        ("jsonsafe.py", "loads", "decode"),
        # base64 output decoded as ascii (cannot fail): encoders
        ("bundle.py", "encode", "decode"),
        ("keys.py", "_b64", "decode"),
        ("message.py", "encode_body", "decode"),
        # NOT files of ours: the key file (the keys dir), operator-given input files
        # (`--param k=@file`, `poll --file`, `wire-decode FILE`) — a bad file exits 1
        ("keys.py", "load", "read_text"),
        ("cli.py", "_value", "read_text"),
        ("cli.py", "cmd_poll", "read_text"),
        ("cli.py", "cmd_wire_decode", "read_text"),
        # NOT a file of ours: the mail helper's stdout and stderr, read up to a bound
        # decided before the read and decoded with replacement (the JSON rows are
        # judged after, row by row; a wire failure is reported on the text) — round 21
        ("adapters/mail.py", "default_runner", "decode"),
    }
    found = set()
    for f in sorted(PKG.rglob("*.py")):
        rel = f.relative_to(PKG).as_posix()
        for fn, what in _text_reads(ast.parse(f.read_text(encoding="utf-8"))):
            found.add((rel, fn, what))
    assert found == expected, (sorted(found - expected), sorted(expected - found))


# ---- P3. every export crosses the ONE outgoing boundary --------------------------------------


def _no_runner(argv):
    raise AssertionError("the transport was called")


def _damaged_copy_from(monkeypatch, cls, method: str):
    """`method` on `cls` returns its real result with the object's signature damaged
    AFTER whatever validation produced it (the round-8 wrapper technique)."""
    real = getattr(cls, method)

    def damaged(self, *args, **kw):
        out = real(self, *args, **kw)
        r, tail = (out[0], out[1:]) if isinstance(out, tuple) else (out, ())
        if not isinstance(r, dict):
            return out
        d = {**r, "object": {**r["object"], "sig": _flip(r["object"]["sig"])}}
        return (d, *tail) if tail else d

    monkeypatch.setattr(cls, method, damaged)


def test_ack_out_crosses_the_outgoing_boundary_in_both_forms(tmp_path, monkeypatch, capsys):
    """P3: a sound stored reply whose outgoing copy is damaged after the validation
    that read it: `ack --out` and `ack --dry-run --out` both exit 2 naming
    reply.invalid, no file written (an existing one untouched), the stored ack
    untouched, zero transport calls; the failure gone, both forms export a file
    whose content verifies."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "one"))
    assert wb.poll_once()["replies"] == 1
    msg_id = a.outbox()[-1]["msg_id"]
    stored_before = seen_of(b)[msg_id]
    transport = _no_transport(monkeypatch)
    _damaged_copy_from(monkeypatch, Node, "stored_reply")
    out = tmp_path / "ack.txt"
    for form in (["--out", str(out)], ["--dry-run", "--out", str(out)]):
        assert main([*_argv(b), "ack", msg_id, *form]) == 2
        err = capsys.readouterr().err
        assert "reply.invalid" in err and "ack.sig" in err and "nothing sent" in err
        assert not out.exists()
    out.write_text("an earlier export, left alone", encoding="utf-8")
    for form in (["--out", str(out)], ["--dry-run", "--out", str(out)]):
        assert main([*_argv(b), "ack", msg_id, *form]) == 2
        assert out.read_text(encoding="utf-8") == "an earlier export, left alone"
    assert transport == [] and seen_of(b)[msg_id] == stored_before
    monkeypatch.undo()
    monkeypatch.setattr(mailmod, "default_runner", _no_runner)
    for form in (["--out", str(out)], ["--dry-run", "--out", str(out)]):
        out.unlink()
        assert main([*_argv(b), "ack", msg_id, *form]) == 0
        r = bundlemod.decode(out.read_text(encoding="utf-8"))
        assert b.check_reply(r) is r and r["object"] == stored_before["ack"]
    capsys.readouterr()


@pytest.mark.parametrize("kind", ["message", "card", "revocation"])
def test_every_other_export_crosses_its_own_kinds_check(tmp_path, monkeypatch, capsys, kind):
    """P3: the sweep — send --info, send --card and revoke, in the --out and the
    --dry-run --out forms and at the wire's send: a bundle of that kind damaged
    after it was composed is <kind>.invalid (exit 2), no file, nothing recorded,
    nothing transmitted; the sound one exports."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    transport = _no_transport(monkeypatch)
    method = {"message": "compose_info", "card": "compose_card", "revocation": "compose_revocation"}
    argv = {
        "message": ["send", "--to", b.card["agent"]["name"], "--info", "hi"],
        "card": ["send", "--card"],
        "revocation": ["revoke", "--grant", uid("grt"), "--statement", "never mind"],
    }
    out = tmp_path / f"{kind}.txt"
    _damaged_copy_from(monkeypatch, Node, method[kind])
    outbox_before, feed_before, ledger_before = (
        len(a.outbox()),
        len(a.revocations.entries()),
        len(a.ledger),
    )
    for form in (["--out", str(out)], ["--dry-run", "--out", str(out)]):
        assert main([*_argv(a), *argv[kind], *form]) == 2
        err = capsys.readouterr().err
        assert f"{kind}.invalid" in err and "sig.invalid" in err and "nothing sent" in err
        assert not out.exists()
    assert len(a.outbox()) == outbox_before and transport == []
    # nothing was RECORDED either: a refused revocation changed no enforcement state
    assert len(a.revocations.entries()) == feed_before and len(a.ledger) == ledger_before
    # the wire's send refuses the same bundle: nothing transmitted, nothing recorded
    compose = {
        "message": lambda: a.compose_info(b.card, "hi"),
        "card": a.compose_card,
        "revocation": lambda: a.compose_revocation(
            a.revoke(grants=[uid("grt")], principal_statement="never mind")
        ),
    }
    sends_before = len(fake.sends)
    with pytest.raises(IntegrityError) as e:
        wa.send(compose[kind]())
    assert e.value.reason == f"{kind}.invalid"
    assert len(fake.sends) == sends_before and len(a.outbox()) == outbox_before
    monkeypatch.undo()
    monkeypatch.setattr(mailmod, "default_runner", _no_runner)
    assert main([*_argv(a), *argv[kind], "--dry-run", "--out", str(out)]) == 0
    exported = bundlemod.decode(out.read_text(encoding="utf-8"))
    assert exported["kind"] == kind and a.check_outgoing(exported) is exported
    capsys.readouterr()


def test_the_outgoing_check_refuses_what_is_not_this_nodes(pair):
    """P3: `check_outgoing`, directly: another node's message, card or revocation,
    an ack (through check_reply), a damaged card or grant in the envelope, a
    non-bundle — each refused by its kind; this node's own bundles pass."""
    a, b, clock, reports = pair
    g = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "f.txt"), principal_statement=STATEMENT
    )
    m = write_bundle(a, b, g, "f.txt")
    assert a.check_outgoing(m) is m and a.check_outgoing(a.compose_card()) is not None
    rev = a.compose_revocation(a.revoke(grants=[g["grant_id"]], principal_statement="x"))
    assert a.check_outgoing(rev) is rev
    for bad, reason in (
        (m, "message.invalid"),  # b: not signed by this agent
        (a.compose_card(), "card.invalid"),  # b: not this node's card
        (rev, "revocation.invalid"),  # b: not by this node's principal
        ({**m, "cards": [[]]}, "message.invalid"),
        ({**m, "grants": [{**g, "sig": []}]}, "message.invalid"),
        ([], "bundle.invalid"),
        (bundlemod.make("ack", {}), "reply.invalid"),
    ):
        with pytest.raises(IntegrityError) as e:
            b.check_outgoing(bad)
        assert e.value.reason == reason and "nothing sent" in str(e.value)


# ---- P4. a cleanup failure beside a transport failure is counted -----------------------------


class _NoRemoval(type(Path())):
    def unlink(self, missing_ok=False):
        raise OSError(5, "Input/output error", str(self))


def _transport_failing(wb, fake, how: str, monkeypatch):
    """The send tool fails: a non-zero exit, or the runner raising (a timeout)."""
    if how == "nonzero-exit":
        fake.fail_sends = True
        return "rc=1"
    real = wb.run

    def run(argv):
        if Path(argv[1]).name == mailmod.GMAIL_SEND.name:
            raise subprocess.TimeoutExpired(argv, 120)
        return real(argv)

    monkeypatch.setattr(wb, "run", run)
    return "TimeoutExpired"


@pytest.mark.parametrize("how", ["runner-raises", "nonzero-exit"])
def test_a_cleanup_failure_beside_a_transport_failure_is_counted_naming_both(
    tmp_path, monkeypatch, how
):
    """P4: the send tool fails AND the staged body cannot be removed: ONE storage
    failure naming both facts, storage_failures 1, complete False, the cursor
    unchanged, the held copy kept, nothing transmitted, no attempt spent — never
    a transport failure that hides the cleanup; the failures gone, the copy goes."""
    a, b, wa, wb, fake, clock, held, reports = _held_ack_over_mail(tmp_path)
    (p,) = held
    cursor_before = wb.cursor()
    assert cursor_before is not None
    clock.tick(5)
    inbox_before, sends_before = _inbox_len(fake), len(fake.sends)
    token = _transport_failing(wb, fake, how, monkeypatch)
    monkeypatch.setattr(mailmod, "Path", _NoRemoval)
    s = wb.poll_once()
    monkeypatch.undo()
    fake.fail_sends = False
    assert s["storage_failures"] == 1 and s["complete"] is False and s["replies"] == 0
    assert p.exists() and wb.cursor() == cursor_before and _inbox_len(fake) == inbox_before
    (err,) = [e for e in s["errors"] if f"in the send of held reply {p.name}" in e]
    assert token in err and "could not be removed" in err and "Input/output error" in err
    assert "StorageError" in err and not any("ack send failed" in e for e in s["errors"])
    assert "pending_reply.corrupt" not in _actions(b)
    s = wb.poll_once()
    assert s["replies"] == 1 and s["complete"] is True and not p.exists()
    assert len(fake.sends) >= sends_before + 1
    assert wa.poll_once()["applied"] == 1 and a.outbox()[-1]["status"] == "acked"


@pytest.mark.parametrize("how", ["runner-raises", "nonzero-exit"])
def test_a_transport_failure_with_a_clean_removal_keeps_the_existing_accounting(
    tmp_path, monkeypatch, how
):
    """P4: the transport class alone, as before: reported as a send failure, no
    storage count, the held copy kept for the next poll, the staged body gone."""
    a, b, wa, wb, fake, clock, held, reports = _held_ack_over_mail(tmp_path)
    (p,) = held
    staged: list[str] = []
    real_tmp = mailmod.tempfile.NamedTemporaryFile

    def tmp(*args, **kw):
        f = real_tmp(*args, **kw)
        staged.append(f.name)
        return f

    monkeypatch.setattr(mailmod.tempfile, "NamedTemporaryFile", tmp)
    _transport_failing(wb, fake, how, monkeypatch)
    s = wb.poll_once()
    monkeypatch.undo()
    fake.fail_sends = False
    assert s["storage_failures"] == 0 and s["replies"] == 0 and p.exists()
    assert any("ack send failed" in e for e in s["errors"])
    assert not any("storage failure in the send" in e for e in s["errors"])
    assert staged and not any(Path(x).exists() for x in staged)
    s = wb.poll_once()
    assert s["replies"] == 1 and s["complete"] is True and not p.exists()


def test_the_send_failure_classes_beside_a_cleanup_failure_are_told_apart_by_type(
    tmp_path, monkeypatch
):
    """P4: at the outbox re-send too — a transport failure beside a cleanup failure
    is the storage class (the entry kept, no attempt spent, counted); a transport
    failure alone spends no attempt and counts nothing."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "anyone?"))
    msg_id = a.outbox()[-1]["msg_id"]
    clock.tick(2 * a.poll_s)
    fake.fail_sends = True
    monkeypatch.setattr(mailmod, "Path", _NoRemoval)
    s = wa.poll_once()
    monkeypatch.undo()
    assert s["storage_failures"] == 1 and s["resent"] == 0 and s["complete"] is False
    (err,) = [e for e in s["errors"] if f"re-sending {msg_id}" in e]
    assert "rc=1" in err and "could not be removed" in err and "no attempt spent" in err
    assert a.outbox_entry(msg_id)["attempts"] == 1
    s = wa.poll_once()  # the transport failure alone
    assert s["storage_failures"] == 0 and s["resent"] == 0 and s["complete"] is True
    assert any(f"re-send of {msg_id} failed" in e for e in s["errors"])
    assert a.outbox_entry(msg_id)["attempts"] == 1
    fake.fail_sends = False
    assert wa.poll_once()["resent"] == 1 and a.outbox_entry(msg_id)["attempts"] == 2


# ---- the self-gate's findings (one round; fixed inside P1 to P4) -----------------------------


def test_a_constraint_the_regex_engine_cannot_compile_is_a_verdict_never_an_escape(
    tmp_path, monkeypatch
):
    """Self-gate 1 (P1): a constraint pattern within the length cap that the engine
    cannot compile (nested past the recursion limit): on an ATTACHED grant a
    VerifyError at receipt (a refusal on peer input, never verify_failed:malformed);
    on a CACHED grant state.corrupt at the load — a storage failure, the mail
    unseen; the file put back, the retry applies. Round 20: the deep nesting never
    reaches an engine — the constraint language's parser refuses it by name at its
    depth bound (grant.constraint.pattern) — and the engine guard behind it is
    pinned with the engine's compile made to fail on a sound emission."""
    a, b, wa, wb, fake, clock, g = _cached_grant_over_mail(tmp_path, "grant")
    deep = "(" * 400 + "x" + ")" * 400
    assert len(deep) <= grantmod.MAX_PATTERN
    bad_scope = [
        {**g["scope"][0], "params": {"keys": ["content"], "values": {"content": {"regex": deep}}}}
    ]
    damaged = {**g, "scope": bad_scope}
    with pytest.raises(VerifyError) as e:
        grantmod.check_structure(damaged)
    assert e.value.reason == "grant.constraint.pattern"
    assert f"nested more than {grantmod.MAX_GROUP_DEPTH} deep" in e.value.detail

    def broken_compile(*_a, **_kw):
        raise grantmod.regex.error("the engine refused a sound emission")

    with monkeypatch.context() as m:
        m.setattr(grantmod.regex, "compile", broken_compile)
        with pytest.raises(VerifyError) as e:
            grantmod.check_structure(g)
    assert e.value.reason == "grant.scope[0].params.values.content.regex"
    assert "bad regex" in e.value.detail and "error" in e.value.detail
    # attached: refused as peer input, the mail seen. The language is a STRUCTURE
    # verdict, judged before the signature (a linear parse costs less than a
    # signature check), so the refusal names the pattern; the damaged copy's
    # signature no longer holds either
    fake.add(wb.self_email, wa.self_email, bundlemod.encode(_attaching(a, b, damaged, "f.txt")))
    s = wb.poll_once()
    assert s["storage_failures"] == 0 and s["complete"] is True and s["applied"] == 1
    assert "verify_failed:malformed" not in _outcomes(b)
    assert any(o == "verify_failed:grant.constraint.pattern" for o in _outcomes(b))
    # cached: corruption, the mail unseen, the retry applies once the file is back
    stored = b.state / "grants" / f"{g['grant_id']}.json"
    original = stored.read_bytes()
    stored.write_text(json.dumps(damaged), encoding="utf-8")
    with pytest.raises(IntegrityError) as e:
        b.load_grant(g["grant_id"])
    assert e.value.reason == "state.corrupt" and str(stored) in str(e.value)
    wa.send(_naming_only(a, b, g["grant_id"], "f.txt"))
    s = wb.poll_once()
    assert s["storage_failures"] == 1 and s["complete"] is False
    assert len(_unseen_mail_ids(fake, b, wb)) == 1 and "verify_failed:malformed" not in _outcomes(b)
    stored.write_bytes(original)
    assert wb.poll_once()["applied"] == 1 and (b.scratch_dir / "f.txt").read_text() == "y\n"


def test_issuance_never_stores_a_document_the_loader_would_refuse(pair, capsys):
    """Self-gate 2 (P1): `issue_grant` / `delegate_grant` (and the `grant` verb)
    refuse a document that is not sound — `--max-uses 0` is a ValueError at issue,
    exit 1 — so nothing lands under grants/ that a later load (every family
    accounting reads every grant) would refuse as corruption; a loose delegation
    still stores (its bounds are the receiver's refusal at use)."""
    a, b, clock, reports = pair
    before = sorted(p.name for p in (a.state / "grants").iterdir())
    with pytest.raises(ValueError) as e:
        a.issue_grant(
            subject_card=b.card,
            scope=fs_write_scope(b, "f.txt"),
            principal_statement=STATEMENT,
            max_uses=0,
        )
    assert "not a sound document" in str(e.value) and "grant.max_uses" in str(e.value)
    assert sorted(p.name for p in (a.state / "grants").iterdir()) == before
    assert (
        main(
            [
                *_argv(a),
                "grant",
                "--to",
                "b",
                "--file",
                "f.txt",
                "--action",
                "fs.write",
                "--statement",
                STATEMENT,
                "--max-uses",
                "0",
            ]
        )
        == 1
    )
    # round 19: the verb validates its values before any work (Usage, exit 1)
    assert "--max-uses must be at least 1" in capsys.readouterr().err
    assert sorted(p.name for p in (a.state / "grants").iterdir()) == before
    a.grants_on_file()  # every grant on file still loads
    parent = a.issue_grant(
        subject_card=a.card,
        scope=fs_write_scope(b, "f.txt", regex=None),
        principal_statement=STATEMENT,
        audience=b.host.public,
    )
    loose = a.delegate_grant(  # the same scope: not a strict subset, stored anyway
        parent=parent,
        subject_card=b.card,
        scope=fs_write_scope(b, "f.txt", regex=None),
        principal_statement=STATEMENT,
    )
    assert a.load_grant(loose["grant_id"]) == loose


def test_a_ledger_repair_whose_regeneration_tore_resumes_under_its_intent(tmp_path, capsys):
    """Self-gate 3 (P2): the repair verb cut the torn tail and its audit append was
    regenerating the missing lines when the write tore inside a multibyte character
    (power loss): the intent marker stands at step `truncated` and the mirror does
    not decode again. A fresh instance's `ledger repair` cuts the torn regenerated
    tail back under the same intent, lands the audit (once) and regenerates the
    lines; the ledger verifies and the mail applies."""
    from natively import ledger as ledgermod

    a, b, wa, wb, fake, clock = _with_history_over_mail(tmp_path)
    wa.send(a.compose_info(b.card, "hello"))
    mirror = b.ledger.prose_path
    _tear_mirror(mirror, "tail")
    real_append = ledgermod.Ledger._append_prose
    torn = {"done": False}

    def tearing_append(self, lines):
        if torn["done"]:
            return real_append(self, lines)
        torn["done"] = True
        line = lines[0].encode("utf-8")
        cut = line.index(EM_DASH) + 2  # the power cut inside the em dash
        with open(self.prose_path, "ab") as f:
            f.write(line[:cut])
        raise OSError(5, "Input/output error", str(self.prose_path))

    ledgermod.Ledger._append_prose = tearing_append
    try:
        assert main([*_argv(b), "ledger", "repair"]) == 1
    finally:
        ledgermod.Ledger._append_prose = real_append
    assert "Input/output error" in capsys.readouterr().err
    marker = b.state / "ledger-repair-pending.json"
    assert json.loads(marker.read_text())["step"] == "truncated"
    with pytest.raises(IntegrityError) as e:
        b.ledger.verify()
    assert e.value.reason == "ledger.mirror_corrupt"
    # a fresh instance resumes: the torn regenerated tail cut again, the audit once
    n2 = Node(state_dir=b.state, keys_dir=b.keys_dir, scratch_dir=b.scratch_dir, clock=clock)
    assert main([*_argv(n2), "ledger", "repair"]) == 0
    out = capsys.readouterr()
    assert "resuming an interrupted ledger repair" in out.err
    assert "regenerated mirror tail cut again" in out.err
    assert not marker.exists() and n2.ledger.verify()
    assert _actions(n2).count("ledger.mirror_truncated") == 1
    assert wb.poll_once()["applied"] == 1


def test_a_revocation_is_checked_before_anything_is_recorded_and_a_dry_run_records_nothing(
    tmp_path, monkeypatch, capsys
):
    """Self-gate 4 (P3): `revoke` composes and checks the bundle BEFORE the feed and
    the ledger are written: a refused one leaves both untouched (exit 2); a dry run
    records nothing anywhere (the body written for inspection only); the ordinary
    form records then sends."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    transport = _no_transport(monkeypatch)
    gid = uid("grt")
    argv = ["revoke", "--grant", gid, "--statement", "never mind"]
    feed_before, ledger_before = len(a.revocations.entries()), len(a.ledger)
    out = tmp_path / "rev.txt"
    _damaged_copy_from(monkeypatch, Node, "compose_revocation")
    assert main([*_argv(a), *argv, "--out", str(out)]) == 2
    assert "revocation.invalid" in capsys.readouterr().err
    assert len(a.revocations.entries()) == feed_before and len(a.ledger) == ledger_before
    assert not out.exists() and not a.revocations.grant_revoked_by(gid, a.principal.public)
    monkeypatch.undo()
    monkeypatch.setattr(mailmod, "default_runner", _no_runner)
    assert main([*_argv(a), *argv, "--dry-run", "--out", str(out)]) == 0
    assert "DRY RUN" in capsys.readouterr().out
    assert len(a.revocations.entries()) == feed_before and len(a.ledger) == ledger_before
    assert bundlemod.decode(out.read_text(encoding="utf-8"))["kind"] == "revocation"
    assert not a.revocations.grant_revoked_by(gid, a.principal.public)
    out.unlink()
    assert main([*_argv(a), *argv, "--out", str(out)]) == 0
    assert "recorded in the local feed" in capsys.readouterr().out
    assert len(a.revocations.entries()) == feed_before + 1 and len(a.ledger) == ledger_before + 1
    assert a.revocations.grant_revoked_by(gid, a.principal.public)
    assert transport == []


def test_the_local_wire_refuses_every_kind_that_is_not_the_senders(tmp_path):
    """Self-gate 5 (P3): LocalWire.deliver crosses the outgoing boundary for a
    message, a card and a revocation too — one that fails is <kind>.invalid before
    it is recorded, logged or delivered; the sound ones still deliver."""
    from .test_gate_round9 import _local_pair

    a, b, lw = _local_pair(tmp_path)
    log_before, outbox_before, ledger_before = len(lw.log), len(a.outbox()), len(b.ledger)
    receive_calls: list[dict] = []
    real_receive = b.receive
    b.receive = lambda bundle: (receive_calls.append(bundle), real_receive(bundle))[1]
    m = a.compose_info(b.card, "hi")
    rev = a.compose_revocation(a.revoke(grants=[uid("grt")], principal_statement="x"))
    for bad, reason in (
        ({**m, "object": {**m["object"], "sig": _flip(m["object"]["sig"])}}, "message.invalid"),
        (b.compose_card(), "card.invalid"),
        (
            {**rev, "object": {**rev["object"], "sig": _flip(rev["object"]["sig"])}},
            "revocation.invalid",
        ),
    ):
        with pytest.raises(IntegrityError) as e:
            lw.deliver(a, b, bad)
        assert e.value.reason == reason
    assert receive_calls == [] and len(lw.log) == log_before
    assert len(a.outbox()) == outbox_before and len(b.ledger) == ledger_before
    assert lw.deliver(a, b, m) != [] and lw.deliver(a, b, rev) == []
    assert len(receive_calls) == 2


def test_an_outbox_failure_after_a_successful_send_keeps_the_cleanup_failure_visible(
    tmp_path, monkeypatch
):
    """Self-gate 6 (P4): the send tool returned success, the staged body could not be
    removed AND recording the message in the outbox failed: ONE StorageError names
    all three facts (the gmail id, the outbox failure, the path that could not be
    removed) — the cleanup failure never vanishes behind the recording failure."""
    a, b, wa, wb, fake, clock = _connected_over_mail(tmp_path)
    inbox_before = len(fake.inbox.get(wb.self_email, []))
    monkeypatch.setattr(mailmod, "Path", _NoRemoval)
    monkeypatch.setattr(
        a, "outbox_record", lambda *args, **kw: (_ for _ in ()).throw(OSError(28, "No space left"))
    )
    with pytest.raises(StorageError) as e:
        wa.send(a.compose_info(b.card, "hello"))
    msg = str(e.value)
    assert "transmitted" in msg and "gmail" in msg and "outbox failed" in msg
    assert "No space left" in msg and "could not be removed" in msg and "Input/output error" in msg
    assert len(fake.inbox.get(wb.self_email, [])) == inbox_before + 1  # it did leave the box

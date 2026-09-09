"""Round 21: the round-20 verdicts ruled (the maintainer's gate: BA1 to BA5; the Fable
read: BB1 to BB4), the ratifications (D1 to D4 stand; D5 tightened), and the mail
adapter with its helper (Z1 to Z5), pinned.

BA1 a bracket class holds at most MAX_CLASS_ITEMS (256) items — refused by name at the
    offending item — and its items are SORTED and merged (overlapping and adjacent)
    in one pass after the sort, so the parse is linearithmic in the pattern and the
    emission is canonical whatever order the items were written in; the WORK is
    pinned by a comparison counter, the wall clock once, generously.
BA2 every feed and denial repair stage validates the permitted suffix before any
    write: at "truncated" and "audited" the store ends exactly at the cut point, and
    bytes past it are <store>.repair.refused with nothing written, on a retry and on
    a restart alike.
BA3 one option-applicability table per verb and mode (`cli.OPTIONS`, `cli.MODES`):
    an option GIVEN — empty included — that the selected mode never reads is refused
    by name before the node; `--state ""`, `--keys ""`, `--scratch ""` are refused,
    never the default; the sentinel table is derived from the table itself.
BB1 the fold is Unicode's canonical caseless match, NFD(casefold(NFD(x))): the three
    Greek code points whose uppercase spelling APFS treats as one name are one name.
BB2 after both directories exist, the state directory and the scratch root are
    compared by (device, inode) before anything is written under either.
BB3 a CLI value that is not valid UTF-8 (a surrogate-escaped argv byte) is refused by
    name before the node.
Z1  every helper row is validated as a whole (fields, types, the identifier rule)
    and a response with a bad row is refused whole; search pages are read strictly.
Z2  the mailbox the helper is signed into is asserted against the configured one
    before any search, cursor or freshness move; the account comes from config.
Z3  the window is scanned in slices, oldest first; a pass that ends on a budget
    after at least one slice completed records its position durably and the next
    poll continues from it; freshness moves only on a complete scan.
Z4  a peer mail cut past the wire bound is rejected once (the ledger's reject row,
    the seen note) and never re-fetched; an unobtainable body stays transient.
Z5  the helper's reads and the adapter's reads are bounded before the data is read;
    an oversized thread is halved to one and recorded; each pass has a byte budget.

Kinds: bounds (BA1, Z4, Z5), RESTART RECOVERY (BA2, Z3), the filesystem (BB1, BB2),
the CLI's validation (BA3, BB3), the wire (Z1, Z2, Z3)."""

from __future__ import annotations

import argparse
import importlib.util
import io
import json
import os
import random
import subprocess
import sys
import time
import unicodedata
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import regex

from natively import bundle as bundlemod
from natively import cli, durable, keys
from natively import grant as grantmod
from natively import state as statemod
from natively.adapters import mail as mailmod
from natively.adapters.mail import (
    CHUNK_OUTPUT_CAP,
    MAX_PAGES,
    MAX_ROWS,
    WIRE_CHARS,
    MailWire,
    OversizedOutput,
    parse_thread_json,
    row_problem,
)
from natively.canon import sha256_hex
from natively.cli import main
from natively.errors import IntegrityError
from natively.node import Node
from natively.objects import new_id
from natively.timeutil import fmt

from .test_gate_round7 import _argv
from .test_gate_round19 import PKG
from .test_gate_round20 import _GRANT, _GRT, _SEND, ACCEPTED, _sound_store
from .test_hardening import STATEMENT, fs_write_scope, pair
from .test_mail_adapter import pair_over_mail

__all__ = ["pair"]

_MSG = new_id("msg")
_HASH = "sha256:" + "0" * 64


def _no_node(monkeypatch):
    def no_node(_a):
        raise AssertionError("the node was constructed before the value was judged")

    monkeypatch.setattr(cli, "_node", no_node)


# ---- BA1. the class-item bound and the sorted merge --------------------------------------

SINGLETONS_256 = "[" + "".join(chr(0x100 + 2 * i) for i in range(256)) + "]"
SINGLETONS_257 = "[" + "".join(chr(0x100 + 2 * i) for i in range(257)) + "]"
RANGES_256 = "[" + "".join(chr(0x100 + 3 * i) + "-" + chr(0x101 + 3 * i) for i in range(256)) + "]"
RANGES_257 = "[" + "".join(chr(0x100 + 3 * i) + "-" + chr(0x101 + 3 * i) for i in range(257)) + "]"
GATE_1022 = "[" + "".join(chr(0x100 + 2 * i) for i in range(1022)) + "]"  # the gate's shape


def test_a_class_holds_at_most_256_items_refused_at_the_offending_item(pair):
    """BA1 (b): the 257th item refuses by name at ITS position; 256 singletons and 256
    ranges are legal; the gate's 1,022-singleton class refuses; a CJK range is one
    item and stays legal; the refusal reaches every boundary as
    grant.constraint.pattern."""
    a, b, clock, reports = pair
    assert grantmod.pattern_problem(SINGLETONS_256) is None
    assert grantmod.pattern_problem(RANGES_256) is None
    for pat, pos in ((SINGLETONS_257, 257), (RANGES_257, 1 + 3 * 256), (GATE_1022, 257)):
        why = grantmod.pattern_problem(pat)
        expect = (
            f"position {pos}: more than 256 items in a character class "
            f"(an item is a literal, an escape or a range)"
        )
        assert why == expect, why
    assert grantmod.emit_pattern("[一-鿿]") == "[一-鿿]"
    assert grantmod.MAX_CLASS_ITEMS == 256  # the bound the README's grammar table names
    with pytest.raises(ValueError) as e:
        a.issue_grant(
            subject_card=b.card,
            scope=fs_write_scope(b, "x.txt", regex=GATE_1022),
            principal_statement=STATEMENT,
        )
    assert "grant.constraint.pattern" in str(e.value) and "more than 256 items" in str(e.value)


SORTED = [
    ("[ba]", "[a-b]"),
    ("[cab]", "[a-c]"),
    ("[a-cd]", "[a-d]"),  # adjacent items merge
    ("[ac]", "[ac]"),
    ("[^ba]", "[^a-b]"),
    ("[z-za-a]", "[az]"),
    ("[b-da-a]", "[a-d]"),
    ("[Ā-￿\U00010000-\U0010ffff]", "[Ā-\U0010ffff]"),  # across the BMP edge
    ("[ -~\n]", "[\\\n\\ -\\~]"),  # the newline sorts first
    ("[9-90-8]", "[0-9]"),
]


@pytest.mark.parametrize("pattern, emission", SORTED, ids=[s[0] for s in SORTED])
def test_the_class_emission_is_sorted_and_merged(pattern, emission):
    """BA1 (a): the canonical emission is the sorted merged span list, deterministic
    whatever the written order, and means the same to the engine."""
    assert grantmod.emit_pattern(pattern) == emission
    inner = pattern[1:-1].lstrip("^")
    neg = "^" if pattern.startswith("[^") else ""
    items = regex.findall(r"(?:\\.|.)(?:-(?:\\.|.))?", inner, flags=regex.DOTALL)
    for _ in range(5):
        random.shuffle(items)
        assert grantmod.emit_pattern("[" + neg + "".join(items) + "]") == emission
    for ch in ("a", "b", "z", "\n", " ", "~", "0", "Ā", "\U0010ffff"):
        assert bool(regex.fullmatch(emission, ch, flags=regex.DOTALL)) == (
            grantmod._value_ok(ch, {"regex": pattern}) is None
        ), (pattern, ch)


@pytest.mark.parametrize("n", [16, 64, 256])
def test_the_merge_work_is_linearithmic(n):
    """BA1 (c): the WORK of the class parse pinned as a count of interval comparisons
    — under n * (log2 n + 1) for n items in any order, where the round-20 scan did
    n(n-1)/2 comparisons (32,640 for 256) — for singleton items and for ranges."""
    bound = n * ((n - 1).bit_length() + 1)  # 2,304 for 256 items
    for seed in range(4):
        rnd = random.Random(seed)
        for kind in ("singletons", "ranges"):
            idx = list(range(n))
            rnd.shuffle(idx)
            if kind == "singletons":
                pat = "[" + "".join(chr(0x100 + 2 * i) for i in idx) + "]"
            else:
                pat = (
                    "[" + "".join(chr(0x100 + 3 * i) + "-" + chr(0x101 + 3 * i) for i in idx) + "]"
                )
            grantmod.class_comparisons = 0
            grantmod.emit_pattern(pat)
            work = grantmod.class_comparisons
            assert 0 < work <= bound, (n, kind, seed, work, bound)
            assert work < n * (n - 1) // 2 or n < 8, (n, kind, work)
    # identical overlapping ranges: every sort comparison compares both ends (counted)
    grantmod.class_comparisons = 0
    grantmod.emit_pattern("[" + "\u0100-\uffff" * n + "]")
    assert 0 < grantmod.class_comparisons <= bound


def test_the_wall_clock_once_generously_cold():
    """BA1 (c): ONE wall-clock smoke test — the maximum-singleton class, the
    maximum-range class and every shape of the accepted table each compile cold
    (the engine's cache purged) and fullmatch 16 KB in under 250 ms."""
    big = "a" * 16384
    for pattern in (SINGLETONS_256, RANGES_256, *[p for p, *_ in ACCEPTED]):
        regex.purge()
        t0 = time.monotonic()
        grantmod._compile_pattern(pattern, "x")
        grantmod._value_ok(big, {"regex": pattern})
        assert time.monotonic() - t0 < 0.25, pattern[:40]


def test_the_readme_states_the_round_21_rules():
    """BA1 (d), D2, BA3, BB1, BB2, Z1 to Z5: the README carries the rules."""
    readme = (PKG / "README.md").read_text(encoding="utf-8")
    for needle in (
        "LINEARITHMIC",
        "256 items",
        "sorted",
        "bounded by the TIMEOUT",
        "NFD(casefold(NFD(",
        "device and inode",
        "poll without --file",
        "given and empty",
        "wire-scan.json",
        "profile --json",
        "wire.oversize",
        "--max-rows",
        "mailbox mismatch",
    ):
        assert needle in readme, needle
    assert "polynomial in the value, but its degree" not in readme


# ---- BA2. every repair stage validates the permitted suffix first --------------------------


def _marker_at(node, sname, step, to, torn):
    marker = node.state / f"{sname}-repair-pending.json"
    intent = {
        "step": step,
        "file": {"feed": "revocations.jsonl", "denial": "denials.jsonl"}[sname],
        "truncate_to": to,
        "bytes": len(torn),
        "tail_sha256": "sha256:" + sha256_hex(torn),
        "intent_id": new_id("rpr"),
        "ts": node.ts(),
    }
    if step == "audited":
        intent["audit_hash"] = _HASH
    durable.write_json(marker, intent)
    return marker


@pytest.mark.parametrize("step", ["truncated", "audited"])
@pytest.mark.parametrize("store", ["feed", "denials"])
def test_bytes_past_the_cut_point_at_a_later_step_refuse_with_nothing_written(pair, store, step):
    """BA2, the gate's reproduction: a valid retained prefix, a standing marker at
    "truncated" (and at "audited") and the replacement suffix `{"x":1}junk` —
    <store>.repair.refused at once: no ledger entry, the marker byte-identical, the
    store byte-identical; a restart (a fresh Node over the same state) repeats the
    refusal byte-identical with nothing changed."""
    node, obj, sname, verb, data = _sound_store(pair, store)
    torn = b'{"x":"'
    marker = _marker_at(node, sname, step, len(data), torn)
    obj.path.write_bytes(data + b'{"x":1}junk')
    before = (obj.path.read_bytes(), marker.read_bytes(), node.ledger.path.read_bytes())
    entries = len(node.ledger.entries())
    repair = {"feed": Node.repair_feed, "denial": Node.repair_denials}[sname]
    with pytest.raises(IntegrityError) as e:
        repair(node)
    assert e.value.reason == f"{sname}.repair.refused" and "past the intent" in str(e.value)
    first = str(e.value)
    assert (obj.path.read_bytes(), marker.read_bytes(), node.ledger.path.read_bytes()) == before
    assert len(node.ledger.entries()) == entries
    assert json.loads(marker.read_text())["step"] == step
    # RESTART: a new instance over the state the last one left
    fresh = Node(
        state_dir=node.state, keys_dir=node.keys_dir, scratch_dir=node.scratch_dir, clock=node.clock
    )
    with pytest.raises(IntegrityError) as e2:
        repair(fresh)
    assert str(e2.value) == first
    assert (obj.path.read_bytes(), marker.read_bytes(), node.ledger.path.read_bytes()) == before
    assert main([*_argv(node), *verb]) == 2
    assert (obj.path.read_bytes(), marker.read_bytes(), node.ledger.path.read_bytes()) == before


@pytest.mark.parametrize("store", ["feed", "denials"])
def test_a_differing_suffix_at_the_intent_step_refuses_before_the_markers_barrier(
    pair, store, monkeypatch
):
    """BA2 (self-gate minor 2): a standing "intent" marker over bytes that are not
    the recorded ones is intent_mismatch from the validator, before the marker's
    fsync and before any step; nothing written."""
    from natively import node as nodemod

    node, obj, sname, verb, data = _sound_store(pair, store)
    marker = _marker_at(node, sname, "intent", len(data), b'{"x":"')
    obj.path.write_bytes(data + b'{"y":"')
    synced: list[Path] = []
    monkeypatch.setattr(nodemod, "fsync_existing", lambda p: synced.append(Path(p)))
    before = (obj.path.read_bytes(), marker.read_bytes(), node.ledger.path.read_bytes())
    with pytest.raises(IntegrityError) as e:
        {"feed": Node.repair_feed, "denial": Node.repair_denials}[sname](node)
    assert e.value.reason == f"{sname}.repair.intent_mismatch"
    assert marker not in synced and synced == []
    assert (obj.path.read_bytes(), marker.read_bytes(), node.ledger.path.read_bytes()) == before


# ---- BA3. option applicability per verb and mode ---------------------------------------------

MODE_ARGV = {
    ("card", "card --show"): ["card", "--show"],
    ("card", "card (making the card)"): ["card"],
    ("grant", "grant (a root grant)"): _GRANT,
    ("grant", "grant --parent"): [*_GRANT, "--parent", _GRT],
    ("send", "--card"): ["send", "--card"],
    ("send", "--info"): ["send", "--to", "b", "--info", "hi"],
    ("send", "send --action"): _SEND,
    ("poll", "poll without --file (a live poll)"): ["poll"],
    ("poll", "poll --file"): ["poll", "--file", "/nonexistent/wire"],
    ("ledger", "ledger show"): ["ledger", "show"],
    ("ledger", "ledger verify"): ["ledger", "verify"],
    ("ledger", "ledger repair"): ["ledger", "repair"],
    ("pending", "pending list"): ["pending", "list"],
    ("pending", "pending repair"): ["pending", "repair"],
    ("pending", "pending discard"): ["pending", "discard", "x.corrupt-1-2"],
    ("revoke", "revoke (sending)"): ["revoke", "--grant", _GRT, "--statement", "s"],
    ("revoke", "revoke --no-send"): ["revoke", "--grant", _GRT, "--statement", "s", "--no-send"],
}
SAMPLE = {
    "--in-reply-to": [_MSG],
    "--parent": [_GRT],
    "--audience": ["k"],
    "--expires-in": ["1"],
    "--max-uses": ["1"],
    "--window": ["1,1"],
    "--tail": ["1"],
    "--interval": ["60"],
    "--principal-kind": ["stand-in"],
    "--param": ["k=v"],
    "--grant": [_GRT],
    "--card": [],  # send's flag; revoke's list takes a hash below
    "--set": ["poll_s=60"],
    "NAME": ["x.corrupt-1-2"],
    "MSG_ID": [_MSG],
}
# the options that SELECT a mode: adding one changes the mode rather than being unread
SELECTORS = {
    ("card", "--show"),
    ("grant", "--parent"),
    ("send", "--card"),
    ("send", "--info"),
    ("poll", "--file"),
    ("revoke", "--no-send"),
}


def _rows():
    rows = []
    for verb, modes in cli.MODES.items():
        for mode, reads in modes.items():
            if (verb, mode) not in MODE_ARGV:
                continue
            for option, kind in cli.OPTIONS[verb].items():
                if option in reads or (verb, option) in SELECTORS or option == "SUB":
                    continue
                if kind == cli._F:
                    extra = [option]
                elif option == "--card":
                    extra = ["--card", _HASH]
                elif option in ("NAME", "MSG_ID"):
                    extra = SAMPLE[option]
                else:
                    extra = [option, *SAMPLE.get(option, ["v"])]
                rows.append((verb, mode, option, [*MODE_ARGV[(verb, mode)], *extra]))
    return rows


ROWS = _rows()


def test_the_derived_table_covers_the_gate_shapes():
    """BA3: the rows derived from `cli.MODES` include every combination the gate
    named, and the table is not empty for any verb with more than one mode."""
    triples = {(v, m, o) for v, m, o, _ in ROWS}
    assert ("poll", "poll without --file (a live poll)", "--out") in triples
    assert ("pending", "pending list", "NAME") in triples
    assert ("pending", "pending repair", "--with-held") in triples
    assert ("card", "card --show", "--agent-name") in triples
    assert ("ledger", "ledger verify", "--tail") in triples
    assert ("revoke", "revoke --no-send", "--out") in triples
    assert ("grant", "grant --parent", "--audience") in triples
    assert len(ROWS) >= 20


@pytest.mark.parametrize("verb, mode, option, argv", ROWS, ids=[f"{r[1]}|{r[2]}" for r in ROWS])
def test_an_option_the_mode_never_reads_is_refused_before_the_node(
    pair, capsys, monkeypatch, verb, mode, option, argv
):
    """BA3, one sentinel row per (verb, mode, unread option) triple the table
    declares: exit 1 naming the mode and the option, `cli._node` never called."""
    a, b, clock, reports = pair
    _no_node(monkeypatch)
    assert main([*_argv(a), *argv]) == 1, argv
    err = capsys.readouterr().err
    assert f"{mode} takes no" in err and option in err and "Traceback" not in err, err


@pytest.mark.parametrize(
    "argv, needle",
    [
        (["poll", "--out", "reply.wire"], "poll without --file (a live poll) takes no --out"),
        (["pending", "list", ".."], "pending list takes no NAME"),
        (["pending", "repair", "--with-held"], "pending repair takes no --with-held"),
        (["card", "--show", "--agent-name", ""], "card --show takes no --agent-name"),
        (
            ["card", "--show", "--principal-kind", "stand-in"],
            "card --show takes no --principal-kind",
        ),
        (["ledger", "verify", "--tail", "3"], "ledger verify takes no --tail"),
        (["ledger", "repair", "--json"], "ledger repair takes no --json"),
        (
            ["revoke", "--grant", _GRT, "--statement", "s", "--no-send", "--out", "f"],
            "revoke --no-send takes no --out",
        ),
        ([*_GRANT, "--parent", _GRT, "--audience", "k"], "grant --parent takes no --audience"),
        ([*_GRANT, "--parent", _GRT, "--audience", ""], "grant --parent takes no --audience"),
    ],
    ids=lambda x: x if isinstance(x, str) else " ".join(x)[:40],
)
def test_the_gate_shapes_are_refused_by_name(pair, capsys, monkeypatch, argv, needle):
    """BA3, the gate's own combinations (finding 3), empty values included."""
    a, b, clock, reports = pair
    _no_node(monkeypatch)
    assert main([*_argv(a), *argv]) == 1
    err = capsys.readouterr().err
    assert needle in err and "Traceback" not in err, err


@pytest.mark.parametrize("flag", ["--state", "--keys", "--scratch"])
def test_an_empty_directory_option_is_refused_never_the_default(pair, capsys, monkeypatch, flag):
    """BA3 (cli.py:207 before): `--scratch "" card --show` selected the default
    scratch directory; an explicitly empty directory option is refused by name
    before any verb and before the node, for all three."""
    a, b, clock, reports = pair
    _no_node(monkeypatch)
    argv = [*_argv(a), "card", "--show"]
    i = argv.index(flag)
    argv[i + 1] = ""
    assert main(argv) == 1
    err = capsys.readouterr().err
    assert f"{flag} given and empty" in err and "Traceback" not in err, err
    # None is still absence: the default directories are selected without the flag
    del argv[i : i + 2]
    with pytest.raises(AssertionError, match="the node was constructed"):
        main(argv)


def test_the_table_declares_every_option_the_parser_knows():
    """BA3: the applicability table and the argparse definitions agree — every verb,
    every option string, every positional — so a new option cannot land unread."""
    ap = cli.build_parser()
    subparsers = next(a for a in ap._actions if isinstance(a, argparse._SubParsersAction))
    for verb, sp in subparsers.choices.items():
        assert verb in cli.OPTIONS, verb
        declared = set()
        for act in sp._actions:
            if act.dest == "help":
                continue
            if act.option_strings:
                declared.add(max(act.option_strings, key=len))
            else:
                declared.add(act.dest.upper())
        assert declared == set(cli.OPTIONS[verb]), (verb, declared ^ set(cli.OPTIONS[verb]))
        for mode, reads in cli.MODES[verb].items():
            assert reads <= set(cli.OPTIONS[verb]), (verb, mode)
    assert set(cli.OPTIONS) == set(subparsers.choices)


def test_card_defaults_apply_only_when_making_the_card(pair, capsys):
    """BA3: the card's names default at the verb (`CARD_DEFAULTS`), so `card` with no
    name still makes the default card, and an empty name given is refused."""
    a, b, clock, reports = pair
    assert main([*_argv(a), "card"]) == 0
    n = Node(state_dir=a.state, keys_dir=a.keys_dir, scratch_dir=a.scratch_dir, clock=a.clock)
    assert n.card["agent"]["name"] == cli.CARD_DEFAULTS["agent_name"]
    assert main([*_argv(a), "card", "--agent-name", ""]) == 1
    assert "--agent-name must not be empty" in capsys.readouterr().err
    assert main([*_argv(a), "card", "--principal-kind", "king"]) == 1
    assert "--principal-kind 'king' is not one of" in capsys.readouterr().err


# ---- BB3. a value that is not UTF-8 -----------------------------------------------------------

_BAD = chr(0xDCFF)  # what Python makes of an argv byte that is not UTF-8 (surrogateescape)
_LONE = chr(0xD800)


@pytest.mark.parametrize(
    "argv, what",
    [
        ([*_GRANT[:7], "--statement", "s" + _BAD], "--statement"),
        ([*_GRANT, "--param", "k=regex:" + _BAD], "--param"),
        ([*_GRANT, "--param", "k=regex:" + _LONE], "--param"),
        (["grant", "--to", "b" + _BAD, *_GRANT[3:]], "--to"),
        (["pin", "ed25519:" + "A" * 43 + "=", "--name", "n" + _BAD], "--name"),
        (["card", "--agent-name", "x" + _BAD], "--agent-name"),
        (["revoke", "--grant", _GRT, "--statement", "s" + _BAD], "--statement"),
        (
            ["deny", "--action", "a", "--resource", "host:x", "--statement", "s" + _BAD],
            "--statement",
        ),
        (["send", "--to", "b", "--info", "h" + _BAD], "--info"),
        ([*_SEND, "--param", "k=v" + _BAD], "--param"),
        (["pending", "repair", "x" + _BAD + ".corrupt-1-2"], "pending repair NAME"),
        (["config", "--set", "subject=x" + _BAD], "--set subject"),
        (["config", "--set", "peer_email=a" + _BAD + "@b.c"], "--set peer_email"),
    ],
    ids=[
        "grant-statement",
        "grant-param-regex",
        "grant-param-lone-surrogate",
        "grant-to",
        "pin-name",
        "card-agent-name",
        "revoke-statement",
        "deny-statement",
        "send-info",
        "send-param",
        "pending-name",
        "config-subject",
        "config-peer-email",
    ],
)
def test_a_value_that_is_not_utf8_is_refused_before_the_node(pair, capsys, monkeypatch, argv, what):
    """BB3 (N3): the value constructed the node and was refused by the canonicalizer
    at signing; now `_nonempty` and `_parse_param` encode it first."""
    a, b, clock, reports = pair
    _no_node(monkeypatch)
    assert main([*_argv(a), *argv]) == 1
    err = capsys.readouterr().err
    assert f"{what} is not valid UTF-8" in err and "Traceback" not in err, err
    cfg = a.state / "config.json"
    assert not cfg.exists() or _BAD not in cfg.read_text(encoding="utf-8", errors="replace")


@pytest.mark.parametrize("flag", ["--state", "--keys", "--scratch"])
def test_a_directory_option_that_is_not_utf8_is_refused(pair, capsys, monkeypatch, flag):
    """BB3 (self-gate 8): a surrogate-escaped directory option reached the node."""
    a, b, clock, reports = pair
    _no_node(monkeypatch)
    argv = [*_argv(a), "cards"]
    i = argv.index(flag)
    argv[i + 1] = argv[i + 1] + _BAD
    assert main(argv) == 1
    assert f"{flag} is not valid UTF-8" in capsys.readouterr().err


# ---- BB1. the fold ----------------------------------------------------------------------------

GREEK_PAIRS = [
    (chr(0x1FB7), chr(0x0391) + chr(0x0342) + chr(0x0345)),
    (chr(0x1FC7), chr(0x0397) + chr(0x0342) + chr(0x0345)),
    (chr(0x1FF7), chr(0x03A9) + chr(0x0342) + chr(0x0345)),
]


def _old_fold(x: str) -> str:
    return unicodedata.normalize("NFC", unicodedata.normalize("NFC", x).casefold())


@pytest.mark.parametrize("lower, upper", GREEK_PAIRS, ids=["1FB7", "1FC7", "1FF7"])
def test_the_fold_is_unicodes_canonical_caseless_match(tmp_path, lower, upper):
    """BB1 (N1): the three code points and their uppercase spellings are ONE name
    under NFD(casefold(NFD(x))) — and two under the round-20 formula — as siblings,
    one level down and one level up, through Node() and through keygen + card in a
    second process (rc 1, nothing created)."""
    assert keys._fold(lower) == keys._fold(upper)
    assert _old_fold(lower) != _old_fold(upper)  # why the formula changed
    assert keys._fold(chr(0x0390)) == keys._fold(chr(0x0399) + chr(0x0308) + chr(0x0301))
    kd = tmp_path / "keys"
    keys.generate_all(kd)
    home = tmp_path / "home"
    for state, scratch in (
        (home / lower, home / upper),
        (home / lower, home / upper / "sub"),
        (home / upper / "sub", home / lower),
    ):
        with pytest.raises(ValueError, match="count as one name"):
            Node(state_dir=state, keys_dir=kd, scratch_dir=scratch)
        assert not home.exists()
    env = {
        **os.environ,
        "NATIVELY_STATE": str(home / lower),
        "NATIVELY_KEYS": str(tmp_path / "keys2"),
        "NATIVELY_SCRATCH": str(home / upper),
        "PYTHONPATH": str(PKG),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    for state, scratch in (
        (home / lower, home / upper),
        (home / lower, home / upper / "sub"),
        (home / upper / "sub", home / lower),
    ):
        env["NATIVELY_STATE"], env["NATIVELY_SCRATCH"] = str(state), str(scratch)
        for verb in (["keygen"], ["card"]):
            r = subprocess.run(
                [sys.executable, "-B", "-m", "natively", *verb],
                env=env,
                capture_output=True,
                text=True,
                timeout=120,
            )
            assert r.returncode == 1 and "count as one name" in r.stderr, (verb, r.stderr)
            assert not (tmp_path / "keys2").exists() and not home.exists()


def test_the_fold_sweep_of_the_read_has_no_false_refusals():
    """BB1: over the Latin, Greek and Cyrillic blocks, no two names the filesystem
    could not alias fold together — every code point folds to itself alone unless it
    has a case or normalization variant (the read measured 0 false refusals over
    21,005 pairs)."""
    folded: dict[str, list[str]] = {}
    for cp in list(range(0x41, 0x250)) + list(range(0x370, 0x530)):
        ch = chr(cp)
        folded.setdefault(keys._fold(ch), []).append(ch)
    for group in folded.values():
        if len(group) == 1:
            continue
        # every member of a group is a case or normalization variant of the first
        first = group[0]
        for other in group[1:]:
            assert other.casefold() == first.casefold() or unicodedata.normalize(
                "NFD", other
            ) == unicodedata.normalize("NFD", first), (first, other)


# ---- BB2. the identity re-check after creation -----------------------------------------------


def _fs_folds(root: Path, a: str, b: str) -> bool:
    (root / a).mkdir(parents=True)
    return (root / b).exists()


def test_the_identity_recheck_refuses_a_pair_the_fold_cannot_see(tmp_path, monkeypatch):
    """BB2 (N2): with the fold blind (an identity function stands in for the tables
    the interpreter lacks), a case pair on this case-insensitive filesystem passes
    the pre-check, the node creates ONE directory under two names — and the
    (device, inode) re-check refuses before anything is written under it: the
    directory exists and is EMPTY, no lock file, no subdirectory, no state file."""
    if not _fs_folds(tmp_path / "probe", "Probe", "probe"):
        pytest.skip("case-sensitive filesystem: no alias to reach the re-check with")
    monkeypatch.setattr(keys, "_fold", lambda x: x)
    kd = tmp_path / "keys"
    keys.generate_all(kd)
    home = tmp_path / "home"
    with pytest.raises(ValueError, match="filesystem identity"):
        Node(state_dir=home / "state", keys_dir=kd, scratch_dir=home / "STATE")
    assert sorted(p.name for p in home.iterdir()) == ["state"]
    assert list((home / "state").iterdir()) == []
    # nested: the scratch root one level under the state's alias
    home2 = tmp_path / "home2"
    with pytest.raises(ValueError, match="filesystem identity"):
        Node(state_dir=home2 / "state", keys_dir=kd, scratch_dir=home2 / "STATE" / "s")
    assert sorted(p.name for p in home2.iterdir()) == ["state"]
    assert sorted(p.name for p in (home2 / "state").iterdir()) == ["s"]
    assert list((home2 / "state" / "s").iterdir()) == []


def test_the_unicode_16_pair_is_refused_on_a_filesystem_that_folds_it(tmp_path):
    """BB2 (N2), the real pair: U+1C89 / U+1C8A (Cyrillic Tje, Unicode 16) are one
    directory to this kernel and two names to Python 3.11's tables."""
    upper, lower = chr(0x1C89), chr(0x1C8A)
    assert keys._fold(upper) != keys._fold(lower)  # the tables cannot see the pair
    if not _fs_folds(tmp_path / "probe", upper, lower):
        pytest.skip("this filesystem keeps the Unicode 16 pair apart")
    kd = tmp_path / "keys"
    keys.generate_all(kd)
    home = tmp_path / "home"
    with pytest.raises(ValueError, match="filesystem identity"):
        Node(state_dir=home / upper, keys_dir=kd, scratch_dir=home / lower)
    assert list((home / upper).iterdir()) == []


def test_check_scratch_identity_directly(tmp_path):
    """BB2: the check itself — two distinct directories pass; the same directory
    under one name, and nesting either way, refuse; a missing directory is refused
    as not yet checkable."""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    keys.check_scratch_identity(tmp_path / "b", state_dir=tmp_path / "a")
    with pytest.raises(ValueError, match="filesystem identity"):
        keys.check_scratch_identity(tmp_path / "a", state_dir=tmp_path / "a")
    (tmp_path / "a" / "in").mkdir()
    with pytest.raises(ValueError, match="filesystem identity"):
        keys.check_scratch_identity(tmp_path / "a" / "in", state_dir=tmp_path / "a")
    with pytest.raises(ValueError, match="filesystem identity"):
        keys.check_scratch_identity(tmp_path / "a", state_dir=tmp_path / "a" / "in")
    with pytest.raises(ValueError, match="does not exist yet"):
        keys.check_scratch_identity(tmp_path / "missing", state_dir=tmp_path / "a")


def test_nothing_is_written_before_the_recheck(pair, monkeypatch):
    """BB2: the constructor's order — the re-check runs before the lock file, the
    subdirectories and the startup sweep: with the check made to raise, a fresh
    state directory holds nothing."""
    a, b, clock, reports = pair
    monkeypatch.setattr(
        keys, "check_scratch_identity", lambda *x, **k: (_ for _ in ()).throw(ValueError("stop"))
    )
    state = a.state.parent / "fresh-state"
    with pytest.raises(ValueError, match="stop"):
        Node(state_dir=state, keys_dir=a.keys_dir, scratch_dir=a.state.parent / "fresh-scratch")
    assert list(state.iterdir()) == []


# ---- Z1. helper rows validated structurally -----------------------------------------------

GOOD_ROW = {
    "id": "m1",
    "threadId": "t1",
    "labelIds": ["INBOX"],
    "date": "d",
    "from": "instinct <taylor@teale.com>",
    "to": "taylor@houmanoids.com",
    "subject": "Natively v0 wire",
    "snippet": "",
    "body": "X-Natively: v0\nAAAA",
    "truncated": False,
    "body_chars": 19,
}
BAD_ROWS = [
    (
        "missing-id",
        {k: v for k, v in GOOD_ROW.items() if k != "id"},
        "id None is not a transport id",
    ),
    ("id-dash", {**GOOD_ROW, "id": "-x"}, "id '-x' is not a transport id"),
    ("id-space", {**GOOD_ROW, "threadId": "t 1"}, "threadId 't 1' is not a transport id"),
    ("id-long", {**GOOD_ROW, "id": "a" * 65}, "is not a transport id"),
    ("labels-not-list", {**GOOD_ROW, "labelIds": "INBOX"}, "labelIds is not a list of strings"),
    ("date-number", {**GOOD_ROW, "date": 5}, "date is neither a string nor null"),
    ("missing-body", {k: v for k, v in GOOD_ROW.items() if k != "body"}, "body is not a string"),
    ("truncated-text", {**GOOD_ROW, "truncated": "yes"}, "truncated is not a boolean"),
    ("unknown-field", {**GOOD_ROW, "extra": 1}, "a field the adapter does not read: 'extra'"),
    (
        "cut-without-length",
        {k: v for k, v in {**GOOD_ROW, "truncated": True}.items() if k != "body_chars"},
        "a cut body without body_chars",
    ),
    ("chars-negative", {**GOOD_ROW, "body_chars": -1}, "body_chars is not a non-negative integer"),
    ("not-object", ["m1"], "row 1 is not an object"),
]


@pytest.mark.parametrize("name, row, needle", BAD_ROWS, ids=[r[0] for r in BAD_ROWS])
def test_a_bad_row_refuses_the_whole_response(name, row, needle):
    """Z1: the row is named, the response is refused whole — the good row before it
    is not consumed either."""
    assert row_problem(GOOD_ROW, 0) is None
    assert row_problem({**GOOD_ROW, "date": None, "to": None}, 0) is None  # headers may be null
    with pytest.raises(RuntimeError) as e:
        parse_thread_json(json.dumps([GOOD_ROW, row]))
    assert needle in str(e.value) and "refused whole" in str(e.value), str(e.value)


def test_a_bad_row_in_a_poll_advances_nothing(tmp_path):
    """Z1 through the poll: one bad row among good ones — the chunk fails by name,
    nothing is applied, nothing marked seen, no cursor, no freshness."""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    reports: list[str] = []
    a.report = reports.append
    fake.add("taylor@houmanoids.com", "taylor@teale.com", bundlemod.encode(b.compose_card()))
    real = fake.runner_for("taylor@houmanoids.com")

    def run(argv):
        r = real(argv)
        if argv[4] == "thread":
            rows = json.loads(r.stdout)
            rows.append({**rows[0], "id": "-evil"})
            return subprocess.CompletedProcess(argv, 0, json.dumps(rows) + "\n", "")
        return r

    w = MailWire(a, runner=run)
    s = w.poll_once()
    assert s["applied"] == 0 and s["fetch_failures"] == 1 and s["complete"] is False
    assert any("is not a transport id" in e and "refused whole" in e for e in s["errors"])
    assert not (a.state / "seen-mail.json").exists() and w.cursor() is None
    assert a.revocations.last_checked() is None
    assert a.card_for_key(b.agent.public) is None


@pytest.mark.parametrize(
    "page",
    [
        "thread t1 msgs=2 | x\n",
        "garbage\n",
        "thread\n",
        "thread -x\n",
        "next-page-token a b\n",
        "\n\n",
        "thread t1\n\nnext-page-token p1\n",
    ],
    ids=["extra-tokens", "garbage", "no-id", "bad-id", "bad-token", "blank-page", "blank-line"],
)
def test_a_search_line_outside_the_contract_refuses_the_page(tmp_path, page):
    """Z1, the search side: every line is `thread <id>` or `next-page-token <token>`;
    anything else refuses the page as a wire failure (before, unknown lines were
    skipped silently and `thread` lines were split on any whitespace)."""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    real = fake.runner_for("taylor@houmanoids.com")

    def run(argv):
        if argv[4] == "search":
            return subprocess.CompletedProcess(argv, 0, page, "")
        return real(argv)

    w = MailWire(a, runner=run)
    s = w.poll_once()
    assert s["fetch_failures"] == 1 and s["applied"] == 0 and w.cursor() is None
    assert any("does not read" in e or "did not return" in e for e in s["errors"]), s["errors"]


# ---- Z2. the mailbox identity ----------------------------------------------------------------


def test_a_helper_signed_into_another_mailbox_is_refused_before_any_search(tmp_path):
    """Z2: the profile is read first; a mismatch fails the fetch by name — no search,
    nothing applied, nothing seen, the cursor and the freshness clock unmoved; with
    the right mailbox the same poll applies."""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    reports: list[str] = []
    a.report = reports.append
    fake.add("taylor@houmanoids.com", "taylor@teale.com", bundlemod.encode(b.compose_card()))
    fake.profile = "someone.else@example.com"
    s = wa.poll_once()
    assert s["fetch_failures"] == 1 and s["applied"] == 0 and s["complete"] is False
    assert any("mailbox mismatch" in e and "someone.else@example.com" in e for e in s["errors"])
    assert fake.searches == [] and fake.thread_calls == []
    assert not (a.state / "seen-mail.json").exists() and wa.cursor() is None
    assert a.revocations.last_checked() is None
    assert fake.profiles == ["taylor"]
    fake.profile = None
    s = wa.poll_once()
    assert s["applied"] == 1 and s["complete"] is True
    assert a.card_for_key(b.agent.public) is not None
    with pytest.raises(mailmod.MailboxMismatch):
        fake.profile = "TAYLOR@HOUMANOIDS.COM.evil"
        wa.assert_mailbox()
    fake.profile = "TAYLOR@houmanoids.com"  # compared lower-cased
    assert wa.assert_mailbox() == "taylor@houmanoids.com"


def test_the_account_comes_from_config_and_is_typed(tmp_path, capsys):
    """Z2: `mail_account` selects the helper's --account (never assumed); the typed
    loader admits only the helper's accounts; `config --set` refuses the rest."""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    assert statemod.config({"mail_account": "afik"}) is None
    assert "mail_account" in statemod.config({"mail_account": "bob"})
    a.config["mail_account"] = "afik"
    a.save_config()
    w = MailWire(a, runner=fake.runner_for("taylor@houmanoids.com"))
    w.poll_once()
    assert fake.profiles[-1] == "afik"
    assert all(argv[3] == "afik" for argv in fake.searches)
    assert main([*_argv(a), "config", "--set", "mail_account=bob"]) == 1
    assert "mail_account" in capsys.readouterr().err
    assert main([*_argv(a), "config", "--set", "mail_account=taylor"]) == 0


def test_a_mail_not_addressed_to_the_mailbox_is_ignored(tmp_path):
    """Z2: RawMail.to must name the configured address."""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    card = bundlemod.encode(b.compose_card())
    gid = fake.add("taylor@houmanoids.com", "taylor@teale.com", card)
    fake.inbox["taylor@houmanoids.com"][-1]["to"] = "someone@else.example"
    s = wa.poll_once()
    assert s["ignored"] == 1 and s["applied"] == 0 and s["complete"] is True
    seen = json.loads((a.state / "seen-mail.json").read_text())
    assert seen[gid] == "ignored:recipient"
    fake.add("taylor@houmanoids.com", "taylor@teale.com", card)
    fake.inbox["taylor@houmanoids.com"][-1]["to"] = (
        "Other <x@y.example>, Taylor <TAYLOR@houmanoids.com>"
    )
    assert wa.poll_once()["applied"] == 1


# ---- Z3. bounded scan progress with a completeness boundary ------------------------------


def _backlog(fake, wa, a, n, *, days=2):
    """`n` synthetic threads spread evenly over the last `days` days, oldest first."""
    now = int(a.now().timestamp())
    start = now - days * 86400
    for i in range(n):
        fake.thread_times[f"b{i:05d}"] = start + (i * days * 86400) // n
    return start, now


def test_a_backlog_larger_than_a_slice_is_scanned_through_across_polls(tmp_path):
    """Z3: 4,500 threads in a two-day window (over PAGE_CAP in the first slice): the
    first pass reads the slice's newest PAGE_CAP threads, halves, completes the
    slices its page budget allows, and RECORDS its position; freshness and the
    cursor stay; the next pass starts at the record (not the window) and reaches the
    open end — complete, the cursor moves, the record goes, both peer mails applied,
    every synthetic thread listed."""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    reports: list[str] = []
    a.report = reports.append
    start, now = _backlog(fake, wa, a, 4500)
    card = bundlemod.encode(b.compose_card())
    early = fake.add("taylor@houmanoids.com", "taylor@teale.com", card, thread="early")
    late = fake.add("taylor@houmanoids.com", "taylor@teale.com", card, thread="late")
    fake.thread_times["early"] = start + 100
    fake.thread_times["late"] = now - 100
    s = wa.poll_once()
    assert s["complete"] is False
    rec = wa.scan_record()
    assert rec is not None and start < rec[0] < now, rec
    assert s["scan_recorded"] == rec[0]
    assert wa.cursor() is None and a.revocations.last_checked() is None
    assert len(fake.searches) <= MAX_PAGES
    assert any("scan progress recorded" in r for r in reports)
    seen = json.loads((a.state / "seen-mail.json").read_text())
    assert early in seen  # the oldest slice completed: its mail applied and seen
    queries_first = list(fake.queries)
    s = wa.poll_once()
    assert fake.queries[len(queries_first)].startswith(f"subject:(Natively v0 wire) after:{rec[0]}")
    assert s["complete"] is True, s["errors"]
    assert wa.scan_record() is None and wa.cursor() == clock()
    assert a.revocations.last_checked() == clock()
    seen = json.loads((a.state / "seen-mail.json").read_text())
    assert early in seen and late in seen
    listed = {t for call in fake.thread_calls for t in call}
    assert listed >= set(fake.thread_times)


def test_a_dense_backlog_is_narrowed_across_polls_with_the_production_limits(tmp_path):
    """Z3 (self-gate 1): 4,500 threads inside the oldest two hours of the window:
    a pass that completes no slice still records the NARROWED span with the position
    unchanged, so every poll halves a little further instead of from scratch, and
    the scan completes within a few polls under the real PAGE_CAP, MAX_PAGES and
    MIN_SLICE_S."""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    now = int(a.now().timestamp())
    start = now - 2 * 86400
    for i in range(4500):
        fake.thread_times[f"d{i:05d}"] = start + (i * 7200) // 4500
    card = bundlemod.encode(b.compose_card())
    gid = fake.add("taylor@houmanoids.com", "taylor@teale.com", card, thread="dense")
    fake.thread_times["dense"] = start + 7100
    polls = 0
    spans: list[int] = []
    while polls < 6:
        polls += 1
        s = wa.poll_once()
        if s["complete"]:
            break
        rec = wa.scan_record()
        assert rec is not None, s["errors"]
        assert rec[0] >= start and rec[1] < 2 * 86400
        assert not spans or rec[1] <= spans[-1]  # never wider than the pass before
        spans.append(rec[1])
        assert a.revocations.last_checked() is None
    assert s["complete"] is True and polls <= 4, (polls, spans)
    assert wa.scan_record() is None and a.revocations.last_checked() == clock()
    assert gid in json.loads((a.state / "seen-mail.json").read_text())


def test_a_flood_is_reached_and_named_under_the_real_limits(tmp_path):
    """Z3 (self-gate 1): 2,500 threads inside thirty seconds — the halving, carried
    across polls by the record, reaches MIN_SLICE_S and names the flood; the
    record then stands at the flood's start, never past it, freshness stays."""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    reports: list[str] = []
    a.report = reports.append
    now = int(a.now().timestamp())
    start = now - 2 * 86400
    for i in range(2500):
        fake.thread_times[f"f{i:05d}"] = start + (i % 30)
    for _ in range(8):
        wa.poll_once()
        if any("slice overflow" in r for r in reports):
            break
    assert any("slice overflow" in r for r in reports), reports[-3:]
    rec = wa.scan_record()
    assert rec is not None and rec[0] == start and rec[1] <= mailmod.MIN_SLICE_S * 2
    assert a.revocations.last_checked() is None and wa.cursor() is None


def test_a_restart_continues_from_the_record(tmp_path):
    """Z3, RESTART RECOVERY: a fresh node and adapter over the state the last pass
    left start at the recorded position with the recorded slice."""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    _backlog(fake, wa, a, 4500)
    s = wa.poll_once()
    rec = wa.scan_record()
    assert rec is not None and s["complete"] is False
    a2 = Node(state_dir=a.state, keys_dir=a.keys_dir, scratch_dir=a.scratch_dir, clock=clock)
    w2 = MailWire(a2, runner=fake.runner_for("taylor@houmanoids.com"))
    assert w2.scan_start() == rec and w2.search_after() == rec[0]
    n = len(fake.queries)
    s = w2.poll_once()
    assert f"after:{rec[0]} before:{rec[0] + rec[1]}" in fake.queries[n]  # the recorded slice
    assert s["complete"] is True and w2.scan_record() is None


def test_progress_is_not_recorded_over_a_storage_failure(tmp_path, monkeypatch):
    """Z3: a pass that made progress but left a mail unseen (a seen-file write that
    failed) records nothing — the next poll starts the window over."""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    start, now = _backlog(fake, wa, a, 4500)
    gid = fake.add(
        "taylor@houmanoids.com",
        "taylor@teale.com",
        bundlemod.encode(b.compose_card()),
        thread="early",
    )
    fake.thread_times["early"] = start + 100
    real = wa._mark_seen

    def failing(gmail_id, note):
        if gmail_id == gid:
            raise OSError(5, "EIO")
        real(gmail_id, note)

    monkeypatch.setattr(wa, "_mark_seen", failing)
    s = wa.poll_once()
    assert s["complete"] is False and s["storage_failures"] >= 1
    assert wa.scan_record() is None and s["scan_recorded"] is None
    assert not (a.state / "wire-scan.json").exists()


def test_a_flood_no_slice_can_walk_is_named_and_the_clock_stays(tmp_path, monkeypatch):
    """Z3: 2,500 threads inside thirty seconds at the window's start: every slice
    containing them overflows down to the smallest slice, reported by name; nothing
    is recorded (no slice completed), the clock and the cursor stay, and the
    mail the overflowing slices listed is still applied."""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    reports: list[str] = []
    a.report = reports.append
    monkeypatch.setattr(mailmod, "MIN_SLICE_S", 86400)  # the flood reached in ONE pass here;
    # the real limits are exercised in test_a_flood_is_reached_and_named_under_the_real_limits
    now = int(a.now().timestamp())
    start = now - 2 * 86400
    for i in range(2500):
        fake.thread_times[f"f{i:05d}"] = start + (i % 30)
    gid = fake.add(
        "taylor@houmanoids.com",
        "taylor@teale.com",
        bundlemod.encode(b.compose_card()),
        thread="flood",
    )
    fake.thread_times["flood"] = start + 29  # the newest of the flood: listed first
    s = wa.poll_once()
    assert s["complete"] is False and s["applied"] == 1
    assert any("slice overflow" in r for r in reports), reports
    rec = wa.scan_record()  # the narrowing recorded, the position unchanged
    assert rec is not None and rec[0] == start and rec[1] == 86400
    assert wa.cursor() is None and a.revocations.last_checked() is None
    assert json.loads((a.state / "seen-mail.json").read_text())[gid].startswith("card:")


def test_the_page_budget_ends_a_pass_by_name(tmp_path):
    """Z3: a search that adds one id per page forever spends the pass's MAX_PAGES
    calls and ends by name; nothing is recorded (no slice completed)."""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    real = fake.runner_for("taylor@houmanoids.com")
    state = {"i": 0}

    def run(argv):
        if argv[4] == "search":
            state["i"] += 1
            fake.searches.append(argv)
            return subprocess.CompletedProcess(
                argv, 0, f"thread x{state['i']}\nnext-page-token p{state['i']}\n", ""
            )
        return real(argv)

    w = MailWire(a, runner=run)
    got = w.fetch()
    assert got.complete is False and got.pages == MAX_PAGES and got.budget is True
    assert got.incomplete_why == f"page cap ({MAX_PAGES} search pages)"
    assert got.progress is False and got.scanned_through == w.search_after()  # unchanged


# ---- Z4. a terminal rejection for an oversized wire ----------------------------------------


def test_an_oversized_peer_mail_is_rejected_once_and_never_re_fetched(tmp_path):
    """Z4: a peer row the helper cut past the wire bound is ledgered ONCE
    (wire.oversize, verify_failed:wire.size), marked seen with its length, the fetch
    complete (the cursor and the clock move); a later poll never asks for it again,
    and the helper no longer cutting it changes nothing."""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    reports: list[str] = []
    a.report = reports.append
    gid = fake.add("taylor@houmanoids.com", "taylor@teale.com", bundlemod.encode(b.compose_card()))
    fake.truncate.add(gid)
    s = wa.poll_once()
    assert s["applied"] == 0 and s["rejected"] == 1 and s["complete"] is True, s
    assert any("rejected" in e and str(WIRE_CHARS + 1) in e for e in s["errors"])
    seen = json.loads((a.state / "seen-mail.json").read_text())
    assert seen[gid] == f"oversized:{WIRE_CHARS + 1}"
    rows = [e for e in a.ledger.entries() if e["action"] == "wire.oversize"]
    assert len(rows) == 1 and rows[0]["outcome"] == "verify_failed:wire.size"
    assert str(bundlemod.MAX_WIRE_B64_CHARS) in rows[0]["detail"] and gid in rows[0]["detail"]
    assert wa.cursor() == clock() and a.revocations.last_checked() == clock()
    fake.truncate.clear()
    s = wa.poll_once()
    assert s["applied"] == 0 and s["rejected"] == 0 and s["complete"] is True
    assert len([e for e in a.ledger.entries() if e["action"] == "wire.oversize"]) == 1
    assert a.card_for_key(b.agent.public) is None


def test_the_cut_verdict_follows_the_decoder(tmp_path):
    """Z4 (self-gate 4): a cut body is judged by the decoder's own rules — a whole
    bundle before the cut (a long quoted trailer after it) APPLIES; base64 past the
    wire's base64 bound before the cut is oversized (terminal); base64 unfinished at
    the cut and still under the bound is undecidable (transient, not seen)."""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    card = bundlemod.encode(b.compose_card())
    assert MailWire.cut_verdict(card + "\n> " + "q" * 10) == "bundle"
    assert MailWire.cut_verdict("hello, not a wire body") == "bundle"
    long_b64 = bundlemod.HEADER + "\n" + "A" * (bundlemod.MAX_WIRE_B64_CHARS + 1)
    assert MailWire.cut_verdict(long_b64) == "oversized"
    assert MailWire.cut_verdict(bundlemod.HEADER + "\n" + "A\n" * 1000) == "undecidable"
    # applied though cut: a whole bundle then a quoted trailer past WIRE_CHARS
    gid = fake.add("taylor@houmanoids.com", "taylor@teale.com", card + "\n> " + "q" * WIRE_CHARS)
    row = fake.inbox["taylor@houmanoids.com"][-1]
    row["body"] = row["body"][:WIRE_CHARS]
    row.update({"truncated": True, "body_chars": WIRE_CHARS + len(card)})
    s = wa.poll_once()
    assert s["applied"] == 1 and s["rejected"] == 0 and s["complete"] is True, s["errors"]
    assert a.card_for_key(b.agent.public) is not None
    # undecidable: base64 rewrapped one character per line, cut, under the bound
    rewrapped = bundlemod.HEADER + "\n" + "A\n" * (WIRE_CHARS // 2)
    gid2 = fake.add("taylor@houmanoids.com", "taylor@teale.com", rewrapped)
    row = fake.inbox["taylor@houmanoids.com"][-1]
    row["body"] = row["body"][:WIRE_CHARS]
    row.update({"truncated": True, "body_chars": WIRE_CHARS + 10})
    s = wa.poll_once()
    assert s["applied"] == 0 and s["rejected"] == 0 and s["complete"] is False
    assert any("undecidable" in e for e in s["errors"])
    seen = json.loads((a.state / "seen-mail.json").read_text())
    assert gid in seen and gid2 not in seen


def test_a_terminally_rejected_mail_is_never_judged_again(tmp_path):
    """Z4 (self-gate 3): after the rejection the same message reported unavailable
    by the helper does not make the fetch incomplete — a terminal seen mark
    excludes the message from body handling and completeness."""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    gid = fake.add("taylor@houmanoids.com", "taylor@teale.com", bundlemod.encode(b.compose_card()))
    row = fake.inbox["taylor@houmanoids.com"][-1]
    row["body"] = bundlemod.HEADER + "\n" + "A" * WIRE_CHARS
    fake.truncate.add(gid)
    s = wa.poll_once()
    assert s["rejected"] == 1 and s["complete"] is True
    fake.truncate.clear()
    row.update({"truncated": True, "body_unavailable": "attachment x: fetch failed"})
    s = wa.poll_once()
    assert s["complete"] is True and s["rejected"] == 0 and not s["errors"], s["errors"]
    assert a.revocations.last_checked() == clock()


def test_a_rejection_audit_is_appended_once_across_a_failed_seen_write(tmp_path, monkeypatch):
    """Z4/Z5 (self-gate 6): the audit lands, the seen write fails; the retry finds
    the audit by its token, re-establishes the barrier and appends nothing."""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    card = bundlemod.encode(b.compose_card())
    gid = fake.add("taylor@houmanoids.com", "taylor@teale.com", card, thread="t1")
    fake.inbox["taylor@houmanoids.com"][-1]["body"] = bundlemod.HEADER + "\n" + "A" * WIRE_CHARS
    fake.truncate.add(gid)
    fake.add("taylor@houmanoids.com", "taylor@teale.com", card, thread="t9")
    now = int(a.now().timestamp())
    fake.thread_times.update({"t1": now - 10, "t9": now - 5})
    fake.oversized_threads.add("t9")
    real = wa._mark_seen
    fails = {"n": 0}

    def failing(gmail_id, note):
        if fails["n"] < 2 and (gmail_id == gid or gmail_id.startswith("thread:")):
            fails["n"] += 1
            raise OSError(5, "EIO")
        real(gmail_id, note)

    monkeypatch.setattr(wa, "_mark_seen", failing)
    s = wa.poll_once()
    assert s["storage_failures"] == 2 and s["complete"] is False
    s = wa.poll_once()
    assert s["storage_failures"] == 0 and s["complete"] is True
    rows = [e["action"] for e in a.ledger.entries() if e["action"].startswith("wire.")]
    assert rows.count("wire.oversize") == 1 and rows.count("wire.thread_oversize") == 1
    seen = json.loads((a.state / "seen-mail.json").read_text())
    assert seen[gid].startswith("oversized:") and seen["thread:t9"] == "oversized-thread"


def test_an_unobtainable_body_stays_transient(tmp_path):
    """Z4: body_unavailable is not a rejection — not seen, the fetch incomplete, read
    again next poll; obtained later, it applies."""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    gid = fake.add("taylor@houmanoids.com", "taylor@teale.com", bundlemod.encode(b.compose_card()))
    row = fake.inbox["taylor@houmanoids.com"][-1]
    row.update({"truncated": True, "body_unavailable": "attachment att-1: fetch failed"})
    s = wa.poll_once()
    assert s["applied"] == 0 and s["rejected"] == 0 and s["complete"] is False
    assert not (a.state / "seen-mail.json").exists() and wa.cursor() is None
    row.pop("truncated")
    row.pop("body_unavailable")
    s = wa.poll_once()
    assert (
        s["applied"] == 1
        and s["complete"] is True
        and gid in json.loads((a.state / "seen-mail.json").read_text())
    )


# ---- Z5. bounded reads and per-pass budgets --------------------------------------------------


def test_an_oversized_thread_is_halved_to_one_and_recorded(tmp_path):
    """Z5: a chunk the helper refuses (rows over --max-rows) is halved down to one
    thread; the thread still over the bound is ledgered once (wire.thread_oversize)
    and marked `thread:<id>` seen; the other threads apply; the next poll never asks
    for it (the search still lists it)."""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    card = bundlemod.encode(b.compose_card())
    fake.add("taylor@houmanoids.com", "taylor@teale.com", card, thread="t1")
    fake.add("taylor@houmanoids.com", "taylor@teale.com", card, thread="t9")
    fake.thread_times.update(
        {"t1": int(a.now().timestamp()) - 10, "t9": int(a.now().timestamp()) - 5}
    )
    fake.oversized_threads.add("t9")
    s = wa.poll_once()
    assert s["applied"] == 1 and s["rejected"] == 1 and s["complete"] is True, s
    assert fake.thread_calls[0] == ["t1", "t9"] and ["t1"] in fake.thread_calls
    assert ["t9"] in fake.thread_calls
    seen = json.loads((a.state / "seen-mail.json").read_text())
    assert seen["thread:t9"] == "oversized-thread"
    rows = [e for e in a.ledger.entries() if e["action"] == "wire.thread_oversize"]
    assert len(rows) == 1 and "t9" in rows[0]["detail"] and str(MAX_ROWS) in rows[0]["detail"]
    calls = len(fake.thread_calls)
    s = wa.poll_once()
    assert s["rejected"] == 0 and all("t9" not in c for c in fake.thread_calls[calls:])
    assert len([e for e in a.ledger.entries() if e["action"] == "wire.thread_oversize"]) == 1


def test_the_default_runner_bounds_its_read_before_reading():
    """Z5: the bound is decided before the read — a helper printing past it is
    stopped and OversizedOutput raised; within it the output is returned whole; a
    helper that does not return within the timeout is TimeoutExpired."""
    argv = [sys.executable, "-c", "print('x' * 100000)"]
    with pytest.raises(OversizedOutput):
        mailmod.default_runner(argv, max_output=1000)
    r = mailmod.default_runner(argv, max_output=200000)
    assert r.returncode == 0 and len(r.stdout) == 100001
    with pytest.raises(subprocess.TimeoutExpired):
        mailmod.default_runner([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.5)
    r = mailmod.default_runner([sys.executable, "-c", "import sys; sys.exit(3)"])
    assert r.returncode == 3


def test_every_helper_call_carries_its_bound(tmp_path):
    """Z5: the adapter passes the bound to a runner that takes it — the chunk cap for
    `thread`, the small cap for `search` and `profile` — and judges a runner without
    the bound on what it returned."""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    real = fake.runner_for("taylor@houmanoids.com")
    caps: list[tuple[str, int]] = []

    def run(argv, *, max_output):
        caps.append((argv[4], max_output))
        return real(argv)

    fake.add("taylor@houmanoids.com", "taylor@teale.com", bundlemod.encode(b.compose_card()))
    w = MailWire(a, runner=run)
    assert w.poll_once()["applied"] == 1
    assert ("profile", mailmod.SMALL_OUTPUT_CAP) in caps
    assert ("search", mailmod.SMALL_OUTPUT_CAP) in caps
    assert ("thread", CHUNK_OUTPUT_CAP) in caps
    assert CHUNK_OUTPUT_CAP == MAX_ROWS * (6 * WIRE_CHARS + mailmod.ROW_OVERHEAD)

    def unbounded(argv):
        r = real(argv)
        if argv[4] == "thread":
            return subprocess.CompletedProcess(argv, 0, "[" + " " * CHUNK_OUTPUT_CAP + "]", "")
        return r

    fake.add(
        "taylor@houmanoids.com", "taylor@teale.com", bundlemod.encode(b.compose_card()), thread="t2"
    )
    w2 = MailWire(a, runner=unbounded)
    s = w2.poll_once()
    assert s["rejected"] >= 1 and any("oversized" in e for e in s["errors"])


def test_the_byte_budget_ends_a_pass_and_the_next_continues(tmp_path, monkeypatch):
    """Z5 (self-gate 2): EVERY helper call's output is charged at the runner boundary
    — the profile, the search page, a chunk, a failed or oversized answer (at its
    cap) — and the call that crosses PASS_BYTES is the pass's last, inside a split
    included; a slice already completed is recorded. The budget is set from the
    measured cost of the profile and the search so the FIRST chunk is the call that
    crosses it; a budget of one byte ends the pass at the profile, before any
    search."""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    start, now = _backlog(fake, wa, a, 120)  # three chunks in one slice
    for t in list(fake.thread_times):
        fake.add("taylor@houmanoids.com", "taylor@teale.com", "not a bundle", thread=t)
    charged: list[tuple[str, int]] = []
    real_run = wa.run

    def counting(argv):
        r = real_run(argv)
        charged.append((argv[4], len(r.stdout.encode()) + len(r.stderr.encode())))
        return r

    monkeypatch.setattr(wa, "run", counting)
    got = wa.fetch()  # under the real budget: the window completes in three chunks
    assert got.complete is True and got.chunks == 3
    assert got.bytes == sum(n for _v, n in charged)  # every call charged, none twice
    overhead = sum(n for v, n in charged if v != "thread")
    assert 0 < overhead < got.bytes
    monkeypatch.setattr(mailmod, "PASS_BYTES", overhead)  # the first chunk crosses it
    charged.clear()
    got = wa.fetch()
    assert got.complete is False and got.budget is True and "byte budget" in got.incomplete_why
    assert got.chunks == 1 and got.stopped is True and got.bytes > overhead
    assert [v for v, _n in charged] == ["profile", "search", "thread"]
    assert got.progress is False and got.scanned_through == start  # nothing completed
    # inside a split: the first (oversized) answer, charged at its cap, crosses the
    # budget — no further call, not the halves either (the threads are listed
    # newest first, so the newest thread is in the first chunk)
    fake.oversized_threads.add("b00119")
    calls = len(fake.thread_calls)
    got = wa.fetch()
    assert len(fake.thread_calls) - calls == 1 and got.stopped is True and got.budget is True
    assert got.chunks == 1 and "b00119" in fake.thread_calls[-1]
    # the helper's exit-3 answer is charged at what it printed (a runner that
    # crosses its output cap is charged at the cap); nothing recorded as oversized,
    # nothing named: the next pass halves again
    assert got.bytes > overhead and not got.oversized_threads and not got.errors
    # one byte: the profile crosses it; no search, no chunk
    monkeypatch.setattr(mailmod, "PASS_BYTES", 1)
    charged.clear()
    got = wa.fetch()
    assert got.stopped is True and got.pages == 0 and got.chunks == 0
    assert [v for v, _n in charged] == ["profile"]
    # the budget lifted: the same window completes
    monkeypatch.setattr(mailmod, "PASS_BYTES", 10**9)
    fake.oversized_threads.clear()
    got = wa.fetch()
    assert got.complete is True


def _helper():
    spec = importlib.util.spec_from_file_location("gmail_api_r21", PKG.parent / "gmail-api.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_helper_bounds_its_api_read_and_its_rows(capsys):
    """Z5 in the helper: `_read_bounded` reads cap + 1 bytes at most and refuses a
    response over the cap; `thread --json --max-rows N` exits 3 naming the bound
    with nothing on stdout; `profile --json` prints the mailbox; every row carries
    body_chars."""
    api = _helper()
    assert api._read_bounded(io.BytesIO(b"x" * 10), 10) == b"x" * 10
    with pytest.raises(api.ResponseTooLarge):
        api._read_bounded(io.BytesIO(b"x" * 11), 10)
    assert api.READ_CAP == 64 * 1024 * 1024

    class G:
        def get(self, path, **q):
            if path == "profile":
                return {"emailAddress": "taylor@houmanoids.com", "messagesTotal": 1}
            msgs = [
                {
                    "id": f"m{i}",
                    "threadId": "t1",
                    "labelIds": [],
                    "snippet": "",
                    "payload": {
                        "mimeType": "text/plain",
                        "body": {"data": "aGk=", "size": 2},
                        "headers": [],
                    },
                }
                for i in range(3)
            ]
            return {"messages": msgs}

    class A:
        ids = ["t1"]
        chars = 3000
        json = True
        max_rows = 2

    with pytest.raises(SystemExit) as e:
        api.cmd_thread(G(), A())
    out, err = capsys.readouterr()
    assert e.value.code == 3 and out == "" and "rows over 2 for threads t1" in err
    A.max_rows = 3
    api.cmd_thread(G(), A())
    rows = json.loads(capsys.readouterr().out)
    assert [r["body_chars"] for r in rows] == [2, 2, 2] and all(
        r["truncated"] is False for r in rows
    )
    api.cmd_profile(G(), A())
    assert json.loads(capsys.readouterr().out) == {"emailAddress": "taylor@houmanoids.com"}

    # an oversized ATTACHMENT response is the whole-response exit 3, never "unavailable"
    class GA(G):
        def get(self, path, **q):
            if "/attachments/" in path:
                raise api.ResponseTooLarge("response over 67108864 bytes")
            payload = {
                "mimeType": "text/plain",
                "body": {"attachmentId": "att-1", "size": 5},
                "headers": [],
            }
            msgs = [{"id": "m1", "threadId": "t1", "labelIds": [], "payload": payload}]
            return {"messages": msgs}

    A.max_rows = 5
    with pytest.raises(SystemExit) as e:
        api.cmd_thread(GA(), A())
    out, err = capsys.readouterr()
    assert e.value.code == 3 and out == "" and "attachment" in err
    # the OAuth token response is read bounded too (the source, and the bound itself)
    src = (PKG.parent / "gmail-api.py").read_text(encoding="utf-8")
    assert "json.loads(_read_bounded(r, 1 << 20))" in src and "json.load(r)" not in src
    with pytest.raises(api.ResponseTooLarge):
        api._read_bounded(io.BytesIO(b"x" * ((1 << 20) + 1)), 1 << 20)


def test_a_record_past_the_clock_is_ignored_not_trusted(tmp_path):
    """Z3 (self-gate 7): a record one day ahead would list nothing and read as
    complete; it is ignored, the window scanned, the record removed by the
    complete pass."""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    reports: list[str] = []
    a.report = reports.append
    fake.add("taylor@houmanoids.com", "taylor@teale.com", bundlemod.encode(b.compose_card()))
    ahead = int(a.now().timestamp()) + 86400
    durable.write_json(
        a.state / "wire-scan.json",
        {"scanned_through": fmt(datetime.fromtimestamp(ahead, tz=UTC)), "slice_s": 60},
    )
    floor = int((a.now() - timedelta(seconds=mailmod.CATCHUP_FLOOR_S)).timestamp())
    assert wa.scan_start() == (floor, None)
    s = wa.poll_once()
    assert s["applied"] == 1 and s["complete"] is True
    assert fake.queries[-1].endswith(f"after:{floor}") and wa.scan_record() is None
    assert any("past the clock" in r for r in reports)


def test_the_scan_record_is_typed(tmp_path):
    """Z3: wire-scan.json of the wrong shape is state.corrupt — a storage failure of
    the poll (nothing fetched), never a scan that starts anywhere."""
    a, b, wa, wb, fake, clock = pair_over_mail(tmp_path)
    assert statemod.scan_record({"scanned_through": "x", "slice_s": 1}) is None
    assert statemod.scan_record({"scanned_through": "x", "slice_s": 0}) is not None
    assert statemod.scan_record({"scanned_through": 5, "slice_s": 1}) is not None
    (a.state / "wire-scan.json").write_text("[]", encoding="utf-8")
    s = wa.poll_once()
    assert s["storage_failures"] == 1 and s["applied"] == 0 and fake.searches == []
    assert any("wire-scan.json" in e for e in s["errors"])

"""Round 20: the round-19 gate's findings (R1 to R6) and the Fable read's (C1, C2), a
ruling each, and the constraint language that replaces the regex scanner, pinned.

AA1 a `regex` constraint is written in a SMALL CONSTRAINT LANGUAGE with a complete
    recursive-descent parser of its own (`grant.emit_pattern`): alternation, plain
    groups, literals, a fixed escape set, the six shorthand classes, `.`, bracket
    classes, the two anchors, and `*` `+` `?` on a single atom only — at most 64
    atoms, 32 nested groups. Everything else is refused BY NAME at the offending
    position (grant.constraint.pattern) at issue, at receive and at load; what
    compiles is the parser's own re-emission through the `regex` package (the one
    engine, for the compile and the match; ratified in round 21), never the raw
    input; every accepted shape compiles and matches a 16 KB value in milliseconds
    and kilobytes. The scanner over the engine's grammar is gone. Round 21 made the
    class emission SORTED and merged (`[ba]` is `[a-b]`), so the table's emissions
    below are the round-21 forms.
AA2 below the deepest existing ancestor the separation checks compare every path
    component NFC-normalized and case-folded: two ABSENT names that differ only by
    case or Unicode normalization are one name, one level down or up included, and
    the node (and `keygen`, and the CLI in a second process) refuses before any
    directory is created.
AB1 (R4 and C1) ONE PREFIX RULE decides a torn tail: bytes are a repairable tear
    only when they are a strict prefix of exactly one well-formed record of ours —
    the longest valid UTF-8 prefix parses as an unterminated single object with no
    member repeated and nothing after a whole object. Everything else is the
    store's corruption by name at every read, never cut by the repair verbs.
AA4 (R5) a delegation reads the parent family's remaining budget and publishes the
    child under ONE hold of the state lock: a receive that would consume the last
    use waits, so a child never carries a use against zero remaining.
AA5 (R6, widened by the Fable read to 26 shapes) every CLI value of every verb is
    judged before the node is constructed (with `cli._node` made to raise, none of
    the shapes reaches it); a range parameter has two finite bounds.
AB2 (C2) a grant names only a scratch file the executor can honour: `--file
    ../seen.json` and `--file 'a b'` are refused at issue with nothing written, a
    received one refuses verify_failed:grant.resource.name, a stored one is
    state.corrupt at load.
AB3 the engine's own parser (`regex._regex_core._parse_pattern`) is the test
    ORACLE, never production: for a seeded corpus of random patterns, everything the
    language accepts is read by the engine as having no counted and no nested
    repetition, its emission compiles in the `regex` engine (and in the stdlib
    `re`, a cross-check of the emission's plainness), and the parser never raises
    anything but PatternProblem.

Kinds: bounds (AA1, AB3), the filesystem (AA2), RESTART RECOVERY (AB1: the repair
verbs over a damaged tail), two threads on one home (AA4), the CLI's validation
(AA5, AB2)."""

from __future__ import annotations

import json
import os
import random
import re
import subprocess
import sys
import threading
import time
import tracemalloc
import unicodedata

import pytest
import regex
from regex import _regex_core as oracle

from natively import cli, durable, keys
from natively import denial as denialmod
from natively import grant as grantmod
from natively import message as msgmod
from natively import node as nodemod
from natively.cli import main
from natively.errors import IntegrityError
from natively.executor import Executor
from natively.node import Node
from natively.timeutil import fmt, plus

from .conftest import Clock, make_node
from .test_gate_round7 import _argv
from .test_gate_round19 import PKG, VARIANT_SHAPES, _attach, _grant_with_pattern, _naming
from .test_hardening import STATEMENT, fs_write_scope, latest, pair, write_bundle

__all__ = ["pair"]  # the fixture is re-exported for this module's tests


def _grants(n: Node) -> list[str]:
    return sorted(p.name for p in (n.state / "grants").iterdir())


# ---- AA1. the constraint language ------------------------------------------------------------

# every construct of the grammar: (pattern, its canonical emission, values that
# fullmatch, values that do not)
ACCEPTED = [
    ("abc", "abc", ["abc"], ["ab", "abcd"]),
    ("a|b|c", "a|b|c", ["a", "c"], ["d", "ab"]),
    ("(ab|cd)e", "(ab|cd)e", ["abe", "cde"], ["abcde", "e"]),
    ("((a|b)c)", "((a|b)c)", ["ac", "bc"], ["a", "cc"]),
    ("(a)(b)", "(a)(b)", ["ab"], ["ba"]),
    ("()", "()", [""], ["a"]),
    ("x|", "x|", ["x", ""], ["y"]),
    (
        r"\.\*\+\?\(\)\[\]\{\}\|\^\$\\\-\/",
        r"\.\*\+\?\(\)\[\]\{\}\|\^\$\\\-/",
        [".*+?()[]{}|^$\\-/"],
        ["a", ".*+?()[]{}|^$-/"],
    ),
    (
        r"\d\D\w\W\s\S",
        r"[0-9][^0-9][0-9A-Za-z_][^0-9A-Za-z_][\t\n\x0b\x0c\r ][^\t\n\x0b\x0c\r ]",
        ["5x_ \t!"],
        ["ax_ \t!", "5x_ \t "],
    ),
    (".", ".", ["a", "\n", "é"], ["", "ab"]),
    ("[abc]", "[a-c]", ["b"], ["d", "ab"]),
    ("[a-c]", "[a-c]", ["b"], ["d"]),
    ("[a-c0-9_]", "[0-9_a-c]", ["b", "7", "_"], ["d", "-"]),
    ("[^a-c]", "[^a-c]", ["d", "\n"], ["b"]),
    (r"[\]\\\^\-]", r"[\-\\-\^]", ["]", "\\", "^", "-"], ["a"]),
    ("[{}]", r"[\{\}]", ["{", "}"], ["a"]),
    ("[ .]", r"[\ \.]", [" ", "."], ["a"]),
    ("^ab$", "^ab$", ["ab"], ["xab", "abx"]),
    ("^$", "^$", [""], ["a"]),
    ("a*", "a*", ["", "aaa"], ["b"]),
    ("a+", "a+", ["a", "aaa"], [""]),
    ("a?", "a?", ["", "a"], ["aa"]),
    (r"\d+", "[0-9]+", ["12"], ["1a", "\u0661"]),
    (".*", ".*", ["", "any\nthing"], []),
    ("[a-z]?", "[a-z]?", ["", "q"], ["qq", "Q"]),
    ("x?y*z+", "x?y*z+", ["z", "xyyzz"], ["xy", ""]),
    ("é+", "é+", ["éé"], ["e"]),
    ("a\nb", "a\\\nb", ["a\nb"], ["ab"]),
    ("a b", r"a\ b", ["a b"], ["ab"]),
]

# every construct outside the language, with the name its refusal carries
REFUSED = [
    ("a{2}", "a bare brace: counted quantifiers"),
    ("a{2,3}", "a bare brace: counted quantifiers"),
    ("a{,3}", "a bare brace: counted quantifiers"),
    ("{", "a bare brace"),
    ("}", "a bare brace"),
    ("a*{2}", "a counted quantifier after a quantifier"),
    ("(ab)+", "a quantifier on a group"),
    ("(a)*", "a quantifier on a group"),
    ("(a|b)?", "a quantifier on a group"),
    ("(?:a)", "a '(?' group construct"),
    ("(?i)a", "a '(?' group construct"),
    ("(?<n>x)", "a '(?' group construct"),
    ("(?P<n>x)", "a '(?' group construct"),
    ("(?=a)", "a '(?' group construct"),
    ("(?<=a)b", "a '(?' group construct"),
    ("(?>a)", "a '(?' group construct"),
    ("(?#c)a", "a '(?' group construct"),
    ("a*?", "a quantifier on a quantifier"),
    ("a*+", "a quantifier on a quantifier"),
    ("a++", "a quantifier on a quantifier"),
    ("a??", "a quantifier on a quantifier"),
    ("a**", "a quantifier on a quantifier"),
    (r"\1", r"the escape '\1' is outside"),
    (r"(a)\1", r"the escape '\1' is outside"),
    ("[[:alpha:]]", "a bracket inside a character class"),
    ("[[:^alpha:]]", "a bracket inside a character class"),
    ("[a[b]]", "a bracket inside a character class"),
    (r"\p{L}", r"the escape '\p' is outside"),
    (r"\P{L}", r"the escape '\P' is outside"),
    (r"\N{LATIN SMALL LETTER A}", r"the escape '\N' is outside"),
    (r"\x41", r"the escape '\x' is outside"),
    ("\\u0041", r"the escape '\u' is outside"),
    (r"\U00000041", r"the escape '\U' is outside"),
    (r"\n", r"the escape '\n' is outside"),
    (r"\t", r"the escape '\t' is outside"),
    (r"\b", r"the escape '\b' is outside"),
    (r"\A", r"the escape '\A' is outside"),
    (r"[\n]", r"the escape '\n' inside a character class"),
    (r"[\d]", r"the escape '\d' inside a character class"),
    (r"[\[]", r"the escape '\[' inside a character class"),
    ("[abc", "an unterminated character class"),
    ("[a-", "an unterminated character class"),
    ("[", "an unterminated character class"),
    ("[^", "an unterminated character class"),
    (r"[\]", "an unterminated character class"),
    ("[]", "an empty character class"),
    ("[^]", "an empty character class"),
    ("[z-a]", "a range out of order"),
    ("[a-]", "a bare '-' at the end of a class"),
    ("[-a]", "a bare '-' inside a character class"),
    ("[a^b]", "a bare '^' inside a character class"),
    ("]", "a bare ']'"),
    ("*a", "a quantifier '*' with nothing before it"),
    ("|+", "a quantifier '+' with nothing before it"),
    ("^*", "a quantifier on an anchor"),
    ("$+", "a quantifier on an anchor"),
    ("(a", "an unterminated group"),
    ("a)", "an unmatched ')'"),
    ("\\", "a trailing backslash"),
    ("[a\\", "a trailing backslash inside a character class"),
    ("a" * 65, "more than 64 atoms"),
    ("(" * 33 + "a" + ")" * 33, "groups nested more than 32 deep"),
]

# the shapes the reviews ran against the old scanner: the round-19 fresh review's,
# the r19b and r19c self-gates', the gate's R2 and R3, the Fable read's B
REVIEWED = [
    *VARIANT_SHAPES,
    "(a{9999}){9999}",
    "a{99999999}",
    "x{257}",
    "a{,300}",
    "(a{2}){2}",
    "(a+)+",
    "(a*)?",
    "((a{99}){99}){99}",
    r"\d{257}",
    r"(\d{2}){2}",
    "(a{2})(?i){2}",
    r"\w{1000000000}",
    r"(\p{L}{2}){2}",
    r"\s{300}",
    "(a{2}[[:alpha:])(]){2}",
    "[[a]{2}]",
    "[[.a.]]{300}",
    "(a{2}[[:alpha:]){2}",
    r"(\p{2,3}){2}",
    r"(\P{2,3}){2}",
    r"(\N{2,}){2}",
    r"(\N{2,3}){2}",
    r"(\p{2,}){2}",
    r"\N{2{257}",
    "([[.a.]{2}]){2}",
    "([[:a]{2}:]]){2}",
    "([[=a=]{2}]){2}",
    "([[:alph]{2}a:]]){2}",
    "([[.]{2}.]]){2}",
    "a{2}?{3}",
    "a{2}{3}",
    "a{2}*",
    "a{٢٥٦}",
]
# the sub-kilobyte shapes the Fable read measured at 0.4 to 0.9 s and 1.4 to 2.1 GB
HEAVY = [
    "(" + r"\p{256,256}" * 80 + "){256}",
    "(" + r"\N{256,}" * 80 + "){256}",
    "(" + "[[.a.]{256}]" * 80 + "){256}",
    "(" + "[[.a.]{256}]" * 40 + "){256}",
]


@pytest.mark.parametrize("pattern, emission, hits, misses", ACCEPTED, ids=[a[0] for a in ACCEPTED])
def test_every_construct_of_the_grammar_is_accepted_and_matches_what_it_says(
    pattern, emission, hits, misses
):
    """AA1: each construct of the grammar table parses, emits its canonical form,
    and — through the `regex` engine that compiles it and runs the match at use, and
    through the stdlib `re` as a cross-check that the emission is plain syntax —
    fullmatches exactly what the table says."""
    assert grantmod.pattern_problem(pattern) is None
    assert grantmod.emit_pattern(pattern) == emission
    compiled = re.compile(emission, re.DOTALL)
    for v in hits:
        assert compiled.fullmatch(v) is not None, (pattern, v)
        assert regex.fullmatch(emission, v, flags=regex.DOTALL) is not None, (pattern, v)
        assert grantmod._value_ok(v, {"regex": pattern}) is None, (pattern, v)
    for v in misses:
        assert compiled.fullmatch(v) is None, (pattern, v)
        assert regex.fullmatch(emission, v, flags=regex.DOTALL) is None, (pattern, v)
        assert grantmod._value_ok(v, {"regex": pattern}) == "does not match regex", (pattern, v)


def test_an_accepted_pattern_issues_and_an_action_under_it_applies(pair):
    """AA1, end to end: a grant with a class, a shorthand, a group under alternation
    and the three quantifiers issues, a matching write applies, a non-matching one
    is refused at scope."""
    a, b, clock, reports = pair
    pattern = "^([a-z]+|\\d*) ?\\w+\n$"
    g = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "ok.txt", regex=pattern),
        principal_statement=STATEMENT,
        max_uses=2,
    )
    (rep,) = b.receive(write_bundle(a, b, g, "ok.txt", "hello world\n"))
    assert rep["object"]["outcome"] == "applied"
    assert (b.scratch_dir / "ok.txt").read_text() == "hello world\n"
    (rep,) = b.receive(write_bundle(a, b, g, "ok.txt", "Hello world\n"))
    assert rep["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "does not match regex" in latest(b)["detail"]


@pytest.mark.parametrize("pattern, needle", REFUSED, ids=[r[0] for r in REFUSED])
def test_every_excluded_construct_is_refused_by_name_at_issue(pair, pattern, needle):
    """AA1: each construct outside the language is refused at its position, by name,
    at issue — nothing under grants/, nothing compiled, in milliseconds."""
    a, b, clock, reports = pair
    why = grantmod.pattern_problem(pattern)
    assert why is not None and re.match(r"position \d+: ", why) and needle in why, (pattern, why)
    before = _grants(a)
    t0 = time.monotonic()
    with pytest.raises(ValueError) as e:
        a.issue_grant(
            subject_card=b.card,
            scope=fs_write_scope(b, "x.txt", regex=pattern),
            principal_statement=STATEMENT,
        )
    assert time.monotonic() - t0 < 1.0
    assert "grant.constraint.pattern" in str(e.value) and needle in str(e.value)
    assert _grants(a) == before


@pytest.mark.parametrize("pattern", [*REVIEWED, *HEAVY], ids=lambda p: p[:40])
def test_every_shape_the_reviews_ran_against_the_scanner_is_refused(pair, pattern, monkeypatch):
    """AA1 (R2, R3; the round-19 fresh review, r19b, r19c and the Fable read's B):
    every shape that defeated or probed the old scanner is outside the language,
    refused by name at issue with no engine compile at all."""
    a, b, clock, reports = pair
    compiles: list[str] = []
    monkeypatch.setattr(grantmod.re, "compile", lambda *x, **k: compiles.append(x[0]))
    monkeypatch.setattr(grantmod.regex, "compile", lambda *x, **k: compiles.append(x[0]))
    assert grantmod.pattern_problem(pattern) is not None, pattern
    with pytest.raises(ValueError) as e:  # no `match=`: pytest's own compile would count
        a.issue_grant(
            subject_card=b.card,
            scope=fs_write_scope(b, "x.txt", regex=pattern),
            principal_statement=STATEMENT,
        )
    assert "grant.constraint.pattern" in str(e.value)
    assert compiles == []


@pytest.mark.parametrize(
    "pattern",
    ["a{2}", "(ab)+", "(?:a)", r"\p{L}", "[[:alpha:]]", "[a-", *HEAVY[:2]],
    ids=lambda p: p[:30],
)
def test_an_excluded_construct_is_refused_at_receive_and_is_state_corrupt_at_load(
    pair, pattern, monkeypatch
):
    """AA1, the other two boundaries: a grant signed by a pinned principal carrying
    the shape is refused at receive verify_failed:grant.constraint.pattern (nothing
    stored, no compile, milliseconds and kilobytes — the Fable read measured 0.4 s
    and 1.4 GB for the heavy shapes); the same document on file is state.corrupt at
    the load, naming the path (the grant id) and grant.constraint.pattern."""
    a, b, clock, reports = pair
    compiles: list[str] = []
    monkeypatch.setattr(grantmod.re, "compile", lambda *x, **k: compiles.append(x[0]))
    monkeypatch.setattr(grantmod.regex, "compile", lambda *x, **k: compiles.append(x[0]))
    g = _grant_with_pattern(a, b, pattern)
    tracemalloc.start()
    t0 = time.monotonic()
    b.receive(_attach(a, b, g))
    elapsed = time.monotonic() - t0
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert elapsed < 1.0 and peak < 16 * 1024 * 1024, (elapsed, peak)
    assert "verify_failed:grant.constraint.pattern" in [e["outcome"] for e in b.ledger.entries()]
    assert compiles == []
    stored = b.state / "grants" / f"{g['grant_id']}.json"
    assert not stored.exists()
    stored.write_text(json.dumps(g), encoding="utf-8")
    with pytest.raises(IntegrityError) as e:
        b.load_grant(g["grant_id"])
    assert e.value.reason == "state.corrupt" and g["grant_id"] in str(e.value)
    assert "grant.constraint.pattern" in str(e.value) and compiles == []


def test_what_compiles_is_the_emission_never_the_raw_input(pair, monkeypatch):
    """AA1: for every shape of the grammar table the document check hands the
    `regex` engine exactly the parser's emission; where the emission differs from the
    raw pattern (an escape, a literal the emission escapes) the raw text never
    reaches the engine."""
    a, b, clock, reports = pair
    calls: list[str] = []
    real = grantmod.regex.compile

    def compile_(pat, *x, **k):
        calls.append(pat)
        return real(pat, *x, **k)

    monkeypatch.setattr(grantmod.regex, "compile", compile_)
    for pattern, emission, _hits, _misses in ACCEPTED:
        g = _grant_with_pattern(a, b, pattern)
        calls.clear()
        grantmod.check_document(g, extensions=grantmod.ANY_EXTENSION)
        assert calls == [emission], (pattern, calls)
        if emission != pattern:
            assert pattern not in calls


def test_every_accepted_shape_compiles_and_matches_16kb_within_the_budget():
    """AA1, the cost argument pinned: a quantifier on a single atom only means no
    nested repetition, so every shape of the grammar table compiles and fullmatches
    a 16 KB value (the executor's cap is 64 KB) within a few MB, cold — through the
    production path (`_value_ok`: the emission, the `regex` engine, the timeout).
    The engine's cache holds nothing for a refused shape because a refused shape
    never compiles (the test above). The WORK of the parse is pinned by a counter
    and the wall clock ONCE, generously, in tests/test_gate_round21.py (round-20
    gate, finding 1: a 50 ms clock here failed in the gate's sandbox)."""
    big = "a" * 16384
    for pattern, _emission, _hits, _misses in ACCEPTED:
        regex.purge()  # COLD: the engine's cache holds nothing for the shape
        tracemalloc.start()
        grantmod._compile_pattern(pattern, "x")
        grantmod._value_ok(big, {"regex": pattern})
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        assert peak < 4 * 1024 * 1024, (pattern, peak)


def test_a_matching_write_and_a_refused_one_still_run_through_the_regex_timeout(pair):
    """AA1: the match at use runs the emission through the `regex` engine for its
    timeout — a shape the language admits that the engine cannot short-circuit
    (twenty `(\\w*|\\s*)` groups before `[bc]$`) is refused scope.regex_timeout by
    name, never a hang (tests/test_hardening.py pins the whole shape); an ordinary
    one matches."""
    slow = "^" + "(\\w*|\\s*)" * 20 + "[bc]$"
    assert grantmod.pattern_problem(slow) is None
    t0 = time.monotonic()
    with pytest.raises(Exception) as e:
        grantmod._value_ok("b" + "a" * 30 + "d", {"regex": slow})
    assert "scope.regex_timeout" in str(e.value)
    assert time.monotonic() - t0 < grantmod.REGEX_TIMEOUT_S + 5


def test_the_old_scanner_is_gone():
    """AA1: the scanner and its bounds are removed, not kept beside the parser."""
    for name in ("MAX_QUANTIFIER", "_GROUP_RE", "_QUANTIFIER_RE", "_scan_pattern"):
        assert not hasattr(grantmod, name), name
    assert callable(grantmod.emit_pattern) and grantmod.MAX_ATOMS == 64
    assert grantmod.MAX_GROUP_DEPTH == 32


# ---- AB3. the engine's own parser as the test oracle -----------------------------------------

_REPEATS = (oracle.GreedyRepeat, oracle.LazyRepeat, oracle.PossessiveRepeat)
_PLAIN = {(0, None), (1, None), (0, 1)}  # `*` `+` `?`


def _oracle_tree(pattern: str):
    return oracle._parse_pattern(oracle.Source(pattern), oracle.Info(0, str, {}))


def _children(n):
    for v in vars(n).values():
        if isinstance(v, list):
            for x in v:
                if type(x).__module__.endswith("_regex_core"):
                    yield x
        elif type(v).__module__.endswith("_regex_core"):
            yield v


def _has_counted_or_nested_repeat(n, inside: bool = False) -> bool:
    """Whether the engine's parse tree holds a counted quantifier or a repeat
    inside a repeat (the two shapes the language's cost argument excludes)."""
    if isinstance(n, _REPEATS):
        if (n.min_count, n.max_count) not in _PLAIN or inside:
            return True
        inside = True
    return any(_has_counted_or_nested_repeat(x, inside) for x in _children(n))


def test_the_oracle_reads_the_shapes_it_must():
    """AB3, the guard on the private API (regex is pinned in requirements.txt): the
    walker sees `(a{2}){2}` as nested, `x{257}` as counted, `(a+)+` as nested, and
    `a+b*` as neither."""
    assert _has_counted_or_nested_repeat(_oracle_tree("(a{2}){2}"))
    assert _has_counted_or_nested_repeat(_oracle_tree("x{257}"))
    assert _has_counted_or_nested_repeat(_oracle_tree("(a+)+"))
    assert _has_counted_or_nested_repeat(_oracle_tree(r"\p{2,3}"))
    assert not _has_counted_or_nested_repeat(_oracle_tree("a+b*c?"))
    assert not _has_counted_or_nested_repeat(_oracle_tree("(a|b)c*"))


FUZZ_ALPHABET = list("ab.*+?()[]{}|^$\\-/dwsDWSpPNxuU0123456789,:=<>!#e \n")


def test_fuzz_everything_the_language_accepts_the_engine_reads_as_flat_repetition():
    """AB3: a seeded corpus of random patterns over the engine's token alphabet
    (60,000 by default, the size the Fable read ran; NATIVELY_FUZZ overrides): every pattern the
    parser ACCEPTS is one the oracle reads with no counted and no nested repetition,
    and its emission compiles in the `regex` engine (and in the stdlib `re`, the
    cross-check that it is plain syntax); a refused pattern refused by
    PatternProblem only — the parser never raises anything else on any input."""
    n = int(os.environ.get("NATIVELY_FUZZ", "60000"))
    rnd = random.Random(20)
    accepted = 0
    for _ in range(n):
        p = "".join(rnd.choice(FUZZ_ALPHABET) for _ in range(rnd.randint(1, 24)))
        try:
            em = grantmod.emit_pattern(p)
        except grantmod.PatternProblem as e:
            assert e.position >= 0 and e.why
            continue
        accepted += 1
        assert not _has_counted_or_nested_repeat(_oracle_tree(p)), p
        re.compile(em, re.DOTALL)  # the emission is plain syntax to the stdlib too
        regex.compile(em, regex.DOTALL)
    assert accepted > n // 100  # the corpus exercises the accepting paths too


# ---- AA2. the separation checks fold the unresolved remainder -----------------------------------


def _alias_pair(home, shape):
    nfc, nfd = "état", unicodedata.normalize("NFD", "état")
    assert nfc != nfd
    return {
        "case": (home / "state", home / "STATE"),
        "nfc-nfd": (home / nfc, home / nfd),
        "one-down": (home / "state", home / "STATE" / "sub"),
        "one-up": (home / "STATE" / "sub", home / "state"),
    }[shape]


def test_the_fold_is_nfc_and_casefold():
    assert keys._fold("STATE") == keys._fold("state") == "state"
    assert keys._fold(unicodedata.normalize("NFD", "état")) == keys._fold("ÉTAT")
    assert keys._fold("state") != keys._fold("scratch")


@pytest.mark.parametrize("shape", ["case", "nfc-nfd", "one-down", "one-up"])
def test_an_absent_alias_of_the_state_refuses_before_any_directory(tmp_path, shape):
    """AA2 (R1; Fable A): two ABSENT paths that differ only by case or by Unicode
    normalization — as siblings, one level down (the scratch inside the state's
    alias) or one level up (the state inside the scratch's alias) — are one name to
    the separation checks: the node refuses by name and creates nothing; the same
    pair through `--scratch` exits 1 with nothing created."""
    kd = tmp_path / "keys"
    keys.generate_all(kd)
    home = tmp_path / "home"
    state, scratch = _alias_pair(home, shape)
    with pytest.raises(ValueError) as e:
        Node(state_dir=state, keys_dir=kd, scratch_dir=scratch)
    assert "count as one name" in str(e.value) and "scratch dir" in str(e.value)
    assert not home.exists()
    rc = main(["--state", str(state), "--keys", str(kd), "--scratch", str(scratch), "cards"])
    assert rc == 1 and not home.exists()


def test_the_r1_pair_through_keygen_and_card_in_a_second_process(tmp_path):
    """AA2 (Fable G2): `--state …/state --scratch …/STATE` with both absent ran
    `keygen` and `card` with rc 0 and the scratch root's listing was the state's
    contents. Now `keygen` refuses before it writes a key and `card` refuses before
    the state directory exists — through NATIVELY_SCRATCH in a second process."""
    home = tmp_path / "home"
    kd = tmp_path / "keys"
    env = {
        **os.environ,
        "NATIVELY_STATE": str(home / "state"),
        "NATIVELY_KEYS": str(kd),
        "NATIVELY_SCRATCH": str(home / "STATE"),
        "PYTHONPATH": str(PKG),
        "PYTHONDONTWRITEBYTECODE": "1",
    }

    def run(*argv):
        return subprocess.run(
            [sys.executable, "-B", "-m", "natively", *argv],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )

    r = run("keygen")
    assert r.returncode == 1 and "count as one name" in r.stderr and "Traceback" not in r.stderr
    assert not kd.exists() and not home.exists()
    keys.generate_all(kd)
    r = run("card")
    assert r.returncode == 1 and "count as one name" in r.stderr and "Traceback" not in r.stderr
    assert not home.exists()


def test_two_distinct_absent_names_still_construct(tmp_path):
    kd = tmp_path / "keys"
    keys.generate_all(kd)
    home = tmp_path / "home"
    n = Node(state_dir=home / "state", keys_dir=kd, scratch_dir=home / "scratch")
    assert (home / "state").is_dir() and (home / "scratch").is_dir()
    assert n.scratch_identity != (n.state.stat().st_dev, n.state.stat().st_ino)
    assert not keys._same(home / "state", home / "scratch")
    assert not keys._within(home / "state" / "x", home / "scratch")


# ---- AB1. the prefix rule ---------------------------------------------------------------------

PREFIX_SHAPES = [
    ("dup-then-incomplete", b'{"a":1,"a":2,"b":"\xe2\x82', "duplicate member name 'a'"),
    ("two-objects-one-line", b'{"a":1}{"b":2', "bytes after a whole object"),
    ("two-whole-objects", b'{"a":1}{"b":2}', "bytes after a whole object"),
    ("object-then-garbage", b'{"a":1}xyz', "bytes after a whole object"),
    ("object-then-nul", b'{"a":1}\x00', "bytes after a whole object"),
    ("invalid-byte-mid-line", b'{"a":1,\xff"b":2}', "an invalid byte at offset 7"),
    ("invalid-byte-then-dup", b'{"a":\xff,"b":1,"b":2', "an invalid byte at offset 5"),
    ("incomplete-outside-string", b'{"a":1,"b":\xe2', "an incomplete character outside a string"),
    ("control-in-string", b'{"a":"\x01"', "a control character inside a string"),
    ("not-an-object", b"[1,2", "does not begin with an object"),
    ("whole-object", b'{"a":1}', "a whole object"),
]
TEARS = [
    b"",
    b"{",
    b'{"a":"x\xe2\x82',
    b'{"a":[1,{"b":',
    b'{"a":"\\u00',
    b'{"a":tru',
    b'{"a":-1.5e',
    b'{"a":1,"b":{"c":"d"},"e":[',
]


@pytest.mark.parametrize("name, raw, needle", PREFIX_SHAPES, ids=[s[0] for s in PREFIX_SHAPES])
def test_the_prefix_rule_names_what_is_not_a_tear(name, raw, needle):
    why = durable.torn_text_problem(raw)
    assert why is not None and needle in why, (name, why)
    assert durable.is_torn_text(raw) is False


@pytest.mark.parametrize("raw", TEARS, ids=[repr(t)[:24] for t in TEARS])
def test_a_strict_prefix_of_one_record_is_a_tear(raw):
    assert durable.torn_text_problem(raw) is None and durable.is_torn_text(raw) is True


def _sound_store(pair_, store):
    """(node, store object, name, repair argv, the sound bytes) for one of the three
    JSONL stores with at least one record on file."""
    a, b, clock, reports = pair_
    if store == "ledger":
        node, obj, name, verb = b, b.ledger, "ledger", ["ledger", "repair"]
    elif store == "feed":
        a.revoke(grants=[grantmod.new_id("grt")], principal_statement="x")
        node, obj, name, verb = a, a.revocations, "feed", ["feed", "repair"]
    else:
        kp = keys.KeyPair.generate()
        d = denialmod.sign(
            denialmod.build(
                principal_key=kp.public,
                ts=fmt(b.now()),
                deny=[{"action": "*", "resource": "*"}],
                principal_statement="stop",
            ),
            kp,
        )
        b.denials.path.write_text(
            json.dumps(d, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        node, obj, name, verb = b, b.denials, "denial", ["denial", "repair"]
    data = obj.path.read_bytes()
    assert data.endswith(b"\n") and obj.entries()
    return node, obj, name, verb, data


@pytest.mark.parametrize("store", ["ledger", "feed", "denials"])
@pytest.mark.parametrize(
    "shape, raw, needle", PREFIX_SHAPES[:8], ids=[s[0] for s in PREFIX_SHAPES[:8]]
)
def test_bytes_that_are_not_a_prefix_of_one_record_are_corruption_never_cut(
    pair, store, shape, raw, needle
):
    """AB1 (R4 and C1) on each of the three stores: the shape as the unterminated
    last line is <store>.corrupt naming what was found at every read (`torn_tail`,
    the entries), and the repair verb exits 2 with the file byte-identical — before,
    every one of these was offered for the cut."""
    node, obj, name, verb, data = _sound_store(pair, store)
    damaged = data + raw
    obj.path.write_bytes(damaged)
    for read in (obj.torn_tail, obj.entries):
        with pytest.raises(IntegrityError) as e:
            read()
        assert e.value.reason == f"{name}.corrupt", (read.__name__, e.value)
        assert needle in str(e.value), (read.__name__, e.value)
    assert main([*_argv(node), *verb]) == 2
    assert obj.path.read_bytes() == damaged


@pytest.mark.parametrize("store", ["ledger", "feed", "denials"])
@pytest.mark.parametrize("incomplete", [False, True], ids=["cut-in-a-string", "plus-a-torn-char"])
def test_a_genuine_tear_is_still_cut(pair, store, incomplete):
    """AB1, the other side: a strict prefix of the store's own last record, cut
    inside a string value, with or without an incomplete UTF-8 character at its
    end, is offered by `torn_tail` and the repair verb cuts it (rc 0, the file back
    to its sound bytes)."""
    node, obj, name, verb, data = _sound_store(pair, store)
    line = data[:-1].split(b"\n")[-1]
    k = line.rfind(b'":"')
    assert k > 0
    torn = line[: k + 5] + (b"\xe2\x82" if incomplete else b"")
    assert durable.torn_text_problem(torn) is None
    obj.path.write_bytes(data + torn)
    assert obj.torn_tail() == torn
    assert main([*_argv(node), *verb]) == 0
    after = obj.path.read_bytes()
    if store == "ledger":
        # the ledger's own cut is ledgered as its next entry (ledger.tail_truncated)
        assert after.startswith(data) and after.count(b"\n") == data.count(b"\n") + 1
        audit = after[len(data) :]
        assert b'"action":"ledger.tail_truncated"' in audit and not audit.startswith(torn)
    else:
        assert after == data


# ---- AA4. the delegation budget under one lock hold --------------------------------------------


def test_the_budget_is_read_and_the_child_published_under_one_lock_hold(pair, monkeypatch):
    """AA4 (R5): a receive that would consume the parent's last use, started while
    the delegation is between its budget read and the child's publication, WAITS
    for the lock: the child is published first and the receive runs after — never a
    child carrying a use against zero remaining. Before, the budget was read at lock
    depth 0 and the receive slipped in between."""
    a, b, clock, reports = pair
    parent = a.issue_grant(
        subject_card=a.card,
        scope=fs_write_scope(a, "p.txt", regex=None),
        principal_statement=STATEMENT,
        max_uses=1,
    )
    at_read, go = threading.Event(), threading.Event()
    real = nodemod.Node.grant_uses
    depth_at_read: list[int] = []

    def grant_uses(self, g, *, family=False):
        r = real(self, g, family=family)
        if threading.current_thread().name == "delegator" and family and not at_read.is_set():
            depth_at_read.append(self._lock_depth)
            at_read.set()
            assert go.wait(10)
        return r

    monkeypatch.setattr(nodemod.Node, "grant_uses", grant_uses)
    events: list[str] = []
    errors: list[BaseException] = []
    tighter = [{**parent["scope"][0], "params": {"keys": [], "values": {}}}]
    child: dict = {}

    def delegate():
        try:
            child.update(
                a.delegate_grant(
                    parent=parent, subject_card=b.card, scope=tighter, principal_statement="one"
                )
            )
            events.append("child published")
        except BaseException as e:  # noqa: BLE001 — recorded for the assertion
            errors.append(e)

    def receive():
        try:
            (rep,) = a.receive(_naming(b, a, parent, "p.txt"))
            events.append(f"receive {rep['object']['outcome']}")
        except BaseException as e:  # noqa: BLE001 — recorded for the assertion
            errors.append(e)

    t1 = threading.Thread(target=delegate, name="delegator")
    t1.start()
    assert at_read.wait(10)
    assert depth_at_read == [1]  # the budget read runs under the lock
    t2 = threading.Thread(target=receive, name="receiver")
    t2.start()
    t2.join(1.0)
    assert t2.is_alive(), "the receive ran inside the delegation's read-to-publish window"
    go.set()
    t1.join(10)
    t2.join(10)
    assert errors == [] and events == ["child published", "receive applied"]
    assert child["max_uses"] == 1 and a.load_grant(child["grant_id"]) is not None
    assert a.grant_uses(parent, family=True) == (1, None)


# ---- AA5. every CLI value judged before construction ------------------------------------------

_GRT = grantmod.new_id("grt")
_KEY = keys.KeyPair.generate().public
_GRANT = ["grant", "--to", "b", "--action", "fs.write", "--file", "f", "--statement", "s"]
_SEND = ["send", "--to", "b", "--action", "fs.write", "--file", "f", "--grant", _GRT]
_DENY = ["deny", "--action", "a", "--resource", "r", "--statement", "s"]
NO_NODE_SHAPES = [
    (["card", "--agent-name", ""], "--agent-name must not be empty"),
    (["card", "--node-name", ""], "--node-name must not be empty"),
    (["card", "--principal-name", ""], "--principal-name must not be empty"),
    ([*_GRANT, "--statement", ""], "--statement must not be empty"),
    ([*_GRANT, "--statement", "x" * 4001], "--statement is over 4000"),
    ([*_GRANT, "--audience", "bad"], "--audience 'bad' is not a principal key"),
    ([*_GRANT, "--action", ""], "--action must not be empty"),
    ([*_GRANT[:5], "--resource", "", *_GRANT[7:]], "--resource must not be empty"),
    ([*_GRANT[:5], "--resource", "nothost", *_GRANT[7:]], "must start with 'host:'"),
    ([*_GRANT, "--to", ""], "--to must not be empty"),
    ([*_GRANT[:5], *_GRANT[7:]], "give --resource or --file"),
    ([*_GRANT, "--file", "../seen.json"], "bad scratch name '../seen.json'"),
    ([*_GRANT, "--file", "a b"], "bad scratch name 'a b'"),
    ([*_GRANT, "--param", "k=range:,5"], "two finite bounds"),
    ([*_GRANT, "--param", "k=range:1,"], "two finite bounds"),
    ([*_GRANT, "--param", "k=range:,"], "two finite bounds"),
    (_SEND[:-2], "needs --action, --file/--resource, and --grant"),
    (["send", "--info", "hi"], "--to (or --card) must not be empty"),
    (["send", "--to", "b", "--info", ""], "--info must not be empty"),
    ([*_SEND, "--param", "k"], "use key=value"),
    ([*_SEND, "--param", "content=@/nonexistent/x"], "No such file"),
    ([*_SEND, "--action", ""], "--action must not be empty"),
    ([*_SEND, "--file", "../seen.json"], "bad scratch name '../seen.json'"),
    ([*_SEND[:5], "--resource", "nothost", *_SEND[7:]], "must start with 'host:'"),
    ([*_DENY, "--action", ""], "--action must not be empty"),
    ([*_DENY, "--resource", ""], "--resource must not be empty"),
    ([*_DENY, "--statement", ""], "--statement must not be empty"),
    ([*_DENY, "--agent", "bad"], "not sha256:<64 hex>"),
    (["revoke", "--grant", _GRT, "--statement", ""], "--statement must not be empty"),
    (["pin", _KEY, "--name", ""], "--name must not be empty"),
    (["pending", "discard", ""], "is not an aside copy name"),
    (["pending", "discard", "../x.corrupt-1"], "is not an aside copy name"),
    (["pending", "discard", "x\x00y.corrupt-1"], "is not an aside copy name"),
    (["pending", "repair", "nope"], "is not an aside copy name"),
    (["poll", "--file", "/nonexistent/wire"], "No such file"),
]


@pytest.mark.parametrize(
    "argv, needle", NO_NODE_SHAPES, ids=[" ".join(s[0])[:48] for s in NO_NODE_SHAPES]
)
def test_every_cli_value_is_judged_before_the_node_is_constructed(
    pair, capsys, monkeypatch, argv, needle
):
    """AA5 (R6; the Fable read's 26 shapes): with `cli._node` made to raise, each
    shape exits 1 naming the value with nothing written — the node, its startup
    sweep and its directory creation never run."""
    a, b, clock, reports = pair

    def no_node(_a):
        raise AssertionError("the node was constructed before the value was judged")

    monkeypatch.setattr(cli, "_node", no_node)
    before = {p.name: p.read_bytes() for p in a.state.iterdir() if p.is_file()}
    assert main([*_argv(a), *argv]) == 1
    err = capsys.readouterr().err
    assert needle in err and "Traceback" not in err and "constructed before" not in err, err
    assert {p.name: p.read_bytes() for p in a.state.iterdir() if p.is_file()} == before


def test_a_range_has_two_finite_bounds(pair, capsys):
    """AA5 (Y10's literal wording): an open-ended range is refused by name before the
    node; a finite one issues and the grant carries both bounds."""
    a, b, clock, reports = pair
    base = [*_argv(a), *_GRANT]
    before = _grants(a)
    for spec in ("k=range:,5", "k=range:1,", "k=range:,"):
        assert main([*base, "--param", spec]) == 1
        assert "two finite bounds" in capsys.readouterr().err
    assert _grants(a) == before
    assert main([*base, "--param", "k=range:1,5"]) == 0
    g = a.load_grant(capsys.readouterr().out.split()[1])
    assert g["scope"][0]["params"]["values"]["k"] == {"range": [1.0, 5.0]}


# ---- AB2. a grant names only a resource the executor can honour ---------------------------------


def _scope_naming(b, name):
    return [
        {
            "action": "fs.write",
            "resource": f"host:{b.card['node']['key']}:scratch/{name}",
            "params": {"keys": ["content"], "values": {}},
        }
    ]


def test_a_file_the_executor_cannot_honour_is_refused_at_issue_with_nothing_written(pair, capsys):
    """AB2 (C2): `grant --file ../seen.json` and `--file 'a b'` exit 1 naming the
    rule before the node, nothing under grants/; a well-formed name issues; the node
    API refuses the same resource as an unsound document."""
    a, b, clock, reports = pair
    before = _grants(a)
    for bad in ("../seen.json", "a b", ".", "..", "x/y", ""):
        argv = [*_argv(a), *_GRANT[:5], "--file", bad, *_GRANT[7:]]
        assert main(argv) == 1, bad
        err = capsys.readouterr().err
        assert "bad scratch name" in err and "Traceback" not in err, (bad, err)
    assert _grants(a) == before
    assert main([*_argv(a), *_GRANT[:5], "--file", "ok.txt", *_GRANT[7:]]) == 0
    assert len(_grants(a)) == len(before) + 1
    capsys.readouterr()
    with pytest.raises(ValueError) as e:
        a.issue_grant(
            subject_card=b.card,
            scope=_scope_naming(b, "../seen.json"),
            principal_statement=STATEMENT,
        )
    assert "not a sound document" in str(e.value) and "grant.resource.name" in str(e.value)
    assert len(_grants(a)) == len(before) + 1


def test_a_received_grant_with_a_bad_name_is_refused_by_name_and_a_stored_one_is_corrupt(
    pair, monkeypatch
):
    """AB2 (C2): a grant signed by a pinned principal naming `scratch/../seen.json`
    refuses verify_failed:grant.resource.name at receive (nothing stored); the same
    document written under grants/ by hand is state.corrupt at the load. The
    executor never runs for either: `Executor.apply` is a spy that fails the test
    if called (round-20 gate, finding 4: an `or True` here asserted nothing)."""
    a, b, clock, reports = pair
    applied: list[tuple[str, str]] = []
    monkeypatch.setattr(
        Executor, "apply", lambda self, action, resource, params: applied.append((action, resource))
    )
    g = grantmod.build(
        issuer={"principal": a.card["principal"]["name"], "key": a.principal.public},
        subject={"agent": grantmod.cardmod.card_hash(b.card), "key": b.card["agent"]["key"]},
        audience_executor=b.card["node"]["key"],
        scope=_scope_naming(b, "../seen.json"),
        principal_statement=STATEMENT,
        issued_at=a.ts(),
        expires_at=fmt(plus(a.now(), 3600)),
        max_check_interval_s=a.poll_s * 5,
    )
    g = grantmod.sign(g, a.principal)
    b.receive(_attach(a, b, g))
    assert "verify_failed:grant.resource.name" in [e["outcome"] for e in b.ledger.entries()]
    stored = b.state / "grants" / f"{g['grant_id']}.json"
    assert not stored.exists()
    stored.write_text(json.dumps(g), encoding="utf-8")
    with pytest.raises(IntegrityError) as e:
        b.load_grant(g["grant_id"])
    assert e.value.reason == "state.corrupt" and "grant.resource.name" in str(e.value)
    assert applied == []  # nothing of the executor ran, at receive or at the load
    assert not any(b.scratch_dir.iterdir())  # and nothing landed under its root
    n = make_node(b.state.parent, "c", Clock())
    assert n.executor().resource_for("ok.txt").endswith(":scratch/ok.txt")


# ---- the round-20 self-gate: ten findings, fixed in-family ------------------------------------

from natively.canon import sha256_hex  # noqa: E402 — the section's own imports
from natively.objects import new_id  # noqa: E402

SELFGATE_SHAPES = [
    ("cut-after-a-backslash", b'{"x":"\\\xc3', "an incomplete character inside an escape"),
    ("cut-inside-u-digits", b'{"x":"\\u12\xc3', "an incomplete character inside an escape"),
    ("unicode-digit", b'{"a":1\xd9\xa1', "an invalid number"),
    ("unicode-digit-fraction", b'{"a":1.\xd9\xa1', "an invalid number"),
    ("unicode-digit-exponent", b'{"a":1e\xd9\xa1', "an invalid number"),
]


@pytest.mark.parametrize("name, raw, needle", SELFGATE_SHAPES, ids=[s[0] for s in SELFGATE_SHAPES])
def test_an_incomplete_character_in_an_escape_and_a_unicode_digit_are_never_a_tear(
    name, raw, needle
):
    """Self-gate findings 1 and 2: a string cut after a backslash or inside the hex
    digits of a `\\u` escape can be completed only by ASCII, so an incomplete UTF-8
    character there is corruption; JSON digits are ASCII, so a Unicode digit after
    `1` (whole, fractional or exponent) completes no number. Before, all five were
    tears the repair verbs cut."""
    why = durable.torn_text_problem(raw)
    assert why is not None and needle in why, (name, why)
    assert (
        durable.torn_text_problem(
            b'{"x":"\\n',
        )
        is None
    )  # a complete escape, then torn
    assert durable.torn_text_problem(b'{"x":"\\u00ab') is None  # complete hex digits, then torn
    assert durable.torn_text_problem(b'{"a":12') is None  # ASCII digits, then torn


@pytest.mark.parametrize("store", ["ledger", "feed", "denials"])
@pytest.mark.parametrize("name, raw, needle", SELFGATE_SHAPES, ids=[s[0] for s in SELFGATE_SHAPES])
def test_the_five_self_gate_shapes_are_corruption_on_every_store(pair, store, name, raw, needle):
    node, obj, sname, verb, data = _sound_store(pair, store)
    damaged = data + raw
    obj.path.write_bytes(damaged)
    for read in (obj.torn_tail, obj.entries):
        with pytest.raises(IntegrityError) as e:
            read()
        assert e.value.reason == f"{sname}.corrupt" and needle in str(e.value), read.__name__
    assert main([*_argv(node), *verb]) == 2
    assert obj.path.read_bytes() == damaged


@pytest.mark.parametrize("store", ["ledger", "feed", "denials"])
def test_a_standing_intent_over_bytes_that_are_not_a_tear_is_refused_before_any_cut(pair, store):
    """Self-gate finding 3: a repair intent left by the pre-round classifier over
    `{"a":1}xyz` (its hash matching the bytes) is refused under the CURRENT prefix
    rule when the repair resumes — feed.repair.refused / denial.repair.refused
    (`Node._check_store_resume`), ledger.corrupt for the ledger (its tail stage
    judges the bytes through `chain_now`) — with the file byte-identical and the
    marker standing. Before, the feed and denial resumes verified only the
    retained prefix and the suffix hash, then cut."""
    node, obj, sname, verb, data = _sound_store(pair, store)
    suffix = b'{"a":1}xyz'
    obj.path.write_bytes(data + suffix)
    fname = {"ledger": "ledger.jsonl", "feed": "revocations.jsonl", "denial": "denials.jsonl"}[
        sname
    ]
    marker = node.state / f"{sname}-repair-pending.json"
    intent = {
        "step": "intent",
        "file": fname,
        "truncate_to": len(data),
        "bytes": len(suffix),
        "tail_sha256": "sha256:" + sha256_hex(suffix),
        "intent_id": new_id("rpr"),
        "ts": fmt(node.now()),
    }
    durable.write_json(marker, intent)
    before = marker.read_bytes()
    reports: list[str] = []
    node.report = reports.append
    with pytest.raises(IntegrityError) as e:
        {"ledger": node.repair_ledger, "feed": node.repair_feed, "denial": node.repair_denials}[
            sname
        ]()
    expected = "ledger.corrupt" if sname == "ledger" else f"{sname}.repair.refused"
    assert e.value.reason == expected, e.value
    assert "nothing truncated" in str(e.value) or "nothing cut" in str(e.value)
    assert obj.path.read_bytes() == data + suffix and marker.read_bytes() == before
    assert main([*_argv(node), *verb]) == 2
    assert obj.path.read_bytes() == data + suffix and marker.read_bytes() == before


def test_poll_with_an_empty_file_name_is_refused_before_the_node(pair, capsys, monkeypatch):
    """Self-gate finding 4: `poll --file ""` was read as no file and ran a live poll."""
    a, b, clock, reports = pair
    polls: list[int] = []
    monkeypatch.setattr(cli, "_node", lambda _a: polls.append(1))
    assert main([*_argv(a), "poll", "--file", ""]) == 1
    err = capsys.readouterr().err
    assert "--file must not be empty" in err and "Traceback" not in err and polls == []


@pytest.mark.parametrize(
    "argv",
    [
        [*_GRANT[:5], "--resource", "host:x:scratch/../seen.json", *_GRANT[7:]],
        [*_GRANT[:5], "--resource", "host:x:scratch/a b", *_GRANT[7:]],
        [*_SEND[:5], "--resource", "host:x:scratch/../seen.json", *_SEND[7:]],
    ],
    ids=["grant-dot-dot", "grant-space", "send-dot-dot"],
)
def test_an_explicit_scratch_resource_is_judged_by_the_name_rule_before_the_node(
    pair, capsys, monkeypatch, argv
):
    """Self-gate finding 5: `--resource host:…:scratch/../seen.json` passed the
    `host:` check and reached the node; the document check refused it after the
    startup sweep. The shared name rule now runs on an explicit scratch resource
    before the node, for grant and send alike."""
    a, b, clock, reports = pair

    def no_node(_a):
        raise AssertionError("the node was constructed before the value was judged")

    monkeypatch.setattr(cli, "_node", no_node)
    assert main([*_argv(a), *argv]) == 1
    err = capsys.readouterr().err
    assert "--resource: bad scratch name" in err and "Traceback" not in err, err


@pytest.mark.parametrize(
    "argv, needle",
    [
        ([*_SEND, "--grant", _GRT], "--grant names an id twice"),
        (
            [*_SEND[:-2], *sum([["--grant", grantmod.new_id("grt")] for _ in range(17)], [])],
            "--grant names 17 ids; at most 16",
        ),
        (
            [
                "revoke",
                "--statement",
                "s",
                *sum([["--grant", grantmod.new_id("grt")] for _ in range(257)], []),
            ],
            "revoke names 257 ids; at most 256",
        ),
        (
            ["revoke", "--statement", "s", "--grant", _GRT, "--grant", _GRT],
            "revoke names an id twice",
        ),
        (
            ["send", "--to", "b", "--info", "x" * (300 * 1024)],
            "--info is over 262144 bytes encoded",
        ),
        (["send", "--to", "b", "--info", "hi", "--param", "k=v"], "--info takes no --param"),
        (["send", "--to", "b", "--info", "hi", "--action", "fs.write"], "--info takes no --action"),
        (
            [*_SEND, "--param", "content=" + "x" * (300 * 1024)],
            "the action's body (--param) is over 262144 bytes encoded",
        ),
    ],
    ids=[
        "grant-twice",
        "seventeen-grants",
        "257-revoke-targets",
        "revoke-twice",
        "info-300kb",
        "info-with-param",
        "info-with-action",
        "param-300kb",
    ],
)
def test_aggregate_limits_and_incompatible_options_are_judged_before_the_node(
    pair, capsys, monkeypatch, argv, needle
):
    """Self-gate finding 6: a grant id twice, seventeen grant ids, 257 revocation
    targets, an oversized body, and options that belong to an action beside `--info`
    each reached the node's own refusal after the startup sweep."""
    a, b, clock, reports = pair

    def no_node(_a):
        raise AssertionError("the node was constructed before the value was judged")

    monkeypatch.setattr(cli, "_node", no_node)
    assert main([*_argv(a), *argv]) == 1
    err = capsys.readouterr().err
    assert needle in err and "Traceback" not in err, err[:300]


SHORTHAND_CHARS = [
    "a",
    "5",
    "_",
    "\u0301",
    "\u001c",
    "\u00a0",
    "\u0661",
    "é",
    " ",
    "\t",
    "\x0b",
    "-",
]
SHORTHAND_ASCII = {
    "d": set("0123456789"),
    "w": set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_"),
    "s": set(" \t\n\x0b\x0c\r"),
}


@pytest.mark.parametrize("letter", ["d", "D", "w", "W", "s", "S"])
def test_the_six_shorthands_mean_ascii_in_both_engines(letter):
    """Self-gate finding 7: as Unicode shorthands the compile-time `re` and the
    match-time `regex` disagreed (U+0301 under \\w, U+001C under \\S accepted at use,
    refused by the compile-time engine). The emission is an explicit ASCII class, so
    both engines and the production match path give one verdict for every probe."""
    pattern = "\\" + letter
    em = grantmod.emit_pattern(pattern)
    assert em == grantmod._SHORTHAND_CLASS[letter] and em.startswith("[")
    members = SHORTHAND_ASCII[letter.lower()]
    for ch in SHORTHAND_CHARS:
        expected = (ch in members) if letter.islower() else (ch not in members)
        assert (re.fullmatch(em, ch, re.DOTALL) is not None) is expected, (letter, ch)
        assert (regex.fullmatch(em, ch, flags=regex.DOTALL) is not None) is expected, (letter, ch)
        verdict = grantmod._value_ok(ch, {"regex": pattern})
        assert (verdict is None) is expected, (letter, ch, verdict)


def test_the_length_bound_is_the_parsers_own_named_refusal(pair):
    """Self-gate finding 8: `emit_pattern` accepted a 1025-character pattern and the
    document check refused it under a field name without a position; the bound is
    the parser's now, grant.constraint.pattern at every boundary."""
    a, b, clock, reports = pair
    why = grantmod.pattern_problem("|" * (grantmod.MAX_PATTERN + 1))
    assert (
        why == f"position {grantmod.MAX_PATTERN}: a pattern over {grantmod.MAX_PATTERN} characters"
    )
    assert grantmod.pattern_problem("|" * grantmod.MAX_PATTERN) is None
    with pytest.raises(ValueError) as e:
        a.issue_grant(
            subject_card=b.card,
            scope=fs_write_scope(b, "x.txt", regex="|" * (grantmod.MAX_PATTERN + 1)),
            principal_statement=STATEMENT,
        )
    assert "grant.constraint.pattern" in str(e.value) and "over 1024 characters" in str(e.value)


@pytest.mark.parametrize("spec", ["=regex:a", "content=regex", "content", "=", "content=:a"])
def test_a_malformed_param_spec_is_refused_before_the_node(pair, capsys, monkeypatch, spec):
    """Self-gate finding 9: `=regex:a` and `content=regex` were admitted."""
    a, b, clock, reports = pair

    def no_node(_a):
        raise AssertionError("the node was constructed before the value was judged")

    monkeypatch.setattr(cli, "_node", no_node)
    assert main([*_argv(a), *_GRANT, "--param", spec]) == 1
    err = capsys.readouterr().err
    assert f"bad --param {spec!r}: use key=regex:RE" in err and "Traceback" not in err, err


def test_the_readme_example_is_written_in_the_language():
    """Self-gate finding 10: the live-exchange example carried `\\n` and `{1,200}`."""
    readme = (PKG / "README.md").read_text(encoding="utf-8")
    assert "{1,200}" not in readme and "regex:^[ -~\\n]{" not in readme
    assert "$'content=regex:^[ -~\\n]+$'" in readme
    assert grantmod.pattern_problem("^[ -~\n]+$") is None


# ---- the round-20 self-gate, second run: six findings, fixed in-family ------------------------

GATE_CLASS_340 = "[" + "".join(chr(i) + "-" + chr(65535) for i in range(256, 596)) + "]"
# the gate's shape at the round-21 item bound: 256 overlapping ranges (one atom, 766
# characters); the 340-item form is refused by name at the 257th item (round 21)
GATE_CLASS = "[" + "".join(chr(i) + "-" + chr(65535) for i in range(256, 512)) + "]"
WIDE_CLASSES = {
    "gate-256-overlapping-ranges": GATE_CLASS,
    "64-bmp-ranges": "[\u0100-\uffff]" * 64,
    "64-negated-bmp-ranges": "[^\u0100-\uffff]" * 64,
    "64-astral-wide-ranges": "[\u0100-\U0010ffff]" * 64,
    "one-class-64-wide-disjoint": "["
    + "".join(chr(0x100 + 0x300 * i) + "-" + chr(0x100 + 0x300 * i + 0x200) for i in range(64))
    + "]",
    "256-disjoint-ranges": "["
    + "".join(chr(256 + 3 * i) + "-" + chr(257 + 3 * i) for i in range(256))
    + "]",
}


def test_overlapping_class_items_merge_at_emission():
    """Second run, finding 1: overlapping ranges are one range in the emission (256
    of them at the round-21 item bound; the 340-item shape is refused by name).
    Round 21 made the emission SORTED and merged over adjacent items too
    (`merge_spans`): `[ba]` is `[a-b]` and `[abc]` is `[a-c]`."""
    assert grantmod.emit_pattern(GATE_CLASS) == "[\u0100-\uffff]"
    assert "more than 256 items" in grantmod.pattern_problem(GATE_CLASS_340)
    assert grantmod.emit_pattern("[a-cb-d]") == "[a-d]"
    assert grantmod.emit_pattern("[aa]") == "[a]"
    assert grantmod.emit_pattern("[a-cc-e]") == "[a-e]"
    assert grantmod.emit_pattern("[x-za-cb-y]") == "[a-z]"
    assert grantmod.emit_pattern("[ba]") == "[a-b]"
    assert grantmod.emit_pattern("[abc]") == "[a-c]"
    assert grantmod.emit_pattern("[^a-cb-d]") == "[^a-d]"


@pytest.mark.parametrize("name", list(WIDE_CLASSES), ids=list(WIDE_CLASSES))
def test_wide_classes_compile_cold_within_the_budget(name):
    """Second run, finding 1: the compile-time engine is the `regex` package now (one
    engine for the document check and the match), and every wide-class shape —
    the gate's overlapping ranges at the item bound, sixty-four BMP or astral
    ranges in one pattern, sixty-four wide disjoint items in one class — compiles
    COLD (the cache purged) and matches 16 KB under 1 MB. The stdlib `re` walked
    every code point of a wide range: 0.5 s for the gate's shape, 3 s for
    sixty-four classes. The clock is pinned once, in round 21."""
    pattern = WIDE_CLASSES[name]
    assert len(pattern) <= grantmod.MAX_PATTERN and grantmod.pattern_problem(pattern) is None
    regex.purge()
    tracemalloc.start()
    grantmod._compile_pattern(pattern, "x")
    grantmod._value_ok("a" * 16384, {"regex": pattern})
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert peak < 1024 * 1024, (name, peak)


def test_the_document_check_compiles_with_the_engine_that_matches(monkeypatch):
    """Second run, finding 1: one engine — the `regex` compile records the emission
    and a stdlib `re` compile made to fail never runs."""
    calls: list[str] = []
    real = grantmod.regex.compile

    def record(p, *x, **k):
        calls.append(p)
        return real(p, *x, **k)

    def never(*_x, **_k):
        raise AssertionError("the stdlib compile ran")

    monkeypatch.setattr(grantmod.regex, "compile", record)
    monkeypatch.setattr(grantmod.re, "compile", never)
    grantmod._compile_pattern("[a-cb-d]+", "x")
    assert calls == ["[a-d]+"]


def test_the_fold_normalizes_after_the_case_fold(tmp_path):
    """Second run, finding 2: U+0390 and its uppercase spelling U+0399 U+0308 U+0301
    fold to canonically equivalent but different strings unless the fold is
    normalized again; the pair is one name to the checks, as siblings, one level
    down and one level up, through the node and through NATIVELY_SCRATCH."""
    lower, upper = "\u0390", "\u0399\u0308\u0301"
    assert keys._fold(lower) == keys._fold(upper)
    kd = tmp_path / "keys"
    keys.generate_all(kd)
    home = tmp_path / "home"
    pairs = (
        (home / lower, home / upper),
        (home / lower, home / upper / "sub"),
        (home / upper / "sub", home / lower),
    )
    for state, scratch in pairs:
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
    r = subprocess.run(
        [sys.executable, "-B", "-m", "natively", "keygen"],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert r.returncode == 1 and "count as one name" in r.stderr
    assert not (tmp_path / "keys2").exists() and not home.exists()


INTENT_SHAPES = [
    ("blank-suffix", b"   ", "a whitespace-only line"),
    ("terminated-then-nothing", b'{"x":\n', "more than one physical line"),
    ("newline-then-prefix", b'\n{"x":"', "more than one physical line"),
]


def _forge_intent(node, sname, to, suffix):
    marker = node.state / f"{sname}-repair-pending.json"
    durable.write_json(
        marker,
        {
            "step": "intent",
            "file": {"feed": "revocations.jsonl", "denial": "denials.jsonl"}[sname],
            "truncate_to": to,
            "bytes": len(suffix),
            "tail_sha256": "sha256:" + sha256_hex(suffix),
            "intent_id": new_id("rpr"),
            "ts": fmt(node.now()),
        },
    )
    return marker


@pytest.mark.parametrize("store", ["feed", "denials"])
@pytest.mark.parametrize("name, suffix, needle", INTENT_SHAPES, ids=[s[0] for s in INTENT_SHAPES])
def test_a_standing_intent_is_held_to_the_physical_line_rules_too(
    pair, store, name, suffix, needle
):
    """Second run, finding 3: a structurally valid intent whose recorded suffix is
    blank, or holds a physical newline, reached the cut although a fresh read
    refuses those bytes; the resume applies the fresh read's rules — one unterminated
    physical line, not blank, at a line boundary — before the prefix rule."""
    node, obj, sname, verb, data = _sound_store(pair, store)
    obj.path.write_bytes(data + suffix)
    marker = _forge_intent(node, sname, len(data), suffix)
    before = marker.read_bytes()
    with pytest.raises(IntegrityError) as e:
        {"feed": node.repair_feed, "denial": node.repair_denials}[sname]()
    assert e.value.reason == f"{sname}.repair.refused" and needle in str(e.value), e.value
    assert obj.path.read_bytes() == data + suffix and marker.read_bytes() == before
    assert main([*_argv(node), *verb]) == 2
    assert obj.path.read_bytes() == data + suffix and marker.read_bytes() == before


@pytest.mark.parametrize("store", ["feed", "denials"])
def test_a_standing_intent_whose_cut_point_is_inside_a_line_is_refused(pair, store):
    node, obj, sname, verb, data = _sound_store(pair, store)
    suffix = data[-3:] + b'{"x":"'  # the recorded suffix starts inside the last record
    obj.path.write_bytes(data + b'{"x":"')
    _forge_intent(node, sname, len(data) - 3, suffix)
    with pytest.raises(IntegrityError) as e:
        {"feed": node.repair_feed, "denial": node.repair_denials}[sname]()
    assert e.value.reason in (f"{sname}.corrupt", f"{sname}.repair.refused"), e.value
    assert obj.path.read_bytes() == data + b'{"x":"'


@pytest.mark.parametrize(
    "argv",
    [
        ["send", "--to", "b", "--info", "hi", "--out", ""],
        ["send", "--to", "b", "--info", "hi", "--dry-run", "--out", ""],
        ["ack", grantmod.new_id("msg"), "--out", ""],
        ["revoke", "--grant", _GRT, "--statement", "s", "--out", ""],
        ["poll", "--file", "/nonexistent/wire", "--out", ""],
    ],
    ids=["send", "send-dry-run", "ack", "revoke", "poll"],
)
def test_an_empty_out_file_is_refused_before_the_node_never_a_live_send(
    pair, capsys, monkeypatch, argv
):
    """Second run, finding 4: `--out ""` read as no file and chose the live wire."""
    a, b, clock, reports = pair

    def no_node(_a):
        raise AssertionError("the node was constructed before the value was judged")

    monkeypatch.setattr(cli, "_node", no_node)
    assert main([*_argv(a), *argv]) == 1
    err = capsys.readouterr().err
    assert "--out must not be empty" in err and "Traceback" not in err, err


def test_the_body_bound_is_the_decoded_json_byte_length(pair, capsys, monkeypatch):
    """Second run, finding 5: the preflight compared the base64 length, which admits
    bodies of 262,145 and 262,146 bytes; the JSON's UTF-8 length is the bound
    `message.verify` applies, so exactly 262,144 passes and one more byte refuses
    before the node — for `--info` and for an action's `@file` parameters."""
    a, b, clock, reports = pair
    frame = len(json.dumps({"type": "info", "text": ""}, ensure_ascii=False).encode())
    fits = "x" * (msgmod.MAX_BODY_BYTES - frame)
    body = {"type": "info", "text": fits}
    cli._body_within(body, "--info")
    assert len(json.dumps(body, ensure_ascii=False).encode()) == msgmod.MAX_BODY_BYTES
    with pytest.raises(cli.Usage):
        cli._body_within({"type": "info", "text": fits + "x"}, "--info")

    def no_node(_a):
        raise AssertionError("the node was constructed before the value was judged")

    monkeypatch.setattr(cli, "_node", no_node)
    assert main([*_argv(a), "send", "--to", "b", "--info", fits + "x"]) == 1
    assert "--info is over 262144 bytes" in capsys.readouterr().err
    parts = [a.state.parent / f"p{i}.txt" for i in range(4)]
    for p in parts:
        p.write_text("y" * 65536, encoding="utf-8")
    argv = [*_SEND, *sum([["--param", f"k{i}=@{p}"] for i, p in enumerate(parts)], [])]
    assert main([*_argv(a), *argv]) == 1
    assert "the action's body (--param) is over 262144 bytes" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv, needle",
    [
        (["send", "--to", "b", "--info", "hi", "--action", ""], "--info takes no --action"),
        (["send", "--to", "b", "--info", "hi", "--file", ""], "--info takes no --file"),
        (["send", "--to", "b", "--info", "hi", "--resource", ""], "--info takes no --resource"),
        (["send", "--card", "--param", "broken"], "--card takes no --param"),
        (["send", "--card", "--file", "../seen.json"], "--card takes no --file"),
        (["send", "--card", "--to", "b"], "--card takes no --to"),
        (["send", "--card", "--info", "hi"], "--card takes no --info"),
    ],
    ids=[
        "info-empty-action",
        "info-empty-file",
        "info-empty-resource",
        "card-param",
        "card-file",
        "card-to",
        "card-info",
    ],
)
def test_an_option_of_another_mode_is_refused_even_when_empty(
    pair, capsys, monkeypatch, argv, needle
):
    """Second run, finding 6: an empty `--action` beside `--info`, and any option
    beside `--card`, were ignored and reached the node."""
    a, b, clock, reports = pair

    def no_node(_a):
        raise AssertionError("the node was constructed before the value was judged")

    monkeypatch.setattr(cli, "_node", no_node)
    assert main([*_argv(a), *argv]) == 1
    err = capsys.readouterr().err
    assert needle in err and "Traceback" not in err, err

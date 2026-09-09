"""Grant envelope (spec section 3), plus the two citadel extensions behind flags:
`max_uses_per_window` {n, window_s} beside max_uses (reply 3). The standing denial
lives in denial.py and is checked by the node before scope.

Verification split: `check_document` is what is true or false of the grant DOCUMENT
ITSELF, with no clock and no policy — the structure with every field of its type
(every signature and key field a string of its encoding and length; ids, hashes,
timestamps, scope entries, params and constraints of their shapes), the signature
verifying under the issuer key the grant names, and for a delegation the embedded
parent's structure and signature likewise. `verify` adds what this node judges: the
rooting in the pinned principals, a delegation's chain (depth one, the parent rooted,
the child issued by the parent's subject agent) and what it claims against its parent
(audience equal, window and budgets inside the parent's, scope a strict subset), the
time window, the subject/card binding, the audience, capabilities-of-card.
`authenticate` is what a node runs before it stores a grant it merely carries (the
document + the rooting + the chain, no time, binding or bounds). A grant ON FILE was
authenticated (or issued here) before it was stored, so it is read through
`check_document` on every load (state.read_grant): a document whose signatures hold is
exactly the document that was signed, so anything about it that no longer holds is
local corruption, never a refusal at use; what this node judges about a sound document
— the rooting, the delegation chain and bounds, the time window, revocation, use
counts, the extension flags — stays a refusal. Use counts, revocation, and denial are
the node's job because they need the ledger and the feeds.

Key-list semantics (fail closed): `params.keys` is the complete list of parameter
names a request may carry; `[]` means NO parameters, both when a request is matched
and in the delegation subset algebra. A `regex` constraint is written in the
CONSTRAINT LANGUAGE below (`emit_pattern`): a small language with its own complete
parser, re-emitted in canonical syntax both engines read alike — what compiles is
exactly what was parsed, never the raw input. The document check compiles the
emission and the match at use runs it through ONE engine, the `regex` package (a
match timeout, and a compile that costs microseconds for every accepted shape where
the stdlib `re` costs 0.1 s per wide non-ASCII class; a timeout is a refusal, never
a hang)."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

import regex

from . import card as cardmod
from . import keys
from .canon import canonicalize
from .errors import RefusedError, VerifyError
from .executor import MAX_CONTENT, scratch_name_of, scratch_name_problem
from .objects import (
    check_sig,
    new_id,
    require,
    require_hash,
    require_id,
    require_key,
    require_sig,
    require_str,
    signed,
)
from .timeutil import parse

_TOP = (
    "grant_id",
    "issuer",
    "subject",
    "audience",
    "scope",
    "principal_statement",
    "max_uses",
    "not_before",
    "issued_at",
    "expires_at",
    "revocation",
    "parent_grant",
)
_EXT = ("max_uses_per_window",)
_SCOPE = ("action", "resource", "params", "offline_ok", "max_offline_s")
_CONSTRAINTS = ("in", "range", "regex")
MAX_STATEMENT = 4000
MAX_PATTERN = 1024
# ---- the constraint language ------------------------------------------------------
# A `regex` constraint is a pattern in a SMALL LANGUAGE with a complete parser of its
# own (`emit_pattern`), not a whitelist over the engine's grammar: five reviews in a
# row defeated the hand scanner over the `regex` module's syntax (verbose mode and
# comments, branch reset, conditionals, the fuzzy brace, a brace after a plain
# escape, global flags, POSIX classes, the \p \P \N brace argument, the [. .] and
# [= =] class forms — round-19 gate R2, R3), and a grammar the scanner does not own
# will lose again. The language: alternation `|` at any level; plain groups `( ... )`
# only, never a `(?` form; atoms = a literal character, an escaped punctuation
# character from ESCAPABLE, one of the six class escapes \d \D \w \W \s \S (ASCII by
# definition, emitted as explicit classes: _SHORTHAND_CLASS), `.`, or a
# bracket class `[...]` of literal characters, ranges `x-y` and the escapes \] \\ \^
# \- with an optional leading `^`; the anchors `^` and `$`. A quantifier `*` `+` `?`
# applies ONLY to a single atom, never to a group, never to an anchor, never stacked.
# NO counted quantifiers {n} {n,m}, NO lazy or possessive modifiers, NO group
# modifiers, NO backreferences, NO POSIX classes, NO \p \P \N, NO \x \u \U, NO bare
# brace. At most MAX_ATOMS atoms, MAX_GROUP_DEPTH nested groups (the parser is
# recursive; a depth bound keeps it from the interpreter's recursion limit) and
# MAX_CLASS_ITEMS items per bracket class (its items are sorted and merged into the
# canonical span list, `merge_spans`: linearithmic) within MAX_PATTERN characters.
# Every refusal names the offending position.
MAX_ATOMS = 64
MAX_GROUP_DEPTH = 32
# items per bracket class (an item = a literal, an escape or a range: a CJK range is
# ONE item); past it the parser refuses at the offending item, so the merge below never
# runs over more than this many spans (round-20 gate, finding 1; D5 tightened)
MAX_CLASS_ITEMS = 256
# the punctuation an escape may name outside a class (its literal), and the class
# escapes; the six shorthand class escapes; the metacharacters a literal may not be
ESCAPABLE = frozenset(".*+?()[]{}|^$\\-/")
CLASS_ESCAPES = frozenset("]\\^-")
SHORTHANDS = frozenset("dDwWsS")
# the six shorthands are ASCII BY DEFINITION and emitted as explicit classes, so the
# emission means one thing to any engine that reads it (the `regex` package compiles
# and matches it; the test suite's oracle reads it through the stdlib `re` too) — as
# Unicode shorthands two engines disagreed (U+0301 under \w, U+001C under \S: accepted
# at use, refused by the compile-time engine; round-20 self-gate, finding 7)
_SHORTHAND_CLASS = {
    "d": "[0-9]",
    "D": "[^0-9]",
    "w": "[0-9A-Za-z_]",
    "W": "[^0-9A-Za-z_]",
    "s": "[\\t\\n\\x0b\\x0c\\r ]",
    "S": "[^\\t\\n\\x0b\\x0c\\r ]",
}
_META = frozenset("\\()[]{}|^$*+?.")
_QUANTIFIERS = frozenset("*+?")
MAX_PARAM_BYTES = MAX_CONTENT  # a value is capped at the executor's limit BEFORE any match
REGEX_TIMEOUT_S = 2.0
MAX_SCOPE = 64
# a grant's STRUCTURE is one thing whatever a node's flags say: the extension policy
# (a grant carrying a field behind a flag that is off) is `verify`'s refusal at use,
# never a structure verdict on a document read from this node's own files
ANY_EXTENSION = {"max_uses_per_window": True}


def build(
    *,
    issuer: dict[str, str],
    subject: dict[str, str],
    audience_executor: str,
    scope: list[dict[str, Any]],
    principal_statement: str,
    issued_at: str,
    expires_at: str,
    not_before: str | None = None,
    max_uses: int = 1,
    revocation_ledger: str = "",
    max_check_interval_s: int = 300,
    parent_grant: dict[str, Any] | None = None,
    max_uses_per_window: dict[str, int] | None = None,
) -> dict[str, Any]:
    g: dict[str, Any] = {
        "grant_id": new_id("grt"),
        "issuer": dict(issuer),
        "subject": dict(subject),
        "audience": {"executor": audience_executor},
        "scope": [scope_entry(**s) for s in scope],
        "principal_statement": principal_statement,
        "max_uses": max_uses,
        "not_before": not_before or issued_at,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "revocation": {"ledger": revocation_ledger, "max_check_interval_s": max_check_interval_s},
        "parent_grant": parent_grant,
    }
    if max_uses_per_window is not None:
        g["max_uses_per_window"] = {
            "n": int(max_uses_per_window["n"]),
            "window_s": int(max_uses_per_window["window_s"]),
        }
    return g


def scope_entry(
    action: str,
    resource: str,
    params: dict[str, Any] | None = None,
    offline_ok: bool = False,
    max_offline_s: int = 0,
) -> dict[str, Any]:
    return {
        "action": action,
        "resource": resource,
        "params": params or {"keys": [], "values": {}},
        "offline_ok": bool(offline_ok),
        "max_offline_s": int(max_offline_s),
    }


def sign(g: dict[str, Any], kp: keys.KeyPair) -> dict[str, Any]:
    if kp.public != g["issuer"]["key"]:
        raise ValueError("signing key does not match grant.issuer.key")
    return signed(g, kp)


# ---- structure ------------------------------------------------------------------


class PatternProblem(ValueError):
    """A pattern outside the constraint language: `position` (0-based, into the
    pattern) and `why`. `str()` reads `position N: why`."""

    def __init__(self, position: int, why: str):
        self.position, self.why = position, why
        super().__init__(f"position {position}: {why}")


class _PatternParser:
    """The recursive-descent parser of the constraint language (the grammar in the
    module comment above). `parse` returns the canonical re-emission — every literal
    through `re.escape`, so the emission is plain, warning-free regular-expression
    syntax the `regex` package (the one engine) reads as the parser meant it — or
    raises PatternProblem at the offending position. Nothing that is not in the
    grammar is passed to any engine."""

    def __init__(self, pat: str):
        self.s, self.i, self.n = pat, 0, len(pat)
        self.atoms = 0
        self.depth = 0

    def fail(self, why: str, at: int | None = None) -> None:
        raise PatternProblem(self.i if at is None else at, why)

    def peek(self) -> str:
        return self.s[self.i] if self.i < self.n else ""

    def parse(self) -> str:
        if self.n > MAX_PATTERN:
            # the length bound is the parser's own, named like every other refusal
            self.fail(f"a pattern over {MAX_PATTERN} characters", MAX_PATTERN)
        out = self.alternation()
        if self.i < self.n:  # only a ')' stops `alternation` short of the end
            self.fail("an unmatched ')'")
        return out

    def alternation(self) -> str:
        branches = [self.sequence()]
        while self.peek() == "|":
            self.i += 1
            branches.append(self.sequence())
        return "|".join(branches)

    def sequence(self) -> str:
        parts: list[str] = []
        while self.i < self.n and self.s[self.i] not in "|)":
            parts.append(self.piece())
        return "".join(parts)

    def piece(self) -> str:
        ch, start = self.s[self.i], self.i
        if ch == "(":
            self.i += 1
            if self.peek() == "?":
                self.fail(
                    "a '(?' group construct is outside the constraint language (plain groups "
                    "only: no non-capturing, lookaround, atomic, named, flag, conditional, "
                    "comment, branch-reset or subroutine form)"
                )
            self.depth += 1
            if self.depth > MAX_GROUP_DEPTH:
                self.fail(f"groups nested more than {MAX_GROUP_DEPTH} deep", start)
            inner = self.alternation()
            if self.peek() != ")":
                self.fail("an unterminated group", start)
            self.i += 1
            self.depth -= 1
            self.no_quantifier("a group (a quantifier applies to a single atom only)")
            return "(" + inner + ")"
        if ch in "^$":
            self.i += 1
            self.no_quantifier("an anchor")
            return ch
        if ch in _QUANTIFIERS:
            self.fail(f"a quantifier {ch!r} with nothing before it")
        if ch in "{}":
            self.fail(
                "a bare brace: counted quantifiers {n} {n,m} are outside the constraint "
                "language (escape a literal brace: \\{ \\})"
            )
        if ch == "]":
            self.fail("a bare ']' (escape it: \\])")
        atom = self.atom()
        self.atoms += 1
        if self.atoms > MAX_ATOMS:
            self.fail(f"more than {MAX_ATOMS} atoms", start)
        return atom + self.quantifier()

    def quantifier(self) -> str:
        q = self.peek()
        if q not in _QUANTIFIERS or not q:
            return ""
        self.i += 1
        nxt = self.peek()
        if nxt in _QUANTIFIERS and nxt:
            self.fail(
                f"a quantifier on a quantifier ({q}{nxt}: no lazy, possessive or stacked "
                f"quantifiers)"
            )
        if nxt == "{":
            self.fail("a counted quantifier after a quantifier")
        return q

    def no_quantifier(self, what: str) -> None:
        nxt = self.peek()
        if nxt and nxt in "*+?{":
            self.fail(f"a quantifier on {what}")

    def atom(self) -> str:
        ch = self.s[self.i]
        if ch == "\\":
            if self.i + 1 >= self.n:
                self.fail("a trailing backslash")
            e = self.s[self.i + 1]
            self.i += 2
            if e in ESCAPABLE:
                return re.escape(e)
            if e in SHORTHANDS:
                return _SHORTHAND_CLASS[e]
            self.fail(
                f"the escape '\\{e}' is outside the constraint language (an escape names "
                f"one of . * + ? ( ) [ ] {{ }} | ^ $ \\ - / or one of \\d \\D \\w \\W \\s \\S)",
                self.i - 2,
            )
        if ch == ".":
            self.i += 1
            return "."
        if ch == "[":
            return self.bracket_class()
        self.i += 1
        return re.escape(ch)

    def bracket_class(self) -> str:
        start = self.i
        self.i += 1
        neg = ""
        if self.peek() == "^":
            neg = "^"
            self.i += 1
        items: list[tuple[int, int]] = []  # (lo, hi) code points, as written
        while True:
            if self.i >= self.n:
                self.fail("an unterminated character class", start)
            if self.s[self.i] == "]":
                if not items:
                    self.fail("an empty character class", start)
                self.i += 1
                break
            item_start = self.i
            lo = self.class_char()
            if self.peek() == "-":
                if self.i + 1 < self.n and self.s[self.i + 1] == "]":
                    self.fail("a bare '-' at the end of a class (escape it: \\-)")
                self.i += 1
                if self.i >= self.n:
                    # a range cut off at the end of the pattern: refused by name, never
                    # an IndexError out of the parser (the round-20 fuzz's first find)
                    self.fail("an unterminated character class", start)
                hi = self.class_char()
                if ord(hi) < ord(lo):
                    self.fail(f"a range out of order ({lo!r}-{hi!r})", self.i - 1)
                items.append((ord(lo), ord(hi)))
            else:
                items.append((ord(lo), ord(lo)))
            if len(items) > MAX_CLASS_ITEMS:
                # the item bound, at the offending item's position like every other
                # bound (round-20 gate, finding 1: 1,022 singleton items were legal and
                # cost a quadratic merge before the signature check)
                self.fail(
                    f"more than {MAX_CLASS_ITEMS} items in a character class (an item is a "
                    f"literal, an escape or a range)",
                    item_start,
                )
        spans = merge_spans(items)
        parts = [
            re.escape(chr(lo)) if lo == hi else re.escape(chr(lo)) + "-" + re.escape(chr(hi))
            for lo, hi in spans
        ]
        return "[" + neg + "".join(parts) + "]"

    def class_char(self) -> str:
        if self.i >= self.n:
            self.fail("an unterminated character class")
        ch = self.s[self.i]
        if ch == "\\":
            if self.i + 1 >= self.n:
                self.fail("a trailing backslash inside a character class")
            e = self.s[self.i + 1]
            if e not in CLASS_ESCAPES:
                self.fail(
                    f"the escape '\\{e}' inside a character class is outside the constraint "
                    f"language (the class escapes are \\] \\\\ \\^ \\-)"
                )
            self.i += 2
            return e
        if ch == "[":
            self.fail("a bracket inside a character class (no nested or POSIX classes)")
        if ch == "^":
            self.fail("a bare '^' inside a character class (escape it: \\^)")
        if ch == "-":
            self.fail("a bare '-' inside a character class (escape it: \\-)")
        self.i += 1
        return ch


class _SpanKey:
    """The sort key of a class item: ordered by its low end, then its high end. Every
    comparison the merge makes goes through here, counted in `class_comparisons`, so
    a test pins the WORK of the merge (linearithmic in the item count), not a clock
    (round-20 gate, finding 1: the 50 ms budget failed in the gate's sandbox while
    the quadratic scan was the real fault)."""

    __slots__ = ("lo", "hi")

    def __init__(self, item: tuple[int, int]):
        self.lo, self.hi = item

    def __lt__(self, other: _SpanKey) -> bool:
        global class_comparisons
        class_comparisons += 1
        if self.lo != other.lo:
            return self.lo < other.lo
        class_comparisons += 1  # the high ends compared too, counted too
        return self.hi < other.hi


class_comparisons = 0  # interval comparisons made by `merge_spans` since import (a test reads it)


def merge_spans(items: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """The items of a bracket class as the class's CANONICAL span list: sorted by
    their low end, then merged in one pass — an item that overlaps the span before
    it (a code point they share) or is ADJACENT to it (its low end one past the
    span's high end) extends that span. O(n log n) in the item count, and the
    emission is deterministic whatever order the items were written in: `[ba]`,
    `[ab]` and `[a-ab]` all emit `[a-b]`, and 256 overlapping ranges emit one range
    (round-20 self-gate, second run, finding 1; the gate's finding 1 on the
    quadratic scan that preceded this)."""
    global class_comparisons
    ordered = sorted(items, key=_SpanKey)
    out: list[tuple[int, int]] = []
    for lo, hi in ordered:
        class_comparisons += 1
        if out and lo <= out[-1][1] + 1:
            if hi > out[-1][1]:
                out[-1] = (out[-1][0], hi)
            continue
        out.append((lo, hi))
    return out


def emit_pattern(pat: str) -> str:
    """The canonical re-emission of a constraint pattern, or PatternProblem naming the
    position and why. The ONE reading of a pattern: the document check compiles the
    emission (never the raw input) and the match runs the emission."""
    return _PatternParser(pat).parse()


def pattern_problem(pat: str) -> str | None:
    """Why `pat` is outside the constraint language (`position N: why`), or None."""
    try:
        emit_pattern(pat)
    except PatternProblem as e:
        return str(e)
    return None


def _check_constraint(c: Any, where: str, *, compile_patterns: bool = True) -> None:
    require(c, where, (), _CONSTRAINTS)
    if not c:
        raise VerifyError(f"{where}.empty", "a value constraint must name in/range/regex")
    if "in" in c and not isinstance(c["in"], list):
        raise VerifyError(f"{where}.in", "'in' must be a list")
    if "range" in c:
        r = c["range"]
        if (
            not isinstance(r, list)
            or len(r) != 2
            or not all(
                x is None or (isinstance(x, int | float) and not isinstance(x, bool)) for x in r
            )
        ):
            raise VerifyError(f"{where}.range", "'range' must be [lo, hi] (numbers or null)")
    if "regex" in c:
        if not isinstance(c["regex"], str):
            raise VerifyError(f"{where}.regex", "'regex' must be a string")
        # the language is a STRUCTURE verdict, before the signature and before any
        # compile: a linear parse, and nothing outside the language reaches an engine
        # at receive or at a fresh process's load (a fifteen-character pattern cost
        # seconds and gigabytes before)
        why = pattern_problem(c["regex"])
        if why is not None:
            raise VerifyError("grant.constraint.pattern", f"{where}: {why}")
        if compile_patterns:
            _compile_pattern(c["regex"], where)


def _compile_pattern(pat: str, where: str) -> None:
    """The compile of the pattern's EMISSION (what the parser read, never the raw
    input; a pattern outside the language is refused by name first) by the ONE
    engine that runs the match at use, the `regex` package: it compiles every
    accepted shape in microseconds, where the stdlib `re` walks every code point of
    a non-ASCII range (about 0.1 s per class, 3 s for sixty-four `[\u0100-\uffff]`
    classes in one pattern — round-20 self-gate, second run, finding 1), and its
    cache holds only what compiled, which is only what the language accepts. A
    pattern the engine cannot compile is a structure verdict (VerifyError), never an
    exception that escapes to be taken for malformed peer input at receipt or for a
    crash at a load of ours — unreachable for an emission, kept as the guard."""
    try:
        em = emit_pattern(pat)
    except PatternProblem as e:
        raise VerifyError("grant.constraint.pattern", f"{where}: {e}") from e
    try:
        regex.compile(em, regex.DOTALL)
    except (regex.error, RecursionError, OverflowError, ValueError, TypeError) as e:
        raise VerifyError(f"{where}.regex", f"bad regex: {type(e).__name__}: {e}") from e


def compile_patterns(g: dict[str, Any]) -> None:
    """Every constraint pattern of `g` compiled by the `regex` engine from its emission:
    the one step of the document check that costs more than a parse, so
    `check_document` runs it AFTER the signatures verify — a garbage-signed grant
    from the wire is refused by its signature before any pattern compiles (round-19
    Fable read, finding 1)."""
    for i, s in enumerate(g["scope"]):
        for k, c in s["params"]["values"].items():
            if "regex" in c:
                _compile_pattern(c["regex"], f"grant.scope[{i}].params.values.{k}")


def check_structure(
    g: Any, *, extensions: dict[str, bool] | None = None, compile_patterns: bool = True
) -> None:
    """The grant's structure in full: every field present and of its type — the
    signature a base64 string of 64 bytes, every key field a key that decodes, the
    ids, hashes, timestamps, scope entries, params and constraints of their shapes
    (a constraint pattern within the bounded grammar, `pattern_problem`). Whether
    the signature VERIFIES is `check_document`'s; a parent embedded under
    parent_grant is checked by its own call (an object or null here). With
    `compile_patterns` false the engine is not run on the patterns here (the
    document check compiles them after the signatures)."""
    ext = extensions or {}
    require(g, "grant", _TOP + ("sig",), _EXT)
    require_id(g, "grant_id", "grant", "grt_")
    require_sig(g, "grant")
    require(g["issuer"], "grant.issuer", ("key",), ("principal", "agent"))
    require_key(g["issuer"], "key", "grant.issuer")
    if ("principal" in g["issuer"]) == ("agent" in g["issuer"]):
        raise VerifyError("grant.issuer.format", "issuer names exactly one of principal/agent")
    if "principal" in g["issuer"]:
        require_str(g["issuer"], "principal", "grant.issuer")
    else:
        require_hash(g["issuer"], "agent", "grant.issuer")
    require(g["subject"], "grant.subject", ("agent", "key"))
    require_hash(g["subject"], "agent", "grant.subject")
    require_key(g["subject"], "key", "grant.subject")
    require(g["audience"], "grant.audience", ("executor",))
    require_key(g["audience"], "executor", "grant.audience")
    if not isinstance(g["scope"], list) or not g["scope"] or len(g["scope"]) > MAX_SCOPE:
        raise VerifyError("grant.scope.format", f"scope must be a list of 1..{MAX_SCOPE} entries")
    for i, s in enumerate(g["scope"]):
        w = f"grant.scope[{i}]"
        require(s, w, _SCOPE)
        require_str(s, "action", w)
        require_str(s, "resource", w, "host:")
        # a scratch resource names a file the executor's own rule admits: a grant
        # naming `scratch/../seen.json` or `scratch/a b` is refused by name at issue,
        # at receive and at load (state.corrupt), never signed and stored to be
        # refused at every use (round-19 Fable read, C2)
        name = scratch_name_of(s["resource"])
        if name is not None:
            why = scratch_name_problem(name)
            if why is not None:
                raise VerifyError("grant.resource.name", f"{w}.resource: {why}")
        require(s["params"], f"{w}.params", ("keys", "values"))
        if not isinstance(s["params"]["keys"], list) or not all(
            isinstance(k, str) for k in s["params"]["keys"]
        ):
            raise VerifyError(f"{w}.params.keys", "keys must be a list of strings")
        if not isinstance(s["params"]["values"], dict):
            raise VerifyError(f"{w}.params.values", "values must be an object")
        for k, c in s["params"]["values"].items():
            if k not in s["params"]["keys"]:
                raise VerifyError(f"{w}.params.values", f"constrained key {k!r} not in keys")
            _check_constraint(c, f"{w}.params.values.{k}", compile_patterns=compile_patterns)
        if not isinstance(s["offline_ok"], bool):
            raise VerifyError(f"{w}.offline_ok", "must be boolean")
        if not isinstance(s["max_offline_s"], int) or isinstance(s["max_offline_s"], bool):
            raise VerifyError(f"{w}.max_offline_s", "must be an integer")
        if s["offline_ok"] and s["action"] != "info":
            raise VerifyError(f"{w}.offline_ok", "offline tolerance only for read/report scopes")
    stmt = require_str(g, "principal_statement", "grant")
    if len(stmt) > MAX_STATEMENT:
        raise VerifyError("grant.principal_statement.length", f"over {MAX_STATEMENT} chars")
    if not isinstance(g["max_uses"], int) or isinstance(g["max_uses"], bool) or g["max_uses"] < 1:
        raise VerifyError("grant.max_uses", "must be an integer >= 1")
    for f in ("not_before", "issued_at", "expires_at"):
        parse(require_str(g, f, "grant"), f"grant.{f}")
    require(g["revocation"], "grant.revocation", ("ledger", "max_check_interval_s"))
    if not isinstance(g["revocation"]["ledger"], str):
        raise VerifyError("grant.revocation.ledger", "must be a string")
    mci = g["revocation"]["max_check_interval_s"]
    if not isinstance(mci, int) or isinstance(mci, bool) or mci < 0:
        raise VerifyError("grant.revocation.max_check_interval_s", "must be an integer >= 0")
    if g["parent_grant"] is not None and not isinstance(g["parent_grant"], dict):
        raise VerifyError("grant.parent_grant.format", "parent_grant must be an object or null")
    if "max_uses_per_window" in g:
        if not ext.get("max_uses_per_window"):
            raise VerifyError(
                "grant.extension.disabled",
                "grant carries max_uses_per_window but the extension is off on this node",
            )
        w = g["max_uses_per_window"]
        require(w, "grant.max_uses_per_window", ("n", "window_s"))
        for k in ("n", "window_s"):
            if not isinstance(w[k], int) or isinstance(w[k], bool) or w[k] < 1:
                raise VerifyError(f"grant.max_uses_per_window.{k}", "must be an integer >= 1")


# ---- verification ---------------------------------------------------------------


def check_document(g: Any, *, extensions: dict[str, bool] | None = None) -> None:
    """What holds or fails on the grant DOCUMENT ITSELF, no clock and no policy: the
    structure with every field of its type (`check_structure`), the signature
    verifying under the issuer key the grant names — a root grant's issuer naming a
    principal — and, for a delegation, the embedded parent's structure and its
    signature under the issuer key IT names. A document whose signatures hold is
    exactly the document that was signed; whatever this node then judges about it
    — the rooting in the pinned principals, the delegation chain and bounds, the
    time window, the subject binding, revocation, use counts, the extension flags —
    is `verify`'s and the node's, a refusal.

    A grant ON FILE is read through this on every load (state.read_grant): it was
    authenticated before it was stored, so a failure here is local corruption of the
    file, never a refusal of the message that names it.

    Order: the structure of the grant and of its embedded parent (the pattern
    grammar bounded, nothing compiled), then the signatures, then the engine's
    compile of every constraint pattern (`compile_patterns`) — nothing from the
    wire costs more than a scan before its signature is verified."""
    check_structure(g, extensions=extensions, compile_patterns=False)
    parent = g["parent_grant"]
    if parent is None:
        if "principal" not in g["issuer"]:
            raise VerifyError(
                "grant.issuer.not_principal", "a root grant must be issued by a principal"
            )
        check_sig(g, g["issuer"]["key"], "grant")
        compile_patterns(g)
        return
    check_structure(parent, extensions=extensions, compile_patterns=False)
    check_sig(parent, parent["issuer"]["key"], "grant.parent_grant")
    check_sig(g, g["issuer"]["key"], "grant")
    compile_patterns(parent)
    compile_patterns(g)


def _check_root(g: dict[str, Any], *, pinned: set[str]) -> None:
    """A root grant's rooting in THIS node's pinned principals: policy — a refusal
    at receipt and at use, never a verdict on a document."""
    if g["issuer"]["key"] not in pinned:
        raise VerifyError(
            "grant.issuer.unpinned", f"issuer {g['issuer']['key']} is not a pinned principal root"
        )


def _check_chain(g: dict[str, Any], parent: dict[str, Any], *, pinned: set[str]) -> None:
    """A depth-one delegation's chain (both documents already checked): the parent
    rooted in a pinned principal, the child issued by the parent's subject agent.
    Policy at receipt and at use — a refusal, never a verdict on a file of ours."""
    if parent["parent_grant"] is not None:
        raise VerifyError("grant.delegation.depth", "delegation is depth one; parent has a parent")
    if "principal" not in parent["issuer"] or parent["issuer"]["key"] not in pinned:
        raise VerifyError(
            "grant.delegation.root", "parent is not rooted in a pinned principal signature"
        )
    if "agent" not in g["issuer"] or g["issuer"]["key"] != parent["subject"]["key"]:
        raise VerifyError(
            "grant.delegation.issuer",
            "delegated grant must be issued by the parent's subject agent",
        )
    if g["issuer"]["agent"] != parent["subject"]["agent"]:
        raise VerifyError(
            "grant.delegation.issuer", "issuer.agent must be the parent's subject card hash"
        )


def _check_delegation_bounds(g: dict[str, Any], parent: dict[str, Any], *, now: datetime) -> None:
    """What a delegation may claim against its parent, judged at use: the audience
    equal, the window inside the parent's, the budgets no larger, the check
    interval no longer, the parent not expired, the scope a strict subset."""
    if g["audience"] != parent["audience"]:
        raise VerifyError("grant.delegation.audience", "delegated audience must equal the parent's")
    if parse(g["expires_at"]) > parse(parent["expires_at"]):
        raise VerifyError("grant.delegation.expiry", "delegated grant outlives its parent")
    if parse(g["not_before"]) < parse(parent["not_before"]):
        raise VerifyError("grant.delegation.not_before", "delegated grant starts before its parent")
    if g["max_uses"] > parent["max_uses"]:
        raise VerifyError("grant.delegation.max_uses", "delegated max_uses exceeds the parent's")
    pw, cw = parent.get("max_uses_per_window"), g.get("max_uses_per_window")
    if pw is not None and (cw is None or cw["n"] > pw["n"] or cw["window_s"] < pw["window_s"]):
        raise VerifyError(
            "grant.delegation.max_uses_per_window",
            "a delegated grant inherits the parent's max_uses_per_window (n no larger, "
            "window no shorter)",
        )
    if g["revocation"]["max_check_interval_s"] > parent["revocation"]["max_check_interval_s"]:
        raise VerifyError(
            "grant.delegation.max_check_interval",
            "delegated max_check_interval_s exceeds the parent's",
        )
    if now >= parse(parent["expires_at"]):
        raise VerifyError("grant.delegation.parent_expired", "parent grant has expired")
    if not is_strict_subset(g["scope"], parent["scope"]):
        raise VerifyError(
            "grant.delegation.not_subset", "delegated scope is not a strict subset of the parent's"
        )


def verify(
    g: Any,
    *,
    now: datetime,
    subject_card: dict[str, Any],
    executor_keys: set[str],
    pinned: set[str],
    extensions: dict[str, bool] | None = None,
) -> None:
    """Full stateless verification of a grant presented to this executor: the
    document (`check_document`), then the rooting (a delegation: its chain and what
    it claims against its parent), then the binding to this card, this executor and
    the moment."""
    check_document(g, extensions=extensions)
    parent = g["parent_grant"]
    if parent is None:
        _check_root(g, pinned=pinned)
    else:
        _check_chain(g, parent, pinned=pinned)
        _check_delegation_bounds(g, parent, now=now)
    _check_binding(g, now=now, subject_card=subject_card, executor_keys=executor_keys)


def check_time(g: dict[str, Any], *, now: datetime) -> None:
    """The time window ALONE, for a recheck with a freshly read clock after every slow
    step (`Node._grant_valid_now`): the grant's not_before and expiry, and its
    parent's expiry. No file, no key, no compile — nothing between the reading of
    `now` and the verdict. `verify` reads its `now` before the card, the pins, the
    config and the feed are read, so a clock that moved during those reads was
    judged at the earlier reading (round-19 self-gate, second run)."""
    nb = parse(g["not_before"], "grant.not_before")
    exp = parse(g["expires_at"], "grant.expires_at")
    if now < nb:
        raise VerifyError("grant.not_yet_valid", f"not_before {g['not_before']} is in the future")
    if now >= exp:
        raise VerifyError("grant.expired", f"expired at {g['expires_at']}")
    parent = g["parent_grant"]
    if parent is not None and now >= parse(parent["expires_at"], "grant.parent_grant.expires_at"):
        raise VerifyError(
            "grant.delegation.parent_expired", f"parent expired at {parent['expires_at']}"
        )


def authenticate(g: Any, *, pinned: set[str], extensions: dict[str, bool] | None = None) -> None:
    """The document + the rooting (a delegation: its chain), for a grant this node
    stores but is not (yet) asked to execute: a root grant signed by a pinned
    principal, or a delegation whose parent is. No time window, no subject binding,
    no delegation bounds (those are `verify`, at use)."""
    check_document(g, extensions=extensions)
    parent = g["parent_grant"]
    if parent is None:
        _check_root(g, pinned=pinned)
    else:
        _check_chain(g, parent, pinned=pinned)


def _check_binding(
    g: dict[str, Any], *, now: datetime, subject_card: dict[str, Any], executor_keys: set[str]
) -> None:
    ch = cardmod.card_hash(subject_card)
    if g["subject"]["agent"] != ch:
        raise VerifyError(
            "grant.subject.agent", f"subject.agent {g['subject']['agent']} is not this card {ch}"
        )
    if g["subject"]["key"] != subject_card["agent"]["key"]:
        raise VerifyError("grant.subject.key", "subject.key is not this card's agent key")
    if g["audience"]["executor"] not in executor_keys:
        raise VerifyError(
            "grant.audience",
            f"audience.executor {g['audience']['executor']} is not this node or agent",
        )
    nb, exp, iss = (parse(g[f], f"grant.{f}") for f in ("not_before", "expires_at", "issued_at"))
    if exp <= iss:
        raise VerifyError("grant.expires_at", "expires_at must be after issued_at")
    if now < nb:
        raise VerifyError("grant.not_yet_valid", f"not_before {g['not_before']} is in the future")
    if now >= exp:
        raise VerifyError("grant.expired", f"expired at {g['expires_at']}")
    for i, s in enumerate(g["scope"]):
        if not cardmod.allows(subject_card, s["action"], s["resource"]):
            raise VerifyError(
                "grant.scope.not_in_card",
                f"scope[{i}] {s['action']} on {s['resource']} is not a capability of the card",
            )


# ---- scope algebra --------------------------------------------------------------


def _constraint_within(child: dict[str, Any], parent: dict[str, Any]) -> bool:
    """child is at least as tight as parent on every constraint parent has."""
    if "in" in parent:
        if "in" not in child:
            return False
        pv = [canonicalize(v) for v in parent["in"]]
        if any(canonicalize(v) not in pv for v in child["in"]):
            return False
    if "range" in parent:
        if "range" not in child:
            return False
        plo, phi = parent["range"]
        clo, chi = child["range"]
        if plo is not None and (clo is None or clo < plo):
            return False
        if phi is not None and (chi is None or chi > phi):
            return False
    if "regex" in parent and child.get("regex") != parent["regex"]:
        return False
    return True


def _entry_within(child: dict[str, Any], parent: dict[str, Any]) -> bool:
    if child["action"] != parent["action"] or child["resource"] != parent["resource"]:
        return False
    if child.get("offline_ok", False) and not parent.get("offline_ok", False):
        return False
    if child.get("max_offline_s", 0) > parent.get("max_offline_s", 0):
        return False
    pk, ck = set(parent["params"]["keys"]), set(child["params"]["keys"])
    if not ck <= pk:
        # keys is the complete list a request may carry; [] permits none, so a child
        # can only drop names, never add them (and never widen [] into anything)
        return False
    for k, pc in parent["params"]["values"].items():
        if k not in ck:
            # the child forbids this parameter altogether: strictly tighter than any
            # constraint the parent put on it, so there is nothing to compare
            continue
        cc = child["params"]["values"].get(k)
        if cc is None or not _constraint_within(cc, pc):
            return False
    return True


def is_subset(child_scope: list[dict[str, Any]], parent_scope: list[dict[str, Any]]) -> bool:
    return all(any(_entry_within(c, p) for p in parent_scope) for c in child_scope)


def is_strict_subset(child_scope: list[dict[str, Any]], parent_scope: list[dict[str, Any]]) -> bool:
    return is_subset(child_scope, parent_scope) and canonicalize(child_scope) != canonicalize(
        parent_scope
    )


# ---- matching a request against scope ---------------------------------------------


def _value_ok(v: Any, c: dict[str, Any]) -> str | None:
    if isinstance(v, str) and len(v.encode("utf-8", "surrogatepass")) > MAX_PARAM_BYTES:
        return f"over {MAX_PARAM_BYTES} bytes"
    if "in" in c and canonicalize(v) not in [canonicalize(x) for x in c["in"]]:
        return "not in allowed set"
    if "range" in c:
        if not isinstance(v, int | float) or isinstance(v, bool):
            return "range constraint on a non-number"
        lo, hi = c["range"]
        if (lo is not None and v < lo) or (hi is not None and v > hi):
            return f"outside range [{lo}, {hi}]"
    if "regex" in c:
        if not isinstance(v, str):
            return "regex constraint on a non-string"
        try:
            # the EMISSION, never the raw pattern, through the `regex` package for its
            # match timeout: the TIMEOUT is the bound on the match, not any claim about
            # the search (a fixed pattern without nested repetition backtracks
            # polynomially in the value, but the pattern is the issuer's variable and
            # alternation alone is exponentially ambiguous — `(a|aa)` twenty-one times
            # on a^40 — so no grammar bound short of the timeout holds; round-20 gate D2)
            hit = regex.fullmatch(
                emit_pattern(c["regex"]), v, flags=regex.DOTALL, timeout=REGEX_TIMEOUT_S
            )
        except TimeoutError as e:
            raise RefusedError(
                "scope.regex_timeout", f"regex match exceeded {REGEX_TIMEOUT_S}s"
            ) from e
        except (regex.error, RecursionError, OverflowError, ValueError, TypeError) as e:
            # a PatternProblem (ValueError) here means a grant whose document check
            # did not run — refused, never an escape
            raise RefusedError("scope.regex_error", f"{type(e).__name__}: {e}") from e
        if hit is None:
            return "does not match regex"
    return None


def match_scope(
    g: dict[str, Any], action: str, resource: str, params: dict[str, Any]
) -> dict[str, Any]:
    """Return the scope entry that admits (action, resource, params) or raise RefusedError
    listing why each entry declined."""
    reasons = []
    for i, s in enumerate(g["scope"]):
        if s["action"] != action:
            reasons.append(f"scope[{i}]: action {s['action']} != {action}")
            continue
        if s["resource"] != resource:
            reasons.append(f"scope[{i}]: resource {s['resource']} != {resource}")
            continue
        keys_allowed = s["params"]["keys"]
        extra = [k for k in params if k not in keys_allowed]
        if extra:
            reasons.append(f"scope[{i}]: params {extra} not permitted")
            continue
        bad = None
        for k, c in s["params"]["values"].items():
            if k in params:
                why = _value_ok(params[k], c)
                if why:
                    bad = f"scope[{i}]: param {k} {why}"
                    break
        if bad:
            reasons.append(bad)
            continue
        return s
    raise RefusedError("scope.no_match", "; ".join(reasons) or "grant has no scope entries")


def uses_ok(g: dict[str, Any], uses: int, uses_in_window: int | None = None) -> None:
    if uses >= g["max_uses"]:
        raise VerifyError("grant.max_uses", f"grant already used {uses} of {g['max_uses']}")
    w = g.get("max_uses_per_window")
    if w is not None and uses_in_window is not None and uses_in_window >= w["n"]:
        raise VerifyError(
            "grant.max_uses_per_window",
            f"{uses_in_window} uses in the last {w['window_s']}s, limit {w['n']}",
        )

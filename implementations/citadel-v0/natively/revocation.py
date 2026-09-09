"""Revocation (spec section 6): one signed message from a principal revokes an agent
card and every grant under it, or named grants. Honored within a poll interval.

The feed is a local JSONL file of signed revocation objects plus a sidecar recording
the last successful lookup. Before an action, the executor's revocation lookup must
be fresh: no older than the grant's max_check_interval_s plus a grace period (one
poll), else fail closed. A scope entry with offline_ok may stretch that to its
max_offline_s (spec: only read/report scopes carry offline tolerance).

Identity in the feed is the exact authenticated triple (principal key, rev_id,
canonical body hash): the same body again is a duplicate; a second signed body under
the same (principal, rev_id) with a different canonical body is RECORDED as its own
entry (revocations only ever add coverage, so recording both revokes the union);
different principals never collide. A duplicate is not a short-circuit: the file and
the directory are fsynced again before False is reported, so a retry after a write
whose barrier failed after the bytes became visible stands on synced bytes.

Every line of the feed was verified before it was appended, so every load verifies
each stored record as a DOCUMENT again (`check_document`, as state.read_grant does
for a grant on file): the structure with every field of its type — the principal key
one that decodes to 32 bytes, the signature a base64 string of 64 bytes — and the
signature verifying under the principal key the record names. A record that no
longer holds is local corruption, IntegrityError feed.corrupt naming the path and the
line, never a record to skip: enforcement never reads past a record it cannot verify
(a stored key replaced by a string that is not a key would otherwise disable the
revocation it carries), so a feed that fails to load is a storage failure at
authorization, at the pin, at the check verbs and at every other read. What stays a
policy decision at use is only the rooting (the principal pinned or not) and time.

Framing is validated on every load: a parse failure anywhere in the LOCAL file, or a
final line without its newline that does not parse (a torn tail), is an
IntegrityError (a storage failure, never malformed peer input); a physical line that
is empty or whitespace-only is feed.corrupt naming the line — the ONLY element any
reader skips is the synthetic empty string after the final newline
(durable.physical_lines), and a whitespace-only unterminated tail is corruption, never
a torn tail to cut; a complete final object short of its newline is accepted and gets
its newline back on the next append; `repair()` truncates a torn tail (only when every
preceding line parses)."""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from . import keys
from . import state as statemod
from .canon import hash_of
from .durable import (
    append_line,
    append_text,
    fsync_dir,
    fsync_existing,
    is_blank_line,
    parse_local,
    physical_lines,
    torn_text_problem,
    write_json,
)
from .errors import IntegrityError, VerifyError
from .objects import (
    check_sig,
    is_id,
    new_id,
    require,
    require_id,
    require_key,
    require_sig,
    require_str,
    signed,
)
from .timeutil import fmt, parse

_TOP = ("rev_id", "ts", "principal", "revokes", "principal_statement")
# the monotonic clock the freshness check measures elapsed time on within a process
# (a module attribute so a test can drive it); the wall clock decides too, and the
# stricter of the two refuses
_monotonic = time.monotonic
_MISSING = object()  # the sidecar is ABSENT (a present `null` is corruption)
MAX_REVOKES = 256
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _is_card_hash(x: Any) -> bool:
    return isinstance(x, str) and x.startswith("sha256:") and bool(_HEX64.fullmatch(x[7:]))


def build(
    *,
    principal_key: str,
    ts: str,
    cards: list[str] | None = None,
    grants: list[str] | None = None,
    principal_statement: str = "",
) -> dict[str, Any]:
    if not cards and not grants:
        raise ValueError("a revocation names at least one card or grant")
    return {
        "rev_id": new_id("rev"),
        "ts": ts,
        "principal": {"key": principal_key},
        "revokes": {"cards": list(cards or []), "grants": list(grants or [])},
        "principal_statement": principal_statement,
    }


def sign(r: dict[str, Any], kp: keys.KeyPair) -> dict[str, Any]:
    if kp.public != r["principal"]["key"]:
        raise ValueError("signing key does not match revocation.principal.key")
    return signed(r, kp)


def verify(r: Any, *, pinned: set[str]) -> None:
    """Peer input: the document (`check_document`) and this node's policy on it —
    the principal rooted in the pinned set. The rooting is judged before the
    signature so an unpinned principal's revocation is refused by that name."""
    pk = check_structure(r)
    if pk not in pinned:
        raise VerifyError("revocation.principal.unpinned", f"{pk} is not a pinned principal root")
    check_sig(r, pk, "revocation")


def check_document(r: Any) -> str:
    """What holds or fails on the revocation DOCUMENT itself, no policy: the
    structure with every field of its type and the signature verifying under the
    principal key it names. Returns that key. A record ON FILE is read through this
    on every load (`RevocationFeed._parse`): it was verified before it was stored,
    so a failure here is local corruption of the feed, never a refusal."""
    pk = check_structure(r)
    check_sig(r, pk, "revocation")
    return pk


def check_structure(r: Any) -> str:
    """The revocation's structure in full (every field, every nested type: the
    principal key one that decodes, the signature a base64 string of 64 bytes);
    returns the principal key it names. Whether the signature verifies is
    `check_document`'s; the rooting is `verify`'s."""
    require(r, "revocation", _TOP + ("sig",))
    require_id(r, "rev_id", "revocation", "rev_")
    parse(require_str(r, "ts", "revocation"), "revocation.ts")
    require(r["principal"], "revocation.principal", ("key",))
    pk = require_key(r["principal"], "key", "revocation.principal")
    require(r["revokes"], "revocation.revokes", ("cards", "grants"))
    cards = r["revokes"]["cards"]
    if not isinstance(cards, list) or not all(_is_card_hash(x) for x in cards):
        raise VerifyError("revocation.revokes.cards", "must be a list of sha256:<64 hex> hashes")
    grants = r["revokes"]["grants"]
    if not isinstance(grants, list) or not all(is_id(x, "grt_") for x in grants):
        raise VerifyError("revocation.revokes.grants", "must be a list of grt_ ids")
    if len(cards) + len(grants) > MAX_REVOKES:
        raise VerifyError("revocation.revokes.size", f"more than {MAX_REVOKES} ids")
    if not r["revokes"]["cards"] and not r["revokes"]["grants"]:
        raise VerifyError("revocation.revokes.empty", "revokes nothing")
    if not isinstance(r["principal_statement"], str):
        raise VerifyError("revocation.principal_statement", "must be a string")
    require_sig(r, "revocation")
    return pk


class RevocationFeed:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.check_path = self.path.with_suffix(".check.json")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # the last complete lookup as this process knows it: (the sidecar's value,
        # the monotonic clock when it was written here or first read here)
        self._anchor: tuple[str, float] | None = None

    # ---- framing ----
    def _read(self) -> bytes:
        try:
            with open(self.path, "rb") as f:
                return f.read()
        except FileNotFoundError:
            return b""

    def _decode(self, raw: bytes, ln: int) -> dict[str, Any]:
        """The FRAMING of one line of the LOCAL file: a JSON object. Every parser
        failure (a syntax error, a bad encoding, an oversized integer literal,
        nesting past the recursion limit) and a value that is not an object is
        feed.corrupt naming the path and the line: local corruption, never
        malformed peer input. On the unterminated last line this is the one
        failure that reads as a TORN write (`load`, `torn_tail`)."""
        try:
            e = parse_local(raw)
        except (UnicodeDecodeError, ValueError, RecursionError) as ex:
            raise IntegrityError(
                "feed.corrupt", f"{self.path} line {ln}: {type(ex).__name__}: {ex}"
            ) from ex
        if not isinstance(e, dict):
            raise IntegrityError("feed.corrupt", f"{self.path} line {ln}: not an object")
        return e

    def _parse(self, raw: bytes, ln: int) -> dict[str, Any]:
        """One line of the LOCAL file: its framing (`_decode`), then the document
        (`_verify`)."""
        return self._verify(self._decode(raw, ln), ln)

    def _verify(self, e: dict[str, Any], ln: int) -> dict[str, Any]:
        # a line of OUR feed is a revocation DOCUMENT in full — every field of its
        # type, the signature verifying under the principal key it names — exactly
        # as it was verified when it was added: anything else is local corruption,
        # named by path and line, never a record to skip at enforcement, never a
        # KeyError at a later read, never malformed peer input
        try:
            check_document(e)
        except VerifyError as ex:
            raise IntegrityError(
                "feed.corrupt", f"{self.path} line {ln}: not a revocation ({ex})"
            ) from ex
        return e

    def load(self) -> tuple[list[dict[str, Any]], bool]:
        """Every entry, and whether the final line lacks its newline. A line of the
        LOCAL file that does not parse is IntegrityError (feed.corrupt); a final line
        without its newline that does not parse is a torn tail (feed.torn) — local
        corruption in both cases, never a VerifyError about peer input."""
        data = self._read()
        unterminated = bool(data) and not data.endswith(b"\n")
        out: list[dict[str, Any]] = []
        last = data.count(b"\n") + 1  # the physical line number of an unterminated tail
        # every PHYSICAL line is a record: a blank or whitespace-only line is
        # feed.corrupt at its line number (physical_lines), a whitespace-only
        # unterminated tail included — never a line to skip, never a torn write
        for ln, raw in physical_lines(data, self.path, "feed.corrupt"):
            if unterminated and ln == last:
                try:
                    e = self._decode(raw, ln)
                except IntegrityError as e:
                    # only a strict prefix of one record is torn: a complete record
                    # that fails its document check is corruption, kept — and so is
                    # anything else that is not a prefix of one record of ours (a
                    # member named twice, a second object, trailing bytes, an
                    # invalid byte: `durable.torn_text_problem`, the prefix rule)
                    why = torn_text_problem(raw)
                    if why is not None:
                        raise IntegrityError(
                            "feed.corrupt",
                            f"{self.path} line {ln}: the last line ({len(raw)} bytes) has no "
                            f"newline and is not a torn write of ours ({why}); nothing cut: "
                            f"restore the file ({e})",
                        ) from e
                    raise IntegrityError(
                        "feed.torn",
                        f"{self.path} ends in a torn partial line (line {ln}, {len(raw)} bytes; "
                        f"`natively feed repair` truncates it): {e}",
                    ) from e
                out.append(self._verify(e, ln))  # a whole record: verified like any
                continue
            out.append(self._parse(raw, ln))
        return out, unterminated

    def entries(self) -> list[dict[str, Any]]:
        return self.load()[0]

    def check_prefix(self, to: int) -> None:
        """The first `to` bytes of the feed are PRESENT and are whole lines that
        each verify as a revocation document: what a resumed repair must find before
        it cuts, at every step — a file shorter than the cut point (records lost
        since the intent was recorded) is refused as corruption, never accepted
        as "already cut"."""
        data = self._read()
        if len(data) < to:
            raise IntegrityError(
                "feed.corrupt",
                f"{self.path}: {len(data)} bytes, shorter than the repair intent's cut point "
                f"{to}; records before the intent are missing — nothing truncated, the "
                f"intent stays: restore the file before `natively feed repair`",
            )
        for ln, raw in physical_lines(data[:to], self.path, "feed.corrupt"):
            self._parse(raw, ln)

    def torn_tail(self) -> bytes:
        """The torn partial final line `repair()` would truncate: a final line without
        its newline that fails to parse, when every preceding line parses (an earlier
        line that does not is feed.corrupt, reported, never repaired). Empty when
        nothing is torn — a complete object short of its newline is not torn, the
        next append puts the newline back."""
        data = self._read()
        if not data or data.endswith(b"\n"):
            self.load()  # every line must parse; anything else is reported, not repaired
            return b""
        head, sep, tail = data.rpartition(b"\n")
        keep = head + sep  # a leading blank line stays line 1: refused before any cut
        for ln, raw in physical_lines(keep, self.path, "feed.corrupt"):
            self._parse(raw, ln)
        last = keep.count(b"\n") + 1
        if is_blank_line(tail):
            # whitespace (Unicode-aware: durable.is_blank_line) where a record
            # belongs: corruption, never a torn write to cut
            raise IntegrityError(
                "feed.corrupt",
                f"{self.path} line {last}: the last line ({len(tail)} bytes) is whitespace "
                f"only and has no newline; not a torn write, nothing cut: restore the file",
            )
        try:
            e = self._decode(tail, last)
        except IntegrityError as ex:
            why = torn_text_problem(tail)
            if why is None:
                return tail  # a strict prefix of one record: a torn write
            # a whole object, or bytes that are not a prefix of one record of ours:
            # corruption by name, never cut (the prefix rule)
            raise IntegrityError(
                "feed.corrupt",
                f"{self.path} line {last}: the last line ({len(tail)} bytes) has no newline "
                f"and is not a torn write of ours ({why}); nothing cut: restore the file "
                f"({ex})",
            ) from ex
        # a whole record short of only its newline is verified like any other and
        # NEVER cut: one that fails is corruption (feed.corrupt, raised), kept
        self._verify(e, last)
        return b""

    def repair(self) -> int:
        """Truncate a torn partial final line (see torn_tail). Returns the bytes
        removed. The truncation is fsynced (file, then directory) before it returns;
        and a file found already clean is fsynced the same way before 0 is returned —
        a retry after a truncation whose barrier failed AFTER it became visible
        re-establishes the barrier rather than reporting success on visible bytes."""
        tail = self.torn_tail()
        if not tail:
            if self.path.exists():
                fsync_existing(self.path)
            return 0
        keep = len(self._read()) - len(tail)
        with open(self.path, "r+b") as f:
            f.truncate(keep)
            f.flush()
            os.fsync(f.fileno())
        fsync_dir(self.path.parent)
        return len(tail)

    # ---- write ----
    @staticmethod
    def identity(r: dict[str, Any]) -> tuple[str, str, str]:
        """(principal key, rev_id, canonical body hash): the feed's deduplication key."""
        return (r["principal"]["key"], r["rev_id"], hash_of(r))

    def add(self, r: dict[str, Any], *, pinned: set[str]) -> str:
        """Verify and append. Returns "recorded" (a new body), "recorded:variant" (a
        different signed body under a (principal, rev_id) already on file: recorded
        too, coverage only ever grows) or "duplicate" (the exact body is already on
        file). The bytes are durable before this returns in EVERY case — a duplicate
        fsyncs the file and the directory again rather than short-circuiting — so a
        caller may mark the mail seen, advance a cursor, delete a held copy or
        publish trust only once this has returned."""
        verify(r, pinned=pinned)
        me = self.identity(r)
        outcome = "recorded"
        for e in self.entries():
            other = self.identity(e)
            if other == me:
                fsync_existing(self.path)  # a retry after a half-synced write
                return "duplicate"
            if other[:2] == me[:2]:
                outcome = "recorded:variant"
        self.append(r)
        return outcome

    def append(self, r: dict[str, Any]) -> None:
        """Durable append of one object on its own line. Refused (IntegrityError)
        while the file has a torn tail; a complete final object short of its newline
        gets the newline back first (same rule as the ledger's prose mirror)."""
        _, unterminated = self.load()
        if unterminated:
            append_text(self.path, "\n")
        append_line(self.path, json.dumps(r, ensure_ascii=False, separators=(",", ":")))

    def card_revoked_by(self, card_hash: str, principal_key: str) -> dict[str, Any] | None:
        for e in self.entries():
            if e["principal"]["key"] == principal_key and card_hash in e["revokes"]["cards"]:
                return e
        return None

    def grant_revoked_by(self, grant_id: str, principal_key: str) -> dict[str, Any] | None:
        for e in self.entries():
            if e["principal"]["key"] == principal_key and grant_id in e["revokes"]["grants"]:
                return e
        return None

    # ---- freshness ----
    def mark_checked(self, now: datetime) -> None:
        # atomic and durable, never an in-place write: a torn sidecar would read as
        # "never checked" (fail closed, but for no reason) or as a stale clock
        write_json(self.check_path, {"last_checked": fmt(now)})
        self._anchor = (fmt(now), _monotonic())

    def last_checked(self) -> datetime | None:
        """The freshness sidecar; absent is None (never checked). A sidecar of ours
        with the wrong shape or an unparseable timestamp is local corruption
        (IntegrityError, a storage failure), never "never checked" and never a
        verification failure attributed to peer input."""
        # the typed loader: a present `null`, a list, an object without a last_checked
        # string is state.corrupt naming the path (never "never checked")
        c = statemod.read(self.check_path, _MISSING, statemod.check_sidecar)
        if c is _MISSING:
            return None  # absent
        try:
            return parse(c["last_checked"], "revocation.check")
        except VerifyError as e:
            raise IntegrityError("state.corrupt", f"{self.check_path}: {e.detail}") from e

    def freshness_snapshot(self) -> datetime | None:
        """The I/O half of the freshness check: the sidecar read, and the monotonic
        anchor for its value established the moment the value is first read here —
        whatever verdict follows. Before, the anchor was set only after the wall-clock
        verdicts passed, so a first read that refused (age 361 s of 360) left none,
        and a clock stepped back 400 monotonic seconds later made the same sidecar
        pass (round-19 self-gate, third run)."""
        last = self.last_checked()
        if last is not None:
            key = fmt(last)
            if self._anchor is None or self._anchor[0] != key:
                # a lookup this process first sees now (another process's poll, or one
                # read before any of ours): the elapsed time counts from here
                self._anchor = (key, _monotonic())
        return last

    def assert_fresh(
        self, grant: dict[str, Any], scope_entry: dict[str, Any], now: datetime, grace_s: int
    ) -> None:
        """`check_fresh` on a snapshot read now: the one-call form for the choosing
        loop and the adapter. The pre-executor recheck takes the snapshot first and
        runs `check_fresh` after every other read, on a fresh clock reading."""
        self.check_fresh(self.freshness_snapshot(), grant, scope_entry, now, grace_s)

    def check_fresh(
        self,
        last: datetime | None,
        grant: dict[str, Any],
        scope_entry: dict[str, Any],
        now: datetime,
        grace_s: int,
    ) -> None:
        """The last complete lookup is recent enough for this grant, or fail closed.
        The verdict half: no file is read here, so it can run on a clock reading
        taken after every other read of the recheck (before, the freshness verdict
        preceded the card, pin, config and feed reads and could expire during them;
        round-19 self-gate, third run).
        Two clocks, the stricter decides: the wall clock (the sidecar's timestamp
        against `now`) and, within a process, the monotonic clock since the sidecar's
        value was written here or first read here. A sidecar timestamp in the FUTURE
        of the wall clock (a clock stepped back) is refused as stale until the next
        complete poll rewrites it — before, a negative age read as fresh for the
        size of the step plus the limit (round-19 gate, finding 6; Fable J1: actions
        applied 3600 to 7559 s after the lookup with a 360 s limit)."""
        limit = grant["revocation"]["max_check_interval_s"] + grace_s
        if scope_entry["offline_ok"]:
            limit = max(limit, scope_entry["max_offline_s"])
        if last is None:
            raise VerifyError(
                "revocation.never_checked",
                "no revocation lookup has ever succeeded on this node; failing closed",
            )
        age = int((now - last).total_seconds())
        if age < 0:
            raise VerifyError(
                "revocation.stale",
                f"the last revocation lookup is recorded at {fmt(last)}, {-age}s in the future "
                f"of the clock ({fmt(now)}): the clock was stepped back; failing closed until "
                f"the next complete poll rewrites the sidecar",
            )
        if age > limit:
            raise VerifyError(
                "revocation.stale",
                f"last revocation lookup {age}s ago exceeds {limit}s; failing closed",
            )
        key = fmt(last)
        if self._anchor is None or self._anchor[0] != key:
            self._anchor = (key, _monotonic())  # a value handed in without its snapshot
        elapsed = int(_monotonic() - self._anchor[1])
        if elapsed > limit:
            raise VerifyError(
                "revocation.stale",
                f"{elapsed}s of monotonic time since the last complete lookup ({key}) exceeds "
                f"{limit}s, whatever the wall clock says ({age}s ago); failing closed",
            )

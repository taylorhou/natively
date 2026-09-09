"""Standing denial (citadel extension, reply 3; behind the `standing_denial` flag):
a principal signs once that a resource class is denied to an agent, and no future
grant overrides it. The executor checks it before scope; a refusal is ledgered.

{"denial_id", "ts", "principal": {"key"}, "subject": {"agent": <card hash>|null},
 "deny": [{"action": <name or "*">, "resource": <glob>}], "principal_statement", "sig"}

The store is a local JSONL file with the revocation feed's discipline, the same
shapes. Every line was verified before it was appended, so every load verifies each
stored record as a DOCUMENT again (`check_document`: the structure with every field of
its type — the principal key one that decodes, the signature a base64 string of 64
bytes — and the signature verifying under the principal key the record names); a
record that no longer holds is IntegrityError denial.corrupt naming the path and the
line, never a record `denied()` skips — a store that fails to load is a storage
failure at authorization, at the pin, at the check verbs and at every other read.
Framing is validated on every load (a line of the LOCAL file that does not
parse is IntegrityError denial.corrupt; a physical line that is empty or
whitespace-only is denial.corrupt naming the line — the ONLY element any reader skips
is the synthetic empty string after the final newline, durable.physical_lines, and a
whitespace-only unterminated tail is corruption, never a torn tail to cut; a final
line without its newline that does not parse is a torn tail, denial.torn; a complete
final object short of its newline is accepted and gets its newline back on the next
append); an append is refused while
the tail is torn; `repair()` truncates a torn tail only when every preceding line
parses (`natively denial repair`, under the lock, ledgered denial.repaired). Identity
is the exact triple (principal key, denial_id, canonical body hash): a different body
under a known (principal, denial_id) is recorded as its own entry (denials only ever
add coverage), an exact duplicate fsyncs the file and the directory again before
False is reported — never a short-circuit on visible bytes. A corrupt store raises
IntegrityError (a storage failure: nothing ledgered as malformed, the mail stays
unseen) from `denied()` and `entries()` alike."""

from __future__ import annotations

import json
import os
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from . import keys
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
)
from .errors import IntegrityError, VerifyError
from .objects import (
    check_sig,
    new_id,
    require,
    require_id,
    require_key,
    require_sig,
    require_str,
    signed,
)
from .timeutil import parse

_TOP = ("denial_id", "ts", "principal", "subject", "deny", "principal_statement")


def build(
    *,
    principal_key: str,
    ts: str,
    deny: list[dict[str, str]],
    principal_statement: str,
    subject_agent: str | None = None,
) -> dict[str, Any]:
    if not deny:
        raise ValueError("a denial names at least one action/resource class")
    return {
        "denial_id": new_id("dny"),
        "ts": ts,
        "principal": {"key": principal_key},
        "subject": {"agent": subject_agent},
        "deny": [{"action": d["action"], "resource": d["resource"]} for d in deny],
        "principal_statement": principal_statement,
    }


def sign(d: dict[str, Any], kp: keys.KeyPair) -> dict[str, Any]:
    if kp.public != d["principal"]["key"]:
        raise ValueError("signing key does not match denial.principal.key")
    return signed(d, kp)


def verify(d: Any, *, pinned: set[str]) -> None:
    """Peer input: the document (`check_document`) and this node's policy on it —
    the principal rooted in the pinned set, judged before the signature."""
    pk = check_structure(d)
    if pk not in pinned:
        raise VerifyError("denial.principal.unpinned", f"{pk} is not a pinned principal root")
    check_sig(d, pk, "denial")


def check_document(d: Any) -> str:
    """What holds or fails on the denial DOCUMENT itself, no policy: the structure
    with every field of its type and the signature verifying under the principal key
    it names. Returns that key. A record ON FILE is read through this on every load
    (`DenialStore._parse`): a failure there is local corruption, never a refusal."""
    pk = check_structure(d)
    check_sig(d, pk, "denial")
    return pk


def check_structure(d: Any) -> str:
    """The denial's structure in full (every field, every nested type: the principal
    key one that decodes, the signature a base64 string of 64 bytes); returns the
    principal key it names. Whether the signature verifies is `check_document`'s;
    the rooting is `verify`'s."""
    require(d, "denial", _TOP + ("sig",))
    require_id(d, "denial_id", "denial", "dny_")
    parse(require_str(d, "ts", "denial"), "denial.ts")
    require(d["principal"], "denial.principal", ("key",))
    pk = require_key(d["principal"], "key", "denial.principal")
    require(d["subject"], "denial.subject", ("agent",))
    if d["subject"]["agent"] is not None and not (
        isinstance(d["subject"]["agent"], str) and d["subject"]["agent"].startswith("sha256:")
    ):
        raise VerifyError("denial.subject.agent", "must be null or a card hash")
    if not isinstance(d["deny"], list) or not d["deny"]:
        raise VerifyError("denial.deny", "must be a non-empty list")
    for i, x in enumerate(d["deny"]):
        require(x, f"denial.deny[{i}]", ("action", "resource"))
        require_str(x, "action", f"denial.deny[{i}]")
        require_str(x, "resource", f"denial.deny[{i}]")
    require_str(d, "principal_statement", "denial")
    require_sig(d, "denial")
    return pk


class DenialStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

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
        denial.corrupt naming the path and the line: local corruption, never
        malformed peer input. On the unterminated last line this is the one
        failure that reads as a TORN write (`load`, `torn_tail`)."""
        try:
            e = parse_local(raw)
        except (UnicodeDecodeError, ValueError, RecursionError) as ex:
            raise IntegrityError(
                "denial.corrupt", f"{self.path} line {ln}: {type(ex).__name__}: {ex}"
            ) from ex
        if not isinstance(e, dict):
            raise IntegrityError("denial.corrupt", f"{self.path} line {ln}: not an object")
        return e

    def _parse(self, raw: bytes, ln: int) -> dict[str, Any]:
        """One line of the LOCAL file: its framing (`_decode`), then the document
        (`_verify`)."""
        return self._verify(self._decode(raw, ln), ln)

    def _verify(self, e: dict[str, Any], ln: int) -> dict[str, Any]:
        # a line of OUR store is a denial DOCUMENT in full (every field of its type,
        # the signature under the principal key it names, as verified when it was
        # added): anything else is local corruption named by path and line, never
        # a record `denied()` skips, never a later KeyError
        try:
            check_document(e)
        except VerifyError as ex:
            raise IntegrityError(
                "denial.corrupt", f"{self.path} line {ln}: not a denial ({ex})"
            ) from ex
        return e

    def load(self) -> tuple[list[dict[str, Any]], bool]:
        """Every entry, and whether the final line lacks its newline. A line that
        does not parse is IntegrityError (denial.corrupt); a final line without its
        newline that does not parse is a torn tail (denial.torn)."""
        data = self._read()
        unterminated = bool(data) and not data.endswith(b"\n")
        out: list[dict[str, Any]] = []
        last = data.count(b"\n") + 1  # the physical line number of an unterminated tail
        # every PHYSICAL line is a record: a blank or whitespace-only line is
        # denial.corrupt at its line number (physical_lines), a whitespace-only
        # unterminated tail included — never a line to skip, never a torn write
        for ln, raw in physical_lines(data, self.path, "denial.corrupt"):
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
                            "denial.corrupt",
                            f"{self.path} line {ln}: the last line ({len(raw)} bytes) has no "
                            f"newline and is not a torn write of ours ({why}); nothing cut: "
                            f"restore the file ({e})",
                        ) from e
                    raise IntegrityError(
                        "denial.torn",
                        f"{self.path} ends in a torn partial line (line {ln}, {len(raw)} bytes; "
                        f"`natively denial repair` truncates it): {e}",
                    ) from e
                out.append(self._verify(e, ln))  # a whole record: verified like any
                continue
            out.append(self._parse(raw, ln))
        return out, unterminated

    def entries(self) -> list[dict[str, Any]]:
        return self.load()[0]

    def check_prefix(self, to: int) -> None:
        """The first `to` bytes of the store are PRESENT and are whole lines that
        each verify as a denial document: what a resumed repair must find before
        it cuts, at every step — a file shorter than the cut point (records lost
        since the intent was recorded) is refused as corruption, never accepted
        as "already cut"."""
        data = self._read()
        if len(data) < to:
            raise IntegrityError(
                "denial.corrupt",
                f"{self.path}: {len(data)} bytes, shorter than the repair intent's cut point "
                f"{to}; records before the intent are missing — nothing truncated, the "
                f"intent stays: restore the file before `natively denial repair`",
            )
        for ln, raw in physical_lines(data[:to], self.path, "denial.corrupt"):
            self._parse(raw, ln)

    def torn_tail(self) -> bytes:
        """The torn partial final line `repair()` would truncate (empty when nothing
        is torn); an earlier line that does not parse is denial.corrupt, never
        repaired. Same rule as the revocation feed."""
        data = self._read()
        if not data or data.endswith(b"\n"):
            self.load()
            return b""
        head, sep, tail = data.rpartition(b"\n")
        keep = head + sep  # a leading blank line stays line 1: refused before any cut
        for ln, raw in physical_lines(keep, self.path, "denial.corrupt"):
            self._parse(raw, ln)
        last = keep.count(b"\n") + 1
        if is_blank_line(tail):
            # whitespace (Unicode-aware: durable.is_blank_line) where a record
            # belongs: corruption, never a torn write to cut
            raise IntegrityError(
                "denial.corrupt",
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
                "denial.corrupt",
                f"{self.path} line {last}: the last line ({len(tail)} bytes) has no newline "
                f"and is not a torn write of ours ({why}); nothing cut: restore the file "
                f"({ex})",
            ) from ex
        # a whole record short of only its newline is verified like any other and
        # NEVER cut: one that fails is corruption (denial.corrupt, raised), kept
        self._verify(e, last)
        return b""

    def repair(self) -> int:
        """Truncate a torn partial final line, fsynced (file, then directory) before
        it returns; a file found already clean is fsynced the same way before 0 is
        returned (a retry after a truncation whose barrier failed). Returns the
        bytes removed."""
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
    def identity(d: dict[str, Any]) -> tuple[str, str, str]:
        """(principal key, denial_id, canonical body hash): the deduplication key."""
        return (d["principal"]["key"], d["denial_id"], hash_of(d))

    def add(self, d: dict[str, Any], *, pinned: set[str]) -> bool:
        """Verify and append durably (the line fsynced, then the directory): a
        standing denial is the enforcing record, so it must survive power loss before
        it is ledgered or reported as recorded. True when a body was recorded (a
        different body under a known (principal, denial_id) is recorded as its own
        entry); False for the exact body already on file — after the file and the
        directory were fsynced again, so a retry after a write whose barrier failed
        after the bytes became visible stands on synced bytes."""
        verify(d, pinned=pinned)
        me = self.identity(d)
        for e in self.entries():
            if self.identity(e) == me:
                fsync_existing(self.path)
                return False
        self.append(d)
        return True

    def append(self, d: dict[str, Any]) -> None:
        """Durable append of one object on its own line. Refused (IntegrityError)
        while the file has a torn tail; a complete final object short of its newline
        gets the newline back first."""
        _, unterminated = self.load()
        if unterminated:
            append_text(self.path, "\n")
        append_line(self.path, json.dumps(d, ensure_ascii=False, separators=(",", ":")))

    def denied(
        self, *, action: str, resource: str, card_hash: str, principal_key: str
    ) -> dict[str, Any] | None:
        """A denial applies when it was signed by the executor's own pinned principal
        (`principal_key`: the principal on the executor's card), names this card or
        every card, and one of its classes matches the request. A store that does
        not parse raises IntegrityError (a storage failure) rather than answering."""
        for d in self.entries():
            if d["principal"]["key"] != principal_key:
                continue
            if d["subject"]["agent"] not in (None, card_hash):
                continue
            for x in d["deny"]:
                if x["action"] in ("*", action) and fnmatchcase(resource, x["resource"]):
                    return d
        return None

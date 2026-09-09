"""Ledger (spec section 5): append-only JSONL, one entry per action taken against a
grant (and, per principle 5, one per verification failure and one per information
message received, so nothing is dropped), hash-chained through prev_hash, with a
prose mirror file beside it.

Entry: {"ts", "actor", "grant_id", "action", "params_hash", "outcome", "prev_hash"}
plus "msg_id" (idempotency key), "detail" (short prose) and "direction" ("in": this
node handled something a peer sent, or acted on its own; "out": a record about a
message THIS node sent — a peer's ack of it, or its undelivery). The entry hash is
SHA-256 over JCS(entry) exactly as stored; the head is the last entry's hash. A prose
line ends with [<first 12 hex of the entry hash>] so the verifier can pair the files.

Legacy entries: an entry written before the direction field existed has no
"direction" key. It is accepted as it is — its hash is over the entry as stored, so
the historical chain holds; it reads as direction "in" (every entry of that era was
inbound or the node's own, and the outbound names out.ack / out.send did not exist),
so `find_msg` still recovers its completion; its prose line renders exactly as it did
then (no direction = the "->" arrow), so an existing mirror still verifies. New entries
always carry the field; any other missing or extra key is still refused.

Integrity in operation: every load from disk re-reads the file when it changed and
verifies the prev_hash chain. Both files are files of OURS, so every framing,
encoding, shape or chain fault met while reading either is local corruption — an
IntegrityError (a storage failure: nothing ledgered, nothing acknowledged, the mail
unseen) naming the path and the line or byte offset, never a VerifyError taken for a
verdict on the bundle in hand: a final JSONL line without its newline
(ledger.truncated), a line that does not decode or parse or is not an entry
(ledger.corrupt), a physical line that is empty or whitespace-only (ledger.corrupt
naming the line: the ONLY element any reader skips is the synthetic empty string after
the final newline — durable.physical_lines; a whitespace-only unterminated tail is
corruption too, never an entry short of its newline and never a torn tail to cut), a
broken chain (ledger.chain), an entry with the wrong fields (ledger.entry.fields), and
the mirror's ledger.prose.* / ledger.repair.refused / ledger.mirror_corrupt below. The
same full check, read-only (`check_intact`: the chain, every entry, the mirror compared
through the head), is the first ledger read of every receive — before use accounting,
before a reservation, before the executor. A VerifyError is raised in this module for peer input
only (there is none: the ledger reads no peer input). `Node.repair_ledger` restores an
unterminated JSONL tail: a whole entry of this chain short of only its newline is
terminated (`terminate_tail`), a torn partial line is cut by the intent machine
(`torn_tail`) and ledgered `ledger.tail_truncated` — only when the part before it is
this ledger's chain in full, else refused by that fault's name with nothing written.
Every prose field is
escaped to one line, and `verify()` regenerates the expected prose for every entry
and compares whole PHYSICAL lines (no blank line is ever skipped); a final line with
no newline is unterminated and refused (ledger.prose.unterminated). `repair()`
regenerates ONLY missing trailing prose lines (a crash between the two writes) when
the JSONL chain verifies, terminating an unterminated last line first when it equals
its entry's prose. `append()` runs that
same check first: a mirror short by a trailing suffix (or its newline) is repaired in
place before the new entry is written, and any other difference refuses the append
(ledger.prose.mismatch) so a gap can never turn into an interior mismatch that
repair() must refuse. Every write (the JSONL line, a prose line, a repaired suffix,
a terminating newline) goes through durable.py, so the file AND its directory are
synced before the method returns.

The JSONL is the source of truth and its barrier precedes every mirror write: before
`repair()` or `sync_prose()` regenerates a line or a newline, the JSONL file and its
directory are fsynced (a barrier that raises stops the repair with nothing written to
the mirror), so a prose line never outlives the entry it mirrors. A mirror that
nevertheless has MORE lines than the JSONL has entries (a line written for an
unsynced entry by an older tool, then the power cut) is refused by verify() and by
append(); `Node.repair_ledger` (the `ledger repair` verb) truncates it to the JSONL's
length and ledgers `ledger.mirror_truncated` — entries are never invented from prose.

The mirror is a text file of OURS: one that does not decode as UTF-8 (a write torn
inside a multibyte character — the em dash before a detail — at the tail or in the
middle) is local corruption, IntegrityError ledger.mirror_corrupt naming the path and
the byte offset where decoding failed, everywhere the mirror is read (verify, the
pre-append sync, the barrier, repair): a storage failure, so a receive that meets it
refuses with nothing ledgered and its mail unseen, and a UnicodeDecodeError is not
reachable above this module. `Node.repair_ledger` rebuilds such a mirror from the
durable JSONL when the JSONL verifies: the whole lines before the damage must be
their entries' prose (else ledger.repair.refused: not this ledger's mirror), the
bytes from the damaged line on are truncated by the same intent machine and ledgered
`ledger.mirror_truncated`, and `repair()` regenerates every line cut. A JSONL that is
damaged too is refused by its own name (ledger.corrupt, ledger.chain) and nothing is
written."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from .canon import hash_of
from .durable import (
    DuplicateMember,
    append_line,
    append_lines,
    append_text,
    fsync_dir,
    fsync_existing,
    is_blank_line,
    is_blank_text,
    parse_local,
    physical_lines,
    torn_text_problem,
)
from .errors import IntegrityError, VerifyError
from .objects import is_id
from .timeutil import parse

GENESIS = "sha256:" + "0" * 64
FIELDS = (
    "ts",
    "actor",
    "grant_id",
    "action",
    "params_hash",
    "outcome",
    "prev_hash",
    "msg_id",
    "detail",
    "direction",
    "intent_id",
)
DIRECTIONS = ("in", "out")
# the fields an entry may lack: direction on a legacy entry; intent_id on every entry
# that is not a repair audit (the audits carry the intent id they record as a FIELD,
# matched by equality — never recovered from the detail's text: round-14 gate, finding 3)
OPTIONAL_FIELDS = ("direction", "intent_id")
# outcomes that consume a grant use: an applied action, a use reserved for an action
# whose completion was interrupted, and an executor failure AFTER its side effect
# existed (fail closed: the use is spent in both)
USE_OUTCOMES = ("applied", "failed:interrupted", "failed:post_commit")
MESSAGE_OUTCOMES = ("applied", "information", "refused", "failed")
# Entries that carry a msg_id but are NOT the completion of an inbound message are
# direction "out": a peer's ack of OUR message ("out.ack") and our own undelivered
# send ("out.send"). The out.* names are a convention for the human mirror; the
# DISCRIMINATOR is the explicit direction field, so a peer naming its inbound action
# "out.ack" (refused executor.unsupported, direction "in") still has a recoverable
# completion. Recovery of an inbound message must never key on an outbound entry (an
# unsolicited ack naming a msg_id could otherwise erase an interrupted use).
OUTBOUND_PREFIX = "out."
OUT_ACK = "out.ack"
OUT_SEND = "out.send"
# what the CLI tells an operator when the prose mirror is not this ledger's
RESTORE_GUIDANCE = (
    "the mirror was edited or is not this ledger's; restore state/ledger.prose.txt from a "
    "backup or regenerate it from the JSONL (`natively ledger repair` writes only missing "
    "trailing lines) — no entry is appended until the mirror verifies"
)

_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029]")
_NAMED = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}


def entry_hash(e: dict[str, Any]) -> str:
    return hash_of(e)


def one_line(s: Any) -> str:
    """Escape every line break and control character so a peer-chosen string can
    never become a second prose line."""
    s = str(s)
    return _CONTROL.sub(lambda m: _NAMED.get(m.group(), f"\\x{ord(m.group()):02x}"), s)


def outcome_kind(outcome: str) -> str:
    return outcome.split(":", 1)[0]


_STR_FIELDS = ("ts", "actor", "action", "outcome", "prev_hash")
_OPT_STR_FIELDS = ("grant_id", "params_hash", "msg_id")


def _entry_shape(e: Any, ln: int, path: Path) -> None:
    """One parsed line of OUR ledger is an entry IN FULL: an object with exactly the
    entry fields (direction may be absent: a legacy entry; intent_id may be absent:
    any entry that is not a repair audit — ledger.entry.fields otherwise, a missing
    or an unknown key alike, so nothing unknown is ever hashed), ts, actor, action,
    outcome and prev_hash strings, grant_id, params_hash and msg_id strings or
    null, detail a string, direction one of its values, intent_id when present an
    rpr_ id IN FULL (the prefix and exactly the ULID the package mints) and ts a
    timestamp that parses (ledger.entry.fields). Anything else is
    local corruption — IntegrityError naming the path and the line, at the LOAD —
    never a fault attributed to the bundle in hand, and never a VerifyError met
    later where an entry's field is used (a use count parsing a timestamp)."""
    if not isinstance(e, dict):
        raise IntegrityError("ledger.corrupt", f"{path} line {ln}: not an object")
    missing = [k for k in FIELDS if k not in e and k not in OPTIONAL_FIELDS]
    if missing or set(e) - set(FIELDS):
        raise IntegrityError(
            "ledger.entry.fields", f"{path} line {ln}: entry has fields {sorted(e)}"
        )
    for k in _STR_FIELDS:
        if not isinstance(e.get(k), str):
            raise IntegrityError(
                "ledger.corrupt", f"{path} line {ln}: {k} is not a string ({e.get(k)!r})"
            )
    for k in _OPT_STR_FIELDS:
        if e[k] is not None and not isinstance(e[k], str):
            raise IntegrityError("ledger.corrupt", f"{path} line {ln}: {k} is not a string or null")
    if not isinstance(e["detail"], str):
        raise IntegrityError("ledger.corrupt", f"{path} line {ln}: detail is not a string")
    if "direction" in e and e["direction"] not in DIRECTIONS:
        raise IntegrityError(
            "ledger.entry.fields", f"{path} line {ln}: direction {e['direction']!r}"
        )
    if "intent_id" in e and not is_id(e["intent_id"], "rpr_"):
        raise IntegrityError(
            "ledger.entry.fields",
            f"{path} line {ln}: intent_id is not rpr_<26-char ULID> in full ({e['intent_id']!r})",
        )
    try:
        parse(e["ts"], "ledger.ts")
    except VerifyError as ex:
        raise IntegrityError("ledger.entry.fields", f"{path} line {ln}: ts: {ex.detail}") from ex


class Ledger:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.prose_path = self.path.with_suffix(".prose.txt")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._entries: list[dict[str, Any]] | None = None
        self._loaded_key: tuple[int, int] | None = None
        # the owner's gate on every append (the node refuses while a repair of the
        # mirror is unfinished: its intent marker stands); None for a bare ledger
        self.guard: Callable[[], None] | None = None
        # the owner's anchors: (msg_id, ledger_head) of every ack this node stored
        # (seen.json), each signed over the head of the chain at the time; every
        # full check requires each head to be the hash of an entry present in the
        # chain as loaded (`_check_anchors`). None for a bare ledger
        self.anchors: Callable[[], list[tuple[str, str, str]]] | None = None

    # ---- read ----
    def _file_key(self) -> tuple[int, int] | None:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return None
        return (st.st_size, st.st_mtime_ns)

    def _read_bytes(self) -> bytes:
        try:
            with open(self.path, "rb") as f:
                return f.read()
        except FileNotFoundError:
            return b""

    def _load(self) -> list[dict[str, Any]]:
        return self._load_bytes(self._read_bytes())

    def _load_bytes(self, data: bytes) -> list[dict[str, Any]]:
        """The entries of `data`, the whole JSONL file of OURS as read, its chain
        verified. Every fault is local corruption — an IntegrityError naming the path
        and the line or the byte offset, a storage failure wherever the ledger is
        read, never a VerifyError taken for a verdict on peer input: a final line
        without its newline (ledger.truncated: an interrupted append — `natively
        ledger repair` terminates it when it is a whole entry of this chain and
        cuts it otherwise), a line that does not decode or parse, a line that is not
        an entry of its shape, a line that cannot be hashed (ledger.corrupt), an
        entry whose prev_hash is not the previous entry's hash (ledger.chain)."""
        out: list[dict[str, Any]] = []
        if data and not data.endswith(b"\n"):
            start = data.rfind(b"\n") + 1
            if is_blank_line(data[start:]):
                # whitespace (Unicode-aware: durable.is_blank_line) where an entry
                # belongs is corruption, never an entry that lacked only its newline
                # and never a torn append to cut
                last = data.count(b"\n") + 1
                raise IntegrityError(
                    "ledger.corrupt",
                    f"{self.path} line {last}: the last line (byte offset {start}, "
                    f"{len(data) - start} bytes) is whitespace only and has no newline; "
                    f"not a torn write, nothing cut: restore the file",
                )
            self._torn_tail_is_not_anchored(data[:start])
            tail = data[start:]
            try:
                parse_local(tail)
            except DuplicateMember as ex:
                # a member name twice in the unterminated line: bytes this node never
                # wrote, so corruption by name wherever the ledger is read — never an
                # interrupted append for the repair to judge (round-19 self-gate)
                raise IntegrityError(
                    "ledger.corrupt",
                    f"{self.path}: the last line (byte offset {start}) has no newline and "
                    f"carries a repeated member name ({ex}); not a torn write, nothing cut: "
                    f"restore the file",
                ) from ex
            except (UnicodeDecodeError, ValueError, RecursionError):
                why = torn_text_problem(tail)
                if why is not None:
                    # not a strict prefix of one record: bytes this node never wrote
                    # (the prefix rule, `durable.torn_text_problem`; round-20)
                    raise IntegrityError(
                        "ledger.corrupt",
                        f"{self.path}: the last line (byte offset {start}) has no newline and "
                        f"is not a torn write of ours ({why}); nothing cut: restore the file",
                    ) from None
                # torn or whole: the repair verb decides (`_tail_is_entry`)
            raise IntegrityError(
                "ledger.truncated",
                f"{self.path}: the last line (byte offset {start}, {len(data) - start} bytes) "
                f"has no newline (interrupted write); `natively ledger repair` terminates it "
                f"when it is a whole entry of this chain and cuts it otherwise",
            )
        prev = GENESIS
        offset = 0
        # every PHYSICAL line is an entry: a blank or whitespace-only line is
        # ledger.corrupt at its line number (physical_lines); only the synthetic
        # empty element after the final newline is passed over
        for ln, raw in physical_lines(data, self.path, "ledger.corrupt"):
            start, offset = offset, offset + len(raw) + 1
            try:
                e = parse_local(raw)
            except UnicodeDecodeError as ex:
                raise IntegrityError(
                    "ledger.corrupt",
                    f"{self.path} line {ln}: not UTF-8 at byte offset {start + ex.start} "
                    f"({type(ex).__name__}: {ex.reason})",
                ) from ex
            except (ValueError, RecursionError) as ex:
                raise IntegrityError(
                    "ledger.corrupt",
                    f"{self.path} line {ln} (byte offset {start}): {type(ex).__name__}: {ex}",
                ) from ex
            # the entry in full — its fields, their types, the direction, the
            # timestamp — or the line is local corruption at the load: never a
            # KeyError at find_msg or head, never a VerifyError at uses()
            _entry_shape(e, ln, self.path)
            if e["prev_hash"] != prev:
                raise IntegrityError(
                    "ledger.chain",
                    f"{self.path} line {ln} (byte offset {start}): prev_hash {e['prev_hash']} "
                    f"!= {prev}, the hash of the entry before it",
                )
            try:
                prev = entry_hash(e)
            except (TypeError, ValueError, RecursionError) as ex:
                # every value is a string or null after _entry_shape, so hashing
                # cannot recurse; a hash that fails all the same is corruption
                raise IntegrityError(
                    "ledger.corrupt",
                    f"{self.path} line {ln} (byte offset {start}): cannot be hashed "
                    f"({type(ex).__name__}: {str(ex)[:120]})",
                ) from ex
            out.append(e)
        return out

    def _torn_tail_is_not_anchored(self, keep: bytes) -> None:
        """Before a final line without its newline is named ledger.truncated (a torn
        append): when the part before it is this ledger's chain, that chain must
        anchor every stored ack (`_check_anchors`) — an ack is stored only after its
        entry's append returned durable, so a tear INSIDE an anchored entry is not an
        interrupted append but damage to a record that landed: ledger.head.mismatch
        naming the ack's msg_id, wherever the ledger is read (the receive, the
        verify verb, the repair verb before any cut), never a tail to cut — an
        empty part before the tail included (a torn ONLY entry that a stored ack
        anchors: the empty chain anchors nothing, so every reader names
        ledger.head.mismatch there too, never ledger.truncated). A part before the
        tail that is not the chain is named by its own fault where it is read;
        nothing is decided here."""
        if self.anchors is None:
            return
        try:
            es = self._load_bytes(keep)
            self._check_fields(es)
        except IntegrityError:
            return
        self._check_anchors(es)

    def check(self) -> list[dict[str, Any]]:
        """The JSONL on disk is this ledger's chain in full — the framing, every
        entry's fields and the chain (`_check_entries`) — and the acks this node
        stored anchor into it (`_check_anchors`: an entry an authenticated stored
        ack names is PRESENT, so no repair completes over one that was cut or
        edited) — with nothing written; anything else is IntegrityError by its
        name. The check every resumed step of the repair machine runs BEFORE it
        touches the mirror or its marker, and again before its marker goes.
        Returns the entries."""
        return self._checked_chain()

    def _checked_chain(self) -> list[dict[str, Any]]:
        """The chain as loaded, its fields and links checked, and anchored: what
        every read of the repair family stands on (the tail stages, the mirror
        stage, the regeneration of prose) — never a chain an authenticated stored
        ack no longer anchors into."""
        es, _ = self._check_entries()
        self._check_anchors(es)
        return es

    def check_intact(self) -> None:
        """Both files, read from disk NOW, nothing written, nothing cached past
        this call: the JSONL's framing, every entry's shape and the chain
        (`_check_entries`), then the prose mirror compared with every entry's
        regenerated prose line, the head included — the same comparison the
        append runs inside its barrier (`_prose_gap`: a mirror short by a trailing
        suffix, or ending in its entry's prose short of only its newline, is the
        documented crash between the two writes and passes; any other difference
        is ledger.prose.mismatch). The FIRST ledger read of every receive
        (`Node._receive`), before authorization counts uses, before a reservation
        is written, before the executor runs: a last completion whose outcome was
        edited (its chain link intact, its mirror line no longer its prose) or a
        mirror edited instead is a storage failure by name there, never a use
        count of zero and an execution that a later append refuses. One full read
        of both files per receive."""
        self._entries = None  # from disk, whatever the cached key says
        try:
            es = self.entries()
            self._prose_gap(es, "ledger.prose.mismatch")
            self._check_anchors(es)
        finally:
            self._entries = None  # the append re-reads what it stands on, pass or fail

    def _check_anchors(self, es: list[dict[str, Any]]) -> None:
        """The head every stored ack of this node was signed over, and the completion
        entry it named, are entries PRESENT in the chain as loaded — the local anchor
        of the tail: a last completion edited with its mirror line deleted passes the
        chain (its incoming link holds) and the mirror comparison (the line is
        absent), and the next append would regenerate the mirror line from the
        edited entry; the ack this node already sent for that message carries the
        original entry's head and hash, so the edit is caught here — the ack itself
        authenticated by the owner before its fields are read (`Node._stored_ack_anchors`:
        a damaged stored ack is seen.corrupt, never an anchor and never skipped).
        ledger.head.mismatch names the ack's msg_id and the field: an IntegrityError
        (a storage failure: the mail unseen, nothing reserved, nothing executed,
        nothing rebuilt). The entry named must be the inbound completion of that
        very message. A node with no stored ack has no anchor and is unchanged."""
        if self.anchors is None:
            return
        by_hash = {entry_hash(e): e for e in es}
        for msg_id, head, entry in self.anchors():
            if head not in by_hash:
                self._anchor_mismatch(msg_id, "ledger_head", head, len(es))
            completion = by_hash.get(entry)
            if (
                completion is None
                or completion.get("msg_id") != msg_id
                or direction_of(completion) != "in"
                or outcome_kind(completion["outcome"]) not in MESSAGE_OUTCOMES
            ):
                self._anchor_mismatch(msg_id, "ledger_entry", entry, len(es))

    def _anchor_mismatch(self, msg_id: str, field: str, value: str, n: int) -> None:
        raise IntegrityError(
            "ledger.head.mismatch",
            f"{self.path}: the ack this node stored for {msg_id} was signed over "
            f"{field} {value[:19] or '(not a hash)'}, which is the hash of no "
            f"{'entry' if field == 'ledger_head' else 'inbound completion of that message'} "
            f"in the chain as loaded ({n} entries): the entry it anchored was edited or "
            f"removed; nothing authorized over it — restore state/ledger.jsonl from a backup",
        )

    def check_prefix(self, to: int) -> list[dict[str, Any]]:
        """The first `to` bytes of the JSONL are PRESENT and are this ledger's chain
        in full (whole lines, each an entry, chained from genesis, the fields of
        their shape): what a resumed cut of the JSONL's tail must find before it
        cuts — at every step, a file shorter than the cut point (entries lost
        since the intent was recorded) is refused as corruption, never accepted
        as "already cut" — and the chain that REMAINS anchors every stored ack
        (`_check_anchors`: an entry an authenticated ack of this node names is never
        past the cut point; a tear inside one is ledger.head.mismatch, refused with
        the marker as found, the operator restores the JSONL from the mirror or a
        backup). Returns the entries."""
        data = self._read_bytes()
        if len(data) < to:
            raise IntegrityError(
                "ledger.corrupt",
                f"{self.path}: {len(data)} bytes, shorter than the repair intent's cut point "
                f"{to}; entries recorded before the intent are missing — nothing truncated, "
                f"the intent stays: restore the file before `natively ledger repair`",
            )
        es = self._load_bytes(data[:to])
        self._check_fields(es)
        self._check_anchors(es)
        return es

    def _split_tail(self) -> tuple[bytes, bytes]:
        """(the newline-terminated part, the unterminated final line) of the JSONL;
        the second is empty when the file ends in its newline (or is empty)."""
        data = self._read_bytes()
        if not data or data.endswith(b"\n"):
            return data, b""
        head, sep, tail = data.rpartition(b"\n")
        # the separator stays with the part before the tail: a file that is one
        # blank line and a torn tail (b"\n{") keeps its blank line 1, which the
        # prefix validation then refuses (ledger.corrupt) before anything is cut
        return head + sep, tail

    def _tail_is_entry(self, keep: bytes, tail: bytes) -> list[dict[str, Any]] | None:
        """The unterminated final line is a WHOLE entry of this chain — the file
        with only its newline added is this ledger's chain in full (the line
        parses, has an entry's fields, chains onto the part before it and hashes):
        short of only its newline (a write that landed all but the last byte);
        returns that chain's entries then, None for a torn write.
        A line that is a complete JSON object but NOT the next entry of this
        chain is neither that nor a torn write: it is local corruption
        (ledger.corrupt, raised) — never cut as a torn tail, since cutting it
        would erase a record on the strength of its damage; so is a line carrying
        a member name twice, whole or not (`durable.is_torn_text`). So is a whitespace-only
        unterminated line (ledger.corrupt, raised): not an entry short of its
        newline, not a torn append, never terminated and never cut."""
        if is_blank_line(tail):
            last = keep.count(b"\n") + 1
            raise IntegrityError(
                "ledger.corrupt",
                f"{self.path} line {last}: the last line (byte offset {len(keep)}, "
                f"{len(tail)} bytes) is whitespace only and has no newline; not a torn "
                f"write, nothing cut: restore the file",
            )
        try:
            es = self._load_bytes(keep + tail + b"\n")
            self._check_fields(es)
        except IntegrityError as e:
            why = torn_text_problem(tail)
            if why is None:
                return None  # a torn write: a strict prefix of one record, never whole
            # a whole object that is not the next entry, or bytes that are not a
            # strict prefix of one record (a repeated member, a second object,
            # trailing bytes, an invalid byte): bytes this node never wrote, so
            # corruption, never a torn write to cut (the prefix rule; round-20)
            raise IntegrityError(
                "ledger.corrupt",
                f"{self.path}: the last line (byte offset {len(keep)}) has no newline and is "
                f"not a torn write of ours ({why}), nor the next entry of this chain "
                f"({e.reason}: {e.detail}); nothing cut: restore the file",
            ) from e
        return es

    def chain_now(self) -> tuple[list[dict[str, Any]], bytes]:
        """(the entries of the JSONL as it stands, the torn tail): the
        newline-terminated part loaded and checked as this ledger's chain in full
        — the framing, the fields, the links — plus an unterminated final line
        that is a whole entry of the chain short of only its newline; the torn
        tail is a final line without its newline that is NOT such an entry (a torn
        append), empty otherwise. The chain returned is ANCHORED (`_check_anchors`)
        — the chain that would remain after the torn tail is cut: an entry an
        authenticated stored ack names is never a torn append (its ack was stored
        only after its append returned durable), so a tear inside one is
        ledger.head.mismatch by name, never a cut. A blank unterminated line, or a
        whole object that is not the next entry, is ledger.corrupt
        (`_tail_is_entry`). Nothing written."""
        keep, tail = self._split_tail()
        es = self._load_bytes(keep)
        self._check_fields(es)
        if tail:
            whole = self._tail_is_entry(keep, tail)
            if whole is not None:
                es, tail = whole, b""
        self._check_anchors(es)
        return es, tail

    def torn_tail(self) -> bytes:
        """The bytes `Node.repair_ledger` cuts from the END of the JSONL: a final line
        without its newline that is NOT a whole entry of this chain (a torn append).
        The part before it must be this ledger's chain in full and anchor every
        stored ack (`chain_now`) — refused by its own name (ledger.chain,
        ledger.corrupt, ledger.head.mismatch) otherwise: a tail is never cut from a
        JSONL that is not this ledger's, and never out of an entry an ack of this
        node anchors. Empty when the file ends in its newline (then the whole file
        must load) and when the unterminated line is a whole entry short of only
        its newline (`terminate_tail` puts the newline back)."""
        return self.chain_now()[1]

    def terminate_tail(self, *, mirror_excess_ok: bool | None = None) -> bool:
        """An unterminated final line that is a whole entry of this chain gets its
        newline back, durably (the file, then the directory) — the JSONL's analogue
        of the mirror's `_terminate_prose`: an entry that landed is never cut. The
        chain the newline would complete is anchored FIRST (`_check_anchors`): an
        anchored entry edited and left without its newline is ledger.head.mismatch
        with nothing written, never terminated into the chain (round-14 self-gate).
        With `mirror_excess_ok` given, the CURRENT mirror is checked against that
        completed chain too (`check_mirror`) before the newline is written — the
        repair verb's fresh run and its run under a standing mirror intent, where
        no resume validated the mirror yet: a mirror damaged past a valid retained
        prefix is ledger.prose.mismatch with the JSONL byte-identical, never a
        newline written and then the mirror refused (round-14 self-gate); a tail
        stage resumed at "truncated" validated it already and passes None. True
        when the newline was written. Only the repair verb calls this."""
        keep, tail = self._split_tail()
        if not tail:
            return False
        self._check_fields(self._load_bytes(keep))
        es = self._tail_is_entry(keep, tail)
        if es is None:
            return False
        self._check_anchors(es)
        if mirror_excess_ok is not None:
            self.check_mirror(es, excess_ok=mirror_excess_ok)
        append_text(self.path, "\n")
        self._entries = None
        return True

    def whole_entry_tail(self) -> tuple[list[dict[str, Any]], bytes] | None:
        """(the chain the newline would complete, the unterminated entry's bytes)
        when the JSONL's final line is a whole entry of this chain short of only its
        newline — the part before it this ledger's chain in full, the completed
        chain anchored (`_check_anchors`: an anchored entry edited and left without
        its newline is ledger.head.mismatch); None when the file ends in its newline
        or the final line is a torn append (`torn_tail` names that). A blank final
        line or a whole object that is not the next entry is ledger.corrupt
        (`_tail_is_entry`). Nothing written."""
        keep, tail = self._split_tail()
        if not tail:
            return None
        self._check_fields(self._load_bytes(keep))
        es = self._tail_is_entry(keep, tail)
        if es is None:
            return None
        self._check_anchors(es)
        return es, tail

    def fresh_mend_point(self, es: list[dict[str, Any]]) -> int | None:
        """The repair verb's FRESH run over a whole last entry short of only its
        newline (`whole_entry_tail`): the mirror's state is decided here, against
        `es` (the chain the newline completes), BEFORE anything is written. Three
        cases. (a) The mirror already agrees with the result the newline would
        produce — whole, short by trailing lines, its last line short of only its
        newline, or beyond the entries by the non-blank excess the ledger's own
        tail stage cuts: None, and the newline is written as before. A mirror
        that does not DECODE is none of these: it is refused FIRST, by the name
        every reader of the mirror gives it (ledger.mirror_corrupt, round 13),
        nothing written and no intent invented for it — before, it was taken as
        (a) and the newline written over it with no intent standing that could
        finish anything (round-15 gate, finding 2). (b) The mirror's last line is a
        non-blank strict prefix of THAT entry's prose — a prose write of the
        interrupted append that tore after an ASCII prefix, the mend case: the
        byte offset where that line begins, the mirror cut point a termination
        intent records so the mend runs under a standing intent. (c) Anything
        else is refused by name with nothing written: a partial line that is not
        such a prefix or is blank (ledger.prose.mismatch), a blank line anywhere
        (ledger.repair.refused), a whole line that is not its entry's
        (ledger.prose.mismatch), and a strict prefix of an EARLIER entry's line
        with entries after it (ledger.prose.mismatch: not a tear of the line the
        newline completes — no append of ours lands over an unterminated mirror
        line, so that shape is not this machine's). Before this decision the
        verb wrote the newline over the mend case and refused the mirror after
        it, with no intent to finish the mend (round-14 gate, finding 2)."""
        data = self._prose_bytes()
        text = self._decode_mirror(data)  # ledger.mirror_corrupt by name: nothing written
        self.check_mirror(es, excess_ok=True)  # (c) by name: nothing written
        lines, unterminated = self._split_prose(text)
        if not unterminated:
            return None  # (a): whole lines only; a trailing gap is regenerated
        i = len(lines) - 1
        if i >= len(es) or lines[i] == prose_line(es[i], entry_hash(es[i])):
            return None  # (a): the excess the tail stage cuts; short of only its newline
        # check_mirror admitted it: a non-blank strict prefix of entry i's prose
        if i != len(es) - 1:
            self._refuse_earlier_prefix(i, len(es) - 1, "the missing newline completes")
        return self._offset_after(data, i)

    def terminated_mend_point(self) -> tuple[bytes, int] | None:
        """The repair verb's FRESH run over a JSONL that is whole and TERMINATED:
        the terminated sibling of the mend case (`fresh_mend_point` (b)) — the
        last entry landed with its newline and the machine's own prose write for
        it then tore after an ASCII prefix (the documented crash between the two
        writes, one write boundary later than the mend case). Decided with
        nothing written: (the bytes of the last entry's line without its newline,
        the byte offset the torn mirror line begins at) when the JSONL is
        non-empty and ends in its newline, loads as this ledger's chain in full
        and anchored (`_checked_chain`), the mirror decodes, every whole mirror
        line is its entry's prose, and the unterminated last line is a non-blank
        STRICT prefix of the LAST entry's prose — the last only (round 13's rule):
        a strict prefix of an EARLIER entry's line with later lines missing is not
        a tear of this machine's (no append of ours lands over an unterminated
        mirror line) and is ledger.prose.mismatch by name, nothing written. None
        for every other shape, each left to what handles it now: an unterminated
        or empty JSONL (the tail stages), a mirror that does not decode (the
        mirror stage cuts it back to its sound lines under its own intent and
        regenerates them: the multibyte sibling, unchanged), whole lines only, a
        last line short of only its newline (the barrier terminates it), a line
        beyond the entries (the mirror stage's excess), a whole or partial line
        that is not its entry's (refused where it is read). The verb writes a
        finishing intent of the termination shape over the pair returned
        (`Node._termination_intent`) before it mends anything. Before, this shape
        was refused by the fresh run (ledger.repair.refused), by every append and
        by every receive, with no verb that finished it (round-15 Fable read,
        section D)."""
        data = self._read_bytes()
        if not data or not data.endswith(b"\n"):
            return None
        es = self._checked_chain()
        prose = self._prose_bytes()
        try:
            text = prose.decode("utf-8")
        except UnicodeDecodeError:
            return None  # the mirror stage's cut under its own intent, as before
        lines, unterminated = self._split_prose(text)
        if not unterminated:
            return None
        i = len(lines) - 1
        if i >= len(es):
            return None  # beyond the entries: the mirror stage's excess
        for j in range(i):
            if lines[j] != prose_line(es[j], entry_hash(es[j])):
                return None  # not this machine's tear: refused where it is read
        expected, partial = prose_line(es[i], entry_hash(es[i])), lines[i]
        if partial == expected or is_blank_text(partial) or not expected.startswith(partial):
            return None
        if i != len(es) - 1:
            self._refuse_earlier_prefix(i, len(es) - 1, "landed last")
        return data[:-1].rpartition(b"\n")[2], self._offset_after(prose, i)

    def _refuse_earlier_prefix(self, i: int, last: int, which: str) -> None:
        raise IntegrityError(
            "ledger.prose.mismatch",
            f"{self.prose_path}: the unterminated last prose line ({i}) is a prefix of "
            f"entry {i}'s line, not of the entry {which} ({last}); not a torn write of "
            f"this ledger's, nothing written: {RESTORE_GUIDANCE}",
        )

    def visible_tail_object(self) -> dict[str, Any] | None:
        """The JSONL's last physical line — terminated or short of only its newline —
        as the JSON object it is; None when the file is empty or that line is not
        one (a torn append, bytes that are not UTF-8, text that is not JSON). Read
        only and nothing written: what `Node._bind_visible_audit` binds to a
        standing marker at step "truncated" BEFORE any mend writes, when the line
        carries that intent's id (round-15 self-gate, finding 2). The object is
        checked IN FULL as an entry first (`_entry_shape`, the check every loaded
        line crosses): one that is not — a field missing or unknown
        (ledger.entry.fields), a field of another type, an action that is not a
        string (ledger.corrupt) — is refused by the ledger's own name for such a
        line, never a raw object handed to the binding (an
        action that was a list or a dict reached the store lookup and raised
        TypeError there: round-16 self-gate)."""
        data = self._read_bytes()
        if not data:
            return None
        lines = data.split(b"\n")
        last = lines[-2] if data.endswith(b"\n") else lines[-1]
        try:
            e = parse_local(last)
        except (UnicodeDecodeError, ValueError, RecursionError):
            return None  # not a whole object: nothing to bind
        if not isinstance(e, dict):
            return None
        _entry_shape(e, len(lines) - 1 if data.endswith(b"\n") else len(lines), self.path)
        return e

    def line_at(self, to: int) -> bytes:
        """The JSONL's physical line starting at byte offset `to`, without its newline
        (all the bytes from `to` when none landed): what a termination intent binds
        by hash — the entry it stands to terminate, whether or not its newline
        landed yet and whether or not the stage's own audit followed it."""
        rest = self._read_bytes()[to:]
        i = rest.find(b"\n")
        return rest if i < 0 else rest[:i]

    def after_line(self, to: int) -> bytes:
        """The bytes of the JSONL past the physical line starting at byte offset
        `to` — empty when that line has no newline yet, its newline alone when it
        is the file's last line, more when something follows it: what a
        termination intent at step "intent" requires to be nothing or the newline
        (`Node._validate_termination_resume`; a whole entry there is not this
        machine's write). Bytes only, nothing decoded, nothing written."""
        return self._read_bytes()[to + len(self.line_at(to)) :]

    def lines_before(self, to: int) -> int:
        """The newline-terminated lines of the JSONL before byte offset `to` — the
        entries before the one a termination intent stands on (`to` is at a line
        boundary: the chain before it verified and the line at it bound by hash)."""
        return self._read_bytes()[:to].count(b"\n")

    def check_mirror_cut(self, mirror_to: int, n_lines: int, es: list[dict[str, Any]]) -> None:
        """A termination intent's recorded mirror cut point: the first `mirror_to`
        bytes of the mirror are exactly `n_lines` whole lines (the prose of the
        entries before the one being terminated), each its entry's prose
        (`check_prose_prefix`); anything else is ledger.prose.mismatch with the
        marker standing and nothing written."""
        self.check_prose_prefix(mirror_to, es)
        if self._prose_bytes()[:mirror_to].count(b"\n") != n_lines:
            raise IntegrityError(
                "ledger.prose.mismatch",
                f"{self.prose_path}: the repair intent's mirror cut point {mirror_to} is not "
                f"the end of prose line {n_lines - 1}; nothing written, the intent stays: "
                f"{RESTORE_GUIDANCE}",
            )

    def check_prose_prefix(self, to: int, es: list[dict[str, Any]]) -> None:
        """The first `to` bytes of the mirror — the prose a standing MIRROR intent
        retains — are PRESENT, whole newline-terminated lines, no more of them than
        the entries `es` (the chain as checked), each its entry's prose: what a
        resumed cut of the mirror must find before it cuts, advances or removes
        its marker. The bytes past the cut point are the tail the intent recorded
        (checked by hash at the cut) or the regeneration the stage's own mend and
        append validate. A mirror shorter than the cut point, a cut point inside a
        line, a retained line that is not its entry's (an equal-length replacement
        by whitespace included) or more retained lines than entries is
        ledger.prose.mismatch naming the line, nothing cut, the marker standing; a
        retained prefix that does not decode is ledger.mirror_corrupt. Nothing
        written. (A resume that validated only the JSONL cut the recorded suffix
        and advanced the marker before the append refused the prefix: round-13
        gate, finding 3.)"""
        data = self._prose_bytes()
        if len(data) < to:
            raise IntegrityError(
                "ledger.prose.mismatch",
                f"{self.prose_path}: {len(data)} bytes, shorter than the repair intent's cut "
                f"point {to}; the prose the intent retains is missing — nothing cut, the "
                f"intent stays: {RESTORE_GUIDANCE}",
            )
        prefix = data[:to]
        if prefix and not prefix.endswith(b"\n"):
            raise IntegrityError(
                "ledger.prose.mismatch",
                f"{self.prose_path}: the repair intent's cut point {to} is not the end of a "
                f"prose line; nothing cut, the intent stays: {RESTORE_GUIDANCE}",
            )
        lines, _unterminated = self._split_prose(self._decode_mirror(prefix))
        self._lines_are_prose(es, lines, unterminated=False, excess_ok=False)

    def check_mirror(self, es: list[dict[str, Any]], *, excess_ok: bool) -> None:
        """The mirror as it is NOW against the entries `es` it corresponds to (the
        chain a standing intent retains, plus the audit that landed past its cut
        point), nothing written: what every RESUMED repair stage checks before any
        cut, marker advance or marker removal, so a mirror edited while the intent
        stood is refused by name with the file and the marker as found, never cut
        into or advanced over. Every whole line at an index below the entry count
        is its entry's prose; an unterminated last line at such an index is that
        line or a non-blank strict prefix of it (a regeneration of ours that tore:
        the stage's mend completes it); anything else there is
        ledger.prose.mismatch naming the line. A line beyond the entries is, with
        `excess_ok`, a non-blank line the stage cuts (the ledger's own tail stage:
        a line written for the entry the torn append never made durable; a blank
        one is ledger.repair.refused) and otherwise ledger.prose.mismatch. A mirror
        that does not decode: the whole lines before the damage are checked the
        same way, and the damage from its line on is the stage's cut under its
        intent (`cut_undecodable_tail`) when that line is inside the entries (a
        torn regeneration) or `excess_ok`; beyond the entries otherwise it is
        ledger.prose.mismatch. The WHOLE cut the stage would then make — the
        damaged line and everything after it — is checked for a blank physical
        line here (`_no_blank_cut`, ledger.repair.refused), so the refusal the cut
        would raise comes BEFORE any cut of either file (round-14 self-gate: a
        blank line after an undecodable one passed this check and refused only
        after the JSONL's tail was cut and the marker advanced)."""
        data = self._prose_bytes()
        damaged: int | None = None
        cut = len(data)
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as e:
            # UTF-8 decoding is sequential: everything before the first offending
            # byte decodes, and the line it is in starts after the newline before it
            cut = data.rfind(b"\n", 0, e.start) + 1
            text, damaged = data[:cut].decode("utf-8"), e.start
        lines, unterminated = self._split_prose(text)
        self._lines_are_prose(es, lines, unterminated=unterminated, excess_ok=excess_ok)
        if damaged is None:
            return
        if len(lines) >= len(es) and not excess_ok:
            raise IntegrityError(
                "ledger.prose.mismatch",
                f"{self.prose_path}: not UTF-8 at byte offset {damaged}, in prose line "
                f"{len(lines)} beyond the {len(es)} entries; not a torn regeneration of this "
                f"repair, nothing cut, the intent stays: {RESTORE_GUIDANCE}",
            )
        self._no_blank_cut(data[cut:], len(lines))

    def _lines_are_prose(
        self,
        es: list[dict[str, Any]],
        lines: list[str],
        *,
        unterminated: bool,
        excess_ok: bool,
    ) -> None:
        for i, p in enumerate(lines):
            last_partial = unterminated and i == len(lines) - 1
            if i < len(es):
                expected = prose_line(es[i], entry_hash(es[i]))
                if p == expected:
                    continue
                if last_partial and not is_blank_text(p) and expected.startswith(p):
                    continue  # a torn regeneration of ours: the stage's mend completes it
                how = "(unterminated) is not a prefix of" if last_partial else "does not match"
                raise IntegrityError(
                    "ledger.prose.mismatch",
                    f"{self.prose_path}: prose line {i} {how} entry {i}; nothing cut, the "
                    f"intent stays: {RESTORE_GUIDANCE}",
                )
            if not excess_ok:
                raise IntegrityError(
                    "ledger.prose.mismatch",
                    f"{self.prose_path}: prose line {i} is beyond the {len(es)} entries; "
                    f"nothing cut, the intent stays: {RESTORE_GUIDANCE}",
                )
            if is_blank_text(p):
                raise IntegrityError(
                    "ledger.repair.refused",
                    f"{self.prose_path}: prose line {i} is blank ({len(p)} byte(s) of "
                    f"whitespace) where a line of this ledger's prose or nothing belongs; not "
                    f"an excess line to cut, nothing written: {RESTORE_GUIDANCE}",
                )

    def entries(self) -> list[dict[str, Any]]:
        """The chain as it is on disk right now: re-read when the file changed, the
        prev_hash chain checked on every load (another process may have appended)."""
        key = self._file_key()
        if self._entries is None or key != self._loaded_key:
            self._entries = self._load()
            self._loaded_key = key
        return self._entries

    def head(self) -> str:
        es = self.entries()
        return entry_hash(es[-1]) if es else GENESIS

    def __len__(self) -> int:
        return len(self.entries())

    def find_msg(self, msg_id: str) -> dict[str, Any] | None:
        """The INBOUND completion entry for msg_id: an action applied / refused /
        failed, or information received. Matched on direction "in" only — never an
        outbound entry, whatever the inbound request called its action (even
        "out.ack"). A legacy entry (no direction field) is inbound."""
        for e in self.entries():
            if (
                e.get("msg_id") == msg_id
                and direction_of(e) == "in"
                and outcome_kind(e["outcome"]) in MESSAGE_OUTCOMES
            ):
                return e
        return None

    def uses(self, grant_id: str, since: datetime | None = None) -> int:
        n = 0
        for e in self.entries():
            if e["grant_id"] == grant_id and e["outcome"] in USE_OUTCOMES:
                if since is None or parse(e["ts"]) >= since:
                    n += 1
        return n

    # ---- write ----
    def append(
        self,
        *,
        ts: str,
        actor: str,
        grant_id: str | None,
        action: str,
        params_hash: str | None,
        outcome: str,
        msg_id: str | None = None,
        detail: str = "",
        direction: str = "in",
        intent_id: str | None = None,
    ) -> dict[str, Any]:
        """One entry appended: the repair machine's audits pass `intent_id` (an rpr_
        id in full), carried as the entry's own field — the id a resumed repair
        matches by equality (`Node._repair_audit`); every other entry has no such
        field, and an entry without it hashes as it always did."""
        if direction not in DIRECTIONS:
            raise ValueError(f"ledger direction {direction!r} is not one of {DIRECTIONS}")
        if intent_id is not None and not is_id(intent_id, "rpr_"):
            raise ValueError(f"ledger intent_id {intent_id!r} is not rpr_<26-char ULID> in full")
        if self.guard is not None:
            self.guard()  # an unfinished mirror repair refuses every append (IntegrityError)
        # the mirror must be whole (or repaired to whole) BEFORE another line lands
        self.sync_prose()
        e = {
            "ts": ts,
            "actor": actor,
            "grant_id": grant_id,
            "action": action,
            "params_hash": params_hash,
            "outcome": outcome,
            "prev_hash": self.head(),
            "msg_id": msg_id,
            "detail": detail[:500],
            "direction": direction,
        }
        if intent_id is not None:
            e["intent_id"] = intent_id
        h = entry_hash(e)
        line = json.dumps(e, ensure_ascii=False, separators=(",", ":"))
        prose = prose_line(e, h)
        append_line(self.path, line)  # the line, the file, then the directory
        self._entries = None  # next read re-loads and re-verifies what landed on disk
        self._append_prose([prose])
        return e

    def _append_prose(self, lines: list[str]) -> None:
        append_lines(self.prose_path, lines)

    def barrier(self) -> None:
        """Re-establish durability for everything VISIBLE in both files, then make the
        mirror whole: the JSONL and the prose mirror fsynced (file, then directory),
        then sync_prose (a missing trailing line regenerated, an unterminated one
        terminated). The step before a caller promotes something it found in the
        ledger to another durable record — a recovered completion to a stored ack —
        since the entry it found may be an unsynced tail whose append failed after
        the bytes became visible; the promotion must not outlive it."""
        for p in (self.path, self.prose_path):
            if p.exists():
                fsync_existing(p)
        self.sync_prose()

    # ---- verify / repair ----
    def _prose_bytes(self) -> bytes:
        return self.prose_path.read_bytes() if self.prose_path.exists() else b""

    def _decode_mirror(self, data: bytes) -> str:
        """The mirror's bytes as text. A mirror that does not decode is local
        corruption — IntegrityError ledger.mirror_corrupt naming the path and the
        byte offset where decoding failed — a storage failure wherever the mirror
        is read, never an exception out of a poll."""
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as e:
            raise IntegrityError(
                "ledger.mirror_corrupt",
                f"{self.prose_path}: not UTF-8 at byte offset {e.start} ({e.reason}); "
                f"`natively ledger repair` rebuilds the mirror from the JSONL when the JSONL "
                f"verifies",
            ) from e

    @staticmethod
    def _split_prose(text: str) -> tuple[list[str], bool]:
        if not text:
            return [], False
        lines = text.split("\n")
        if text.endswith("\n"):
            return lines[:-1], False
        return lines, True

    def _prose_state(self) -> tuple[list[str], bool]:
        """The mirror's PHYSICAL lines and whether its final line is UNTERMINATED (no
        newline: a crash inside the prose write). Nothing is stripped or skipped: a
        blank or whitespace-only line is a line that matches no entry, and an
        unterminated whitespace tail is exactly that, never "no line". A mirror that
        does not decode is ledger.mirror_corrupt (`_decode_mirror`)."""
        return self._split_prose(self._decode_mirror(self._prose_bytes()))

    def _prose_lines(self) -> list[str]:
        return self._prose_state()[0]

    def _terminate_prose(self) -> None:
        """The final line is its entry's prose and only the newline is missing: put
        it there (durably), so the next append lands on its own line."""
        append_text(self.prose_path, "\n")

    def _check_fields(self, es: list[dict[str, Any]]) -> str:
        """The head of a loaded chain, the chain recomputed from genesis (every
        entry was checked in full at its load, `_entry_shape`); a chain fault is
        local corruption — IntegrityError ledger.chain naming the path and the
        entry — never a verdict on peer input."""
        prev = GENESIS
        for i, e in enumerate(es):
            _entry_shape(e, i + 1, self.path)
            if e["prev_hash"] != prev:
                raise IntegrityError(
                    "ledger.chain", f"{self.path}: entry {i} prev_hash {e['prev_hash']} != {prev}"
                )
            prev = entry_hash(e)
        return prev

    def _check_entries(self) -> tuple[list[dict[str, Any]], str]:
        self._entries = None
        es = self.entries()
        return es, self._check_fields(es)

    def verify(self) -> str:
        """Recompute the chain and regenerate every prose line, comparing whole lines.
        Returns the head. Every fault is IntegrityError: the JSONL's by its name
        (`_load_bytes`, `_check_fields`), the mirror's ledger.prose.* naming the
        path — both are files of ours, never peer input."""
        es, head = self._check_entries()
        prose, unterminated = self._prose_state()
        if unterminated:
            raise IntegrityError(
                "ledger.prose.unterminated",
                f"{self.prose_path}: the last prose line ({len(prose) - 1}) has no newline "
                f"(interrupted write); `natively ledger repair` terminates it when it is its "
                f"entry's prose",
            )
        if len(prose) != len(es):
            raise IntegrityError(
                "ledger.prose.count",
                f"{self.prose_path}: {len(prose)} prose lines for {len(es)} entries",
            )
        for i, (e, p) in enumerate(zip(es, prose, strict=True)):
            if p != prose_line(e, entry_hash(e)):
                raise IntegrityError(
                    "ledger.prose.mismatch", f"{self.prose_path}: prose line {i} is not entry {i}"
                )
        self._check_anchors(es)
        return head

    def _prose_gap(
        self, es: list[dict[str, Any]], reason: str
    ) -> tuple[list[dict[str, Any]], bool]:
        """What the mirror is short by at its END: the entries whose prose line is
        missing, and whether the final physical line is its entry's prose short of
        only its newline. Nothing is written here. Any other difference between the
        two files (more prose than entries, a line that is not its entry, an
        unterminated line that is not its entry) is an IntegrityError with `reason` and
        the same restore guidance (more prose than entries: `natively ledger repair`
        truncates the mirror to the JSONL, see excess_prose)."""
        prose, unterminated = self._prose_state()
        if len(prose) > len(es):
            raise IntegrityError(
                reason,
                f"{self.prose_path}: {len(prose)} prose lines for {len(es)} entries: "
                f"{RESTORE_GUIDANCE}",
            )
        for i, (e, p) in enumerate(zip(es, prose, strict=False)):
            if p != prose_line(e, entry_hash(e)):
                raise IntegrityError(
                    reason,
                    f"{self.prose_path}: prose line {i} does not match entry {i}: "
                    f"{RESTORE_GUIDANCE}",
                )
        # when unterminated: every physical line matched its entry exactly, the last
        # one included, so it is its entry's prose short of its newline (a
        # whitespace-only or otherwise unmatched tail was refused above)
        return es[len(prose) :], unterminated

    def _mend_prose(self, missing: list[dict[str, Any]], terminate: bool) -> int:
        """Write what the mirror is short by — the JSONL FIRST. The JSONL is the
        source of truth and the mirror only ever mirrors durable entries: a prose
        line written for an entry whose own append failed after its bytes became
        visible would outlive that entry on power loss, and the mirror would then
        exceed the ledger. So the JSONL file and its directory are fsynced before
        any mirror write (a barrier that raises stops here, the mirror untouched),
        then the newline, then the missing lines. Returns lines written."""
        if not missing and not terminate:
            return 0
        fsync_existing(self.path)  # the entries the mirror is about to stand on
        if terminate:
            self._terminate_prose()
        if missing:
            self._append_prose([prose_line(e, entry_hash(e)) for e in missing])
        return len(missing)

    def sync_prose(self) -> int:
        """Before an append: the mirror is complete, or short by a trailing suffix
        (a crash between the two writes) that is regenerated here, or ends in an
        unterminated line that is its entry's prose (terminated here) — the JSONL
        fsynced before either write; anything else is ledger.prose.mismatch and the
        append is refused. Returns lines written."""
        missing, terminate = self._prose_gap(self.entries(), "ledger.prose.mismatch")
        return self._mend_prose(missing, terminate)

    def repair(self) -> int:
        """Append the prose lines missing at the END of the mirror (an append that
        crashed between the JSONL write and the prose write), terminating an
        unterminated final line first when it is its entry's prose; the JSONL (file,
        then directory) is fsynced BEFORE either mirror write, and a barrier that
        raises leaves the mirror untouched. Every existing prose line must match its
        entry and the chain must verify; anything else is refused (more prose than
        entries is the one refusal `Node.repair_ledger` resolves, by truncating the
        mirror). Returns the number of lines written. A mirror found already whole
        (nothing to write, nothing to terminate) is fsynced with its JSONL (file,
        then directory) before 0 is returned: a retry after a repair whose barrier
        failed AFTER its line became visible re-establishes the barrier rather than
        reporting success on visible bytes."""
        es = self._checked_chain()
        missing, terminate = self._prose_gap(es, "ledger.repair.refused")
        if missing or terminate:
            return self._mend_prose(missing, terminate)
        for p in (self.path, self.prose_path):
            if p.exists():
                fsync_existing(p)
        return 0

    def cut_undecodable_tail(self) -> int:
        """Inside a repair whose intent already stands: the regeneration that
        followed the cut may itself have torn (power loss inside a multibyte
        character of a regenerated line), and the audit append that resumes the
        machine would then meet ledger.mirror_corrupt forever. The mirror is cut
        back to its sound lines here, durably (file, then directory), so the
        append's own regeneration can land; every sound line must be its entry's
        prose and the JSONL must verify, as for `excess_prose`. Returns the bytes
        cut, 0 for a mirror that decodes. Only the repair verb calls this."""
        es = self._checked_chain()
        data = self._prose_bytes()
        try:
            data.decode("utf-8")
            return 0
        except UnicodeDecodeError as e:
            tail = self._undecodable_tail(es, data, e.start)
        with open(self.prose_path, "r+b") as f:
            f.truncate(len(data) - len(tail))
            f.flush()
            os.fsync(f.fileno())
        fsync_dir(self.prose_path.parent)
        return len(tail)

    def mend_torn_prose_tail(self) -> int:
        """Inside a repair whose intent already stands: a prose write of an earlier
        run of this same intent (the lines regenerated before the audit, the
        audit's own line) may have torn AFTER an ASCII prefix — a DECODABLE partial
        final line without its newline, which `cut_undecodable_tail` leaves and the
        audit append's barrier would then refuse forever (ledger.prose.mismatch).
        Recognised here, under the intent: every prose line before it is its
        entry's prose (else ledger.repair.refused, nothing written), the partial
        line is a non-blank STRICT prefix of the expected prose line of the entry
        at its index, regenerated from that entry (else ledger.prose.mismatch, the
        marker standing, nothing written), and the rest of that line with its
        newline is written durably (the JSONL fsynced first, as before every
        mirror write) so the line is the regenerated one and the barrier can run.
        Returns the bytes written: 0 for a mirror ending in its newline, or ending
        in a whole line short of only its newline (`sync_prose` terminates that).
        Only the repair verb calls this."""
        es = self._checked_chain()
        prose, unterminated = self._prose_state()
        if not unterminated:
            return 0
        partial, i = prose[-1], len(prose) - 1
        if i >= len(es):
            raise IntegrityError(
                "ledger.prose.mismatch",
                f"{self.prose_path}: the unterminated last prose line ({i}) is beyond the "
                f"{len(es)} entries; not a torn regeneration, nothing written: {RESTORE_GUIDANCE}",
            )
        self._prefix_is_prose(es[:i], prose[:i])
        expected = prose_line(es[i], entry_hash(es[i]))
        if partial == expected:
            return 0  # short of only its newline: the barrier terminates it
        if is_blank_text(partial) or not expected.startswith(partial):
            raise IntegrityError(
                "ledger.prose.mismatch",
                f"{self.prose_path}: the unterminated last prose line ({i}) is not a prefix of "
                f"entry {i}'s prose; not a torn regeneration, nothing written: {RESTORE_GUIDANCE}",
            )
        fsync_existing(self.path)  # the entry the regenerated line stands on
        rest = expected[len(partial) :] + "\n"
        append_text(self.prose_path, rest)
        return len(rest.encode("utf-8"))

    def excess_prose(self) -> bytes:
        """The bytes of the mirror beyond the JSONL's entries — the artifact of exactly
        one sequence: a prose line was written (by an older repair, or by hand) for an
        entry whose own JSONL append had failed after its bytes became visible, and a
        power cut then removed that unsynced JSONL tail. Empty when the mirror has no
        more lines than entries. Every prose line up to the entry count must match
        its entry and the chain must verify; anything else is refused
        (ledger.repair.refused) as not this ledger's mirror. JSONL entries are never
        invented from prose: `Node.repair_ledger` truncates these bytes, durably, and
        ledgers `ledger.mirror_truncated`.

        The other artifact this names: a mirror that does not DECODE (a write torn
        inside a multibyte character). The JSONL verified above, so the mirror is the
        only damaged side: the bytes from the start of the damaged line on — and
        from the entry count on, when the whole lines before the damage already
        exceed it — are the excess, provided every whole line before them is its
        entry's prose (else refused the same way); `repair()` regenerates every line
        cut, from the JSONL."""
        es = self._checked_chain()
        data = self._prose_bytes()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as e:
            return self._undecodable_tail(es, data, e.start)
        prose, _unterminated = self._split_prose(text)
        if len(prose) <= len(es):
            return b""
        self._prefix_is_prose(es, prose)
        self._no_blank_excess(prose[len(es) :], len(es))
        return data[self._offset_after(data, len(es)) :]

    def _no_blank_excess(self, lines: list[str], first: int) -> None:
        """The excess `ledger repair` cuts is prose lines written for entries that
        never became durable — never a blank or whitespace-only physical line: a
        blank line is a mirror mismatch by its name (ledger.repair.refused here),
        never something the repair removes; the operator restores the file."""
        for i, p in enumerate(lines):
            if is_blank_text(p):
                raise IntegrityError(
                    "ledger.repair.refused",
                    f"{self.prose_path}: prose line {first + i} is blank ({len(p)} byte(s) of "
                    f"whitespace) where a line of this ledger's prose or nothing belongs; not "
                    f"an excess line to cut, nothing written: {RESTORE_GUIDANCE}",
                )

    def _prefix_is_prose(self, es: list[dict[str, Any]], prose: list[str]) -> None:
        for i, (e, p) in enumerate(zip(es, prose, strict=False)):
            if p != prose_line(e, entry_hash(e)):
                raise IntegrityError(
                    "ledger.repair.refused",
                    f"{self.prose_path}: prose line {i} does not match entry {i}: "
                    f"{RESTORE_GUIDANCE}",
                )

    def cut_excess_prose(self) -> int:
        """Inside the repair of the JSONL's own tail, whose intent already stands
        (the ledger closed to every other writer): once the torn tail is cut, a
        mirror line written for the entry that never became durable (by an older
        tool, before the power cut) is beyond the JSONL's entries, and the audit
        append that finishes the machine would refuse the mismatch forever. The
        excess (`excess_prose`: the lines beyond the entries, or a tail that does
        not decode, every whole line kept being its entry's prose) is cut here,
        durably (the file, then the directory), so that append can land and
        regenerate what the cut removed. Returns the bytes cut, 0 for a mirror
        that is not beyond the JSONL. Only the repair verb calls this."""
        tail = self.excess_prose()
        if not tail:
            return 0
        data = self._prose_bytes()
        with open(self.prose_path, "r+b") as f:
            f.truncate(len(data) - len(tail))
            f.flush()
            os.fsync(f.fileno())
        fsync_dir(self.prose_path.parent)
        return len(tail)

    @staticmethod
    def _offset_after(data: bytes, lines: int) -> int:
        """The byte offset just past `lines` newline-terminated lines of `data`."""
        keep = 0
        for _ in range(lines):
            keep = data.index(b"\n", keep) + 1
        return keep

    def _undecodable_tail(self, es: list[dict[str, Any]], data: bytes, bad: int) -> bytes:
        """The bytes to cut from a mirror whose decoding failed at byte `bad`: from
        the start of the line the damage is in (everything before that offset
        decodes: UTF-8 decoding is sequential, `bad` is the first offending byte),
        or from the entry count when the whole lines before the damage are more
        than the entries. Every whole line kept must be its entry's prose."""
        cut = data.rfind(b"\n", 0, bad) + 1  # the start of the damaged line
        whole = self._split_prose(data[:cut].decode("utf-8"))[0]
        keep = min(len(whole), len(es))
        self._prefix_is_prose(es[:keep], whole[:keep])
        tail = data[self._offset_after(data, keep) :]
        self._no_blank_cut(tail, keep)
        return tail

    def _no_blank_cut(self, tail: bytes, first: int) -> None:
        """The WHOLE proposed cut, checked before any mutation: every physical line
        of `tail` — the sound lines beyond the entries, the line that does not
        decode, and everything after it — is either undecodable or a decodable
        non-blank line; a blank physical line (durable.is_blank_line) anywhere in
        it is ledger.repair.refused with the mirror untouched. (Checking only the
        lines before the damage and returning the rest let a blank line after an
        undecodable one ride out with the cut: round-12 gate, finding 4.)"""
        lines = tail.split(b"\n")
        for i, raw in enumerate(lines):
            if i == len(lines) - 1 and not raw:
                break  # the synthetic empty element after the final newline
            if is_blank_line(raw):
                raise IntegrityError(
                    "ledger.repair.refused",
                    f"{self.prose_path}: prose line {first + i} is blank ({len(raw)} byte(s) of "
                    f"whitespace) where a line of this ledger's prose or nothing belongs; not "
                    f"an excess line to cut, nothing written: {RESTORE_GUIDANCE}",
                )


def direction_of(e: dict[str, Any]) -> str:
    """The entry's direction; a legacy entry without the field is inbound."""
    return e.get("direction", "in")


def prose_line(e: dict[str, Any], h: str) -> str:
    g = f" under {one_line(e['grant_id'])}" if e["grant_id"] else " (no grant)"
    m = f" msg {one_line(e['msg_id'])}" if e.get("msg_id") else ""
    d = f" — {one_line(e['detail'])}" if e.get("detail") else ""
    # the arrow rule: only an explicit "out" turns it; a legacy entry renders as it
    # did before the field existed, so an existing mirror still verifies
    arrow = "<-" if direction_of(e) == "out" else "->"
    return (
        f"{one_line(e['ts'])}  {one_line(e['actor'])}: {one_line(e['action'])}{g}{m}"
        f" {arrow} {one_line(e['outcome'])}{d} [{h[7:19]}]"
    )

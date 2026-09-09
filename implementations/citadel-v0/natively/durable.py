"""Durable file writes, shared by every module that persists state (the node, the
revocation feed, the denial store, the ledger, the mail adapter). One rule everywhere:
a file is written to a temp name, fsynced, renamed over the target, and the
containing directory is fsynced, so nothing that was acknowledged can vanish on power
loss and nothing is ever half written in place. An append is written, the file
fsynced, then the directory fsynced (a freshly created file's entry needs it too).

A retry after a write whose barrier failed AFTER the bytes became visible must
re-establish the barrier before it reports success: `fsync_existing` is that
second barrier (file, then directory) for a caller that finds its bytes already
on disk."""

from __future__ import annotations

import json
import os
import re
import tempfile
import unicodedata
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .errors import IntegrityError


class DuplicateMember(ValueError):
    """A member name repeated inside one object of a file of ours. This node's writers
    emit each member once, so the fault is corruption wherever it is met — never a
    torn write of ours, whatever else the text looks like (`is_torn_text`)."""


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """The object hook of every LOCAL parse: a member name that repeats inside one
    object is refused (ValueError, which the callers turn into that file's
    corruption name). Python's default keeps the LAST value, so a seen.json with one
    message key twice would erase the first reservation from enforcement and could
    release a consumed use after an interrupted execution (round-19 gate, finding 3);
    the peer-input parser (jsonsafe) refuses duplicates the same way at its own
    boundary."""
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise DuplicateMember(f"duplicate member name {k!r} in one object")
        out[k] = v
    return out


def parse_local(raw: bytes | str) -> Any:
    """Parse text this node wrote, with the ONE local object rule (`_no_duplicates`).
    Raises what json.loads raises, plus UnicodeDecodeError on bytes that are not
    UTF-8 and ValueError on a duplicate member; the caller names the file. Every
    parse of a file of ours — a state file (`load_local`), a line of the ledger, the
    feed or the denial store — comes through here, never through a bare json.loads."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    return json.loads(raw, object_pairs_hook=_no_duplicates)


def is_torn_text(raw: bytes | str) -> bool:
    """Whether `raw` reads as a TORN write of ours (`torn_text_problem` is None)."""
    return torn_text_problem(raw) is None


def torn_text_problem(raw: bytes | str) -> str | None:
    """None when `raw` is a repairable TEAR — a strict prefix of exactly one
    well-formed record of ours — else what was found. THE ONE PREFIX RULE the three
    JSONL stores' unterminated-tail decisions share (`Ledger._load_bytes`,
    `Ledger._tail_is_entry`, the feed's and the denial store's `load` and
    `torn_tail`): the bytes decode as UTF-8, or fail to decode only at their very end
    inside a string (an incomplete character); the text parses as an unterminated
    single JSON object — one that opens and never closes, cut inside a string, a
    number, a literal or between tokens — with no member named twice so far and no
    complete object before it on the line. Anything else is bytes this node never
    wrote and is the store's corruption by name, never a torn write to cut: a member
    repeated (whole or not), a whole object (the store judged it first and refused
    it), a second object or trailing bytes after a whole one, an invalid byte, an
    invalid escape or a control character inside a string, an incomplete character
    where only ASCII belongs (outside a string, after a backslash, inside the hex
    digits of a `\\u` escape), a Unicode digit inside a number. Before, any parse
    failure without a visible duplicate was a tear, and two whole objects on one
    line, an object followed by garbage or a NUL byte, an invalid byte mid-line and
    a duplicate before an incomplete character were all cut by the repair verbs
    (round-19 gate R4, Fable C1)."""
    cut = False
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            if e.reason != "unexpected end of data" or e.end != len(raw):
                return f"an invalid byte at offset {e.start} ({e.reason})"
            text = raw[: e.start].decode("utf-8")
            cut = True
    else:
        text = raw
    kind, detail = _scan_object_prefix(text)
    if kind == "corrupt":
        return detail
    if kind == "whole":
        return "a whole object" + (" followed by an incomplete character" if cut else "")
    if cut and detail != "string":
        where = "inside an escape" if detail == "escape" else "outside a string"
        return f"an incomplete character {where}, where only ASCII belongs"
    return None


# JSON digits are ASCII: `[0-9]`, never `\d` (Unicode digits such as U+0661 can complete
# no JSON number, so a prefix carrying one is corruption; round-20 self-gate, finding 2)
_NUMBER_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
# every strict prefix of a JSON number (`-`, `1.`, `1e`, `1e+`, `1.5e-3`)
_NUMBER_PREFIX_RE = re.compile(
    r"-?(?:(?:0|[1-9][0-9]*)(?:\.[0-9]*)?(?:(?<=[0-9])[eE](?:[+-]?[0-9]*)?)?)?"
)
_WS = " \t\r\n"
_HEX = "0123456789abcdefABCDEF"


def _scan_string(text: str, i: int) -> tuple[str, int | str]:
    """A JSON string starting at the quote at `i`: ("ok", the index after its closing
    quote); ("torn", "string") when the text ends inside ordinary string content,
    ("torn", "escape") when it ends after a backslash or inside the hex digits of a
    `\\u` escape — only ordinary content may be followed by an incomplete UTF-8
    character, since an escape letter and a hex digit are ASCII (round-20 self-gate,
    finding 1); or ("corrupt", why)."""
    n, j = len(text), i + 1
    while j < n:
        c = text[j]
        if c == '"':
            return "ok", j + 1
        if c == "\\":
            if j + 1 >= n:
                return "torn", "escape"
            e = text[j + 1]
            if e in '"\\/bfnrt':
                j += 2
                continue
            if e == "u":
                hexes = text[j + 2 : j + 6]
                if all(h in _HEX for h in hexes):
                    if len(hexes) == 4:
                        j += 6
                        continue
                    if j + 2 + len(hexes) == n:
                        return "torn", "escape"
                return "corrupt", f"an invalid \\u escape at offset {j}"
            return "corrupt", f"an invalid escape '\\{e}' at offset {j}"
        if ord(c) < 0x20:
            return "corrupt", f"a control character inside a string at offset {j}"
        j += 1
    return "torn", "string"


def _scan_object_prefix(text: str) -> tuple[str, str]:
    """("whole", ""), ("torn", where: "string" or "token"), or ("corrupt", why) for
    JSON text that must be one object or a strict prefix of one. Member names are
    read as the parser reads them (escapes decoded) and a name repeated inside one
    object is corruption wherever the scan is."""
    n, i = len(text), 0
    # per open container: ("obj", names, state) or ("arr", None, state)
    stack: list[list[Any]] = []

    def closed() -> tuple[str, str] | None:
        stack.pop()
        if stack:
            stack[-1][2] = "next"
            return None
        k = i
        while k < n and text[k] in _WS:
            k += 1
        if k < n:
            return "corrupt", f"bytes after a whole object at offset {k}"
        return "whole", ""

    while True:
        while i < n and text[i] in _WS:
            i += 1
        if i >= n:
            return "torn", "token"
        c = text[i]
        if not stack:
            if c != "{":
                return "corrupt", f"does not begin with an object ({c!r} at offset {i})"
            stack.append(["obj", set(), "key0"])
            i += 1
            continue
        kind, names, state = stack[-1]
        if state in ("key0", "key"):
            if c == "}" and state == "key0":
                i += 1
                done = closed()
                if done:
                    return done
                continue
            if c != '"':
                return "corrupt", f"expected a member name, found {c!r} at offset {i}"
            r, at = _scan_string(text, i)
            if r == "torn":
                return "torn", str(at)
            if r == "corrupt":
                return "corrupt", str(at)
            try:
                name = json.loads(text[i:at])
            except ValueError:
                return "corrupt", f"an invalid member name at offset {i}"
            if name in names:
                return "corrupt", f"duplicate member name {name!r} in one object"
            names.add(name)
            stack[-1][2] = "colon"
            i = at
            continue
        if state == "colon":
            if c != ":":
                return "corrupt", f"expected ':' after a member name, found {c!r} at offset {i}"
            stack[-1][2] = "value"
            i += 1
            continue
        if state == "next":
            if c == ",":
                stack[-1][2] = "key" if kind == "obj" else "value"
                i += 1
                continue
            if c == ("}" if kind == "obj" else "]"):
                i += 1
                done = closed()
                if done:
                    return done
                continue
            return "corrupt", f"expected ',' or a closing bracket, found {c!r} at offset {i}"
        # a value is expected (state "value", or "value0" in a fresh array)
        if c == "]" and kind == "arr" and state == "value0":
            i += 1
            done = closed()
            if done:
                return done
            continue
        if c == '"':
            r, at = _scan_string(text, i)
            if r == "torn":
                return "torn", str(at)
            if r == "corrupt":
                return "corrupt", str(at)
            stack[-1][2] = "next"
            i = at
            continue
        if c == "{":
            stack.append(["obj", set(), "key0"])
            i += 1
            continue
        if c == "[":
            stack.append(["arr", None, "value0"])
            i += 1
            continue
        if c in "tfn":
            for lit in ("true", "false", "null"):
                if text.startswith(lit, i):
                    stack[-1][2] = "next"
                    i += len(lit)
                    break
                if lit.startswith(text[i:]):
                    return "torn", "token"
            else:
                return "corrupt", f"an invalid token at offset {i}"
            continue
        if c == "-" or c in "0123456789":
            m = _NUMBER_RE.match(text, i)
            if m and m.end() < n and text[m.end()] in _WS + ",}]":
                stack[-1][2] = "next"
                i = m.end()
                continue
            if _NUMBER_PREFIX_RE.fullmatch(text, i):
                return "torn", "token"
            return "corrupt", f"an invalid number at offset {i}"
        return "corrupt", f"an unexpected character {c!r} at offset {i}"


# the Unicode general categories a blank line is made of: space separators (Zs:
# U+0020, U+00A0, U+2003, U+202F, ...), the line and paragraph separators (Zl, Zp),
# control characters (Cc: tab, CR, VT, FF, ...) and format characters (Cf: U+200B,
# U+FEFF, ...). bytes.strip() knows ASCII whitespace only, so a record replaced by
# U+00A0s read as a torn write to cut (round-12 gate, finding 3)
_BLANK_CATEGORIES = frozenset({"Zs", "Zl", "Zp", "Cc", "Cf"})
# the process umask, read once at import (os.umask can only be read by setting it):
# write_json gives its temp file the mode a plain open() would have
_UMASK = os.umask(0)
os.umask(_UMASK)


def is_blank_text(s: str) -> bool:
    """A physical line of TEXT is blank when it is empty or every code point is a
    separator, a control or a format character (`_BLANK_CATEGORIES`) — the ONE
    blank-line rule of every file of ours, Unicode-aware, shared by every reader of
    the three JSONL stores and of the prose mirror."""
    return all(unicodedata.category(ch) in _BLANK_CATEGORIES for ch in s)


def is_blank_line(raw: bytes) -> bool:
    """The same rule on a physical line of BYTES: empty, or a UTF-8 decode made only
    of blank code points. A line that does not decode as UTF-8 is never blank (it is
    corrupt by the store's name, or, only as the unterminated final line that is not
    a whole object, torn)."""
    if not raw:
        return True
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return is_blank_text(text)


def physical_lines(data: bytes, path: Path, reason: str) -> Iterator[tuple[int, bytes]]:
    """The physical lines of a JSONL file of OURS (the ledger, the feed, the denial
    store), numbered from 1, in order — the ONE line reader every loader, prefix
    check, tail check and repair verb of those files uses. The ONLY element skipped
    is the synthetic empty string after the final newline (the artefact of splitting
    a terminated file); a physical line that is empty or whitespace-only is local
    corruption — IntegrityError `reason` naming the path and the line — never a
    line to skip: a record replaced by spaces would otherwise disappear from
    enforcement with the file still loading. The unterminated final line of a file
    that does not end in its newline is yielded like any other (the caller judges
    it torn or whole); a whitespace-only one is corruption here, never torn. Blank
    is `is_blank_line`: Unicode-aware (U+00A0, U+2003, U+202F, U+200B, U+FEFF and
    the like count), a line that does not decode never blank."""
    lines = data.split(b"\n")
    for ln, raw in enumerate(lines, 1):
        if ln == len(lines) and not raw:
            return  # the synthetic empty element after the final newline (or an empty file)
        if is_blank_line(raw):
            raise IntegrityError(
                reason,
                f"{path} line {ln}: a blank line ({len(raw)} byte(s) of whitespace"
                f"{'' if ln < len(lines) else ', no newline'}) where a record belongs; "
                f"not a torn write, nothing cut: restore the file",
            )
        yield ln, raw


def load_local(raw: bytes | str, what: str) -> Any:
    """Parse a file THIS node wrote. Every parser failure — a syntax error, a
    decoding error, an integer literal past the parser's digit limit (ValueError),
    a value nested past the recursion limit (RecursionError), a member name that
    repeats inside one object (`parse_local`) — is local corruption: an
    IntegrityError (a storage failure), never a failure attributed to peer input."""
    try:
        return parse_local(raw)
    except (UnicodeDecodeError, ValueError, RecursionError) as ex:
        raise IntegrityError("state.corrupt", f"{what}: {type(ex).__name__}: {ex}") from ex


def read_json(p: Path, default: Any) -> Any:
    """A state file (a reservation, a cursor, a seen file, a held copy): absent is
    `default`; present but not parsing is IntegrityError (see load_local), named by
    the file's path."""
    if not p.exists():
        return default
    return load_local(p.read_bytes(), str(p))


def list_dir(d: Path, suffix: str = "") -> list[Path]:
    """The entries of a state directory whose names end with `suffix`, sorted. The
    ONLY way a state directory is enumerated: built on os.scandir, so every OSError
    (PermissionError included) propagates to the caller as the storage failure it is
    — Path.glob and Path.iterdir swallow an unreadable directory into "empty", and an
    empty revocations-pending/ is an authorization decision. A directory that does
    not exist yet is empty (it is created on its first write); anything else that
    goes wrong is raised."""
    d = Path(d)
    try:
        it = os.scandir(d)
    except FileNotFoundError:
        return []  # only the ABSENT directory is "empty"; nothing past this point is
    with it:
        # a failure while iterating (the directory vanished, an I/O error, a
        # permission change) propagates: a listing cut short is not a listing
        names = [e.name for e in it if e.name.endswith(suffix)]
    return [d / n for n in sorted(names)]


def fsync_dir(d: Path) -> None:
    """Make a rename or an append inside `d` durable: the file's bytes were synced,
    but without this the directory entry that names them can still be lost on power
    loss."""
    fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def fsync_existing(p: Path) -> None:
    """The durability barrier for bytes that are already visible at `p` (a retry
    after a failed fsync): the file, then its directory. Cheap, and the only way a
    caller may treat a "found it already there" as durable."""
    fd = os.open(p, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_dir(p.parent)


def write_json(p: Path, v: Any) -> None:
    """Atomic and durable: temp file fsynced, renamed over the target, then the
    containing directory fsynced (a reservation must survive a power cut before the
    executor runs). Never an in-place write. The temp file is created EXCLUSIVELY
    under a unique name in the target's directory (mkstemp: O_CREAT|O_EXCL), so two
    writers of one target each rename their own bytes and never each other's — with
    one fixed temp name (`<file>.tmp`) the second writer's open truncated the first
    writer's inode, one process then reported success over the other's content and
    the other raised at its rename (round-19 gate, finding 2; Fable I1, 6 of 6
    trials). A temp file left by a failure is removed before the error propagates."""
    p = Path(p)
    fd, tmp_name = tempfile.mkstemp(prefix=p.name + ".", suffix=".tmp", dir=p.parent)
    tmp = Path(tmp_name)
    try:
        try:
            # mkstemp creates the file 0600; the mode a plain open() would have given
            # (0666 under the process umask) is restored so a state file's mode does
            # not change with this round
            os.fchmod(fd, 0o666 & ~_UMASK)
            f = os.fdopen(fd, "w", encoding="utf-8")
        except BaseException:
            os.close(fd)  # the descriptor never reached a file object: closed here
            raise
        with f:
            f.write(json.dumps(v, ensure_ascii=False, indent=1) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass  # the original error is the one to report
        raise
    fsync_dir(p.parent)


def append_text(p: Path, text: str) -> None:
    """Append `text` durably: written, flushed, the file fsynced, then the directory
    fsynced. Only after this returns may a caller advance a cursor, publish trust,
    or delete a copy that the bytes replace."""
    with open(p, "a", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    fsync_dir(p.parent)


def append_line(p: Path, line: str) -> None:
    """Append one line durably (see append_text)."""
    append_text(p, line + "\n")


def append_lines(p: Path, lines: list[str]) -> None:
    """Append several lines under one barrier pair (see append_text)."""
    append_text(p, "".join(ln + "\n" for ln in lines))

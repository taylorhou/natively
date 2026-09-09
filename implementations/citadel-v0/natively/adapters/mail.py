"""Gmail wire (stage 1): the transport both sides already poll.

send:    assets/ops/mayor-tools/gmail-send.py from taylor@houmanoids.com to the peer
         address, subject "Natively v0 wire" (a new thread, never the human design
         thread), body = the bundle as one base64 envelope under "X-Natively: v0".
receive: the helper's `profile --json` FIRST, every poll: the mailbox the helper is
         signed into must be the configured self_email, else the poll's fetch fails
         by name ("mailbox mismatch") before any search, cursor or freshness update
         (round-21 Z2; the account name comes from config `mail_account`, never
         assumed). Then gmail-api.py search "subject:(Natively v0 wire) after:<A>
         [before:<B>]" --max 200 --ids-only, following its next-page-token line page
         by page. The window is walked in TIME SLICES, oldest first (Z3): the first
         slice is the whole window; a slice that lists PAGE_CAP threads with more to
         come OVERFLOWS and is halved (the same start, half the span) until it fits
         or reaches MIN_SLICE_S — a minute that still holds over PAGE_CAP threads is a
         flood, reported by name ("slice overflow"), never walked; a slice whose
         bodies were all read is SCANNED THROUGH its end, and the next slice doubles
         the span. Every pass is bounded: MAX_PAGES search calls, PASS_BYTES of
         helper output, a page whose token repeats one already seen or two
         consecutive pages that add no new id end the pass ("nonprogressing
         pagination"). A pass that ends on a budget or a flood after at least one
         slice completed records its progress DURABLY in state/wire-scan.json (the
         position scanned through and the slice span in force) so the next poll
         resumes there instead of starting the window over; a pass that lists the
         open-ended last slice and reads it is COMPLETE, and the record goes. Every
         line of a search page is read strictly (`thread <id>`, `next-page-token
         <token>`, nothing else; an id or a token outside its rule refuses the page).
         Then `thread ... --json --max-rows N` in chunks of THREAD_CHUNK ids, each its
         own subprocess with its own timeout and its output BOUNDED before it is read
         (the cap follows from the row bound and the row size: `default_runner` never
         reads past it; a helper that exceeds --max-rows exits 3 and prints nothing) —
         structured rows: metadata separate from the body text, so a body can never
         fabricate a transport record; EVERY row is validated as a whole before any of
         it is used (Z1, `row_problem`: the transport ids under the identifier rule,
         every field of its type, the flags consistent), and a response with one bad
         row is refused whole — never consumed as an empty message, never a seen
         mark, never a cursor or freshness move. A chunk whose output is oversized
         is halved down to one thread; a single thread that still exceeds the bound
         is recorded ONCE (the ledger's wire.thread_oversize row, `thread:<id>` in
         the seen file) and never fetched again (Z5). --chars is sized to the largest
         wrapped wire body; a peer row the helper CUT there (truncated, body_chars
         over the wire's text bound) is demonstrably not a bundle this node could
         accept: rejected ONCE by name (the ledger's wire.oversize row, the seen note
         `oversized:<chars>`), never re-fetched as an incomplete poll (Z4); a row
         whose body the helper could not OBTAIN (body_unavailable) is transient —
         reported, not marked seen, the fetch incomplete. The mails of a chunk that
         failed or timed out are simply not in this poll (the fetch is incomplete,
         "chunk N failed"), the others are applied and marked seen one by one, and
         the next poll asks again only for what is still unseen. A seen file of
         transport ids so each mail is parsed once; the node's own seen.json makes
         apply idempotent on msg_id. A mail counts only if its From address is one
         of the configured peer_addresses, its To names the configured mailbox and
         its subject is the wire subject or "Re: " + it; anything else is ignored and
         counted (one summary line per poll). A fetch is complete when the whole
         window was scanned through, every chunk answered and every peer body whole.
window:  the search starts at the last COMPLETE fetch minus one day (state/
         wire-cursor.json; floor two days back, also the window when no cursor
         exists) — or at the standing scan record's position when that is later; the
         cursor advances only on a complete fetch, so an outage of any length is
         re-read from before it began and a revocation is never skipped.
order:   pending replies (acks whose send failed last time) first, before the fetch;
         then within one poll batch: cards and revocations (the control phase), THEN
         (only after a complete fetch in which every control write landed) the
         freshness clock, THEN acks and messages, THEN (only once every write landed)
         the cursor, so a revocation on the wire lands before the action it revokes
         and a catch-up poll authorizes the actions it carried; then the outbox (due
         re-sends, undelivered), which runs even when the fetch failed (re-sends do
         not depend on it). If the control phase did NOT land (a storage failure on a
         card or a revocation), the poll applies NO ack and NO message this pass: an
         action whose revocation could not be recorded must not be judged against a
         clock that still reads fresh; their mails stay unseen, clock and cursor stay,
         the outbox still runs, and the summary says why.
durable: the cursor, the transport seen file and the revocation freshness sidecar are
         written atomically and fsynced (durable.write_json); the node's feed append
         is fsynced before it returns, so the cursor can never outlive a revocation it
         acknowledges. A local storage failure while a bundle is applied (StorageError)
         leaves that mail unseen and the fetch incomplete: read again next poll. EVERY
         read and write of the adapter's own state is inside the same boundary — the
         seen file (its initial read too), the cursor, the freshness sidecar, a held
         reply (written and read back), the ledger line for an undecodable mail, the
         outbox listing and bookkeeping: an OSError or a StorageError (a file of ours
         that does not parse) there is reported and counted, the mail concerned
         stays unseen, the cursor does not move, and the poll goes on to the outbox
         (one outbox entry's failure never stops the others). A seen file that cannot
         be read ends the fetch-and-apply half of the poll — the poller cannot know
         what is seen — and the outbox step still runs.
replies: a reply (an ack) is HELD durably under state/pending-replies/ BEFORE its
         mail is marked seen, then sent, and the held copy is deleted only after the
         send returned; so a seen mark that becomes visible while its barrier fails,
         or a send that fails, never loses the obligation: the held reply goes out at
         the start of the next poll. A hold that fails leaves the mail unseen (read
         again next poll), counted, and the poll never reports complete; a failed
         deletion of a sent copy re-sends the same ack next poll (harmless: the peer
         dedups on msg_id). A held file is named <msg_id>.<kind>.json — the id of the
         message it answers and the reply kind — so both survive its corruption.
         ONE validation (Node.reply_problem: the envelope and its cards, the ack's
         structure and OUR signature, the msg_id and kind of its name; this node's
         own card verified first) runs on EVERY reply before it is held and again
         before it is sent, on the same-poll path and the flush alike. A reply that
         fails it is never held — pending_reply.invalid, a storage failure ledgered
         once with the message id: the mail stays unseen, nothing is sent, the poll
         incomplete — and a held reply that fails it is never sent. One that does not
         parse, or is not the reply its name promises, FAILS CLOSED: it is NEVER
         deleted and never sent — moved aside in the same directory
         (below). The send itself has two failure classes, told apart by exception
         type: a storage failure inside it (the validation at the outgoing
         boundary — card.self_corrupt, reply.invalid, any IntegrityError — or an
         OSError) is a storage failure of the poll: counted, the held copy kept,
         nothing transmitted, the cursor frozen; a transport failure (the send
         tool's non-zero exit, a timeout) keeps the held copy for the next poll
         with no storage count — unless the staged wire body could not be removed
         after it: then ONE StorageError names both facts and is counted as a
         storage failure, the transport accounting unchanged. A held copy is moved
         aside in the same directory
         (<name>.corrupt-<stamp>-<ulid>, an os.replace), counted as a storage
         failure, ledgered pending_reply.corrupt once, and left there. Nothing
         automatic rebuilds or sends from a damaged source: EVERY poll counts an
         unresolved aside copy as a storage failure (the cursor stays frozen) until
         an operator resolves it — `natively pending repair` rebuilds the reply from
         a validated source (the stored ack, checked the same way, else the ledger
         completion) and holds it again for the NEXT poll's flush to validate and
         send; `natively pending discard <name>` ledgers the decision to drop it. A
         peer's re-send of the message meanwhile is answered on the ordinary path
         (receive() finds the stored ack, validated; a damaged one is seen.corrupt,
         a storage failure, the mail unseen) and never consults the aside copies.
complete: a poll is complete — and the cursor moves — only when the fetch was
         complete AND no storage failure was counted anywhere in the pass: the held
         replies (their listing, a read, a corrupt copy, a hold, a removal), the seen
         file, the cursor read, every apply, the freshness sidecar, the outbox
         bookkeeping, the reject rows. The cursor read is local state like every
         other: an OSError or an IntegrityError there is a storage failure that skips
         the fetch half (the poller cannot know where to start) and still runs the
         outbox; the fetch handler itself catches only wire and subprocess errors
         (fetch_failures). The scan record is written only by a pass that made
         progress with NO storage failure (every mail it listed applied or marked
         seen), so a position is never recorded past a mail left unseen.
retry:   sized to the 60-s poll: an unacked message is re-sent after 2P, then 4P, then
         8P, then ledgered "undelivered" when the 16P deadline passes; a re-send keeps
         the outbox entry, and the attempt is counted (node.outbox_advance) only after
         the transmission succeeded. Every send failure is reported and counted in
         the summary and the poll goes on; an ack whose first send failed is kept
         under state/pending-replies/ and sent at the start of the next poll (acks are
         never on the retry schedule, but a never-sent ack is not lost either).

The whole of poll_once() runs under the node's state lock (every ledger writer
does). Only this module runs the mail scripts. The secret-bearing OAuth env lives
in ~/.config/google-taylor/env and never passes through here. One poller per state
directory is assumed for the transport seen-file."""

from __future__ import annotations

import inspect
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import getaddresses, parseaddr
from pathlib import Path
from typing import Any

from .. import bundle as bundlemod
from .. import state as statemod
from ..durable import fsync_dir, list_dir
from ..durable import write_json as _write_json
from ..errors import IntegrityError, StorageError, VerifyError
from ..node import DEFAULT_CONFIG, MAX_RESENDS, Node
from ..objects import is_id, new_id
from ..timeutil import fmt, parse

TOOLS_DIR = Path(__file__).resolve().parents[3]  # assets/ops/mayor-tools
GMAIL_SEND = TOOLS_DIR / "gmail-send.py"
GMAIL_API = TOOLS_DIR / "gmail-api.py"
Runner = Callable[..., subprocess.CompletedProcess]  # (argv, *, max_output=N) or (argv)

SEARCH_MAX = 200  # threads per search page; the next-page-token line continues it
# the most threads one SLICE may list: past this the slice overflows and is halved
# (the same start, half the span) rather than walked — never a poll that never ends
PAGE_CAP = 2000
# the most search calls one poll (one pass) will make, whatever the pages contain: a
# search that repeats a page, or answers empty pages with fresh tokens, can never
# reach PAGE_CAP unique ids, so the loop is bounded on calls too; a pass that spends
# them after at least one slice completed records its progress and stops
MAX_PAGES = 40
NONPROGRESSING = "nonprogressing pagination"
# the smallest slice: a minute of the mailbox that still holds over PAGE_CAP threads
# is a flood, reported by name, never split further and never walked
MIN_SLICE_S = 60
# thread ids per `thread --json` call: each call is one subprocess with its own
# timeout, so a large window is read in bounded pieces instead of one call that
# times out on every poll and never recovers
THREAD_CHUNK = 50
NEXT_PAGE_PREFIX = "next-page-token "
# --chars for `thread --json`: the largest WRAPPED wire body (header line, base64 at
# 76 columns) plus a margin, so the helper never cuts a bundle the node would accept
WIRE_CHARS = bundlemod.MAX_WIRE_TEXT_CHARS + 4096
# the row bound of one `thread --json` call (the helper's --max-rows): more rows than
# this and the helper exits 3 with nothing printed; the adapter halves the chunk
MAX_ROWS = 32
# bytes of one row beyond its body (the ids, the headers, the snippet, the flags)
ROW_OVERHEAD = 8192
# the output cap of one `thread --json` call, decided BEFORE the read: every body is
# at most WIRE_CHARS characters (six bytes each once JSON-escaped, the worst case)
CHUNK_OUTPUT_CAP = MAX_ROWS * (6 * WIRE_CHARS + ROW_OVERHEAD)
# the output cap of a search page or the profile (a few hundred short lines)
SMALL_OUTPUT_CAP = 1024 * 1024
# helper output one pass will read across its chunks; past it the pass records its
# progress and stops (the next poll continues)
PASS_BYTES = 256 * 1024 * 1024
HELPER_TIMEOUT_S = 120
CATCHUP_OVERLAP_S = 24 * 3600  # the search starts one day before the last complete fetch
CATCHUP_FLOOR_S = 2 * 24 * 3600  # and at least two days back
KIND_ORDER = {"card": 0, "revocation": 1, "ack": 2, "message": 3}
_MISSING = object()  # a state file that is ABSENT (a present `null` is corruption)
CONTROL_KINDS = ("card", "revocation")  # applied before the freshness clock moves
# the identifier rule for a gmail message or thread id: one argv-safe token — no
# whitespace, no separator, never starting with `-` (an id is handed to the helper as
# an argument, and keyed in the seen file)
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
TOKEN_RE = re.compile(r"[A-Za-z0-9_=.:-]{1,4096}")  # a next-page token
THREAD_SEEN = "thread:"  # the seen-file key prefix of an oversized thread


class OversizedOutput(RuntimeError):
    """A helper call whose output would exceed the bound decided before the read
    (the runner stopped reading), or whose rows exceed --max-rows (the helper
    exited 3 with nothing printed)."""


class MailboxMismatch(RuntimeError):
    """The mailbox the helper is signed into is not the configured self_email."""


@dataclass
class RawMail:
    gmail_id: str
    thread_id: str
    labels: str
    date: str
    sender: str
    to: str
    subject: str
    body: str
    truncated: bool = False  # the helper cut the body at --chars, or could not obtain it
    unavailable: str = ""  # why the helper could not obtain the body (body_unavailable)
    body_chars: int | None = None  # the decoded body's length before any cut, when reported


@dataclass
class Fetched:
    mails: list[RawMail] = field(default_factory=list)  # from a peer address, wire subject
    ignored: list[tuple[RawMail, str]] = field(default_factory=list)
    truncated: list[RawMail] = field(default_factory=list)  # peer mail the helper could not obtain
    # peer mail over the wire bound, and threads over the row bound: terminal rejections
    oversized: list[RawMail] = field(default_factory=list)
    oversized_threads: list[str] = field(default_factory=list)
    complete: bool = True
    pages: int = 0  # search calls made
    threads: int = 0  # thread ids the search listed (unique, over every slice)
    chunks: int = 0  # thread calls made
    slices: int = 0  # slices scanned through
    overflows: int = 0  # slices that listed PAGE_CAP threads with more to come (halved)
    bytes: int = 0  # helper output read by the thread calls
    scanned_through: int | None = None  # the epoch second every message before which was read
    slice_s: int | None = None  # the slice span in force when the pass ended
    progress: bool = False  # ended on a budget AFTER at least one slice completed: record it
    budget: bool = False  # ended on a budget or a flood (not a transient failure)
    transient: bool = False  # a chunk failed, or a body could not be obtained: no record
    overflow: bool = False  # the slice just searched listed PAGE_CAP threads with more to come
    # the byte budget crossed: the pass makes NO further helper call (round-21
    # self-gate, finding 2) — not a chunk, not a half of a split, not a search
    stopped: bool = False
    # the search ended (the page cap, nonprogressing pagination): no further search
    # page this pass, but the threads the slice listed so far are still READ
    searched_out: bool = False
    # "page cap (N search pages)" | "nonprogressing pagination" | "slice overflow: …" |
    # "byte budget …" | "chunk N of M failed" | "N peer mail(s) unavailable" (joined with
    # "; "), "" when complete
    incomplete_why: str = ""
    errors: list[str] = field(default_factory=list)  # one per failed chunk or oversized thread

    def incomplete(self, why: str) -> None:
        self.complete = False
        self.incomplete_why = f"{self.incomplete_why}; {why}" if self.incomplete_why else why


def _drain(stream: Any, cap: int, box: list[bytes]) -> None:
    """Read `stream` into `box[0]`, at most cap + 1 bytes (one past the cap tells
    the caller the cap was exceeded), then stop reading: the writer blocks or
    dies with the process; nothing past the cap is ever allocated here."""
    data = stream.read(cap + 1)
    box.append(data if data is not None else b"")


def default_runner(
    argv: list[str], *, max_output: int = SMALL_OUTPUT_CAP, timeout: float = HELPER_TIMEOUT_S
) -> subprocess.CompletedProcess:
    """The helper as a subprocess, its stdout read up to `max_output` bytes and NOT
    past them (the bound is decided before the read, never applied to a body
    already allocated: round-21 Z5): over the cap the process is killed and
    OversizedOutput raised; a process that does not finish within `timeout` is
    killed and TimeoutExpired raised (the transport class, as before). stderr is
    read up to 64 KiB for the message. stdin is closed."""
    proc = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL
    )
    out_box: list[bytes] = []
    err_box: list[bytes] = []
    t_out = threading.Thread(target=_drain, args=(proc.stdout, max_output, out_box), daemon=True)
    t_err = threading.Thread(target=_drain, args=(proc.stderr, 64 * 1024, err_box), daemon=True)
    t_out.start()
    t_err.start()
    t_out.join(timeout)
    if t_out.is_alive():
        proc.kill()
        proc.wait()
        raise subprocess.TimeoutExpired(argv, timeout)
    out = out_box[0] if out_box else b""
    if len(out) > max_output:
        proc.kill()
        proc.wait()
        raise OversizedOutput(
            f"{Path(argv[1]).name} printed over {max_output} bytes; the read stopped there"
        )
    try:
        rc = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise
    t_err.join(5)
    err = err_box[0] if err_box else b""
    return subprocess.CompletedProcess(
        argv, rc, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")
    )


# the row of `thread --json`: every field the adapter reads, of its type. The headers
# may be null (a message without that header; the helper prints what Gmail served);
# `truncated` and the two body facts are optional with their absent meaning
_ROW_FIELDS = {
    "id": "id",
    "threadId": "id",
    "labelIds": "labels",
    "date": "header",
    "from": "header",
    "to": "header",
    "subject": "header",
    "snippet": "text?",
    "body": "text",
    "truncated": "bool?",
    "body_unavailable": "text?",
    "body_chars": "int?",
}


def row_problem(r: Any, i: int) -> str | None:
    """Why row `i` of a `thread --json` response is not a row the adapter can read,
    or None (round-21 Z1): not an object, a field missing, a field of the wrong
    type, a field the schema does not name, an id outside the identifier rule, a
    cut body (`truncated` without `body_unavailable`) that does not say how long
    the body was — each refuses the WHOLE response, so no row of it becomes an
    empty message, a seen mark, or a cursor or freshness move."""
    if not isinstance(r, dict):
        return f"row {i} is not an object"
    for k in r:
        if k not in _ROW_FIELDS:
            return f"row {i}: a field the adapter does not read: {k!r}"
    for k, kind in _ROW_FIELDS.items():
        v = r.get(k)
        if kind.endswith("?") and k not in r:
            continue
        if kind == "id":
            if not isinstance(v, str) or not ID_RE.fullmatch(v):
                return f"row {i}: {k} {v!r} is not a transport id ({ID_RE.pattern})"
        elif kind == "labels":
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                return f"row {i}: labelIds is not a list of strings"
        elif kind == "header":
            if v is not None and not isinstance(v, str):
                return f"row {i}: {k} is neither a string nor null"
        elif kind.startswith("text"):
            if not isinstance(v, str):
                return f"row {i}: {k} is not a string"
        elif kind.startswith("bool"):
            if not isinstance(v, bool):
                return f"row {i}: {k} is not a boolean"
        elif kind.startswith("int"):
            if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                return f"row {i}: {k} is not a non-negative integer"
    if r.get("truncated") is True and not r.get("body_unavailable") and "body_chars" not in r:
        return f"row {i}: a cut body without body_chars (how long the body was)"
    return None


def parse_thread_json(text: str) -> list[RawMail]:
    """gmail-api.py `thread --json`: a JSON array of rows (`_ROW_FIELDS`), every row
    validated as a whole before any is used (`row_problem`); a response with one
    bad row is refused whole (RuntimeError naming the row: a wire failure of the
    chunk, the fetch incomplete, nothing consumed)."""
    try:
        rows = json.loads(text)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"gmail-api.py thread --json did not return JSON: {e}") from e
    if not isinstance(rows, list):
        raise RuntimeError("gmail-api.py thread --json did not return a list")
    for i, r in enumerate(rows):
        why = row_problem(r, i)
        if why is not None:
            raise RuntimeError(f"gmail-api.py thread --json: {why}; the response is refused whole")
    return [_row_to_mail(r) for r in rows]


def _row_to_mail(r: dict[str, Any]) -> RawMail:
    def s(k: str) -> str:
        v = r.get(k)
        return v if isinstance(v, str) else ""

    return RawMail(
        gmail_id=r["id"],
        thread_id=r["threadId"],
        labels=",".join(r["labelIds"]),
        date=s("date"),
        sender=s("from"),
        to=s("to"),
        subject=s("subject"),
        body=r["body"],
        # a body the helper could not obtain (a text part Gmail served through an
        # attachment id whose fetch failed: body_unavailable, with truncated true) is
        # an INCOMPLETE FETCH exactly like a body it cut — never a body to decode,
        # never a mail to mark seen; either flag alone makes the row incomplete
        truncated=r.get("truncated") is True or bool(r.get("body_unavailable")),
        unavailable=s("body_unavailable"),
        body_chars=r.get("body_chars"),
    )


class MailWire:
    def __init__(self, node: Node, *, runner: Runner | None = None, python: str | None = None):
        self.node = node
        self.run = runner or default_runner
        # a runner that takes the output bound (`max_output`) bounds the read itself;
        # one that does not (an in-memory fake) is bounded on what it returned
        params = inspect.signature(self.run).parameters
        self._bounded = "max_output" in params or any(
            p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()
        )
        self.python = python or sys.executable
        self.seen_path = node.state / "seen-mail.json"
        self.cursor_path = node.state / "wire-cursor.json"
        self.scan_path = node.state / "wire-scan.json"
        self.pending_dir = node.state / "pending-replies"
        self.subject = node.config["subject"]
        self.peer_email = node.config["peer_email"]
        self.self_email = node.config["self_email"]
        self.account = node.config["mail_account"]
        self._pass_bytes = 0  # helper output charged this pass (`_run`, `_over_budget`)

    def _run(self, argv: list[str], cap: int) -> subprocess.CompletedProcess:
        """One helper call with its output bound `cap` decided here, before the
        read (`default_runner` reads no further); a runner without the bound is
        judged on what it returned (OversizedOutput past the cap). EVERY call's
        output — a search page, the profile, a chunk, an answer that failed or was
        oversized (charged at its cap) — is charged to the pass's byte budget
        (`_pass_bytes`, round-21 self-gate finding 2), which `_over_budget` judges
        after every call."""
        try:
            if self._bounded:
                r = self.run(argv, max_output=cap)
            else:
                r = self.run(argv)
                if r is not None and len(r.stdout.encode("utf-8", "surrogatepass")) > cap:
                    raise OversizedOutput(f"{Path(argv[1]).name} printed over {cap} bytes")
        except OversizedOutput:
            self._pass_bytes += cap
            raise
        if r is not None:
            self._pass_bytes += len(r.stdout.encode("utf-8", "surrogatepass")) + len(
                r.stderr.encode("utf-8", "surrogatepass")
            )
        return r

    def _over_budget(self, out: Fetched) -> bool:
        """The pass's byte budget, judged after every helper call: crossed, the pass
        ends by name after that call (no further call, even inside a split or on a
        slice's last chunk) and the slices completed so far are recorded."""
        if self._pass_bytes > PASS_BYTES and not out.stopped:
            out.incomplete(f"byte budget ({PASS_BYTES} bytes of helper output this pass)")
            out.budget = True
            out.stopped = True
        out.bytes = self._pass_bytes
        return out.stopped

    def peer_addresses(self) -> set[str]:
        """The addresses a mail is read from, lower-cased: config.json's
        peer_addresses read NOW through the typed loader (state.config: every
        element an address, else state.corrupt naming the path and the index — a
        storage failure of the poll, nothing classified, nothing seen, the clock
        and the cursor unmoved; the adapter never filters or coerces the list),
        the package default when the file names none. Zero configured addresses
        is config.no_peers, refused by name — never a poll that classifies every
        mail as ignored."""
        path = self.node.state / "config.json"
        cfg = {**DEFAULT_CONFIG, **statemod.read(path, {}, statemod.config)}
        addrs = cfg["peer_addresses"]
        if not addrs:
            raise IntegrityError(
                "config.no_peers",
                f"{path}: peer_addresses names no address; nothing "
                f"is read from the wire until one is configured (`natively config --set "
                f"peer_addresses=...`)",
            )
        return {a.lower() for a in addrs}

    # ---- the mailbox identity (round-21 Z2) ----
    def mailbox(self) -> str:
        """The address the helper is signed into (`gmail-api.py profile --json`,
        users.getProfile), lower-cased. A helper that fails, prints no JSON object,
        or names no address is a wire failure (RuntimeError)."""
        argv = [self.python, str(GMAIL_API), "--account", self.account, "profile", "--json"]
        r = self._run(argv, SMALL_OUTPUT_CAP)
        if r.returncode != 0:
            raise RuntimeError(
                f"gmail-api.py profile failed rc={r.returncode}: {r.stderr.strip()[-400:]}"
            )
        try:
            obj = json.loads(r.stdout)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"gmail-api.py profile did not return JSON: {e}") from e
        addr = obj.get("emailAddress") if isinstance(obj, dict) else None
        why = statemod.address(addr, "the helper's emailAddress")
        if why is not None:
            raise RuntimeError(f"gmail-api.py profile: {why}")
        return addr.lower()

    def assert_mailbox(self) -> str:
        """The mailbox the helper reads IS the configured one, judged before any
        search of a poll and before any cursor, scan or freshness update: a helper
        signed into another mailbox (the wrong account's credentials, a configured
        self_email that moved) is MailboxMismatch by name — the fetch fails, nothing
        is applied, nothing is marked seen, the clocks stay (round-21 Z2: the
        adapter assumed the mailbox and read the wrong one's mail as its own)."""
        got = self.mailbox()
        if got != self.self_email.lower():
            raise MailboxMismatch(
                f"mailbox mismatch: gmail-api.py --account {self.account} is signed into "
                f"{got}, the configured self_email is {self.self_email}; nothing fetched"
            )
        return got

    # ---- transport-level seen file ----
    def _seen(self) -> dict[str, str]:
        """The transport seen file, typed (state.seen_mail: gmail id -> note). The
        wrong shape is state.corrupt naming the path — a storage failure (nothing
        fetched or applied this pass), never an empty seen file that re-reads the
        whole window."""
        return statemod.read(self.seen_path, {}, statemod.seen_mail)

    def _mark_seen(self, gmail_id: str, note: str) -> None:
        # atomic and durable (temp file, fsync, rename, directory fsync): a torn seen
        # file after power loss would either re-read everything or, worse, be
        # unparseable and stop the poller
        s = self._seen()
        s[gmail_id] = note
        _write_json(self.seen_path, s)

    # ---- catch-up cursor and the scan record ----
    def cursor(self) -> datetime | None:
        """When the last COMPLETE fetch happened, or None before the first one. A
        cursor file of ours that does not parse is IntegrityError (a storage
        failure), like every other state read."""
        # the typed loader: a list, a `null`, an object without the string is
        # state.corrupt naming the path
        c = statemod.read(self.cursor_path, _MISSING, statemod.cursor)
        if c is _MISSING:
            return None
        try:
            return parse(c["last_complete_fetch"], "wire.cursor")
        except VerifyError as e:
            # a cursor of ours with the wrong shape or an unparseable timestamp is
            # local corruption like a cursor that is not JSON: a storage failure
            # (counted, the fetch half skipped), never an exception out of the poll
            raise IntegrityError("state.corrupt", f"{self.cursor_path}: {e.detail}") from e

    def _advance_cursor(self) -> None:
        _write_json(self.cursor_path, {"last_complete_fetch": self.node.ts()})

    def scan_record(self) -> tuple[int, int] | None:
        """The standing scan record (state/wire-scan.json: the epoch second scanned
        through and the slice span in force), or None. Typed like the cursor; a
        record of ours that does not parse is a storage failure."""
        c = statemod.read(self.scan_path, _MISSING, statemod.scan_record)
        if c is _MISSING:
            return None
        try:
            through = parse(c["scanned_through"], "wire.scan")
        except VerifyError as e:
            raise IntegrityError("state.corrupt", f"{self.scan_path}: {e.detail}") from e
        return int(through.timestamp()), c["slice_s"]

    def _record_scan(self, got: Fetched) -> None:
        """The pass's progress written durably: every message dated before
        `scanned_through` was listed and read (applied or marked seen, by the
        caller's accounting), and the slice span the halving reached."""
        assert got.scanned_through is not None and got.slice_s is not None
        _write_json(
            self.scan_path,
            {
                "scanned_through": fmt(datetime.fromtimestamp(got.scanned_through, tz=UTC)),
                "slice_s": got.slice_s,
                "recorded_at": self.node.ts(),
            },
        )

    def _clear_scan(self) -> None:
        if self.scan_path.exists():
            self.scan_path.unlink()
            fsync_dir(self.node.state)

    def search_after(self) -> int:
        """The epoch second the search starts at: one day before the last complete
        fetch, and never later than two days ago — or the standing scan record's
        position when that is later (a pass that made progress is continued, not
        started over)."""
        return self.scan_start()[0]

    def scan_start(self) -> tuple[int, int | None]:
        """(the epoch second the scan starts at, the slice span to start with or
        None for the whole window): the catch-up start (`cursor` minus the overlap,
        floored) unless a scan record stands past it."""
        now = self.node.now()
        start = now - timedelta(seconds=CATCHUP_FLOOR_S)
        cur = self.cursor()
        if cur is not None:
            start = min(start, cur - timedelta(seconds=CATCHUP_OVERLAP_S))
        after = int(start.timestamp())
        rec = self.scan_record()
        if rec is not None:
            now_epoch = int(now.timestamp())
            if rec[0] > now_epoch:
                # a record past the clock (a rollback, a hand-written file): searching
                # after it would list nothing and read as complete; the window is
                # scanned instead and the pass overwrites or removes the record
                # (round-21 self-gate, finding 7)
                self.node.report(
                    f"natively: the scan record's position {rec[0]} is past the clock "
                    f"{now_epoch}; ignored, the window is scanned from {after}"
                )
                return after, None
            if rec[0] >= after:
                return rec
        return after, None

    # ---- held replies (every reply is held before its mail is marked seen) ----
    @staticmethod
    def held_name(msg_id: str | None, kind: str = "ack") -> str:
        """<msg_id>.<kind>.json: the id of the message the reply answers and the
        reply's kind, both readable from the name alone — taken from the REQUEST
        (the message received, the aside copy's name), never from the reply, so a
        reply of any shape has a name to be refused under."""
        return f"{msg_id or 'reply'}.{kind}.json"

    @staticmethod
    def parse_held_name(name: str) -> tuple[str | None, str | None]:
        """(msg_id, kind) from a held file's name, or (None, None) parts when the name
        is not of the <msg_id>.<kind>.json shape (an aside copy keeps the prefix)."""
        parts = name.split(".")
        msg_id = parts[0] if len(parts) >= 3 and is_id(parts[0], "msg_") else None
        kind = parts[1] if len(parts) >= 3 and parts[1] else None
        return msg_id, kind

    def _hold_reply(self, r: Any, msg_id: str | None, kind: str = "ack") -> Path:
        """Validated in full FIRST (`Node.reply_problem`, against the id and kind of
        the REQUEST it answers — `msg_id` from the message received or the aside
        copy's name, so a reply of any shape, even one that is not an object, is
        refused inside the boundary): a reply that fails is never written — IntegrityError
        pending_reply.invalid, a storage failure (the mail stays unseen, nothing is
        sent, the poll incomplete), ledgered pending_reply.invalid once with the
        message id (keyed on the exact held name, so the re-read next poll appends
        nothing). Then durable (temp file, fsync, rename, directory fsync); the same
        ack held again lands on the same name, so a retry re-establishes the
        barrier. A DIFFERENT file already under that name — a corrupt held copy the
        flush has not quarantined yet, or a reply of another shape — is never
        overwritten (IntegrityError, a storage failure: the mail stays unseen), so
        the evidence of the corruption survives for the quarantine."""
        p = self.pending_dir / self.held_name(msg_id, kind)
        problem = self.node.reply_problem(r, msg_id, kind)
        if problem is not None:
            self.node.report(
                f"natively: reply {p.name} is not this node's reply ({problem}); not held, "
                f"not sent, its mail stays unseen"
            )
            self._ledger_pending_once(
                "pending_reply.invalid",
                msg_id,
                f"reply {p.name} failed validation before it was held ({problem[:120]}); "
                f"not held, not sent",
                p.name,
                token=self._invalid_key(p.name),
            )
            raise IntegrityError(
                "pending_reply.invalid", f"{p}: not this node's reply ({problem}); not held"
            )
        self.pending_dir.mkdir(exist_ok=True)
        if p.exists():
            fresh = json.dumps(r, ensure_ascii=False, indent=1) + "\n"
            if p.read_bytes() != fresh.encode("utf-8"):
                raise IntegrityError(
                    "pending_reply.conflict",
                    f"{p}: a different file is already held under this name; it is left for "
                    f"the quarantine, nothing overwrites it",
                )
        _write_json(p, r)
        return p

    def _pending_replies(self) -> list[Path]:
        """The held replies to send (durable.list_dir: an unreadable directory is an
        OSError, a storage failure, never an empty listing)."""
        return list_dir(self.pending_dir, ".json")

    def _aside_replies(self) -> list[Path]:
        """The corrupt held copies moved aside, resolved (.reconstructed) or not."""
        return [p for p in list_dir(self.pending_dir) if ".corrupt-" in p.name]

    @staticmethod
    def _unresolved(aside: Path) -> bool:
        return not aside.name.endswith(".reconstructed")

    # ---- send ----
    def send(self, b: dict[str, Any], *, dry_run: bool = False, resend: bool = False) -> str:
        """Send one bundle. A first send of a message records it in the outbox; a
        re-send (`resend=True`) keeps the existing entry and its attempt count; a dry
        run records nothing. Every bundle crosses the node's outgoing boundary here
        (`Node.check_outgoing`: a reply through the ONE validation, every other kind
        through its own check): one that fails is never encoded, never transmitted,
        never recorded (IntegrityError <kind>.invalid).
        Failure classes, by exception TYPE: everything before the send tool runs
        (the validation — a StorageError; staging the wire body — an OSError) leaves
        the box untouched, nothing transmitted; the send tool's non-zero exit is a
        RuntimeError (the transport class), a runner that raises (a timeout) its own
        exception. The staged body's removal runs in a finally block and records its
        own failure whatever the transport did: after a transport failure the two
        facts are raised together as ONE StorageError naming both (the transport
        failure and the path that could not be removed) — a storage failure the
        caller counts, the transport accounting unchanged (the held copy kept, no
        attempt spent, the cursor frozen), never a transport failure that hides the
        cleanup; after the tool returned success it is raised LAST — after the
        result is recorded — as a StorageError whose text says the send returned and
        names the gmail id, so a caller counts it without taking it for "not
        transmitted"."""
        self.node.check_outgoing(b)
        body = bundlemod.encode(b)
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write(body)
            path = f.name
        argv = [
            self.python,
            str(GMAIL_SEND),
            "--to",
            self.peer_email,
            "--subject",
            self.subject,
            "--body-file",
            path,
            "--from-addr",
            self.self_email,
        ]
        if dry_run:
            argv.append("--dry-run")
        cleanup: OSError | None = None
        transport: Exception | None = None  # the runner raised (a timeout, a launch failure)
        r: subprocess.CompletedProcess | None = None
        try:
            r = self.run(argv)
        except Exception as e:  # noqa: BLE001 — classed below, never before the cleanup ran
            transport = e
        finally:
            # the removal's failure is recorded on its own, whatever the transport did
            try:
                Path(path).unlink(missing_ok=True)
            except OSError as e:
                cleanup = e  # reported after the transport result is known
        if transport is None and r is not None and r.returncode != 0:
            transport = RuntimeError(
                f"gmail-send.py failed rc={r.returncode}: {r.stderr.strip()[-400:]}"
            )
        if transport is not None:
            if cleanup is not None:
                raise StorageError(
                    f"the send failed ({type(transport).__name__}: {transport}) AND the staged "
                    f"wire body {path} could not be removed afterwards: "
                    f"{type(cleanup).__name__}: {cleanup}",
                    cleanup,
                ) from transport
            if isinstance(transport, RuntimeError):
                raise transport
            # a runner exception (a timeout, a launch failure) is the transport
            # failure it is — RuntimeError, one line at the CLI, exit 1 — never
            # re-raised as its own class: subprocess.TimeoutExpired is neither an
            # OSError nor a RuntimeError, and `send`, `revoke` and the dry run
            # ended in a traceback (round-19 Fable read, finding 7). Nothing is
            # recorded (the outbox is written only after the tool returns) — but
            # whether the mailbox took the message before the tool stopped answering
            # is UNKNOWN, and the line says so: a fresh send is not a safe retry
            # (round-19 self-gate, third run)
            raise RuntimeError(
                f"the send tool did not return ({type(transport).__name__}: {transport}); "
                f"delivery unknown (the mailbox may have taken the message first), nothing "
                f"recorded: check the Sent mailbox before sending again"
            ) from transport
        assert r is not None
        ref = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
        if not dry_run:
            # (a dry run: nothing left the box, so nothing waits for an ack — it must
            # never enter the outbox, or the next poll would re-send it for real at 2P)
            try:
                ref = json.loads(ref).get("id", ref)
            except json.JSONDecodeError:
                pass
            if not resend:
                try:
                    self.node.outbox_record(b, transport_ref=ref)
                except (OSError, StorageError) as e:
                    if cleanup is None:
                        raise
                    # both facts, or the cleanup failure vanishes behind this one
                    raise StorageError(
                        f"the send tool returned (gmail {ref!r}; transmitted) but recording "
                        f"it in the outbox failed ({type(e).__name__}: {e}) AND the staged "
                        f"wire body {path} could not be removed afterwards: "
                        f"{type(cleanup).__name__}: {cleanup}",
                        e,
                    ) from e
        if cleanup is not None:
            fate = "a dry run" if dry_run else "transmitted"
            if not dry_run and not resend:
                fate += " and recorded"
            raise StorageError(
                f"the send tool returned (gmail {ref!r}; {fate}) but the staged wire body "
                f"{path} could not be removed afterwards: {type(cleanup).__name__}: {cleanup}",
                cleanup,
            )
        return ref

    # ---- receive ----
    def _classify(self, m: RawMail, peers: set[str]) -> str | None:
        """None when the mail is from a peer address, to the configured mailbox, on
        the wire subject; else why not."""
        addr = parseaddr(m.sender)[1].lower()
        if addr == self.self_email.lower():
            return "self"
        if addr not in peers:
            return "sender"
        # the To of the row names the configured mailbox (round-21 Z2): a mail the
        # helper's mailbox holds that was not addressed to this node is not its wire
        if self.self_email.lower() not in {a.lower() for _n, a in getaddresses([m.to])}:
            return "recipient"
        subj = m.subject.strip()
        if subj not in (self.subject, "Re: " + self.subject):
            return "subject"
        return None

    def _search_page(self, q: str, page_token: str | None) -> tuple[list[str], str | None]:
        """One search page: the thread ids it lists and the next-page token, if any.
        Every line is read strictly: `thread <id>` with the id under the identifier
        rule, `next-page-token <token>` under the token rule, blank lines; anything
        else refuses the page (RuntimeError, a wire failure)."""
        argv = [self.python, str(GMAIL_API), "--account", self.account, "search", q]
        argv += ["--max", str(SEARCH_MAX), "--ids-only"]
        if page_token:
            argv += ["--page-token", page_token]
        r = self._run(argv, SMALL_OUTPUT_CAP)
        if r.returncode != 0:
            raise RuntimeError(
                f"gmail-api.py search failed rc={r.returncode}: {r.stderr.strip()[-400:]}"
            )
        tids: list[str] = []
        nxt: str | None = None
        for ln in r.stdout.splitlines():
            if not ln.strip():
                raise RuntimeError(
                    "gmail-api.py search printed a blank line the adapter does not read"
                )
            parts = ln.split(" ")
            if parts[0] == "thread" and len(parts) == 2 and ID_RE.fullmatch(parts[1]):
                tids.append(parts[1])
            elif ln.startswith(NEXT_PAGE_PREFIX) and TOKEN_RE.fullmatch(
                ln[len(NEXT_PAGE_PREFIX) :]
            ):
                nxt = ln[len(NEXT_PAGE_PREFIX) :]
            else:
                raise RuntimeError(
                    f"gmail-api.py search printed a line the adapter does not read: {ln[:80]!r}"
                )
        return tids, nxt

    def _search_slice(self, q: str, out: Fetched, seen_ids: set[str]) -> list[str]:
        """Walk the pages of one slice: at most PAGE_CAP ids unique to the slice (more
        to come past that = the slice overflows: `out.overflow`), the pass's
        MAX_PAGES calls, a repeated token or two consecutive pages that add no id
        new TO THE SLICE (nonprogressing: named) each end the searching
        (`out.searched_out`) with what the slice listed so far still read — never
        an exception, never a loop that holds the lock; the byte budget
        (`out.stopped`) ends the pass outright. Returns the slice's ids not yet
        listed this pass (a thread a wider slice listed already is read once)."""
        slice_ids: set[str] = set()
        tids: list[str] = []
        tokens: set[str] = set()
        token: str | None = None
        stalled = 0  # consecutive pages that added no id new to the slice
        out.overflow = False
        while True:
            if out.stopped or self._over_budget(out):
                return tids  # the pass ended: what the slice listed so far is still read
            if out.pages >= MAX_PAGES:
                # the pass's call budget: what the slice listed so far is still read
                out.incomplete(f"page cap ({MAX_PAGES} search pages)")
                out.budget = True
                out.searched_out = True
                return tids
            page, token = self._search_page(q, token)
            out.pages += 1
            new = 0
            for t in page:
                if t in slice_ids:
                    continue  # a thread listed on two pages of the slice
                slice_ids.add(t)
                new += 1
                if t not in seen_ids:  # listed by a wider slice this pass: read once
                    seen_ids.add(t)
                    tids.append(t)
                    out.threads += 1
            if not token:
                return tids
            if len(slice_ids) >= PAGE_CAP:
                out.overflow = True
                return tids
            stalled = 0 if new else stalled + 1
            if token in tokens or stalled >= 2:
                # a helper malfunction, transient: what was listed is still read
                out.incomplete(NONPROGRESSING)
                out.transient = True
                out.searched_out = True
                return tids
            tokens.add(token)

    def _thread_chunk(self, tids: list[str]) -> tuple[list[RawMail], int]:
        argv = [
            self.python,
            str(GMAIL_API),
            "--account",
            self.account,
            "thread",
            *tids,
            "--chars",
            str(WIRE_CHARS),
            "--max-rows",
            str(MAX_ROWS),
            "--json",
        ]
        r = self._run(argv, CHUNK_OUTPUT_CAP)
        if r.returncode == 3:
            raise OversizedOutput(f"gmail-api.py thread: {r.stderr.strip()[-400:]}")
        if r.returncode != 0:
            raise RuntimeError(
                f"gmail-api.py thread failed rc={r.returncode}: {r.stderr.strip()[-400:]}"
            )
        return parse_thread_json(r.stdout), len(r.stdout.encode("utf-8", "surrogatepass"))

    def _read_chunk(self, tids: list[str], out: Fetched, label: str) -> list[RawMail] | None:
        """The rows of one chunk; an oversized answer halves the chunk down to one
        thread, and a single thread that still exceeds the bound is recorded in
        `out.oversized_threads` (terminal: the poll ledgers it and never asks
        again); a chunk that fails or times out is named and None is returned (the
        slice is not read whole, the fetch incomplete). No call is made once the
        pass has stopped (the byte budget crossed by the call before, inside a
        split included)."""
        if out.stopped:
            return None
        out.chunks += 1
        try:
            rows, _nbytes = self._thread_chunk(tids)
        except OversizedOutput as e:
            self._over_budget(out)
            if len(tids) == 1:
                out.oversized_threads.append(tids[0])
                out.errors.append(
                    f"thread {tids[0]} is oversized ({e}); rejected, never re-fetched"
                )
                return []
            mid = len(tids) // 2
            left = self._read_chunk(tids[:mid], out, label)
            if left is None:
                return None
            right = self._read_chunk(tids[mid:], out, label)
            if right is None:
                return None
            return left + right
        except Exception as e:  # noqa: BLE001 — a timeout or a helper failure, per chunk
            self._over_budget(out)
            out.errors.append(f"thread chunk {label} failed: {type(e).__name__}: {e}")
            out.incomplete(f"chunk {label} failed")
            out.transient = True
            return None
        self._over_budget(out)
        return rows

    def _read_threads(self, tids: list[str], out: Fetched) -> tuple[list[RawMail], bool]:
        """The rows of every chunk of `tids` (a chunk that failed is named and the
        others are still read: their mails apply and are marked seen), and whether
        the slice was read WHOLE — false after a failed chunk (transient) or when
        the pass stopped before a chunk was read (the byte budget crossed by the
        call before; a budget crossed by the slice's LAST chunk leaves it whole)."""
        rows: list[RawMail] = []
        whole = True
        chunks = [tids[i : i + THREAD_CHUNK] for i in range(0, len(tids), THREAD_CHUNK)]
        for i, chunk in enumerate(chunks, 1):
            if out.stopped:
                whole = False
                break
            got = self._read_chunk(chunk, out, f"{i} of {len(chunks)}")
            if got is None:
                whole = False
                continue
            rows.extend(got)
        return rows, whole

    @staticmethod
    def cut_verdict(body: str) -> str:
        """What a body the helper CUT at --chars can still be judged to be, by the
        decoder's own acceptance rules (round-21 self-gate, finding 4: a body over
        the wire's text bound can still decode — the decoder tolerates trailing
        quoted text and rewrapped base64 — so a length alone rejects nothing):
        "bundle" when the prefix holds a whole wire body or is no wire body at all
        (the normal path decides: applied, or ledgered undecodable and seen);
        "oversized" when the base64 that reaches the cut is already past the wire's
        base64 bound (no bundle this node accepts is that long — terminal);
        "undecidable" when the base64 runs to the cut still under the bound (a
        rewrapping that inflated the text; transient, read again)."""
        # the decoder's own reading (`bundle.decode`): CR LF folded, every line
        # stripped, leading blank lines skipped, the header line, then base64 lines
        # until a blank line or a quoted (">") line. The cut falls INSIDE the last
        # element of the split — an unfinished line (or "" after a final newline):
        # only a line the newline after it completes is judged as the decoder
        # would; the unfinished tail can still become anything (a blank line, an
        # indented base64 line), so it counts as base64 when it holds any and
        # decides nothing when it is empty or whitespace.
        lines = [ln.strip() for ln in body.replace("\r\n", "\n").split("\n")]
        *whole, tail = lines
        while whole and not whole[0]:
            whole.pop(0)
        if not whole:
            # the header line itself is unfinished: a wire body only if it can
            # still become one
            return "undecidable" if tail and bundlemod.HEADER.startswith(tail) else "bundle"
        if whole[0] != bundlemod.HEADER:
            return "bundle"
        b64 = 0
        for ln in whole[1:]:
            if not ln:
                if b64:
                    return "bundle"  # the base64 ended before the cut: whole, or no bundle
                continue
            if ln.startswith(">"):
                return "bundle"
            b64 += len(ln)
            if b64 > bundlemod.MAX_WIRE_B64_CHARS:
                return "oversized"
        if tail.startswith(">"):
            return "bundle"  # a quoted line, however it continues, ends the base64
        b64 += len(tail)
        if b64 > bundlemod.MAX_WIRE_B64_CHARS:
            return "oversized"
        return "undecidable"

    def _take_rows(
        self,
        rows: list[RawMail],
        peers: set[str],
        out: Fetched,
        got_ids: set[str],
        terminal: frozenset[str] = frozenset(),
    ) -> None:
        for m in rows:
            if m.gmail_id in got_ids or m.gmail_id in terminal:
                continue  # read once; a terminally rejected message is never judged again
            got_ids.add(m.gmail_id)
            why = self._classify(m, peers)
            if why is not None:
                if why != "self":
                    out.ignored.append((m, why))
                continue
            if m.truncated and m.unavailable:
                # a body the helper could not obtain could be a valid bundle (a
                # revocation among them): a fetch error for this mail, transient, and
                # the fetch is not complete
                out.truncated.append(m)
                out.complete = False
                out.transient = True
                continue
            verdict = self.cut_verdict(m.body) if m.truncated else "bundle"
            if verdict == "oversized":
                out.oversized.append(m)  # terminal (round-21 Z4)
            elif verdict == "undecidable":
                out.truncated.append(m)
                out.complete = False
                out.transient = True
            else:
                out.mails.append(m)

    def fetch(
        self,
        after: int | None = None,
        peers: set[str] | None = None,
        *,
        skip: frozenset[str] = frozenset(),
        terminal: frozenset[str] = frozenset(),
        slice_s: int | None = None,
    ) -> Fetched:
        """Every mail on the wire subject since the catch-up boundary, split into peer
        mail, ignored mail, peer mail the helper could not obtain (transient) and
        peer mail over the wire bound (terminal), with whether the fetch was
        complete: the whole window scanned through (`_search_slice`, slice by
        slice, oldest first: the mailbox identity asserted first, the first slice the
        whole window or the standing record's span, an overflowing slice read then
        halved, a completed slice's span doubled), every thread chunk answered,
        every peer body whole. `skip` names the threads recorded oversized (never
        asked for again), `terminal` the messages recorded oversized (never judged
        again); `peers` is the address set of this poll (`peer_addresses`, read
        inside the poll's storage boundary); read here when the caller gave none.
        A pass that ends on a budget or a flood with nothing transient is `progress`
        when at least one slice completed OR the halving narrowed the span (the
        narrowing is recorded with the position unchanged, so a dense window is
        narrowed a little further on every poll instead of from scratch; round-21
        self-gate, finding 1) — `scanned_through` and `slice_s` say what."""
        if after is None:
            after, slice_s = self.scan_start()
        if peers is None:
            peers = self.peer_addresses()
        self._pass_bytes = 0
        self.assert_mailbox()  # before any search, any cursor or freshness move
        out = Fetched()
        now_epoch = int(self.node.now().timestamp())
        seen_ids: set[str] = set()
        got_ids: set[str] = set()
        a = after
        span = slice_s
        while True:
            b: int | None = None if span is None or a + span >= now_epoch else a + span
            q = f"subject:({self.subject}) after:{a}" + (f" before:{b}" if b is not None else "")
            tids = self._search_slice(q, out, seen_ids)
            rows, whole = self._read_threads([t for t in tids if t not in skip], out)
            self._take_rows(rows, peers, out, got_ids, terminal)
            if out.stopped or out.searched_out or not whole:
                # the byte budget ended the pass, the searching ended (its threads
                # read above), or the slice was not read whole: named already
                break
            if out.overflow:
                # the slice's newest PAGE_CAP threads were listed and READ (applied
                # or marked seen by the caller, so a capped mailbox still moves); the
                # slice itself is not scanned through — halved, the same start, and
                # the threads already listed this pass are not listed again
                out.overflows += 1
                end = b if b is not None else now_epoch
                if end - a <= MIN_SLICE_S:
                    out.incomplete(
                        f"slice overflow: over {PAGE_CAP} threads between {a} and {end} "
                        f"(a flood no slice can walk)"
                    )
                    out.budget = True
                    span = end - a
                    break
                span = (end - a) // 2
                continue
            out.slices += 1
            if b is None:
                out.scanned_through = now_epoch  # the open-ended slice: the window is done
                out.slice_s = span
                break
            out.scanned_through = b
            out.slice_s = span
            a = b
            span = span * 2 if span is not None else None
        out.bytes = self._pass_bytes
        if out.truncated:
            out.incomplete(f"{len(out.truncated)} peer mail(s) unavailable or undecidable")
        if not out.complete and out.overflows:
            # the fact first: a slice listed PAGE_CAP threads with more to come
            out.incomplete_why = (
                f"page cap ({PAGE_CAP} threads in a slice; halved {out.overflows} time(s)); "
                + out.incomplete_why
            )
        if out.scanned_through is None:
            out.scanned_through = a  # the start of the slice in hand: nothing before it is lost
            out.slice_s = span
        # progress is recorded only for a pass that ended on a BUDGET or a flood with
        # nothing transient in it (a chunk that failed, a body not obtained: those
        # mails must stay inside the next scan) and either a slice completed or the
        # span narrowed below the one the pass started with
        narrowed = out.slice_s is not None and (slice_s is None or out.slice_s < slice_s)
        if (
            out.budget
            and not out.transient
            and (out.scanned_through > after or (out.overflows and narrowed))
        ):
            out.progress = True
            if out.slice_s is None:
                out.slice_s = max(now_epoch - after, MIN_SLICE_S)
        return out

    def poll_once(self) -> dict[str, Any]:
        """One pass, under the node's state lock: send the replies held from the last
        poll; fetch; decode each unseen mail; apply the control bundles (cards,
        revocations); after a COMPLETE fetch in which every write landed refresh the
        revocation freshness clock and advance the catch-up cursor; apply acks and
        messages and send their acks; then re-send what is past its ack deadline
        (also when the fetch failed). A send failure is reported and counted, never
        fatal; a storage failure leaves its mail unseen and the fetch incomplete."""
        with self.node.locked():
            return self._poll_once()

    def _contain(
        self, verb: str, what: str, do: Callable[[], Any], summary: dict[str, Any]
    ) -> bool:
        """The storage boundary around one read or write of the adapter's own state:
        an OSError, or a StorageError (a file of ours that does not parse), is
        reported and counted as a storage failure, and the poll goes on (the mail
        concerned stays unseen; the outbox still runs). Returns whether it landed."""
        try:
            do()
        except (OSError, StorageError) as e:
            msg = f"storage failure {verb} {what}: {type(e).__name__}: {e}"
            self.node.report(f"natively: {msg}; the poll goes on, the mail is read again next poll")
            summary["errors"].append(msg)
            summary["storage_failures"] += 1
            return False
        return True

    def _persist(self, what: str, do: Callable[[], Any], summary: dict[str, Any]) -> bool:
        """One of the adapter's own writes (the seen file, the cursor, the freshness
        sidecar, a held reply, the ledger line for an undecodable mail, the outbox
        bookkeeping) inside the boundary."""
        return self._contain("writing", what, do, summary)

    def _guard(self, what: str, do: Callable[[], Any], summary: dict[str, Any]) -> bool:
        """One of the adapter's own reads (the seen file, a held reply, the outbox
        listing) inside the boundary."""
        return self._contain("reading", what, do, summary)

    def _send_reply(
        self, r: dict[str, Any], held: Path, summary: dict[str, Any], what: str = "reply"
    ) -> bool:
        """Send a reply that is already held under `held`; on success delete the held
        copy. Returns whether every persistence step landed. Two failure classes,
        told apart by exception TYPE, never by message text: a STORAGE failure inside
        the send — the validation at the outgoing boundary (`Node.check_reply`:
        card.self_corrupt, reply.invalid, any IntegrityError), an OSError reading
        state or staging the body (nothing transmitted), or the staged body's removal
        after the tool returned (transmitted; `send` says so) — is a storage failure
        of the poll (counted, the held copy left in place, the poll incomplete, the
        cursor frozen; the copy goes out once more next poll, harmless: the peer
        dedups on msg_id); a TRANSPORT failure (the send tool's non-zero exit, a
        timeout: RuntimeError, SubprocessError) is not a persistence failure (the
        held copy simply goes out next poll). A failed deletion of a sent copy is a
        persistence failure (reported, counted; the same ack is sent once more next
        poll, harmless)."""
        try:
            self.send(r)
        except (OSError, StorageError) as e:
            msg = (
                f"storage failure in the send of {what} {held.name} (the held copy kept): "
                f"{type(e).__name__}: {e}"
            )
            self.node.report(f"natively: {msg}; the poll goes on, tried again next poll")
            summary["errors"].append(msg)
            summary["storage_failures"] += 1
            return False
        except Exception as e:  # noqa: BLE001 — a transport failure never ends the poll
            summary["errors"].append(f"ack send failed: {e}")
            self.node.report(
                f"natively: ack send failed, kept for the next poll ({held.name}): {e}"
            )
            return True
        summary["replies"] += 1
        # the removal is a write of the adapter's own: a failure there is reported
        # and the ack is simply sent once more next poll (the peer's stored ack is
        # the same object), never an escape from the poll
        return self._persist(f"the removal of sent {what} {held.name}", held.unlink, summary)

    def _held_reply_problem(self, r: Any, p: Path) -> str | None:
        """Why a parsed held copy is NOT the reply its name promises (<msg_id>.<kind>.json):
        the node's full reply validation against the name's id and kind. None when
        sound — and only then is it sent."""
        msg_id, kind = self.parse_held_name(p.name)
        return self.node.reply_problem(r, msg_id, kind)

    def _flush_pending_replies(self, summary: dict[str, Any]) -> None:
        """The replies held from earlier polls go out first. ORDER: the aside copies
        first — every unresolved one is counted as a storage failure (the poll stays
        incomplete, the cursor frozen) and its corruption audit written if the pass
        that moved it could not — THEN the held replies: each read, validated
        (`_held_reply_problem`) and sent. A held copy that cannot be READ (OSError)
        is reported, counted and left in place; one that does not parse, or is not
        the reply its name promises, is never deleted and never sent: moved aside,
        counted, ledgered, and left for the operator (`_quarantine_reply`). Nothing
        here rebuilds or sends from a damaged source — `natively pending repair`
        rebuilds from a validated source, and the reply it holds again goes out
        through this same path on the next poll. A listing or a validation that
        fails is a storage failure: nothing from it is sent, and the poll stays
        incomplete. When anything is held — an aside copy or a held reply —
        `Node.check_ledger` runs FIRST, inside the boundary, before any of it is
        read: a ledger that fails its check (ledger.head.mismatch and the rest) is
        one storage failure of the poll by that name and the flush ends there —
        nothing counted from the aside copies, no held reply sent, none removed;
        the acks held here witness the chain as recorded, and the aside copy and
        the canonical held reply both stay for the restore (round-14 self-gate:
        the aside count refused by name, then the canonical held reply was sent
        and removed on the same poll). With nothing held there is nothing to send
        or remove, and the receive runs its own full check on every mail."""
        aside: list[Path] = []
        pending: list[Path] = []
        if not self._guard(
            "the aside held replies", lambda: aside.extend(self._aside_replies()), summary
        ):
            return
        listing = lambda: pending.extend(self._pending_replies())  # noqa: E731
        if not self._guard("the held replies", listing, summary):
            return
        if not aside and not pending:
            return
        if not self._guard(
            "the ledger before the held replies go out", self.node.check_ledger, summary
        ):
            return
        for a in aside:
            self._count_aside(a, summary)
        for p in pending:
            got: list[Any] = []
            try:
                # the typed loader (an envelope is an object; the ONE validation
                # judges the rest): a copy that does not parse or is not an object
                # is state.corrupt, quarantined below like any copy that fails
                got.append(statemod.read(p, None, statemod.held_reply))
            except StorageError as e:  # a held copy of ours that does not parse
                self._quarantine_reply(p, f"{type(e).__name__}: {e}", summary)
                continue
            except OSError as e:
                msg = f"storage failure reading held reply {p.name}: {type(e).__name__}: {e}"
                self.node.report(f"natively: {msg}; left in place, tried again next poll")
                summary["errors"].append(msg)
                summary["storage_failures"] += 1
                continue
            r = got[0]
            problem: list[str | None] = []
            if not self._guard(
                f"the validation of held reply {p.name}",
                lambda r=r, p=p, problem=problem: problem.append(self._held_reply_problem(r, p)),
                summary,
            ):
                continue  # left in place, validated again next poll
            if problem[0] is not None:
                self._quarantine_reply(p, problem[0], summary)
                continue
            self._send_reply(r, p, summary, what="held reply")

    @staticmethod
    def held_name_of(aside: Path) -> str:
        """The canonical held name an aside copy was moved from."""
        return aside.name.split(".corrupt-", 1)[0]

    @staticmethod
    def _stamp(ts: str) -> str:
        return ts.replace("-", "").replace(":", "")

    def _aside_path(self, p: Path) -> Path:
        """<name>.corrupt-<stamp>-<ulid>: an identity no later quarantine can reuse
        (the stamp is the clock, readable; the ulid is unique, so an audit keyed on
        it can never be found for another copy, even after this one is discarded)."""
        return p.with_name(f"{p.name}.corrupt-{self._stamp(self.node.ts())}-{new_id('qtn')[4:]}")

    @staticmethod
    def _audit_key(name: str) -> str:
        """The exact token an audit's detail carries for one aside copy: bracketed,
        so `x.corrupt-S` never matches the audit of `x.corrupt-S-2`."""
        return f"[aside {name}]"

    @staticmethod
    def _invalid_key(name: str) -> str:
        """The exact token a pending_reply.invalid entry carries for one held name (a
        reply refused before it was held: no aside copy exists for it)."""
        return f"[invalid {name}]"

    def _find_pending_entry(
        self, action: str, key: str, *, token: str | None = None
    ) -> dict[str, Any] | None:
        """The pending-reply audit (`action`, keyed on the exact token for `key`) on
        record, or None — an audit the caller then TRUSTS: a discard it finishes,
        a reconstruction it only marks, a corruption audit it does not repeat.
        `Node.check_ledger` is the FIRST ledger read here (the repair guard, the
        chain, every entry, the mirror through the head, the stored acks'
        anchors), inside the caller's storage boundary: a ledger that fails its
        check is a storage failure of the poll or the verb by the ledger's own
        name (ledger.head.mismatch and the rest) — nothing is decided from its
        entries, nothing deleted, the aside copy and the canonical held reply
        kept, no durability barrier reached. (An anchored last completion edited
        into a matching discard record, its mirror line removed, read as the
        decision to delete both files: round-13 gate, finding 2.)"""
        self.node.check_ledger()
        token = token or self._audit_key(key)
        for e in self.node.ledger.entries():
            if e["action"] == action and token in e.get("detail", ""):
                return e
        return None

    def _ledger_pending_once(
        self, action: str, msg_id: str | None, detail: str, key: str, *, token: str | None = None
    ) -> dict[str, Any]:
        """The audit entry for one aside copy (or, with `token`, one held name),
        appended once: the exact token for `key` is in the detail, so a retry after
        the entry became visible but its step failed finds it instead of appending
        it again — and a FOUND entry may be an unsynced tail (its append failed
        after the bytes), so the ledger barrier is re-established before it is
        relied on. Returns the entry (found or appended)."""
        token = token or self._audit_key(key)
        found = self._find_pending_entry(action, key, token=token)
        if found is not None:
            self.node.ledger.barrier()
            return found
        return self._ledger_pending(action, msg_id, f"{detail} {token}")

    def _ledger_pending(self, action: str, msg_id: str | None, detail: str) -> dict[str, Any]:
        # the ledger in full before the adapter's own append (`Node.ledger_append`)
        return self.node.ledger_append(
            ts=self.node.ts(),
            actor="wire",
            grant_id=None,
            action=action,
            params_hash=None,
            outcome="recorded",
            msg_id=msg_id,
            detail=detail,
            direction="out",
        )

    def _quarantine_reply(self, p: Path, why: str, summary: dict[str, Any]) -> Path:
        """A held reply that does not parse or is not its reply: moved aside in the
        same directory (an os.replace, the directory fsynced; the aside name chosen
        inside the same boundary), counted as a storage failure, ledgered
        pending_reply.corrupt once with the message id from its name — and that is
        all: never deleted, never sent, nothing rebuilt from it. Every later poll
        counts the aside copy again until an operator resolves it. Returns the aside
        path (the original path when the move itself failed: the next poll reads,
        fails to validate and quarantines it again)."""
        msg = f"storage failure reading held reply {p.name}: not a valid held reply: {why}"
        self.node.report(
            f"natively: {msg}; moved aside, never deleted, never sent; `natively pending "
            f"repair` rebuilds it from a validated source"
        )
        summary["errors"].append(msg)
        summary["storage_failures"] += 1
        moved: list[Path] = []

        def move() -> None:
            aside = self._aside_path(p)
            os.replace(p, aside)
            fsync_dir(self.pending_dir)
            moved.append(aside)

        if not self._persist(f"the quarantine of held reply {p.name}", move, summary):
            return p
        aside = moved[0]
        self._audit_aside(aside, why, summary)  # a failure here: the next poll writes it
        return aside

    def _audit_aside(self, aside: Path, why: str, summary: dict[str, Any]) -> bool:
        """The pending_reply.corrupt entry for an aside copy, appended once (keyed on
        the aside name); a retry after an audit that failed writes it then."""
        msg_id, _kind = self.parse_held_name(aside.name)
        held_name = self.held_name_of(aside)
        return self._persist(
            f"the ledger line for corrupt held reply {held_name}",
            lambda: self._ledger_pending_once(
                "pending_reply.corrupt",
                msg_id,
                f"held reply {held_name} did not parse ({why[:120]}); moved aside as {aside.name}",
                aside.name,
            ),
            summary,
        )

    def _count_aside(self, aside: Path, summary: dict[str, Any]) -> None:
        """One aside copy, whatever its suffix. A discard on record whose removal did
        not finish (the copy is still on disk) is a storage failure, named as such:
        `natively pending discard NAME` again (or `pending repair`) finishes it from
        the record. An unresolved copy is a
        storage failure too (the poll stays incomplete, the cursor frozen) — every
        poll, until a verb resolves it — and its corruption audit is written if the
        pass that moved it could not (once, keyed on the exact name). A resolved copy
        with no discard on record is inert. A poll removes nothing and rebuilds
        nothing."""
        discarded: list[dict[str, Any] | None] = []
        if not self._guard(  # a lookup that fails is the storage failure counted
            f"the discard record of {aside.name}",
            lambda: discarded.append(
                self._find_pending_entry("pending_reply.discarded", aside.name)
            ),
            summary,
        ):
            return
        if discarded[0] is not None:
            summary["storage_failures"] += 1
            msg = (
                f"storage failure: discarded held reply {aside.name} is still on disk (its "
                f"removal did not finish); `natively pending discard {aside.name}` or "
                f"`natively pending repair` finishes it"
            )
            self.node.report(f"natively: {msg}")
            summary["errors"].append(msg)
            return
        if not self._unresolved(aside):
            return
        summary["storage_failures"] += 1
        msg = (
            f"storage failure: corrupt held reply {aside.name} is still aside and unresolved; "
            f"`natively pending repair` rebuilds it from a validated source, `natively "
            f"pending discard {aside.name}` drops it"
        )
        self.node.report(f"natively: {msg}")
        summary["errors"].append(msg)
        self._audit_aside(aside, "audited on a later poll", summary)

    DROPS_HELD = "[held reply dropped too]"  # in a discard record made with --with-held

    # ---- the operator's `natively pending` verbs (under the node lock) ----
    def pending_status(self) -> list[dict[str, Any]]:
        """Every file under pending-replies/, one row each: a held reply to send
        (`held`), an aside copy unresolved (`corrupt`), resolved by the repair verb
        (`reconstructed`), or discarded on record with its removal unfinished
        (`discarded`). Under the lock; the reads are the caller's to contain."""
        out = []
        for p in list_dir(self.pending_dir):
            msg_id, kind = self.parse_held_name(p.name)
            if ".corrupt-" not in p.name:
                status = "held"
            elif self._find_pending_entry("pending_reply.discarded", p.name) is not None:
                status = "discarded"  # on record; the removal did not finish
            elif not self._unresolved(p):
                status = "reconstructed"
            else:
                status = "corrupt"
            out.append({"name": p.name, "status": status, "msg_id": msg_id, "kind": kind})
        return out

    def repair_pending(self, name: str | None = None) -> dict[str, Any]:
        """`natively pending repair [NAME]`: rebuild every unresolved aside copy (or
        the named one) from a VALIDATED source only — the stored ack after the full
        reply validation, else the ledger completion — held again under the
        canonical name for the next poll's flush to validate and send; the verb
        never sends. A copy with no validated source is refused by name
        (`unresolvable`); one whose canonical name holds a different file is refused
        too (`pending_reply.conflict`, both files left). The discard record is
        checked BEFORE anything is decided from the suffix: a copy with a discard on
        record and files still present is an unfinished discard — finished here from
        its record (`_remove_discarded`, the same resumable path the discard verb
        takes: the ledger barrier, then the removal the record calls for), reported
        as `discarded`, never rebuilt, whatever its suffix. Storage failures are
        counted in the returned summary like a poll's. Under the lock."""
        summary: dict[str, Any] = {
            "rebuilt": [],
            "unresolvable": [],  # (name, why)
            "refused": [],  # (name, why)
            "resolved": [],  # already marked; the mark's directory barrier re-established
            "discarded": [],  # a discard on record, unfinished: finished from the record here
            "storage_failures": 0,
            "errors": [],
        }
        with self.node.locked():
            aside: list[Path] = []
            if not self._guard(
                "the aside held replies", lambda: aside.extend(self._aside_replies()), summary
            ):
                return summary
            if name is not None:
                aside = [a for a in aside if a.name == name]
                if not aside:
                    raise FileNotFoundError(
                        f"{name} is not an aside copy under {self.pending_dir} (see `pending list`)"
                    )
            for a in aside:
                discarded: list[dict[str, Any] | None] = []
                if not self._guard(
                    f"the discard record of {a.name}",
                    lambda a=a, discarded=discarded: discarded.append(
                        self._find_pending_entry("pending_reply.discarded", a.name)
                    ),
                    summary,
                ):
                    continue
                if discarded[0] is not None:
                    # the decision stands and its removal did not finish: finished from
                    # the record (a found record may be an unsynced tail: the ledger
                    # barrier first), nothing rebuilt
                    record = discarded[0]
                    self.node.report(
                        f"natively: pending repair: {a.name} is discarded on record and still "
                        f"on disk; finishing the removal from the record, nothing rebuilt"
                    )

                    def finish(a=a, record=record) -> None:
                        self.node.ledger.barrier()
                        self._remove_discarded(a.name, record)

                    if self._persist(f"the unfinished discard of {a.name}", finish, summary):
                        summary["discarded"].append(a.name)
                    continue
                if self._unresolved(a):
                    self._repair_aside(a, summary)
                else:
                    summary["resolved"].append(a.name)
            if summary["resolved"]:
                # a mark whose rename landed but whose directory fsync failed looks
                # finished and would never be retried by name: every visible mark's
                # barrier is re-established here, once per run
                self._persist(
                    "the directory barrier of the resolved marks",
                    lambda: fsync_dir(self.pending_dir),
                    summary,
                )
        return summary

    def _repair_aside(self, aside: Path, summary: dict[str, Any]) -> None:
        """One unresolved aside copy with no discard on record (`repair_pending`
        checked), every step resumable through the ledger record: the corruption
        audit first (once); a reconstruction already on record (a run that failed
        at the mark) is only marked, after the ledger barrier (the found audit may be an
        unsynced tail; its hold was durable before the audit was written); else the
        source (`_rebuild_source`), held under the canonical name — a DIFFERENT file
        there refuses (`pending_reply.conflict`), both files stay — ledgered
        pending_reply.reconstructed once, then the aside marked .reconstructed
        (durably), the mark never outrunning the hold or the audit. Never sends."""
        msg_id, _kind = self.parse_held_name(aside.name)
        if msg_id is None:
            summary["unresolvable"].append((aside.name, "the name carries no message id"))
            return
        if not self._audit_aside(aside, "audited by pending repair", summary):
            return
        done = aside.with_name(aside.name + ".reconstructed")
        found: list[dict[str, Any] | None] = []

        def look() -> None:
            e = self._find_pending_entry("pending_reply.reconstructed", done.name)
            if e is not None:
                self.node.ledger.barrier()  # a found audit may be an unsynced tail
            found.append(e)

        if not self._guard(f"the rebuild record of held reply {aside.name}", look, summary):
            return
        if found[0] is None:
            box: list[tuple[dict[str, Any] | None, str]] = []
            if not self._guard(
                f"the source for held reply {aside.name}",
                lambda: box.append(self._rebuild_source(msg_id)),
                summary,
            ):
                return
            r, source = box[0]
            if r is None:
                self.node.report(f"natively: pending_reply.unresolvable {aside.name}: {source}")
                summary["unresolvable"].append((aside.name, source))
                return
            conflict: list[str] = []

            def hold() -> None:
                try:
                    self._hold_reply(r, msg_id)
                except IntegrityError as e:
                    if e.reason != "pending_reply.conflict":
                        raise
                    conflict.append(e.detail)

            if not self._persist(f"the rebuilt held reply for {msg_id}", hold, summary):
                return
            if conflict:
                self.node.report(f"natively: pending repair refused {aside.name}: {conflict[0]}")
                summary["refused"].append((aside.name, conflict[0]))
                return
            if not self._persist(
                f"the ledger line for rebuilt held reply {aside.name}",
                lambda: self._ledger_pending_once(
                    "pending_reply.reconstructed",
                    msg_id,
                    f"reply for {msg_id} rebuilt from {source} and held again as "
                    f"{self.held_name_of(aside)}; the corrupt copy kept as {done.name}",
                    done.name,
                ),
                summary,
            ):
                return  # unresolved still: the next run finds the audit and marks
            self.node.report(f"natively: held reply for {msg_id} rebuilt from {source}, held again")

        def mark() -> None:
            os.replace(aside, done)
            fsync_dir(self.pending_dir)

        if self._persist(f"the resolved mark of {aside.name}", mark, summary):
            summary["rebuilt"].append(aside.name)

    def _rebuild_source(self, msg_id: str) -> tuple[dict[str, Any] | None, str]:
        """The one validated source a reply may be rebuilt from, and its name: the
        stored ack when it passes the full reply validation; else the ledger
        completion (`Node.rebuild_from_completion`: the ledger's full check with its
        anchors first — so a stored ack that no longer verifies is seen.corrupt
        there, a storage failure, never rebuilt over — then the barrier, then the
        ack stored), checked the same way; else (None, why).
        Only a source that is present and READS cleanly but fails validation falls
        through to the next: a storage error while a candidate is read (the seen
        file, the self card, a card on file) is raised through — the caller's
        storage failure, reported by name with the path, the copy left unresolved —
        never taken for an absent or damaged source."""
        r, why = self.node.stored_reply(msg_id)
        if r is not None:
            return r, "the stored ack"
        if why is not None:
            self.node.report(
                f"natively: the stored ack for {msg_id} is damaged ({why}); "
                f"trying the ledger completion"
            )
        r = self.node.rebuild_from_completion(msg_id)
        if r is None:
            return None, (
                "no validated source: the stored ack "
                + ("is damaged" if why is not None else "is absent")
                + " and no completion entry names one card on file"
            )
        problem = self.node.reply_problem(r, msg_id, "ack")
        if problem is not None:
            return None, f"the ack rebuilt from the completion does not verify: {problem}"
        return r, "the ledger completion"

    def discard_pending(self, name: str, *, with_held: bool = False) -> dict[str, Any]:
        """`natively pending discard NAME [--with-held]`: the operator's decision to
        drop an aside copy, ledgered pending_reply.discarded BEFORE any removal
        (once, keyed on the exact name; the record carries DROPS_HELD when
        --with-held), then the removal the RECORD calls for: with --with-held the
        canonical held reply of that message first, its directory fsynced, then the
        aside copy, its directory fsynced. Without --with-held a canonical held
        reply for the message refuses the discard (it is an obligation the next
        poll sends; say --with-held to drop it too). A retry that finds the record
        finishes the removal from the record, whichever file is already gone (a
        missing file is a finished step); a second discard of a finished name
        appends nothing. Under the lock. Returns what was done."""
        if "/" in name or ".corrupt-" not in name:
            raise FileNotFoundError(f"{name} is not an aside copy name (see `pending list`)")
        p = self.pending_dir / name
        held = self.pending_dir / self.held_name_of(p)
        msg_id, _kind = self.parse_held_name(name)
        with self.node.locked():
            record = self._find_pending_entry("pending_reply.discarded", name)
            if record is not None:
                self.node.ledger.barrier()  # a found record may be an unsynced tail
                found = True
            elif not p.exists():
                raise FileNotFoundError(f"{name} is not an aside copy under {self.pending_dir}")
            else:
                if not with_held and held.exists():
                    raise FileExistsError(
                        f"a held reply {held.name} stands for {msg_id} (the next poll sends "
                        f"it); `pending discard {name} --with-held` drops it too"
                    )
                record = self._ledger_pending_once(
                    "pending_reply.discarded",
                    msg_id,
                    f"operator discarded the aside held reply {name}"
                    + (f" {self.DROPS_HELD}" if with_held else ""),
                    name,
                )
                found = False
            drops_held = self._remove_discarded(name, record)
        return {"record": "found" if found else "appended", "with_held": drops_held}

    def _remove_discarded(self, name: str, record: dict[str, Any]) -> bool:
        """The removal a discard RECORD calls for — the one resumable path the discard
        verb and `pending repair` share: with the record's `[held reply dropped too]`
        the canonical held reply of that message first (the cancelled obligation is
        durable on its own before the evidence of the decision leaves the
        directory), its directory fsynced; then the aside copy, its directory
        fsynced. A missing file is a finished step. Returns whether the record
        drops the held reply."""
        p = self.pending_dir / name
        held = self.pending_dir / self.held_name_of(p)
        drops_held = self.DROPS_HELD in record.get("detail", "")
        if drops_held:
            held.unlink(missing_ok=True)
            fsync_dir(self.pending_dir)
        p.unlink(missing_ok=True)
        fsync_dir(self.pending_dir)
        return drops_held

    def _apply(
        self,
        batch: list[tuple[int, int, RawMail, dict[str, Any]]],
        summary: dict[str, Any],
    ) -> bool:
        """Apply each bundle; hold every reply durably (validated first: a reply that
        fails is not held, pending_reply.invalid); mark the mail seen; validate each
        reply AGAIN (the same `Node.reply_problem`) and send it, deleting the held
        copy — one that fails now is never sent: quarantined like a held copy the
        flush refuses (the mail is seen by then; the held copy is the obligation).
        A local storage failure inside one receive (StorageError), in a hold, or in
        the seen-file write leaves THAT mail unseen — read again next poll (the
        node's own seen.json answers the re-read with the stored ack) — and is
        counted; the batch goes on. Returns whether every write landed."""
        ok = True
        for _rank, _i, m, b in batch:
            try:
                replies = self.node.receive(b)
            except StorageError as e:
                ok = False
                summary["errors"].append(f"storage failure on mail {m.gmail_id}: {e.detail}")
                summary["storage_failures"] += 1
                continue
            summary["applied"] += 1
            # the reply obligation is durable BEFORE the seen mark: a hold that fails
            # leaves the mail unseen, so it is read (and answered) again next poll
            held: list[Path] = []
            if not self._hold_all(m, b, replies, held, summary):
                ok = False
                continue
            note = f"{b['kind']}:{b['object'].get('msg_id') or b['object'].get('ack_id') or ''}"
            if not self._persist(
                f"the seen file for mail {m.gmail_id}",
                lambda m=m, note=note: self._mark_seen(m.gmail_id, note),
                summary,
            ):
                # the replies are not sent now: they are held, and go out at the
                # start of the next poll whether or not the mark became visible
                ok = False
                continue
            for r, p in zip(replies, held, strict=True):
                ok &= self._send_held(r, p, summary)
        return ok

    def _send_held(self, r: dict[str, Any], p: Path, summary: dict[str, Any]) -> bool:
        """The direct send of a reply just held under `p`: validated once more
        (`_held_reply_problem`, the same check the hold and the flush run) inside
        the boundary, sent only when sound; a reply that fails is quarantined (never
        sent, never deleted), a validation that cannot run leaves the held copy for
        the next poll's flush. Returns whether every persistence step landed."""
        problem: list[str | None] = []
        if not self._guard(
            f"the validation of reply {p.name} before its send",
            lambda: problem.append(self._held_reply_problem(r, p)),
            summary,
        ):
            return False  # held; the next poll's flush validates it again
        if problem[0] is not None:
            self._quarantine_reply(p, problem[0], summary)
            return False
        return self._send_reply(r, p, summary)

    def _hold_all(
        self,
        m: RawMail,
        b: dict[str, Any],
        replies: list[Any],
        held: list[Path],
        summary: dict[str, Any],
    ) -> bool:
        """Hold every reply for mail `m` (the bundle `b`) durably (into `held`), each
        under the name of the message it answers — the id taken from the REQUEST;
        False at the first hold that fails."""
        msg_id = b["object"].get("msg_id")
        for r in replies:
            if not self._persist(
                f"a held reply for mail {m.gmail_id}",
                lambda r=r: held.append(self._hold_reply(r, msg_id)),
                summary,
            ):
                return False
        return True

    def _process_outbox(self, summary: dict[str, Any]) -> None:
        """Re-send what is past its ack deadline; ledger what is out of attempts.
        Independent of the fetch: runs on every poll, a failed fetch included. The
        listing and each entry's bookkeeping are inside the storage boundary: a
        failure on one entry is counted and the remaining entries are still
        processed; a failure listing the outbox ends the step. A re-send's failure
        is classed by exception TYPE like a held reply's (`_send_reply`): an OSError
        or a StorageError inside the send is a storage failure of the poll (counted,
        the entry kept, no attempt spent, the cursor frozen); a transport failure
        spends no attempt and counts nothing."""
        due: list[dict[str, Any]] = []
        if not self._guard("the outbox", lambda: due.extend(self.node.outbox_due()), summary):
            return
        for x in due:
            if x["attempts"] > MAX_RESENDS:
                if self._persist(
                    f"the undelivered mark for {x['msg_id']}",
                    lambda x=x: self.node.outbox_mark_undelivered(x["msg_id"]),
                    summary,
                ):
                    summary["undelivered"] += 1
                continue
            try:
                self.send(x["bundle"], resend=True)
            except (OSError, StorageError) as e:
                msg = (
                    f"storage failure re-sending {x['msg_id']} (the entry kept, no attempt "
                    f"spent): {type(e).__name__}: {e}"
                )
                self.node.report(f"natively: {msg}")
                summary["errors"].append(msg)
                summary["storage_failures"] += 1
                continue
            except Exception as e:  # noqa: BLE001 — a failed re-send spends no attempt
                self.node.report(
                    f"natively: re-send of {x['msg_id']} failed, attempt not counted: {e}"
                )
                summary["errors"].append(f"re-send of {x['msg_id']} failed: {e}")
                continue
            summary["resent"] += 1
            self._persist(
                f"the attempt count for {x['msg_id']}",
                lambda x=x: self.node.outbox_advance(x["msg_id"]),
                summary,
            )

    def _poll_once(self) -> dict[str, Any]:
        summary: dict[str, Any] = {
            "fetched": 0,
            "ignored": 0,
            "applied": 0,
            "replies": 0,
            "resent": 0,
            "undelivered": 0,
            "storage_failures": 0,
            "fetch_failures": 0,  # the fetch raised (wire, subprocess), or a chunk failed
            "rejected": 0,  # oversized mails and threads recorded this pass (terminal)
            "scan_recorded": None,  # the position a budget-ended pass recorded
            "deferred": 0,  # ack/message mails left unseen because the control phase did not land
            "complete": False,
            "errors": [],
        }
        # replies held from the last poll go out FIRST: the peer is waiting on them,
        # and nothing about them depends on what this poll fetches
        self._flush_pending_replies(summary)
        # the seen file: without it the poller cannot know what is seen, so a read
        # failure ends the fetch-and-apply half of this poll (the outbox still runs)
        seen_box: list[dict[str, str]] = []
        if not self._guard("the seen file", lambda: seen_box.append(self._seen()), summary):
            self.node.report(
                "natively: the seen file could not be read: nothing fetched or applied"
            )
            self._process_outbox(summary)
            return summary
        seen = seen_box[0]
        # the cursor is local state, read inside the boundary like the seen file: a
        # read that fails (OSError, a cursor of ours that does not parse) is a
        # storage failure, and the poller cannot know where to start — nothing is
        # fetched or applied this pass, the outbox still runs
        start_box: list[tuple[int, int | None]] = []
        if not self._guard("the cursor", lambda: start_box.append(self.scan_start()), summary):
            self.node.report("natively: the cursor could not be read: nothing fetched or applied")
            self._process_outbox(summary)
            return summary
        # the peer addresses are local state read inside the boundary like the seen
        # file and the cursor: a config that fails the typed load (an element that is
        # not an address, named by index) or names no peer (config.no_peers) is a
        # storage failure — nothing fetched, nothing classified, nothing seen, the
        # clock and the cursor unmoved; the outbox still runs
        peers_box: list[set[str]] = []
        if not self._guard(
            "the peer addresses", lambda: peers_box.append(self.peer_addresses()), summary
        ):
            self.node.report(
                "natively: the peer addresses could not be read: nothing fetched or applied"
            )
            self._process_outbox(summary)
            return summary
        skip = frozenset(k[len(THREAD_SEEN) :] for k in seen if k.startswith(THREAD_SEEN))
        terminal = frozenset(k for k, note in seen.items() if note.startswith("oversized:"))
        try:
            after, slice_s = start_box[0]
            got = self.fetch(after, peers_box[0], skip=skip, terminal=terminal, slice_s=slice_s)
        except (RuntimeError, subprocess.SubprocessError, OSError) as e:
            # wire and subprocess failures only (the helper failed, timed out, could
            # not be run, or answered nonsense): reported, and freshness is NOT reset
            self.node.report(f"natively: mail fetch failed, revocation lookup NOT refreshed: {e}")
            summary["errors"].append(str(e))
            summary["fetch_failures"] += 1
            self._process_outbox(summary)  # due re-sends do not depend on the fetch
            return summary
        for msg in got.errors:  # a thread chunk that failed or timed out
            self.node.report(f"natively: {msg}; fetch incomplete, its mails are read next poll")
            summary["errors"].append(msg)
            summary["fetch_failures"] += 1
        for m in got.truncated:
            if m.gmail_id in seen:
                continue
            how = (
                f"could not be obtained by the mail helper ({m.unavailable})"
                if m.unavailable
                else (
                    f"was cut by the mail helper with its base64 unfinished and still under "
                    f"the wire bound ({m.body_chars} chars of text; undecidable)"
                )
            )
            msg = f"mail {m.gmail_id} body {how}; not marked seen, fetch incomplete"
            self.node.report(f"natively: {msg}")
            summary["errors"].append(msg)
        ignored_new = [(m, why) for m, why in got.ignored if m.gmail_id not in seen]
        landed = True
        # the terminal rejections (round-21 Z4, Z5): a peer mail cut past the wire
        # bound, a thread over the row bound — each ledgered ONCE (the reject row,
        # inside the boundary) and marked seen, so it is never fetched again; a
        # failure there leaves it unseen and the pass incomplete like any other
        for m in got.oversized:
            if m.gmail_id in seen:
                continue
            summary["rejected"] += 1
            msg = (
                f"mail {m.gmail_id} body carries base64 past the wire's "
                f"{bundlemod.MAX_WIRE_B64_CHARS} chars before the cut ({m.body_chars} chars of "
                f"text); rejected (wire.oversize), never re-fetched"
            )
            self.node.report(f"natively: {msg}")
            summary["errors"].append(msg)
            landed &= self._persist(
                f"the ledger line for oversized mail {m.gmail_id}",
                lambda m=m: self._ledger_oversized(m),
                summary,
            ) and self._persist(
                f"the seen file for oversized mail {m.gmail_id}",
                lambda m=m: self._mark_seen(m.gmail_id, f"oversized:{m.body_chars}"),
                summary,
            )
        for tid in got.oversized_threads:
            if THREAD_SEEN + tid in seen:
                continue
            summary["rejected"] += 1
            landed &= self._persist(
                f"the ledger line for oversized thread {tid}",
                lambda tid=tid: self._ledger_oversized_thread(tid),
                summary,
            ) and self._persist(
                f"the seen file for oversized thread {tid}",
                lambda tid=tid: self._mark_seen(THREAD_SEEN + tid, "oversized-thread"),
                summary,
            )
        if ignored_new:
            summary["ignored"] = len(ignored_new)
            self.node.report(
                f"natively: ignored {len(ignored_new)} mail(s) on the wire subject not from a "
                f"peer address or not on the exact subject: "
                + ", ".join(f"{m.gmail_id}({why})" for m, why in ignored_new[:10])
            )
            for m, why in ignored_new:
                landed &= self._persist(
                    f"the seen file for ignored mail {m.gmail_id}",
                    lambda m=m, why=why: self._mark_seen(m.gmail_id, f"ignored:{why}"),
                    summary,
                )
        batch: list[tuple[int, int, RawMail, dict[str, Any]]] = []
        for i, m in enumerate(got.mails):
            summary["fetched"] += 1
            if m.gmail_id in seen:
                continue
            try:
                b = bundlemod.decode(m.body)
            except VerifyError as e:
                self.node.report(
                    f"natively: mail {m.gmail_id} is not a v0 wire body: {e.reason} — {e.detail}"
                )
                landed &= self._persist(
                    f"the ledger line for undecodable mail {m.gmail_id}",
                    lambda m=m, e=e: self._ledger_undecodable(m, e),
                    summary,
                ) and self._persist(
                    f"the seen file for undecodable mail {m.gmail_id}",
                    lambda m=m, e=e: self._mark_seen(m.gmail_id, f"undecodable:{e.reason}"),
                    summary,
                )
                continue
            batch.append((KIND_ORDER[b["kind"]], i, m, b))
        batch.sort(key=lambda t: (t[0], t[1]))
        # control first: the cards and revocations this fetch carried are on file
        # (durably: the feed append fsyncs before it returns) before the clock says
        # the lookup is fresh and before any action is judged
        control = [t for t in batch if t[3]["kind"] in CONTROL_KINDS]
        actions = [t for t in batch if t[3]["kind"] not in CONTROL_KINDS]
        control_landed = self._apply(control, summary)
        landed &= control_landed
        if got.complete and control_landed:
            # the lookup is fresh BEFORE any action is judged (a catch-up poll must
            # authorize what it carried); the sidecar write is inside the boundary
            # (a failure is counted and the cursor does not advance either)
            landed &= self._persist("the freshness sidecar", self.node.mark_lookup_ok, summary)
        else:
            why = got.incomplete_why or "a storage failure left a control bundle unapplied"
            self.node.report(
                f"natively: {why}: fetch incomplete, revocation lookup NOT refreshed, "
                f"cursor not advanced"
            )
        if not control_landed:
            # a revocation (or a card) this poll carried is NOT on file: nothing that
            # could be judged against the old, still-valid clock is judged now. The
            # acks and messages stay unseen and are read again next poll, after the
            # control data landed.
            msg = (
                f"control phase did not land: {len(actions)} ack/message mail(s) deferred to "
                f"the next poll, none applied, none marked seen"
            )
            self.node.report(f"natively: {msg}")
            summary["errors"].append(msg)
            summary["deferred"] = len(actions)
        else:
            landed &= self._apply(actions, summary)
        # the outbox step BEFORE the completeness decision: its bookkeeping is
        # persistence of ours too, and a failure there must freeze the cursor like
        # any other storage failure of the pass
        self._process_outbox(summary)
        if got.complete and landed and summary["storage_failures"] == 0:
            # the cursor moves only once EVERY write this pass needed has landed and
            # no storage failure was counted anywhere in it — a mail left unseen, a
            # held reply that could not be flushed, a corrupt copy left aside, an
            # outbox mark that failed: each must stay inside the next window; the
            # scan record goes first (a record standing past a moved cursor would
            # only ever narrow a later window)
            if self._persist("the scan record's removal", self._clear_scan, summary) and (
                self._persist("the cursor", self._advance_cursor, summary)
            ):
                summary["complete"] = True
        elif got.complete:
            self.node.report(
                "natively: a storage failure left work undone: cursor not advanced, "
                "the pass is repeated next poll"
            )
        elif got.progress and landed and summary["storage_failures"] == 0:
            # the pass ended on a budget or a flood after at least one slice was
            # listed AND read, every mail of it applied or marked seen: the position
            # is recorded, and the next poll continues from it instead of starting
            # the window over (round-21 Z3); with any storage failure the record is
            # left as it was (a mail left unseen must stay inside the next scan)
            if self._persist("the scan record", lambda: self._record_scan(got), summary):
                summary["scan_recorded"] = got.scanned_through
                self.node.report(
                    f"natively: scan progress recorded: through {got.scanned_through}, slice "
                    f"{got.slice_s}s; the next poll continues from there"
                )
        return summary

    def _ledger_reject_once(self, action: str, token: str, detail: str) -> dict[str, Any]:
        """The reject row for one transport identity, appended ONCE: an existing row
        of that action carrying the exact token is found first (the ledger's full
        check runs in `_find_pending_entry`) and its barrier re-established — a
        retry after the audit landed but the seen write failed appends nothing
        (round-21 self-gate, finding 6)."""
        found = self._find_pending_entry(action, token, token=token)
        if found is not None:
            self.node.ledger.barrier()
            return found
        return self.node.ledger_append(
            ts=self.node.ts(),
            actor="wire",
            grant_id=None,
            action=action,
            params_hash=None,
            outcome="verify_failed:wire.size",
            detail=f"{detail} {token}",
        )

    def _ledger_oversized(self, m: RawMail) -> None:
        self._ledger_reject_once(
            "wire.oversize",
            f"[gmail {m.gmail_id}]",
            f"gmail {m.gmail_id} from {m.sender[:60]}: base64 past the wire's "
            f"{bundlemod.MAX_WIRE_B64_CHARS} chars before the cut ({m.body_chars} chars of text); "
            f"rejected, never re-fetched",
        )

    def _ledger_oversized_thread(self, tid: str) -> None:
        self._ledger_reject_once(
            "wire.thread_oversize",
            f"[gmail thread {tid}]",
            f"gmail thread {tid}: over {MAX_ROWS} rows or {CHUNK_OUTPUT_CAP} bytes of helper "
            f"output; rejected, never re-fetched",
        )

    def _ledger_undecodable(self, m: RawMail, e: VerifyError) -> None:
        # the ledger in full, its anchors included, before this append and the seen
        # mark that follows it (`Node.ledger_append`): a damaged ledger is the
        # storage failure here too (the mail unseen, the clocks unmoved), never a
        # line appended over it
        self.node.ledger_append(
            ts=self.node.ts(),
            actor="wire",
            grant_id=None,
            action="wire.decode",
            params_hash=None,
            outcome=f"verify_failed:{e.reason}",
            detail=f"gmail {m.gmail_id} from {m.sender[:60]}",
        )

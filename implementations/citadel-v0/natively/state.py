"""The ONE typed loader for every state file this node reads as a structure.

Local state is never peer input. Every state file — the seen file (reservations and
stored acks), the outbox, the pinned roots, the wire cursor, the freshness sidecar,
the transport seen file, a held reply, the config, the replay marker, a repair
intent, the peer heads, a card on file, a grant on file — comes through `read`,
which checks the top-level type AND the per-entry shape the code relies on, once,
at the read: a mismatch is IntegrityError state.corrupt (a card file: card.corrupt;
the callers that already carry a name keep it) naming the path and the reason.
A parse fault stays what durable.read_json makes it (state.corrupt, the same
class); absent is `default`. So an AttributeError, a TypeError or a KeyError from a
file of ours of the wrong shape is not reachable anywhere — in particular never as
verify_failed:malformed, which is a verdict on PEER input: a state file of the wrong
shape is a storage failure wherever it surfaces (receive refuses and the mail stays
unseen, the poll is incomplete and counts it, the repair verb reports it by name and
leaves the copy, the CLI exits 2 naming the path).

The shapes name what the code READS, no more. A stored ack is an object under `ack`
(the reply validation judges it); a reservation carries a `ts` string (use counting
parses it); an outbox entry the fields the retry schedule reads; a pinned root an
object under the key (its name is display only); a peer head a `head` string; a
card on file is a card in full (structure, both signatures) bound to its file name;
a grant on file is a grant DOCUMENT in full (structure with every field of its type,
the signatures under the keys it names, its embedded parent likewise and the
relation between the two — `grant.check_document`; only the rooting, the time
window, revocation, use counts and the extension flags stay `grant.verify`'s at
use) bound to its file name."""

from __future__ import annotations

import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import bundle as bundlemod
from . import card as cardmod
from . import grant as grantmod
from . import message as msgmod
from .durable import read_json
from .errors import IntegrityError, VerifyError
from .objects import is_id
from .timeutil import parse

OUTBOX_STATUSES = ("pending", "exported", "acked", "undelivered")

Shape = Callable[[Any], str | None]  # why a parsed value is NOT the shape, or None

REPAIR_STEPS = ("intent", "truncated", "audited")
_INTENT_FIELDS = "an object with step intent|truncated|audited, truncate_to and bytes integers, "
_INTENT_FIELDS += "tail_sha256 and file strings, intent_id an rpr_<26-char ULID> in full, "
_INTENT_FIELDS += "mirror_to (a termination intent's mirror cut point) a non-negative integer when "
_INTENT_FIELDS += "present, and at step audited an audit_hash string (sha256:<64 hex>)"
MISSING = object()


def read(p: Path, default: Any, shape: Shape, *, reason: str = "state.corrupt") -> Any:
    """A state file read as a structure: absent is `default`; a parse fault is
    state.corrupt (durable.read_json); a value that is not `shape` is IntegrityError
    `reason` naming the path and why. The only way a state file is read as a
    structure (a guard test greps the package for read_json callers)."""
    v = read_json(p, MISSING)
    if v is MISSING:
        return default
    why = shape(v)
    if why is not None:
        raise IntegrityError(reason, f"{p}: {why}")
    return v


def _kind(v: Any) -> str:
    return {type(None): "null", bool: "a boolean"}.get(type(v), f"a {type(v).__name__}")


def is_object(v: Any) -> str | None:
    return None if isinstance(v, dict) else f"not an object but {_kind(v)}"


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _fields(
    e: dict[str, Any],
    what: str,
    strs: tuple[str, ...] = (),
    ints: tuple[str, ...] = (),
    objs: tuple[str, ...] = (),
) -> str | None:
    for k in strs:
        if not isinstance(e.get(k), str):
            return f"{what}: {k} is not a string but {_kind(e.get(k))}"
    for k in ints:
        if not _is_int(e.get(k)):
            return f"{what}: {k} is not an integer but {_kind(e.get(k))}"
    for k in objs:
        if not isinstance(e.get(k), dict):
            return f"{what}: {k} is not an object but {_kind(e.get(k))}"
    return None


def seen(v: Any) -> str | None:
    """seen.json: msg_id -> a stored ack ({ack: <object>, ...}) or a reservation
    ({status: "in_progress", grant_id: <grt_ id>, ts: <timestamp>}) — a reservation
    IS a consumed use of that grant (use counting, the interrupted-resolution), so
    every field it counts by is checked, never defaulted."""
    if not isinstance(v, dict):
        return f"not an object (msg_id -> entry) but {_kind(v)}"
    for k, e in v.items():
        if not isinstance(e, dict):
            return f"entry {k!r} is not an object but {_kind(e)}"
        if "ack" in e:
            if not isinstance(e["ack"], dict):
                return f"entry {k!r}: ack is not an object but {_kind(e['ack'])}"
            continue
        why = _reservation(e)
        if why is not None:
            return (
                f"entry {k!r} is neither a stored ack (an object under ack) nor a "
                f"reservation ({why})"
            )
    return None


def _reservation(e: dict[str, Any]) -> str | None:
    if e.get("status") != "in_progress":
        return f"status is {e.get('status')!r}, not 'in_progress'"
    if not is_id(e.get("grant_id"), "grt_"):
        return f"grant_id is not a grt_ id but {_kind(e.get('grant_id'))}"
    ts = e.get("ts")
    if not isinstance(ts, str):
        return f"ts is not a string but {_kind(ts)}"
    try:
        parse(ts, "reservation.ts")
    except VerifyError as ex:
        return f"ts does not parse ({ex.detail})"
    return None


def outbox(v: Any) -> str | None:
    """outbox.json: a list of sends awaiting acks. Each entry's bundle is what a
    re-send TRANSMITS, so it is checked as a message bundle in full (the envelope,
    the message's structure and signature) and bound to the entry (its msg_id and
    recipient are the message's); the scheduling values parse; the status is one
    the retry schedule knows; the attempt count is an integer."""
    if not isinstance(v, list):
        return f"not a list of outbox entries but {_kind(v)}"
    for i, e in enumerate(v):
        if not isinstance(e, dict):
            return f"entry {i} is not an object but {_kind(e)}"
        what = f"entry {i}"
        why = _fields(
            e,
            what,
            strs=("msg_id", "to", "sent_at", "status", "due"),
            ints=("attempts",),
            objs=("bundle",),
        )
        if why is not None:
            return why
        if e["status"] not in OUTBOX_STATUSES:
            return f"{what}: status {e['status']!r} is not one of {OUTBOX_STATUSES}"
        if e["attempts"] < 1:
            return f"{what}: attempts {e['attempts']} is below 1"
        for k in ("sent_at", "due"):
            try:
                parse(e[k], f"outbox.{k}")
            except VerifyError as ex:
                return f"{what}: {k} does not parse ({ex.detail})"
        b = e["bundle"]
        try:
            bundlemod.check(b)
            if b["kind"] != "message":
                raise VerifyError("bundle.kind", f"kind {b['kind']!r} is not 'message'")
            msgmod.verify(b["object"])
        except VerifyError as ex:
            return f"{what}: bundle is not a message bundle ({ex.reason}: {ex.detail})"
        except Exception as ex:  # noqa: BLE001 — a shape the checkers did not expect
            return f"{what}: bundle is not a message bundle ({type(ex).__name__}: {ex})"
        m = b["object"]
        if m["msg_id"] != e["msg_id"]:
            return f"{what}: msg_id {e['msg_id']} is not the bundle's {m['msg_id']}"
        if m["to"] != e["to"]:
            return f"{what}: to {e['to']} is not the bundle's recipient"
    return None


def pinned(v: Any) -> str | None:
    """pinned.json: principal key -> {name, pinned_at} (an object; the code reads the keys)."""
    if not isinstance(v, dict):
        return f"not an object (principal key -> root) but {_kind(v)}"
    for k, e in v.items():
        if not isinstance(e, dict):
            return f"root {k!r} is not an object but {_kind(e)}"
    return None


def peer_heads(v: Any) -> str | None:
    """peer-heads.json: agent key -> {head: <string>, ...}."""
    if not isinstance(v, dict):
        return f"not an object (agent key -> head) but {_kind(v)}"
    for k, e in v.items():
        if not isinstance(e, dict):
            return f"head {k!r} is not an object but {_kind(e)}"
        why = _fields(e, f"head {k!r}", strs=("head",))
        if why is not None:
            return why
    return None


def address(a: Any, what: str) -> str | None:
    """Why `a` is not a peer address — a non-empty string, no whitespace (any
    Unicode whitespace, control or format character), exactly one @ — or None.
    The rule every element of peer_addresses passes at the typed load; the
    adapter never filters or coerces the list it reads (a peer address replaced
    with {} made that peer's mail ignored:sender and permanently seen, the poll
    complete and the cursor advanced: round-12 gate, finding 1)."""
    if not isinstance(a, str):
        return f"{what} is not a string but {_kind(a)}"
    if not a:
        return f"{what} is an empty string"
    if any(ch.isspace() or unicodedata.category(ch) in ("Cc", "Cf") for ch in a):
        return f"{what} carries whitespace or a control character ({a!r})"
    if a.count("@") != 1:
        return f"{what} is not one address (exactly one @): {a!r}"
    return None


CONFIG_KEYS = (
    "peer_email",
    "peer_addresses",
    "self_email",
    "subject",
    "poll_s",
    "extensions",
    "mail_account",
)
MAIL_ACCOUNTS = ("afik", "taylor")  # the helper's --account choices
EXTENSION_FLAGS = ("max_uses_per_window", "standing_denial")
POLL_S_MIN, POLL_S_MAX = 5, 86400  # the poll cadence's bounds: five seconds to one day


def config(v: Any) -> str | None:
    """config.json: an object whose keys are the known set (`CONFIG_KEYS`) and whose
    values, when present, are what the node reads — mail_account one of the helper's
    accounts (`MAIL_ACCOUNTS`), peer_email and self_email each
    an address (`address`: a mail whose From does not parse classified as "self"
    under an empty self_email, never counted and never seen), subject a non-empty
    string, poll_s an integer within `POLL_S_MIN`..`POLL_S_MAX` (0 made a tight loop
    and every new grant's check interval 0; a negative value reached time.sleep and
    put an outbox entry due before it was sent), peer_addresses a list whose EVERY
    element is an address, named by its index when it is not (an empty list is a
    valid shape here and `config.no_peers` at the poll), extensions an object of
    the known flags (`EXTENSION_FLAGS`) each a boolean. An unknown key or an
    unknown flag is refused by name: a value the node never reads is never stored
    as if it were policy (round-19 gate, finding 15; Fable finding 8)."""
    if not isinstance(v, dict):
        return f"not an object but {_kind(v)}"
    for k in v:
        if k not in CONFIG_KEYS:
            return f"{k!r} is not a config key (the keys are {', '.join(CONFIG_KEYS)})"
    for k in ("peer_email", "self_email"):
        if k in v:
            why = address(v[k], k)
            if why is not None:
                return why
    if "subject" in v:
        if not isinstance(v["subject"], str):
            return f"subject is not a string but {_kind(v['subject'])}"
        if not v["subject"].strip():
            return "subject is empty"
    if "poll_s" in v:
        if not _is_int(v["poll_s"]):
            return f"poll_s is not an integer but {_kind(v['poll_s'])}"
        if not POLL_S_MIN <= v["poll_s"] <= POLL_S_MAX:
            return f"poll_s {v['poll_s']} is outside {POLL_S_MIN}..{POLL_S_MAX} seconds"
    if "peer_addresses" in v:
        if not isinstance(v["peer_addresses"], list):
            return f"peer_addresses is not a list but {_kind(v['peer_addresses'])}"
        for i, a in enumerate(v["peer_addresses"]):
            why = address(a, f"peer_addresses[{i}]")
            if why is not None:
                return why
    if "mail_account" in v and v["mail_account"] not in MAIL_ACCOUNTS:
        return f"mail_account is not one of {', '.join(MAIL_ACCOUNTS)} but {v['mail_account']!r}"
    if "extensions" in v:
        ext = v["extensions"]
        if not isinstance(ext, dict):
            return f"extensions is not an object but {_kind(ext)}"
        for k, flag in ext.items():
            if k not in EXTENSION_FLAGS:
                return (
                    f"extensions.{k} is not an extension flag "
                    f"(the flags are {', '.join(EXTENSION_FLAGS)})"
                )
            if not isinstance(flag, bool):
                return f"extensions.{k} is not a boolean but {_kind(flag)}"
    return None


def replay_marker(v: Any) -> str | None:
    """replay-pending.json: {principals: [<string>...], why, ts}."""
    if not isinstance(v, dict):
        return f"not an object but {_kind(v)}"
    pks = v.get("principals")
    if not isinstance(pks, list) or not all(isinstance(x, str) for x in pks):
        return "principals is not a list of strings"
    return None


def repair_intent(v: Any) -> str | None:
    """<store>-repair-pending.json: the intent state machine's record."""
    ok = (
        isinstance(v, dict)
        and v.get("step") in REPAIR_STEPS
        and _is_int(v.get("truncate_to"))
        and _is_int(v.get("bytes"))
        and isinstance(v.get("tail_sha256"), str)
        and isinstance(v.get("file"), str)
        and ("mirror_to" not in v or (_is_int(v["mirror_to"]) and v["mirror_to"] >= 0))
        and (
            v.get("step") != "audited"
            or (
                isinstance(v.get("audit_hash"), str)
                and v["audit_hash"].startswith("sha256:")
                and len(v["audit_hash"]) == 71
            )
        )
    )
    if ok and not is_id(v.get("intent_id"), "rpr_"):
        # the id in FULL — the rpr_ prefix and exactly the ULID the package mints
        # (26 characters of its alphabet): a damaged id (`rpr_`, a prefix, a longer
        # string) is not this marker's identity and matches no audit; refused at the
        # load, the marker as found (round-14 gate, finding 3: a shortened id
        # matched an older repair's audit by substring and promoted its hash)
        return (
            f"not a repair intent: intent_id is not rpr_<26-char ULID> in full but "
            f"{v.get('intent_id')!r}; nothing truncated, nothing audited, nothing promoted: "
            f"inspect it, restore it from a backup or remove it by hand"
        )
    if ok:
        return None
    return (
        f"not a repair intent ({_INTENT_FIELDS}); nothing truncated, nothing audited: "
        f"inspect it, restore it from a backup or remove it by hand"
    )


def cursor(v: Any) -> str | None:
    """wire-cursor.json: {last_complete_fetch: <timestamp string>}."""
    if not isinstance(v, dict) or not isinstance(v.get("last_complete_fetch"), str):
        return "not an object with a last_complete_fetch string"
    return None


def scan_record(v: Any) -> str | None:
    """wire-scan.json: {scanned_through: <timestamp string>, slice_s: <positive int>, …}."""
    if not isinstance(v, dict) or not isinstance(v.get("scanned_through"), str):
        return "not an object with a scanned_through string"
    if not _is_int(v.get("slice_s")) or v["slice_s"] < 1:
        return "slice_s is not a positive integer"
    return None


def check_sidecar(v: Any) -> str | None:
    """revocations.check.json: {last_checked: <timestamp string>}."""
    if not isinstance(v, dict) or not isinstance(v.get("last_checked"), str):
        return "not an object with a last_checked string"
    return None


def seen_mail(v: Any) -> str | None:
    """seen-mail.json: gmail id -> a note string."""
    if not isinstance(v, dict):
        return f"not an object (gmail id -> note) but {_kind(v)}"
    for k, e in v.items():
        if not isinstance(e, str):
            return f"note for {k!r} is not a string but {_kind(e)}"
    return None


held_reply = is_object  # a held reply is an envelope; the reply validation judges the rest


def read_card(f: Path) -> dict[str, Any] | None:
    """A card under cards/ or cards-pending/: verified in full (structure, both
    signatures) and bound to its file name (the hash) on EVERY read, so a card whose
    agent key was damaged while its name survived is never a sender identity, a
    recipient, or a key signed for. A card that fails is local corruption —
    IntegrityError card.corrupt naming the path — never skipped. None when absent."""
    c = read(f, MISSING, is_object, reason="card.corrupt")
    if c is MISSING:
        return None
    try:
        h = cardmod.verify(c)
    except (VerifyError, TypeError, KeyError, AttributeError, ValueError) as e:
        raise IntegrityError("card.corrupt", f"{f}: {e}") from e
    if h[7:] != f.stem:
        raise IntegrityError("card.corrupt", f"{f}: the card's hash is not its name")
    return c


def read_grant(f: Path) -> dict[str, Any] | None:
    """A grant under grants/ or grants-embedded/: the DOCUMENT verified in full on
    EVERY read — the structure with every field of its type (every signature and key
    field a string of its encoding and length), the signature under the issuer key
    it names, its embedded parent's structure and signature and the relation between
    the two (`grant.check_document`, with the extension structure admitted whatever
    this node's flags say) — and bound to its file name (the grant id). A grant on
    file was authenticated before it was stored, so anything about the document that
    no longer holds is local corruption: IntegrityError state.corrupt naming the path
    and the reason, never a refusal at use (never no_authorizing_grant, which a
    restored file could not undo once acknowledged). What stays a refusal at use is
    what depends on the moment or this node's policy — the rooting in the pinned
    principals, the time window, revocation, use counts, the extension flags:
    `grant.verify`'s. None when absent."""
    g = read(f, MISSING, is_object)
    if g is MISSING:
        return None
    try:
        grantmod.check_document(g, extensions=grantmod.ANY_EXTENSION)
    except Exception as e:  # noqa: BLE001 — whatever a file of OURS makes the checker raise
        # (a VerifyError, a shape the checker did not expect, a RecursionError from a
        # constraint the engine cannot compile) is local corruption, never an escape
        raise IntegrityError("state.corrupt", f"{f}: not a grant ({type(e).__name__}: {e})") from e
    if g["grant_id"] != f.stem:
        raise IntegrityError("state.corrupt", f"{f}: the grant's id is not its name")
    return g

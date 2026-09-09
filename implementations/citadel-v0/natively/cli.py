"""natively CLI. Global options pick the state, keys, and scratch directories; every
verb is a thin call into the node or an adapter.

  natively keygen [--force]
  natively card [--agent-name N --node-name N --principal-name N] | card --show
  natively pin <principal-key> --name NAME
  natively cards
  natively grant --to REF (--file NAME | --resource R) --action A --statement S
                 [--param key=regex:RE | key=in:a,b | key=range:lo,hi]
                 [--expires-in S] [--max-uses N] [--window N,S] [--parent GRANT_ID]
  natively send --to REF (--info TEXT | --action A (--file NAME | --resource R)
                 [--param k=v ...] --grant ID ...) [--in-reply-to MSG] [--dry-run] [--out FILE]
  natively ack MSG_ID                       re-send the stored ack for a seen message
  natively poll [--file WIRE_BODY]          one pass (or apply a wire body from a file)
  natively run [--interval 60]              loop
  natively ledger show [--tail N] | ledger verify | ledger repair   (both under the state lock;
                                            repair regenerates missing trailing prose lines, and
                                            truncates a mirror longer than the JSONL, ledgered)
  natively feed verify | feed repair        the local revocation feed's framing (under the lock;
                                            repair truncates a torn partial last line only, then
                                            replays every held revocation and reopens authorization)
  natively denial verify | denial repair    the same for the standing-denial store
  natively pending list | pending repair [NAME] | pending discard NAME [--with-held]
                                            the held replies: list them and the corrupt copies
                                            moved aside (unresolved, reconstructed, discarded);
                                            rebuild every unresolved copy (or NAME) from a
                                            validated source — the stored ack, else the ledger
                                            completion — held again for the next poll to send
                                            (the verb never sends; no source = refused by name);
                                            or ledger the decision to drop one (--with-held drops
                                            the canonical held reply of that message too; without
                                            it a standing held reply refuses the discard)
  natively revoke (--grant ID ... | --card HASH ...) --statement S [--no-send]
  natively deny --action A --resource R --statement S [--agent HASH]
  natively outbox | config [--set k=v ...] | wire-decode FILE

`--out FILE` records the message as "exported" (delivered by hand, never re-sent by
the poll); `--dry-run` wins over `--out` (the wire body is still written for
inspection, nothing is recorded, nothing is sent); `poll --file` applies one wire
body and never refreshes the revocation freshness clock (only a complete mail poll
does).

Every bundle a verb writes to a file or hands to the wire — send, ack, revoke, the
card, the replies of poll --file, in the --out and the --dry-run --out forms alike —
crosses the node's ONE outgoing boundary first (`Node.check_outgoing`: a reply
through `check_reply`, every other kind through its own check): a bundle that fails
is exit 2 naming <kind>.invalid, no file written (an existing one untouched),
nothing recorded, nothing sent.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from . import bundle as bundlemod
from . import card as cardmod
from . import grant as grantmod
from . import keys
from . import message as msgmod
from . import state as statemod
from .durable import list_dir, load_local, write_json
from .errors import IntegrityError, NativelyError, VerifyError
from .executor import scratch_name_of, scratch_name_problem
from .ledger import prose_line
from .node import DEFAULT_CONFIG, Node, state_lock
from .objects import is_id
from .revocation import MAX_REVOKES
from .timeutil import fmt, plus

_CARD_HASH_RE = re.compile(r"sha256:[0-9a-f]{64}")

TOOL_DIR = Path(__file__).resolve().parents[1]


class Usage(Exception):
    """A bad invocation: printed as one line, exit 1. Every CLI value is validated
    before any work and before any write — an id argument of the wrong form, a
    non-positive interval or expiry, a negative tail, a window that does not
    parse, a config value the typed loader would refuse — so a refusal is one
    exit code with nothing written (round-19 gate, finding 15; Fable finding 8)."""


def _id(v: Any, what: str, prefix: str) -> str:
    """A protocol id argument in full (<prefix>_<26-char ULID>), else Usage."""
    if not is_id(v, prefix):
        raise Usage(f"{what} {v!r} is not a {prefix}<ULID> id")
    return v


def _card_hash(v: str) -> str:
    if not _CARD_HASH_RE.fullmatch(v):
        raise Usage(f"card hash {v!r} is not sha256:<64 hex>")
    return v


def _utf8(v: str, what: str) -> str:
    """A CLI text value that is valid UTF-8 — judged before the node. Python
    decodes an argv byte that is not UTF-8 with surrogateescape (`$'s\\xff'` is
    `s\\udcff`), and such a value passed every check here, constructed the node (its
    startup sweep and directory creation ran) and was refused only by the
    canonicalizer at signing (round-20 Fable read, N3). No document of ours can
    carry it, so it is refused by name here, first."""
    try:
        v.encode("utf-8")
    except UnicodeEncodeError as e:
        raise Usage(f"{what} is not valid UTF-8 ({e.reason} at offset {e.start})") from e
    return v


def _nonempty(v: Any, what: str, maximum: int | None = None) -> str:
    """A text value that the object it lands in requires non-empty (a name, a
    statement, an action, a resource, an info text), judged BEFORE the node is
    built — the node's own structure check would refuse it after the startup sweep
    had run (round-19 gate R6; Fable read: 26 shapes) — and valid UTF-8 (`_utf8`)."""
    if not isinstance(v, str) or not v:
        raise Usage(f"{what} must not be empty")
    _utf8(v, what)
    if maximum is not None and len(v) > maximum:
        raise Usage(f"{what} is over {maximum} characters")
    return v


def _scratch_file(v: str, what: str) -> str:
    """A `--file NAME` the executor's own rule admits (`executor.scratch_name_problem`):
    a grant or an action naming `../seen.json` or `a b` is refused here, before the
    node, never issued, signed and stored to be refused at every use (Fable C2)."""
    why = scratch_name_problem(v)
    if why is not None:
        raise Usage(f"{what}: {why}")
    return v


def _principal_key(v: str, what: str) -> str:
    try:
        keys.public_from_str(v, what)
    except VerifyError as e:
        raise Usage(f"{what} {v!r} is not a principal key ({e.detail})") from e
    return v


def _unique_ids(ids: list[str], what: str, maximum: int) -> None:
    """The aggregate rules a list of ids carries, judged before the node: at most
    `maximum`, and no id twice (round-20 self-gate, finding 6)."""
    if len(ids) > maximum:
        raise Usage(f"{what} names {len(ids)} ids; at most {maximum}")
    if len(set(ids)) != len(ids):
        raise Usage(f"{what} names an id twice")


def _body_within(body: dict[str, Any], what: str) -> None:
    """The message body as `message.build` will encode it, against the protocol's
    body bound, before the node (an oversized `--info` text or `--param` reached the
    node's own refusal after the startup sweep; round-20 self-gate, finding 6). The
    JSON's UTF-8 byte length, the bound `message.verify` applies to the decoded body
    — the base64 length admitted two bytes past it (second run, finding 5)."""
    if len(json.dumps(body, ensure_ascii=False).encode("utf-8")) > msgmod.MAX_BODY_BYTES:
        raise Usage(f"{what} is over {msgmod.MAX_BODY_BYTES} bytes encoded")


def _out_file(a) -> None:
    """`--out FILE`, when given, a non-empty name — judged before the node: an empty
    one read as "no file" and chose the live wire (round-20 self-gate, second run,
    finding 4)."""
    if a.out is not None:
        _nonempty(a.out, "--out")


def _aside_name(v: Any, what: str) -> str:
    """The NAME of an aside held copy (`pending repair NAME`, `pending discard
    NAME`): one file name of the `<msg_id>.<kind>.json.corrupt-<stamp>-<ulid>`
    shape — no separator, no NUL, never `.` or `..`, not empty."""
    if not isinstance(v, str) or not v or v in (".", "..") or "/" in v or "\x00" in v:
        raise Usage(f"{what} {v!r} is not an aside copy name (see `pending list`)")
    _utf8(v, what)
    if ".corrupt-" not in v:
        raise Usage(f"{what} {v!r} is not an aside copy name (see `pending list`)")
    return v


# the ceilings a CLI count may reach: ten years of seconds for an expiry or a window, a
# billion uses — a value past them is a Usage error before the node is built (before,
# `--expires-in 999999999999999999999999` reached the timestamp arithmetic after the
# startup sweep and ended in an OverflowError; round-19 self-gate, third run)
MAX_SECONDS = 10 * 366 * 86400
MAX_COUNT = 1_000_000_000


def _positive(v: int | None, what: str, maximum: int = MAX_COUNT) -> int | None:
    if v is not None and v < 1:
        raise Usage(f"{what} must be at least 1, not {v}")
    if v is not None and v > maximum:
        raise Usage(f"{what} must be at most {maximum}, not {v}")
    return v


def _window(spec: str) -> dict[str, int]:
    """--window N,S: N uses per S seconds, both integers >= 1, else Usage."""
    parts = spec.split(",")
    if len(parts) != 2:
        raise Usage(f"bad --window {spec!r}: use N,SECONDS")
    try:
        n, sec = int(parts[0]), int(parts[1])
    except ValueError as e:
        raise Usage(f"bad --window {spec!r}: {e}") from e
    if n < 1 or sec < 1:
        raise Usage(f"bad --window {spec!r}: N and SECONDS are at least 1")
    if n > MAX_COUNT or sec > MAX_SECONDS:
        raise Usage(f"bad --window {spec!r}: N at most {MAX_COUNT}, SECONDS at most {MAX_SECONDS}")
    return {"n": n, "window_s": sec}


def _check_globals(a: argparse.Namespace) -> None:
    """The three directory options, judged before any verb: one GIVEN and empty
    (`--scratch ""`) is refused by name — before, it read as absent and silently
    selected the default directory (round-20 gate, finding 3). `main` runs this
    first, so a refusal here reaches no verb and no node."""
    for flag, v in (("--state", a.state), ("--keys", a.keys), ("--scratch", a.scratch)):
        if v is not None and not v:
            raise Usage(f"{flag} given and empty (an empty name is never the default directory)")
        if v is not None:
            _utf8(v, flag)  # a directory name no state file of ours could record


def _dirs(a: argparse.Namespace) -> tuple[Path, Path, Path]:
    # `~` expanded here as the node expands it, so keygen's separation check and the
    # node see one path (round-19 self-gate, second run); None is absence, "" is
    # refused before this runs (`_check_globals`)
    _check_globals(a)
    state = Path(
        a.state if a.state is not None else os.environ.get("NATIVELY_STATE") or TOOL_DIR / "state"
    ).expanduser()
    kd = Path(
        a.keys if a.keys is not None else os.environ.get("NATIVELY_KEYS") or keys.DEFAULT_KEYS_DIR
    ).expanduser()
    scratch = Path(
        a.scratch
        if a.scratch is not None
        else os.environ.get("NATIVELY_SCRATCH") or TOOL_DIR / "scratch"
    ).expanduser()
    return state, kd, scratch


# ---- option applicability: which options each verb's MODE reads ------------------------
# Every option a verb declares, with how "given" is told: a value option is given when
# it is not None ("" is GIVEN, never absence), a list when non-empty, a flag when set, a
# positional when present. A MODE is what the verb does with the argv it got (the
# selector is itself an option, or the absence of one); an option GIVEN that the
# selected mode does not read is refused BY NAME before the node — never ignored
# (round-20 gate, finding 3: `poll --out reply.wire` without --file ran a LIVE poll
# with the file option ignored; `card --show --agent-name ""`, `pending list ..` and
# `pending repair --with-held` reached the node). The README's CLI section carries
# this table; tests/test_gate_round21.py derives one sentinel row per (verb, mode,
# unread option) from it.
_V, _L, _F, _P = "value", "list", "flag", "positional"
OPTIONS: dict[str, dict[str, str]] = {
    "keygen": {"--force": _F},
    "card": {
        "--show": _F,
        "--agent-name": _V,
        "--node-name": _V,
        "--principal-name": _V,
        "--principal-kind": _V,
        "--ledger-url": _V,
    },
    "pin": {"KEY": _P, "--name": _V},
    "cards": {},
    "grant": {
        "--to": _V,
        "--action": _V,
        "--resource": _V,
        "--file": _V,
        "--statement": _V,
        "--param": _L,
        "--expires-in": _V,
        "--max-uses": _V,
        "--window": _V,
        "--parent": _V,
        "--audience": _V,
    },
    "send": {
        "--to": _V,
        "--card": _F,
        "--info": _V,
        "--action": _V,
        "--resource": _V,
        "--file": _V,
        "--param": _L,
        "--grant": _L,
        "--in-reply-to": _V,
        "--dry-run": _F,
        "--out": _V,
    },
    "ack": {"MSG_ID": _P, "--dry-run": _F, "--out": _V},
    "poll": {"--file": _V, "--out": _V},
    "run": {"--interval": _V, "--once": _F},
    "ledger": {"SUB": _P, "--tail": _V, "--json": _F},
    "feed": {"SUB": _P},
    "denial": {"SUB": _P},
    "pending": {"SUB": _P, "NAME": _P, "--with-held": _F},
    "revoke": {
        "--grant": _L,
        "--card": _L,
        "--statement": _V,
        "--no-send": _F,
        "--dry-run": _F,
        "--out": _V,
    },
    "deny": {"--action": _V, "--resource": _V, "--statement": _V, "--agent": _V},
    "outbox": {},
    "config": {"--set": _L},
    "wire-decode": {"FILE": _P},
}


def _all_but(verb: str, *unread: str) -> frozenset[str]:
    return frozenset(o for o in OPTIONS[verb] if o not in unread)


# verb -> mode -> the options that mode READS (its selector included). A verb with one
# mode reads every option it declares.
MODES: dict[str, dict[str, frozenset[str]]] = {
    "card": {
        "card --show": frozenset({"--show"}),
        "card (making the card)": _all_but("card", "--show"),
    },
    "grant": {
        "grant (a root grant)": _all_but("grant", "--parent"),
        # a delegation carries its parent's audience: `delegate_grant` takes none
        "grant --parent": _all_but("grant", "--audience"),
    },
    "send": {
        "--card": frozenset({"--card", "--dry-run", "--out"}),
        "--info": frozenset({"--to", "--info", "--in-reply-to", "--dry-run", "--out"}),
        "send --action": _all_but("send", "--card", "--info"),
    },
    "poll": {
        "poll without --file (a live poll)": frozenset(),
        "poll --file": frozenset({"--file", "--out"}),
    },
    "ledger": {
        "ledger show": frozenset({"SUB", "--tail", "--json"}),
        "ledger verify": frozenset({"SUB"}),
        "ledger repair": frozenset({"SUB"}),
    },
    "pending": {
        "pending list": frozenset({"SUB"}),
        "pending repair": frozenset({"SUB", "NAME"}),
        "pending discard": frozenset({"SUB", "NAME", "--with-held"}),
    },
    "revoke": {
        "revoke (sending)": _all_but("revoke", "--no-send"),
        # nothing leaves the box, so no file is written: --out is unread
        "revoke --no-send": _all_but("revoke", "--out"),
    },
}
for _verb in OPTIONS:
    MODES.setdefault(_verb, {_verb: frozenset(OPTIONS[_verb])})


def _attr(option: str) -> str:
    return option.lstrip("-").lower().replace("-", "_")


def _given(a: argparse.Namespace, option: str, kind: str) -> bool:
    v = getattr(a, _attr(option))
    if kind == _L:
        return bool(v)
    if kind == _F:
        return v is True
    return v is not None


def mode_of(verb: str, a: argparse.Namespace) -> str:
    """The mode of `verb` the argv selected (a key of `MODES[verb]`)."""
    if verb == "card":
        return "card --show" if a.show else "card (making the card)"
    if verb == "grant":
        return "grant --parent" if a.parent is not None else "grant (a root grant)"
    if verb == "send":
        if a.card:
            return "--card"
        return "--info" if a.info is not None else "send --action"
    if verb == "poll":
        return "poll --file" if a.file is not None else "poll without --file (a live poll)"
    if verb in ("ledger", "pending"):
        return f"{verb} {a.sub}"
    if verb == "revoke":
        return "revoke --no-send" if a.no_send else "revoke (sending)"
    return verb


def check_applicable(a: argparse.Namespace, verb: str) -> str:
    """Every option GIVEN that the selected mode does not read is refused by name,
    together, before the node (`main` runs this after the global options and before
    the verb). Returns the mode."""
    mode = mode_of(verb, a)
    reads = MODES[verb][mode]
    unread = [o for o, kind in OPTIONS[verb].items() if o not in reads and _given(a, o, kind)]
    if unread:
        raise Usage(f"{mode} takes no {', '.join(unread)} (given, and this mode never reads it)")
    return mode


def _node(a: argparse.Namespace) -> Node:
    state, kd, scratch = _dirs(a)
    return Node(state_dir=state, keys_dir=kd, scratch_dir=scratch)


def _wire(node: Node):
    from .adapters.mail import MailWire

    return MailWire(node)


def _out(obj: Any) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=1))


def _parse_param(spec: str) -> tuple[str, dict[str, Any]]:
    """key=regex:RE | key=in:a,b | key=range:lo,hi  (values are strings, or numbers for range)"""
    _utf8(spec, "--param")  # the key and the value: no document carries a surrogate
    key, eq, rest = spec.partition("=")
    kind, colon, val = rest.partition(":")
    if not eq or not key or not colon:
        # the documented delimiters, each present, the key non-empty (`=regex:a` and
        # `content=regex` were admitted; round-20 self-gate, finding 9)
        raise Usage(f"bad --param {spec!r}: use key=regex:RE | key=in:a,b | key=range:lo,hi")
    if kind == "regex":
        return key, {"regex": val}
    if kind == "in":
        return key, {"in": val.split(",")}
    if kind == "range":
        parts = val.split(",")
        if len(parts) != 2:
            raise Usage(f"bad --param {spec!r}: range is lo,hi (two finite numbers)")
        bounds = []
        for x in parts:
            if not x:
                # two finite bounds (round-19 Y10): an open-ended range is refused by
                # name, never stored as a null bound
                raise Usage(f"bad --param {spec!r}: a range has two finite bounds, lo,hi")
            try:
                f = float(x)
            except ValueError as e:
                raise Usage(f"bad --param {spec!r}: {x!r} is not a number") from e
            if f != f or f in (float("inf"), float("-inf")):
                raise Usage(f"bad --param {spec!r}: a range bound is a finite number")
            bounds.append(f)
        return key, {"range": bounds}
    raise Usage(f"bad --param {spec!r}: use key=regex:RE | key=in:a,b | key=range:lo,hi")


def _value(v: str) -> Any:
    """--param k=v for send: '@file' reads a file, else the literal string."""
    if v.startswith("@"):
        return Path(v[1:]).read_text(encoding="utf-8")
    return v


# ---- verbs -----------------------------------------------------------------------------


def cmd_keygen(a):
    state, kd, scratch = _dirs(a)
    keys.check_separation(kd, state_dir=state, scratch_dir=scratch)
    keys.check_scratch_separation(scratch, state_dir=state)
    pubs = keys.generate_all(kd, force=a.force)
    print(f"keys written under {kd} (mode 0600; never copy them into city assets)")
    _out(pubs)


CARD_DEFAULTS = {
    "agent_name": "citadel-mayor",
    "node_name": "citadel",
    "principal_name": "Taylor Hou (citadel stand-in)",
    "principal_kind": "stand-in",
}


def cmd_card(a):
    if a.show:
        # `check_applicable` refused every name option beside --show already
        n = _node(a)
        _out(n.card)
        print(f"hash {n.card_hash}", file=sys.stderr)
        return
    # the defaults are applied HERE, not by argparse, so a name given (empty included)
    # is told from one absent (round-20 gate, finding 3); every name before the
    # node: an empty one is refused by the card's own loader after the startup
    # sweep otherwise (round-19 gate R6)
    names = {k: getattr(a, k) if getattr(a, k) is not None else v for k, v in CARD_DEFAULTS.items()}
    _nonempty(names["agent_name"], "--agent-name")
    _nonempty(names["node_name"], "--node-name")
    _nonempty(names["principal_name"], "--principal-name")
    if names["principal_kind"] not in cardmod.PRINCIPAL_KINDS:
        raise Usage(
            f"--principal-kind {names['principal_kind']!r} is not one of "
            f"{', '.join(cardmod.PRINCIPAL_KINDS)}"
        )
    if a.ledger_url is not None:
        _utf8(a.ledger_url, "--ledger-url")
    n = _node(a)
    c = n.make_card(
        agent_name=names["agent_name"],
        node_name=names["node_name"],
        principal_name=names["principal_name"],
        principal_kind=names["principal_kind"],
        ledger_url=a.ledger_url or "",
    )
    print(f"card {cardmod.card_hash(c)} written to {n.state / 'self.card.json'}")
    print(
        f"agent {c['agent']['key']}\nnode  {c['node']['key']}\n"
        f"principal ({c['principal']['principal_kind']}) {c['principal']['key']}"
    )


def cmd_pin(a):
    _principal_key(a.key, "pin")
    _nonempty(a.name, "--name")
    n = _node(a)
    n.pin(a.key, a.name)
    print(f"pinned {a.key} as {a.name!r}; held cards from that principal are now trusted")


def cmd_cards(a):
    n = _node(a)
    for c in n.trusted_cards():
        print(
            f"trusted  {cardmod.card_hash(c)}  {c['agent']['name']}  agent {c['agent']['key']}  "
            f"node {c['node']['key']}  principal {c['principal']['key']} "
            f"({c['principal']['principal_kind']})"
        )
    for f in list_dir(n.state / "cards-pending", ".json"):
        # the typed card loader: a parse fault is state.corrupt, a card that does not
        # verify or is not bound to its name card.corrupt — IntegrityError, exit 2,
        # the path named
        c = statemod.read_card(f)
        if c is None:
            continue
        print(
            f"PENDING  sha256:{f.stem}  {c['agent']['name']}  principal {c['principal']['key']}  "
            f"<- `natively pin {c['principal']['key']} --name ...`"
        )


def _check_target(a, what: str) -> None:
    """`--resource R` or `--file NAME`, judged before the node: a resource names a
    host (`host:` and non-empty), a file name is one the executor admits."""
    if a.resource is None and a.file is None:
        raise Usage(f"{what}: give --resource or --file")
    if a.resource is not None:
        _nonempty(a.resource, "--resource")
        if not a.resource.startswith("host:"):
            raise Usage(f"--resource {a.resource!r} must start with 'host:'")
        # an explicit scratch resource carries the same name rule as --file: judged
        # here, not by the document check after the node (round-20 self-gate, finding 5)
        name = scratch_name_of(a.resource)
        if name is not None:
            _scratch_file(name, "--resource")
    if a.file is not None:
        _scratch_file(a.file, "--file")


def _resource(subject: dict[str, Any], a) -> str:
    if a.resource is not None:
        return a.resource
    return f"host:{subject['node']['key']}:scratch/{a.file}"


def cmd_grant(a):
    # every value before any work: the names and the statement non-empty, the
    # target a host resource or an admissible file name, the audience a key, the
    # expiry and the use count positive when given, the window well formed, the
    # parent a grant id in full
    _nonempty(a.to, "--to")
    _nonempty(a.action, "--action")
    _nonempty(a.statement, "--statement", grantmod.MAX_STATEMENT)
    _check_target(a, "grant")
    if a.audience is not None:
        _principal_key(a.audience, "--audience")
    _positive(a.expires_in, "--expires-in", MAX_SECONDS)
    _positive(a.max_uses, "--max-uses")
    # `--window ""` is a window given and malformed, not a window absent
    window = _window(a.window) if a.window is not None else None
    if a.parent is not None:
        _id(a.parent, "--parent", "grt_")
    # every --param parsed BEFORE the node is constructed (its startup sweep replays
    # held revocations and writes the ledger): a bad value does no work
    params = {"keys": [], "values": {}}
    for spec in a.param or []:
        k, c = _parse_param(spec)
        # the constraint as the grant's structure check will judge it — the pattern
        # grammar bound and the engine's compile included — BEFORE the node is built
        # (before, `--param content=regex:(a{2}){2}` ran the startup sweep first;
        # round-19 self-gate, third run)
        try:
            grantmod._check_constraint(c, f"--param {k}")
        except VerifyError as e:
            raise Usage(f"bad --param {spec!r}: {e.reason}: {e.detail}") from e
        if k not in params["keys"]:
            params["keys"].append(k)
        params["values"][k] = c
    if a.action == "fs.write" and "content" not in params["keys"]:
        params["keys"].append("content")
    n = _node(a)
    subject = n.find_card(a.to)
    scope = [{"action": a.action, "resource": _resource(subject, a), "params": params}]
    if a.parent:
        parent = n.load_grant(a.parent)
        if parent is None:
            raise Usage(f"unknown parent grant {a.parent}")
        # every restriction asked for reaches the delegation: an expiry (None: the
        # parent's), the use count (None: the parent's remaining budget), the window
        # (None: the parent's); looser than the parent's is refused by name
        g = n.delegate_grant(
            parent=parent,
            subject_card=subject,
            scope=scope,
            principal_statement=a.statement,
            expires_at=fmt(plus(n.now(), a.expires_in)) if a.expires_in is not None else None,
            max_uses=a.max_uses,
            max_uses_per_window=window,
        )
    else:
        g = n.issue_grant(
            subject_card=subject,
            scope=scope,
            principal_statement=a.statement,
            expires_in_s=3600 if a.expires_in is None else a.expires_in,
            max_uses=1 if a.max_uses is None else a.max_uses,
            max_uses_per_window=window,
            audience=a.audience,
        )
    print(
        f"grant {g['grant_id']} -> {subject['agent']['name']} {scope[0]['action']} "
        f"{scope[0]['resource']} expires {g['expires_at']} max_uses {g['max_uses']}"
    )


def _send_bundle(n: Node, b: dict[str, Any], a) -> None:
    # the outgoing boundary BEFORE anything is encoded, written, recorded or handed
    # to the wire, in every form: a reply damaged after the validation that read it
    # (or any other bundle that is not this node's) is exit 2, <kind>.invalid, no
    # file; the wire's own send runs the same check again on what reaches it
    n.check_outgoing(b)
    if a.dry_run:
        # --dry-run takes precedence over --out: the body may be written for
        # inspection, but nothing enters the outbox and nothing leaves the box
        if a.out is not None:
            Path(a.out).write_text(bundlemod.encode(b), encoding="utf-8")
            print(f"DRY RUN wire body written to {a.out}; nothing recorded, nothing sent")
            return
        ref = _wire(n).send(b, dry_run=True)
        print(f"DRY RUN {b['kind']} {_object_id(b)} gmail {ref}".rstrip())
        return
    if a.out is not None:
        Path(a.out).write_text(bundlemod.encode(b), encoding="utf-8")
        # a file export is delivered by hand: recorded, never retried by the poll
        n.outbox_record(b, transport_ref=f"file:{a.out}", status="exported")
        print(f"wire body written to {a.out}")
        return
    ref = _wire(n).send(b)
    print(f"sent {b['kind']} {_object_id(b)} gmail {ref}".rstrip())


def _object_id(b: dict[str, Any]) -> str:
    o = b["object"]
    return o.get("msg_id") or o.get("ack_id") or o.get("rev_id") or ""


def cmd_send(a):
    # every value before the node: the ids of their form, the recipient or --card,
    # an info text or an action with its target and grant, every --param a k=v with
    # its file (an `@file`) read here
    _out_file(a)
    for gid in a.grant or []:
        _id(gid, "--grant", "grt_")
    if a.in_reply_to is not None:
        _id(a.in_reply_to, "--in-reply-to", "msg_")
    params: dict[str, Any] = {}
    # an option GIVEN — empty included — that belongs to another mode was refused by
    # name before this verb ran (`check_applicable`; round-20 self-gate, second run,
    # finding 6; the one table for every verb: round-20 gate, finding 3)
    if not a.card:
        _nonempty(a.to, "--to (or --card)")
        if a.info is not None:
            _nonempty(a.info, "--info")
            _body_within({"type": "info", "text": a.info}, "--info")
        else:
            if a.action is None or not a.grant:
                raise Usage("an action needs --action, --file/--resource, and --grant")
            _nonempty(a.action, "--action")
            _check_target(a, "send")
            _unique_ids(a.grant, "--grant", msgmod.MAX_GRANT_IDS)
            for spec in a.param or []:
                _utf8(spec, "--param")
                k, sep, v = spec.partition("=")
                if not sep or not k:
                    raise Usage(f"bad --param {spec!r}: use key=value (or key=@file)")
                params[k] = _value(v)
            # the body's size with the resource at its exact length (a node key is 52
            # characters), before the node
            shape = a.resource if a.resource is not None else f"host:{'x' * 52}:scratch/{a.file}"
            _body_within(
                {"type": "action", "action": a.action, "resource": shape, "params": params},
                "the action's body (--param)",
            )
    n = _node(a)
    if a.card:
        b = n.compose_card()
    else:
        to = n.find_card(a.to)
        if a.info is not None:
            b = n.compose_info(to, a.info, in_reply_to=a.in_reply_to)
        else:
            b = n.compose_action(
                to,
                action=a.action,
                resource=_resource(to, a),
                params=params,
                grant_ids=a.grant,
                in_reply_to=a.in_reply_to,
            )
    _send_bundle(n, b, a)


def cmd_ack(a):
    _id(a.msg_id, "MSG_ID", "msg_")
    _out_file(a)
    n = _node(a)
    # the stored ack is validated in full before it goes out (a parse fault in the
    # seen file is IntegrityError, exit 2; so is a stored ack that no longer verifies:
    # a damaged stored ack is never sent by any path); the copy handed on is checked
    # AGAIN at the outgoing boundary inside _send_bundle, before it is encoded or
    # written in either form
    r, why = n.stored_reply(a.msg_id)
    if r is None and why is None:
        if n.ledger.find_msg(a.msg_id) is not None:
            raise Usage(
                f"{a.msg_id} was completed here but no ack is stored; a re-delivery "
                f"(or `poll --file` again) rebuilds it from the ledger completion"
            )
        raise Usage(f"{a.msg_id} was never applied here; nothing to ack")
    if r is None:
        raise IntegrityError(
            "seen.corrupt",
            f"{n.state / 'seen.json'}: the stored ack for {a.msg_id} is not this node's "
            f"reply ({why}); nothing sent",
        )
    _send_bundle(n, r, a)


def cmd_poll(a):
    # the wire body read (and decoded) before the node: a file that is not there,
    # or not a bundle, does no startup work; `--file ""` is a file given and empty,
    # never a live poll (round-20 self-gate, finding 4)
    _out_file(a)
    b = None
    if a.file is not None:
        _nonempty(a.file, "--file")
        b = bundlemod.decode(Path(a.file).read_text(encoding="utf-8"))
    n = _node(a)
    if b is not None:
        replies = n.receive(b)  # a file is not a lookup: the freshness clock stays put
        for r in replies:
            n.check_outgoing(r)  # the outgoing boundary: reply.invalid leaves the box empty
            if a.out is not None:
                Path(a.out).write_text(bundlemod.encode(r), encoding="utf-8")
                print(f"reply {r['kind']} written to {a.out}")
            else:
                _wire(n).send(r)
                print(f"reply {r['kind']} sent")
        print(f"applied {b['kind']} from file; ledger head {n.ledger.head()}")
        return
    _out(_wire(n).poll_once())


def cmd_run(a):
    # the interval before any poll: given, it is within the poll cadence's bounds
    # (0 is never "use poll_s", a negative value never reaches time.sleep after a
    # poll already ran); absent, the configured poll_s
    if a.interval is not None and not statemod.POLL_S_MIN <= a.interval <= statemod.POLL_S_MAX:
        raise Usage(
            f"--interval {a.interval} is outside {statemod.POLL_S_MIN}..{statemod.POLL_S_MAX} "
            f"seconds"
        )
    n = _node(a)
    w = _wire(n)
    interval = a.interval if a.interval is not None else n.poll_s
    print(
        f"natively run: polling every {interval}s as {n.card['agent']['name']}; ctrl-c to stop",
        file=sys.stderr,
    )
    while True:
        s = w.poll_once()
        print(
            f"{n.ts()} poll fetched={s['fetched']} applied={s['applied']} replies={s['replies']} "
            f"resent={s['resent']} undelivered={s['undelivered']} errors={len(s['errors'])}",
            file=sys.stderr,
        )
        if a.once:
            return
        time.sleep(interval)


def cmd_ledger(a):
    tail = a.tail if a.tail is not None else 0  # None is absence; `show` reads it
    if tail < 0:
        raise Usage(f"--tail {tail} is negative; give the number of entries to show")
    n = _node(a)
    if a.sub == "verify":
        with n.locked():  # a poller's append (and its own gap repair) never interleaves
            head = n.ledger.verify()
        print(f"ledger ok: {len(n.ledger)} entries, head {head}")
        return
    if a.sub == "repair":
        # the same flock every ledger writer holds: a receive running beside this
        # repairs a trailing gap itself before it appends, so the two can never both
        # see the gap and both write the line
        with n.locked():
            truncated, wrote, tail = n.repair_ledger()
            head = n.ledger.verify()
        cut = (
            f"; {truncated} byte(s) of prose beyond the JSONL truncated (ledger.mirror_truncated)"
            if truncated
            else ""
        )
        torn = (
            f"; {tail} torn byte(s) of the JSONL's last line truncated (ledger.tail_truncated)"
            if tail
            else ""
        )
        print(
            f"ledger repaired: {wrote} trailing prose line(s) regenerated{torn}{cut}; head {head}"
        )
        return
    es = n.ledger.entries()
    from .ledger import entry_hash

    for e in es[-tail:] if tail else es:
        print(prose_line(e, entry_hash(e)) if not a.json else json.dumps(e, ensure_ascii=False))
    print(f"head {n.ledger.head()}", file=sys.stderr)


def cmd_feed(a):
    n = _node(a)
    if a.sub == "verify":
        with n.locked():
            entries, unterminated = n.revocations.load()
        tail = "; the last line lacks its newline (the next append adds it)" if unterminated else ""
        print(f"feed ok: {len(entries)} revocation(s){tail}")
        return
    # repair: under the same flock every feed writer holds, so a poll's append and
    # this truncation never interleave; only a torn partial LAST line is removed, and
    # only when every preceding line parses; the intent is durable before the
    # truncation and the byte count is ledgered after it; then the held revocations
    # of every pinned principal are replayed and the replay marker removed
    removed = n.repair_feed()
    with n.locked():
        entries, _ = n.revocations.load()
    print(f"feed repaired: {removed} torn byte(s) truncated; {len(entries)} revocation(s) on file")


def cmd_denial(a):
    n = _node(a)
    if a.sub == "verify":
        with n.locked():
            entries, unterminated = n.denials.load()
        tail = "; the last line lacks its newline (the next append adds it)" if unterminated else ""
        print(f"denial store ok: {len(entries)} denial(s){tail}")
        return
    removed = n.repair_denials()
    with n.locked():
        entries, _ = n.denials.load()
    print(
        f"denial store repaired: {removed} torn byte(s) truncated; {len(entries)} denial(s) on file"
    )


def cmd_pending(a):
    if a.sub == "discard" or (a.sub == "repair" and a.name is not None):
        _aside_name(a.name, f"pending {a.sub} NAME")
    n = _node(a)
    w = _wire(n)
    if a.sub == "list":
        with n.locked():
            rows = w.pending_status()
        for r in rows:
            print(
                f"{r['status']:<14} {r['name']}  msg {r['msg_id'] or '?'}  kind {r['kind'] or '?'}"
            )
        if not rows:
            print("no held replies")
        return
    if a.sub == "repair":
        s = w.repair_pending(a.name)
        for name in s["rebuilt"]:
            print(f"rebuilt      {name}  (held again; the next poll validates and sends it)")
        for name, why in s["unresolvable"]:
            print(f"unresolvable {name}  (pending_reply.unresolvable: {why})")
        for name, why in s["refused"]:
            print(f"refused      {name}  ({why})")
        for name in s["discarded"]:
            print(f"discarded    {name}  (discard on record, unfinished: removed, nothing rebuilt)")
        if a.name is not None:
            for name in s["resolved"]:
                print(f"resolved     {name}  (already reconstructed; its barrier re-established)")
        for e in s["errors"]:
            print(f"natively: {e}", file=sys.stderr)
        print(
            f"pending repaired: {len(s['rebuilt'])} rebuilt, {len(s['unresolvable'])} "
            f"unresolvable, {len(s['refused'])} refused, {len(s['discarded'])} discard(s) "
            f"finished, {s['storage_failures']} storage failure(s)"
        )
        # a requested repair that remains unsuccessful — a storage failure, a copy
        # with no validated source, a refused one — is the verb's exit code, one
        # line per failure printed above (round-19 gate, finding 14: exit 0 after
        # a storage failure, and a test pinned it)
        failed = s["storage_failures"] + len(s["unresolvable"]) + len(s["refused"])
        return 1 if failed else 0
    r = w.discard_pending(a.name, with_held=a.with_held)
    what = "the aside copy and its held reply" if r["with_held"] else "the aside copy"
    if r["record"] == "found":
        print(f"discard of {a.name} already on record; {what} removed if still present")
    else:
        print(f"discarded {a.name}: {what} removed (ledgered pending_reply.discarded)")


def cmd_revoke(a):
    for gid in a.grant or []:
        _id(gid, "--grant", "grt_")
    for h in a.card or []:
        _card_hash(h)
    if not a.grant and not a.card:
        raise Usage("revoke names at least one --grant ID or --card HASH")
    _unique_ids([*(a.grant or []), *(a.card or [])], "revoke", MAX_REVOKES)
    _nonempty(a.statement, "--statement", grantmod.MAX_STATEMENT)
    _out_file(a)
    n = _node(a)
    # composed and checked at the outgoing boundary FIRST: a revocation whose
    # bundle would be refused changes nothing (no feed line, no ledger entry, exit
    # 2); a dry run records nothing anywhere (the body may be written for inspection)
    r = n.build_revocation(cards=a.card, grants=a.grant, principal_statement=a.statement)
    b = n.compose_revocation(r)
    n.check_outgoing(b)
    if a.dry_run:
        print(f"DRY RUN revocation {r['rev_id']}: nothing recorded in the local feed")
        if not a.no_send:
            _send_bundle(n, b, a)
        return
    n.record_revocation(r)
    print(f"revocation {r['rev_id']} recorded in the local feed")
    if not a.no_send:
        _send_bundle(n, b, a)


def cmd_deny(a):
    _nonempty(a.action, "--action")
    _nonempty(a.resource, "--resource")
    _nonempty(a.statement, "--statement", grantmod.MAX_STATEMENT)
    if a.agent is not None:
        _card_hash(a.agent)
    n = _node(a)
    d = n.deny(
        deny=[{"action": a.action, "resource": a.resource}],
        principal_statement=a.statement,
        subject_agent=a.agent,
    )
    print(f"standing denial {d['denial_id']} recorded")


def cmd_outbox(a):
    n = _node(a)
    for x in n.outbox():
        print(
            f"{x['status']:<11} {x['msg_id']} attempts={x['attempts']} due={x['due']} "
            f"sent={x['sent_at']}"
        )


def _loadable_config(path: Path) -> tuple[dict[str, Any], list[str]]:
    """The complete effective config from the LOADABLE parts of config.json — every
    key that passes the typed loader on its own, the package default beneath the
    rest — and one line per part that could not be read (the file not parsing, a
    key the loader refuses). The config verb's read, which never requires the
    whole file to load: a config that locks every other verb out (state.corrupt)
    is repaired from this surface with one `config --set`."""
    problems: list[str] = []
    raw: Any = {}
    if path.exists():
        try:
            raw = load_local(path.read_bytes(), str(path))
        except IntegrityError as e:
            problems.append(f"the file does not parse ({e}); every key starts from its default")
            raw = {}
        if not isinstance(raw, dict):
            problems.append("not an object; every key starts from its default")
            raw = {}
    cfg: dict[str, Any] = {**DEFAULT_CONFIG, "extensions": dict(DEFAULT_CONFIG["extensions"])}
    for k, v in raw.items():
        if k == "extensions" and isinstance(v, dict):
            for flag, fv in v.items():
                why = statemod.config({"extensions": {flag: fv}})
                if why is None:
                    cfg["extensions"][flag] = fv
                else:
                    problems.append(f"{why}; dropped")
            continue
        why = statemod.config({k: v})
        if why is None:
            cfg[k] = v
        else:
            problems.append(f"{why}; {k} starts from its default")
    return cfg, problems


def _config_value(k: str, v: str) -> tuple[str, Any]:
    """One --set key=value parsed and validated through the typed loader: the key
    from the known set (a flag as extensions.<flag>), the value of its type and
    within its bounds, else Usage naming it — nothing is written that the next
    verb's load would refuse (round-19 Fable read, finding 3: an unvalidated
    peer_addresses locked every verb out, the config verb included)."""
    keys_ = ", ".join(x for x in statemod.CONFIG_KEYS if x != "extensions")
    _utf8(k, "--set key")
    _utf8(v, f"--set {k}")  # before the lock and the write path (round-21 self-gate, 8)
    if k.startswith("extensions."):
        flag = k[len("extensions.") :]
        if flag not in statemod.EXTENSION_FLAGS:
            raise Usage(
                f"--set {k}: not an extension flag (the flags are "
                f"{', '.join('extensions.' + f for f in statemod.EXTENSION_FLAGS)})"
            )
        lv = v.strip().lower()
        if lv in ("1", "true", "on", "yes"):
            return k, True
        if lv in ("0", "false", "off", "no"):
            return k, False
        raise Usage(f"--set {k}={v!r}: not a boolean (true or false)")
    if k not in statemod.CONFIG_KEYS or k == "extensions":
        raise Usage(f"--set {k!r}: not a config key (the keys are {keys_}, extensions.<flag>)")
    val: Any
    if k == "poll_s":
        try:
            val = int(v)
        except ValueError as e:
            raise Usage(f"--set poll_s={v!r}: not an integer") from e
    elif k == "peer_addresses":
        val = [x.strip().lower() for x in v.split(",") if x.strip()]
        if not val:
            raise Usage("--set peer_addresses: names no address (a comma-separated list)")
    else:
        val = v
    why = statemod.config({k: val})
    if why is not None:
        raise Usage(f"--set {k}: {why}; nothing written")
    return k, val


def cmd_config(a):
    """`natively config [--set k=v ...]`: the effective config printed; with --set,
    every value validated (`_config_value`) before anything is written, the
    read-modify-write under the state lock (no node is constructed: the verb works
    over a config no node could load), and the COMPLETE valid config written — so a
    hand-corrupted or stale file is repaired by one --set. Without --set, a part
    that could not be read is reported and the verb exits 2 (state.corrupt named)
    after printing what it could read."""
    state, _kd, _scratch = _dirs(a)
    path = state / "config.json"
    sets = []
    for kv in a.set or []:
        k, sep, v = kv.partition("=")
        if not sep or not k:
            raise Usage(f"bad --set {kv!r}: use key=value")
        sets.append(_config_value(k, v))
    with state_lock(state):
        cfg, problems = _loadable_config(path)
        if not sets:
            _out(cfg)
            for why in problems:
                print(f"natively: state.corrupt: {path}: {why}", file=sys.stderr)
            return 2 if problems else 0
        for k, val in sets:
            if k.startswith("extensions."):
                cfg["extensions"] = {**cfg["extensions"], k[len("extensions.") :]: val}
            else:
                cfg[k] = val
        why = statemod.config(cfg)
        if why is not None:  # every key was checked on its own; the whole again
            raise Usage(f"--set: {why}; nothing written")
        write_json(path, cfg)
        for why in problems:
            print(f"natively: {path}: {why} (repaired by this write)", file=sys.stderr)
    _out(cfg)


def cmd_wire_decode(a):
    _out(bundlemod.decode(Path(a.file).read_text(encoding="utf-8")))


# ---- parser ----------------------------------------------------------------------------


class _Parser(argparse.ArgumentParser):
    """argparse's own refusal (a non-integer `--max-uses`, an unknown verb) is a Usage
    error like every other bad value — one line, exit 1 — not argparse's usage block
    and exit 2 (round-19 self-gate, second run). `--help` still exits 0."""

    def error(self, message: str):  # noqa: D401 — argparse's hook
        raise Usage(message)


def build_parser() -> argparse.ArgumentParser:
    ap = _Parser(
        prog="natively", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--state", help="state dir (default natively/state or $NATIVELY_STATE)")
    ap.add_argument(
        "--keys", help="keys dir (default ~/.config/citadel-mayor/natively or $NATIVELY_KEYS)"
    )
    ap.add_argument(
        "--scratch", help="executor scratch root (default natively/scratch or $NATIVELY_SCRATCH)"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("keygen")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_keygen)
    s = sub.add_parser("card")
    s.add_argument("--show", action="store_true")
    # None = absent (the defaults are `CARD_DEFAULTS`, applied by the verb): a name
    # GIVEN beside --show is refused, never taken for the default
    s.add_argument("--agent-name", help="default citadel-mayor")
    s.add_argument("--node-name", help="default citadel")
    s.add_argument("--principal-name", help="default 'Taylor Hou (citadel stand-in)'")
    s.add_argument("--principal-kind", help=f"one of {', '.join(cardmod.PRINCIPAL_KINDS)}")
    s.add_argument("--ledger-url")
    s.set_defaults(fn=cmd_card)
    s = sub.add_parser("pin")
    s.add_argument("key")
    s.add_argument("--name", required=True)
    s.set_defaults(fn=cmd_pin)
    s = sub.add_parser("cards")
    s.set_defaults(fn=cmd_cards)
    s = sub.add_parser("grant")
    s.add_argument("--to", required=True)
    s.add_argument("--action", required=True)
    s.add_argument("--resource")
    s.add_argument("--file")
    s.add_argument("--statement", required=True)
    s.add_argument("--param", action="append")
    # None = the verb's default: 3600 s and one use for a root grant; for a
    # delegation the parent's expiry and its remaining budget
    s.add_argument("--expires-in", type=int)
    s.add_argument("--max-uses", type=int)
    s.add_argument("--window")
    s.add_argument("--parent")
    s.add_argument("--audience")
    s.set_defaults(fn=cmd_grant)
    s = sub.add_parser("send")
    s.add_argument("--to")
    s.add_argument("--card", action="store_true", help="send this node's card")
    s.add_argument("--info")
    s.add_argument("--action")
    s.add_argument("--resource")
    s.add_argument("--file")
    s.add_argument("--param", action="append")
    s.add_argument("--grant", action="append")
    s.add_argument("--in-reply-to")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--out")
    s.set_defaults(fn=cmd_send)
    s = sub.add_parser("ack")
    s.add_argument("msg_id")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--out")
    s.set_defaults(fn=cmd_ack)
    s = sub.add_parser("poll")
    s.add_argument("--file")
    s.add_argument("--out")
    s.set_defaults(fn=cmd_poll)
    s = sub.add_parser("run")
    s.add_argument("--interval", type=int)
    s.add_argument("--once", action="store_true")
    s.set_defaults(fn=cmd_run)
    s = sub.add_parser("ledger")
    s.add_argument("sub", choices=["show", "verify", "repair"])
    s.add_argument("--tail", type=int)  # None = absent; `show` reads it
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_ledger)
    s = sub.add_parser("feed")
    s.add_argument("sub", choices=["verify", "repair"])
    s.set_defaults(fn=cmd_feed)
    s = sub.add_parser("denial")
    s.add_argument("sub", choices=["verify", "repair"])
    s.set_defaults(fn=cmd_denial)
    s = sub.add_parser("pending")
    s.add_argument("sub", choices=["list", "repair", "discard"])
    s.add_argument("name", nargs="?")
    s.add_argument("--with-held", action="store_true")
    s.set_defaults(fn=cmd_pending)
    s = sub.add_parser("revoke")
    s.add_argument("--grant", action="append")
    s.add_argument("--card", action="append")
    s.add_argument("--statement", required=True)
    s.add_argument("--no-send", action="store_true")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--out")
    s.set_defaults(fn=cmd_revoke)
    s = sub.add_parser("deny")
    s.add_argument("--action", required=True)
    s.add_argument("--resource", required=True)
    s.add_argument("--statement", required=True)
    s.add_argument("--agent")
    s.set_defaults(fn=cmd_deny)
    s = sub.add_parser("outbox")
    s.set_defaults(fn=cmd_outbox)
    s = sub.add_parser("config")
    s.add_argument("--set", action="append")
    s.set_defaults(fn=cmd_config)
    s = sub.add_parser("wire-decode")
    s.add_argument("file")
    s.set_defaults(fn=cmd_wire_decode)
    return ap


def main(argv: list[str] | None = None) -> int:
    try:
        a = build_parser().parse_args(argv)  # a parse refusal is a Usage error too
        # the global directory options, then the option applicability of the verb's
        # mode — both before any verb runs and before any node is built
        _check_globals(a)
        check_applicable(a, a.cmd)
        rc = a.fn(a)  # a verb may return its own exit code (pending repair, config)
    except NativelyError as e:
        print(f"natively: {e}", file=sys.stderr)
        return 2
    except (
        Usage,
        OSError,  # every storage error a verb did not contain (EIO included), one line
        KeyError,
        ValueError,
        RuntimeError,
        subprocess.SubprocessError,  # a send tool that timed out or did not launch
    ) as e:
        print(f"natively: {e}", file=sys.stderr)
        return 1
    return int(rc or 0)

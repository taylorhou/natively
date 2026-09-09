# Natively v0 on citadel

An implementation of the Natively protocol, SPEC.md v0.2 as published at
github.com/taylorhou/natively (commit ad36d9a), so citadel's mayor agent and
Instinct's agent can communicate over Natively itself. Stage 1 rides the mail
transport both sides already poll; stage 2 moves the same envelopes onto the
Teale relay once enrollment is real. Nothing here is published (Taylor, 9/7:
"Don't publish anything until you and instinct are communicating with it
successfully at the speed of ai").

## Close-out (2026-09-09): this package as a pull request

Taylor, 2026-09-08 20:23 CT: "Close it out with a PR to the repo. That ends the
round series." This directory (`implementations/citadel-v0/`) is that pull request:
the package as it stood when the series ended, opened as a DRAFT so the maintainer
reads it on his own terms. Nothing in it is wired into the reference node beside it;
`natively/` at the repository root is untouched.

**What is here.** `natively/` (the package), `tests/`, this README, `bin/natively`,
`pyproject.toml`, `requirements.txt`.

**What is excluded, on purpose.** The node's `state/` directory (its card, the pinned
roots, peer cards, grants, embedded parents, the ledger and its prose mirror, the
feeds, the seen file, the outbox, the wire cursor, pending replies, `self.card.json`
and `pinned.json`); `scratch/`; every key (private keys live under
`~/.config/citadel-mayor/natively/` and never in this tree); every credential; and the
Gmail helpers `gmail-api.py` and `gmail-send.py`, which sit beside the package on the
citadel machine and hold the OAuth token path. The mail adapter imports nothing from
those helpers: it runs them as subprocesses, so the tests exercise it through in-memory
fakes (`tests/test_mail_adapter.py`, the round-21 fakes). The layout section below
describes `state/` and `scratch/` as the running node uses them; neither ships here.

**Nothing is published or consumed.** No card has been sent on any wire, no peer card
has been pinned, no message or ack has been exchanged, and the package has never been
run against a live mailbox. The first live exchange (the section near the end of this
file) did not happen.

**Tests.** 1,457 collected, 1,457 passed on 2026-09-09 with the venv's Python
3.11 (`.venv/bin/python -m pytest`); `ruff check` and `ruff format --check` clean over
`natively` and `tests`.

### The twenty-one rounds

Each round implemented the previous gate's findings as the mayor ruled them, then a
reviewer that had not written the code (OpenAI Codex on gpt-6-astra, read-only; from
round 11 on a Claude Fable 5.1 read as the second opinion) gated the result. One line
per round: what the round did, what its gate found.

1. Round 1 (hw-dvk9i): the package built from SPEC v0.2 at `ad36d9a` (objects, JCS,
   grants, ledger, executor, the mail wire); 94 tests. Gate: BLOCK, 19 findings
   (replay and use limits not atomic, delegation bypassing parent budgets).
2. Round 2 (hw-1tayp): the 19 fixed; `jsonsafe.py`, the `regex` engine; 132 tests.
   Gate: 11 MAJOR + 5 MINOR.
3. Round 3 (hw-rmhli): scratch root by filesystem identity, `Ledger.find_msg` inbound
   only, directory fsync, poll order and the wire cursor; 155 tests. Gate: 6 MAJOR +
   6 MINOR + 2 partial fixes.
4. Round 4 (hw-myvbh): `durable.py` as the one durable-write rule, `PostCommitError`
   after the rename, a storage fault leaving the mail unseen; 182 tests. Gate: 8 MAJOR
   + 4 MINOR + 7 partial fixes.
5. Round 5 (hw-444xk): the fourth gate's rulings; 214 tests. Gate: 7 MAJOR + 3 MINOR +
   9 partial fixes.
6. Round 6 (hw-20p75): `Ledger.barrier`, the ordering / failure-before / failure-after
   / restart-recovery sections; 250 tests. Gate: 4 MAJOR + 4 MINOR + 13 partial fixes.
7. Round 7 (hw-2bb8q, then 7b hw-hrcms): held-reply recovery through five self-gate
   runs, then rewritten fail-closed; 339 then 351 tests. Gate on 7b: 1 MAJOR
   (same-poll replies bypassing full validation).
8. Round 8 (hw-h9ci6): the self card verified and key-bound, one validation before
   hold and send, repair finishing discards; 384 tests. Gate: 2 MAJOR (a malformed
   `seen.json` attributed to peer input; an invalid ack crossing one outgoing boundary).
9. Round 9 (hw-i4nlj): `state.py` as the one typed loader, `LocalWire` checking
   explicit acks; 451 tests. Gate: 3 MAJOR + 1 MINOR (cached grants turning local
   corruption into a permanent refusal).
10. Round 10 (hw-njl0a): `grant.check_document` at every load, `ledger.mirror_corrupt`
    and torn-mirror repair, `check_outgoing` on every export; 486 tests. Gate: 2 MAJOR
    + 1 MINOR (an unterminated JSONL tail escaping the poll).
11. Round 11 (hw-hw3c9): every fault reading a file of ours is `IntegrityError`, feed
    and denial records verified as documents at load; 521 tests. Gate: 2 MAJOR
    (whitespace-only records silently disappearing).
12. Round 12 (hw-axfqd): blank physical lines are corruption in every JSONL reader,
    `check_intact` first, the audited-step whole-file check; 589 tests. Gate: 3 MAJOR
    + 3 MINOR (malformed peer-address state discarding mail; the Gmail attachment body).
13. Round 13 (hw-w4o7q): stored acks as authenticated anchors of the ledger tail; 709
    tests. Gate: 4 MAJOR (missing or shortened helper bodies becoming permanent
    refusals).
14. Round 14 (hw-1qheu): anchored repair (T1 to T6); 756 tests. Gate: 3 MAJOR (empty
    child MIME types producing complete rows; fresh repair changing the JSONL before
    refusing the mirror).
15. Round 15 (hw-5lz2l): the fresh-mend intent (U1 to U5); 796 tests. Gate: 1 MAJOR +
    2 MINOR (mirror recovery writing before binding its audit).
16. Round 16 (hw-57xb4): the mirror intent binds its visible audit, the terminated
    mend; 811 tests. Gate: CLEAN.
17. Round 17 (hw-nrgx0): the last-entry rule, exact bytes at the intent step; 825
    tests. Gate: CLEAN with 2 MINOR.
18. Round 18 (hw-rcerq): chain binding before displacement; 830 tests. Gate: CLEAN. A
    fresh whole-package review followed: 12 MAJOR + 3 MINOR, ruled into round 19.
19. Round 19 (hw-1fvpt): the fresh review's fourteen rulings (Y1 to Y14); 990 tests.
    Gate: 4 MAJOR + 2 MINOR (scratch separation accepting nonexistent case aliases).
20. Round 20 (hw-hdg1p): the constraint language as a parser of its own, the Unicode
    fold, the prefix rule, the delegate lock, the CLI hoists; 1,326 tests. Gate: 3 MAJOR
    + 1 MINOR (quadratic class parsing, repair resume reading past the cut, CLI
    preflight); the Fable read 1 MAJOR + 2 MINOR; deviations D1 to D4 ratified, D5
    tightened (below).
21. Round 21 (hw-843op): the round-20 verdicts (BA1 to BA5, BB1 to BB3) and the mail
    adapter (Z1 to Z5: the row schema, the mailbox assertion, the time-sliced scan,
    oversize as terminal, bounded helper reads); self-gate 9 MAJOR + 5 MINOR, all fixed
    in-family; 1,457 tests. No maintainer's gate: the series ended on Taylor's
    word, and the second self-gate was cancelled with it.

### The ratifications (round 20's deviations, ruled 2026-09-08)

- D1 RATIFIED: the compile at receive, issue and load runs in the `regex` package on
  the parser's EMISSION, never the raw text, after the document's signature check; the
  stdlib `re` is not required anywhere (it walks code points when it compiles wide
  non-ASCII classes; nothing pathological reaches an engine because the parser refuses
  it first).
- D2 RATIFIED: the match at use keeps the `regex` package's timeout
  (`scope.regex_timeout`) as the operational bound; the cost argument is that the match
  is bounded by the TIMEOUT, not by a polynomial claim.
- D3 RATIFIED: the six shorthands mean ASCII and are emitted as explicit classes.
- D4 RATIFIED: empty branches and empty groups are admitted (nullable branches; groups
  cannot be quantified).
- D5 TIGHTENED into round 21's BA1: character classes parse sort-then-merge with
  `MAX_CLASS_ITEMS = 256`, refused by name at the offending item, the work pinned under
  n(log2 n + 1) comparisons.

### Residual, as of 2026-09-09

1. Written against SPEC v0.2 (`ad36d9a`). Upstream SPEC.md is v0.3 now; the package
   has not been re-read against v0.3, and no claim is made about it.
2. Round 21 carries no maintainer's gate. Its one self-gate found 9 MAJOR + 5 MINOR,
   every one fixed and pinned in `tests/test_gate_round21.py`; the second self-gate the
   round planned was never run.
3. The mail adapter's last change before the pause (the `searched_out` flag: a
   page-capped or nonprogressing search stops the search, not the reading of what it
   listed) is covered by the suite above and by nothing else.
4. The Unicode fold in `keys._fold` sees only the case pairs this interpreter's tables
   know (Unicode 14.0 on Python 3.11); the inode re-check (`keys.check_scratch_identity`)
   stands behind it, but only after both directories exist, so a refusal leaves two
   empty directories behind.
5. The time-sliced scan's halving state is durable only through the scan record's
   `slice_s`; a pass that completes no slice records nothing and repeats the same
   halvings next poll, bounded by `MAX_PAGES` per poll and named each time.
6. The `after:`/`before:` semantics at the exact boundary second are not exercised
   against the real Gmail API (the seen file dedups any double listing).
7. The per-thread oversize rejection keys on the Gmail thread id; a thread that later
   gains a legitimate wire message is never read again until the operator removes its
   `thread:<id>` note.
8. `gmail-api.py` is outside this tree and outside the package's test collection; its
   bounded-read paths were tested through `importlib` on the citadel machine.
9. The mailbox is asserted once per poll; a credential swap mid-poll is seen at the
   next.
10. Stage 2 (the same envelopes over the Teale relay) was never started.

## Layout

```
natively/                 the package (no network anywhere but adapters/mail.py)
  canon.py                RFC 8785 JCS, in-tree, tested against the RFC vector
  jsonsafe.py             bounded JSON parsing for peer input: no duplicate members, no ints past 2^53, depth 32
  keys.py                 Ed25519; private keys ONLY under ~/.config/citadel-mayor/natively/
  card.py                 agent card: node vouches (node_sig), principal signs (sig); hash = SHA-256(JCS minus sig)
  grant.py                envelope build/sign/verify, scope matching, delegation subset algebra, the constraint language (a complete parser of its own, `emit_pattern`; the `regex` engine compiles its emission, never the raw pattern)
  message.py  ack.py      messages with base64 bodies; signed acks carrying the ledger head
  ledger.py               hash-chained JSONL + prose mirror; the chain is verified on every load, prose is regenerated and compared whole; every fault in either file is local corruption (IntegrityError, the path and the line or byte offset named), an unterminated JSONL tail included (`ledger repair` terminates a whole entry, cuts a torn line)
  durable.py              the one durable-write rule (a temp file created EXCLUSIVELY under a unique name in the target's directory, fsync, rename, directory fsync; durable line appends) every module uses, the one local parser (`parse_local`: a member name repeated inside one object is that file's corruption, never last-value-wins) every state file and every JSONL line of ours comes through, the one physical-line reader of the three JSONL stores, and the ONE blank-line rule (`is_blank_line` / `is_blank_text`, Unicode-aware: Zs, Zl, Zp, Cc, Cf — U+00A0, U+2003, U+202F, U+200B, U+FEFF count; a line that does not decode is never blank)
  state.py                the one typed loader every state file read as a structure comes through (the top-level type and the per-entry shape the code relies on, checked at the read; a mismatch is `state.corrupt` naming the path — local state is never peer input; every element of `peer_addresses` an address, named by its index when it is not)
  revocation.py           signed revocations, the local feed (durable appends; identity = principal + rev_id + body; every stored record verified as a DOCUMENT at every load — the key and signature fields of their type, the signature under the named principal key — else `feed.corrupt`, a storage failure, never a record enforcement skips; a torn tail is local corruption, `feed repair`), freshness (fail closed after grace)
  denial.py               standing_denial (extension, flag-gated; the store is a durable append, written before the ledger entry; the feed's framing discipline, identity = principal + denial_id + body, every stored record verified as a document at every load else `denial.corrupt`, a torn tail is local corruption, `denial repair`)
  executor.py             exactly two actions: "info" (no-op) and "fs.write" under scratch/ (descriptor-relative, root by identity, symlinks refused; everything after the rename is committed state)
  node.py                 identity, trust store, receive pipeline (one lock for every ledger writer, reserved uses), outbox/retry
  bundle.py               the wire envelope and the mail body format
  adapters/local.py       two nodes in one process (the proof; every bundle handed to it crosses the sender's outgoing boundary before anything is recorded, logged or delivered)
  adapters/mail.py        the Gmail wire via gmail-send.py / gmail-api.py
  cli.py                  `natively` verbs
tests/                    pytest, one file per module + tests/test_e2e_local.py (the proof)
bin/natively              wrapper: runs the package in .venv
state/                    this node's public state (card, pinned roots, cards, grants, embedded parents, ledger, feeds,
                          seen, outbox, wire cursor, pending revocations and replies)
scratch/                  the only place fs.write may land
```

```
.venv/bin/python -m pytest | tail -1      # "1457 passed in …" on 2026-09-08 (the count is read from this run, never typed)
.venv/bin/ruff check natively tests && .venv/bin/ruff format --check natively tests
```

`bin/natively` runs from any working directory (it puts the package on PYTHONPATH
rather than changing directory, so a relative `--out FILE` is relative to where you
are). The venv has one non-test runtime dependency beyond `cryptography` and
`python-ulid`: the `regex` package (pinned in requirements.txt), which compiles and runs a
grant constraint at use with a timeout; the pattern itself is a sentence of the package's own
constraint language, parsed by `grant.emit_pattern` and compiled from that parser's emission (the grammar table under "The constraint language" below).

## Wire format

One transport message carries one bundle:

```json
{"natively": "v0", "kind": "message" | "ack" | "card" | "revocation",
 "object": { ...the signed protocol object... },
 "cards":  [ ...sender card, so the recipient can verify... ],
 "grants": [ ...the grants the message's grant_ids name, parents embedded... ]}
```

Mail body = plain text, first line `X-Natively: v0`, then the bundle JSON as
base64 wrapped at 76 columns. Subject `Natively v0 wire` (a new thread, never the
human design thread). From `taylor@houmanoids.com` to `taylor@teale.com`
(`peer_email`, the send target). A mail is read only if its From address is one
of `peer_addresses` (config; default `taylor@teale.com` and `taylor@hou.vc`, the
two Instinct writes from; every element validated at the typed load — a non-empty
string, no whitespace, exactly one `@`, compared lower-cased — else `state.corrupt`
naming the path and the index; the list is read inside every poll's storage
boundary, never filtered or coerced, so a config that fails is a storage failure of
the poll with nothing classified, nothing seen and the clock and the cursor unmoved,
and a list that names no address is `config.no_peers` by name, never a poll that
ignores everything) its To names the configured mailbox (`self_email`; round 21, Z2) and its subject is exactly
the wire subject or `Re: ` + it; anything else on the thread is ignored and counted in the
poll summary, never ledgered. The mail is read through `gmail-api.py thread --json`, so headers and
body are separate fields and body text can never pose as a transport record.
Transport ids, thread ids and arrival order are never trusted: `msg_id`,
`in_reply_to` and ordering come from inside the envelope and the ledger.

Limits, all on decoded bytes: 512 KiB per bundle, 256 KiB per message body, 64 KiB
per parameter value (checked before any regex runs), JSON nesting 32, duplicate
member names and integers past 2^53 rejected at parse time (RFC 8785 agreement).
Every id is `<prefix>_<26-char Crockford ULID>` and is validated in full.

Objects (all JCS-canonicalized, Ed25519 over the object minus `sig`):

- **card** `{card_version, agent{name,key}, node{name,key}, principal{name,key,principal_kind}, capabilities[{action,resource}], ledger_url, issued_at, node_sig, sig}`.
  `principal_kind` is `"stand-in"` on citadel until Taylor holds a signing client.
- **grant** exactly spec section 3; `params.values` grammar `in` / `range` / `regex`;
  `params.keys` is the complete list of parameter names a request may carry — `[]` permits
  NO parameters (in matching and in the delegation subset algebra alike; the CLI adds
  `content` for `fs.write`); `parent_grant` embeds the full parent (depth one, strict subset,
  rooted in a pinned principal). Regex constraints run through the `regex` package with a
  2 s timeout; a timeout is refused as `scope.regex_timeout` and ledgered.
- **message** `{msg_id, ts, from, to, in_reply_to, grant_ids, body, sig}`; body plaintext is
  `{"type":"info","text":...}` or `{"type":"action","action":...,"resource":...,"params":{...}}`.
  Classification: empty `grant_ids` with a well-formed body is information whatever the body
  says (an action body is NOT executed); non-empty `grant_ids` with an info body is refused
  (`message.body.type`); a malformed body is refused and ledgered whatever `grant_ids` says;
  a grant whose subject is another agent is refused (`no_authorizing_grant`, the reason names
  `grant.subject.agent`) and ledgered. Nothing is silently information.
- **ack** `{ack_id, ts, from, to, in_reply_to, outcome, ledger_head, ledger_entry, sig}` signed by the
  recipient agent key; `outcome` is `information | applied | refused:<reason> | failed:<reason> | duplicate`.
- **ledger entry** `{ts, actor, grant_id, action, params_hash, outcome, prev_hash, msg_id, detail, direction}`,
  plus `intent_id` on a repair audit only (an `rpr_` id in full — the intent the audit
  records, matched by equality when a repair resumes; validated at the load like every
  field, absent from every other entry so their hashes are what they always were);
  entry hash = SHA-256(JCS(entry)); head = last entry's hash; genesis prev_hash = `sha256:000…0`.
  `direction` is `in` (this node handled something a peer sent, or acted on its own) or `out` (a
  record about a message THIS node sent: a peer's ack of it, or its undelivery).
  `state/ledger.prose.txt` mirrors every entry as exactly one line ending in `[<12 hex of the
  entry hash>]` (line breaks and control characters in any field are escaped). The chain is
  verified on every load from disk — a broken chain (`ledger.chain`), a line that does not
  decode or is not an entry (`ledger.corrupt`), a physical line that is empty or
  whitespace-only (`ledger.corrupt` naming the line: the ONLY element any reader of a
  JSONL of ours skips is the synthetic empty string after the final newline — a record
  replaced by spaces would otherwise vanish from enforcement with the file still loading;
  blank by the one Unicode-aware rule, `durable.is_blank_line`, so a record replaced by
  U+00A0s or U+2003s is corruption too, never a torn tail the repair cuts;
  the same rule, by their own names, in the revocation feed and the denial store, in every
  loader, prefix check, tail check, repair verb, verify verb and the pin; a whitespace-only
  unterminated tail is corruption, never "an entry short of its newline" and never a torn
  tail the repair cuts — the operator restores the file; a blank line in the prose mirror is
  never removable excess either, `ledger.repair.refused`) or a last line without its newline
  (`ledger.truncated`) is local corruption of a file of ours, an `IntegrityError` naming
  the path and the line or byte offset: a storage failure that stops the node (fail
  closed: nothing ledgered, nothing acknowledged, the mail unseen), never a `VerifyError`
  taken for a verdict on the bundle in hand — and `ledger verify` regenerates every prose
  line and compares whole lines; every entry is checked IN FULL at the load (its
  fields, their types, the direction, a timestamp that parses: `ledger.entry.fields`),
  so no field of an entry on file can fail later where it is used. `ledger repair`
  restores an unterminated JSONL tail first (a whole entry of this chain short of only
  its newline is terminated — on the verb's FRESH run only after the mirror's state is
  decided against the chain the newline completes, nothing written to the JSONL unless
  the mirror is already consistent with that result or an intent stands that can finish
  it: a mirror whose last line is a non-blank strict prefix of that entry's prose, the
  mend case, first gets a TERMINATION intent for the ledger's own tail stage — the same
  marker with `bytes` 0, the entry bound by hash, the mirror cut point recorded as
  `mirror_to` — and the newline, the mend, the `ledger.tail_truncated` audit (its detail
  saying the entry was terminated — "its newline put back where an append had stopped
  short of it, or already there" — and its mirror line mended, nothing cut: one text true
  of both termination shapes, since a resume at "truncated" cannot know whether an earlier
  run wrote the newline) and the marker's removal follow under it, each step resumable
  after a failure; a resumed termination intent requires the bytes past its cut point to
  be EXACTLY the bound line or that line plus its newline at step "intent" (a whole
  chained entry there, terminated or not, is a hand edit or a foreign tool and refuses
  `ledger.repair.intent_mismatch` with nothing written and the marker unchanged — before,
  it was terminated as "the last entry" under an intent whose hash names another line),
  and at step "truncated" admits past the bound entry only this stage's own audit (whole,
  short of only its newline, or torn — a torn tail after the audit landed whole is not
  this machine's and refuses); a cut intent past its intent step applies the same rule to
  what follows its cut point; any other mirror shape — a partial line that is
  not such a prefix, a blank line, a whole line that is not its entry's, a strict prefix
  of an earlier entry's line, a mirror that does not decode (`ledger.mirror_corrupt`, no
  intent invented for it) — is refused by name with both files byte-identical and no
  marker written. The terminated sibling of the mend case — the last entry landed WITH
  its newline and the machine's own prose write for it then tore after an ASCII prefix,
  no intent standing — gets the same finishing intent first (bytes 0, the entry bound by
  hash, `mirror_to` the cut point; its intent step finds nothing to terminate) and the
  mend, the audit and the marker's removal under it, resumable the same way; the same
  tear inside a multibyte character stays the mirror stage's one-run cut and
  regeneration, and a strict prefix of an earlier entry's line is refused there too.
  While a mirror intent stands at its truncated step, the JSONL's last line that carries
  that intent's id (terminated or short of only its newline) is bound to the marker —
  the one binding every found audit crosses: the audit of the store the marker names,
  the marker's tail hash — before its newline is written and before the subordinate
  tail stage does anything; a torn partial line — one that is not a whole JSON object
  — is cut by the intent machine below and ledgered `ledger.tail_truncated`; a whole
  object that is not the next entry of the chain is corruption, never cut;
  a mirror line an older tool wrote for the cut entry cut under the same intent — only
  when the part before it is this ledger's chain in full, else refused by that fault's
  name with nothing written), appends prose lines missing at the end of the mirror (a crash between
  the JSONL write and the prose write), truncates a mirror LONGER than the JSONL to the
  JSONL's length (ledgered `ledger.mirror_truncated`, see the durability inventory below),
  rebuilds a mirror that does not DECODE as UTF-8 (a write torn inside a multibyte
  character — the em dash before a detail — at the tail or in the middle: everywhere the
  mirror is read that is `IntegrityError ledger.mirror_corrupt` naming the path and the
  byte offset, a storage failure like any other local corruption, never an exception out
  of a poll; the repair cuts the bytes from the damaged line on when the whole lines
  before it are their entries' prose and the JSONL verifies, ledgers
  `ledger.mirror_truncated`, and regenerates every line cut — a JSONL damaged too refuses
  by its own name, nothing written; a regeneration that itself tears under a standing
  intent is cut back again when the repair resumes, under that same intent; and a mirror
  repair whose OWN audit append tore the JSONL's tail — power loss inside that append, the
  mirror marker at step `truncated`, the one step at which the machine writes the JSONL —
  is recoverable: `ledger repair` runs a subordinate tail stage under the nested marker
  `state/ledger-repair-pending.tail.json`, the same machine with the same validation and
  the same `ledger.tail_truncated` audit (a whole audit entry short of only its newline is
  terminated instead), cutting only the bytes after the last complete entry that continues
  the chain and only when that prefix is this ledger's chain in full — a torn tail that is
  not this ledger's is refused by name with both markers standing — and then resumes the
  mirror repair to completion with exactly one mirror audit; the nested marker goes only
  after the whole file validates, exists only beside a mirror intent, and at any other
  step of a mirror intent a torn tail is not this machine's: refused by name, nothing
  written), and refuses
  anything else; a final line whose newline
  never landed is "unterminated" — `ledger verify` refuses it (`ledger.prose.unterminated`),
  and repair (or the next append) puts the newline back when the line IS its entry's prose,
  refusing it as a mismatch otherwise. Every append runs that same check first: a trailing gap
  is regenerated before the new entry lands, and any other difference (an interior mismatch,
  more prose than entries) refuses the append (`ledger.prose.mismatch`, with what to restore).
  That same full check — the chain, every entry's shape, the mirror compared through the
  head, plus the repair guard — is the FIRST ledger read of every receive
  (`Ledger.check_intact` in `Node._receive`, read-only, before even the envelope is judged,
  and the same check before `pin` publishes trust since the replay it runs ledgers; one full read of both files per
  receive, no cache between it and the append): before authorization counts uses, before a
  reservation is written, before the executor runs. A last completion whose outcome was
  edited (its incoming chain link intact, so the loader alone would pass and count zero
  uses) or a mirror edited instead is a storage failure by name there — the executor never
  called, nothing reserved, nothing ledgered, the mail unseen — never an execution the
  append refuses afterwards. The chain's tail has a local anchor besides: every ack this
  node stored in `seen.json` was signed over the ledger head of its moment, and the same
  full check (`check_intact`, and `ledger verify`) requires each stored ack's
  `ledger_head` to be the hash of an entry PRESENT in the chain as loaded — a last
  completion edited AND its mirror line deleted (or regenerated from the edit) passes the
  chain and the mirror comparison but not this: `ledger.head.mismatch` naming the ack's
  msg_id, a storage failure; a node with no stored ack has no anchor and is unchanged,
  so a gap can never become the interior mismatch that repair refuses. Every stored ack
  is AUTHENTICATED before its head anchors anything (its structure, OUR signature, the
  msg_id it answers): one that no longer verifies is `seen.corrupt` at every ledger check
  (every receive, the pin, the verbs, the pending-reply rebuild — never an anchor read
  from an unverified field, never a record skipped), the operator restores `seen.json`;
  and an ack is verified BEFORE it is stored (`ack.self_invalid`, a storage failure:
  nothing stored, nothing sent, the completion standing for the re-delivery to rebuild
  from), so a stored ack that fails is always one damaged on disk. Every ledger append
  of the package goes through ONE method, `Node.ledger_append`, which runs that same full
  check (the repair guard, the chain, the mirror through the head, the anchors)
  immediately before the line lands — the receive's completions, the `revoke` and `deny`
  records (both verbs run it once more BEFORE their enforcing record is written, so a
  ledger that fails its check refuses the verb by name with nothing written; a damaged
  ledger already fails every receive closed, so nothing a revocation would stop can run in
  the meantime), the repair machine's audits (under their own intent, which the guard
  admits), the outbox's undelivered line, a replayed held revocation, the adapter's line
  for a mail that is not a wire body and its pending-reply audits — and a test pins the
  package's `Ledger.append` call sites to that method. The same check is the first ledger
  read of every path that TRUSTS an existing pending-reply audit (the poll's aside count,
  `pending list`, `pending repair`, `pending discard`: a discard on record is finished only
  after it passes, so a ledger whose anchor check fails — a discard record forged over an
  anchored completion — is a storage failure of the verb or the poll by the ledger's own
  name, nothing deleted, the aside copy and the canonical held reply kept, no barrier
  reached; the seen file being read by that check, a seen file that cannot be read or a
  damaged stored ack fails the verb at that first lookup). `ledger verify` and
  `ledger repair` run under the state lock, so a poller's append and its own gap repair never
  interleave with them. An `applied` entry, a `failed:interrupted` entry, or a
  `failed:post_commit` entry (the executor failed after its side effect existed) consumes a
  grant use. Outbound entries are direction `out` and, by convention, named `out.ack` (a peer's
  ack of our message) and `out.send` (our undelivered send); the DISCRIMINATOR is the
  `direction` field, never the name. The completion entry of an inbound message (applied /
  refused / failed / information, direction `in`) is what a lost ack is rebuilt from, whatever
  the inbound request called its action: an inbound action named `out.anything` is refused
  `executor.unsupported` before any grant is read, and that refusal entry (direction `in`)
  recovers its lost ack like any other, consuming nothing. A LEGACY entry — written before
  the field existed — has no `direction` key and is accepted as it is: its hash is over the
  entry as stored (the historical chain holds), it reads as `in` (every entry of that era
  was inbound or the node's own), and its prose line renders as it did then (the `->` arrow),
  so an existing mirror still verifies; no migration rewrites history. Any other missing or
  extra key, or a direction that is not `in`/`out`, is still refused.
- **revocation** `{rev_id, ts, principal{key}, revokes{cards[],grants[]}, principal_statement, sig}`.
- **standing_denial** (extension) `{denial_id, ts, principal{key}, subject{agent|null}, deny[{action,resource}], principal_statement, sig}`.

Keys are `ed25519:<base64 raw 32 bytes>`; hashes are `sha256:<hex>`; ids are
`msg_/ack_/grt_/rev_/dny_` + ULID (26 Crockford characters, the first `0`–`7`: a value
past the 128-bit maximum is a format failure); timestamps RFC 3339 UTC seconds (`…Z`).
Number literals that overflow to infinity (`1e999`) are rejected at parse time like
`NaN`, so a signed body carrying one is a body-verification refusal, not a hashing crash.

## What the executor enforces, in order

Every ledger writer runs under one exclusive lock on `state/.lock` (flock, re-entrant
within a Node instance): `receive()` as a whole, `revoke`, `deny`, `pin`, the outbox and
freshness bookkeeping, the CLI's `ledger verify` / `ledger repair`, the startup sweep,
and the mail adapter's entire poll pass — and so does every other state write: the
config (`save_config`, and the config verb's read-modify-write, which takes the same
lock without constructing a node), the self card (`natively card`), and the grant store and
the card import a verb reaches (`natively grant`) — every state-file write in node.py runs
through one method, `Node._write_state`, which takes the lock (round-19 self-gate). Two writers of one
state file never share a temp name either (`durable.write_json`: an exclusive, unique
temp file, so one process can never rename another's bytes over the target and report
success — round-19 gate, finding 2). Replay checks, use counts, the executor, the
ledger append and the ack save are one critical section per state directory, and a
`natively revoke` run beside the poller can never capture the same ledger head. Anything
a peer sends that is not a clean verification failure (a parser blow-up, an odd type) is
ledgered as `verify_failed:malformed` and the poll continues — except a LOCAL storage
failure, which says nothing about the bundle: an `OSError` from the feed, the ledger, a
state file, or the very write that would have ledgered a refusal; or an `IntegrityError`, a
file this node wrote that does not parse — a torn feed or denial-store tail after power
loss, a ledger line, a seen file or a cursor that does not parse; EVERY local parser
failure counts, a syntax error, an oversized integer literal, nesting past the recursion
limit, a member name repeated inside one object (`seen.json` with one message key twice
would otherwise keep the last reservation and drop the first from use counting) alike — in an
unterminated last line too, where ONE PREFIX RULE decides (`durable.torn_text_problem`): the
bytes are a repairable tear only when they are a strict prefix of exactly one record of ours —
the longest valid UTF-8 prefix parses as an unterminated single object with no member repeated
and no whole object before it on the line — and anything else (a member repeated, whole or
not; a second object or trailing bytes after a whole one; an invalid byte, a damaged character
in the middle of the line, a control character or an invalid escape inside a string, an
incomplete character where only ASCII belongs — outside a string, after a backslash, inside the
hex digits of a `\u` escape — or a Unicode digit inside a number, since JSON digits are ASCII) is the store's corruption by name at every
read and never a tail the repair verbs cut (before, any parse failure without a visible
repeated member read as a tear, and two whole objects on one line, an object followed by
garbage or a NUL byte, an invalid byte mid-line and a repeated member before an incomplete
character were all cut; round-19 gate R4, Fable C1) —, and a genuine tear
(`ledger.truncated`, `feed.torn`, `denial.torn`); a standing feed or denial repair intent is
judged under the same rules before its cut (`Node._check_store_resume`: the cut point at a
line boundary, the recorded bytes one unterminated physical line, not blank, and a strict
prefix of one record — an intent an older classifier left over anything else refuses
`<store>.repair.refused` with nothing truncated and the marker standing), as the ledger's tail stages judge theirs through `chain_now`; no
fault met while READING a file of ours is a `VerifyError` (a guard test pins where the
loaders raise one: a revocation's or a denial's structure and rooting at receipt, the
feed's freshness at use — peer input and policy, never a file) —
or a file this node wrote that parses but has the WRONG SHAPE. Local state is never peer
input: every state file read as a structure (`seen.json`, `outbox.json`, `pinned.json`, the
wire cursor, `revocations.check.json`, `seen-mail.json`, a held reply, `config.json`, the
replay marker, a repair intent, `peer-heads.json`, every card and grant on file) comes
through ONE typed loader (`state.read`, `state.py`), which checks the top-level type and the
per-entry shape the code relies on — for `seen.json` an object whose values are objects,
a stored ack an object under `ack`, a reservation the fields a consumed use is counted by
(status `in_progress`, a `grt_` grant id, a timestamp: never defaulted, so a damaged
reservation can never read as zero uses); for `outbox.json` a message bundle in full
(the envelope, the message's structure and signature) bound to its entry's `msg_id` and
recipient, with deadlines that parse and a status the retry schedule knows, so a re-send
never transmits a `{}`; for the line-framed stores — the revocation feed, the denial
store, the ledger — every line a full object of its kind, and for the feed and the store
the DOCUMENT in full on every load (`revocation.check_document`, `denial.check_document`:
the principal key one that decodes, the signature a base64 string of 64 bytes verifying
under that key — a stored key replaced by a string that is not a key, a damaged
signature or one under another key is `feed.corrupt` / `denial.corrupt` naming the path
and the line, a storage failure at authorization, at `natively pin` (which reads both
stores before it publishes trust) and at the verify verbs, never a record that
`grant_revoked_by` / `denied` skips so a revoked or denied action becomes authorized;
only the rooting and time stay decisions at use; the ledger's read fields of their
type), `feed.corrupt` / `denial.corrupt` / `ledger.corrupt` naming the path and the line;
for a grant on file (`grants/`,
`grants-embedded/`) the DOCUMENT in full on every read (`grant.check_document`: the
structure with every field of its type — every signature and key field a string of its
encoding and length — the signature under the issuer key it names, the embedded parent's
structure and signature likewise) bound to its file name, since it was authenticated
before it was stored and a document whose signatures hold is exactly the one signed; only
the rooting, the delegation chain and bounds, the time window, revocation, use counts and
the extension flags stay `grant.verify`'s refusals at use, so a cached grant whose `sig`
became `[]` is `state.corrupt` and the mail stays unseen until the file is put back —
never `no_authorizing_grant` acknowledged and replayed; a constraint pattern the regex
engine cannot compile is a structure verdict too, never an escape, and a pattern is a sentence of the
CONSTRAINT LANGUAGE (the subsection below: a small language with a complete parser of its
own, `grant.emit_pattern`, in place of the scanner over the engine's grammar that five reviews
in a row defeated; everything outside the language is refused by name and position as
`grant.constraint.pattern` at receive, at issue and at load, and what compiles is the parser's
emission, never the raw input), and the document check verifies the
signatures BEFORE it compiles any pattern, so a garbage-signed grant from the wire is refused
by its signature at the cost of a linear parse; and nothing lands under
`grants/` that the loader would refuse: `issue_grant` / `delegate_grant` check the document
before storing, so `grant --max-uses 0` is refused at issue (exit 1) rather than stored to
block every later family accounting, while a loose SCOPE still stores (its bounds are the
receiver's refusal at use) — a delegation's other restrictions are applied exactly as asked
for or refused by name at issue: the expiry never past the parent's (`--expires-in`, none
given = the parent's), the uses never more than the parent's remaining budget across its
family (`--max-uses`, none given = that budget, an explicit 0 a usage error), the window
never looser than the parent's (`--window`, none given = the parent's); the parent family's
remaining budget is read and the child published under ONE hold of the state lock, so a
receive in another process that consumes the parent's last use waits for the publication or
runs before the read, never between (a child never carries a use against zero remaining;
round-19 gate R5) — and refuses a mismatch as
`IntegrityError state.corrupt` naming the path and the reason (`card.corrupt` for a card on
file: verified in full and bound to its name on every read; `card.self_corrupt` for the self
card; `<store>.repair.intent_corrupt` for a repair intent), so an `AttributeError`, a
`TypeError` or a `KeyError` from local state is reachable nowhere, and never as
`verify_failed:malformed`. Every text read the package performs on a file of its own
decodes inside its loader with a failure mapped to that file's corruption reason
(`state.corrupt`, `feed.corrupt`, `denial.corrupt`, `ledger.corrupt`,
`ledger.mirror_corrupt` with the byte offset): a `UnicodeDecodeError` is reachable
nowhere above the loaders (a guard test walks the package's AST for every text read). It is a storage failure wherever it surfaces: receive refuses with
nothing ledgered and nothing acked, the mail stays unseen and the poll counts it; `natively
ack` and `pending repair` refuse by name with the path (the copy left unresolved); a node
whose `config.json`, `pinned.json` or self card fails does not construct, and every CLI
verb exits 2 naming the path. A state file of the wrong shape is repaired by hand
(restored from a backup, or removed where the file is rebuilt from the wire — the seen
file is not one of those: a stored ack removed is answered from the ledger completion).
It is reported and raised as `StorageError`, nothing is ledgered (the ledger may be what
failed), and the mail adapter leaves that mail unseen (read again next poll). The freshness rule,
exactly as the adapter runs it: the revocation-lookup clock advances only after a COMPLETE
fetch whose cards and revocations (the control phase) all landed, and BEFORE the acks and
messages are applied; a storage failure in that message phase does not roll it back — the
control data did land, and the clock claims nothing more. When the control phase did NOT
land, the poll applies no ack and no message at all (their mails stay unseen), and neither
the clock nor the cursor moves. The cursor moves only once every write the fetch needed
has landed.

1. bundle shape, version, depth; attached cards verified (held in `cards-pending/` until their principal is pinned);
   attached grants AUTHENTICATED before they are stored (structure, signatures, rooted in a pinned principal
   or a delegation chain that is); a chain in which the child and its embedded parent share an id is refused
   (`grant.id_conflict`) before anything is written; a known id with a different body is never overwritten —
   the attached grant AND the parent it embeds are each compared with the grant on file under that id
   (`grants/`, then `grants-embedded/`), any difference refuses the whole attachment (a re-signed parent
   variant cannot lift the stored parent's budget); a parent first met inside a child is stored under
   `state/grants-embedded/<id>.json` — read for identity and budget checks, NEVER executable: a message may
   name only a grant under `grants/`, and a parent gets there only by arriving top-level, attached and
   authenticated like any other grant; a grant whose attached copy failed is refused for this message even
   if a cached original exists (no substitution);
2. message structure and the sender's signature; sender must have a trusted card that is not revoked by
   its own principal (checked on every lookup: messages, acks, delegators; an agent whose old card was
   revoked and replaced is its unrevoked replacement); `to` must be this agent;
3. duplicate `msg_id` re-sends the stored ack, applies nothing — the stored ack is validated in full
   first (the ONE reply validation, `Node.reply_problem`: the envelope and every card it carries, one
   of them this agent's; no grants — a reply carries none, `reply.grants_not_allowed`; the ack's
   structure and OUR signature; `in_reply_to` = the `msg_id`), exactly
   as every reply is before it is held and again before it is sent; one that no longer verifies is LOCAL corruption
   (`seen.corrupt`, a `StorageError` naming the file: nothing sent, the mail stays unseen, the poll
   incomplete) and is never sent by any path (`natively ack` refuses it too; `natively pending repair`
   refuses it as well — the stored acks anchor the ledger's tail, and the completion a damaged
   ack anchored can no longer be told from an edited one, so nothing is rebuilt over it: the
   operator restores `seen.json` from a backup); a re-delivery whose ack was never stored
   is answered from its ledger completion entry (the outcome and the refusal reason are rebuilt, nothing
   is re-evaluated or re-executed: a refusal stays a refusal even once the condition has cleared) — and
   storing that rebuilt ack is a durability step: the completion found may be an unsynced tail whose
   append failed after the bytes became visible, and the ack replaces the reservation that is the last
   durable record of the use, so the ledger barrier is re-established first (both files fsynced, the
   mirror made whole) and only then is the ack written; a barrier that fails leaves the reservation; a
   duplicate of a message whose use was reserved but never reached the ledger is acked
   `failed:interrupted` (once; the use stays consumed); a peer's ack naming the `msg_id` never counts;
4. empty `grant_ids` = information (ledgered, acked `information`);
5. held revocations a startup sweep could not replay (`state/replay-pending.json` exists) block every
   authorization: the node attempts the replay itself first (the feed may have been repaired by another
   process), and a replay that fails is the storage failure it is — raised through, the mail unseen,
   nothing ledgered, nothing acked, the action evaluated again after `natively feed repair` (no named
   refusal exists for the state: every cause is a fault in a file of ours) — for every
   cause that keeps the replay from running — the feed still torn or a record of it corrupt
   (`IntegrityError`), the
   `revocations-pending/` directory unreadable (an enumeration failure is a storage failure, never an
   empty listing: `durable.list_dir`, no `Path.glob` anywhere), a held copy that does not parse, a held
   copy that parses but is no longer the revocation it was when held (not an object, a damaged or
   missing principal key, a signature that no longer verifies: `revocation.held_corrupt`, the copy kept
   in place and named — every held copy is verified in full against the key it names BEFORE any
   principal filter, so no damaged copy is ever skipped), an unfinished feed repair
   (`feed.repair_pending`), or a replay write that fails — and the marker is cleared only once the
   enumeration AND every replay succeeded. Distinct from a refusal: a storage failure EARLIER in the receive — the sender's card
   unreadable or not parsing (step 2), a stored ack that no longer verifies (step 3, `seen.corrupt`),
   any state read or write that raises — is a `StorageError`:
   nothing is ledgered, no ack is produced, the adapter leaves the mail unseen and reads it again next
   poll; then standing denial (if the extension is on) before any scope — the extension flags
   and `poll_s` are read from `config.json` through the typed loader at EVERY authorization
   (`Node._config_now`, under the receive's lock), never from the copy cached at construction, so
   a flag enabled by `config --set` from another process binds the running poller at its next
   action, and a config the loader refuses fails every authorization closed (`state.corrupt`);
6. for each named grant: structure, issuer pinned (or delegation chain rooted in a pinned principal),
   signature, subject = this card, audience = this node/agent, time window, capabilities-of-card,
   revocation (grant, parent, the delegator's card by ITS principal, own card), max_uses and
   max_uses_per_window counted over the ledger PLUS in-progress reservations, and for a delegated
   grant over the parent's whole family (parent + every child on file) against the parent's limits,
   scope match with params constraints, revocation-lookup freshness (fail closed after one poll of grace);
7. a durable reservation of the use in `seen.json` (`in_progress`: the file fsynced, renamed into place,
   and the directory fsynced); then, immediately before the executor and after every slow step, the
   chosen grant and its parent are rechecked for revocation and its freshness and, LAST, for the
   time window (expiry, `not_before`, the parent's expiry) on a clock read after every other read
   (`grant.check_time`: `verify` reads its `now` before the card, the pins, the config and the feed,
   so a clock that moved during those reads was judged at the earlier reading) — a validity crossed
   in between is refused by name,
   the refusal ledgered saying nothing executed, and the reservation released by that stored ack (no
   use consumed; round-19 gate, finding 7); then the executor: `info` or `fs.write` to `scratch/<name>` where the
   resource is `host:<this node key>:scratch/<name>` — the scratch root is opened at the CONFIGURED path
   with `O_DIRECTORY|O_NOFOLLOW` and must have the `(dev, ino)` the node recorded when it created the
   root (a symlink or another directory put at that path between two receives is refused), the
   destination is refused if it is a symlink or not a regular file, the temp file is created
   `O_CREAT|O_EXCL|O_NOFOLLOW` under a random name and owned by a file object from that moment (its
   identity is read through the file object's fileno, so a lookup that fails closes the descriptor,
   unlinks the temp name and closes the directory descriptor — no exit path leaves a descriptor open),
   the rename is descriptor-relative, and the directory is fsynced after it. Failure accounting splits at the rename: anything raised BEFORE it is an ordinary
   `failed` (nothing changed, no use consumed; the temp file is removed), anything raised AFTER it (the
   directory fsync AND the close of the directory descriptor) is `failed:post_commit` — the side effect
   exists, so the use is consumed exactly as for `applied`, and the ack says `failed:post_commit`. A close
   failure never masks a fsync failure already propagating: the original error is kept and the close
   error is appended to its detail. An exception FROM the rename itself is decided by identity, never by
   the exception: the temp file's `(dev, ino)` is taken from its open descriptor beforehand; if the
   destination now carries it the rename took effect (`failed:post_commit`); if the temp file is still
   itself and the destination is not it, nothing was committed (ordinary `failed`, the temp removed);
   anything else is an UNCERTAIN commit and fails closed as `failed:post_commit` ("rename result
   uncertain");
8. one ledger entry per outcome, one ack carrying the ledger head; the reservation becomes the stored ack.

Every failure is printed to stderr and ledgered (`verify_failed:<reason>` / `refused`). Nothing is dropped.

Documented limits: the mail seen-file assumes a single poller per state directory (run one
`natively run` per node; other verbs may run beside it, they take the same lock).

What is durable, and in which order (`durable.py` is the one write rule; the tests record
every fsync and the file it hit, and check each order below):

- a state file — reservations and stored acks (`seen.json`), the transport seen file, the
  cursor, the freshness sidecar, pinned roots, config, cards, grants, embedded parents, the
  outbox, peer heads, held revocations, held replies, the replay marker and the repair
  intents — is written to a temp name, fsynced, renamed over the target, then the directory
  is fsynced; never in place;
- a reply (an ack) is held under `state/pending-replies/<msg_id>.<kind>.json` BEFORE its mail
  is marked seen, sent after, and its held copy deleted only after the send returned: a seen
  mark that became visible while its barrier failed, or a send that failed, never loses the
  obligation — the held copy goes out at the start of the next poll. The send has two
  failure classes, told apart by exception TYPE, never by message text: a storage failure
  inside it (the validation at the outgoing boundary — `card.self_corrupt`, `reply.invalid`,
  any `IntegrityError` — or an `OSError`) is a storage failure of the poll: counted, the
  held copy kept, the poll incomplete, the cursor frozen; a transport failure (the send
  tool's non-zero exit, a timeout) keeps the held copy for the next poll and counts nothing
  (the cursor may move: the obligation is on disk). Before the send tool runs nothing is
  transmitted. The staged wire body's removal runs in a `finally` and records its own
  failure whatever the transport did: beside a transport failure (the tool's non-zero
  exit, a runner that raised) the two facts are raised as ONE `StorageError` naming both —
  counted, the held copy kept, the cursor frozen, no attempt spent, never a transport
  failure that hides the cleanup; after the tool returned success it is raised last, after
  the result is recorded, and its text says the send returned (with the gmail id), so the
  copy kept is re-sent once more next poll (harmless: the peer dedups on `msg_id`), never
  taken for "not transmitted" — and an outbox write that fails at that point is raised
  together with it (the gmail id, the recording failure and the path that could not be
  removed, in one message). The outbox re-send classes its failures the same way (a
  storage failure counted, the entry kept, no attempt spent; a transport failure spends no
  attempt and counts nothing). ONE validation
  (`Node.reply_problem`: the envelope and every card it carries — verified in full, one of them
  this agent's — no grants (a reply carries no grants and no messages: a non-empty `grants`
  field is `reply.grants_not_allowed`, so `reply.invalid` at every boundary below; every
  other kind's attached grants cross the shared document check at `check_outgoing`), the
  ack's structure and OUR signature, the `in_reply_to` and kind of its name
  `<msg_id>.<kind>.json`) runs on EVERY reply before it is held and again before it is sent, on
  the same-poll path and the flush alike, and once more at every outgoing boundary a reply
  crosses (`Node.check_reply` in the wire's send, the file exports of `poll --file --out` and
  `ack --out` / `ack --dry-run --out`, the in-process transport: `reply.invalid`, nothing
  leaves, no file written, an existing one untouched). Every OTHER bundle a verb exports or
  hands to the wire — `send`, `send --card`, `revoke`, in the `--out` and `--dry-run --out`
  forms — crosses the same boundary through its own kind's check (`Node.check_outgoing`:
  the envelope, every card and grant it carries, the object's structure and signature,
  and that it is THIS node's — `<kind>.invalid`, exit 2, nothing written or recorded).
  Every kind then crosses the wire's size bound at that same boundary (`bundle.encode`
  over 512 KiB is `<kind>.invalid` too — a storage failure the poll counts on a re-send,
  the entry kept, no attempt spent; before, the encode raised inside the wire's send and
  was classed as a transport failure, so an oversized stored entry stayed due forever
  with nothing counted).
  `revoke` composes and checks its bundle BEFORE the feed and the ledger are written (a
  refused revocation changes no enforcement state; `--dry-run` records nothing anywhere),
  and the in-process wire (`adapters/local.py`) runs the same check on every kind it is
  handed, before anything is recorded, logged or delivered — and on every automatic reply
  the receiver returns, at the RECEIVER's boundary (`check_outgoing`, the size bound
  included: an oversized ack is `ack.invalid`, nothing logged as sent, nothing delivered),
  before that reply is logged or fed back. A reply is held under the id of
  the REQUEST it answers (the message received, the aside copy's name), never a name taken
  from the reply, so a reply of any shape is refused inside the boundary. A reply that fails
  the validation is never held:
  `pending_reply.invalid`, a storage failure ledgered once with the message id (keyed on the
  exact bracketed held name) — the mail stays unseen, nothing is sent, the poll incomplete. The
  validation begins with this node's OWN card: `state/self.card.json` is read through the card
  module's full verification (structure, both signatures) and bound to this node's own keys
  (the agent, node and principal keys equal the pairs under the keys dir — the signed card IS
  the file, it carries no separate hash, so a sound card of another identity is refused for its
  keys) at construction and on every read, so before every ack; one that fails is
  `card.self_corrupt` naming the path, a storage failure: a fresh node refuses to construct
  (every CLI verb exits 2), receive acks nothing and the mail stays unseen, the flush sends
  nothing and leaves every held copy in place — the operator removes the file and runs
  `natively card` again; the refusal is reported with its path and counted. A rebuilt ack
  (a re-delivery, the repair verb's completion source) reads the self card before anything
  is signed or the seen file written, so a source that cannot be read leaves the seen state
  unchanged. A held reply that does not parse, or is not the
  reply its name promises, FAILS CLOSED: it is never deleted and never sent — moved aside in
  the same directory (`<name>.corrupt-<stamp>-<ulid>`, an identity no later quarantine can
  reuse), counted as a storage failure, ledgered `pending_reply.corrupt` once (keyed on the
  exact bracketed aside name; a pass that could not write the audit writes it on the next
  poll), and left there. NOTHING automatic rebuilds or sends from a damaged source: every
  poll runs the ledger's full check with its anchors ONCE when anything is held (a ledger that
  fails it is one storage failure of the poll by the ledger's name and the flush ends there:
  nothing counted, no held reply sent, none removed — round-14 self-gate), then takes the aside
  copies FIRST and counts each unresolved one as a storage failure (the poll is incomplete,
  the cursor stays frozen), then sends the held replies that validate.
  What freezes the cursor: an unresolved aside copy (until a verb resolves it), a discard on
  record whose removal did not finish (whatever the copy's suffix — a `.reconstructed` copy
  too), an aside listing that fails, a held copy that cannot
  be read or validated, a quarantine that could not complete. A peer's re-send of the message
  meanwhile is answered on the ordinary path only — `receive()` finds the stored ack, validated
  (step 3 above), holds it before the seen mark and the flush sends it; a damaged stored ack is
  `seen.corrupt` — and never consults the aside copies. The operator resolves an aside copy
  with three verbs, all under the state lock, every audit before its file effect, every step
  resumable through the ledger record:
  `natively pending list` — one line per file: `held` (to send), `corrupt` (unresolved),
  `reconstructed`, `discarded` (on record, removal unfinished), with the msg_id and kind;
  `natively pending repair [NAME]` — the ledger's full check with its anchors is the verb's
  first ledger read, before any copy's discard record is looked up (a discard record forged
  over an anchored completion is `ledger.head.mismatch`, a storage failure of the verb,
  nothing removed); rebuilds every unresolved copy (or NAME) ONLY from a
  validated source: the stored ack after the same full validation, else — when NO ack is
  stored — the ledger completion (the ledger's full check with its anchors first, so a
  damaged stored ack is `seen.corrupt` there, a storage failure of the verb, nothing rebuilt
  over it; then `Ledger.barrier`, then the ack stored; the actor resolved to exactly one
  card on file, every card read verified in full and bound to its file name first — a
  damaged card is `card.corrupt`, a storage failure, never a key signed for); holds it
  under the canonical name only when no
  DIFFERENT file is there (`pending_reply.conflict` refuses and leaves both files); ledgers
  `pending_reply.reconstructed` once (found again only after the ledger barrier); marks the
  aside `.reconstructed` after the hold is durable (a mark whose rename landed but whose
  directory fsync failed looks finished: every run re-establishes the barrier of every visible
  mark, and a named run on a `.reconstructed` name does the same). The verb NEVER sends: the
  next poll's flush validates and sends the held reply like any other. No validated source =
  refused by name (`pending_reply.unresolvable` in the output, nothing changed). The discard
  record is checked BEFORE the suffix decides anything: a copy discarded on record and still on
  disk (whatever its suffix) is an unfinished discard, finished from its record — the same
  resumable removal the discard verb takes, the ledger barrier first — and reported
  `discarded`, never rebuilt. A source is taken only when it READS cleanly: a storage error
  while a candidate is read (the seen file unreadable or not parsing, the self card
  `card.self_corrupt`, a card on file `card.corrupt`) is the verb's storage failure, reported by
  name with the path and counted, the copy left unresolved — never a fallthrough to the next
  source; only a source that reads cleanly but fails validation falls through;
  `natively pending discard NAME [--with-held]` — ledgers `pending_reply.discarded` once
  BEFORE any removal (the record carries `[held reply dropped too]` with `--with-held`), then
  removes what the RECORD calls for: with `--with-held` the canonical held reply of that
  message first, its directory fsynced, then the aside copy, its directory fsynced; without
  `--with-held` a standing canonical held reply refuses the discard (it is a genuine
  obligation the next poll sends). A retry that finds the record — the verb again, or
  `pending repair` — finishes the removal from it, whichever file is already gone (a missing
  file is a finished step, never an error); a second discard of a finished name appends nothing. The accepted cost of record-first: a
  poll that runs between the record and the canonical's removal sends that standing held
  reply — an ack that passed the validated hold path, which the peer dedups — and the retry
  finds it gone. The accepted cost of failing closed: a corrupt held reply waits for an
  operator, and the peer sees its ack after their re-send or after the repair;
- a rebuilt ack (a completion found in the ledger, its ack lost — the re-delivery path, and the
  repair verb's second source) is stored only after the ledger barrier was re-established: the
  JSONL and the mirror fsynced, the mirror made whole;
- the revocation feed: the line appended, the file fsynced, then the directory. A retry that
  finds its body already on file (a barrier that failed AFTER the bytes became visible) fsyncs
  the file and the directory again before it answers `duplicate`; a held revocation whose file
  already exists is synced again the same way. Only after that return may a mail be marked
  seen, the cursor advanced, a held copy deleted, or trust published;
- the standing-denial store: the same append order, BEFORE the ledger entry that records the
  denial; a store failure leaves no ledger entry and is reported; a duplicate fsyncs the file
  and the directory again before it is answered, like the feed;
- a repair verb (`feed repair`, `denial repair`, `ledger repair` on a mirror longer than the
  JSONL): one resumable state machine driven by the intent marker
  `state/<store>-repair-pending.json` — step `intent` (which file, the byte offset to cut
  at, the hash of the bytes to be cut, an intent id — an `rpr_` id IN FULL, the prefix
  and exactly the 26-character ULID the package mints: a marker whose id is anything
  else, `rpr_` or a prefix or a longer string, is `<store>.repair.intent_corrupt` at the
  typed load with the marker as found and nothing promoted) written durably BEFORE
  anything is touched; the truncation, fsynced (file, then directory); step `truncated`;
  the `<store>.repaired` / `ledger.mirror_truncated` ledger entry carrying the intent id
  as its own `intent_id` field (and naming it in its detail); step `audited` with that
  entry's hash (required at that step: an audited marker without a `sha256:` hash is
  `<store>.repair.intent_corrupt`, nothing removed); then the marker removed. A retry or
  a restart resumes at the recorded step: a file already at the cut point is fsynced
  again and advances, the audit is appended only when the ledger holds none whose
  `intent_id` field EQUALS this intent's id (never one matched by the detail's text, a
  substring or a prefix — a marker id damaged to `rpr_` once matched an older repair's
  audit by containment and promoted its hash), and a found audit is BOUND to the marker
  before it is barriered, promoted or trusted: its `params_hash` is the tail hash the
  marker recorded and its action is the audit of the store the marker names, else
  `<store>.repair.intent_mismatch` naming both, the marker standing at its step — the id
  is matched FIRST and the binding checked on whatever carries it (an entry under this
  id whose action is another store's audit is a mismatch, never "absent"), and it is
  checked at step `truncated` BEFORE any mend writes (an audit line visible on the JSONL,
  terminated or short of only its newline, is bound before its newline is written or its
  torn prose line regenerated: a wrong hash leaves the JSONL, the mirror and the marker
  byte-identical on every retry; under a mirror intent the chain as the file stands is
  bound the same way — every entry under the intent's id by action and hash — and a torn
  tail past an audit that landed whole is refused by name before the subordinate tail
  stage cuts or appends anything, since that audit's append ran once); at `audited`
  the marker is deleted — for the ledger's own stages only after the CURRENT mirror is
  validated and, where a prose write of that intent's earlier run tore, mended while the
  intent still stands (an undecodable tail cut back to its sound lines, a decodable
  strict-prefix partial line completed; anything else refused by name with the marker
  standing, so the retry finds the intent that permits the regeneration), the lines a cut
  removed regenerated, and the mirror verified whole through the head with the anchors —
  a crash anywhere truncates once and audits once, and the
  verb reports the bytes truncated by THIS run (0 on a resume). Every resumed ledger stage
  validates the CURRENT mirror as well as the JSONL before any cut, marker advance or
  marker removal: the mirror stage checks the prose the intent retains through its recorded
  cut point (an equal-length whitespace replacement of that prefix is `ledger.prose.mismatch`
  naming the line, nothing cut, every marker standing) and, past the cut, the whole mirror;
  the tail stages check the whole current mirror against the chain as it stands. And every
  read of the repair family — `torn_tail`, `check_prefix`, `check`, the cuts, the
  regeneration — checks the stored acks' anchors against the chain that would REMAIN: an
  entry an authenticated ack of this node names is never cut as a torn append (an ack is
  stored only after its entry's append returned durable), so a tear inside one is
  `ledger.head.mismatch` at every reader, the verify verb included, and the repair refuses
  with nothing written; the operator restores `state/ledger.jsonl` from the mirror or a
  backup. A resume fsyncs the marker
  it found before anything it authorizes is cut (the marker may be visible and unsynced), and
  an audit entry found in the ledger is trusted — barriered (it may be an unsynced tail) and
  promoted to `audited` — only after the ledger's full check with its anchors
  (`Node.check_ledger`, the same check the append it replaces would run: an anchored
  completion edited into this intent's audit record is `ledger.head.mismatch` with the
  marker at its step and nothing regenerated over it), for every store. While an intent stands at step `intent`, every writer of
  that store — a peer revocation, `natively revoke`, a held replay, `natively deny` — refuses
  (`<store>.repair_pending`, a storage failure: the mail stays unseen, the startup sweep
  writes the replay marker) so nothing lands past the cut point — and the refusal holds at
  EVERY step the marker shows (a later step may be visible and unsynced) until the
  marker's deletion, the machine's last step; the ledger's own appends refuse the same way
  while `ledger-repair-pending.json` stands, so no mirror line lands past the cut;
  `natively ledger repair` fsyncs the JSONL before the mirror is cut. A repair that finds its file already clean
  fsyncs it again before it returns 0 rather than reporting success on visible bytes. A
  standing intent names the file it cuts and only that stage resumes; EVERY run validates
  the store it stands on BEFORE it touches the file or the marker — a fresh run before its
  intent is written, a resumed step before any cut, marker advance or marker removal — the
  JSONL's chain and framing for the ledger (the whole JSONL under a mirror intent, the part
  before the cut point under a tail intent) with the CURRENT mirror against the chain that
  remains (a retained prose line replaced, or a blank line hidden after an undecodable one,
  refuses by name with no marker written and nothing cut), the sound part before the cut
  point for the feed and the denial store — so a store found damaged leaves the file and
  the marker exactly as found, refused by that fault's name, the intent (where one stands)
  standing for a run after the store is restored; under a standing mirror intent the
  intent's OWN retained prefix is checked before the subordinate tail stage terminates,
  cuts or appends anything (a lost prefix is `ledger.prose.mismatch`, never regenerated by
  a stage the intent did not validate); `terminate_tail` anchors the chain the newline
  would complete before writing it — and, on the verb's fresh run and under a standing
  mirror intent, checks the CURRENT mirror against that completed chain first, so a mirror
  damaged past a valid retained prefix is `ledger.prose.mismatch` with the JSONL
  byte-identical, never a newline written and then the mirror refused — and an empty chain
  before a torn tail anchors nothing
  (`ledger.head.mismatch` at every reader, never `ledger.truncated`);
  at step `audited` — the step that removes the marker — the audit the marker recorded is
  identified FIRST, read-only (on record under its intent id, hashing to what the marker
  recorded, for the ledger's own intents the last entry — a rule the lookup every found
  audit crosses applies itself, and the binding of a visible audit at step "truncated"
  applies to the chain as the file stands — every entry there under the intent's id bound
  by action and hash before its displacement is judged, and a torn tail past an audit that
  landed whole refused, before the subordinate tail stage cuts or appends — so a found
  audit with an entry after it refuses
  before the mirror path's termination newline, before every mend, before the barrier and
  before the marker is promoted, the marker still at "truncated" and both files
  byte-identical on every retry), before any prose is mended from
  the entries, so nothing is regenerated from an audit the marker rejects; then the
  validation is the COMPLETE
  store (the feed or the denial store in full, the JSONL's chain in full) and the ledger
  in full holding the audit entry the marker recorded (its intent id and its hash; for
  the ledger's own intents the LAST entry, since the guard admits no other append while
  the marker stands) — a torn audit suffix (`ledger.truncated`), a store torn past its
  cut point (`<store>.torn`), a lost or displaced audit (`<store>.repair.intent_mismatch`)
  each keep the marker with the file exactly as found; a JSONL-tail stage resumed at step
  `truncated` first mends its OWN audit append's interrupted writes (the audit entry short
  of only its newline terminated, a torn partial audit line cut again, a regenerated or
  audit prose line torn inside a multibyte character cut back to the sound lines, one torn
  after an ASCII prefix — a decodable partial line that is a strict prefix of its entry's
  regenerated line, the lines before it validated — regenerated to that line, `Ledger.mend_torn_prose_tail`;
  an unterminated line that is not such a prefix is `ledger.prose.mismatch` with the
  marker standing and nothing written; and the whole proposed cut of an undecodable
  mirror tail is checked before any mutation — a blank physical line anywhere in it is
  `ledger.repair.refused`, the mirror untouched) so the audit can land; the ledger's JSONL-tail stage runs
  under `ledger-repair-pending.json` on its own and under the nested
  `ledger-repair-pending.tail.json` beneath a standing mirror intent (the mirror's excess
  is then the mirror intent's to cut; the ledger's guard refuses every append while either
  marker stands; the nested marker found without its mirror intent is
  `ledger.repair.intent_mismatch`);
  a store SHORTER than the intent's cut point at any step (records lost since the
  intent) is refused the same way, never taken for "already cut";
- the ledger: the JSONL line (file, then directory), then the prose line (file, then
  directory). The JSONL is the source of truth and its barrier precedes every mirror write:
  `ledger repair`, a trailing gap regenerated before an append, and a terminating newline
  fsync the JSONL (file, then directory) BEFORE they touch the mirror, and a barrier that
  raises leaves the mirror untouched — so a prose line never outlives the entry it
  mirrors. A mirror that nevertheless has more lines than the JSONL has entries (a line an
  older tool wrote for an unsynced entry, then the power cut) is refused by `ledger verify`
  and by every append; `ledger repair` truncates it to the JSONL's length (the machine
  above) and ledgers `ledger.mirror_truncated` — entries are never invented from prose; a
  mirror that does not decode (`ledger.mirror_corrupt`, the path and the byte offset) is
  cut back to its sound lines by the same machine and the lines cut regenerated, when the
  JSONL verifies;
- the executor: the temp file fsynced, the descriptor-relative rename, the directory fsynced,
  the descriptor closed; everything after the rename is committed state.

The residual: a power cut INSIDE one of those sequences — after the bytes are visible, before
the barrier returned — leaves the next start one of three states, and it need not be the
detectable one:

- **a valid older state.** The rename (or the append) never reached the platter: the file is
  whole and simply older. A state file is its previous version — a reservation instead of
  the ack that replaced it: when the ledger's completion entry survived (it was durable
  before the ack was stored), the re-delivery rebuilds its ORIGINAL outcome from that entry
  and stores the ack again; `failed:interrupted` applies only when no completion entry exists.
  The use stays consumed when its outcome consumed one — `applied`, `failed:post_commit`,
  `failed:interrupted` — and a surviving `refused` or ordinary `failed` completion consumed
  none (the rebuilt ack says which); an older seen file (the mail is read again; the
  node's `seen.json` answers it with the stored ack), an older cursor (the window starts
  earlier), a missing held reply whose mail is therefore still unseen (held again on the
  re-read); an aside copy whose quarantine audit never landed (the next poll writes it,
  once), a `.reconstructed` mark that never landed (the repair verb finds its audit — after
  the ledger barrier — and marks again), a discard record whose removal never landed (the
  discard verb finishes it from the record; the poll only counts it). Nothing a peer
  observed outran this: every promotion — the seen mark, the cursor, trust, a deleted held
  copy, a resolved mark — waits for the barrier of what it stands on;
- **a removed unsynced tail.** An appended line (a feed entry, a denial, a ledger completion)
  is gone with no torn framing left behind. The feed simply lacks the entry: its mail was not
  marked seen (the mark waits for the append's barrier), so it is read and appended again.
  A denial is issued locally (`natively deny`) and has no incoming wire kind, so there is no
  mail replay for it: a denial whose append never became durable was never reported
  recorded (the report follows the barrier), and the principal issues it again; it reaches
  another node only through that principal's own signed feed. The ledger lacks a
  completion: its reservation is still in `seen.json` (a rebuilt ack is stored only after
  the ledger barrier, so the reservation is never released on an unsynced completion) and
  the re-delivery is `failed:interrupted`; the mirror lacks the line too (every mirror write
  waits for the JSONL's barrier); a replayed held revocation is still held (its file is
  deleted only after ITS append returned) and is replayed again; an aside copy's lost
  `pending_reply.corrupt` is written again by the next poll, a lost
  `pending_reply.reconstructed` by the repair verb run again (the hold it stands on was
  durable first: the same bytes land under the same name), a lost `pending_reply.discarded`
  means the discard never happened (nothing was removed before the record was durable) and
  the operator issues it again; a lost `pending_reply.invalid` is written again by the next
  poll's re-read of the unseen mail (the reply is refused at the hold again);
- **a torn tail.** A partial final line without its newline: the feed and the denial store
  raise `IntegrityError` on every read and refuse every write until `natively feed repair` /
  `natively denial repair` truncates it under the lock (the intent durable first, the
  `<store>.repaired` entry after, the held revocations replayed and the replay marker
  removed before the lock is released); a partial ledger line refuses to load until the
  file is restored; a prose mirror short of its final newline is terminated by `ledger
  repair` or the next append when the line is its entry's. A complete final object short of
  only its newline (the feed, the denial store) is accepted and gets its newline back on
  the next append.

A state where trust was published before a held revocation replayed is repaired by the
startup sweep; a sweep that cannot replay (the feed is torn, the held directory cannot be
enumerated or read, a replay write fails, or the ledger fails its full check — run BEFORE
the first feed line lands, as before every enforcing record the package writes, so a
damaged ledger leaves the feed untouched and is named in the marker) leaves
`state/replay-pending.json`, and nothing is authorized until the enumeration and every
replay ran (the node still constructs over a damaged ledger, since `natively ledger
repair` needs a constructed node). A real power cut is not
something the suite can stage. The gate test modules classify their tests in their
docstrings, and the four kinds are different claims: ORDERING tests record every
fsync and assert which file was synced before which; FAILURE-BEFORE tests replace one
persistence step with an immediate exception (nothing became visible) and assert the
retry; FAILURE-AFTER tests let the syscall's effect become visible and fail its barrier,
then retry or restart (dropping the unsynced tail where the shape calls for it); RESTART
RECOVERY tests start a NEW instance (a fresh Node, a fresh feed handle, a CLI process) over
the state directory the last one left, the old instance discarded. Not every test is of the
third kind; each says which it is, and a test on a hand-staged file with no failure injected
and no second instance is labelled a framing test, not a recovery.

### The constraint language

A `regex` constraint in a grant is a sentence of a SMALL LANGUAGE of the package's own, read
by a complete recursive-descent parser (`grant.emit_pattern`), never by a scanner over an
engine's grammar: five reviews in a row defeated the scanner (verbose mode and comments,
branch reset, conditionals, the fuzzy brace, a brace after a plain escape, global flags,
POSIX classes, the `\p` `\P` `\N` brace argument, the `[. .]` and `[= =]` class forms), and a
whitelist over a grammar the scanner does not own loses again. The parser accepts exactly the
grammar below and refuses everything else BY NAME at the offending position
(`grant.constraint.pattern`, "position N: why") at issue (`natively grant --param
k=regex:…`, exit 1, nothing stored), at receive (`verify_failed:grant.constraint.pattern`,
nothing stored, no compile) and at load (`state.corrupt` naming the file). What compiles is
the parser's own canonical re-emission (every literal through `re.escape`; a class's items
SORTED by their low end and merged — overlapping and adjacent items become one span — so the
emission is one form whatever order the items were written in: `[ba]`, `[ab]` and `[a-ab]`
all emit `[a-b]`), compiled after the signatures verify (the document check's order:
structure, signatures, compile) by ONE engine, the `regex` package, which also runs the match
at use with its timeout (`scope.regex_timeout` after 2 s, a refusal, never a hang). The raw
pattern text never reaches an engine. The engine is `regex` for the compile too (ratified,
round 21, D1), not the stdlib `re`, because `re` walks every code point of a non-ASCII range
when it compiles a class — about 0.1 s for `[\u0100-\uffff]`, 3 s for sixty-four such classes
in one pattern — while `regex` compiles every accepted shape in microseconds; nothing
pathological reaches an engine because the parser refuses it first (a refused pattern never
compiles; an accepted one is a few tens of KB in the engine's cache, which is capped at 500
entries).

| Construct | Written as | Notes |
|---|---|---|
| alternation | `a\|b` | at any level; a branch may be empty (ratified, round 21, D4) |
| group | `( … )` | plain groups only, and a group may be empty; never quantified; nested at most 32 deep |
| literal | any character but `\ ( ) [ ] { } \| ^ $ * + ? .` | a newline is written as itself (there is no `\n` escape); non-ASCII as itself |
| escaped punctuation | `\. \* \+ \? \( \) \[ \] \{ \} \| \^ \$ \\ \- \/` | the literal character |
| shorthand class | `\d \D \w \W \s \S` | ASCII by definition, emitted as explicit classes (`[0-9]`, `[0-9A-Za-z_]`, tab / newline / VT / FF / CR / space, and their negations), one meaning in every engine — as Unicode shorthands the stdlib `re` and `regex` disagreed (U+0301 under `\w`, U+001C under `\S`) |
| any character | `.` | a newline included (DOTALL) |
| bracket class | `[…]`, `[^…]` | literal characters, ranges `x-y` in order, the escapes `\] \\ \^ \-`; a `-` or `^` anywhere else must be escaped; `{` `}` are literals inside; no nested or POSIX class, no other escape; at most 256 items (an item is a literal, an escape or a range: a CJK range is one item), refused by name at the offending item; the emission is the items sorted and merged (overlapping and adjacent items one span) |
| anchors | `^` `$` | never quantified |
| quantifiers | `*` `+` `?` | on ONE atom only (a literal, an escape, `.`, a class): never on a group or an anchor, never stacked (`*?` `*+` `**` are refused) |
| bounds | | at most 1024 characters, 64 atoms, 32 nested groups, 256 items per class — each the parser's own refusal by name and position |

Outside the language, refused by name: counted quantifiers `{n}` `{n,m}` and any bare brace;
lazy and possessive modifiers; every `(?` form (non-capturing, named in either spelling,
lookaround, atomic, flags, conditional, comment, branch reset, recursion, subroutine, fuzzy);
backreferences; POSIX classes; property and named escapes `\p` `\P` `\N`; `\x` `\u` `\U`
and every other escape (`\n` `\t` `\b` `\A` …); an escape inside a class beyond the four.

Cost. The parse is LINEARITHMIC in the pattern: one pass over its characters, and a class's
items sorted then merged in one pass (`grant.merge_spans`; at most 256 items, so the sort is
bounded too — round 21: before, each class item was checked against every earlier one, a
quadratic scan that a legal 1,022-singleton class made cost 90 ms before the signature check).
A quantifier applies to a single atom and a group is never quantified, so no emission carries
a nested or a counted repetition: the cost at RECEIVE and at LOAD — the surface the round-19
reviews measured at 0.4 to 0.9 s and 1.4 to 2.1 GB per sub-kilobyte signed pattern, retained
by the engine's cache at 0.73 GB each — is that parse plus ONE compile per document check of
at most 64 atoms, milliseconds and kilobytes, and a refused pattern never compiles at all, so
the cache holds nothing for it. The match at USE is bounded by the TIMEOUT, not by any claim
about the search (round 21, D2): a fixed pattern without nested repetition backtracks
polynomially in the value, but the pattern is the issuer's variable, alternation alone is
exponentially ambiguous (`(a|aa)` twenty-one times on a^40), and no bound on unbounded
quantifiers would make the stdlib engine viable either — the gate showed `a?` thirty-one times
followed by `a` thirty-one times still running in it after 0.5 s — so the `regex` timeout is
the operational bound: twenty `(\w*|\s*)` groups before `[bc]$` (44 atoms) on a 32-byte value
that ends in neither branch are refused `scope.regex_timeout` after 2 s (test_hardening pins
the shape), and a message costs at most one timeout. Tests pin the WORK, not a clock: the
merge's interval comparisons are counted and asserted under n·(log2 n + 1) for 256 items in
any order, every shape of the grammar table and the wide-class shapes (sixty-four BMP or
astral ranges in one pattern, sixty-four wide disjoint items in one class, 256 overlapping
ranges) compile cold and fullmatch 16 KB within a few MB, and ONE wall-clock smoke test pins
the maximum-singleton class, the maximum-range class and the table at a generous 250 ms cold;
a seeded fuzz of 60,000 random patterns uses the `regex` module's own parser as the ORACLE
(test suite only, never production): every pattern the language accepts is one the engine
reads with no counted and no nested repetition, its emission compiles in both engines, and the
parser raises nothing but its named refusal.

Migration. A grant on file whose pattern the parser refuses is `state.corrupt` at load
naming the file and `grant.constraint.pattern` (fail closed: re-issue it in the language); a
received one refuses by name. The old scanner (`pattern_problem` over the engine's grammar,
`MAX_QUANTIFIER`, `_GROUP_RE`) is removed, not kept beside. Shapes the scanner admitted that
the language refuses, with the spelling in the language where one exists: counted repeats up
to 256 (`\d{1,256}`, `a{2}`: `\d+`, `aa`); `(?:…)`, `(?<n>…)`, `(?P<n>…)` (a plain group);
`(?i)`, `(?-i:…)`, `(?>…)`, the lookarounds, `(?#…)` (none); lazy `a+?` and possessive
`a{2}+` (`a+`, `aa`); `\p{L}`, `\P{L}`, `\N{…}` (a class of the characters meant); `\x41`
(the character itself); POSIX `[[:alpha:]]` (`[A-Za-z]`); `\[` inside a class (`\[` outside
one); `\n` (a newline written as itself); a bare `-` at the end of a class (`\-`).

## Extensions (citadel, design-thread reply 3), default OFF

`natively config --set extensions.max_uses_per_window=true` lets grants carry
`"max_uses_per_window": {"n": N, "window_s": S}` beside `max_uses`. A node with
the flag off REFUSES such a grant (`grant.extension.disabled`) rather than
ignoring the constraint. `natively config --set extensions.standing_denial=true`
turns on `natively deny` and the pre-scope check. A standing denial is the enforcing
record: `natively deny` appends it durably (the line, the file, then the directory) BEFORE
the ledger entry and the report, so a denial that was reported recorded survives power
loss. The store has the feed's framing discipline (`natively denial verify` / `denial
repair`; a torn tail is local corruption, and the pre-scope check on a corrupt store is a
storage failure that leaves the mail unseen, never a `verify_failed:malformed`). With both
off the wire is v0.2-conformant. The flags are read from `config.json` at every
authorization, so a running `natively run` honours a flag set from another process at its
next action. `natively config --set` validates every value through the typed loader before
it writes (the known keys only, an extension flag one of the two, `poll_s` within 5..86400,
`self_email` / `peer_email` addresses, a non-empty `subject`, every peer address an address
— a refusal is exit 1 with nothing written), takes the state lock without constructing a
node, and writes the COMPLETE valid config from the loadable parts and the defaults, so a
hand-corrupted config that locks every other verb out (`state.corrupt`) is repaired by one
`--set`; a bare `config` over such a file prints what it could read and exits 2.

## Retry timers (poll transport)

P = `poll_s` (60). A sent message with no ack is re-sent at 2P, again at 4P after
that, again at 8P after that (three re-sends), then ledgered `undelivered` when the
next deadline, 16P after the third re-send, passes — one audit per transition: the
`out.send` / `undelivered` line is looked up by its key (the msg_id and the attempt count
it names), after the ledger's full check and before it is appended, so a retry after an
outbox write that failed with the audit already on the ledger appends nothing — and runs
the ledger barrier over the audit it found (visible bytes whose append may have failed
before its fsync or its prose line) before the terminal status is written; the audit
lands before the status, so a terminal status never stands on disk without its record. A
re-send keeps the outbox entry
and its attempt count; only a first send records one. A peer's ack is ledgered BEFORE the
outbox entry is marked acked and the peer head written (the `out.ack` line names the
entry's state as it stands), so a failed append leaves the entry pending with no record
and the retry records it once — the order the undelivered transition keeps. A send tool
that times out or fails to launch is one line and exit 1 for `send`, `send --dry-run`,
`send --card` and `revoke` alike (delivery unknown — the mailbox may have taken the message before
the tool stopped answering, so the line says to check the Sent mailbox before sending again;
nothing recorded; a revocation's feed
line lands first, as before). `send --out FILE` records the
message as `exported` (delivered by hand) and the poll never re-sends it. Acks are
never retried; a peer that missed one re-sends the message and gets the stored ack.

A poll pass runs in this order: the acks held from the last poll (whose send failed)
go out first, before anything is fetched; then the fetch; then, within the batch,
bundles are applied in kind order — cards and revocations first, THEN (only after a
COMPLETE fetch whose control writes all landed) the revocation-lookup clock is
refreshed, THEN acks and messages, THEN the outbox (due re-sends, undelivered; it runs
even when the fetch failed, since a re-send does not depend on it), and LAST (only once
every write the pass needed has landed and no storage failure was counted, the outbox
bookkeeping included) the catch-up cursor advanced — so a revocation on the wire lands
before the action it revokes, a node's first (or first after an outage) complete poll
authorizes the actions it carried instead of refusing them as stale, and a mail a
storage failure left unseen stays inside the next window. If the
control phase did NOT land (a storage failure on a card or a revocation), the poll applies
NO ack and NO message this pass — an action whose revocation could not be recorded must
not be judged against a clock that still reads fresh — their mails stay unseen, the clock
and the cursor stay, the outbox still runs, and the summary says why (`deferred`). A fetch
is complete when every search page was fetched, every thread chunk answered, and no peer
mail was truncated; a failed or incomplete fetch leaves the clock and the cursor alone,
and `poll --file` never touches them. So a node cut off from the wire stops executing
state-changing grants after `max_check_interval_s + P`.

Every poll asserts the MAILBOX first (round 21, Z2): `gmail-api.py profile --json` (the
address the credentials are signed into, `users.getProfile`; the account is config
`mail_account`, `afik` or `taylor`, never assumed) must equal `self_email`, else the fetch
fails by name (`mailbox mismatch`) before any search, and nothing is applied, seen, or moved.

The search is paged: `gmail-api.py search --max 200 --ids-only` prints the thread ids (no
per-thread metadata request) and a `next-page-token T` line when more results exist, and
the adapter passes it back as `--page-token` until the last page; every line is read
STRICTLY (`thread <id>` with the id under the identifier rule `[A-Za-z0-9][A-Za-z0-9_-]{0,63}`
— an argv-safe token, since ids are handed to the helper as arguments — or `next-page-token
<token>`; anything else refuses the page as a wire failure; round 21, Z1). The window is
walked in TIME SLICES, oldest first (round 21, Z3): the first slice is the whole window; a
slice that lists 2,000 threads with more to come (`page cap`) has those threads READ (their
mail applies) and is then HALVED — the same start, half the span — until a slice fits or the
span reaches a minute; a minute that still holds over 2,000 threads is a flood, reported by
name (`slice overflow`) and never walked; a slice whose every thread was read is scanned
through, and the next slice doubles the span. Every pass is bounded whatever the pages
contain: at most 40 search calls per pass, 256 MiB of helper output per pass, and a page whose
token repeats one already seen in the slice, or two consecutive pages that add no id new to
the slice, end the pass (`nonprogressing pagination`, transient) — the state lock is never
held by a loop that makes no progress. A pass that ends on a budget or a flood with nothing
transient in it and every listed mail applied or marked seen RECORDS its progress durably
in `state/wire-scan.json` when a slice completed OR the halving narrowed the span (the
position scanned through — unchanged when only the span narrowed — and the span in force),
and the next poll continues from there instead of starting the window over, so a dense
window is narrowed a little further on every poll; a record whose position is past the
clock is ignored (the window is scanned; the pass overwrites or removes it); a pass that
scans through the open-ended last slice is COMPLETE and the record goes. Every helper
call's output, failed and oversized answers included, is charged to the pass's byte budget,
and the call that crosses it is the pass's last. A search page's every physical line is
one of the two forms; a blank line refuses the page. Freshness is refreshed only by a complete scan. The bodies are read with
`thread --json --max-rows 32` in chunks of 50 ids, each its own subprocess with its own
120-s timeout and its output BOUNDED before it is read (the cap follows from the row bound
and the largest row; the runner never reads past it, and the helper reads no API response
past 64 MiB; round 21, Z5); EVERY row is validated as a whole before any is used (the ids
under the rule, every field of its type, the flags consistent) and a response with one bad
row is refused whole — never consumed as an empty message, never a seen mark (Z1). The mails
of the chunks that answered are applied and marked seen one by one; a chunk that failed or
timed out makes the fetch incomplete (`chunk N failed`, reported, transient: nothing recorded
past it), the cursor and the clock stay, and the next poll asks again and applies only what
is still unseen. A chunk the helper refuses as oversized (rows over `--max-rows`, or output
over the cap) is halved down to one thread, and a single thread still over the bound is a
TERMINAL rejection: ledgered once (`wire.thread_oversize`), `thread:<id>` in the seen file,
never asked for again. A peer row the helper CUT at `--chars` (`truncated`, with
`body_chars` the body's length before the cut) is judged by the decoder's own rules
(`cut_verdict`): a prefix that holds a whole wire body (the decoder tolerates trailing
quoted text) or no wire body at all takes the normal path; base64 already past the wire's
base64 bound before the cut is demonstrably no bundle this node could accept — rejected
ONCE by name (the ledger's `wire.oversize` row, outcome `verify_failed:wire.size`, appended
idempotently by its `[gmail <id>]` token; the seen note `oversized:<chars>`), never judged
or re-fetched again (round 21, Z4); base64 that runs to the cut still under the bound (a
rewrapping that inflated the text) is transient, like a row whose body the helper could
not OBTAIN (`body_unavailable`): reported, not seen, the fetch incomplete.

The search window is anchored to a durable boundary: `state/wire-cursor.json` holds
the time of the last COMPLETE fetch, and the query is `after:` that time minus one day
(never later than two days ago; two days back when no cursor exists yet) — or the standing
scan record's position when that is later. An outage of any length is therefore re-read
from before it began, and a revocation posted during it cannot fall outside the window.
The feed append is fsynced (file, then directory) before it returns, and the cursor moves
only after every such write returned, so the cursor can never outlive a revocation it
acknowledges.

A revocation whose principal is not pinned yet is not dropped, and it is not trusted
blindly either: unpinned means untrusted, not unverifiable, so its structure and
signature are checked against the principal key it names right away (a failure is
ledgered `verify_failed:revocation.sig.invalid` and nothing is written). What verifies is
kept under `state/revocations-pending/<rev_id>-<12 hex of the body hash>.json` — one
file per body, never overwritten, so a later variant can never displace an earlier
original (its mail is marked seen like any other) — ledgered
`revocation.received -> unpinned`, and replayed, ledgered `revocation.replayed`, in two
places: `natively pin` replays every candidate for that principal FIRST and writes
`pinned.json` only after the feed append returned (a crash in between leaves the
principal unpinned, so nothing it revoked can be authorized), and every node start
sweeps the held revocations of principals that are already pinned — under the lock,
before anything else can authorize — so a state where trust was published first is
repaired before it can be used. A held copy is deleted only after ITS OWN feed append
returned, candidate by candidate, never all at once.

The feed's identity is the exact authenticated triple (principal key, rev_id, canonical
body hash). The same body again is a `duplicate` — and not a short-circuit: the file and
the directory are fsynced again before it is answered, so a retry after a barrier that
failed once the bytes were visible stands on synced bytes. A second signed body under the
same (principal, rev_id) with a different body is recorded as its own entry, ledgered
`recorded:variant` (revocations only ever add coverage: both are honoured, the union is
revoked). Different principals never collide. The file's framing is validated on every
load: a line that does not parse, or a final line without its newline that does not parse
(a torn tail), is an `IntegrityError` — local corruption, a storage failure, never
malformed peer input (a peer revocation arriving meanwhile stays unseen) — and every feed
write refuses until `natively feed repair` (under the lock) truncates the torn partial
line, only when every preceding line parses, and ledgers `feed.repaired` with the byte
count (the intent is written durably before the truncation, so a crash between the
truncation and its ledger entry still yields the audit on retry); then, still under the
lock, it replays every held revocation of every pinned principal and removes
`state/replay-pending.json` — a node that started on the torn feed could not run its
sweep, wrote that marker, and authorizes nothing until the replay ran (it attempts the
replay itself before every action; a replay that fails there is a storage failure — the
mail unseen, nothing ledgered or acked, never a refusal the peer keeps), so a feed
repaired by another process never reopens authorization on the
truncation alone. `natively feed verify` reports the framing. A complete final object
short of only its newline is accepted (verified as a document like any other line, and
one that fails is `feed.corrupt`, kept — only a line that is not a whole object is a
torn tail the repair may cut), and the newline is put back on the next append.

The mail helper is asked for `--chars` sized to the largest WRAPPED wire body (header line
plus base64 at 76 columns, 708,266 characters, plus a margin), and `gmail-api.py thread
--json` reports `"truncated": true` on any row it cut. A text part Gmail serves through
`body.attachmentId` (no inline data) is fetched by the helper for the `--json` rows
(`messages.attachments.get`); a body it cannot obtain (a fetch error, an attachment
without data, data that does not decode; since round 14 also a text part with neither data
nor an attachment id unless it declares size 0, inline or fetched bytes that are not the size
the part declares, a multipart part with no children, and a part at any depth whose
mimeType is not a NON-EMPTY string — missing, null, not a string, or `""`, which is never
"not a text part"; the WHOLE part tree is checked before a body is selected from it, so
the parts after the first text found are checked too, and the reason names the part (the
root as the payload part) — the body must be DEMONSTRABLY present or
demonstrably empty before a row is
complete) is reported as an INCOMPLETE FETCH — `truncated`
true, `body` empty, `body_unavailable` naming why — never the snippet in the body field
(the snippet rides its own field; the plain-text output never fetches and is unchanged).
An unavailable peer body is a fetch error: reported, counted in the poll summary's
`errors`, NOT marked seen (it is read again next poll; nothing is ledgered for it), and
the fetch counts as incomplete — the clock and the cursor stay. A body the helper CUT at
`--chars` is judged by the decoder's own acceptance rules (round 21, Z4; `cut_verdict`):
a prefix holding a whole wire body, or no wire body at all, goes down the normal path;
base64 already past the wire's bound before the cut is a TERMINAL rejection (see
"Retry timers"); base64 that runs to the cut still under the bound is transient like an
unavailable body.

A send failure never ends the poll: every send and re-send is caught, reported, and
counted in `errors`, and the pass goes on. A re-send counts as an attempt (and moves the
deadline) only once the transmission succeeded, so a transport outage spends none of the
schedule. Every ack is held under `state/pending-replies/` BEFORE its mail is marked seen,
sent after the mark, and its held copy deleted only after the send returned; one whose
send failed simply stays held and goes out at the very start of the next poll, before the
fetch (acks are still never on the retry schedule; a never-sent ack is not lost, a seen
mark that became visible while its barrier failed loses nothing either, and a stalled fetch
holds neither up). A hold that fails leaves its mail unseen (read and answered again next
poll) and the poll never reports complete. `natively run` therefore keeps looping through
transport errors and prints the count on every pass; a poll summary also carries
`storage_failures`, every local read or write that failed in the pass (the outbox
bookkeeping included: the outbox step runs before the completeness decision), `fetch_failures`,
the wire and subprocess failures (the fetch itself, a thread chunk), and `deferred`, the
ack and message mails left unseen because the control phase did not land. EVERY read and
write of the adapter's own state — the seen file (its initial read included), the cursor
(its read before the fetch included: the poller cannot know where to start without it, so
a failure there skips the fetch half and the outbox still runs; a cursor or a freshness
sidecar with the wrong shape or an unparseable timestamp is `IntegrityError` too), the
freshness sidecar, a
held reply (written and read back; the listing of `pending-replies/` too), the ledger line
for an undecodable mail, the outbox listing and its per-entry bookkeeping — is inside the
same storage boundary as the node's: an `OSError`, or a file of ours that does not parse
(`IntegrityError`), is reported and counted, the mail concerned stays unseen, and the poll
goes on (one outbox entry's failure never stops the others; a seen file that cannot be read
ends the fetch-and-apply half of that poll and the outbox step still runs). A poll reports
`complete` — and the cursor moves — only when the fetch was complete AND no storage
failure was counted anywhere in the pass, the flush of held replies included.

## Spec ambiguities and the choice made

- **Where grants travel.** The spec names `grant_ids` only. Choice: the bundle carries the grants
  (and the sender's card) beside the message; the node also keeps every grant it has seen under `state/grants/`.
- **Card signatures.** "Vouched for by its node" + "signed by the principal": two signatures,
  `node_sig` first (over the card minus both), then `sig` (over everything incl. `node_sig`). The hash
  excludes `sig` only, per the bead.
- **Pinned roots.** A card's principal must be pinned explicitly (`natively pin`) before anything from
  that agent is trusted; nothing is TOFU. Our own principal is pinned when the card is made.
- **Who issues cross-deployment grants.** The executor accepts grants from any pinned principal, so
  citadel's stand-in principal can grant Instinct's agent a write on Instinct's node once Instinct pins it
  (and vice versa). The subject is always the executing agent; a grant whose subject is another agent is
  refused (`no_authorizing_grant`, reason `grant.subject.agent`) and ledgered.
- **Delegated grant issuer.** `issuer: {"agent": <parent subject card hash>, "key": <its agent key>}`,
  signed by that agent; `audience` equal to the parent's; expiry/not_before/max_uses within the parent's;
  the child inherits the parent's `max_uses_per_window` (n no larger, window no shorter) and may not
  raise `max_check_interval_s` above the parent's; scope a strict subset (canonically unequal; a child
  that forbids a parameter the parent constrained is tighter, so the parent's constraint on a key the
  child's `keys` omits is not required). Depth one enforced (`parent.parent_grant` must be null). The
  parent's budget is spent by its direct uses plus every child's; the embedded parent must equal the
  parent on file (`grants/` or `grants-embedded/`); a parent first met inside a child is cached under
  `grants-embedded/` and is never executable there — it becomes executable only by arriving top-level;
  the delegator's card must be on file here and is checked for revocation by its own principal.
- **Ack signer.** An ack is accepted only from the agent the message was sent to; a third trusted agent
  acking someone else's message is `verify_failed:ack.signer` and changes nothing.
- **max_check_interval_s** on issued grants = 5 × poll_s (300 s); grace = one poll. Two clocks
  judge the freshness sidecar and the stricter refuses: the wall clock (a sidecar timestamp in the
  FUTURE of the clock — a clock stepped back — is `revocation.stale` naming it until the next
  complete poll rewrites the sidecar) and, within a process, the monotonic clock since the sidecar's
  value was written or first read there (round-19 gate, finding 6).
- **offline_ok** accepted only on `info` scopes (spec: never on scopes that change state).
- **Ledger scope.** Entries also record information received, cards, revocations, acks, and every
  verification failure (principle 5). Heads are exchanged in acks and stored under `state/peer-heads.json`.
- **Unknown fields fail closed** on every object (a constraint we do not understand is never ignored).

## First live exchange with Instinct

One-time on citadel (done 9/7; keys under `~/.config/citadel-mayor/natively/`, mode 0600):

```
bin/natively keygen                 # refuses a keys dir inside the package, state, or scratch dirs
bin/natively card --agent-name citadel-mayor --node-name citadel --principal-name "Taylor Hou (citadel stand-in)"
bin/natively card --show            # our card JSON + hash; safe to share, no secrets in it
bin/natively config --set peer_addresses=taylor@teale.com,taylor@hou.vc   # the addresses Instinct writes from (default)
```

Instinct sends first: their **card** on the wire (subject `Natively v0 wire`, body per
the format above). Then, in order:

```
bin/natively poll                                   # ingest their card -> cards-pending
bin/natively cards                                  # shows PENDING + the principal key to pin
bin/natively pin <their principal key> --name "instinct principal"   # after confirming the key out of band
bin/natively send --card                            # our card to them; they pin ours the same way
bin/natively send --to <their agent name> --info "hello from citadel over Natively v0"
bin/natively poll                                   # their ack lands; outbox -> acked; peer head recorded
bin/natively grant --to <their agent name> --action fs.write --file hello-from-citadel.txt \
    --statement "Write hello-from-citadel.txt into your scratch directory, once." \
    --param $'content=regex:^[ -~\n]+$'    # $'…' quoting: a literal newline in the class (the language has no \n escape and no counted repeat; the executor's 64 KB cap bounds the length)
bin/natively send --to <their agent name> --action fs.write --file hello-from-citadel.txt \
    --param 'content=hello, instinct' --grant <grt_id>
bin/natively poll                                   # ack applied + their ledger head
bin/natively ledger show --tail 10 ; bin/natively ledger verify   # (ledger repair: an unterminated JSONL tail — a whole entry terminated, a torn line cut and ledgered — a crash between the two ledger writes, a mirror longer than the JSONL, or a mirror torn inside a multibyte character — cut back, ledgered, regenerated; both take the state lock, safe beside `run`)
bin/natively feed verify                            # (feed repair: only after a torn feed tail — power loss inside an append; it replays held revocations too; both take the state lock)
bin/natively denial verify                          # (denial repair: the same for the standing-denial store)
bin/natively pending list                           # held replies and the corrupt copies moved aside; an unresolved copy freezes the cursor until `pending repair [NAME]` rebuilds it from a validated source (held, sent by the next poll) or `pending discard NAME [--with-held]` ledgers dropping it; `pending repair` exits 1 when any requested repair remains unsuccessful (a storage failure, an unresolvable or a refused copy), one line per failure
bin/natively run                                    # loop at 60 s while the exchange runs (ctrl-c to stop); ONE per state dir
```

Their grant to us arrives the same way: their principal (pinned here) issues a grant
whose subject is `citadel-mayor`, audience our node key, resource
`host:<our node key>:scratch/<name>`; our poll applies it and the file lands in
`scratch/`. `bin/natively send --dry-run …` exercises everything but the send (nothing
enters the outbox); `--out FILE` writes the wire body to a file (outbox `exported`, never
re-sent); with both, `--dry-run` wins: the file is written for inspection, nothing is
recorded, the CLI prints `DRY RUN`. `poll --file FILE` applies one without refreshing the
revocation clock.

## Rules

No key material in this directory or on the wire: the keys directory may not be
inside the package directory, the state directory, or the scratch directory
(symlinks resolved; checked on node start and on keygen). The executor writes only
under `scratch/`, and its root is kept apart from the state and the code: a scratch
directory equal to, inside or containing the state directory or the code directory
(`natively/natively/`), or equal to or containing the package directory, refuses on
node start and on keygen before any file is touched (`ValueError`, exit 1; inside the
package directory only the package's own `scratch/` is admitted) — whether it comes
from `--scratch`, `NATIVELY_SCRATCH` or the default. Every CLI value is validated
before any work and before any write, one exit code (1) naming the value (argparse's own
refusals — a non-integer count, an unknown verb — included; `--param` is parsed before the node
is built; `~` in a directory argument is expanded once, by the node, so the separation checks
judge the path the executor uses, and the separation checks compare filesystem identity —
device and inode of every existing ancestor — so a symlink or a case alias of the state
directory refuses like its own spelling, and below the deepest EXISTING ancestor every
remaining component folded by Unicode's canonical caseless match, `NFD(casefold(NFD(x)))`
(Unicode 15 §3.13 D145; round 21: the NFC-around-the-fold formula of round 20 left U+1FB7,
U+1FC7 and U+1FF7 distinct from their uppercase spellings U+0391/0397/03A9 U+0342 U+0345 where
APFS sees one name, and the executor's root became the state directory), so two absent names
that differ only by case or by Unicode normalization (`state` beside `STATE`, `état` in its
two normalizations, U+0390 beside U+0399 U+0308 U+0301, an alias one level down or up) are ONE
name to the checks on every filesystem — conservative by design, the operator picks distinct
names, and the message says so; round-19 gate R1. The fold sees only the case pairs the
interpreter's Unicode tables know (14.0 on this Python; this kernel folds pairs Unicode 15 and
16 added), so once BOTH directories exist the node compares the state directory and the
scratch root — and the code and package directories — by device and inode again
(`keys.check_scratch_identity`), before its lock file, its subdirectories or any state file
is written: two names for one directory refuse there with the empty directory all that
exists; round 21, BB2):
an id argument of the wrong form (`ack`, `send --grant`, `grant --parent`, `revoke`,
`pin`), `run --interval` outside 5..86400 (0 is never "use poll_s"), a negative
`ledger show --tail`, `grant --expires-in` or `--max-uses` below 1, a `--window` that does
not parse, a `--param range` without two finite bounds (`lo,hi`; an open end is refused by
name), and EVERY value of every verb judged before the node is constructed — its startup
sweep and its directory creation never run for a refused value (a test with the constructor
made to raise pins thirty-five shapes; round-19 gate R6, widened by the Fable read): a
card's three names, a grant's `--to`, `--action`, `--statement` (non-empty, at most 4000
characters), `--audience` (a key), `--resource` (non-empty, `host:`), `--file` (a name the
executor's own rule admits: one component of `[A-Za-z0-9._-]`, 1..64 characters, never `..`
— `../seen.json` and `a b` are refused at issue, and the same rule runs in
`grant.check_structure` at receive (`grant.resource.name`) and at load (`state.corrupt`), so
a signed grant on file never names a resource nothing can serve; Fable C2), `send`'s
`--to`/`--card`, `--info` (with no action, target, grant or `--param` beside it), `--action`
with its target and `--grant` (at most 16 ids, none twice), an explicit `--resource` of the
`host:…:scratch/<name>` form under the same name rule as `--file`, every `--param` as
`k=v` with its `@file` read there and the body's JSON byte length within the protocol's bound
(the bound `message.verify` applies to the decoded body; an option of another mode given beside
`--info` or `--card`, empty included, is refused rather than ignored — one applicability table
for every verb and mode, below), `--out` given and empty
refused (never the live wire) for `send`, `ack`, `revoke` and `poll`, every text value valid
UTF-8 (an argv byte that is not UTF-8 arrives surrogate-escaped and no document of ours can
carry it: refused by name, `is not valid UTF-8`, before the node; round 21, BB3),
`revoke`'s targets (at most 256, none twice), `poll --file` (given and empty is refused, never
a live poll), a `--param key=kind:value` with every delimiter present and a non-empty key, `deny`'s action, resource and statement, `revoke`'s
statement, `pin`'s name, `pending`'s NAME, `poll --file`. `natively card` validates the
complete card through its own loader before it replaces the self card (an empty agent name
is refused at the verb, and by the loader behind it, with the old card intact). `natively revoke` and `natively deny` are the principal's word: on
citadel that is the stand-in key, used only on Taylor's instruction.

Option applicability (round 21, BA3; `cli.OPTIONS` and `cli.MODES` are the table, and a test
derives one sentinel row per verb, mode and unread option from it). An option GIVEN — empty
included; a value option is given when present, a list when non-empty, a flag when set — that
the selected MODE never reads is refused by name before the node (`<mode> takes no <option>`),
never ignored; `--state ""`, `--keys ""` and `--scratch ""` are refused as given and empty,
never taken for the default directory. The modes that read fewer options than their verb
declares:

| verb | mode | reads | refuses when given |
|---|---|---|---|
| `card` | `--show` | `--show` | `--agent-name`, `--node-name`, `--principal-name`, `--principal-kind`, `--ledger-url` (the names default at the verb, not in the parser) |
| `card` | making the card | the five name options | `--show` selects the other mode |
| `grant` | a root grant | everything but `--parent` | — |
| `grant` | `--parent` | everything but `--audience` | `--audience` (a delegation carries its parent's) |
| `send` | `--card` | `--card`, `--dry-run`, `--out` | `--to`, `--info`, `--action`, `--file`, `--resource`, `--param`, `--grant`, `--in-reply-to` |
| `send` | `--info` | `--to`, `--info`, `--in-reply-to`, `--dry-run`, `--out` | `--action`, `--file`, `--resource`, `--param`, `--grant` |
| `send` | an action | everything but `--card` and `--info` | — |
| `poll` | `poll without --file` (a live poll) | nothing | `--out` (it was ignored and the poll ran live) |
| `poll` | `--file` | `--file`, `--out` | — |
| `ledger` | `show` | `--tail`, `--json` | — |
| `ledger` | `verify`, `repair` | nothing | `--tail`, `--json` |
| `pending` | `list` | nothing | `NAME`, `--with-held` |
| `pending` | `repair` | `NAME` | `--with-held` |
| `pending` | `discard` | `NAME`, `--with-held` | — |
| `revoke` | sending | everything but `--no-send` | — |
| `revoke` | `--no-send` | everything but `--out` | `--out` (nothing leaves the box, no file is written) |

Every other verb has one mode that reads every option it declares.

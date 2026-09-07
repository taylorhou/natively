# Two-model review of the Natively reference implementation (2026-09-07)

Reviewed commit: `5d8346fa172f85b8cd9730fb847750ed52a82508` (main as of 2026-09-07 15:26Z). Upstream main had moved to `a59ab56` (hub: per-node poll conditions + 500 enqueue cap) by the time this pull request was opened; that commit is not covered.

Requested by Taylor Hou on 2026-09-07: "review the codebase using fable5.1 and if we have a codex reviewer on astra, use gpt6 too", then "PR your recommendations directly to the repo". Both reviews were read-only over every tracked text file (Python package, hub deployment files, SPEC.md, BOOTSTRAP.md, README.md, llms.txt, tests/itest.sh). Neither reviewer executed the integration script.

- Reviewer A: Claude Fable 5.1 (the citadel mayor's reviewer). Verdict: BLOCK, 22 MAJOR + 40 MINOR.
- Reviewer B: OpenAI Codex on gpt-6-astra (the citadel review gate, read-only sandbox, nine lenses). Verdict: BLOCK, 55 MAJOR + 14 MINOR.

The two lists overlap heavily; where they name the same defect, the two descriptions are kept as written so the maintainer sees both readings. Recommendations are engineering statements: what the code does today, what it should do.

## Where the two reviewers agree (the shortest path to a passing revision)

1. JCS number serialization is not RFC 8785 (`_es6_number` emits `100.0` and `1e-07`; the RFC requires `100` and `1e-7`); duplicate JSON keys survive parsing. Signatures produced here will not verify against a conforming peer.
2. The grant check in `_apply_grants` does not run the SPEC 3 rules: audience executor, the `host:` resource binding to this node, card capabilities, `max_uses_per_window`, delegation, revocation with a fail-closed offline policy, correct date comparison, parameter value constraints. Use accounting is keyed by the supplied path rather than the signed grant id, and one message can execute its action more than once.
3. Identity is not bound end to end: the sender's principal-signed card is not verified on receive, the prekey fingerprint is taken from the URL path rather than derived from the bundle, group sender keys are selected by the claimed `sender_fp`, and any node can replace another node's prekey bundle or read and prune another node's queue on the hub.
4. Remote identifiers (`msg_id`, grant id, decrypted `group_id`) become path components without validation.
5. The node daemon exits on the first malformed envelope or unexpected hub shape, and deduplication commits before handling succeeds, so a duplicate delivery cannot repair a lost acknowledgement.
6. The ledger has no fsync, concurrent appends fork the chain, a torn tail blocks startup, and the code, BOOTSTRAP.md and SPEC.md describe three different hash formats.
7. The hub's state snapshot and count-only limits do not bound memory on the 1 GB machine; the save throttle can lose mutations; blobs are consumed on the first GET before delivery is known to have succeeded; the default configuration loses every blob.
8. Ratchet and group state advance before authenticated decryption succeeds, and the ack-preview path decrypts twice.
9. Group creation omits the creator from the membership; group state has several unsynchronized writers.
10. `tests/itest.sh` is a smoke script whose exit status does not depend on delivery; the bootstrap's conformance test proves only a local round trip.

---

# Part A: Claude Fable 5.1 review

# Natively reference implementation - review

- Repo: github.com/taylorhou/natively (public clone)
- Commit: 5d8346fa172f85b8cd9730fb847750ed52a82508 ("site: terminal theme for BOOTSTRAP/docs pages via layout override")
- Date: 2026-09-07
- Reviewer: Fable 5.1 (citadel)
- Scope: README.md, SPEC.md, BOOTSTRAP.md, llms.txt, natively/{__init__,__main__,cli,crypto,envelope,hub,jcs,ledger,node}.py, requirements.txt, Dockerfile, fly.toml, tests/itest.sh. JCS behaviour was checked by running `natively.jcs` against probe values; everything else is by reading.

## Findings by file

### natively/jcs.py

- **MAJOR** `jcs.py:24-43` - `_es6_number` returns `repr(n)` for floats. Probed: `100.0 -> "100.0"`, `3.0 -> "3.0"`, `1e-7 -> "1e-07"`. RFC 8785 (ES6 `Number::toString`) requires `100`, `3`, `1e-7`. Any signed object containing an integral float or a small exponent (e.g. a `range` constraint `[0, 1.0]`) canonicalizes differently from a conformant peer, so cross-implementation signatures fail while same-code round trips pass and hide it. Change: after the non-finite/zero checks, `if n == int(n) and abs(n) < 1e21: return str(int(n))`; in the exponent branch emit `mant + "e" + str(exp)` (no zero padding, sign kept) instead of `r.replace("e+", "e")` at line 42; add the RFC 8785 Appendix B number vectors as a unit test.
- **MINOR** `jcs.py:14-15` - `return str(n)` prints Python ints of any size exactly; RFC 8785 serializes numbers as IEEE doubles, so an int above 2^53 (probed `9007199254740993`) diverges from a JS/Go peer. Change: raise `ValueError` for ints with `abs(n) > 2**53`.
- **MINOR** `hub.py:201,221,241`, `node.py:562` (parse boundaries for jcs input) - `json.loads` keeps the last of duplicate keys (probed `{"a":1,"a":2} -> {"a":2}`) and accepts `NaN`/`Infinity`/`1e400`, which `canonicalize` later rejects with `ValueError` outside any try block (hub 209/227, ledger 34). RFC 8785 input must not have duplicate keys. Not an observed misbehaviour inside this codebase, but the same bytes verify differently under a first-wins parser. Change: one `jcs.loads(b)` helper with `object_pairs_hook` rejecting duplicates and `parse_constant` raising, used at every wire parse.
- (OK) Key ordering by UTF-16 code units (line 61) and string escaping (line 57: lowercase `\u00xx`, DEL unescaped, `/` unescaped) match RFC 8785 in probes.

### natively/crypto.py

- **MAJOR** `crypto.py:215-233` - `DRSession.decrypt` advances `recv_chain`/`recv_n` (lines 230-232) and may run `_ratchet_step_recv` before `aead_decrypt` (line 233) succeeds; on AEAD failure the in-memory session stays advanced while the on-disk copy does not (`node.py:196-200` saves only after success). `node.py:573-583` triggers this in normal operation: an envelope of `type == "ack"` is decrypted once as a preview and, if the body is not `kind == "ack"`, decrypted again by `_handle_envelope`, which fails and leaves `recv_n` two ahead; every later message on that channel then fails until restart. Change: compute the ratchet step on a shallow copy of the session and commit fields only after AEAD succeeds; in `run()` decrypt once and dispatch on `body["kind"]`.
- **MINOR** `crypto.py:196-204` - `_skip_to` caps derivations per call but prunes one entry when `len(skipped) > MAX_SKIP`, so the store can grow by up to 199 per call; and a gap larger than `MAX_SKIP` (line 199) silently derives the wrong key at line 231 instead of refusing as `SenderKey.decrypt_at` does at 282-283. Change: raise `CryptoError("skip window exceeded")` when `n - recv_n > MAX_SKIP` before mutating, and prune with `while len(self.skipped) > MAX_SKIP`.
- **MINOR** `crypto.py:277-290` - `SenderKey.decrypt_at` also advances the chain (284-289) before the AEAD check at 290. Change: same commit-on-success pattern.
- **MINOR** `crypto.py:210,222,233` - the ratchet header bound as AAD is `json.dumps(hdr, separators=..., sort_keys=True)`, not JCS; a non-Python peer must replicate Python's encoder exactly. Change: `jcs.canonicalize(hdr)`.
- **MINOR** `crypto.py:238-248` - `x3dh_initiator` computes `dh3 = x_dh(ek, spk_peer_xpk)` (line 244), a duplicate of `dh2` (243); the responder identity key never enters the agreement, and the docstring promises a 3-tuple while line 248 returns two values. The initiator's assurance about the peer rests entirely on `spk_sig` (see hub prekey finding). Change: use the standard triple (`IK_A*SPK_B`, `EK_A*IK_B`, `EK_A*SPK_B`) with `ed_pk_to_x(peer_node_pub)` on both sides, and fix the docstring.
- **MINOR** `crypto.py:87` - `box = SecretBox(key)` is dead (overwritten at 90). Change: delete the line.

### natively/envelope.py

- **MAJOR** `envelope.py:111-124`, `node.py:426-447` - `audience.executor` is never compared with the executing node or agent key; a grant whose audience names another node is accepted on any node holding the file. SPEC 3: "A grant presented to a different executor is invalid." Change: in `_apply_grants`, refuse unless `g["audience"]["executor"]` equals `"ed25519:"+b64(self.node_pub)` or the receiving agent's key, ledgering `wrong-audience`.
- **MAJOR** `envelope.py:126-152`, `node.py:442-445` - `grant_covers` matches `sc["resource"]` by string equality against the `resource` the *sender* put in the body; nothing checks that the `host:<node-key>:` component names this node. SPEC 3 binds the resource to a host so a grant "cannot be replayed against a different machine". Change: parse `host:<key>:<name>`, require `<key>` to equal this node's key (or `any` only if the spec chooses to allow it), and refuse otherwise before consulting the grant.
- **MAJOR** `envelope.py:122`, `node.py:449-452` - `verify_grant` only checks the `max_uses` XOR `max_uses_per_window` shape; the node counts uses solely `if "max_uses" in g`, so a grant carrying `max_uses_per_window` has no limit at all (fails open). Change: implement the per-window count from the ledger (`grant_id` + `outcome == ok` within `window_s`) and refuse when `n` is reached; until then reject grants without `max_uses` as unsupported.
- **MAJOR** `envelope.py:99`, `node.py:426-431` - `revocation.ledger` / `max_check_interval_s` are carried but never consulted; nothing implements the per-principal tombstone feed of SPEC 6, and there is no local revocation list either, so a revoked card or grant stays valid until expiry. Change: before every action, read a revocation source (v0: `<home>/revoked/` tombstones signed by the pinned principal or its recovery key; later the feed URL), cache per `max_check_interval_s`, and fail closed when the source cannot be read past the grace window.
- **MAJOR** `node.py:432-441` - the node locates the subject card (`subj_card`) but never checks the grant's scope actions against `card["capabilities"]`, which SPEC 2 says bind ("a grant whose scope names an action outside the subject card's capabilities is invalid"). Change: in `_apply_grants`, refuse if any `sc["action"]` is not in `subj_card[1]["card"]["capabilities"]`.
- **MINOR** `envelope.py:100,111-124` - `parent_grant` is accepted and never inspected; no delegation depth, subset or root check exists. With a pinned principal an agent-signed child fails the issuer check by accident. Change: reject grants with non-null `parent_grant` as unsupported until delegation is implemented.
- **MINOR** `envelope.py:118-121`, `envelope.py:75` - `not_before`/`expires_at`/card `expires_at` are compared as strings; a valid RFC 3339 value with fractional seconds or an offset compares wrongly. Change: parse to epoch seconds and compare numerically; reject unparseable values.
- **MINOR** `envelope.py:136-149` - params not listed in `keys`/`values` pass unconstrained; `range` on a missing or non-numeric value raises `TypeError` (line 144) instead of refusing; `in` treats `true` as `1`. Change: refuse unknown param keys, wrap each rule in a type check that returns `False`, and compare with `type(v) is type(x)` for `in`.
- **MINOR** `envelope.py:71-77` - `verify_card` exists but no receive path calls it (see node identity finding). Change: covered below.

### natively/ledger.py

- **MAJOR** `ledger.py:40-45`, `ledger.py:17-24` - appends have no flush/fsync and the JSONL and prose writes are two unordered appends; a crash mid-write leaves a partial last line, `head()` then raises `JSONDecodeError` on every `append`, and `Node.run()` cannot pass its `node.start` entry (`node.py:545`), so the daemon restarts into the same failure. Change: on open, detect a trailing partial line, move it to `ledger.jsonl.torn` and record the event in the prose mirror; `flush()+os.fsync()` after each JSONL write before writing the mirror line.
- **MINOR** `ledger.py:28,17-24` - `head()` re-reads the whole file on every append (O(n) per entry, O(n^2) over a run). Change: cache the head hash in memory after the first read and update it in `append`.
- **MINOR** `ledger.py:38-39` vs `BOOTSTRAP.md:135-136` - the chain hashes `JCS(entry minus prev_hash_chain)`, while BOOTSTRAP says `prev_hash` is "the hash of the exact bytes of the previous line"; SPEC 5 is silent. Change: pick one (JCS hashing is the better choice) and say so in SPEC 5; rename `prev_hash_chain` to `entry_hash`.
- **MINOR** `ledger.py:43` - the prose line carries no hash, so after a torn write a reader cannot pair prose with entries. Change: prefix each prose line with the first 12 hex of `entry_hash`.
- **MINOR** `ledger.py:30` - `jcs and __import__("time")...` is an obscured `time.strftime`. Change: `import time` at module top.

### natively/node.py

- **MAJOR** `node.py:559-589` - the poll loop catches only `URLError`/`OSError` (line 588); any `KeyError`/`TypeError`/`AttributeError` raised while handling one envelope (examples: `env["from"]` not a string at 330, `sig` missing at `envelope.py:45`, `to` sent as a list at 319, `body` decrypting to a non-dict at 337, `hdr["n"]` non-int at `crypto.py:230`) exits the process before `_save_state()` at 586, so the same envelope is re-polled after restart. Change: wrap the per-item body in `try/except Exception` that ledgers `msg.recv error`, records the `msg_id` in `seen`, advances `last_seq`, and continues; validate types at the top of `_handle_envelope`.
- **MAJOR** `node.py:407`, `node.py:421`, `node.py:102-103` (via 344, 386, 121) - wire-supplied identifiers become path components: `env["msg_id"]` names the inbox file, `grant_ids[i]` names the grant file read, and the decrypted `group_id` names the group file that `_save_group` writes with truncate. A `group_id` of `../../<name>` writes outside `groups/`. Change: one `_safe_id(s)` check (`^[a-z]{3}_[0-9a-z]{26}$`) applied at all three sites; refuse and ledger on mismatch.
- **MAJOR** `node.py:330,491-503`, `node.py:176-181` - the receiver learns the sender's node fp from the hub directory and the sender's identity key from the hub prekey bundle; the sender's principal-signed card (`verify_card`) is never checked, and `card["node_key"]` is never compared with the session peer key. The hub is documented as untrusted (`hub.py:3`), yet it decides residency. Change: fetch the sender card from the directory entry, require `verify_card(card)` (pinned root set, not just one key), `card["agent_key"] == env["from"]`, and `card["node_key"] == bundle["node_key"]` before opening or using a session.
- **MAJOR** `node.py:355-361`, `node.py:392-393` - the sender key for a group message is selected by the plaintext-claimed `sender_fp`, never compared with the authenticated outer sender (`env["from"]` resolved to a node). Sender Keys are symmetric, so any member holding the key can produce ciphertext attributed to that fp; and a `group_key` naming another member's fp is stored first-come, after which the real one is `ignored-duplicate`. Change: derive the sender fp from the verified envelope (`_resolve_node_by_key(env["from"])`), refuse when it differs from `sender_fp`, and key `_recv` by that verified fp.
- **MAJOR** `node.py:204-217`, `node.py:227-231` - `create_group` puts only the invitees in `members`; joiners fan out and distribute their sender keys to `g["members"]` only, so nothing a non-creator sends ever reaches the creator (`tests/itest.sh:40` tolerates exactly this failure). Change: include the creator's agent in `members` before distributing, and have `group_send` skip only the sending agent.
- **MAJOR** `node.py:298-310`, `node.py:587-593` - with the hub unreachable, `_flush_outbox` appends a `msg.send retry` ledger entry (and prose line) per outbox file on every 0.5 s pass, the poll failure is `pass`ed, and the loop sleeps 0.5 s: the audit ledger fills at 2 lines/s per pending message, each append re-reading the file. Change: exponential backoff on hub connectivity (1 s to 60 s), one `hub.unreachable`/`hub.restored` entry per state change, and no ledger line for a deferred send.
- **MINOR** `node.py:299-302` - `http.client.RemoteDisconnected` (an `OSError`) is classed transient, so a hub handler that raises (no status sent, see hub) is retried forever. Change: count attempts per outbox file and move to `.err` after N.
- **MINOR** `node.py:403-410` - the inbox record (with `kind: action` and `grant_ids`) is written before the grant verdict and carries no outcome; a consumer reading the inbox cannot tell a refused action from an allowed one without the ledger. Change: write the record after `_apply_grants` and include `outcome`.
- **MINOR** `node.py:566-571,586`, `node.py:453-455` - `seen` and `last_seq` are persisted only after the whole batch; a crash after `test.ping` executes re-executes it on restart (SPEC 4 idempotency on `msg_id` across restarts). Change: `_save_state()` immediately after adding to `seen` and before executing an action.
- **MINOR** `node.py:250-256,491-503` - a full `/v1/directory` GET per outbox file, per received envelope and per ack. Change: cache the directory for `P` seconds.
- **MINOR** `node.py:73-81,551` - `_load_agents` runs every 0.5 s and a `.key` without a `.card.json` raises `FileNotFoundError` outside the try (process exits). Change: rescan on directory mtime change and ledger a bad bundle instead of raising.
- **MINOR** `node.py:67-70`, `node.py:596-602` - `_save_state` has no fsync and relies on refcount close before `os.replace`; the home directory is created with the umask default (files are 0600, good). Change: `with open(...) as f: json.dump; f.flush(); os.fsync(f.fileno())`; `os.makedirs(home, mode=0o700)`.
- **MINOR** `node.py:131` - `spk_sig` signs raw `spk_x` bytes with the same node key that signs JCS objects, with no domain tag. Change: sign `b"nv1-spk:" + spk_x`.
- **MINOR** `node.py:464-468` - acks set `in_reply_to` to null and carry the target in the body; SPEC 4 puts `in_reply_to` in the envelope. Change: pass `in_reply_to=env["msg_id"]`.
- **MINOR** `node.py:146-150` - the comment records that the DH ratchet is static per direction; SPEC 9.1 promises "a DH ratchet on reply" (break-in recovery). See divergences.

### natively/hub.py

- **MAJOR** `hub.py:24`, `hub.py:265-268`, `hub.py:103-107`, `hub.py:176-181`, `hub.py:288` - one `MAX_BODY` of 64 MB applies to `/v1/msg` and `/v1/register` as well as blobs; envelopes are held in RAM (`queues`), JSON-serialized on every save, and returned by poll with no page limit; `ThreadingHTTPServer` spawns a thread per connection with the full body in memory. On the 1 GB VM a handful of large envelopes or concurrent uploads reproduces the OOM class of "break #10". Change: 256 KB cap for `/v1/msg`, 64 KB for `/v1/register` and `/v1/prekey`; poll returns at most 200 entries / 4 MB with `last_seq` of the page; a `threading.Semaphore(8)` around body reads and streaming blob writes to disk in 1 MB chunks.
- **MAJOR** `hub.py:218-237` - `/v1/register` verifies only a self-signature: no timestamp or nonce (a captured body re-registers an old agent set later), no check that `a["card"]` is principal-signed or that `card["node_key"]`/`card["agent_key"]` match `reg["node_key"]`/`a["agent_key"]`, and line 235 lets any node overwrite `agent_owner[key]` for a key another node registered, moving routing for that agent. Change: require `ts` within 5 min plus a hub-issued nonce (`GET /v1/nonce/<fp>`), verify each card and its node/agent key equality, and refuse to move an `agent_key` between fps unless the new card `supersedes` the stored one.
- **MAJOR** `hub.py:194-214` - a prekey bundle is stored under the *path* fp (`self.path.rsplit("/",1)[1]`, line 196) after verifying the signature of whatever `node_key` the body names; the two are never tied, so a bundle signed by node A can sit under node B's fp and every X3DH toward B (and every responder lookup of B) uses A's keys. Change: compute `fp = jcs.sha256(b64d(nk))[:32]` from the body as `/v1/register` does (line 229) and reject when it differs from the path.
- **MAJOR** `hub.py:166-191` - `/v1/poll/<fp>?after=N` is unauthenticated: any client that reads `/v1/directory` can fetch another node's queued envelopes and, via the prune at 185-190, delete them by sending a high `after`. SPEC 8.1: "the registry binds the transport session to the node_key". Change: require a node-signed poll token (`{fp, after, ts}` in a header, verified against the registered `node_key`); same for `/v1/blob` GET.
- **MAJOR** `hub.py:266`, `hub.py:95-107`, `hub.py:291-295` - `seq[fp]` lives in the throttled JSON save (2 s) with no fsync and no shutdown flush; after a crash the counter can be lower than a node's persisted `last_seq`, so new enqueues receive `_seq <= after` and are filtered out at 177 until the counter catches up, while sender retries dedupe against the queued copy and end `undelivered`. Change: make `_seq` monotonic across restarts (e.g. `(boot_ms << 20) | counter`, or fsync the seq on every enqueue), and handle SIGTERM with `save(force=True)`.
- **MAJOR** `hub.py:86-93`, `hub.py:162-165`, `cli.py:113-126` - blob GET deletes on first fetch; `group-blob` uploads once and references the same `blob_id` for every member, so all but the first fetcher get 404, and a node's second attempt after a failed decrypt also gets 404. Change: replace pop-on-GET with a TTL (e.g. 24 h) or an upload-declared fetch count, evicted by the sweep at 76-84.
- **MAJOR** `hub.py:113-118` and every handler - no handler has a top-level exception boundary; a malformed `Content-Length` (120), `after=` (172), a list `to` (146, because `_route_node` runs before the list check at 249), a missing `name`/`agent_key`/`card` (233-235), a `..` blob id (163-165, `IsADirectoryError`), or a bad base64 key (209, 227) raises out of the handler, which closes the connection with no status; the node classes that as transient (`node.py:300`) and retries every 0.5 s forever. Change: wrap `do_GET/PUT/POST` bodies in `try/except Exception` returning `{"error": "bad request"}` 400 (or 500) with no internals, plus `Connection: close` on 413.
- **MINOR** `hub.py:119-123` - `_body` accepts a negative `Content-Length` (`rfile.read(-1)` blocks until the client closes) and returns None on 413 without draining or closing. Change: `if n < 0 or n > MAX_BODY`, reject and close.
- **MINOR** `hub.py:63,76-84` - `BLOB_CAP` equals `MAX_BODY`, so one maximal upload evicts every other pending blob before its consumer fetches; concurrent puts can `unlink` the same file (`FileNotFoundError`). Change: per-blob cap 16 MB, total cap 512 MB (volume permitting), and `try/except FileNotFoundError` around `unlink`.
- **MINOR** `hub.py:31,67-73,278-285` - without `--state`, `blob_dir` is None, `blob_put` returns silently and the handler still answers 200 with a `blob_id` (fails open). Change: use a temp dir or answer 503.
- **MINOR** `hub.py:238-257` - `/v1/msg` never checks the envelope signature (the outer object is cleartext), so unsigned junk fills a node's queue up to the 5000 cap and evicts real entries; the multi-recipient branch at 249-253 is unreachable (see above). Change: `envelope.verify_message(env)` at the hub before enqueue; delete or fix the list branch.
- **MINOR** `hub.py:231-235` - re-registration never removes agents absent from the new set; stale `agent_dir`/`agent_owner` entries route to a node that answers `undeliverable`. Change: drop entries for that fp not in the new list.
- **MINOR** `hub.py:13,173,182` - docstring says a 25 s long-poll; the code uses 5 s. Change: align (and export the value so the node's `_http` timeout of 35 s stays above it).
- **MINOR** `hub.py:100-102` - the save throttle drops a save when the previous one was under 2 s ago and nothing schedules a later one, so a single mutation followed by quiet stays in memory indefinitely; `save` has no fsync before `os.replace`. Change: a timer thread that flushes dirty state every 2 s, and fsync the temp file.

### natively/cli.py

- **MINOR** `cli.py:163` - blob integrity is an `assert`, removed under `python -O`. Change: `if ...: raise SystemExit("blob hash mismatch")` before writing `args.out`.
- **MINOR** `cli.py:49,183` - `agent-add` and `grant-issue` read the principal seed on the node machine; `BOOTSTRAP.md:183-184` and SPEC 1.4 say the principal key never lives there. Change: document as the v0 developer flow and add `--grant-file` so a grant signed elsewhere can be installed.
- **MINOR** `cli.py:61-71` - `send --action` without `--grants` queues an action-shaped body that the receiver files as information (correct per SPEC 4) with no warning to the operator. Change: print a notice.

### Dockerfile, fly.toml, requirements.txt

- **MINOR** `Dockerfile:1-7` - runs as root, no `HEALTHCHECK`, base image unpinned by digest; `requirements.txt:1` is `PyNaCl>=1.5` (unbounded). Change: `USER nobody`, `HEALTHCHECK` on `/v1/healthz`, pin `PyNaCl==1.5.0` and the image digest.
- **MINOR** `fly.toml:14-22` - no `[[http_service.checks]]` (a wedged hub is not restarted), no `[http_service.concurrency]` limits, one volume with no snapshot note; `force_https` is the only edge control and every endpoint (register, msg, poll, blob, prekey, directory) is reachable without authentication on the public URL. Change: add the health check and `concurrency = {type="requests", soft_limit=50, hard_limit=100}`; the auth findings above are the real fix.

### tests/itest.sh

- **MAJOR** `tests/itest.sh:31,35,42,51,62` - inbox and ledger output is printed, never asserted; line 40 tolerates the group send failing; the exit status depends only on `cmp` (53) and `ledger verify` (63). A run in which no 1:1 or group message is delivered and the ping is refused still prints `ITEST DONE` with status 0, which is what the commit log cites as evidence. Change: `grep -q` each expected inbox line and `grep -q '"test.ping".*"ok"'` in the n2 ledger tail, failing under `set -e`.
- **MINOR** `tests/itest.sh:2,4` - `PYTHONPATH=/tmp/natively` is hard-coded (the script only runs from that path) and `pkill -f natively` kills every matching process on the host. Change: `PYTHONPATH="$(dirname "$0")/.."` and kill only `$HUB $N1 $N2`.
- Exercised: hub start, principal init, two nodes, three agents, 1:1 both directions, group create + creator send, blob round trip, grant issue + `test.ping` with `max_uses 2`, chain verify.
- No test at all for: JCS vectors, grant refusals (expired, not-yet-valid, wrong subject, wrong audience, out-of-scope, exhausted, unknown grant), a no-grant message carrying an action body, duplicate delivery/idempotency, node restart mid-batch, hub restart (seq/cursor), hub switch reset, poll prune, retry/undelivered timing, out-of-order ratchet delivery, sender-key replay (break #11), group send from a joiner, blob eviction and second fetch, 413 handling, torn ledger tail. There are no unit tests (`tests/` holds only the shell script).

### Docs (README.md, llms.txt, BOOTSTRAP.md)

- **MINOR** version drift: `README.md:22` says v0.3, `llms.txt:5,14` v0.2, `SPEC.md:1` v0.4, `BOOTSTRAP.md:12` v0.3, `__init__.py` 0.4.0. Change: one version string sourced from `__init__.py`.
- **MINOR** `BOOTSTRAP.md:66-71` card fields (`principal`, `ledger`, no `card_version`/`issued_at`/`expires_at`/`supersedes`) do not match `SPEC.md:62-72` or `envelope.py:57-67`. Change: paste the spec card.
- **MINOR** `BOOTSTRAP.md:88,114` recommend `canonicaljson`, which is not RFC 8785 (rejects floats; code-point key order differs from UTF-16 order above U+FFFF), two lines after warning against approximations. Change: point at `natively.jcs` or an RFC 8785 library and ship test vectors.

## Divergence from SPEC.md

1. SPEC 8 / 8.1 enrollment (principal-signed record, nonce-signed heartbeats, session bound to node_key) vs `hub.py:218-237` self-signed registration and unauthenticated poll. Code moves; SPEC 8 should also state the v0 interim explicitly so BOOTSTRAP 6 ("do not improvise enrollment") is not contradicted by the shipped hub.
2. SPEC 3 audience, resource host binding, capabilities binding (SPEC 2), delegation, revocation (SPEC 6), `max_uses_per_window` - none enforced (`envelope.py:111-152`, `node.py:415-462`). Code moves.
3. SPEC 9.1 X3DH "plus ephemeral prekeys published by each node" and Double Ratchet "DH ratchet on reply" vs one static signed prekey (never rotated, `node.py:48`), no one-time prekeys, a duplicated `dh3`, and directional channels with a static DH key (`node.py:146-150`). Code should move to the standard triple and ratchet on reply; if directional channels stay for v0, SPEC 9.1 must say forward secrecy is symmetric-chain only and break-in recovery is deferred.
4. SPEC 9.1 "Principals are silent members" - not implemented anywhere (no principal recipient in any session). Code moves or SPEC marks it deferred; today the property is provided only by the principal reading the node's inbox files.
5. SPEC 9.1 groups: "one ciphertext fan-out, not N pairwise sends" and "membership change rotates sender keys" vs `node.py:227-231` (N pairwise sends; `inner_wire` accepted at 236 and unused) and no rotation. Code moves (or SPEC allows the pairwise wrapper for v0).
6. SPEC 4 message fields vs code: code adds `type` and `suite` (`envelope.py:163-164`, SPEC 9.1 mentions `suite` only), acks use `body.ack` instead of `in_reply_to`, no ack jitter. SPEC 4 should list `type`/`suite`; code should set `in_reply_to`.
7. SPEC 5 entry shape vs `ledger.py:39` extra `prev_hash_chain`; hash input (JCS entry vs raw line, BOOTSTRAP 136). SPEC moves: define entry hash = SHA-256(JCS(entry)) and name the field.
8. SPEC 1.5 "surfaced to the human with the reason" vs failures written only to the ledger; `cli.py` has no surface command beyond `ledger tail`. Code moves (an `inbox --rejected` or the outcome in the inbox record).
9. SPEC 2 "pinned principal root ... root set includes a recovery key" vs one `principal.pub` per node (`node.py:49`) and no card verification on receive. Code moves to a root set file.
10. BOOTSTRAP 183-184 / SPEC 1.4 principal key location vs `cli.py` requiring the seed on the node. Docs move (state the v0 developer exception) until the signer exists.

## Top 10 recommendations

1. Enforce the full SPEC 3 grant check in `_apply_grants`: audience executor, `host:<key>` resource binding to this node, card capabilities, `max_uses_per_window`, and a revocation source that fails closed - refuse rather than skip any check that is not implemented.
2. Isolate every polled envelope in `Node.run` with a per-item exception boundary that ledgers the failure and advances the cursor, and validate wire types before use, so one malformed message cannot stop the daemon or replay on restart.
3. Validate every wire identifier (`msg_id`, grant id, `group_id`) with one `_safe_id` regex before it becomes a path under the node home.
4. Bind identity end to end: verify the sender's principal-signed card on receive, require `card.node_key` to equal the X3DH peer key, derive the prekey fp from the bundle's `node_key` at the hub, and select group sender keys by the authenticated envelope sender rather than the claimed `sender_fp`.
5. Commit ratchet state only after AEAD succeeds in `DRSession.decrypt` and `SenderKey.decrypt_at`, and decrypt each envelope once in the poll loop.
6. Fix `_es6_number` for integral floats and negative exponents, reject duplicate keys and non-finite constants at parse boundaries, and add the RFC 8785 test vectors as the first unit test file.
7. Authenticate hub poll/blob-fetch/register with node-signed, time-bounded tokens (SPEC 8.1) and refuse to move an `agent_key` between nodes without a superseding card.
8. Bound hub memory: per-endpoint body caps (256 KB envelope, 64 KB register), a poll page limit, a semaphore on concurrent bodies, streaming blob writes, and a top-level handler exception boundary that always returns a status.
9. Make the hub `_seq` monotonic across restarts and flush state on SIGTERM; replace blob pop-on-GET with a TTL or declared fetch count so group attachments and retries work.
10. Make the ledger crash-safe (fsync, torn-tail quarantine, cached head), remove per-pass retry entries in favour of hub-connectivity backoff, include the creator in group `members`, and turn `tests/itest.sh` into an asserting test with the negative grant paths.

## Verdict

BLOCK - 22 MAJOR findings (jcs 1, crypto 1, envelope/grant 5, ledger 1, node 6, hub 7, tests 1).


---

# Part B: Codex (gpt-6-astra) review

This revision has major correctness and robustness failures.

Read-only validation: all nine Python modules parsed, and `bash -n tests/itest.sh` passed. In-memory probes reproduced the failures identified below; those requiring unavailable PyNaCl used mocked cryptographic results. The integration script was not executed because it writes files and kills processes.

Findings follow your requested lens order. Unless explicitly stated otherwise, the implementation should move to SPEC.md.

1. **MAJOR — `natively/jcs.py:14`: Number serialization is not JCS.** Probes produced `1.0`, `1e-06`, `1e-07`, and `1e21` instead of `1`, `0.000001`, `1e-7`, and `1e+21`; arbitrary Python integers also escape the required binary64 representation. **Change:** replace `_es6_number` with a conforming implementation and RFC known-answer vectors. [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html#section-3.2.2.3)

2. **MAJOR — `natively/hub.py:241`: Duplicate JSON keys disappear before verification.** Every ordinary `json.loads` silently keeps the last occurrence, allowing different parsers to interpret the same signed document differently. Non-finite constants are also accepted during parsing, although JCS later rejects them. **Change:** use one strict JSON decoder that rejects duplicate keys and non-finite numbers at every document boundary. [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html#section-3.1)

3. **MAJOR — `natively/envelope.py:43`: Verification does not contain malformed-input failures.** Missing signatures, invalid base64, malformed key references, and canonicalization errors escape before `crypto.verify` can return `False`; inbound handling can terminate the daemon. **Change:** make public verifiers validate input and return a bounded, typed verification failure that callers consistently report.

4. **MAJOR — `natively/envelope.py:113`: Missing principal pins fail open.** `None` or an empty principal file disables issuer matching; `verify_card` has the same behavior. Key parsing also accepts arbitrary algorithm prefixes and permissive base64, while identity comparisons use inconsistent strings. **Change:** require a nonempty validated principal root and parse all identity keys into canonical, exactly 32-byte Ed25519 values before comparison.

5. **MAJOR — `natively/hub.py:212`, `natively/node.py:159`: Anyone can replace another node’s prekey bundle.** The hub accepts a bundle signed by any key under any requested fingerprint; the sending node checks the prekey’s signature against that supplied key without binding it to the intended node. An attacker can substitute their prekey and decrypt intercepted traffic. **Change:** verify the complete bundle against the authenticated card/enrollment chain and require its node-key fingerprint to match the requested identity.

6. **MAJOR — `natively/node.py:573`: Acknowledgements bypass signature and recipient verification.** The ack branch decrypts and calls `_handle_ack` directly; that function accepts any known message ID without checking the original recipient. A control-flow probe removed an outstanding message using an invalid-signature ack naming the wrong sender and destination. **Change:** verify every envelope before decryption and bind each ack to the outstanding message’s expected recipient and sender.

7. **MAJOR — `natively/node.py:433`: Grant identity binding is incomplete.** The local card-hash check rejects a different local subject, but `subject.key`, audience, card signature, card expiry, card-to-node binding, and capabilities are never enforced. A grant outside the card’s capabilities or intended executor still acts. **Change:** validate the complete subject/card/executor chain before scope evaluation.

8. **MAJOR — `natively/envelope.py:136`: Parameter constraints permit unauthorized inputs.** `params.keys` acts as a required-key list rather than an allowlist; extra keys pass, unknown constraint operators are ignored, and Python equality permits `True` where `1` is allowed. Missing values and regex string coercion create further ambiguities. **Change:** implement a typed, closed constraint grammar that rejects extra keys, unknown operators, and incompatible values.

9. **MAJOR — `natively/envelope.py:117`: Grant schema and time validation are incomplete.** Dates are compared lexicographically; malformed dates such as `"garbage"` can pass, offsets are misinterpreted, and expiry equality remains valid. Required metadata—including `principal_statement`—can be absent. Resources such as `host:any:ping` pass unchanged. **Change:** validate the complete envelope schema, parse timestamps into UTC instants, and enforce actual host-bound resources.

10. **MAJOR — `natively/node.py:448`: Rolling-window limits are never enforced.** A scope limited to one use per hour executed three times in the probe. The envelope’s `any(...)` check also permits other scopes without any limit, and fractional `max_uses` values can authorize more executions than their numeric value. **Change:** require positive integer budgets on every applicable scope and count the matched scope’s uses from durable history.

11. **MAJOR — `natively/node.py:427`: Revocation and offline policy are absent.** No feed is fetched, no card or principal tombstone is checked, no recovery key is supported, and `offline_ok`, grace, and check intervals are ignored. Issuance defaults to an empty revocation URL. **Change:** require a usable signed revocation feed and enforce freshness, recovery tombstones, and read-only offline allowances before execution.

12. **MAJOR — `natively/envelope.py:111`: Delegation is ignored.** A principal-signed grant with a nonexistent parent passes; parent validity, depth, expiry, revocation, and strict scope narrowing are unchecked. Agent-signed delegated grants cannot establish the required principal chain. **Change:** implement depth-one chain verification and conservative subset checks, rejecting non-null parents until that verification exists.

13. **MAJOR — `natively/node.py:420`: Grant path aliases bypass `max_uses`.** The use counter is keyed by the supplied filename rather than the signed `grant_id`; `grt_1`, `./grt_1`, and `../grants/grt_1` each executed the same one-shot grant in the probe. **Change:** require a canonical grant identifier matching the signed field and use that verified identifier for lookup and accounting.

14. **MAJOR — `natively/node.py:419`: One message can execute its action repeatedly.** Every matching grant triggers execution, including duplicate entries in `grant_ids`; listing one grant twice consumed two uses and produced two pings. **Change:** select one valid authorization for the requested action and execute once per message.

15. **MAJOR — `natively/node.py:337`: Grantless messages can change group state and distribute keys.** `group_key` bypasses `_apply_grants`, creates membership state, and queues sender-key disclosures to supplied members. The explicit `test.ping` path is grant-gated, but group administration is an instruction path outside that gate. **Change:** require authorized group membership/key-management operations before joining or distributing keys.

16. **MAJOR — `natively/ledger.py:40`: Ledger and prose appends are not durable together.** Neither file is fsynced, and failure between writes leaves the JSONL without its prose. Because prose is not retained in the machine record, exact reconstruction is unavailable. **Change:** commit a durable record containing recoverable prose, then maintain the mirror as a checked projection.

17. **MAJOR — `natively/ledger.py:28`: Concurrent appends fork the chain.** `head()` and append are separate unlocked operations; an in-memory concurrent probe produced two entries referencing `GENESIS` and failed verification. The daemon lock does not protect other ledger callers. **Change:** hold an interprocess append lock across head selection, complete write, and durability confirmation.

18. **MAJOR — `natively/ledger.py:17`, `natively/node.py:50`: Torn tails prevent recovery, and startup never verifies integrity.** A partial final JSON object raises from both `head()` and `verify_chain`; otherwise startup trusts stored chain hashes without verification. **Change:** verify the complete prefix at startup, distinguish an incomplete tail from interior corruption, and require explicit recovery before appending.

19. **MAJOR — `natively/node.py:61`, `natively/node.py:453`: Execution accounting cannot recover from the ledger.** Missing `state.json` resets grant uses and deduplication despite existing history; malformed state prevents startup. Counters, session advancement, inbox delivery, and action entries commit separately, with no recovery transaction. **Change:** persist recoverable message IDs, execution decisions, counters, and ledger records in one transaction.

20. **MINOR — `natively/ledger.py:20`: Append cost grows with the entire ledger.** Every append reparses all previous entries; an outage itself creates repeated retry entries, producing quadratic accumulated work. **Change:** maintain a verified cached/indexed head under the append lock.

21. **MAJOR — `natively/node.py:484`: Ledger reconciliation is not implemented.** Peer heads are merely hashed into log parameters; no stored checkpoint, consistency comparison, or reconciliation follows. A rewritten or truncated local chain can still pass self-verification. **Change:** retain authenticated peer/local checkpoints and implement consistency reconciliation against them.

22. **MAJOR — `natively/hub.py:227`: Registration proves only possession of an arbitrary node key.** There is no owner-signed enrollment, machine fingerprint, residency class, expiry, or nonce-bound session. Agent cards are not verified, and any registrant can overwrite another agent’s owner mapping. **Change:** require authenticated enrollment and validated, node-bound principal-signed cards before publishing ownership.

23. **MAJOR — `natively/hub.py:185`: Unauthenticated polling deletes other nodes’ queues.** Anyone knowing a public fingerprint can submit a large `after` cursor and prune its pending entries; the handler probe confirmed this. **Change:** authenticate polling as that node and accept deletion progress only through authenticated delivery commits.

24. **MAJOR — `natively/hub.py:46`, `natively/hub.py:270`: The OOM fixes do not bound memory.** A 5,000-entry queue can contain roughly 312 GiB of allowed payloads; queue/node/prekey counts are globally unlimited. Startup loads the whole file before clamping, including legacy blob data. Commits `86696c1`, `dda6859`, and `425218e` document precisely this OOM/serialization history. **Change:** enforce global byte quotas and use bounded, incremental storage and loading.

25. **MAJOR — `natively/hub.py:56`, `natively/hub.py:271`: Queue limits silently discard accepted messages.** Startup retains only 500 entries while runtime retains 5,000; sender retries are finite and therefore cannot guarantee recovery. **Change:** preserve accepted messages durably and apply backpressure before accepting traffic that exceeds capacity.

26. **MAJOR — `natively/hub.py:100`: The save throttle has an indefinite loss window.** Mutations inside the two-second interval are skipped without a scheduled flush; the final mutation can remain unsaved forever. Rename is not followed by fsync, and shutdown does not force persistence. **Change:** use a durable journal or a real dirty-state flusher with file/directory fsync and shutdown handling.

27. **MAJOR — `natively/hub.py:60`: Corrupt state silently becomes an empty or partially loaded hub.** `/healthz` still reports success, and sequence numbers may restart behind clients’ persisted cursors, causing new messages to be skipped and pruned. **Change:** validate state before installing it, fail startup on corruption, and include a durable hub incarnation in cursor negotiation.

28. **MAJOR — `natively/hub.py:86`: Blob GET consumes the only copy before delivery succeeds.** A disconnected download cannot retry, and the first group recipient prevents every later recipient from fetching the same attachment. **Change:** make GET repeatable and separate deletion from reads using explicit retention/consumer acknowledgements.

29. **MAJOR — `natively/hub.py:74`: Blob writes and eviction race and are not durable.** Concurrent upload, fetch, and eviction can read partially written files or raise during stat/unlink; FIFO eviction can remove an acknowledged upload before its reference is consumed. **Change:** atomically publish fsynced blobs and manage retention, quotas, and deletion through synchronized metadata.

30. **MAJOR — `natively/hub.py:71`: Default hub operation silently loses every blob.** Without `--state`, `blob_put` does nothing while POST returns success; the probe immediately fetched `None`. **Change:** require configured blob storage before serving uploads.

31. **MAJOR — `natively/hub.py:155`: Slow clients can hold the global state lock.** Directory serialization and socket writes occur inside `st.lock`; state serialization also blocks all users of that lock. This recreates the timeout feedback loop described in the history. **Change:** serve bounded immutable snapshots outside the lock and move persistence off request-critical lock sections.

32. **MAJOR — `natively/hub.py:232`, `natively/hub.py:246`: Registration replacement and routing are inconsistent.** Removed/renamed agents remain in directory and ownership maps; routing reads ownership before acquiring the queue lock, permitting a concurrent update to redirect ownership after target selection. **Change:** atomically replace a validated node registration and resolve routing against the same synchronized ownership generation.

33. **MINOR — `natively/hub.py:246`: The advertised multi-recipient path crashes.** `_route_node` calls `.startswith()` on `to` before the list branch runs. **Change:** validate and dispatch recipient types before string routing, then deduplicate destination nodes.

34. **MINOR — `natively/hub.py:277`: Delivery accounting reports targets, not enqueues.** A completely deduplicated POST still reports `queued: 1`; the documented sequence response is absent. **Change:** return explicit accepted/duplicate status and the relevant durable sequence identifier.

35. **MAJOR — `natively/node.py:72`, `natively/node.py:551`: Agent reload misses removal and replacement.** The agent dictionary never clears deleted bundles, and re-registration compares names only, missing same-name key/card changes. A partially installed bundle can also terminate the loop. **Change:** load and validate an atomic bundle snapshot and compare its full registration digest.

36. **MAJOR — `natively/node.py:543`: Startup and hub recovery are brittle.** Initial prekey publication/registration fail outside retry handling; after startup there is no periodic registration or prekey refresh when the hub loses state. **Change:** use a persistent registration state machine with bounded backoff, periodic refresh, and validated responses.

37. **MAJOR — `natively/node.py:561`: Unexpected hub responses terminate the daemon.** `[]`, `{"messages":null}`, and HTML each crashed the control-flow probe; only network/OSError exceptions are caught. Directory errors can instead be swallowed and cause a message to be recorded as permanently undecryptable. **Change:** validate each response shape and distinguish retryable transport/protocol failures from permanently invalid messages.

38. **MAJOR — `natively/node.py:284`: Retrying an uncertain POST creates another logical message.** Encryption advances the session and a new message ID is generated before every attempt; if the hub accepted a POST whose response was lost, the retained outbox request produces a second delivery/action. **Change:** durably assign and store the exact signed ciphertext envelope before its first POST, then retry those same bytes.

39. **MAJOR — `natively/node.py:565`: Deduplication commits before successful handling.** IDs enter `seen` before signature verification, decryption, or delivery; transient failure therefore poisons retries. The 5,000-ID FIFO also forgets old executions, without a durable replay check. **Change:** authenticate first and transactionally record completed handling in a persistent deduplication index.

40. **MAJOR — `natively/node.py:566`: Duplicate delivery cannot repair a lost ack.** Seen messages are skipped without regenerating a receipt; after the hub prunes the original entry, sender retries are accepted again but still receive no ack. **Change:** replay the stored receipt for an authenticated duplicate without reapplying or redecrypting it.

41. **MAJOR — `natively/node.py:290`: Acks themselves enter the unacked queue.** Valid ack handling deliberately produces no further ack, so successful conversations create retry traffic and false `undelivered` records for their receipts. **Change:** give acknowledgements a separate delivery policy that does not require acknowledgements of acknowledgements.

42. **MINOR — `natively/node.py:510`: Retry counting is off by one.** Starting at `attempts=1` permits only two retransmissions before declaring failure, despite logging “3 retries”; jitter is absent. **Change:** track initial transmission separately and implement the specified three retry deadlines.

43. **MAJOR — `natively/node.py:558`: Outbox work can starve polling and receipts.** Every pending send runs synchronously before the next poll, often with a directory request and up to 35-second network waits; there is no batch/time budget. Retry deadlines therefore have no reliable relationship to `P`. **Change:** schedule bounded send batches, polls, and retry timers independently.

44. **MAJOR — `natively/node.py:397`: Two local group recipients consume the same receive key.** Group state is shared by node/sender, while ciphertext is delivered separately to each agent; the probe delivered to beta and rejected gamma as replayed. The exception can terminate the daemon. **Change:** decrypt a group message once and fan out its durable plaintext record to authorized local recipients.

45. **MAJOR — `natively/node.py:205`: Group creation omits the creator from membership.** The integration script supplies beta and gamma only; joiners distribute keys and replies to that list, so alpha cannot receive their group traffic. **Change:** include the creator’s agent identity in the canonical membership list.

46. **MAJOR — `natively/node.py:355`: Group sender identity and key epochs are unenforced.** Supplied `sender_fp` is not bound to the authenticated envelope sender, membership is not checked, and every later key for a known sender is ignored—including legitimate rotation. **Change:** implement authenticated member/sender identities and monotonic key epochs, rotating and redistributing keys on membership changes.

47. **MAJOR — `natively/node.py:116`, `natively/node.py:231`: Group state has multiple unsynchronized writers.** CLI processes and the daemon load independent snapshots; one can overwrite another’s advanced sender/receiver state. Enqueued group messages can also survive a crash before their sender counter is saved. **Change:** make the daemon the sole transactional owner of group ratchets and enqueue operations.

48. **MAJOR — `natively/node.py:171`: Existing sessions cannot accept a legitimate new handshake.** Any existing receive session causes a new X3DH ephemeral to be ignored, so session loss/reinitialization on one endpoint can permanently wedge communication. **Change:** add authenticated session identifiers and an explicit replacement protocol retaining necessary outstanding-message state.

49. **MINOR — `natively/node.py:277`: Loopback bypasses the advertised conformance path.** It creates an unsigned partial envelope, has no receipt/durable message-ID lifecycle, and silently deletes requests whose local recipient cannot be found. **Change:** route loopback through the same signed, idempotent delivery/receipt machinery.

50. **MAJOR — `natively/node.py:406`: Remote identifiers escape storage directories.** The probe resolved `msg_id="../../state"` to the node’s `state.json`; group IDs and directory-provided peer fingerprints also reach filesystem paths unchecked. **Change:** validate canonical identifier grammars and enforce directory containment before every identifier-based file access.

51. **MAJOR — `natively/hub.py:119`: HTTP body framing is unsafe.** Negative `Content-Length` reaches `read(-1)`, bypassing the cap; malformed lengths raise, oversized register/message requests return inconsistent errors, and unread bodies remain on persistent connections. **Change:** strictly validate request framing, reject unsupported transfer encoding, and close rejected/incomplete requests.

52. **MAJOR — `natively/hub.py:288`, `natively/node.py:36`: Network resource limits are incomplete.** The server permits unlimited threads and blocking body reads; clients read unlimited responses. JSON has no protocol depth/container/string bounds, and Python’s integer digit guard does not enforce JCS-compatible numeric ranges. **Change:** apply connection, time, byte, nesting, collection, and numeric limits before expensive decoding or cryptographic work.

53. **MINOR — `natively/cli.py:163`: Blob integrity checking disappears under optimization.** `python -O` removes the hash assertion while the command still prints “sha256 verified.” **Change:** use an explicit comparison and exception before atomically publishing the output file.

54. **MAJOR — `natively/cli.py:181`: The signing workflow requires principal secrets beside node secrets.** Grant issuance constructs `Node`, requiring its private keys, and then reads the principal seed; agent issuance has the same coupling. The provided CLI cannot perform the specified public-document-only signing workflow on the principal’s separate machine. **Change:** split offline signing from node installation, accepting public cards/enrollment documents as signer inputs.

55. **MINOR — `natively/node.py:24`, `BOOTSTRAP.md:43`: Secret-file permissions are not reliably enforced.** Mode `0600` applies only on creation, existing symlinks are followed, and bootstrap writes its private PEM using ordinary umask-dependent `open`. Node-home directories are not made private. **Change:** use private directories and checked, non-symlink, mode-enforced secret-file creation.

56. **MAJOR — `natively/node.py:595`, `natively/cli.py:24`: Initialization silently destroys existing identities.** Re-running initialization truncates principal/node/prekey files while retaining cards and sessions bound to the previous keys. **Change:** refuse initialization into an existing identity and provide a separate explicit rotation procedure.

57. **MINOR — `Dockerfile:1`: The public hub runs as root.** No `USER` changes the base image’s default privilege. **Change:** run as a dedicated unprivileged UID owning only the required data directory.

58. **MINOR — `Dockerfile:1`, `requirements.txt:1`: Builds are not reproducible.** The floating Python image and open-ended PyNaCl requirement allow unchanged source to deploy different cryptographic dependencies. **Change:** lock the dependency graph with hashes and pin the reviewed image digest.

59. **MAJOR — `tests/itest.sh:2`: The test harness can damage unrelated work.** Failure invokes `pkill -f natively`; startup deletes a fixed directory and uses a fixed port/import path. **Change:** use an isolated temporary directory, repository-derived imports, an allocated port, and an EXIT trap that cleans up only recorded child PIDs.

60. **MAJOR — `tests/itest.sh:31`, `tests/itest.sh:53`: The script does not establish most claimed behavior.** It attempts pairwise messages, groups, one attachment, and one granted ping, but mostly prints results; group-send failure is masked, and `cmp ... && echo ...` does not stop execution on mismatch under `set -e`. Ledger verification alone cannot prove delivery or authorization. **Change:** make every expected result and child-process health condition an explicit assertion.

The package has no automated coverage for canonical interoperability, rejected authority, revocation/delegation, replay/crash recovery, hostile input, concurrent state updates, or bounded resource use. The three tests that would most raise confidence are:

- **MAJOR — `tests/itest.sh:58`: Add a parameterized conformance/authorization test** using independent JCS/signature vectors and proving that every invalid subject, executor, constraint, budget, delegation, and revocation case produces zero actions.
- **MAJOR — `tests/itest.sh:29`: Add a fault-injected delivery/restart test** covering lost POST responses, lost acks, duplicate/reordered delivery, crash points, two local group recipients, and repeatable attachment downloads, while asserting exactly-once effects and recoverable ledgers.
- **MAJOR — `tests/itest.sh:8`: Add a concurrent hub durability/resource test** covering malformed bodies, slow clients, ownership replacement, quota exhaustion, queue retention, and restart, with measured bounds and no acknowledged-data loss.

Additional specification/documentation divergences:

61. **MAJOR — `natively/crypto.py:238`: `nv1` does not implement the specified key agreement and recovery properties.** X3DH repeats `EK × SPK` instead of including the recipient identity DH; optional one-time-prekey input has no matching responder support. Nodes retain a static prekey and use separate one-way channels without a DH ratchet on replies. Compromising that retained prekey permits reconstruction from recorded handshakes. **Change:** implement the specified authenticated X3DH/Double Ratchet lifecycle with interoperable vectors. [X3DH specification](https://signal.org/docs/specifications/x3dh/)

62. **MAJOR — `natively/crypto.py:196`, `natively/crypto.py:215`: Ratchet bounds and failure semantics are incorrect.** `_skip_to(1000)` stored 999 keys despite `MAX_SKIP=200`; the limit moves with the loop, `pn` is ignored, and failed authentication consumes state. SenderKey’s aggregate skipped-key store also grows without bound. **Change:** validate counters, enforce fixed skip/storage limits, honor `pn`, and commit ratchet changes only after successful authentication. [Double Ratchet specification](https://signal.org/docs/specifications/doubleratchet/#decrypting-messages)

63. **MAJOR — `natively/node.py:185`, `natively/node.py:211`: Principals are not session recipients.** Pairwise and group keys are distributed only to nodes/agents; the pinned principal public key is never used to provide the mandatory audit access in §§1 and 9. **Change:** include authenticated principal recipients in session establishment and group-key distribution.

64. **MINOR — `natively/node.py:227`: Group transport performs N pairwise sends.** The shared group ciphertext is independently wrapped and queued for each member, contrary to §9’s single-ciphertext fan-out requirement. **Change:** implement signed group-ciphertext fan-out with authenticated per-member delivery accounting.

65. **MINOR — `natively/node.py:240`, `natively/node.py:466`: Threading and receipt semantics are incomplete.** The outbox cannot preserve `in_reply_to`; acks leave it null, and there is no distinct read-receipt operation. **Change:** carry signed reply references through queueing and define/implement explicit delivery versus read receipt behavior.

66. **MINOR — `natively/ledger.py:38`, `BOOTSTRAP.md:135`: Ledger hash formats disagree.** Code hashes canonical entry content without `prev_hash_chain`, uses hexadecimal hashes and `"GENESIS"`; bootstrap requires hashes of exact previous-line bytes, base64, and null genesis. SPEC.md does not resolve these choices. **Change:** specify one byte-level ledger/hash format in SPEC.md and align code and bootstrap with published vectors.

67. **MAJOR — `BOOTSTRAP.md:88`: The bootstrap teaches an insufficient conformance test.** `canonicaljson` is a different canonicalization scheme, and verifying the same saved `msg` proves only a signature round trip—not JCS interoperability or correct envelope reconstruction. **Change:** use a conforming JCS implementation and verify independently specified canonical bytes reconstructed from the received object. [canonicaljson project](https://github.com/matrix-org/python-canonicaljson)

68. **MINOR — `BOOTSTRAP.md:67`, `README.md:50`, `llms.txt:5`: Published bootstrap/schema versions are stale.** The card uses obsolete field names and omits required version/lifetime fields; the grant uses placeholder keys/card hashes and an unbound resource. Bootstrap PEM keys also cannot be loaded by the CLI’s hex-seed reader. **Change:** regenerate the executable bootstrap from current, tested CLI/schema examples and update all version references.

69. **MINOR — `SPEC.md:129`, `SPEC.md:170`: Some normative rules remain ambiguous enough to prevent independent interoperability.** “Defaults to 1” conflicts with “never neither” unless issuance and wire validation are distinguished; message ordering is assigned to ledgers without a transmitted ordering/reconciliation contract. **Change:** specify omission semantics, ordering references, receipt schema, and exact `nv1` wire/KDF parameters in SPEC.md.

Prioritize these ten changes:

1. Authenticate enrollment, cards, directory ownership, and prekeys against pinned principal roots.
2. Constrain every filesystem identifier and bind grant lookup/accounting to the signed grant ID.
3. Complete grant enforcement for executor, capabilities, constraints, budgets, delegation, expiry, and revocation.
4. Verify every envelope and bind acknowledgements to the expected recipient before changing state.
5. Replace the nonconforming JCS and cryptographic session algorithms with independently tested implementations.
6. Make sending, receiving, deduplication, grant accounting, and ledger updates durably recoverable transactions.
7. Replace hub snapshots and count-only limits with durable bounded storage, byte quotas, and backpressure.
8. Make blobs durable, repeatably readable, and retained until authorized consumers finish.
9. Repair group membership, sender authentication, rotation, local fan-out, and concurrent state ownership.
10. Replace the smoke script with the three asserted conformance, recovery, and resource tests above.

VERDICT: BLOCK

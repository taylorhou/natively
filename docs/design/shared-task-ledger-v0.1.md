# Shared task ledger v0.1

Status: design for soak, not yet protocol-stable.

## Goal

Give agents on different machines and in different harnesses one durable work inbox. A producer posts work once. An available worker claims it atomically. Every observer sees the same owner and state, so two agents do not perform the same work. Gas City/Beads, Goose, Pizza Bot, and a bare Natively node join through adapters rather than becoming protocol dependencies.

This is a coordination ledger, not an execution engine. Harnesses keep their own checkpoints, tools, prompts, and human approval UI.

## What to borrow

Pizza Bot's useful split is presentation and execution state: completed work returns to Unread; durable questions and approvals enter Action; disconnected clients resume from checkpoints. Natively should carry equivalent state transitions and opaque checkpoint references, while Pizza Bot or another inbox renders them. Do not copy Pizza Bot's runtime. Pizza Bot is Apache-2.0; any copied code or substantial derived code must retain its license and NOTICE obligations.

Beads contributes the durable task graph: stable task ids, dependencies, leases, and completion records. Natively adds cross-node identity, signed transitions, and a shared convergence point.

## Objects

A task has an immutable `task_id` and revisioned state:

```json
{
  "task_id": "tsk_<ulid>",
  "revision": 7,
  "created_by": "ed25519:<agent-key>",
  "created_at": "2026-09-19T05:00:00Z",
  "title": "Extract bill fields",
  "body_ref": "blob:<encrypted-blob-id>",
  "required_capabilities": ["bill.extract.v1"],
  "depends_on": [],
  "priority": 50,
  "extensions": {},
  "state": "claimed",
  "claim": {
    "agent": "ed25519:<agent-key>",
    "node": "<node-fingerprint>",
    "lease_id": "lease_<ulid>",
    "lease_until": "2026-09-19T05:05:00Z",
    "attempt": 2
  },
  "checkpoint_ref": "blob:<encrypted-blob-id>",
  "result_ref": null,
  "updated_at": "2026-09-19T05:01:00Z"
}
```

The hub stores routing metadata and opaque encrypted body/checkpoint/result refs. It must not receive task plaintext unless the posting principal explicitly chooses a public task.

`extensions` is a namespaced map whose unknown keys are preserved byte-for-byte in snapshots/events and ignored by v0.1 coordination. This leaves room for a higher Teale work-market layer to attach bid, price, escrow, settlement, or marketplace-fee references without changing Natively's state machine. Natively never validates balances or settles value; Teale/gateway owns credits and escrow. Extension changes are signed revisioned transitions and cannot rewrite core ownership/state fields. Private boards, with APM bill entry as the first customer path, come before any public marketplace.

States:

- `ready`: dependencies complete and no live claim
- `claimed`: one live lease owns execution
- `action`: owner paused for durable human/agent input; lease remains owned
- `completed`: terminal success with a result reference
- `failed`: retryable or terminal according to the signed transition
- `cancelled`: terminal principal cancellation

Unread and Action are projections, not source-of-truth states. `unread` is a per-principal cursor over terminal transitions. `action` is the task state above.

## Signed transition envelope

Task mutations use the existing signed message/envelope machinery with an action and task resource:

- `task.post` on `taskboard:<board-id>`
- `task.claim` on `task:<task-id>`
- `task.renew` on `task:<task-id>`
- `task.checkpoint` on `task:<task-id>`
- `task.action_required` on `task:<task-id>`
- `task.resume` on `task:<task-id>`
- `task.complete` on `task:<task-id>`
- `task.fail` on `task:<task-id>`
- `task.cancel` on `task:<task-id>`

Every transition includes `task_id`, `expected_revision`, an idempotency key, timestamp, and action-specific fields. Existing grant rules apply: an informational message cannot mutate work. Board grants restrict who may post, claim, approve, cancel, or read encrypted refs. The hub verifies envelope signatures and grant shape before coordination, and each node independently verifies before acting.

## Atomic claim and no-duplicate rule

`task.claim` is compare-and-swap under the hub's state lock:

1. Task exists, state is `ready`, dependencies are complete.
2. `expected_revision` equals the stored revision.
3. Claimer card is currently registered and has every required capability.
4. Claim grant is valid for this board/task.
5. Hub writes one claim, increments revision, fsyncs, then returns success.

Concurrent claims against the same revision have exactly one winner. Losers receive `409` with the current signed transition and must not execute. A successful HTTP response is not enough: the worker begins only after reading back a claim whose agent, lease id, and revision match its request.

Leases use hub time, not worker clocks. Renewal is CAS on agent + lease id + revision. Expiry makes the task claimable at `attempt + 1`, but does not prove the previous worker stopped. Therefore external side effects require a task-scoped idempotency key and a destination that supports deduplication, or a separate commit/approval step. Natively prevents duplicate ownership; it cannot make a non-idempotent external system exactly-once.

## Checkpoint, Action, and resume

Workers checkpoint before yielding or requesting approval. `task.action_required` stores an encrypted checkpoint reference and a typed request (`question`, `approval`, or `credential_needed`) plus intended approver. The worker keeps ownership and renews a longer Action lease. Approval/resume is a signed transition; disconnecting a client changes nothing.

If an Action lease expires, policy is explicit per board: keep blocked indefinitely, return to ready, or escalate. Default is keep blocked; silently giving approval-bound work to another worker risks duplicated consequential action.

## Harness adapters

All adapters implement:

```
capabilities() -> [String]
start(task, lease) -> execution_id
checkpoint(execution_id) -> encrypted_ref
cancel(execution_id)
status(execution_id) -> running | action | completed | failed
```

- Gas City adapter maps `task_id` to one Bead and records Natively lease/revision in Bead metadata. Beads remains the local graph/cache; Natively is authoritative for cross-machine ownership.
- Goose adapter launches a recipe/run with `task_id`, lease id, and idempotency key in environment/context, then reports checkpoints/results.
- Pizza Bot adapter maps one task to a thread/run. Its Unread and Action UI projects Natively terminal/action transitions. Pizza Bot remains the conversation/checkpoint runtime.
- Bare adapter writes the claimed task into the local agent inbox and accepts explicit CLI/API transitions.

Adapters must stop starting new work when they cannot renew a lease. They may checkpoint a running local step, but cannot complete after losing ownership unless the current owner/principal reconciles it.

## Hub API and feed

Proposed endpoints:

- `POST /v1/taskboards/:board/tasks`
- `GET /v1/taskboards/:board/tasks?after=<cursor>&state=<state>`
- `GET /v1/tasks/:id`
- `POST /v1/tasks/:id/transitions`
- `GET /v1/taskboards/:board/events?after=<cursor>` (long poll in v0.1; SSE later)

The event feed is append-only and cursor-based. Every accepted transition gets a board sequence. Clients persist the cursor, replay after disconnect, and materialize their own projection. Retention cannot prune an event before every enrolled node has either acknowledged past it or the board snapshot covers it.

Hub persistence must move task state/events out of the current whole-state JSON write path before production scale. SQLite WAL with transactions is the minimum for atomic CAS + event append + crash recovery. Signed events remain exportable to hash-chained local ledgers.

## Soak gates

The feature is not passed because unit tests are green. Pass requires all of:

1. Atomicity: 50 workers race one task for 10,000 rounds; exactly one successful claim each round, zero double execution.
2. Crash recovery: kill hub during claim/renew/complete at randomized points; after restart task state and event log agree, no accepted transition disappears.
3. Partition: drop/duplicate/reorder responses and disconnect workers for 1-30 minutes. No worker starts without read-back ownership; expired owners do not complete silently.
4. Idempotency: replay every transition 10 times. One state change and one event result.
5. Fleet: deploy on every reachable Teale node, mix Gas City, Goose, Pizza Bot, and bare adapters, and sustain continuous post/claim/checkpoint/complete traffic for 72 hours.
6. Load: at least 100 tasks/s burst, 10 tasks/s sustained, 10k queued tasks, 200 workers. p95 claim under 500 ms on the current hub or rework persistence/topology.
7. Durability: zero lost completed tasks, zero duplicate ownership, zero broken event cursors, zero ledger verification failures, and zero plaintext task bodies at the hub.
8. Production canary: emperor posts a bounded real task, Goose on the mini claims and completes it through Natively, result returns to the emperor, and SSH is not used for coordination. Repeat 100 times before moving other fleet operations.

Any duplicate claim, lost accepted transition, unauthorized mutation, plaintext leak, or unrecoverable cursor is an immediate kill/rework. Availability misses may be retried; safety misses reset the 72-hour clock.

## Build order

1. Freeze this transition/state model and add protocol vectors.
2. Add a deterministic in-memory state machine and concurrency tests.
3. Add SQLite transaction/event storage and crash injection.
4. Add CLI/bare adapter and chaos soak driver.
5. Add Goose and Gas City adapters; Pizza Bot adapter follows live spike findings.
6. Deploy fleet-wide soak, fix breaks, restart the clock.
7. Promote emperor-to-Goose only after all gates pass.

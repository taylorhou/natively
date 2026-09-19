# Natively v0 soak gate

Current verdict: **not passed**.

## What exists

- Signed cards, messages, grants, acks, revocation, groups, encrypted blobs, retry/dead-letter handling, and hash-chained local ledgers.
- Hub admission/queue quotas, persistence, auth, long poll, shutdown flush, queue pruning, and blob durability tests.
- A real-process integration journey for two nodes, three agents, 1:1, group, blob, granted action, ack drain, and ledger verification.
- Prior live traffic across several machines and two organizations.

A focused reliability subset on current main passed locally (38 tests covering conformance, durability, retries, send idempotency, hub load/prune, and parallel flush). The complete suite is too slow for this sandbox's 120-second execution window and has no CI workflow in the repository, so current-main whole-suite status is not established here.

## What blocks "proven"

1. No committed, repeatable fleet soak driver or result artifact. Prior dogfood found bugs but does not establish a current-main pass window.
2. No CI workflow runs the suite or the real-process integration journey on each change.
3. No declared release/commit under soak and no reproducible node inventory/config snapshot.
4. No 72-hour current-main continuous run with explicit safety/error counters.
5. Fleet enrollment is incomplete, and the first production path (emperor to Goose on mini) is still SSH rather than Natively.
6. The hub is one Fly process with whole-state JSON persistence, thread-per-request long polls, and no HA. It is adequate for the v0 soak scale, but restart/corruption/partition injection must be measured before production dependency.
7. Async shared-task claim semantics are designed separately; they are not implemented and are not a prerequisite for proving the existing message plane. They become v0.1 unless the v0 soak exposes a message-plane dependency.

## Pass protocol

Pin one commit. Deploy it to every reachable fleet node with per-node venvs and durable homes. Record node/agent fingerprints, versions, and hub version without private keys.

Run continuous mixed traffic:

- bidirectional 1:1 messages and acknowledgements;
- group fan-out and membership change;
- encrypted 1 KB, 200 KB, 5 MB, and 50 MB blobs with hash verification;
- granted actions, expiry, exhaustion, revocation, and unauthorized attempts;
- process restart, hub restart, network loss, duplicate POST/response loss, delayed poll, and disk-near-quota cases;
- a low-rate real workload alongside synthetic traffic.

Every minute, append a signed result record with sent, delivered, acknowledged, duplicate deliveries, dead letters, p50/p95/p99 latency, queue depth/bytes, retries, blob hash mismatches, ledger verification, and node/hub restarts. Aggregate centrally but keep raw per-node evidence.

Pass only after 72 continuous hours on the same commit with:

- zero unauthorized actions;
- zero duplicate action execution;
- zero lost accepted messages or completed blob transfers;
- zero blob hash mismatches;
- zero ledger verification failures;
- zero stuck unacked messages after a 10-minute recovery budget;
- at least 99.9% delivery/ack within 60 seconds outside injected partitions;
- successful recovery from every scheduled hub/node restart;
- p95 delivery under 5 seconds and p99 under 30 seconds at the soak rate.

A safety failure resets the clock after a fix. An availability miss needs a grounded fix or an explicit tighter operating envelope, then resets the clock. After pass, run 100 emperor-to-Goose tasks over Natively with no SSH coordination before migrating more fleet operations.

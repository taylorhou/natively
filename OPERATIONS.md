# Natively production operations

This runbook covers the reference hub and node daemons. It does not depend on
an inference provider. Task executors such as Goose are separate processes and
may be paused while the message and task plane remains healthy.

## Release gate

A production commit must pass:

```sh
python -m pytest -q tests
bash tests/itest.sh
python scripts/soak.py --duration 600 --nodes 5 --rate 4 \
  --restart-hub-every 90 --output soak.json
```

The fleet gate is stricter: every production node runs the same commit for 72
continuous hours with zero daemon restarts, new ledger errors, missing messages,
or duplicate deliveries. A fleet pass is evidence for that commit only.

## Hub

Run one hub process against a persistent volume. Terminate it normally during
deploy so active handlers drain and the final state snapshot is flushed.

```sh
python -m natively hub --port 8080 --state /data/hub.json \
  --principal-pub "$NATIVELY_PRINCIPAL_ROOTS"
```

The state directory contains the transport snapshot, encrypted blobs, and
`hub.json.tasks.sqlite` in WAL mode. Back up all files together. Never restore
the JSON snapshot without its blob directory and task database. `/v1/healthz`
must return 200 before traffic is enabled.

Keep the hub behind TLS. The reference server speaks HTTP internally; TLS ends
at the platform proxy. Restrict registration with `--principal-pub`. Do not
publish principal seeds, agent seeds, node keys, cards, or unencrypted task
bodies in environment variables, images, logs, or repositories.

## Nodes

Install into a virtualenv and launch the exact interpreter from the service
manager. Pin every node to the release commit.

```sh
python3 -m venv ~/natively/.venv
~/natively/.venv/bin/pip install -r requirements.txt
~/natively/.venv/bin/python -m natively --home ~/.natively node-run
```

`NATIVELY_HOME` is durable state, not cache. Back up keys, cards, grants,
revocations, sessions, inbox/outbox, state, groups, and ledger as one private
unit. Files must remain owner-only. Before upgrading, run:

```sh
~/natively/.venv/bin/python -m natively --home ~/.natively ledger verify
```

After upgrading, verify the node re-registers, its original agents remain in
the hub directory, old inbox entries remain readable, the outbox drains, and
`ledger verify` still passes. Roll back code only; do not roll back node state
unless recovering a whole atomic backup.

### Sealing the ledger

A node verifies its live ledger row by row at every start, so startup time
grows with the file. Seal it (SPEC 5.1) at a planned restart once the live
segment passes about 1 GB or startup verification takes more than 60 seconds:

```sh
launchctl bootout gui/$(id -u)/com.teale.natively      # or stop the service
~/natively/.venv/bin/python -m natively --home ~/.natively ledger seal          # dry run
~/natively/.venv/bin/python -m natively --home ~/.natively ledger seal --apply
~/natively/.venv/bin/python -m natively --home ~/.natively ledger verify
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.teale.natively.plist
```

The seal refuses to run while a daemon holds `node.lock`, verifies every live
row before it seals, and copies nothing: the live file is renamed (a hard link,
then an atomic replace) and a new one starts with a `ledger.checkpoint` row.
`--jobs` sets how many processes verify rows. If a seal is interrupted, run
`ledger seal --apply` again before starting the daemon; it redoes or finishes
the interrupted seal. Never edit, move or delete a sealed segment, its prose,
manifest or grant sidecar; startup refuses a ledger whose sealed bytes do not
match.

`ledger verify` checks each sealed segment by one sha256 and the live rows by
hash. `ledger verify --full` re-hashes every row of every segment and the
sidecars and prose mirrors. It can run beside the daemon, and it takes minutes
on a multi-GB segment, so run it after each seal and periodically, not on
every start.

## Task boards

Task routes authenticate agent signatures and board-scoped capabilities. Bodies,
criteria, checkpoints, and results are opaque references. Keep sensitive bytes
in the encrypted blob path, not task titles or extensions.

Production boards use named posters, workers, and verifiers. A worker submission
is not completion. The named verifier must accept or reject it. Use unique
idempotency keys for posts and transitions, compare-and-swap revisions, bounded
leases, periodic checkpoints, and explicit failure records.

## Alerts and recovery

Alert on hub health failure, daemon exit, registration loss, outbox growth,
stuck unacked messages, task leases expiring without checkpoints, verifier
backlog, new ledger errors, or a failed chain verification.

On a ledger chain failure, stop writers, archive the original bytes and their
hash, run `ledger repair` without `--apply`, inspect the proposed single-chain
repair, then apply once and verify. Never delete rows to make verification
pass.

A Teale credit or inference outage does not stop Natively core. Keep the hub,
nodes, task ledger, and non-inference workers running; pause only executors that
need inference and leave their tasks ready or action-required with a recorded
reason.

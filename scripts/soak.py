#!/usr/bin/env python3
"""Deterministic Natively safety soak with crash/restart evidence.

This is the CI/local floor, not the fleet pass. It creates isolated node homes,
sends continuous signed 1:1 traffic through a real threaded hub, restarts the
hub on the same port, and fails on loss, duplicate inbox delivery, stuck acks,
or ledger corruption. The fleet 72-hour run uses the same result schema.
"""
import argparse
import collections
import json
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from natively import crypto, hub as hubmod, jcs, node as nodemod  # noqa: E402


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class RestartableHub:
    def __init__(self, path, port):
        self.path, self.port = str(path), port
        self.server = self.thread = self.state = None

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.port

    def start(self):
        self.state = hubmod.State(self.path)
        self.state.POLL_WAIT = 0.01
        self.server = hubmod.make_server(self.port, self.state)
        # Keep make_server's non-daemon handler contract. server_close() must
        # join every in-flight handler before State.close() and before the
        # replacement State opens the same state.json path. Overriding this
        # to True let an old handler and the restarted hub share
        # state.json.tmp, producing intermittent FileNotFoundError at rename.
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.01},
            daemon=True,
        )
        self.thread.start()

    def stop(self):
        if not self.server:
            return
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.state.close()
        self.server = self.thread = self.state = None

    def restart(self):
        self.stop()
        self.start()


def inbox_records(node, agent):
    path = Path(node.home) / "inbox" / agent
    if not path.is_dir():
        return []
    records = []
    for item in path.glob("*.json"):
        try:
            records.append(json.loads(item.read_text()))
        except (OSError, ValueError):
            pass
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--nodes", type=int, default=5)
    ap.add_argument("--rate", type=float, default=4.0, help="total messages/second")
    ap.add_argument("--restart-hub-every", type=int, default=0)
    ap.add_argument("--output", default="soak.json")
    args = ap.parse_args()
    if args.nodes < 2 or args.duration < 1 or args.rate <= 0:
        ap.error("nodes >= 2, duration >= 1, and rate > 0 are required")

    started = time.time()
    failures = []
    latencies = []
    sent = {}
    delivered_at = {}
    restarts = 0
    with tempfile.TemporaryDirectory(prefix="natively-soak-") as temp:
        base = Path(temp)
        principal_seed = crypto.gen_signing_key()
        principal_pub = crypto.b64e(crypto.sign_pub(principal_seed))
        hub = RestartableHub(base / "hub" / "state.json", free_port())
        (base / "hub").mkdir()
        hub.start()
        nodes = []
        try:
            for i in range(args.nodes):
                home = base / ("node-%02d" % i)
                nodemod.init_node(str(home), "soak-%02d" % i, hub.url, principal_pub)
                nodemod.add_agent(str(home), "worker", principal_seed, ["msg.send"])
                node = nodemod.Node(str(home))
                node.start()
                nodes.append(node)

            # All cards must be visible before traffic starts.
            deadline = time.time() + 15
            while time.time() < deadline:
                for node in nodes:
                    node.step()
                if all(node._last_reg_time for node in nodes):
                    break
            if not all(node._last_reg_time for node in nodes):
                raise RuntimeError("not every node registered")

            interval = 1.0 / args.rate
            next_send = time.monotonic()
            next_restart = (time.monotonic() + args.restart_hub_every
                            if args.restart_hub_every else float("inf"))
            sequence = 0
            end = time.monotonic() + args.duration
            while time.monotonic() < end:
                now = time.monotonic()
                if now >= next_restart:
                    hub.restart()
                    restarts += 1
                    next_restart = now + args.restart_hub_every
                if now >= next_send:
                    source = nodes[sequence % len(nodes)]
                    target = nodes[(sequence + 1) % len(nodes)]
                    marker = "soak:%08d:%s" % (sequence, jcs.sha256(os.urandom(16))[:16])
                    recipient = target.agents["worker"]["card"]["agent_key"]
                    source.queue_send("worker", recipient, {"kind": "text", "text": marker})
                    sent[marker] = time.time()
                    sequence += 1
                    next_send += interval
                for node in nodes:
                    node.step()
                for node in nodes:
                    for record in inbox_records(node, "worker"):
                        marker = record.get("body", {}).get("text")
                        if marker in sent and marker not in delivered_at:
                            delivered_at[marker] = time.time()
                time.sleep(0.005)

            # Recovery budget: everything accepted into a local outbox must
            # deliver and ack after the final restart/partition.
            deadline = time.time() + 60
            while time.time() < deadline:
                for node in nodes:
                    node.step()
                for node in nodes:
                    for record in inbox_records(node, "worker"):
                        marker = record.get("body", {}).get("text")
                        if marker in sent and marker not in delivered_at:
                            delivered_at[marker] = time.time()
                if len(delivered_at) == len(sent) and all(not n.state["unacked"] for n in nodes):
                    break
                time.sleep(0.01)

            counts = collections.Counter()
            for node in nodes:
                for record in inbox_records(node, "worker"):
                    marker = record.get("body", {}).get("text")
                    if marker in sent:
                        counts[marker] += 1
                if not node.ledger.verify_chain():
                    failures.append("ledger verification failed: %s" % node.name)
                if node.state["unacked"]:
                    failures.append("stuck unacked on %s: %d" % (node.name, len(node.state["unacked"])))
            missing = sorted(set(sent) - set(delivered_at))
            duplicate = sorted(k for k, count in counts.items() if count != 1)
            if missing:
                failures.append("missing deliveries: %d" % len(missing))
            if duplicate:
                failures.append("non-single inbox deliveries: %d" % len(duplicate))
            latencies = [delivered_at[k] - sent[k] for k in delivered_at]
        finally:
            for node in nodes:
                node.stop()
            hub.stop()

    ordered = sorted(latencies)
    def percentile(p):
        if not ordered:
            return None
        return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * p))]
    result = {
        "schema": "natively.soak.v1",
        "started_at": started,
        "duration_seconds": time.time() - started,
        "config": vars(args),
        "sent": len(sent),
        "delivered": len(delivered_at),
        "hub_restarts": restarts,
        "latency_seconds": {"p50": percentile(.50), "p95": percentile(.95), "p99": percentile(.99)},
        "failures": failures,
        "passed": not failures,
    }
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

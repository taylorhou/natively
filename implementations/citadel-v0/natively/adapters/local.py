"""In-process transport: two nodes, bundles handed across directly. Used by the
two-agent proof and by anyone who wants to watch the protocol without a mailbox."""

from __future__ import annotations

from typing import Any

from ..node import Node


class LocalWire:
    def __init__(self):
        self.log: list[tuple[str, str, str]] = []  # (from, to, kind)

    def deliver(self, sender: Node, receiver: Node, b: dict[str, Any]) -> list[dict[str, Any]]:
        """Send one bundle sender -> receiver; feed every reply (acks) straight back to
        the sender. Returns the replies. Duplicates are delivered as the transport
        would: the caller may deliver the same bundle twice. EVERY input bundle
        crosses the sender's outgoing boundary here (`Node.check_outgoing`: an ack
        through the ONE reply validation, a message, a card or a revocation through
        its own kind's check), exactly as MailWire.send does, BEFORE it is recorded,
        logged or delivered: one that fails is IntegrityError <kind>.invalid and
        nothing is recorded, logged or delivered. EVERY automatic reply the receiver
        returns crosses the RECEIVER's outgoing boundary the same way — the one
        reply validation AND the wire's size bound (`check_outgoing`, never
        `check_reply` alone: a correctly signed ack over 512 KiB was logged and
        delivered here while the wire's send refused it, round-15 gate, finding 3)
        — BEFORE it is logged or delivered: an oversized or otherwise unsound reply
        is <kind>.invalid, a storage failure, nothing logged as sent, nothing
        delivered."""
        sender.check_outgoing(b)
        sender.outbox_record(b, transport_ref="local")
        self.log.append((sender.card["agent"]["name"], receiver.card["agent"]["name"], b["kind"]))
        replies = receiver.receive(b)
        for r in replies:
            receiver.check_outgoing(r)  # the receiver's outgoing boundary: <kind>.invalid
            self.log.append(
                (receiver.card["agent"]["name"], sender.card["agent"]["name"], r["kind"])
            )
            sender.receive(r)
        return replies

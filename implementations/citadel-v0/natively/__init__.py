"""Natively v0 on citadel — SPEC.md v0.2 (github.com/taylorhou/natively @ ad36d9a).

Protocol objects (card, grant, message, ack, ledger, revocation, standing denial),
the executor, the node state machine, and two transport adapters (in-process,
Gmail wire). The library never touches the network; only adapters/mail.py does.
"""

PROTOCOL_VERSION = "v0"

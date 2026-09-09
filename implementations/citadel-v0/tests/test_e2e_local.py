"""The two-agent proof: A (citadel) and B (instinct) in one process, no mail.
Cards each way, information each way with acks, one grant-scoped fs.write each way,
a refused out-of-scope action, a revoked grant, a standing denial, a parent-grant
subset failure (and the matching success), a duplicate delivery; both ledgers verify
and the heads match through the acks at every step."""

from __future__ import annotations

import pytest

from natively import grant as grantmod
from natively.adapters.local import LocalWire
from natively.errors import IntegrityError, VerifyError

from .conftest import Clock, make_node

STATEMENT = "Write one greeting file into the other side's scratch directory, once."


def heads_match(sender, receiver):
    """The head the receiver reported in its last ack equals its real head now."""
    assert sender.peer_head(receiver.agent.public) == receiver.ledger.head()


def latest(node):
    return node.ledger.entries()[-1]


@pytest.fixture
def pair(tmp_path):
    clock = Clock()
    reports: list[str] = []
    a = make_node(
        tmp_path, "citadel-mayor", clock, extensions={"standing_denial": True}, reports=reports
    )
    b = make_node(
        tmp_path, "instinct", clock, extensions={"standing_denial": True}, reports=reports
    )
    # Out of band, each side pins the other's principal root (a human step in the live run).
    a.pin(b.principal.public, "instinct-principal (stand-in)")
    b.pin(a.principal.public, "citadel-principal (stand-in)")
    wire = LocalWire()
    return a, b, wire, clock, reports


def fs_write_scope(executor, name, regex="^[ -~\n]+$"):
    return [
        {
            "action": "fs.write",
            "resource": executor.executor().resource_for(name),
            "params": {"keys": ["content"], "values": {"content": {"regex": regex}}},
        }
    ]


def test_two_agents_end_to_end(pair):
    a, b, wire, clock, reports = pair

    # 1. cards each way
    wire.deliver(a, b, a.compose_card())
    wire.deliver(b, a, b.compose_card())
    assert b.card_for_key(a.agent.public)["agent"]["name"] == "citadel-mayor"
    assert a.card_for_key(b.agent.public)["agent"]["name"] == "instinct"
    a.mark_lookup_ok()
    b.mark_lookup_ok()

    # 2. information each way, acked, heads reconciled through the acks
    replies = wire.deliver(a, b, a.compose_info(b.card, "hello from citadel"))
    assert replies[0]["kind"] == "ack" and replies[0]["object"]["outcome"] == "information"
    assert latest(b)["outcome"] == "ack" or latest(b)["action"] == "info.received"
    heads_match(a, b)
    assert a.outbox()[-1]["status"] == "acked"
    wire.deliver(b, a, b.compose_info(a.card, "hello from instinct"))
    heads_match(b, a)

    # 3. one grant-scoped fs.write each way
    g_ab = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "hello-from-citadel.txt"),
        principal_statement=STATEMENT,
    )
    replies = wire.deliver(
        a,
        b,
        a.compose_action(
            b.card,
            action="fs.write",
            resource=b.executor().resource_for("hello-from-citadel.txt"),
            params={"content": "hello, instinct\n"},
            grant_ids=[g_ab["grant_id"]],
        ),
    )
    assert replies[0]["object"]["outcome"] == "applied"
    assert (b.scratch_dir / "hello-from-citadel.txt").read_text() == "hello, instinct\n"
    assert latest(b)["grant_id"] == g_ab["grant_id"] and latest(b)["outcome"] == "applied"
    heads_match(a, b)

    g_ba = b.issue_grant(
        subject_card=a.card,
        scope=fs_write_scope(a, "hello-from-instinct.txt"),
        principal_statement=STATEMENT,
    )
    replies = wire.deliver(
        b,
        a,
        b.compose_action(
            a.card,
            action="fs.write",
            resource=a.executor().resource_for("hello-from-instinct.txt"),
            params={"content": "hello, citadel\n"},
            grant_ids=[g_ba["grant_id"]],
        ),
    )
    assert replies[0]["object"]["outcome"] == "applied"
    assert (a.scratch_dir / "hello-from-instinct.txt").read_text() == "hello, citadel\n"
    heads_match(b, a)

    # 3b. duplicate delivery of the applied action: the stored ack is re-sent, no re-apply
    dup = a.outbox()[-1]["bundle"]
    (a.scratch_dir / "hello-from-instinct.txt").write_text("touched\n")
    replies = a.receive(b.outbox()[-1]["bundle"])
    assert replies[0]["object"]["outcome"] == "applied"  # the same stored ack
    assert (a.scratch_dir / "hello-from-instinct.txt").read_text() == "touched\n"  # not rewritten
    assert a.ledger.uses(g_ba["grant_id"]) == 1
    assert dup["kind"] == "message"

    # 4. refused out-of-scope: same grant, a different file name (and the grant is spent)
    replies = wire.deliver(
        a,
        b,
        a.compose_action(
            b.card,
            action="fs.write",
            resource=b.executor().resource_for("somewhere-else.txt"),
            params={"content": "nope\n"},
            grant_ids=[g_ab["grant_id"]],
        ),
    )
    assert replies[0]["object"]["outcome"] == "refused:no_authorizing_grant"
    assert not (b.scratch_dir / "somewhere-else.txt").exists()
    assert latest(b)["outcome"] == "refused" and "grant.max_uses" in latest(b)["detail"]
    heads_match(a, b)

    # 4b. out of scope on a fresh grant: the resource does not match the scope entry
    g_scope = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "only-this.txt"), principal_statement=STATEMENT
    )
    replies = wire.deliver(
        a,
        b,
        a.compose_action(
            b.card,
            action="fs.write",
            resource=b.executor().resource_for("not-this.txt"),
            params={"content": "nope\n"},
            grant_ids=[g_scope["grant_id"]],
        ),
    )
    assert replies[0]["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "scope.no_match" in latest(b)["detail"]
    # 4c. an action the executor does not implement is refused even inside a grant
    g_other = a.issue_grant(
        subject_card=b.card,
        principal_statement=STATEMENT,
        scope=[{"action": "node.config.set", "resource": f"host:{b.host.public}:config"}],
    )
    replies = wire.deliver(
        a,
        b,
        a.compose_action(
            b.card,
            action="node.config.set",
            resource=f"host:{b.host.public}:config",
            params={},
            grant_ids=[g_other["grant_id"]],
        ),
    )
    assert "refused" in replies[0]["object"]["outcome"]
    assert "not_in_card" in latest(b)["detail"] or "executor.unsupported" in latest(b)["detail"]
    heads_match(a, b)

    # 5. revoked grant: issued, revoked, the revocation reaches B, then the action is refused
    g_rev = a.issue_grant(
        subject_card=b.card, scope=fs_write_scope(b, "revoked.txt"), principal_statement=STATEMENT
    )
    r = a.revoke(grants=[g_rev["grant_id"]], principal_statement="Never mind that file.")
    wire.deliver(a, b, a.compose_revocation(r))
    assert latest(b)["action"] == "revocation.received"
    replies = wire.deliver(
        a,
        b,
        a.compose_action(
            b.card,
            action="fs.write",
            resource=b.executor().resource_for("revoked.txt"),
            params={"content": "x\n"},
            grant_ids=[g_rev["grant_id"]],
        ),
    )
    assert replies[0]["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "grant.revoked" in latest(b)["detail"]
    assert not (b.scratch_dir / "revoked.txt").exists()
    heads_match(a, b)

    # 6. standing denial on B, signed by B's principal: a well-formed grant cannot override it
    b.deny(
        deny=[{"action": "fs.write", "resource": f"host:{b.host.public}:scratch/secret-*"}],
        principal_statement="Customer data never crosses between the deployments. Always no.",
    )
    g_den = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "secret-customers.txt"),
        principal_statement=STATEMENT,
    )
    replies = wire.deliver(
        a,
        b,
        a.compose_action(
            b.card,
            action="fs.write",
            resource=b.executor().resource_for("secret-customers.txt"),
            params={"content": "x\n"},
            grant_ids=[g_den["grant_id"]],
        ),
    )
    assert replies[0]["object"]["outcome"] == "refused:denied"
    assert latest(b)["outcome"] == "refused" and "standing denial" in latest(b)["detail"]
    heads_match(a, b)

    # 7. delegation: parent to A's agent (audience B's node); a child that is NOT a
    #    strict subset is refused; a child that is a strict subset is applied
    parent = a.issue_grant(
        subject_card=a.card,
        audience=b.host.public,
        scope=fs_write_scope(b, "delegated.txt", regex="^[a-z\n]+$"),
        principal_statement="Citadel may have Instinct write delegated.txt, lowercase only.",
        max_uses=2,
    )
    loose = a.delegate_grant(
        parent=parent,
        subject_card=b.card,
        principal_statement="loosened",
        scope=[
            {
                "action": "fs.write",
                "resource": b.executor().resource_for("delegated.txt"),
                "params": {"keys": ["content"], "values": {}},
            }
        ],
    )
    replies = wire.deliver(
        a,
        b,
        a.compose_action(
            b.card,
            action="fs.write",
            resource=b.executor().resource_for("delegated.txt"),
            params={"content": "SHOUT\n"},
            grant_ids=[loose["grant_id"]],
        ),
    )
    assert replies[0]["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "grant.delegation.not_subset" in latest(b)["detail"]
    tight = a.delegate_grant(
        parent=parent,
        subject_card=b.card,
        principal_statement="lowercase, short",
        scope=[
            {
                "action": "fs.write",
                "resource": b.executor().resource_for("delegated.txt"),
                "params": {
                    "keys": ["content"],
                    "values": {"content": {"regex": "^[a-z\n]+$", "in": ["quiet\n"]}},
                },
            }
        ],
        max_uses=1,
    )
    replies = wire.deliver(
        a,
        b,
        a.compose_action(
            b.card,
            action="fs.write",
            resource=b.executor().resource_for("delegated.txt"),
            params={"content": "quiet\n"},
            grant_ids=[tight["grant_id"]],
        ),
    )
    assert replies[0]["object"]["outcome"] == "applied", latest(b)["detail"]
    assert (b.scratch_dir / "delegated.txt").read_text() == "quiet\n"
    heads_match(a, b)

    # 8. both ledgers verify end to end; every message A sent was acked
    assert a.ledger.verify() == a.ledger.head()
    assert b.ledger.verify() == b.ledger.head()
    assert all(x["status"] == "acked" for x in a.outbox())
    assert all(x["status"] == "acked" for x in b.outbox())
    # nothing under scratch but the three files the grants named
    assert sorted(p.name for p in b.scratch_dir.iterdir()) == [
        "delegated.txt",
        "hello-from-citadel.txt",
    ]
    assert sorted(p.name for p in a.scratch_dir.iterdir()) == ["hello-from-instinct.txt"]
    # every refusal was printed (principle 5)
    assert sum("refused" in r or "rejected" in r for r in reports) >= 6
    # the prose mirror has one line per entry and reads as prose
    prose = b.ledger.prose_path.read_text().splitlines()
    assert len(prose) == len(b.ledger.entries())
    assert any("fs.write" in ln and "applied" in ln for ln in prose)


def test_tampered_ledger_fails_verify(pair):
    a, b, wire, clock, _ = pair
    wire.deliver(a, b, a.compose_card())
    wire.deliver(b, a, b.compose_card())
    wire.deliver(a, b, a.compose_info(b.card, "one"))
    lines = b.ledger.path.read_text().splitlines()
    lines[0] = lines[0].replace('"outcome":"trusted"', '"outcome":"forged"')
    b.ledger.path.write_text("\n".join(lines) + "\n")
    with pytest.raises(IntegrityError) as e:
        b.ledger.verify()
    assert e.value.reason == "ledger.chain"


def test_unpinned_sender_is_information_at_most(tmp_path):
    clock = Clock()
    reports: list[str] = []
    a = make_node(tmp_path, "a", clock, reports=reports)
    b = make_node(tmp_path, "b", clock, reports=reports)
    b.mark_lookup_ok()
    wire = LocalWire()
    # B has not pinned A's principal: A's card is held, A's message is rejected and ledgered.
    wire.deliver(a, b, a.compose_card())
    assert b.card_for_key(a.agent.public) is None
    assert (b.state / "cards-pending").exists() and list((b.state / "cards-pending").glob("*.json"))
    replies = wire.deliver(a, b, a.compose_info(b.card, "hi"))
    assert replies == []
    assert latest(b)["outcome"] == "verify_failed:message.sender.untrusted"
    assert any("message.sender.untrusted" in r for r in reports)
    # pinning promotes the held card; the resend now lands
    b.pin(a.principal.public, "a-principal")
    assert b.card_for_key(a.agent.public) is not None
    a.pin(b.principal.public, "b-principal")
    wire.deliver(b, a, b.compose_card())
    replies = wire.deliver(a, b, a.compose_info(b.card, "hi again"))
    assert replies[0]["object"]["outcome"] == "information"


def test_revocation_lookup_stale_fails_closed(tmp_path):
    clock = Clock()
    a = make_node(tmp_path, "a", clock)
    b = make_node(tmp_path, "b", clock)
    a.pin(b.principal.public, "b")
    b.pin(a.principal.public, "a")
    wire = LocalWire()
    wire.deliver(a, b, a.compose_card())
    wire.deliver(b, a, b.compose_card())
    g = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "late.txt"),
        principal_statement=STATEMENT,
        expires_in_s=24 * 3600,
    )
    bundle = a.compose_action(
        b.card,
        action="fs.write",
        resource=b.executor().resource_for("late.txt"),
        params={"content": "x\n"},
        grant_ids=[g["grant_id"]],
    )
    # never checked -> closed
    replies = wire.deliver(a, b, bundle)
    assert "revocation.never_checked" in latest(b)["detail"]
    b.mark_lookup_ok()
    clock.tick(g["revocation"]["max_check_interval_s"] + b.poll_s + 1)
    bundle2 = a.compose_action(
        b.card,
        action="fs.write",
        resource=b.executor().resource_for("late.txt"),
        params={"content": "x\n"},
        grant_ids=[g["grant_id"]],
    )
    replies = wire.deliver(a, b, bundle2)
    assert "revocation.stale" in latest(b)["detail"]
    b.mark_lookup_ok()
    bundle3 = a.compose_action(
        b.card,
        action="fs.write",
        resource=b.executor().resource_for("late.txt"),
        params={"content": "x\n"},
        grant_ids=[g["grant_id"]],
    )
    replies = wire.deliver(a, b, bundle3)
    assert replies[0]["object"]["outcome"] == "applied"


def test_grant_for_other_agent_is_information_for_me(tmp_path):
    """Confused deputy: a grant whose subject is A, attached to a message to B, never
    becomes an action on B."""
    clock = Clock()
    a = make_node(tmp_path, "a", clock)
    b = make_node(tmp_path, "b", clock)
    a.pin(b.principal.public, "b")
    b.pin(a.principal.public, "a")
    wire = LocalWire()
    wire.deliver(a, b, a.compose_card())
    wire.deliver(b, a, b.compose_card())
    b.mark_lookup_ok()
    g_self = a.issue_grant(
        subject_card=a.card, scope=fs_write_scope(a, "mine.txt"), principal_statement=STATEMENT
    )
    replies = wire.deliver(
        a,
        b,
        a.compose_action(
            b.card,
            action="fs.write",
            resource=b.executor().resource_for("mine.txt"),
            params={"content": "x\n"},
            grant_ids=[g_self["grant_id"]],
        ),
    )
    assert replies[0]["object"]["outcome"] == "refused:no_authorizing_grant"
    assert "grant.subject.agent" in latest(b)["detail"]
    assert not (b.scratch_dir / "mine.txt").exists()


def test_max_uses_per_window_extension(tmp_path):
    clock = Clock()
    a = make_node(tmp_path, "a", clock, extensions={"max_uses_per_window": True})
    b = make_node(tmp_path, "b", clock, extensions={"max_uses_per_window": True})
    a.pin(b.principal.public, "b")
    b.pin(a.principal.public, "a")
    wire = LocalWire()
    wire.deliver(a, b, a.compose_card())
    wire.deliver(b, a, b.compose_card())
    b.mark_lookup_ok()
    g = a.issue_grant(
        subject_card=b.card,
        scope=fs_write_scope(b, "w.txt"),
        principal_statement=STATEMENT,
        max_uses=5,
        max_uses_per_window={"n": 1, "window_s": 600},
        expires_in_s=7200,
    )

    def go():
        return wire.deliver(
            a,
            b,
            a.compose_action(
                b.card,
                action="fs.write",
                resource=b.executor().resource_for("w.txt"),
                params={"content": "x\n"},
                grant_ids=[g["grant_id"]],
            ),
        )[0]["object"]["outcome"]

    assert go() == "applied"
    assert go() == "refused:no_authorizing_grant"
    assert "grant.max_uses_per_window" in latest(b)["detail"]
    clock.tick(601)
    b.mark_lookup_ok()
    assert go() == "applied"
    # a node with the extension OFF refuses the envelope outright (unknown constraint)
    c = make_node(tmp_path, "c", clock)
    with pytest.raises(VerifyError) as e:
        grantmod.check_structure(g, extensions=c.extensions)
    assert e.value.reason == "grant.extension.disabled"

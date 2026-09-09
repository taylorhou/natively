"""A grant id names one object: a received grant never overwrites a different grant
already on file under the same id (it could be one this node issued)."""

from __future__ import annotations

from natively import bundle as bundlemod
from natively import grant as grantmod

from .conftest import Clock, make_node


def test_received_grant_never_overwrites_the_grant_on_file(tmp_path):
    clock = Clock()
    a = make_node(tmp_path, "a", clock)
    b = make_node(tmp_path, "b", clock)
    a.pin(b.principal.public, "b")
    b.pin(a.principal.public, "a")
    a.import_card(b.card)
    b.import_card(a.card)
    g = a.issue_grant(
        subject_card=b.card,
        scope=[{"action": "info", "resource": f"host:{b.host.public}:ping"}],
        principal_statement="one ping",
    )
    # a re-signed variant under the same id (authenticates, differs): never overwrites
    forged = dict(g)
    forged["principal_statement"] = "one ping, and then some"
    forged = grantmod.sign(forged, a.principal)
    a.receive(bundlemod.make("card", b.card, grants=[forged]))
    assert a.load_grant(g["grant_id"]) == g
    outcomes = [e["outcome"] for e in a.ledger.entries()]
    assert outcomes.count("verify_failed:grant.id_conflict") == 1
    # a tampered copy (signature no longer verifies) is rejected before any store
    tampered = dict(g)
    tampered["principal_statement"] = "tampered"
    a.receive(bundlemod.make("card", b.card, grants=[tampered]))
    assert a.load_grant(g["grant_id"]) == g
    outcomes = [e["outcome"] for e in a.ledger.entries()]
    assert outcomes.count("verify_failed:grant.sig.invalid") == 1
    # the identical grant coming back is fine (no failure, still the same object)
    a.receive(bundlemod.make("card", b.card, grants=[g]))
    assert a.load_grant(g["grant_id"]) == g
    outcomes = [e["outcome"] for e in a.ledger.entries()]
    assert outcomes.count("verify_failed:grant.id_conflict") == 1

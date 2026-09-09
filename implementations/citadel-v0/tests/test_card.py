import pytest

from natively import card as cardmod
from natively import keys
from natively.errors import VerifyError


def _card(node_kp, principal_kp, agent_kp, kind="stand-in"):
    return cardmod.build(
        agent_name="a",
        agent_key=agent_kp.public,
        node_name="n",
        node_key=node_kp.public,
        principal_name="p",
        principal_key=principal_kp.public,
        principal_kind=kind,
        capabilities=[{"action": "fs.write", "resource": f"host:{node_kp.public}:scratch/*"}],
        ledger_url="n:ledger",
        issued_at="2026-09-07T07:00:00Z",
    )


@pytest.fixture
def trio():
    return keys.KeyPair.generate(), keys.KeyPair.generate(), keys.KeyPair.generate()


def test_sign_hash_verify(trio):
    node, principal, agent = trio
    c = cardmod.sign(_card(node, principal, agent), node, principal)
    h = cardmod.verify(c)
    assert h == cardmod.card_hash(c) and h.startswith("sha256:")
    assert cardmod.verify(c, pinned={principal.public}) == h
    with pytest.raises(VerifyError) as e:
        cardmod.verify(c, pinned={node.public})
    assert e.value.reason == "card.principal.unpinned"
    # hash excludes sig but includes node_sig
    assert cardmod.card_hash({**c, "sig": "x"}) == h
    assert cardmod.card_hash({**c, "node_sig": "x"}) != h


def test_tamper_breaks_either_signature(trio):
    node, principal, agent = trio
    c = cardmod.sign(_card(node, principal, agent), node, principal)
    bad = {**c, "agent": {**c["agent"], "name": "evil"}}
    with pytest.raises(VerifyError):
        cardmod.verify(bad)
    forged_node = keys.KeyPair.generate()
    bad = cardmod.sign({**_card(node, principal, agent)}, node, principal)
    bad["node_sig"] = forged_node.sign(b"whatever")
    with pytest.raises(VerifyError) as e:
        cardmod.verify(bad)
    assert e.value.reason.startswith("card.node_sig")


def test_sign_requires_matching_keys(trio):
    node, principal, agent = trio
    with pytest.raises(ValueError):
        cardmod.sign(_card(node, principal, agent), principal, principal)
    with pytest.raises(ValueError):
        cardmod.build(
            agent_name="a",
            agent_key=agent.public,
            node_name="n",
            node_key=node.public,
            principal_name="p",
            principal_key=principal.public,
            principal_kind="ghost",
            capabilities=[],
            ledger_url="x",
            issued_at="2026-09-07T07:00:00Z",
        )


def test_structure_rejects_unknown_and_missing(trio):
    node, principal, agent = trio
    c = cardmod.sign(_card(node, principal, agent), node, principal)
    with pytest.raises(VerifyError) as e:
        cardmod.verify({**c, "extra": 1})
    assert e.value.reason == "card.unknown_field"
    with pytest.raises(VerifyError) as e:
        cardmod.verify({k: v for k, v in c.items() if k != "sig"})
    assert e.value.reason == "card.missing"
    with pytest.raises(VerifyError):
        cardmod.verify({**c, "card_version": "v9"})
    with pytest.raises(VerifyError):
        cardmod.verify("not a card")


def test_allows_capability_glob(trio):
    node, principal, agent = trio
    c = _card(node, principal, agent)
    assert cardmod.allows(c, "fs.write", f"host:{node.public}:scratch/x.txt")
    assert not cardmod.allows(c, "fs.write", "host:other:scratch/x.txt")
    assert not cardmod.allows(c, "fs.read", f"host:{node.public}:scratch/x.txt")

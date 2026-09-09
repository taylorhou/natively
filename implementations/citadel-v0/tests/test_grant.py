from datetime import UTC, datetime

import pytest

from natively import card as cardmod
from natively import grant as grantmod
from natively import keys
from natively.errors import RefusedError, VerifyError

NOW = datetime(2026, 9, 7, 7, 0, 0, tzinfo=UTC)
T0, T1, T2 = "2026-09-07T06:00:00Z", "2026-09-07T07:00:00Z", "2026-09-07T08:00:00Z"


@pytest.fixture
def world():
    node, principal, agent = (keys.KeyPair.generate() for _ in range(3))
    card = cardmod.sign(
        cardmod.build(
            agent_name="b",
            agent_key=agent.public,
            node_name="n",
            node_key=node.public,
            principal_name="p",
            principal_key=principal.public,
            principal_kind="stand-in",
            capabilities=[
                {"action": "fs.write", "resource": f"host:{node.public}:scratch/*"},
                {"action": "info", "resource": "*"},
            ],
            ledger_url="n:ledger",
            issued_at=T0,
        ),
        node,
        principal,
    )
    return {
        "node": node,
        "principal": principal,
        "agent": agent,
        "card": card,
        "exec": {node.public, agent.public},
        "pinned": {principal.public},
    }


def scope(node, name="x.txt", **params):
    # every constrained key is a permitted key (check_structure demands it; the
    # subset algebra skips constraints on keys the child forbids, so a fixture that
    # constrained an unlisted key would compare nothing)
    keys = ["content"] + [k for k in params if k != "content"]
    return [
        {
            "action": "fs.write",
            "resource": f"host:{node.public}:scratch/{name}",
            "params": {"keys": keys, "values": params},
        }
    ]


def make(w, **over):
    kw = dict(
        issuer={"principal": "p", "key": w["principal"].public},
        subject={"agent": cardmod.card_hash(w["card"]), "key": w["agent"].public},
        audience_executor=w["node"].public,
        scope=scope(w["node"]),
        principal_statement="write x.txt once",
        issued_at=T0,
        expires_at=T2,
    )
    kw.update(over)
    return grantmod.sign(grantmod.build(**kw), w["principal"])


def verify(w, g, now=NOW, ext=None):
    grantmod.verify(
        g,
        now=now,
        subject_card=w["card"],
        executor_keys=w["exec"],
        pinned=w["pinned"],
        extensions=ext,
    )


def test_valid_grant(world):
    verify(world, make(world))


@pytest.mark.parametrize(
    "over,reason",
    [
        ({"expires_at": T1}, "grant.expired"),
        ({"not_before": T2}, "grant.not_yet_valid"),
        (
            {"audience_executor": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
            "grant.audience",
        ),
        ({"scope": [{"action": "fs.read", "resource": "host:x:y"}]}, "grant.scope.not_in_card"),
        ({"principal_statement": ""}, "grant.principal_statement.format"),
        ({"expires_at": T0}, "grant.expires_at"),
    ],
)
def test_rejections(world, over, reason):
    with pytest.raises(VerifyError) as e:
        verify(world, make(world, **over))
    assert e.value.reason == reason


def test_wrong_subject_and_unpinned_issuer(world):
    g = make(world)
    other = keys.KeyPair.generate()
    with pytest.raises(VerifyError) as e:
        verify(world, {**g, "subject": {**g["subject"], "key": other.public}})
    assert e.value.reason.startswith("grant.sig") or e.value.reason == "grant.subject.key"
    bad = grantmod.sign(
        grantmod.build(
            issuer={"principal": "q", "key": other.public},
            subject=g["subject"],
            audience_executor=world["node"].public,
            scope=scope(world["node"]),
            principal_statement="s",
            issued_at=T0,
            expires_at=T2,
        ),
        other,
    )
    with pytest.raises(VerifyError) as e:
        verify(world, bad)
    assert e.value.reason == "grant.issuer.unpinned"


def test_tamper_breaks_signature(world):
    g = make(world)
    with pytest.raises(VerifyError) as e:
        verify(world, {**g, "max_uses": 99})
    assert e.value.reason == "grant.sig.invalid"


def test_structure_fail_closed_on_unknown_field_and_extension(world):
    g = make(world)
    with pytest.raises(VerifyError) as e:
        verify(world, {**g, "bonus": 1})
    assert e.value.reason == "grant.unknown_field"
    gw = make(world, max_uses_per_window={"n": 2, "window_s": 60}, max_uses=5)
    with pytest.raises(VerifyError) as e:
        verify(world, gw)
    assert e.value.reason == "grant.extension.disabled"
    verify(world, gw, ext={"max_uses_per_window": True})
    grantmod.uses_ok(gw, 1, 1)
    with pytest.raises(VerifyError) as e:
        grantmod.uses_ok(gw, 1, 2)
    assert e.value.reason == "grant.max_uses_per_window"
    with pytest.raises(VerifyError) as e:
        grantmod.uses_ok(gw, 5, 0)
    assert e.value.reason == "grant.max_uses"


def test_offline_ok_only_for_info(world):
    g = grantmod.build(
        issuer={"principal": "p", "key": world["principal"].public},
        subject={"agent": "sha256:" + "0" * 64, "key": world["agent"].public},
        audience_executor=world["node"].public,
        scope=[
            {"action": "fs.write", "resource": "host:x:y", "offline_ok": True, "max_offline_s": 60}
        ],
        principal_statement="s",
        issued_at=T0,
        expires_at=T2,
    )
    with pytest.raises(VerifyError) as e:
        grantmod.check_structure(grantmod.sign(g, world["principal"]))
    assert e.value.reason == "grant.scope[0].offline_ok"


def test_match_scope_constraints(world):
    node = world["node"]
    g = make(
        world,
        scope=[
            {
                "action": "fs.write",
                "resource": f"host:{node.public}:scratch/x.txt",
                "params": {
                    "keys": ["content", "n", "mode"],
                    "values": {
                        "content": {"regex": "^[a-z]+$"},
                        "n": {"range": [1, 4]},
                        "mode": {"in": ["a", "b"]},
                    },
                },
            }
        ],
    )
    r = f"host:{node.public}:scratch/x.txt"
    assert grantmod.match_scope(g, "fs.write", r, {"content": "abc", "n": 2, "mode": "a"})
    assert grantmod.match_scope(
        g, "fs.write", r, {"content": "abc"}
    )  # absent keys are unconstrained
    for bad in ({"content": "ABC"}, {"n": 5}, {"n": "2"}, {"mode": "c"}, {"other": 1}):
        with pytest.raises(RefusedError) as e:
            grantmod.match_scope(g, "fs.write", r, bad)
        assert e.value.reason == "scope.no_match"
    with pytest.raises(RefusedError):
        grantmod.match_scope(g, "fs.write", r + "2", {"content": "abc"})
    with pytest.raises(RefusedError):
        grantmod.match_scope(g, "info", r, {})


def test_bad_constraint_grammar(world):
    for c in ({}, {"in": "x"}, {"range": [1]}, {"regex": "("}, {"gt": 1}):
        g = make(world, scope=scope(world["node"], content=c))
        with pytest.raises(VerifyError):
            grantmod.check_structure(g)


def test_subset_algebra(world):
    node = world["node"]
    parent = scope(node, content={"regex": "^[a-z]+$", "in": ["ab", "cd"]})
    same = scope(node, content={"regex": "^[a-z]+$", "in": ["ab", "cd"]})
    tighter = scope(node, content={"regex": "^[a-z]+$", "in": ["ab"]})
    looser = scope(node, content={"regex": "^[a-z]+$"})
    other_file = scope(node, "y.txt", content={"regex": "^[a-z]+$", "in": ["ab"]})
    assert grantmod.is_subset(same, parent) and not grantmod.is_strict_subset(same, parent)
    assert grantmod.is_strict_subset(tighter, parent)
    assert not grantmod.is_subset(looser, parent)
    assert not grantmod.is_subset(other_file, parent)
    assert grantmod.is_strict_subset(tighter, parent + other_file)
    rng_p = scope(node, n={"range": [1, 10]})
    assert grantmod.is_strict_subset(scope(node, n={"range": [2, 10]}), rng_p)
    assert not grantmod.is_subset(scope(node, n={"range": [0, 10]}), rng_p)
    assert not grantmod.is_subset(scope(node, n={"range": [None, 10]}), rng_p)


def test_delegation_chain(world):
    node, agent = world["node"], world["agent"]
    delegate = keys.KeyPair.generate()
    dnode = keys.KeyPair.generate()
    dcard = cardmod.sign(
        cardmod.build(
            agent_name="d",
            agent_key=delegate.public,
            node_name="dn",
            node_key=dnode.public,
            principal_name="p",
            principal_key=world["principal"].public,
            principal_kind="stand-in",
            capabilities=[{"action": "fs.write", "resource": f"host:{node.public}:scratch/*"}],
            ledger_url="d:ledger",
            issued_at=T0,
        ),
        dnode,
        world["principal"],
    )
    # parent: principal -> delegate agent d, audience = executor node
    parent = grantmod.sign(
        grantmod.build(
            issuer={"principal": "p", "key": world["principal"].public},
            subject={"agent": cardmod.card_hash(dcard), "key": delegate.public},
            audience_executor=node.public,
            scope=scope(node, content={"regex": "^[a-z]+$"}),
            principal_statement="d may have b write x.txt",
            issued_at=T0,
            expires_at=T2,
            max_uses=3,
        ),
        world["principal"],
    )

    def child(**over):
        kw = dict(
            issuer={"agent": cardmod.card_hash(dcard), "key": delegate.public},
            subject={"agent": cardmod.card_hash(world["card"]), "key": agent.public},
            audience_executor=node.public,
            scope=scope(node, content={"regex": "^[a-z]+$", "in": ["ok"]}),
            principal_statement="b writes ok",
            issued_at=T1,
            expires_at=T2,
            max_uses=1,
            parent_grant=parent,
        )
        kw.update(over)
        return grantmod.sign(grantmod.build(**kw), delegate)

    verify(world, child())
    cases = [
        (child(scope=scope(node, content={"regex": "^[a-z]+$"})), "grant.delegation.not_subset"),
        (child(expires_at="2026-09-07T09:00:00Z"), "grant.delegation.expiry"),
        (child(max_uses=4), "grant.delegation.max_uses"),
        (child(audience_executor=agent.public), "grant.delegation.audience"),
        (child(not_before="2026-09-07T05:00:00Z"), "grant.delegation.not_before"),
    ]
    for g, reason in cases:
        with pytest.raises(VerifyError) as e:
            verify(world, g)
        assert e.value.reason == reason, g
    # signed by someone other than the parent's subject
    imp = keys.KeyPair.generate()
    g = grantmod.sign(
        grantmod.build(
            issuer={"agent": cardmod.card_hash(dcard), "key": imp.public},
            subject={"agent": cardmod.card_hash(world["card"]), "key": agent.public},
            audience_executor=node.public,
            scope=scope(node, content={"regex": "^[a-z]+$", "in": ["ok"]}),
            principal_statement="s",
            issued_at=T1,
            expires_at=T2,
            parent_grant=parent,
        ),
        imp,
    )
    with pytest.raises(VerifyError) as e:
        verify(world, g)
    assert e.value.reason == "grant.delegation.issuer"
    # depth two
    grandchild = child(parent_grant=child())
    with pytest.raises(VerifyError) as e:
        verify(world, grandchild)
    assert e.value.reason == "grant.delegation.depth"
    # an agent-signed grant with no parent is a request, never a word
    orphan = grantmod.sign(
        grantmod.build(
            issuer={"agent": cardmod.card_hash(dcard), "key": delegate.public},
            subject={"agent": cardmod.card_hash(world["card"]), "key": agent.public},
            audience_executor=node.public,
            scope=scope(node),
            principal_statement="s",
            issued_at=T1,
            expires_at=T2,
        ),
        delegate,
    )
    with pytest.raises(VerifyError) as e:
        verify(world, orphan)
    assert e.value.reason == "grant.issuer.not_principal"


# ---- gate findings 2 and 3: delegated budgets, empty key list ---------------------------


def test_delegation_inherits_window_and_check_interval(world):
    node, agent = world["node"], world["agent"]
    delegate, dnode = keys.KeyPair.generate(), keys.KeyPair.generate()
    dcard = cardmod.sign(
        cardmod.build(
            agent_name="d",
            agent_key=delegate.public,
            node_name="dn",
            node_key=dnode.public,
            principal_name="p",
            principal_key=world["principal"].public,
            principal_kind="stand-in",
            capabilities=[{"action": "fs.write", "resource": f"host:{node.public}:scratch/*"}],
            ledger_url="d:ledger",
            issued_at=T0,
        ),
        dnode,
        world["principal"],
    )
    ext = {"max_uses_per_window": True}

    def parent(**over):
        kw = dict(
            issuer={"principal": "p", "key": world["principal"].public},
            subject={"agent": cardmod.card_hash(dcard), "key": delegate.public},
            audience_executor=node.public,
            scope=scope(node, content={"regex": "^[a-z]+$"}),
            principal_statement="d may have b write x.txt",
            issued_at=T0,
            expires_at=T2,
            max_uses=3,
            max_check_interval_s=300,
        )
        kw.update(over)
        return grantmod.sign(grantmod.build(**kw), world["principal"])

    def child(p, **over):
        kw = dict(
            issuer={"agent": cardmod.card_hash(dcard), "key": delegate.public},
            subject={"agent": cardmod.card_hash(world["card"]), "key": agent.public},
            audience_executor=node.public,
            scope=scope(node, content={"regex": "^[a-z]+$", "in": ["ok"]}),
            principal_statement="b writes ok",
            issued_at=T1,
            expires_at=T2,
            max_uses=1,
            max_check_interval_s=300,
            parent_grant=p,
        )
        kw.update(over)
        return grantmod.sign(grantmod.build(**kw), delegate)

    p = parent()
    verify(world, child(p), ext=ext)
    with pytest.raises(VerifyError) as e:
        verify(world, child(p, max_check_interval_s=301), ext=ext)
    assert e.value.reason == "grant.delegation.max_check_interval"
    verify(world, child(p, max_check_interval_s=60), ext=ext)
    pw = parent(max_uses_per_window={"n": 2, "window_s": 600})
    with pytest.raises(VerifyError) as e:
        verify(world, child(pw), ext=ext)  # the child dropped the parent's window
    assert e.value.reason == "grant.delegation.max_uses_per_window"
    for cw in ({"n": 3, "window_s": 600}, {"n": 2, "window_s": 599}):
        with pytest.raises(VerifyError) as e:
            verify(world, child(pw, max_uses_per_window=cw), ext=ext)
        assert e.value.reason == "grant.delegation.max_uses_per_window"
    verify(world, child(pw, max_uses_per_window={"n": 2, "window_s": 600}), ext=ext)
    verify(world, child(pw, max_uses_per_window={"n": 1, "window_s": 3600}), ext=ext)
    verify(
        world, child(p, max_uses_per_window={"n": 1, "window_s": 60}), ext=ext
    )  # tighter is fine


def test_empty_key_list_permits_no_params(world):
    node = world["node"]
    r = f"host:{node.public}:scratch/x.txt"
    g = make(
        world, scope=[{"action": "fs.write", "resource": r, "params": {"keys": [], "values": {}}}]
    )
    assert grantmod.match_scope(g, "fs.write", r, {})
    with pytest.raises(RefusedError) as e:
        grantmod.match_scope(g, "fs.write", r, {"content": "x"})
    assert "not permitted" in e.value.detail
    # subset algebra agrees: [] under ["metadata"] is tighter; ["content"] under [] is wider
    parent = [{"action": "fs.write", "resource": r, "params": {"keys": ["metadata"], "values": {}}}]
    none = [{"action": "fs.write", "resource": r, "params": {"keys": [], "values": {}}}]
    content = [{"action": "fs.write", "resource": r, "params": {"keys": ["content"], "values": {}}}]
    assert grantmod.is_strict_subset(none, parent)
    assert not grantmod.is_subset(content, none)
    assert not grantmod.is_subset(content, parent)


def test_authenticate_checks_signatures_and_rooting_only(world):
    g = make(world, expires_at=T1)  # already expired: verify fails, authenticate does not
    grantmod.authenticate(g, pinned=world["pinned"])
    with pytest.raises(VerifyError):
        verify(world, g)
    with pytest.raises(VerifyError) as e:
        grantmod.authenticate(g, pinned=set())
    assert e.value.reason == "grant.issuer.unpinned"
    with pytest.raises(VerifyError) as e:
        grantmod.authenticate({**g, "max_uses": 99}, pinned=world["pinned"])
    assert e.value.reason == "grant.sig.invalid"

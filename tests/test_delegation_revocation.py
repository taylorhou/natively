"""Grant enforcement (review 2026-09-07, point 3, second half): depth-one
delegation walked back to the principal, and revocation - local feed plus
the feed a grant names - consulted before every action, failing closed
when the feed cannot be read past grace, with the offline allowance a
scope entry may carry."""
import json
import os
import time

import pytest

from natively import crypto, envelope, revocation
from natively import node as nodemod
from natively.revocation import RevocationError

from conftest import (Principal, agent_key, issue_grant, ledger_entries, make_node, mirror, outcomes, pump,
                      resource, send_action, uses)


def _restart(node):
    """Stop the daemon and start a fresh one on the same home. A node
    re-registers only once the clock has passed its last registration
    second, so the restart waits for it before the first pass."""
    node.stop()
    time.sleep(1.1)
    n = nodemod.Node(node.home)
    n.start()
    return n


def _pair(tmp_path, hub, principal):
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["test.ping", "svc.restart"], "gamma": ["test.ping"]})
    return n1, n2


def _checks(node):
    return [(e["outcome"], e["grant_id"]) for e in ledger_entries(node) if e["action"] == "grant.check"]


def _write(node, g):
    json.dump(g, open(os.path.join(node.home, "grants", g["grant_id"] + ".json"), "w"))


# ---------- delegation ----------

def _delegate(node, frm, to, parent, scope=None, **kw):
    scope = scope or [{"action": "test.ping", "resource": resource(node), "params": {}}]
    card = node.agents[to]["card"]
    g = envelope.make_delegated_grant(node.agents[frm]["seed"], parent, card, scope, "delegated", **kw)
    _write(node, g)
    return g


def test_delegated_grant_executes_and_walks_back_to_the_principal(tmp_path, hub, principal):
    n1, n2 = _pair(tmp_path, hub, principal)
    parent = issue_grant(n2, "beta", principal, max_uses=3)
    child = _delegate(n2, "beta", "gamma", parent, max_uses=2)
    send_action(n1, "alpha", n2, "gamma", [child["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    assert uses(n2, child["grant_id"]) == 1 and uses(n2, parent["grant_id"]) == 1  # the child's use is the parent's use
    # the parent must be held here: without it the child is invalid
    os.unlink(os.path.join(n2.home, "grants", parent["grant_id"] + ".json"))
    send_action(n1, "alpha", n2, "gamma", [child["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    assert ("invalid", child["grant_id"]) in _checks(n2) and "not held" in mirror(n2)


def test_delegation_rules(tmp_path, hub, principal):
    n1, n2 = _pair(tmp_path, hub, principal)
    res = resource(n2)
    parent = issue_grant(n2, "beta", principal, max_uses=2,
                         scope=[{"action": "test.ping", "resource": res,
                                 "params": {"keys": ["k", "m"], "values": {"k": {"in": [1, 2, 3]}, "m": {"range": [0, 10]}}}}])
    card = n2.agents["gamma"]["card"]
    beta = n2.agents["beta"]["seed"]
    pins = {principal.pub}
    ok = envelope.make_delegated_grant(beta, parent, card,
                                       [{"action": "test.ping", "resource": res,
                                         "params": {"keys": ["k", "m"], "values": {"k": {"in": [1, 2]}, "m": {"range": [1, 5]}}}}], "d")
    beta_card = n2.agents["beta"]["card"]
    envelope.verify_grant(ok, pins, subject_card=card, parent=parent, parent_subject_card=beta_card)

    def refused(why, scope=None, **changes):
        g = envelope.make_delegated_grant(beta, parent, card, scope or ok["scope"], "d")
        if changes:
            g = envelope.sign_obj(dict(g, **changes), beta)
        with pytest.raises(envelope.GrantError, match=why):
            envelope.verify_grant(g, pins, subject_card=card, parent=parent, parent_subject_card=beta_card)

    refused("subset", scope=[{"action": "test.ping", "resource": res, "params": {"keys": ["k", "m", "z"]}}])           # wider allowlist
    refused("subset", scope=[{"action": "test.ping", "resource": res, "params": {"keys": ["k", "m"]}}])                # drops a parent constraint
    refused("subset", scope=[{"action": "test.ping", "resource": res, "params": {"keys": ["k", "m"], "values": {"k": {"in": [1, 4]}, "m": {"range": [1, 5]}}}}])
    refused("subset", scope=[{"action": "test.ping", "resource": res, "params": {"keys": ["k", "m"], "values": {"k": {"in": [1]}, "m": {"range": [0, 11]}}}}])
    refused("subset", scope=[{"action": "svc.restart", "resource": res, "params": {}}])                                # action not in parent
    refused("subset", scope=[{"action": "test.ping", "resource": resource(n2, "other"), "params": {}}])              # resource not in parent
    refused("budget", max_uses=3)
    refused("outlives", expires_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(envelope.parse_iso(parent["expires_at"]) + 1)))
    refused("audience", audience={"executor": agent_key(n2, "gamma")})
    refused("revocation", revocation={"ledger": "file:///elsewhere/feed.jsonl", "max_check_interval_s": 300})  # another feed
    refused("revocation", revocation={"ledger": "", "max_check_interval_s": 3000})                              # a longer interval
    refused("parent's subject", issuer=dict(ok["issuer"], key=agent_key(n2, "gamma")))
    # a principal-signed grant that names a parent is still walked back, and refused when the parent is not held
    with pytest.raises(envelope.GrantError, match="not held"):
        envelope.verify_grant(envelope.sign_obj(dict(ok, parent_grant=envelope.new_id("grt")), principal.seed), pins, parent=None)
    # depth is one: a child of a child is refused
    grandchild = envelope.make_delegated_grant(n2.agents["gamma"]["seed"], ok, n2.agents["beta"]["card"], ok["scope"], "gd")
    with pytest.raises(envelope.GrantError, match="depth"):
        envelope.verify_grant(grandchild, pins, parent=ok, parent_subject_card=card)
    # the parent's own subject card is required, and must be the card the parent names
    with pytest.raises(envelope.GrantError, match="parent grant's subject card"):
        envelope.verify_grant(ok, pins, subject_card=card, parent=parent)
    with pytest.raises(envelope.GrantError, match="parent grant's subject card"):
        envelope.verify_grant(ok, pins, subject_card=card, parent=parent, parent_subject_card=card)
    # an agent-signed grant without a parent has no chain to a principal
    orphan = envelope.sign_obj(dict(ok, parent_grant=None), beta)
    with pytest.raises(envelope.GrantError, match="pinned principal"):
        envelope.verify_grant(orphan, pins)


# ---------- revocation ----------

def test_tombstones_verify_only_under_a_pinned_root(principal):
    other = Principal()
    t = revocation.make_tombstone(principal.seed, "grt_x", "why")
    assert revocation.verify_tombstone(t, {principal.pub})
    assert not revocation.verify_tombstone(t, {other.pub})
    assert not revocation.verify_tombstone(t, set())
    assert not revocation.verify_tombstone(dict(t, target="grt_y"), {principal.pub})
    assert not revocation.verify_tombstone({"kind": "tombstone"}, {principal.pub})
    assert revocation.parse_feed(json.dumps(t) + "\n\n" + json.dumps(t), {principal.pub}) == {"grt_x"}
    with pytest.raises(RevocationError):
        revocation.parse_feed(json.dumps(t) + "\nnot json\n", {principal.pub})
    with pytest.raises(RevocationError):
        revocation.parse_feed(json.dumps(revocation.make_tombstone(other.seed, "grt_z")), {principal.pub})


def _tombstone(node, principal, target):
    t = revocation.make_tombstone(principal.seed, target)
    with open(node.revocations.local_path, "a") as f:
        f.write(json.dumps(t) + "\n")


def test_local_tombstone_stops_the_grant_the_card_and_the_delegation(tmp_path, hub, principal):
    n1, n2 = _pair(tmp_path, hub, principal)
    g = issue_grant(n2, "beta", principal, max_uses=5)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    _tombstone(n2, principal, g["grant_id"])
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    assert ("revoked", g["grant_id"]) in _checks(n2)
    # a tombstone on the CARD stops every grant under it
    g2 = issue_grant(n2, "beta", principal, max_uses=5)
    _tombstone(n2, principal, envelope.obj_hash(n2.agents["beta"]["card"]))
    send_action(n1, "alpha", n2, "beta", [g2["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    # a tombstone signed by a stranger is not a tombstone: the feed is unreadable and every action refuses
    g3 = issue_grant(n2, "gamma", principal, max_uses=5)
    _tombstone(n2, Principal(), "grt_nothing")
    send_action(n1, "alpha", n2, "gamma", [g3["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    assert ("revoked", g3["grant_id"]) in _checks(n2) and "does not verify" in mirror(n2)


def test_recovery_key_tombstone_on_the_principal_revokes_everything_it_issued(tmp_path, hub, principal):
    recovery = Principal()
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]}, roots=[principal.pub, recovery.pub])
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["test.ping"]}, roots=[principal.pub, recovery.pub])
    g = issue_grant(n2, "beta", principal, max_uses=5)
    _tombstone(n2, recovery, "ed25519:" + principal.pub)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == []
    assert ("revoked", g["grant_id"]) in _checks(n2) and "revoked: ed25519:" + principal.pub in mirror(n2)


def test_named_feed_is_fetched_cached_and_fails_closed_past_grace(tmp_path, hub, principal):
    n1, n2 = _pair(tmp_path, hub, principal)
    feed = tmp_path / "feed.jsonl"
    feed.write_text("")
    url = "file://" + str(feed)
    g = issue_grant(n2, "beta", principal, max_uses=10, revocation_ledger=url, max_check_interval_s=60)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    # the principal publishes a tombstone at the feed; inside the interval the cached copy still serves
    feed.write_text(json.dumps(revocation.make_tombstone(principal.seed, g["grant_id"])) + "\n")
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok", "ok"]
    # past the interval it is re-read and the grant is refused
    n2.revocations._feeds[url] = (time.time() - 61, n2.revocations._feeds[url][1])
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok", "ok"]
    assert ("revoked", g["grant_id"]) in _checks(n2)
    # an unreadable feed: the last good copy serves inside grace (one more interval), then fails closed
    g2 = issue_grant(n2, "beta", principal, max_uses=10, revocation_ledger=url, max_check_interval_s=60)
    feed.write_text("")
    n2.revocations._feeds.pop(url, None)
    send_action(n1, "alpha", n2, "beta", [g2["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok", "ok", "ok"]
    feed.unlink()
    n2.revocations._feeds[url] = (time.time() - 100, set())  # stale but inside 2 x interval
    send_action(n1, "alpha", n2, "beta", [g2["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok", "ok", "ok", "ok"]
    n2.revocations._feeds[url] = (time.time() - 121, set())  # past grace
    send_action(n1, "alpha", n2, "beta", [g2["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok", "ok", "ok", "ok"]
    assert ("revoked", g2["grant_id"]) in _checks(n2) and "past grace" in mirror(n2)
    # never read at all + unreadable: refused
    n2.revocations._feeds.pop(url, None)
    send_action(n1, "alpha", n2, "beta", [g2["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping").count("ok") == 4
    assert "never read" in mirror(n2)


def test_offline_ok_scope_runs_on_a_stale_copy_inside_max_offline_s(tmp_path, hub, principal):
    n1, n2 = _pair(tmp_path, hub, principal)
    feed = tmp_path / "feed.jsonl"
    feed.write_text("")
    url = "file://" + str(feed)
    scope = [{"action": "test.ping", "resource": resource(n2), "params": {}, "offline_ok": True, "max_offline_s": 3600}]
    g = issue_grant(n2, "beta", principal, max_uses=10, scope=scope, revocation_ledger=url, max_check_interval_s=60)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    feed.unlink()
    n2.revocations._feeds[url] = (time.time() - 1000, set())  # past grace, inside max_offline_s
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok", "ok"]
    n2.revocations._feeds[url] = (time.time() - 3601, set())  # past max_offline_s
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok", "ok"]
    assert ("revoked", g["grant_id"]) in _checks(n2) and "past grace" in mirror(n2)


def test_tombstone_on_the_parent_grant_stops_its_delegation(tmp_path, hub, principal):
    n1, n2 = _pair(tmp_path, hub, principal)
    parent = issue_grant(n2, "beta", principal, max_uses=5)
    child = _delegate(n2, "beta", "gamma", parent, max_uses=5)
    send_action(n1, "alpha", n2, "gamma", [child["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    _tombstone(n2, principal, parent["grant_id"])
    send_action(n1, "alpha", n2, "gamma", [child["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    assert ("revoked", child["grant_id"]) in _checks(n2) and "revoked: %s" % parent["grant_id"] in mirror(n2)


def test_tombstone_on_the_delegating_agent_stops_its_delegations(tmp_path, hub, principal):
    n1, n2 = _pair(tmp_path, hub, principal)
    beta_card = n2.agents["beta"]["card"]
    parent = issue_grant(n2, "beta", principal, max_uses=5)
    child = _delegate(n2, "beta", "gamma", parent, max_uses=5)
    send_action(n1, "alpha", n2, "gamma", [child["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    # the delegating agent's CARD: the child names it only through the parent's subject
    _tombstone(n2, principal, envelope.obj_hash(beta_card))
    send_action(n1, "alpha", n2, "gamma", [child["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    assert ("revoked", child["grant_id"]) in _checks(n2) and "revoked: %s" % envelope.obj_hash(beta_card) in mirror(n2)
    # the delegating agent's KEY, on a fresh node with no card tombstone
    n3 = make_node(tmp_path, "n3", hub.url, principal, {"beta": ["test.ping"], "gamma": ["test.ping"]})
    parent3 = issue_grant(n3, "beta", principal, max_uses=5)
    child3 = _delegate(n3, "beta", "gamma", parent3, max_uses=5)
    _tombstone(n3, principal, agent_key(n3, "beta"))
    send_action(n1, "alpha", n3, "gamma", [child3["grant_id"]])
    pump([n1, n3], 3)
    assert outcomes(n3, "test.ping") == []
    assert ("revoked", child3["grant_id"]) in _checks(n3) and "revoked: %s" % agent_key(n3, "beta") in mirror(n3)


def test_delegations_spend_the_parents_budget(tmp_path, hub, principal):
    n1, n2 = _pair(tmp_path, hub, principal)
    parent = issue_grant(n2, "beta", principal, max_uses=2)
    c1 = _delegate(n2, "beta", "gamma", parent, max_uses=2)
    c2 = _delegate(n2, "beta", "gamma", parent, max_uses=2)
    for _ in range(2):
        send_action(n1, "alpha", n2, "gamma", [c1["grant_id"]])
        pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok", "ok"]
    assert uses(n2, c1["grant_id"]) == 2 and uses(n2, parent["grant_id"]) == 2
    # the principal granted two uses once: a second child with a fresh
    # budget of its own gets none, and neither does the parent itself
    send_action(n1, "alpha", n2, "gamma", [c2["grant_id"]])
    pump([n1, n2], 3)
    send_action(n1, "alpha", n2, "beta", [parent["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok", "ok"]
    assert ("exhausted", c2["grant_id"]) in _checks(n2) and ("exhausted", parent["grant_id"]) in _checks(n2)
    assert "parent grant %s max_uses reached (2/2)" % parent["grant_id"] in mirror(n2)
    rows = [e for e in ledger_entries(n2) if e["action"] == "test.ping"]
    assert [(e["grant_id"], e["parent"], e["scope"], e["parent_scope"]) for e in rows] == [(c1["grant_id"], parent["grant_id"], 0, 0)] * 2


def test_delegations_spend_the_parents_window(tmp_path, hub, principal):
    n1, n2 = _pair(tmp_path, hub, principal)
    res_a, res_b = resource(n2, "a"), resource(n2, "b")
    w = {"n": 1, "window_s": 3600}
    parent = issue_grant(n2, "beta", principal, max_uses=None,
                         scope=[{"action": "test.ping", "resource": res_a, "params": {}, "max_uses_per_window": w},
                                {"action": "test.ping", "resource": res_b, "params": {}, "max_uses_per_window": w}])
    child = _delegate(n2, "beta", "gamma", parent, max_uses=None,
                      scope=[{"action": "test.ping", "resource": res_b, "params": {}, "max_uses_per_window": w}])
    send_action(n1, "alpha", n2, "gamma", [child["grant_id"]], res=res_b)
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    row = [e for e in ledger_entries(n2) if e["action"] == "test.ping"][0]
    assert (row["scope"], row["parent"], row["parent_scope"]) == (0, parent["grant_id"], 1)
    # the parent's window on entry b is spent by the child; entry a is untouched
    send_action(n1, "alpha", n2, "beta", [parent["grant_id"]], res=res_b)
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    assert ("exhausted", parent["grant_id"]) in _checks(n2)
    send_action(n1, "alpha", n2, "beta", [parent["grant_id"]], res=res_a)
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok", "ok"]


def _feed_grant(tmp_path, n2, principal, **kw):
    feed = tmp_path / "feed.jsonl"
    feed.write_text("")
    url = "file://" + str(feed)
    g = issue_grant(n2, "beta", principal, max_uses=10, revocation_ledger=url, max_check_interval_s=60, **kw)
    return feed, url, g


def test_a_feed_that_shrinks_never_un_revokes(tmp_path, hub, principal):
    n1, n2 = _pair(tmp_path, hub, principal)
    feed, url, g = _feed_grant(tmp_path, n2, principal)
    feed.write_text(json.dumps(revocation.make_tombstone(principal.seed, g["grant_id"])) + "\n")
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == [] and _checks(n2).count(("revoked", g["grant_id"])) == 1
    # the feed is truncated (rollback, a bad publish) and the cached copy is due for a refresh
    feed.write_text("")
    n2.revocations._feeds[url] = (time.time() - 61, n2.revocations._feeds[url][1])
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == [] and _checks(n2).count(("revoked", g["grant_id"])) == 2
    assert g["grant_id"] in n2.revocations._feeds[url][1]


def test_a_failed_fetch_is_not_repeated_inside_the_interval(tmp_path, hub, principal):
    n1, n2 = _pair(tmp_path, hub, principal)
    feed, url, g = _feed_grant(tmp_path, n2, principal)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    calls = []

    def down(u, timeout=10):
        calls.append(u)
        raise OSError("feed host down")

    n2.revocations._fetch = down
    n2.revocations._feeds[url] = (time.time() - 61, set())  # due for a refresh, inside grace
    for _ in range(3):
        send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
        pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"] * 4  # the last good copy serves
    assert len(calls) == 1  # one timeout per interval, not one per action
    n2.revocations._tried[url] -= 61  # the next interval tries the feed again
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"] * 5 and len(calls) == 2


def test_a_feed_line_that_does_not_verify_is_an_unreadable_feed(tmp_path, hub, principal):
    """A broken feed (a line that is not JSON, or a tombstone by a stranger)
    is never applied; the last good copy serves under the same grace and
    offline policy as an unreachable feed, then the action is refused."""
    n1, n2 = _pair(tmp_path, hub, principal)
    feed, url, g = _feed_grant(tmp_path, n2, principal)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    feed.write_text("not json\n")
    n2.revocations._feeds[url] = (time.time() - 61, set())
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok", "ok"]  # inside grace: the last good copy
    n2.revocations._feeds[url] = (time.time() - 121, set())
    n2.revocations._tried.pop(url, None)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok", "ok"]
    assert ("revoked", g["grant_id"]) in _checks(n2) and "past grace" in mirror(n2) and "not JSON" in mirror(n2)


def test_cli_grant_verbs_use_the_pinned_root_set_and_refuse_unreadable_feeds(tmp_path, hub, principal):
    from natively import cli
    other = Principal()
    roots = [other.pub, principal.pub]  # the node's own principal is `other`; `principal` is a further pinned issuer
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["test.ping"], "gamma": ["test.ping"]}, roots=roots)
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]}, roots=roots)
    key = tmp_path / "p.key"
    key.write_text(principal.seed.hex())
    gdir = os.path.join(n2.home, "grants")
    scope = json.dumps([{"action": "test.ping", "resource": resource(n2), "params": {}}])
    base = ["--home", n2.home, "grant-issue", "--agent", "beta", "--principal", str(key), "--scope", scope, "--statement", "ping"]
    cli.main(base + ["--max-uses", "2"])
    (root,) = [n2._load_grant(f[:-5]) for f in os.listdir(gdir)]
    assert root["issuer"]["key"] == "ed25519:" + principal.pub
    # a feed url no execution could read is refused at issuance, and nothing is written
    with pytest.raises(SystemExit, match="unsupported revocation feed url"):
        cli.main(base + ["--revocation-ledger", "ftp://feeds.example/tombstones"])
    assert len(os.listdir(gdir)) == 1
    # a feed of a readable scheme that cannot be read now is refused too, and so is one holding a stranger's line
    with pytest.raises(SystemExit, match="cannot be read"):
        cli.main(base + ["--revocation-ledger", "file://" + str(tmp_path / "missing.jsonl")])
    bad = tmp_path / "bad.jsonl"
    bad.write_text(json.dumps(revocation.make_tombstone(Principal().seed, "grt_x")) + "\n")
    with pytest.raises(SystemExit, match="does not verify"):
        cli.main(base + ["--revocation-ledger", "file://" + str(bad)])
    assert len(os.listdir(gdir)) == 1
    # a parent whose feed has since gone cannot be delegated from: the child would inherit a feed no execution reads
    gone = tmp_path / "gone.jsonl"
    gone.write_text("")
    cli.main(base + ["--revocation-ledger", "file://" + str(gone)])
    (fed,) = [n2._load_grant(f[:-5]) for f in os.listdir(gdir) if f[:-5] != root["grant_id"]]
    gone.unlink()
    with pytest.raises(SystemExit, match="cannot be read"):
        cli.main(["--home", n2.home, "grant-delegate", "--from", "beta", "--to", "gamma", "--parent", fed["grant_id"],
                  "--scope", scope, "--statement", "d"])
    assert len(os.listdir(gdir)) == 2
    os.unlink(os.path.join(gdir, fed["grant_id"] + ".json"))
    # a window-budget parent and a window-budget delegation (no max_uses on either)
    wscope = json.dumps([{"action": "test.ping", "resource": resource(n2), "params": {},
                          "max_uses_per_window": {"n": 1, "window_s": 3600}}])
    cli.main(["--home", n2.home, "grant-issue", "--agent", "beta", "--principal", str(key), "--scope", wscope,
              "--statement", "ping hourly", "--windowed"])
    (wparent,) = [n2._load_grant(f[:-5]) for f in os.listdir(gdir) if f[:-5] != root["grant_id"]]
    assert "max_uses" not in wparent
    cli.main(["--home", n2.home, "grant-delegate", "--from", "beta", "--to", "gamma", "--parent", wparent["grant_id"],
              "--scope", wscope, "--statement", "delegated hourly", "--windowed"])
    (child,) = [n2._load_grant(f[:-5]) for f in os.listdir(gdir) if f[:-5] not in (root["grant_id"], wparent["grant_id"])]
    assert "max_uses" not in child and child["parent_grant"] == wparent["grant_id"]
    send_action(n1, "alpha", n2, "gamma", [child["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]


def test_a_local_feed_that_is_truncated_or_removed_un_revokes_nothing(tmp_path, hub, principal):
    """Targets read from the local feed accumulate in this process and in
    revocations.seen.json: truncating or deleting the feed afterwards,
    with or without a restart, leaves the grant revoked."""
    n1, n2 = _pair(tmp_path, hub, principal)
    g = issue_grant(n2, "beta", principal, max_uses=5)
    _tombstone(n2, principal, g["grant_id"])
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == [] and _checks(n2).count(("revoked", g["grant_id"])) == 1
    open(n2.revocations.local_path, "w").close()  # truncated
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == [] and _checks(n2).count(("revoked", g["grant_id"])) == 2
    os.unlink(n2.revocations.local_path)  # removed, then the daemon restarts
    n2 = _restart(n2)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == [] and _checks(n2).count(("revoked", g["grant_id"])) == 3


def test_remote_revocations_and_fetch_times_survive_a_restart(tmp_path, hub, principal):
    """A tombstone once read from a grant's feed is kept across a restart
    even when the feed has shrunk since; the last good copy's fetch time
    is kept too, so grace is measured from the real fetch."""
    n1, n2 = _pair(tmp_path, hub, principal)
    feed, url, g = _feed_grant(tmp_path, n2, principal)
    feed.write_text(json.dumps(revocation.make_tombstone(principal.seed, g["grant_id"])) + "\n")
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == [] and _checks(n2).count(("revoked", g["grant_id"])) == 1
    fetched_at = n2.revocations._feeds[url][0]
    feed.write_text("")  # the feed shrinks, then the daemon restarts
    n2 = _restart(n2)
    assert n2.revocations._feeds[url][0] == fetched_at and g["grant_id"] in n2.revocations._feeds[url][1]
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == [] and _checks(n2).count(("revoked", g["grant_id"])) == 2
    # the seen file is this node's own: one it did not write fails closed at startup
    with open(n2.revocations.seen_path, "w") as f:
        f.write("[]")
    with pytest.raises(RevocationError):
        nodemod.Node(n2.home)


def test_a_delegation_from_a_subject_without_the_capability_is_refused(tmp_path, hub, principal):
    """A parent whose subject card lacks the scope's action is invalid
    for that subject, so it cannot be delegated to an agent that has the
    capability: the parent is verified with its own subject's card."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"delta": ["msg.send"], "gamma": ["test.ping"]})
    parent = issue_grant(n2, "delta", principal, max_uses=3)  # test.ping, which delta may not do
    child = _delegate(n2, "delta", "gamma", parent, max_uses=2)
    send_action(n1, "alpha", n2, "gamma", [child["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == []
    assert ("invalid", child["grant_id"]) in _checks(n2) and "capabilities" in mirror(n2)
    # and the parent's subject card must be resolvable: a parent naming an agent nobody knows fails closed
    ghost = crypto.gen_signing_key()
    ghost_card = envelope.make_card(ghost, n2.node_pub, principal.seed, ["test.ping"], "")
    orphan = envelope.make_grant(principal.seed, "p", ghost_card, n2.node_key,
                                 [{"action": "test.ping", "resource": resource(n2), "params": {}}], "ping", max_uses=3)
    _write(n2, orphan)
    child2 = envelope.make_delegated_grant(ghost, orphan, n2.agents["gamma"]["card"],
                                           [{"action": "test.ping", "resource": resource(n2), "params": {}}], "d", max_uses=1)
    _write(n2, child2)
    send_action(n1, "alpha", n2, "gamma", [child2["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == []
    assert ("invalid", child2["grant_id"]) in _checks(n2)


# ---------- round-3 findings ----------

def test_a_tombstone_on_the_delegators_card_issuer_stops_its_delegations(tmp_path, hub, principal):
    """Principal A issued the delegating agent's card; principal B issued
    the parent grant. A tombstone on A's key ends every delegation under
    that card, exactly as it ends the parent."""
    a, b = Principal(), principal
    n1 = make_node(tmp_path, "n1", hub.url, b, {"alpha": ["msg.send"]}, roots=[b.pub, a.pub])
    n2 = make_node(tmp_path, "n2", hub.url, b, {"gamma": ["test.ping"]}, roots=[b.pub, a.pub], start=False)
    nodemod.add_agent(n2.home, "beta", a.seed, ["test.ping"])  # beta's card is A's
    n2 = nodemod.Node(n2.home)
    n2.start()
    parent = issue_grant(n2, "beta", b, max_uses=5)  # the grant is B's
    child = _delegate(n2, "beta", "gamma", parent, max_uses=2)
    send_action(n1, "alpha", n2, "gamma", [child["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    _tombstone(n2, b, "ed25519:" + a.pub)  # A is compromised: signed by B, a pinned root
    send_action(n1, "alpha", n2, "gamma", [child["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    assert ("revoked", child["grant_id"]) in _checks(n2) and ("ed25519:" + a.pub) in mirror(n2)


def test_a_tombstone_learned_from_one_feed_revokes_under_every_grant(tmp_path, hub, principal):
    """A key tombstone read through grant 1's feed revokes that key under
    grant 2, which names no feed, and under grant 3, which names another."""
    n1, n2 = _pair(tmp_path, hub, principal)
    feed, url, g1 = _feed_grant(tmp_path, n2, principal)
    feed.write_text(json.dumps(revocation.make_tombstone(principal.seed, n2.agents["beta"]["card"]["agent_key"])) + "\n")
    g2 = issue_grant(n2, "beta", principal, max_uses=5)
    other = tmp_path / "other.jsonl"
    other.write_text("")
    g3 = issue_grant(n2, "beta", principal, max_uses=5, revocation_ledger="file://" + str(other), max_check_interval_s=60)
    send_action(n1, "alpha", n2, "beta", [g2["grant_id"]])  # nothing learned yet: g2 runs
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    send_action(n1, "alpha", n2, "beta", [g1["grant_id"]])  # g1's feed teaches the key tombstone
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"] and ("revoked", g1["grant_id"]) in _checks(n2)
    for g in (g2, g3):
        send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
        pump([n1, n2], 3)
        assert outcomes(n2, "test.ping") == ["ok"]
        assert ("revoked", g["grant_id"]) in _checks(n2)


def test_a_local_parent_card_is_verified_under_the_roots(tmp_path, hub, principal):
    """The delegating agent's card on this node is held to the same
    standard as one from the directory: a card whose signature does not
    verify (same hash, so it is still the card the parent names) makes
    the parent invalid and the delegation with it."""
    n1, n2 = _pair(tmp_path, hub, principal)
    parent = issue_grant(n2, "beta", principal, max_uses=5)
    child = _delegate(n2, "beta", "gamma", parent, max_uses=2)
    cpath = os.path.join(n2.home, "agents", "beta.card.json")
    card = json.load(open(cpath))
    card["sig"] = card["sig"][:-8] + "AAAAAAA="  # obj_hash ignores sig: the hash the parent names is unchanged
    json.dump(card, open(cpath, "w"))
    send_action(n1, "alpha", n2, "gamma", [child["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == []
    assert ("invalid", child["grant_id"]) in _checks(n2) and "does not verify under the pinned roots" in mirror(n2)


def test_seen_file_values_this_node_would_never_write_are_refused(tmp_path, hub, principal):
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["test.ping"]})
    n2.stop()
    good = {"local": [], "feeds": {"file:///f": {"fetched_at": 1.0, "targets": ["grt_x"]}}}
    for bad in ({"local": [], "feeds": {"file:///f": {"fetched_at": "Infinity", "targets": []}}},
                {"local": [], "feeds": {"file:///f": {"fetched_at": True, "targets": []}}},
                {"local": [], "feeds": {"file:///f": {"fetched_at": 1e13, "targets": []}}},
                {"local": [], "feeds": {"file:///f": {"fetched_at": -1, "targets": []}}},
                {"local": [], "feeds": {"file:///f": {"fetched_at": 1.0, "targets": [1]}}},
                {"local": [None], "feeds": {}}, {"local": [], "feeds": {}, "extra": 1}, [], "x"):
        with open(n2.revocations.seen_path, "w") as f:
            f.write(json.dumps(bad) if not isinstance(bad, str) else "not json")
        with pytest.raises(RevocationError):
            nodemod.Node(n2.home)
    with open(n2.revocations.seen_path, "w") as f:
        json.dump(good, f)
    n3 = nodemod.Node(n2.home)
    assert n3.revocations._feeds["file:///f"] == (1.0, {"grt_x"})


def test_an_observation_that_cannot_be_persisted_is_not_treated_as_saved(tmp_path, hub, principal, monkeypatch):
    """A verified tombstone lives in memory from the moment it is read - a
    feed truncated meanwhile cannot un-revoke it - and while the disk
    refuses to take it the action is refused; the next check tries the
    write again before deciding anything."""
    n1, n2 = _pair(tmp_path, hub, principal)
    g = issue_grant(n2, "beta", principal, max_uses=5)
    _tombstone(n2, principal, g["grant_id"])
    real = revocation.Revocations._write_seen

    def refuse(self, local, feeds):
        raise RevocationError("revocation observations could not be persisted: disk full")
    monkeypatch.setattr(revocation.Revocations, "_write_seen", refuse)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == [] and "could not be persisted" in mirror(n2)
    assert g["grant_id"] in n2.revocations._local and n2.revocations._pending
    assert not os.path.exists(n2.revocations.seen_path)
    # the local feed is truncated while the disk still refuses: the observation stands, the action is still refused
    os.unlink(n2.revocations.local_path)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == [] and g["grant_id"] in n2.revocations._local
    monkeypatch.setattr(revocation.Revocations, "_write_seen", real)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == [] and ("revoked", g["grant_id"]) in _checks(n2)
    assert not n2.revocations._pending
    assert g["grant_id"] in json.load(open(n2.revocations.seen_path))["local"]


def test_what_a_feed_held_at_issuance_is_kept(tmp_path, hub, principal):
    """The CLI's feed check keeps what it read: a card tombstone in the
    feed at issuance still revokes after the feed is truncated."""
    from natively import cli
    n1, n2 = _pair(tmp_path, hub, principal)
    key = tmp_path / "p.key"
    key.write_text(principal.seed.hex())
    feed = tmp_path / "feed.jsonl"
    feed.write_text(json.dumps(revocation.make_tombstone(principal.seed, envelope.obj_hash(n2.agents["beta"]["card"]))) + "\n")
    scope = json.dumps([{"action": "test.ping", "resource": resource(n2), "params": {}}])
    cli.main(["--home", n2.home, "grant-issue", "--agent", "beta", "--principal", str(key), "--scope", scope,
              "--statement", "ping", "--max-uses", "5", "--revocation-ledger", "file://" + str(feed)])
    (g,) = [n2._load_grant(f[:-5]) for f in os.listdir(os.path.join(n2.home, "grants"))]
    feed.write_text("")
    n2 = _restart(n2)  # the daemon reads the observation the CLI persisted
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == [] and ("revoked", g["grant_id"]) in _checks(n2)


def test_validity_is_read_again_after_the_feed_fetch(tmp_path, hub, principal):
    """A grant that expires while its feed is being fetched does not run."""
    n1, n2 = _pair(tmp_path, hub, principal)
    feed = tmp_path / "slow.jsonl"
    feed.write_text("")
    g = issue_grant(n2, "beta", principal, max_uses=5, ttl_s=2, revocation_ledger="file://" + str(feed), max_check_interval_s=60)
    real_fetch = n2.revocations._fetch

    def slow(url, timeout=10):
        time.sleep(2.5)
        return real_fetch(url, timeout)
    n2.revocations._fetch = slow
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == []
    assert ("invalid", g["grant_id"]) in _checks(n2) and "left its validity window" in mirror(n2)


def test_a_failure_inside_the_grant_check_refuses_the_grant_and_still_acks(tmp_path, hub, principal, monkeypatch):
    """The hub going away while a parent's card is resolved, or a parent
    file that is not a grant, is a refused grant with the reason - never
    an exception that aborts the message and its ack."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"], "beta": ["test.ping"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"gamma": ["test.ping"]})
    # the parent's subject is beta on n1: its card comes from the directory
    parent = envelope.make_grant(principal.seed, "p", n1.agents["beta"]["card"], n2.node_key,
                                 [{"action": "test.ping", "resource": resource(n2), "params": {}}], "ping", max_uses=3)
    os.makedirs(os.path.join(n2.home, "grants"), exist_ok=True)
    _write(n2, parent)
    child = envelope.make_delegated_grant(n1.agents["beta"]["seed"], parent, n2.agents["gamma"]["card"],
                                          [{"action": "test.ping", "resource": resource(n2), "params": {}}], "d", max_uses=1)
    _write(n2, child)
    real = n2._peer_card

    def hub_gone(key, fresh=False):
        if key == n1.agents["beta"]["card"]["agent_key"]:
            raise OSError("connection refused")
        return real(key, fresh)
    n2._peer_card = hub_gone
    send_action(n1, "alpha", n2, "gamma", [child["grant_id"]])
    pump([n1, n2], 4)
    assert outcomes(n2, "test.ping") == []
    assert ("invalid", child["grant_id"]) in _checks(n2) and "not resolvable" in mirror(n2)
    assert n1.state["unacked"] == {}  # the message was acked
    # a parent file that is not a grant at all
    ppath = os.path.join(n2.home, "grants", parent["grant_id"] + ".json")
    json.dump({"grant_id": parent["grant_id"], "subject": "beta"}, open(ppath, "w"))
    n2._peer_card = real
    send_action(n1, "alpha", n2, "gamma", [child["grant_id"]])
    pump([n1, n2], 4)
    assert outcomes(n2, "test.ping") == [] and _checks(n2)[-1] == ("invalid", child["grant_id"])
    assert n1.state["unacked"] == {}


def test_a_grant_without_the_parent_grant_field_is_malformed_not_a_crash(principal):
    node_seed, agent_seed = crypto.gen_signing_key(), crypto.gen_signing_key()
    node_key = "ed25519:" + crypto.b64e(crypto.sign_pub(node_seed))
    card = envelope.make_card(agent_seed, crypto.sign_pub(node_seed), principal.seed, ["test.ping"], "")
    g = envelope.make_grant(principal.seed, "p", card, node_key,
                            [{"action": "test.ping", "resource": "host:%s:ping" % node_key, "params": {}}], "ping", max_uses=1)
    del g["parent_grant"]
    g = envelope.sign_obj(g, principal.seed)
    with pytest.raises(envelope.GrantError, match="parent_grant"):
        envelope.verify_grant(g, {principal.pub}, subject_card=card)



# ---------- observations shared between processes ----------

def test_observations_persisted_by_another_process_are_taken_in_and_never_overwritten(tmp_path, hub, principal):
    """Two Revocations on one home (the daemon and the CLI's feed check at
    issuance): what one persists the other reads at its next decision,
    and a write folds in what is already on disk, so a process that read
    a truncated feed cannot overwrite a tombstone another process kept."""
    feed = tmp_path / "feed.jsonl"
    feed.write_text("")
    url = "file://" + str(feed)
    home = str(tmp_path / "home")
    os.makedirs(home)
    a = revocation.Revocations(home, {principal.pub})
    b = revocation.Revocations(home, {principal.pub})
    entry = {"action": "test.ping", "resource": "host:x", "params": {}}
    assert a.feed_targets(url, 60, entry) == set()  # a holds a fresh, empty copy
    feed.write_text(json.dumps(revocation.make_tombstone(principal.seed, "grt_x")) + "\n")
    assert b.observe(url) == {"grt_x"}  # b (the CLI) reads and persists the tombstone
    feed.write_text("")  # truncated right after
    assert "grt_x" in a.feed_targets(url, 60, entry)  # a's copy is fresh: the target came from disk
    assert "grt_x" in a.known_targets()
    a._feeds[url] = (time.time() - 61, a._feeds[url][1])
    assert "grt_x" in a.feed_targets(url, 60, entry)  # a re-reads the truncated feed and persists
    assert "grt_x" in json.load(open(a.seen_path))["feeds"][url]["targets"]  # the disk keeps what b saw
    assert "grt_x" in revocation.Revocations(home, {principal.pub}).known_targets()


def test_a_tombstone_the_cli_persisted_stops_the_running_daemon(tmp_path, hub, principal):
    """The daemon's copy of the feed is fresh when the CLI's feed check
    (grant-issue --revocation-ledger) reads a tombstone; the daemon still
    refuses at its next check, because it takes in what the CLI persisted."""
    n1, n2 = _pair(tmp_path, hub, principal)
    feed = tmp_path / "feed.jsonl"
    feed.write_text("")
    url = "file://" + str(feed)
    g = issue_grant(n2, "beta", principal, max_uses=10, revocation_ledger=url, max_check_interval_s=3600)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    feed.write_text(json.dumps(revocation.make_tombstone(principal.seed, g["grant_id"])) + "\n")
    revocation.Revocations(n2.home, n2.principal_roots).observe(url)  # the CLI, in its own process
    feed.write_text("")
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"] and ("revoked", g["grant_id"]) in _checks(n2)


def test_grace_is_judged_by_the_clock_after_the_fetch_returns(tmp_path, hub, principal):
    """A fetch that runs to its timeout may carry the copy past grace: the
    copy's age is what it is when the decision is made, not when the
    fetch began."""
    n1, n2 = _pair(tmp_path, hub, principal)
    feed = tmp_path / "feed.jsonl"
    feed.write_text("")
    url = "file://" + str(feed)
    g = issue_grant(n2, "beta", principal, max_uses=10, revocation_ledger=url, max_check_interval_s=60)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]

    def slow_fail(url, timeout=10):
        time.sleep(2.5)
        raise OSError("timed out")
    n2.revocations._fetch = slow_fail
    n2.revocations._feeds[url] = (time.time() - 119, set())  # inside grace (2 x 60 s) as the fetch begins, past it when it returns
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    assert ("revoked", g["grant_id"]) in _checks(n2) and "past grace" in mirror(n2)


def test_an_unreadable_parent_file_refuses_the_delegation_and_the_next_grant_still_runs(tmp_path, hub, principal):
    """A parent grant file the process cannot read is a refused delegation
    with the reason; the later grants in the message are still tried and
    the message is acked."""
    if os.geteuid() == 0:
        pytest.skip("root reads everything")
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["test.ping"], "gamma": ["test.ping"]})
    parent = issue_grant(n2, "beta", principal, max_uses=3)
    child = _delegate(n2, "beta", "gamma", parent, max_uses=1)
    good = issue_grant(n2, "gamma", principal, max_uses=1)
    ppath = os.path.join(n2.home, "grants", parent["grant_id"] + ".json")
    os.chmod(ppath, 0)
    try:
        send_action(n1, "alpha", n2, "gamma", [child["grant_id"], good["grant_id"]])
        pump([n1, n2], 4)
    finally:
        os.chmod(ppath, 0o600)
    assert outcomes(n2, "test.ping") == ["ok"]
    assert ("invalid", child["grant_id"]) in _checks(n2) and "not held" in mirror(n2)
    assert [e["grant_id"] for e in ledger_entries(n2) if e["action"] == "test.ping"] == [good["grant_id"]]
    assert n1.state["unacked"] == {}


def test_a_spent_parent_entry_does_not_hide_another_that_still_covers(tmp_path, hub, principal):
    """A child entry inside two parent entries is charged to the first
    parent entry with budget left, not refused because the first
    containing one is spent."""
    n1, n2 = _pair(tmp_path, hub, principal)
    res = resource(n2)
    w1, w5 = {"n": 1, "window_s": 3600}, {"n": 5, "window_s": 3600}
    parent = issue_grant(n2, "beta", principal, max_uses=None, scope=[
        {"action": "test.ping", "resource": res, "params": {}, "max_uses_per_window": w1},
        {"action": "test.ping", "resource": res, "params": {}, "max_uses_per_window": w5}])
    child = _delegate(n2, "beta", "gamma", parent, max_uses=None,
                      scope=[{"action": "test.ping", "resource": res, "params": {}, "max_uses_per_window": w1}])
    send_action(n1, "alpha", n2, "beta", [parent["grant_id"]])  # spends parent entry 0
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    send_action(n1, "alpha", n2, "gamma", [child["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok", "ok"]
    rows = [e for e in ledger_entries(n2) if e["action"] == "test.ping"]
    assert rows[0].get("scope") == 0 and rows[0].get("parent") is None
    assert rows[1]["parent"] == parent["grant_id"] and rows[1]["parent_scope"] == 1
    assert uses(n2, parent["grant_id"]) == 2


def test_a_later_covering_entry_with_an_offline_allowance_runs_when_the_first_has_none(tmp_path, hub, principal):
    """The feed is unreadable past grace; the first covering entry has no
    offline allowance and refuses, the second allows running offline
    inside max_offline_s and is the one charged."""
    n1, n2 = _pair(tmp_path, hub, principal)
    feed = tmp_path / "feed.jsonl"
    feed.write_text("")
    url = "file://" + str(feed)
    res = resource(n2)
    scope = [{"action": "test.ping", "resource": res, "params": {}},
             {"action": "test.ping", "resource": res, "params": {}, "offline_ok": True, "max_offline_s": 3600}]
    g = issue_grant(n2, "beta", principal, max_uses=10, scope=scope, revocation_ledger=url, max_check_interval_s=60)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    feed.unlink()
    n2.revocations._feeds[url] = (time.time() - 1000, set())  # past grace, inside the second entry's allowance
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok", "ok"]
    rows = [e for e in ledger_entries(n2) if e["action"] == "test.ping"]
    assert rows[0]["scope"] == 0 and rows[1]["scope"] == 1
    n2.revocations._feeds[url] = (time.time() - 3601, set())  # past the allowance too
    n2.revocations._tried.pop(url, None)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok", "ok"]
    assert ("revoked", g["grant_id"]) in _checks(n2) and "past grace" in mirror(n2)


# ---------- review round 5 ----------

def test_a_tombstone_another_process_persists_during_the_fetch_still_revokes(tmp_path, principal):
    """While this object's fetch of the grant's feed is in flight, another
    process learns a tombstone through a different feed and persists it.
    The write that follows the fetch folds it in, and the decision is made
    on the set as it is after the fetch, not on the snapshot before it."""
    home = str(tmp_path / "home")
    os.makedirs(home)
    feed_a, feed_b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    feed_a.write_text("")
    feed_b.write_text("")
    url_a, url_b = "file://" + str(feed_a), "file://" + str(feed_b)
    a, b = revocation.Revocations(home, {principal.pub}), revocation.Revocations(home, {principal.pub})
    grant = {"grant_id": "grt_x", "issuer": {"key": "ed25519:i"}, "parent_grant": None,
             "revocation": {"ledger": url_a, "max_check_interval_s": 60}}
    card = {"agent_key": "ed25519:k", "principal_key_ref": "ed25519:p"}
    entry = {"action": "x", "resource": "r", "params": {}}
    a.check(grant, card, entry)  # a holds a fresh, empty copy of feed a
    a._feeds[url_a] = (time.time() - 61, set())  # aged: the next check fetches
    real_fetch = a._fetch

    def fetch_while_b_learns(url, timeout=10):
        feed_b.write_text(json.dumps(revocation.make_tombstone(principal.seed, "grt_x")) + "\n")
        b.observe(url_b)  # the other process persists the tombstone mid-fetch
        return real_fetch(url, timeout)
    a._fetch = fetch_while_b_learns
    with pytest.raises(revocation.Revoked, match="grt_x"):
        a.check(grant, card, entry)


def test_an_observation_store_that_cannot_be_read_fails_closed(tmp_path, principal):
    """Only a missing file is an empty store; a file that exists but cannot
    be looked at (here a symlink loop: ELOOP, not ENOENT) refuses to start."""
    home = str(tmp_path / "home")
    os.makedirs(home)
    seen = os.path.join(home, "revocations.seen.json")
    os.symlink("revocations.seen.json", seen)
    with pytest.raises(RevocationError, match="cannot be read"):
        revocation.Revocations(home, {principal.pub})


def test_a_parent_subject_card_that_expires_during_the_fetch_stops_the_delegation(tmp_path, hub, principal):
    """The delegating agent's card was valid when the chain was verified
    and expired while the feed was fetched: the execution clock says no."""
    n1, n2 = _pair(tmp_path, hub, principal)
    short = envelope.make_card(n2.agents["beta"]["seed"], n2.node_pub, principal.seed, ["test.ping", "svc.restart"], "", ttl_s=2)
    with open(os.path.join(n2.home, "agents", "beta.card.json"), "w") as f:
        json.dump(short, f)
    n2._load_agents()
    feed = tmp_path / "slow.jsonl"
    feed.write_text("")
    parent = issue_grant(n2, "beta", principal, max_uses=5, revocation_ledger="file://" + str(feed), max_check_interval_s=60)
    child = _delegate(n2, "beta", "gamma", parent, max_uses=1)
    real_fetch = n2.revocations._fetch

    def slow(url, timeout=10):
        time.sleep(2.5)
        return real_fetch(url, timeout)
    n2.revocations._fetch = slow
    send_action(n1, "alpha", n2, "gamma", [child["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == []
    assert ("invalid", child["grant_id"]) in _checks(n2) and "left its validity window" in mirror(n2)


def test_a_known_tombstone_reports_revoked_even_when_the_feed_is_unavailable(tmp_path, hub, principal):
    """A target already tombstoned is refused as revoked before any fetch:
    an unreadable feed does not turn a revocation into a feed complaint
    that a later scope entry with an offline allowance could get past."""
    n1, n2 = _pair(tmp_path, hub, principal)
    feed = tmp_path / "feed.jsonl"
    feed.write_text("")
    url = "file://" + str(feed)
    scope = [{"action": "test.ping", "resource": resource(n2), "params": {}},
             {"action": "test.ping", "resource": resource(n2), "params": {}, "offline_ok": True, "max_offline_s": 3600}]
    g = issue_grant(n2, "beta", principal, max_uses=10, scope=scope, revocation_ledger=url, max_check_interval_s=60)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    _tombstone(n2, principal, g["grant_id"])
    feed.unlink()
    n2.revocations._feeds[url] = (time.time() - 1000, set())
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]
    assert _checks(n2)[-1] == ("revoked", g["grant_id"]) and "revoked: " + g["grant_id"] in mirror(n2)


def test_a_local_feed_that_cannot_be_opened_fails_closed(tmp_path, hub, principal):
    """Only an absent local feed is empty. One that exists but cannot be
    opened (here a symlink loop; a permission error or an I/O error are
    the same case) is a RevocationError, so a lookup failure never reads
    as 'nothing revoked' - and the action it was checked for is refused."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["test.ping"]})
    loop = n2.revocations.local_path
    os.symlink(loop, loop)  # opening it is ELOOP, and os.path.exists() says False
    with pytest.raises(RevocationError, match="cannot be read"):
        n2.revocations.local_targets()
    g = issue_grant(n2, "beta", principal, max_uses=2)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == []
    assert ("revoked", g["grant_id"]) in _checks(n2) and "cannot be read" in mirror(n2)
    os.unlink(loop)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == ["ok"]


def test_a_receiving_card_that_expires_during_the_feed_fetch_does_not_execute(tmp_path, hub, principal):
    """The validity windows are read again after the revocation fetch,
    against the clock at execution - the receiving agent's own card
    included, not only the grant and the parent's card."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["test.ping"]}, start=False)
    seed = bytes.fromhex(open(os.path.join(n2.home, "agents", "beta.key")).read().strip())
    card = envelope.make_card(seed, n2.node_pub, principal.seed, ["test.ping"], "", ttl_s=4)
    with open(os.path.join(n2.home, "agents", "beta.card.json"), "w") as f:
        json.dump(card, f)
    n2 = nodemod.Node(n2.home)
    n2.start()
    feed = tmp_path / "feed.jsonl"
    feed.write_text("")
    url = "file://" + str(feed)
    g = issue_grant(n2, "beta", principal, max_uses=2, revocation_ledger=url, max_check_interval_s=60)

    def slow(url, timeout=10):
        time.sleep(5)  # the card above expires while the fetch is out
        return ""
    n2.revocations._fetch = slow
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == []
    assert ("invalid", g["grant_id"]) in _checks(n2) and "receiving card" in mirror(n2)


def _tombstone_line(principal, target):
    return json.dumps(revocation.make_tombstone(principal.seed, target), separators=(",", ":")) + "\n"


def test_tombstones_read_before_a_malformed_line_are_kept(tmp_path, hub, principal):
    """A feed that goes bad after a tombstone never un-reads it: the
    verified lines before the bad one are kept under the feed (without a
    fetch time - the copy was not a good one), so the target is revoked
    even after the feed is later replaced by a good copy that lacks it."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["test.ping"]})
    feed = tmp_path / "feed.jsonl"
    feed.write_text("")
    url = "file://" + str(feed)
    g = issue_grant(n2, "beta", principal, max_uses=5, revocation_ledger=url, max_check_interval_s=60)
    feed.write_text(_tombstone_line(principal, g["grant_id"]) + "this line is not json\n")
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == []
    assert g["grant_id"] in n2.revocations.known_targets()
    assert n2.revocations._feeds[url][0] == 0.0  # no good copy: never fresh
    # a good, empty copy later: the tombstone stays
    feed.write_text("")
    n2 = _restart(n2)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == []
    assert "revoked: %s" % g["grant_id"] in mirror(n2)


def test_revoke_verb_persists_the_observation_before_reporting_success(tmp_path, hub, principal, capsys):
    """`revoke` writes the tombstone into the shared observation store, not
    only the local feed: with the feed deleted before any action reads it
    and the daemon restarted, the grant is still revoked."""
    from natively import cli
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["test.ping"]})
    g = issue_grant(n2, "beta", principal, max_uses=5)
    keyfile = tmp_path / "principal.key"
    keyfile.write_text(principal.seed.hex())
    cli.main(["--home", n2.home, "revoke", "--principal", str(keyfile), "--target", g["grant_id"]])
    assert "revoked:" in capsys.readouterr().out
    os.unlink(n2.revocations.local_path)
    n2 = _restart(n2)
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == []
    assert ("revoked", g["grant_id"]) in _checks(n2)


def test_duplicate_keys_in_the_observation_file_are_refused(tmp_path, hub, principal):
    """A seen file with a key twice is not a shape this node writes: it is
    refused at load (a last-wins parser would have silently dropped the
    first value's tombstones), and the action checked against it is
    refused, never run on an empty store."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["test.ping"]})
    g = issue_grant(n2, "beta", principal, max_uses=5)
    with open(n2.revocations.seen_path, "w") as f:
        f.write('{"local": ["%s"], "local": [], "feeds": {}}' % g["grant_id"])
    with pytest.raises(RevocationError, match="not the shape"):
        n2.revocations._reload()
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == []
    assert ("revoked", g["grant_id"]) in _checks(n2) and "not the shape" in mirror(n2)


def test_a_fetch_time_in_the_future_is_not_a_fresh_copy(tmp_path, principal):
    """A persisted fetch time ahead of the clock (a clock correction, a
    damaged file) neither satisfies the check interval nor the grace or
    offline allowance: the copy is due for a fetch now, and when the
    fetch fails the feed is unavailable."""
    home = str(tmp_path / "home")
    os.makedirs(home)
    url = "file://" + str(tmp_path / "feed.jsonl")
    with open(os.path.join(home, "revocations.seen.json"), "w") as f:
        json.dump({"local": [], "feeds": {url: {"fetched_at": time.time() + 10 ** 6, "targets": []}}}, f)

    def failing(url, timeout=10):
        raise OSError("down")
    r = revocation.Revocations(home, {principal.pub}, fetch=failing)
    with pytest.raises(revocation.FeedUnavailable):
        r.feed_targets(url, 60, {"offline_ok": True, "max_offline_s": 3600})
    # the same copy planted in memory is no fresher
    r2 = revocation.Revocations(home, {principal.pub}, fetch=failing)
    r2._reload()
    r2._feeds[url] = (time.time() + 10 ** 6, set())
    with pytest.raises(revocation.FeedUnavailable, match="future"):
        r2.feed_targets(url, 60, {"offline_ok": True, "max_offline_s": 3600})


def test_a_feed_line_nested_past_the_parser_keeps_the_tombstones_before_it(tmp_path, hub, principal):
    """A line the JSON parser cannot take at all (nested past its recursion
    limit) is a malformed line like any other: the tombstones verified
    before it are kept, and the grant is revoked."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["test.ping"]})
    feed = tmp_path / "feed.jsonl"
    feed.write_text("")
    url = "file://" + str(feed)
    g = issue_grant(n2, "beta", principal, max_uses=5, revocation_ledger=url, max_check_interval_s=60)
    feed.write_text(_tombstone_line(principal, g["grant_id"]) + "[" * 100000 + "]" * 100000 + "\n")
    with pytest.raises(revocation.FeedUnreadable) as e:
        revocation.parse_feed(feed.read_text(), {principal.pub})
    assert e.value.verified == {g["grant_id"]}
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == [] and g["grant_id"] in n2.revocations.known_targets()


def test_a_good_refresh_replaces_a_fetch_time_from_the_future(tmp_path, principal):
    """After a clock rollback the recorded fetch time is ahead of the clock;
    a fetch that succeeds now records now (the targets accumulate), so the
    copy is fresh for one interval and qualifies for grace afterwards."""
    home = str(tmp_path / "home")
    os.makedirs(home)
    feed = tmp_path / "feed.jsonl"
    feed.write_text("")
    url = "file://" + str(feed)
    r = revocation.Revocations(home, {principal.pub})
    r._feeds[url] = (time.time() + 10 ** 6, {"grt_" + "0" * 26})
    r.feed_targets(url, 60, {})
    ts, targets = r._feeds[url]
    assert ts <= time.time() and "grt_" + "0" * 26 in targets
    r._fetch = lambda url, timeout=10: (_ for _ in ()).throw(OSError("down"))
    r._feeds[url] = (time.time() - 61, targets)  # due for a refresh, inside grace
    assert r.feed_targets(url, 60, {}) == targets


def test_feed_lines_are_decoded_one_at_a_time_and_split_on_newlines_only(tmp_path, hub, principal):
    """A line that is not UTF-8 after a verified tombstone loses nothing:
    the verified target is kept. A Unicode line separator inside a
    tombstone's reason is content, not a line break."""
    n1 = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n2 = make_node(tmp_path, "n2", hub.url, principal, {"beta": ["test.ping"]})
    feed = tmp_path / "feed.jsonl"
    feed.write_bytes(b"")
    url = "file://" + str(feed)
    g = issue_grant(n2, "beta", principal, max_uses=5, revocation_ledger=url, max_check_interval_s=60)
    feed.write_bytes(_tombstone_line(principal, g["grant_id"]).encode() + b"\xff\xfe not utf-8\n")
    with pytest.raises(revocation.FeedUnreadable, match="UTF-8") as e:
        revocation.parse_feed(feed.read_bytes(), {principal.pub})
    assert e.value.verified == {g["grant_id"]}
    send_action(n1, "alpha", n2, "beta", [g["grant_id"]])
    pump([n1, n2], 3)
    assert outcomes(n2, "test.ping") == [] and g["grant_id"] in n2.revocations.known_targets()
    t = revocation.make_tombstone(principal.seed, "grt_" + "1" * 26, "line\u2028break inside the reason")
    assert revocation.parse_feed(json.dumps(t) + "\n", {principal.pub}) == {"grt_" + "1" * 26}


def test_grace_is_judged_after_the_verified_prefix_is_persisted(tmp_path, principal, monkeypatch):
    """Persisting the verified tombstones of an unreadable feed can wait on
    a lock or a slow disk; the copy's age is read after that wait, so a
    deadline crossed while persisting refuses rather than runs."""
    home = str(tmp_path / "home")
    os.makedirs(home)
    feed = tmp_path / "feed.jsonl"
    feed.write_text(_tombstone_line(principal, "grt_" + "2" * 26) + "not json\n")
    url = "file://" + str(feed)
    r = revocation.Revocations(home, {principal.pub})
    r._feeds[url] = (time.time() - 1.5, set())  # inside 2 x 1 s grace as the fetch begins
    real_keep = r._keep_targets

    def slow_keep(u, targets):
        time.sleep(1.0)  # ...past it once the observation is on disk
        return real_keep(u, targets)
    monkeypatch.setattr(r, "_keep_targets", slow_keep)
    with pytest.raises(revocation.FeedUnavailable, match="past grace"):
        r.feed_targets(url, 1, {})
    assert "grt_" + "2" * 26 in r.known_targets()


def test_a_body_cut_short_by_the_transport_keeps_its_complete_lines(tmp_path, principal):
    """An HTTP response that ends early raises IncompleteRead; the complete
    tombstone lines it did carry are kept (without a fetch time), so a
    grant revoked in them does not run on the older cached copy."""
    import http.client
    home = str(tmp_path / "home")
    os.makedirs(home)
    url = "https://example.invalid/feed.jsonl"
    gid = "grt_" + "3" * 26
    partial = _tombstone_line(principal, gid).encode() + b'{"kind": "tombstone", "signer": "cut'

    def cut_short(u, timeout=10):
        raise http.client.IncompleteRead(partial)
    r = revocation.Revocations(home, {principal.pub}, fetch=cut_short)
    r._feeds[url] = (time.time() - 61, set())  # an older good copy: due for a fetch, inside grace
    assert r.feed_targets(url, 60, {}) == {gid}  # the cached copy serves under grace, with the tombstone read before the cut
    assert gid in r.known_targets()
    assert r._feeds[url][0] < time.time() - 60  # and no fetch time was advanced
    fresh = revocation.Revocations(home, {principal.pub}, fetch=cut_short)
    assert gid in fresh.known_targets()  # persisted


def test_a_fresh_copy_is_judged_by_its_age_after_it_is_persisted(tmp_path, principal, monkeypatch):
    """A fetch that succeeds and then waits on persistence is not fresh by
    the time it is approved if the wait outlived the interval: the copy is
    judged under grace and the offline allowance like any other."""
    home = str(tmp_path / "home")
    os.makedirs(home)
    feed = tmp_path / "feed.jsonl"
    feed.write_text("")
    url = "file://" + str(feed)
    r = revocation.Revocations(home, {principal.pub})
    real_persist = r._persist

    def slow_persist():
        time.sleep(2.5)
        return real_persist()
    monkeypatch.setattr(r, "_persist", slow_persist)
    with pytest.raises(revocation.FeedUnavailable, match="outlived"):
        r.feed_targets(url, 1, {})
    r._feeds.pop(url, None)
    r._tried.pop(url, None)
    assert r.feed_targets(url, 1, {"offline_ok": True, "max_offline_s": 3600}) == set()


"""Persisted hub state must not resurrect directory entries that could not
register today. Fleet sweep 2026-09-08: dead sandbox roots registered
before the registration allowlist existed (#24) were still listed 19-34h
after their containers died, because _load() rehydrated agent_dir with no
revalidation; expired cards would linger for the same reason."""
import json
import os

from natively import crypto, envelope
from natively.hub import State, fingerprint

from conftest import Principal


def _entry(principal_seed, ttl_s=3600):
    """One node with one agent; returns (node_fp, name, agent_dir entry,
    node_key_b64)."""
    node_seed = crypto.gen_signing_key()
    node_pub = crypto.sign_pub(node_seed)
    node_b64 = crypto.b64e(node_pub)
    fp = fingerprint(node_b64)
    agent_seed = crypto.gen_signing_key()
    card = envelope.make_card(agent_seed, node_pub, principal_seed,
                              ["msg.send"], "", ttl_s=ttl_s)
    name = "a@%s" % fp
    return fp, name, {"agent_key": card["agent_key"], "card": card,
                      "node_fp": fp}, node_b64


def _state(path, entries):
    d = {"prekeys": {}, "nodes": {}, "agent_dir": {}, "agent_owner": {},
         "queues": {}, "seq": {}}
    for fp, name, e, node_b64 in entries:
        d["agent_dir"][name] = e
        d["agent_owner"][e["agent_key"].split(":", 1)[1]] = fp
        d["nodes"][fp] = {"name": "n", "agents": [name.split("@")[0]]}
        d["prekeys"][fp] = {"node_key": "ed25519:" + node_b64}
    json.dump(d, open(path, "w"))


def test_load_prunes_foreign_root_and_expired(tmp_path):
    allowed, rogue = Principal(), Principal()
    good = _entry(allowed.seed)
    bad_root = _entry(rogue.seed)
    expired = _entry(allowed.seed, ttl_s=-10)
    path = str(tmp_path / "hub.json")
    _state(path, [good, bad_root, expired])

    st = State(path, principal_roots=[allowed.pub])

    assert list(st.agent_dir) == [good[1]]
    assert list(st.nodes) == [good[0]]
    assert list(st.prekeys) == [good[0]]
    assert st.agent_owner == {good[2]["agent_key"].split(":", 1)[1]: good[0]}


def test_load_without_allowlist_keeps_roots_but_prunes_expired(tmp_path):
    rogue = Principal()
    fresh = _entry(rogue.seed)
    expired = _entry(rogue.seed, ttl_s=-10)
    path = str(tmp_path / "hub.json")
    _state(path, [fresh, expired])

    st = State(path)  # no root restriction

    assert sorted(st.agent_dir) == [fresh[1]]
    assert sorted(st.nodes) == [fresh[0]]


def test_orphaned_node_drops_only_when_last_agent_goes(tmp_path):
    allowed, rogue = Principal(), Principal()
    # one node whose two agents are pruned for different reasons
    node_seed = crypto.gen_signing_key()
    node_pub = crypto.sign_pub(node_seed)
    node_b64 = crypto.b64e(node_pub)
    fp = fingerprint(node_b64)
    entries = []
    for i, (seed, ttl) in enumerate([(rogue.seed, 3600), (allowed.seed, -10)]):
        agent_seed = crypto.gen_signing_key()
        card = envelope.make_card(agent_seed, node_pub, seed, ["msg.send"], "", ttl_s=ttl)
        name = "a%d@%s" % (i, fp)
        entries.append((fp, name, {"agent_key": card["agent_key"], "card": card,
                                   "node_fp": fp}, node_b64))
    keep = _entry(allowed.seed)
    entries.append(keep)
    path = str(tmp_path / "hub.json")
    _state(path, entries)

    st = State(path, principal_roots=[allowed.pub])

    assert list(st.agent_dir) == [keep[1]]
    assert fp not in st.nodes and fp not in st.prekeys
    assert list(st.nodes) == [keep[0]]

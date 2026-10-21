"""Owner-only node homes (node 96, 2026-10-21). Under the default umask
022 the home was 0755 when it already existed, and state.json (by way of
state.json.tmp), the ledger, its prose mirror and the lock files came
back 0644 within seconds of a chmod. Only the plist's Umask 077 kept them
private. The node now creates each of them 0600 itself, and init_node
makes the home 0700."""
import os
import stat

import pytest

from natively import envelope, node as nodemod

from conftest import make_node


@pytest.fixture
def umask022():
    old = os.umask(0o022)
    yield
    os.umask(old)


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_init_node_makes_a_new_home_owner_only(tmp_path, principal, umask022):
    home = str(tmp_path / "fresh")
    nodemod.init_node(home, "fresh", "http://127.0.0.1:9", principal.pub)
    assert _mode(home) == 0o700


def test_init_node_makes_an_existing_home_owner_only(tmp_path, principal, umask022):
    home = str(tmp_path / "existing")
    os.mkdir(home, 0o755)
    assert _mode(home) == 0o755
    nodemod.init_node(home, "existing", "http://127.0.0.1:9", principal.pub)
    assert _mode(home) == 0o700


def test_state_ledger_mirror_and_node_lock_are_created_0600(tmp_path, hub, principal, umask022):
    n = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    n.step()
    n._save_state()
    for f in ("state.json", "ledger.jsonl", "ledger.jsonl.prose", "ledger.jsonl.lock", "node.lock"):
        assert _mode(os.path.join(n.home, f)) == 0o600, f


def test_group_and_revocation_locks_are_created_0600(tmp_path, hub, principal, umask022):
    n = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    gid = envelope.new_id("grp")
    with n._group_lock(gid):
        pass
    assert _mode(n._group_path(gid) + ".lock") == 0o600
    n.revocations._persist()
    assert _mode(n.revocations.lock_path) == 0o600


def test_a_torn_tail_archive_is_created_0600(tmp_path, hub, principal, umask022):
    n = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    with open(n.ledger.path, "ab") as f:
        f.write(b'{"torn')
    nodemod.Ledger(n.ledger.path)
    assert _mode(n.ledger.torn_path) == 0o600


def test_an_existing_file_keeps_its_mode(tmp_path, hub, principal, umask022):
    n = make_node(tmp_path, "n1", hub.url, principal, {"alpha": ["msg.send"]})
    os.chmod(n.ledger.mirror_path, 0o640)
    n.ledger.append("node:n1", None, "test.mode", {}, "ok", "")
    assert _mode(n.ledger.mirror_path) == 0o640  # created 0600, never chmodded behind the operator

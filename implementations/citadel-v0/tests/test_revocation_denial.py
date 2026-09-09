from datetime import UTC, datetime, timedelta

import pytest

from natively import denial as denialmod
from natively import keys
from natively import revocation as revmod
from natively.errors import VerifyError

from .conftest import uid

TS = "2026-09-07T07:00:00Z"
NOW = datetime(2026, 9, 7, 7, 0, 0, tzinfo=UTC)


@pytest.fixture
def principal():
    return keys.KeyPair.generate()


def test_revocation_sign_verify_feed(tmp_path, principal):
    g1, g2 = uid("grt"), uid("grt")
    r = revmod.sign(
        revmod.build(
            principal_key=principal.public, ts=TS, grants=[g1], principal_statement="stop"
        ),
        principal,
    )
    revmod.verify(r, pinned={principal.public})
    with pytest.raises(VerifyError) as e:
        revmod.verify(r, pinned=set())
    assert e.value.reason == "revocation.principal.unpinned"
    with pytest.raises(VerifyError):
        revmod.verify({**r, "revokes": {"cards": [], "grants": [g2]}}, pinned={principal.public})
    # ids are validated in full: a bare prefix or a path is not an id
    for bad in (["grt_1"], ["grt_../x"]):
        with pytest.raises(VerifyError) as e:
            revmod.verify(
                revmod.sign(
                    revmod.build(principal_key=principal.public, ts=TS, grants=bad), principal
                ),
                pinned={principal.public},
            )
        assert e.value.reason == "revocation.revokes.grants"
    feed = revmod.RevocationFeed(tmp_path / "rev.jsonl")
    assert feed.add(r, pinned={principal.public}) == "recorded"
    assert feed.add(r, pinned={principal.public}) == "duplicate"  # the exact body again
    assert feed.grant_revoked_by(g1, principal.public)["rev_id"] == r["rev_id"]
    assert feed.grant_revoked_by(g1, keys.KeyPair.generate().public) is None
    assert feed.card_revoked_by("sha256:" + "0" * 64, principal.public) is None
    with pytest.raises(ValueError):
        revmod.build(principal_key=principal.public, ts=TS)


def test_freshness_fail_closed(tmp_path):
    feed = revmod.RevocationFeed(tmp_path / "rev.jsonl")
    grant = {"revocation": {"max_check_interval_s": 300}}
    write = {"offline_ok": False, "max_offline_s": 0}
    info = {"offline_ok": True, "max_offline_s": 3600}
    with pytest.raises(VerifyError) as e:
        feed.assert_fresh(grant, write, NOW, grace_s=60)
    assert e.value.reason == "revocation.never_checked"
    feed.mark_checked(NOW)
    feed.assert_fresh(grant, write, NOW + timedelta(seconds=360), grace_s=60)
    with pytest.raises(VerifyError) as e:
        feed.assert_fresh(grant, write, NOW + timedelta(seconds=361), grace_s=60)
    assert e.value.reason == "revocation.stale"
    feed.assert_fresh(grant, info, NOW + timedelta(seconds=3600), grace_s=60)
    with pytest.raises(VerifyError):
        feed.assert_fresh(grant, info, NOW + timedelta(seconds=3601), grace_s=60)


def test_denial_sign_verify_store(tmp_path, principal):
    d = denialmod.sign(
        denialmod.build(
            principal_key=principal.public,
            ts=TS,
            deny=[{"action": "*", "resource": "host:n:customers/*"}],
            principal_statement="never",
        ),
        principal,
    )
    denialmod.verify(d, pinned={principal.public})
    with pytest.raises(VerifyError):
        denialmod.verify(d, pinned=set())
    with pytest.raises(VerifyError):
        denialmod.verify({**d, "deny": []}, pinned={principal.public})
    store = denialmod.DenialStore(tmp_path / "d.jsonl")
    assert store.add(d, pinned={principal.public}) and not store.add(d, pinned={principal.public})
    hit = store.denied(
        action="fs.write",
        resource="host:n:customers/list",
        card_hash="sha256:x",
        principal_key=principal.public,
    )
    assert hit["denial_id"] == d["denial_id"]
    assert (
        store.denied(
            action="fs.write",
            resource="host:n:scratch/x",
            card_hash="sha256:x",
            principal_key=principal.public,
        )
        is None
    )
    assert (
        store.denied(
            action="fs.write",
            resource="host:n:customers/list",
            card_hash="sha256:x",
            principal_key=keys.KeyPair.generate().public,
        )
        is None
    )
    # a denial scoped to one card does not bind another
    d2 = denialmod.sign(
        denialmod.build(
            principal_key=principal.public,
            ts=TS,
            subject_agent="sha256:only",
            deny=[{"action": "fs.write", "resource": "*"}],
            principal_statement="only that one",
        ),
        principal,
    )
    store.add(d2, pinned={principal.public})
    assert (
        store.denied(
            action="fs.write",
            resource="host:n:scratch/x",
            card_hash="sha256:only",
            principal_key=principal.public,
        )["denial_id"]
        == d2["denial_id"]
    )
    assert (
        store.denied(
            action="fs.write",
            resource="host:n:scratch/x",
            card_hash="sha256:other",
            principal_key=principal.public,
        )
        is None
    )
    with pytest.raises(ValueError):
        denialmod.build(principal_key=principal.public, ts=TS, deny=[], principal_statement="x")

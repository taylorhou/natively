import os

import pytest

from natively import keys
from natively.errors import VerifyError


def test_generate_sign_verify_roundtrip():
    kp = keys.KeyPair.generate()
    assert kp.public.startswith("ed25519:")
    sig = kp.sign(b"hello")
    keys.verify(kp.public, b"hello", sig)
    with pytest.raises(VerifyError) as e:
        keys.verify(kp.public, b"hellp", sig)
    assert e.value.reason == "sig.invalid"


def test_verify_rejects_malformed():
    kp = keys.KeyPair.generate()
    with pytest.raises(VerifyError) as e:
        keys.verify("rsa:abc", b"x", kp.sign(b"x"))
    assert e.value.reason == "sig.key.format"
    with pytest.raises(VerifyError):
        keys.verify(kp.public, b"x", "not base64!")
    with pytest.raises(VerifyError):
        keys.verify(kp.public, b"x", "AAAA")


def test_save_load_and_permissions(tmp_path):
    kp = keys.KeyPair.generate()
    p = keys.save(kp, tmp_path, "agent")
    assert p.stat().st_mode & 0o777 == 0o600
    assert keys.load(tmp_path, "agent").public == kp.public
    assert (tmp_path / "agent.pub").read_text().strip() == kp.public
    with pytest.raises(FileExistsError):
        keys.save(kp, tmp_path, "agent")
    os.chmod(p, 0o644)
    with pytest.raises(PermissionError):
        keys.load(tmp_path, "agent")


def test_generate_all(tmp_path):
    pubs = keys.generate_all(tmp_path)
    assert set(pubs) == set(keys.ROLES)
    assert len(set(pubs.values())) == 3
    with pytest.raises(FileNotFoundError):
        keys.load(tmp_path, "nope")


def test_repr_never_leaks_seed():
    kp = keys.KeyPair.generate()
    assert kp.seed().hex() not in repr(kp)

import pytest

from natively import bundle as bundlemod
from natively.errors import VerifyError


def test_encode_decode_roundtrip():
    b = bundlemod.make("message", {"msg_id": "msg_1", "body": "x" * 500}, cards=[{"a": 1}])
    text = bundlemod.encode(b)
    lines = text.splitlines()
    assert lines[0] == "X-Natively: v0" and all(len(ln) <= 76 for ln in lines[1:])
    assert bundlemod.decode(text) == b
    # mail-client rewraps, CRLF, leading blank lines and a quoted reply below all survive
    mangled = (
        "\r\n\r\n"
        + text.replace("\n", "\r\n").replace("\r\n", "\r\n  ", 3)
        + "\r\n\r\n> quoted\r\n"
    )
    assert bundlemod.decode(mangled) == b


@pytest.mark.parametrize(
    "text,reason",
    [
        ("hello\n", "wire.header"),
        ("X-Natively: v1\nAAAA\n", "wire.header"),
        ("X-Natively: v0\n@@@@\n", "wire.base64"),
        ("X-Natively: v0\naGVsbG8=\n", "wire.json"),
        ("X-Natively: v0\neyJhIjoxfQ==\n", "bundle.version"),
    ],
)
def test_decode_rejects(text, reason):
    with pytest.raises(VerifyError) as e:
        bundlemod.decode(text)
    assert e.value.reason == reason


def test_check_rejects_shape():
    with pytest.raises(VerifyError) as e:
        bundlemod.check(
            {"natively": "v0", "kind": "message", "object": {}, "cards": [], "grants": [], "x": 1}
        )
    assert e.value.reason == "bundle.fields"
    with pytest.raises(VerifyError):
        bundlemod.check(
            {"natively": "v0", "kind": "spell", "object": {}, "cards": [], "grants": []}
        )
    with pytest.raises(ValueError):
        bundlemod.make("spell", {})

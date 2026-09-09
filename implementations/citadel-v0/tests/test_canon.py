import math

import pytest

from natively.canon import canonicalize, hash_of

BS = chr(92)  # backslash, spelled out so no editor/transport turns escapes into bytes
C0F, LF, DQ = chr(0x0F), chr(0x0A), chr(0x22)


def test_rfc8785_example_vector():
    # RFC 8785 section 3.2.3 example input and its canonical output.
    value = {
        "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 0.000000000000000000000000001],
        "string": "€$" + C0F + LF + "A'B" + DQ + BS + BS + DQ + "/",
        "literals": [None, True, False],
    }
    expected = (
        '{"literals":[null,true,false],'
        '"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        '"string":"€$' + BS + "u000f" + BS + "nA'B" + BS + DQ + BS + BS + BS + BS + BS + DQ + '/"}'
    )
    assert canonicalize(value).decode("utf-8") == expected


def test_rfc8785_example_bytes():
    # Euro sign stays raw UTF-8; C0 controls become lowercase \u escapes.
    b = canonicalize({"string": "€" + C0F})
    assert b == b'{"string":"\xe2\x82\xac' + BS.encode() + b'u000f"}'


def test_key_order_is_utf16_code_units():
    # U+1D11E (surrogate pair, first unit 0xD834) sorts BEFORE U+E000 in UTF-16
    # but AFTER it by code point. RFC 8785 3.2.3 requires UTF-16 unit order.
    astral, private = chr(0x1D11E), chr(0xE000)
    value = {astral: 1, private: 2, "Ā": 3, "a": 4}
    out = canonicalize(value).decode("utf-8")
    assert out == '{"a":4,"Ā":3,"' + astral + '":1,"' + private + '":2}'


@pytest.mark.parametrize(
    "num,text",
    [
        (0, "0"),
        (0.0, "0"),
        (-0.0, "0"),
        (1, "1"),
        (-5, "-5"),
        (100.0, "100"),
        (1e21, "1e+21"),
        (1e20, "100000000000000000000"),
        (1e-6, "0.000001"),
        (1e-7, "1e-7"),
        (123456789012345680000.0, "123456789012345680000"),
        (0.1, "0.1"),
        (1.5e300, "1.5e+300"),
        (2**53, "9007199254740992"),
    ],
)
def test_number_formatting(num, text):
    assert canonicalize(num).decode() == text


def test_rejects_non_es6_numbers():
    with pytest.raises(ValueError):
        canonicalize(math.nan)
    with pytest.raises(ValueError):
        canonicalize(math.inf)
    with pytest.raises(ValueError):
        canonicalize(2**53 + 1)


def test_bool_is_literal_not_number():
    assert canonicalize([True, 1]) == b"[true,1]"


def test_control_chars_and_escapes():
    s = chr(0) + chr(0x1F) + chr(0x7F) + chr(8) + chr(9)
    expected = '"' + BS + "u0000" + BS + "u001f" + chr(0x7F) + BS + "b" + BS + 't"'
    assert canonicalize(s).decode() == expected


def test_rejects_non_string_keys():
    with pytest.raises(TypeError):
        canonicalize({1: "a"})


def test_hash_of_drops_sig():
    a = {"x": 1, "sig": "zzz"}
    b = {"x": 1}
    assert hash_of(a, drop=("sig",)) == hash_of(b)
    assert hash_of(a) != hash_of(b)
    assert hash_of(b).startswith("sha256:") and len(hash_of(b)) == 7 + 64

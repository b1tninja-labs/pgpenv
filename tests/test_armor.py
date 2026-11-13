"""ASCII armor (RFC 9580 sec. 6) and the cleartext signature framework (sec. 7)."""

from __future__ import annotations

import base64
import hashlib

import pytest

from pgpenv import armor, cleartext, signature
from pgpenv.errors import ArmorError, CleartextError, LimitError
from pgpenv.limits import Limits
from pgpenv.packet import parse_packets

from . import vectors as v
from .helpers import fixture, pkt


def test_crc24_known_values():
    # RFC 9580 sec. 6.1: the initial value is 0xB704CE, which the empty input leaves unchanged.
    assert armor.crc24(b"") == 0xB704CE
    # one octet, worked by hand through the loop of the C code in sec. 6.1.1
    crc = 0xB704CE ^ (0x41 << 16)
    for _ in range(8):
        crc <<= 1
        if crc & 0x1000000:
            crc = (crc & 0xFFFFFF) ^ 0x864CFB
    assert armor.crc24(b"A") == crc & 0xFFFFFF


def test_gnupg_checksums_verify():
    blocks = armor.decode_blocks(fixture("rsa2048.asc"))
    assert [b.crc for b in blocks] == ["ok"]


def test_a1_block_decodes_and_first_packet_is_tag_6():
    # the RFC prints the packet with a legacy header (0x98) and armors it with a new-format one
    (armored,) = parse_packets(armor.decode(v.A1_ARMOR))
    (printed,) = parse_packets(v.A1_PACKET)
    assert armored.tag == printed.tag == 6
    assert printed.legacy
    assert not armored.legacy
    assert armored.body == printed.body


def test_bad_crc_is_not_a_rejection():
    text = fixture("rsa2048.asc").decode()
    lines = text.splitlines()
    crc_at = next(i for i, line in enumerate(lines) if line.startswith("=") and len(line) == 5)
    lines[crc_at] = "=AAAA"
    (block,) = armor.decode_blocks("\n".join(lines))
    assert block.crc == "mismatch"
    assert block.data == armor.decode(text)


def test_missing_and_malformed_crc_are_accepted():
    data = fixture("ed25519.pgp")
    assert armor.decode_blocks(armor.encode(data))[0].crc == "absent"
    body = base64.b64encode(data).decode()
    for footer in ("=!!!!", "=AB"):
        text = (
            f"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n{body}\n{footer}\n"
            "-----END PGP PUBLIC KEY BLOCK-----\n"
        )
        (block,) = armor.decode_blocks(text)
        assert (block.crc, block.data) == ("malformed", data)


def test_encode_never_emits_a_crc_by_default_and_checks_out_when_asked():
    data = fixture("ed25519.pgp")
    assert "\n=" not in armor.encode(data)
    (block,) = armor.decode_blocks(armor.encode(data, crc=True))
    assert block.crc == "ok"
    assert block.data == data


def test_encode_infers_the_label_and_wraps_at_76():
    assert armor.encode(pkt(6, b"x" * 90)).startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
    assert armor.encode(pkt(2, b"x" * 90)).startswith("-----BEGIN PGP SIGNATURE-----")
    assert armor.encode(pkt(5, b"x")).startswith("-----BEGIN PGP PRIVATE KEY BLOCK-----")
    assert armor.encode(pkt(11, b"x")).startswith("-----BEGIN PGP MESSAGE-----")
    out = armor.encode(bytes(300), kind="PGP MESSAGE")
    assert max(len(line) for line in out.splitlines()) <= 76
    assert armor.decode(out) == bytes(300)


def test_armor_headers_round_trip_and_are_validated():
    text = armor.encode(bytes(10), {"Comment": "hello: world"}, kind="PGP MESSAGE")
    assert armor.decode_blocks(text)[0].headers == (("Comment", "hello: world"),)
    with pytest.raises(ArmorError):
        armor.encode(bytes(10), {"Bad:Key": "v"}, kind="PGP MESSAGE")
    with pytest.raises(ArmorError):
        armor.encode(bytes(10), {"K": "a\nb"}, kind="PGP MESSAGE")


def test_two_blocks_and_garbage_between_them():
    a = armor.encode(b"\xc0\x00", kind="PGP MESSAGE")
    b = armor.encode(b"\xc0\x01\x00", kind="PGP MESSAGE")
    blocks = armor.decode_blocks("noise\n" + a + "more noise = - \n" + b + "tail")
    assert [x.data for x in blocks] == [b"\xc0\x00", b"\xc0\x01\x00"]
    with pytest.raises(ArmorError, match="exactly one"):
        armor.decode(a + b)
    with pytest.raises(ArmorError, match="exactly one"):
        armor.decode("no armor here")


def test_whitespace_in_the_base64_body_is_ignored_and_crlf_accepted():
    text = armor.encode(bytes(range(200)), kind="PGP MESSAGE").replace("\n", "\r\n")
    assert armor.decode(text.replace("A", "A ")) == bytes(range(200))


@pytest.mark.parametrize(
    "text",
    [
        "-----BEGIN PGP MESSAGE-----\n\nAAAA!AAA\n-----END PGP MESSAGE-----\n",
        "-----BEGIN PGP MESSAGE-----\n\nAAAA\n-----END PGP SIGNATURE-----\n",
        "-----BEGIN PGP MESSAGE-----\n\nAAAA\n",
        "-----BEGIN PGP MESSAGE-----\n",
        "-----BEGIN PGP MESSAGE-----\n\nAAA\n-----END PGP MESSAGE-----\n",
        "-----BEGIN PGP MESSAGE-----\n\nAAAA\n=AAAA\nAAAA\n-----END PGP MESSAGE-----\n",
        "-----BEGIN PGP MESSAGE-----\nnot a header at all\n\nAAAA\n-----END PGP MESSAGE-----\n",
    ],
)
def test_damaged_armor_is_refused(text):
    with pytest.raises(ArmorError):
        armor.decode_blocks(text)


def test_truncated_armor_is_reported_not_crashing():
    text = armor.encode(fixture("ed25519.pgp"))
    for cut in range(0, len(text), 7):
        try:
            armor.decode_blocks(text[:cut])
        except ArmorError:
            continue


def test_oversized_armor_is_bounded():
    with pytest.raises(LimitError):
        armor.decode_blocks("A" * 100, Limits(max_input_bytes=50))
    with pytest.raises(LimitError):
        armor.decode_blocks(
            "-----BEGIN PGP MESSAGE-----\n\n" + "A" * 200, Limits(max_armor_line_bytes=100)
        )


# --- cleartext signature framework -------------------------------------------------------------


def test_a6_cleartext_returns_the_exact_signed_text():
    msg = cleartext.parse(v.A6_MESSAGE)
    assert msg.text == v.A6_TEXT
    assert msg.hash_names == ()
    (sig_block,) = msg.signatures
    sig = signature.parse_signature(parse_packets(sig_block.data)[0].body)
    digest = hashlib.sha512(signature.hash_stream(sig, document=msg.text, text_is_canonical=True))
    assert digest.hexdigest() == v.A6_SHA512
    assert digest.digest()[:2] == sig.left16


def test_cleartext_from_gnupg_hashes_to_the_signature_left_bits():
    msg = cleartext.parse(fixture("msg.txt.clearsigned.asc"))
    assert msg.hash_names == ("SHA512",)
    assert msg.text == b"pgpenv fixture message\r\n"
    sig = signature.parse_signature(parse_packets(msg.signatures[0].data)[0].body)
    stream = signature.hash_stream(sig, document=msg.text, text_is_canonical=True)
    assert hashlib.sha512(stream).digest()[:2] == sig.left16


def test_dash_escaping_trailing_whitespace_and_line_endings():
    sig = armor.encode(bytes(3), kind="PGP SIGNATURE")
    raw = (
        "-----BEGIN PGP SIGNED MESSAGE-----\r\nHash: SHA256,SHA512\r\n\r\n"
        "- -dash  \t\r\n- - three\r\nplain \r\n\r\n" + sig
    )
    msg = cleartext.parse(raw)
    assert msg.text == b"-dash\r\n- three\r\nplain\r\n"
    assert msg.hash_names == ("SHA256", "SHA512")
    assert cleartext.parse(raw.replace("\r\n", "\n")).text == msg.text


def test_empty_cleartext_has_empty_text():
    sig = armor.encode(bytes(3), kind="PGP SIGNATURE")
    assert cleartext.parse("-----BEGIN PGP SIGNED MESSAGE-----\n\n" + sig).text == b""


@pytest.mark.parametrize(
    "head",
    [
        "Comment: sneaky\n",
        "Hash: SHA256, SHA512\n",
        "Hash: MD6\n",
        "Hash:\n",
        "Charset: utf-8\n",
    ],
)
def test_nonconformant_headers_refuse_validation(head):
    sig = armor.encode(bytes(3), kind="PGP SIGNATURE")
    with pytest.raises(CleartextError):
        cleartext.parse("-----BEGIN PGP SIGNED MESSAGE-----\n" + head + "\ntext\n\n" + sig)


def test_unescaped_armor_looking_line_is_refused_and_other_dashes_warn():
    sig = armor.encode(bytes(3), kind="PGP SIGNATURE")
    with pytest.raises(CleartextError, match="dash"):
        cleartext.parse(
            "-----BEGIN PGP SIGNED MESSAGE-----\n\n-----BEGIN PGP MESSAGE-----\n\n" + sig
        )
    msg = cleartext.parse("-----BEGIN PGP SIGNED MESSAGE-----\n\n-x\n\n" + sig)
    assert msg.text == b"-x\r\n"
    assert msg.warnings


def test_cleartext_without_a_signature_is_refused():
    with pytest.raises(CleartextError):
        cleartext.parse("-----BEGIN PGP SIGNED MESSAGE-----\n\ntext\n")
    with pytest.raises(CleartextError):
        cleartext.parse("just text")
    with pytest.raises(CleartextError):
        cleartext.parse(
            "-----BEGIN PGP SIGNED MESSAGE-----\n\ntext\n\n-----BEGIN PGP SIGNATURE-----\n\n!!\n"
        )

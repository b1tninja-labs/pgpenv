"""Signature packets, subpackets and the hashed-data recipe (RFC 9580 sec. 5.2, 5.2.4, 13.13)."""

from __future__ import annotations

import hashlib

import pytest

from pgpenv import armor, load_key, signature
from pgpenv.certificate import parse_keyring
from pgpenv.errors import LimitError, SignatureError
from pgpenv.limits import Limits
from pgpenv.packet import parse_packets
from pgpenv.registry import HASHES
from pgpenv.signature import Notation, parse_signature
from pgpenv.wire import Mpi

from . import vectors as v
from .helpers import fixture, sig_v4_body, subpacket

CREATED = subpacket(2, (1_700_000_000).to_bytes(4, "big"))
FP20 = bytes(range(20))


def sig_of(armored: str):
    return parse_signature(parse_packets(armor.decode(armored))[0].body)


def test_issuer_fingerprint_is_read_from_hashed_area():
    cert = load_key(v.A3_ARMOR)
    sig = cert.signatures[0]
    assert sig.version == 6
    assert sig.sig_type == 0x1F
    assert (sig.pub_algo, sig.hash_algo) == (27, 10)
    assert sig.issuer_fingerprint == (6, bytes.fromhex(v.A3_PRIMARY_FINGERPRINT))
    assert sig.issuer_area == "hashed"
    assert sig.issuer_keyid == bytes.fromhex(v.A3_PRIMARY_FINGERPRINT)[:8]
    assert sig.created == 1669824483
    assert sig.key_flags == b"\x03"
    assert sig.value(30) == b"\x09"
    assert sig.value(21) == (10, 14, 8, 12)
    assert sig.value(39) == ((9, 2), (7, 2))
    assert sig.value(11) == (9, 7)
    assert sig.usable


def test_ed25519_signature_material_is_not_parsed_as_mpi():
    """Erratum 8454: Ed25519 and Ed448 signatures are native octet strings (sec. 5.2.3)."""
    cert = load_key(v.A3_ARMOR)
    (raw,) = cert.signatures[0].parts()
    assert isinstance(raw, bytes)
    assert len(raw) == 64
    legacy = sig_of(v.A2_ARMOR)  # EdDSALegacy in v4: two MPIs
    r, s = legacy.parts()
    assert isinstance(r, Mpi)
    assert isinstance(s, Mpi)
    assert r.octets.hex() == "56f90cca98e2102637bd983fdb16c131dfd27ed82bf4dde5606e0d756aed3366"


def test_a2_v4_signature_fields_and_hashed_input():
    sig = sig_of(v.A2_ARMOR)
    assert (sig.version, sig.sig_type, sig.pub_algo, sig.hash_algo) == (4, 0, 22, 8)
    assert sig.created == 1442406293  # 2015-09-16 12:24:53 UTC, as A.2 states
    assert sig.issuer_keyid.hex() == "8cfde12197965a9a"
    assert sig.issuer_area == "unhashed"
    assert sig.salt is None
    stream = signature.hash_stream(sig, document=b"OpenPGP")
    assert stream == v.A2_HASHED_INPUT
    assert hashlib.sha256(stream).hexdigest() == v.A2_DIGEST
    assert hashlib.sha256(stream).digest()[:2] == sig.left16


def test_a3_hash_streams_match_the_rfc_dumps():
    cert = load_key(v.A3_ARMOR)
    direct = cert.signatures[0]
    assert signature.hash_stream(direct, key=cert.primary) == v.A3_DIRECT_KEY_STREAM
    assert hashlib.sha512(v.A3_DIRECT_KEY_STREAM).digest()[:2] == direct.left16
    sub = cert.subkeys[0]
    binding = sub.signatures[0]
    stream = signature.hash_stream(binding, key=cert.primary, subkey=sub.key)
    assert stream == v.A3_SUBKEY_BINDING_STREAM
    assert hashlib.sha512(stream).digest()[:2] == binding.left16


def test_salt_is_present_in_v6_and_absent_in_v4():
    assert len(load_key(v.A3_ARMOR).signatures[0].salt) == 32
    assert sig_of(v.A2_ARMOR).salt is None


def test_every_gnupg_signature_hashes_to_its_left_16_bits():
    """The recipe for certifications, bindings, revocations and back-signatures, against GnuPG's own output.

    GnuPG wrote the signatures and the two quick-check octets; recomputing them from pgpenv's
    hash_stream() with hashlib shows the recipe is the one a real implementation used, without
    verifying (or trusting) any public key operation.
    """
    checked = {0x10: 0, 0x13: 0, 0x18: 0, 0x19: 0, 0x1F: 0, 0x20: 0, 0x28: 0}
    for name in ("rsa2048", "ed25519", "nistp256", "nistp384", "dsaelg", "brainpool", "rsa4096"):
        cert = load_key(fixture(name + ".pgp"))
        primary = cert.primary

        def check(sig, **kwargs):
            info = HASHES[sig.hash_algo]
            digest = hashlib.new(info.hashlib_name, signature.hash_stream(sig, **kwargs)).digest()
            assert digest[:2] == sig.left16, hex(sig.sig_type)
            checked[sig.sig_type] = checked.get(sig.sig_type, 0) + 1

        for sig in cert.signatures:
            check(sig, key=primary)
        for uid in cert.user_ids:
            for sig in uid.signatures:
                check(sig, key=primary, user_id=uid.body)
        for entry in cert.subkeys:
            for sig in entry.signatures:
                check(sig, key=primary, subkey=entry.key)
                for emb in sig.embedded:
                    check(emb, key=primary, subkey=entry.key)
    assert checked[0x13] >= 7
    assert checked[0x18] >= 7
    assert checked[0x19] >= 1
    assert checked[0x20] >= 1  # nistp256 is revoked
    assert checked[0x28] >= 1  # one ed25519 subkey is revoked
    assert checked[0x10] >= 1  # the rsa2048 certification of the ed25519 key


def test_detached_and_text_signatures_hash_to_their_left_bits():
    ring = parse_keyring(fixture("msg.txt.asc"))
    (sig,) = ring.signatures
    assert sig.sig_type == 0
    stream = signature.hash_stream(sig, document=fixture("msg.txt"))
    assert hashlib.sha512(stream).digest()[:2] == sig.left16
    # a text signature canonicalises line endings before hashing
    assert signature.canonicalize_text(b"a\nb\r\nc\rd") == b"a\r\nb\r\nc\r\nd"


def test_unhashed_only_issuer_is_flagged_untrusted():
    body = sig_v4_body(CREATED, subpacket(16, bytes(8)))
    sig = parse_signature(body)
    assert sig.issuer_area == "unhashed"
    assert sig.issuer_keyid == bytes(8)
    hashed = parse_signature(sig_v4_body(CREATED + subpacket(33, b"\x04" + FP20)))
    assert hashed.issuer_area == "hashed"
    assert hashed.issuer_keyid == FP20[-8:]


def test_unknown_critical_subpacket_is_reported():
    sig = parse_signature(sig_v4_body(CREATED + subpacket(99, b"x", critical=True)))
    assert not sig.usable
    assert any("unknown critical subpacket 99" in p for p in sig.problems)
    quiet = parse_signature(sig_v4_body(CREATED + subpacket(99, b"x")))
    assert quiet.usable
    unhashed = parse_signature(sig_v4_body(CREATED, subpacket(99, b"x", critical=True)))
    assert unhashed.usable  # criticality is a property of the hashed area (sec. 5.2.5)


@pytest.mark.parametrize("size", [1, 191, 192, 193, 8000, 16319, 16320, 60000])
def test_subpacket_length_forms(size):
    sub = subpacket(26, b"u" * (size - 1))  # a policy URI of the right size
    sig = parse_signature(sig_v4_body(CREATED + sub))
    assert len(sig.value(26)) == size - 1


def test_hashed_area_overrun_is_refused():
    body = bytearray(sig_v4_body(CREATED))
    body[4:6] = (0xFFFF).to_bytes(2, "big")
    with pytest.raises(SignatureError, match="hashed"):
        parse_signature(bytes(body))
    with pytest.raises(SignatureError):
        parse_signature(sig_v4_body(CREATED + b"\x09\x02\x00"))  # subpacket longer than the area
    with pytest.raises(SignatureError):
        parse_signature(sig_v4_body(CREATED + b"\x00"))  # zero-length subpacket


def test_malformed_subpacket_bodies_are_problems_not_crashes():
    sig = parse_signature(sig_v4_body(CREATED + subpacket(9, b"\x01\x02")))
    assert not sig.usable
    assert sig.key_expires_after is None
    for kind, body in ((16, b"1234"), (33, b"\x04abc"), (5, b"1"), (29, b""), (20, b"\x00" * 4)):
        bad = parse_signature(sig_v4_body(CREATED + subpacket(kind, body)))
        assert any(p for p in bad.problems), kind


def test_missing_creation_time_is_noted():
    sig = parse_signature(sig_v4_body(b""))
    assert any("creation time" in p for p in sig.problems)


def test_last_hashed_subpacket_wins():
    sig = parse_signature(
        sig_v4_body(
            CREATED
            + subpacket(9, (100).to_bytes(4, "big"))
            + subpacket(9, (200).to_bytes(4, "big"))
        )
    )
    assert sig.key_expires_after == 200


def test_notation_expiration_reason_and_flags_decode():
    notation = (
        (0x80000000).to_bytes(4, "big")
        + (4).to_bytes(2, "big")
        + (5).to_bytes(2, "big")
        + b"a@b.c"[:4]
        + b"value"
    )
    hashed = (
        CREATED
        + subpacket(3, (3600).to_bytes(4, "big"))
        + subpacket(29, b"\x02compromised")
        + subpacket(27, b"\x03")
        + subpacket(20, notation)
        + subpacket(28, b"Signer <s@example.invalid>")
    )
    sig = parse_signature(sig_v4_body(hashed, sig_type=0x20))
    assert sig.usable, sig.problems
    assert sig.expires_after == 3600
    assert sig.value(29) == (2, "compromised")
    note = sig.value(20)
    assert isinstance(note, Notation)
    assert (note.name, note.value, note.human_readable) == ("a@b.", b"value", True)
    assert sig.value(28) == "Signer <s@example.invalid>"


def test_embedded_signature_is_decoded_and_depth_is_bounded():
    inner = sig_v4_body(CREATED, sig_type=0x19)
    outer = parse_signature(sig_v4_body(CREATED + subpacket(32, inner), sig_type=0x18))
    assert [e.sig_type for e in outer.embedded] == [0x19]
    nested = inner
    for _ in range(6):
        nested = sig_v4_body(CREATED + subpacket(32, nested))
    deep = parse_signature(nested)
    depth, level = 0, deep
    while level.embedded:
        level = level.embedded[0]
        depth += 1
    assert depth == 3  # Limits.max_embedded_depth
    assert any("embedded signature" in p for p in level.problems)
    with pytest.raises(LimitError):
        parse_signature(nested, Limits(max_embedded_depth=0), 1)


def test_huge_subpacket_counts_are_bounded():
    flood = CREATED + subpacket(23, b"\x80") * 5000
    with pytest.raises(LimitError):
        parse_signature(sig_v4_body(flood))
    assert parse_signature(sig_v4_body(flood), Limits(max_subpackets=6000)).usable


def test_v3_signature_is_read():
    body = (
        b"\x03\x05\x00"
        + (1_000_000_000).to_bytes(4, "big")
        + bytes(range(1, 9))
        + b"\x01\x02"
        + b"\xab\xcd"
        + (8).to_bytes(2, "big")
        + b"\xff"
    )
    sig = parse_signature(body)
    assert (sig.version, sig.created, sig.issuer_area) == (3, 1_000_000_000, "v3")
    assert sig.issuer_keyid == bytes(range(1, 9))
    assert sig.left16 == b"\xab\xcd"
    assert signature.hash_trailer(sig) == b"\x00" + (1_000_000_000).to_bytes(4, "big")
    assert hashlib.sha1(signature.hash_stream(sig, document=b"x")) is not None  # noqa: S324
    with pytest.raises(NotImplementedError):
        signature.hash_stream(sig.__class__(**{**_as_dict(sig), "sig_type": 0x13}), key=object())
    with pytest.raises(SignatureError):
        parse_signature(body[:10])
    with pytest.raises(SignatureError):
        parse_signature(b"\x03\x06" + body[2:])


def _as_dict(sig):
    from dataclasses import fields

    return {f.name: getattr(sig, f.name) for f in fields(sig)}


def test_v6_salt_length_must_match_the_hash():
    cert = load_key(v.A3_ARMOR)
    body = bytearray(cert.signatures[0].body)
    start = len(body) - 64 - 32 - 1
    assert body[start] == 32
    body[start] = 16
    short = parse_signature(bytes(body[: start + 1 + 16]) + bytes(body[start + 1 + 32 :]))
    assert any("salt" in p for p in short.problems)


def test_unsupported_versions_and_types():
    with pytest.raises(SignatureError, match="version"):
        parse_signature(b"\x05" + bytes(30))
    with pytest.raises(SignatureError):
        parse_signature(b"")
    sig = parse_signature(sig_v4_body(CREATED, sig_type=0x40))
    with pytest.raises(SignatureError, match="recipe"):
        signature.hash_stream(sig)
    with pytest.raises(SignatureError):
        signature.hash_stream(parse_signature(sig_v4_body(CREATED, sig_type=0x13)))
    with pytest.raises(SignatureError):
        signature.hash_stream(parse_signature(sig_v4_body(CREATED, sig_type=0x02)), document=b"x")


def test_md5_signature_is_flagged_weak():
    sig = parse_signature(sig_v4_body(CREATED, hash_algo=1))
    assert any("MD5" in p for p in sig.problems)


def test_third_party_confirmation_hashes_the_target_without_its_unhashed_area():
    target = parse_signature(sig_v4_body(CREATED, subpacket(16, bytes(8))))
    confirm = parse_signature(sig_v4_body(CREATED, sig_type=0x50))
    stream = signature.hash_stream(confirm, confirmed=target)
    cleared = target.body[: target.hashed_end] + b"\x00\x00" + target.body[target.unhashed_end :]
    assert stream.startswith(b"\x88" + len(cleared).to_bytes(4, "big") + cleared)
    with pytest.raises(SignatureError):
        signature.hash_stream(confirm)


def test_sign_and_verify_stay_loud():
    with pytest.raises(NotImplementedError):
        signature.verify(b"", None, None)
    with pytest.raises(NotImplementedError):
        signature.sign(b"", None, None)

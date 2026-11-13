"""Key packets, fingerprints and key ids (RFC 9580 sec. 5.5, 5.5.4)."""

from __future__ import annotations

import hashlib

import pytest

from pgpenv import fingerprint, key, load_key
from pgpenv.errors import KeyPacketError, PgpError
from pgpenv.key import key_id, load_keys, parse_public_key
from pgpenv.packet import parse_packets

from . import vectors as v
from .helpers import ed25519_v4_body, fixture, mpi, pkt, rsa_key_body, v4_fingerprint

N_2048 = (1 << 2047) | 0x1234567890ABCDEF1234567890ABCDEF | 1


def test_v6_fingerprint_matches_rfc9580_appendix_a3():
    cert = load_key(v.A3_ARMOR)
    assert cert.primary.fingerprint_hex == v.A3_PRIMARY_FINGERPRINT
    assert cert.subkeys[0].key.fingerprint_hex == v.A3_SUBKEY_FINGERPRINT
    assert fingerprint(cert) == bytes.fromhex(v.A3_PRIMARY_FINGERPRINT)
    assert cert.primary.version == 6
    assert cert.primary.algorithm_name == "Ed25519"
    assert cert.subkeys[0].key.algorithm_name == "X25519"
    assert cert.primary.created == 1669824483  # 2022-11-30T16:08:03Z as printed in A.3.1
    assert len(cert.primary.fields["public"]) == 32
    assert cert.problems == []


def test_v4_fingerprint_matches_rfc9580_appendix_a1():
    (packet,) = parse_packets(v.A1_PACKET)
    pub = parse_public_key(packet.body)
    assert pub.fingerprint_hex == v.A1_FINGERPRINT
    assert pub.curve == "Ed25519Legacy"
    assert pub.deprecated
    assert pub.created == 1408458507  # 2014-08-19 14:28:27 UTC
    assert pub.fields["point"][0] == 0x40  # prefixed native point (sec. 5.5.5.5)
    assert load_key(v.A1_ARMOR).primary.fingerprint_hex == v.A1_FINGERPRINT


def test_key_id_is_the_first_64_bits_for_v6_and_the_last_for_v4():
    v6 = load_key(v.A3_ARMOR).primary
    assert v6.keyid == v6.fingerprint[:8]
    v4 = load_key(v.A1_ARMOR).primary
    assert v4.keyid == v4.fingerprint[-8:]
    assert key_id(v4) == v4.keyid


def test_subkey_hashes_with_the_same_prefix_as_a_primary():
    body = ed25519_v4_body()
    assert parse_public_key(body, subkey=True).fingerprint_hex == v4_fingerprint(body)
    assert parse_public_key(body).fingerprint_hex == v4_fingerprint(body)


def test_v4_rsa_fingerprint_is_over_the_packet_bytes():
    body = rsa_key_body(4, N_2048)
    pub = parse_public_key(body)
    assert pub.fingerprint_hex == v4_fingerprint(body)
    assert pub.bits == 2048
    assert pub.fields["e"] == 65537
    assert pub.deprecated  # RSA is deprecated by RFC 9580 sec. 9.1


def test_v3_key_is_read_flagged_and_fingerprinted_with_md5():
    body = rsa_key_body(3, N_2048)
    pub = parse_public_key(body)
    n_octets = N_2048.to_bytes(256, "big")
    e_octets = (65537).to_bytes(3, "big")
    assert pub.fingerprint == hashlib.md5(n_octets + e_octets, usedforsecurity=False).digest()
    assert len(pub.fingerprint) == 16
    assert pub.keyid == n_octets[-8:]
    assert any("MD5" in p for p in pub.problems)
    assert pub.valid_days_v3 == 0


def test_v6_rsa_round_trips_with_a_sha256_fingerprint():
    body = rsa_key_body(6, N_2048)
    pub = parse_public_key(body)
    expected = hashlib.sha256(b"\x9b" + len(body).to_bytes(4, "big") + body).hexdigest().upper()
    assert pub.fingerprint_hex == expected


def test_unsupported_version_is_refused():
    for version in (0, 1, 5, 7, 255):
        with pytest.raises(KeyPacketError, match="version"):
            parse_public_key(bytes((version,)) + bytes(40))


@pytest.mark.parametrize("cut", range(1, 10))
def test_truncated_material_is_refused(cut):
    body = rsa_key_body(4, 0xC0FFEE)
    with pytest.raises(KeyPacketError):
        parse_public_key(body[:-cut])


def test_trailing_octets_after_public_material_are_refused_for_public_packets_only():
    body = ed25519_v4_body() + b"\x00"
    with pytest.raises(KeyPacketError, match="trailing"):
        parse_public_key(body)
    sec = parse_public_key(body, secret=True)
    assert sec.secret
    assert sec.body == ed25519_v4_body()  # the fingerprint never covers secret material
    assert sec.fingerprint_hex == v4_fingerprint(ed25519_v4_body())


def test_native_algorithm_sizes_are_exact():
    for algo, size in ((25, 32), (26, 56), (27, 32), (28, 57)):
        body = b"\x04\x00\x00\x00\x01" + bytes((algo,)) + bytes(size)
        assert len(parse_public_key(body).fields["public"]) == size
        with pytest.raises(KeyPacketError):
            parse_public_key(body[:-1])


def test_reserved_curve_oid_lengths_are_refused():
    for size in (0, 255):
        with pytest.raises(KeyPacketError, match="reserved"):
            parse_public_key(b"\x04\x00\x00\x00\x01\x13" + bytes((size,)) + bytes(40))


def test_v6_refuses_legacy_curves_and_unnormalised_mpis():
    oid = bytes.fromhex("2B06010401DA470F01")
    material = bytes((len(oid),)) + oid + mpi(0x40 << 256 | 1)
    body = b"\x06\x00\x00\x00\x01\x16" + len(material).to_bytes(4, "big") + material
    with pytest.raises(KeyPacketError, match="legacy"):
        parse_public_key(body)
    bad = b"\x07\xf9" + mpi(N_2048)[2:]  # claims 2041 bits for a 2048-bit value
    material = bad + mpi(65537)
    body = b"\x06\x00\x00\x00\x01\x01" + len(material).to_bytes(4, "big") + material
    with pytest.raises(KeyPacketError, match="declares"):
        parse_public_key(body)
    # the same sloppy MPI in a v4 key is tolerated and noted (sec. 3.2 makes the check v6-only)
    v4 = b"\x04\x00\x00\x00\x01\x01" + bad + mpi(65537)
    pub = parse_public_key(v4)
    assert any("declares" in p for p in pub.problems)


def test_v6_material_count_must_match():
    material = bytes(32)
    body = b"\x06\x00\x00\x00\x01\x1b" + (33).to_bytes(4, "big") + material + b"\x00"
    with pytest.raises(KeyPacketError, match="count"):
        parse_public_key(body)


def test_unknown_algorithm_is_kept_raw_and_still_fingerprinted():
    body = b"\x06\x00\x00\x00\x01\x63" + (5).to_bytes(4, "big") + b"abcde"
    pub = parse_public_key(body)
    assert pub.algorithm_name == "unknown(99)"
    assert pub.problems
    assert pub.fingerprint_hex
    with pytest.raises(KeyPacketError):
        parse_public_key(b"\x04\x00\x00\x00\x01\x63abc", secret=True)


def test_load_key_requires_exactly_one_certificate():
    with pytest.raises(PgpError, match="found 4"):
        load_key(fixture("ring.pgp"))
    assert len(load_keys(fixture("ring.pgp"))) == 4
    assert len(load_keys(fixture("ring.asc"))) == 4
    with pytest.raises(PgpError):
        load_key(b"")
    with pytest.raises(PgpError):
        load_key("not a key")


def test_fixture_keys_cover_the_algorithm_set():
    seen = {}
    for name in (
        "rsa2048",
        "rsa4096",
        "ed25519",
        "nistp256",
        "nistp384",
        "nistp521",
        "brainpool",
        "dsaelg",
    ):
        cert = load_key(fixture(name + ".pgp"))
        for k in (cert.primary, *(s.key for s in cert.subkeys)):
            seen[(k.algorithm_name, k.curve, k.bits)] = k
    assert ("RSA", None, 2048) in seen
    assert ("RSA", None, 4096) in seen
    assert ("RSA", None, 3072) in seen
    assert ("ECDSA", "NIST P-521", 521) in seen
    assert ("ECDH", "brainpoolP256r1", 256) in seen
    assert ("DSA", None, 2048) in seen
    assert ("Elgamal", None, 2048) in seen
    assert ("ECDH", "Curve25519Legacy", 255) in seen
    assert ("EdDSALegacy", "Ed25519Legacy", 255) in seen


def test_armored_and_binary_fixtures_agree():
    for name in ("rsa2048", "ed25519", "nistp521", "dsaelg"):
        assert load_key(fixture(name + ".asc")).primary == load_key(fixture(name + ".pgp")).primary


def test_secret_packets_are_recognised_without_decoding_secret_material():
    pub_body = ed25519_v4_body()
    secret_material = b"\x00" + bytes(32) + b"\x00\x20"
    ring = pkt(5, pub_body + secret_material)
    (cert,) = load_keys(ring)
    assert cert.primary.secret
    assert cert.primary.fingerprint_hex == v4_fingerprint(pub_body)
    assert secret_material not in cert.primary.body


def test_module_exports():
    assert key.fingerprint is fingerprint

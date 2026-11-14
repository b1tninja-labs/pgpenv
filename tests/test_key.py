"""Key packets, fingerprints and key ids (RFC 9580 sec. 5.5, 5.5.4)."""

from __future__ import annotations

import hashlib
import pathlib

import pytest

from pgpenv import armor, fingerprint, key, load_key, registry, signature
from pgpenv.errors import KeyPacketError, PgpError
from pgpenv.key import key_id, load_keys, parse_public_key
from pgpenv.packet import iter_packets, parse_packets
from pgpenv.verification import verify_document

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


# ---- RFC 9980: post-quantum algorithm ids (algo.rfc9980) ---------------------------------------


RFC9980_DIR = pathlib.Path(__file__).resolve().parent / "data" / "rfc9980"
# appendix, primary algorithm, subkey algorithm, detached signature hash id, key version
RFC9980_VECTORS = [
    ("a3", 30, 35, 8),  # ML-DSA-65+Ed25519 with ML-KEM-768+X25519
    ("a4", 31, 36, 14),
    ("a5", 32, 35, 8),
    ("a6", 33, 35, 8),
    ("a7", 34, 36, 10),
]
NAMES = {
    30: "ML-DSA-65+Ed25519",
    31: "ML-DSA-87+Ed448",
    32: "SLH-DSA-SHAKE-128s",
    33: "SLH-DSA-SHAKE-128f",
    34: "SLH-DSA-SHAKE-256s",
    35: "ML-KEM-768+X25519",
    36: "ML-KEM-1024+X448",
}


def _vector_signature(name: str):
    data = armor.decode((RFC9980_DIR / f"{name}-detached.asc").read_bytes())
    return next(signature.parse_signature(p.body) for p in iter_packets(data) if p.tag == 2)


def test_post_quantum_algorithm_ids_are_named():
    """RFC 9980 sec. 2.1 and 11: the ids, and the real appendix A keys and signatures that carry them."""
    assert {i: registry.PK_ALGORITHMS[i].name for i in NAMES} == NAMES
    for algo in (30, 31, 32, 33, 34):
        assert registry.PK_ALGORITHMS[algo].signs
    for algo in (35, 36):
        assert registry.PK_ALGORITHMS[algo].encrypts
    for appendix, primary, subkey, hash_id in RFC9980_VECTORS:
        cert = load_key((RFC9980_DIR / f"{appendix}-public.asc").read_bytes())
        assert cert.primary.algorithm == primary
        assert cert.primary.algorithm_name == NAMES[primary]
        assert len(cert.primary.fields["public"]) == sum(registry.PQ_PUBLIC_KEY_SIZES[primary])
        assert cert.primary.problems == ()
        assert cert.problems == []
        (sub,) = cert.subkeys
        assert sub.key.algorithm == subkey
        assert len(sub.key.fields["public"]) == sum(registry.PQ_PUBLIC_KEY_SIZES[subkey])
        sig = _vector_signature(appendix)
        assert (sig.version, sig.pub_algo, sig.hash_algo) == (6, primary, hash_id)
        assert len(sig.material) == sum(registry.PQ_SIGNATURE_SIZES[primary])
        assert sig.usable
        assert sig.issuer_fingerprint[1] == cert.primary.fingerprint  # the RFC's own fingerprint


def test_a_version_4_ml_kem_768_subkey_is_the_one_allowed_below_version_6():
    """RFC 9980 sec. 3.5, with the version 4 vector of appendix A.2."""
    cert = load_key((RFC9980_DIR / "a2-public.asc").read_bytes())
    assert (cert.primary.version, cert.primary.algorithm) == (4, 27)
    (sub,) = cert.subkeys
    assert (sub.key.version, sub.key.algorithm, sub.key.problems) == (4, 35, ())
    body = sub.key.body
    created = body[1:5]
    material = body[6:]
    # a version 4 primary key may not carry algorithm 35: only an encryption-capable subkey may
    primary = parse_public_key(bytes([4]) + created + bytes([35]) + material)
    assert any("RFC 9980 sec. 3.5" in p for p in primary.problems)
    as_subkey = parse_public_key(bytes([4]) + created + bytes([35]) + material, subkey=True)
    assert as_subkey.problems == ()
    # algorithm 30 in a version 4 subkey is refused too
    ml_dsa = load_key((RFC9980_DIR / "a3-public.asc").read_bytes()).primary
    v4 = parse_public_key(bytes([4]) + created + bytes([30]) + ml_dsa.body[10:], subkey=True)
    assert any("version 6 keys" in p for p in v4.problems)
    with pytest.raises(KeyPacketError):
        parse_public_key(bytes([4]) + created + bytes([35]) + material[:-1])


def test_a_post_quantum_signature_needs_version_6_a_256_bit_hash_and_a_sound_binding():
    """RFC 9980 sec. 5.3.1, 6.2.1, 7.2, 9.4 on the appendix A.3 signature, altered one octet at a time."""
    sig = _vector_signature("a3")
    assert sig.usable
    body = sig.body
    # hash id 8 (SHA2-256) becomes 2 (SHA-1): digest too small, and the salt size no longer fits
    sha1 = signature.parse_signature(body[:3] + bytes([2]) + body[4:])
    assert any("at least 256 bits" in p for p in sha1.problems)
    assert not sha1.usable
    # type 0x00 becomes 0x18 and the hash MD5: a binding with a weak hash is invalid (sec. 7.2)
    binding = signature.parse_signature(bytes([6, 0x18, 30, 1]) + body[4:])
    assert any("sec. 7.2" in p for p in binding.problems)
    assert signature._pq_signature_problems(4, 0x00, 30, 8, 3373) == [
        "ML-DSA-65+Ed25519 is used only with version 6 signatures (RFC 9980 sec. 5.3.1, 6.2.1)"
    ]
    assert signature._pq_signature_problems(6, 0x00, 30, 8, 3372)  # one octet short


def test_post_quantum_signatures_are_checked_for_structure_but_not_verified():
    """The left 16 bits of the appendix A hash stream are real evidence the recipe is right; the
    mathematics is unsupported, loudly, and a binding with SHA-1 is malformed whatever the key."""
    for appendix, _, _, _ in RFC9980_VECTORS:
        cert = load_key((RFC9980_DIR / f"{appendix}-public.asc").read_bytes())
        result = verify_document(b"Testing\n", _vector_signature(appendix), cert)
        assert result.status == "unsupported"
        assert result.checked == ("hash", "left16")
        assert result.issuer == cert.primary.fingerprint
        assert "RFC 9980" in (result.reason or "")
        assert verify_document(b"Testing!\n", _vector_signature(appendix), cert).status == "invalid"

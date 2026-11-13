"""Signature verification: RFC 9580 appendix A, the statuses, and the failure modes.

Every ``valid`` here rests on a signature somebody else made (the RFC's, or GnuPG's in
``tests/data/gnupg``), except where a test says it builds one: those use a throwaway key from
``cryptography`` and an assembly of the signed octets that does not call pgpenv's own recipe.
The GnuPG cross-check in WSL is ``tests/test_verification_gnupg.py``.
"""

from __future__ import annotations

import dataclasses
import hashlib
import pathlib
import random
import struct
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import pgpenv
from pgpenv import armor, certificate, cleartext, crypto, key, signature
from pgpenv.errors import (
    MalformedKeyMaterialError,
    PolicyRefusalError,
    SignatureError,
    UnsupportedAlgorithmError,
)
from pgpenv.packet import iter_packets
from pgpenv.verification import (
    check_self_signatures,
    verify_back_signatures,
    verify_binding,
    verify_certification,
    verify_cleartext,
    verify_direct_key,
    verify_document,
    verify_signature,
)

from . import vectors as v
from .helpers import fixture, pkt

SIGNATURE_BEGIN = "-----BEGIN PGP SIGNATURE-----"


def signatures_of(raw: bytes) -> list[signature.Signature]:
    data = armor.decode(raw) if raw.lstrip()[:1] == b"-" else raw
    return [signature.parse_signature(p.body) for p in iter_packets(data) if p.tag == 2]


def a2() -> signature.Signature:
    (sig,) = signatures_of(v.A2_PACKET)
    return sig


def a6_signature() -> signature.Signature:
    """The signature packet of the appendix A.6 cleartext message, armored on its own."""
    armored = SIGNATURE_BEGIN + v.A6_MESSAGE.partition(SIGNATURE_BEGIN)[2]
    (sig,) = signatures_of(armored.encode("ascii"))
    return sig


# ---- RFC 9580 appendix A -------------------------------------------------------------------------


def test_a2_v4_ed25519legacy_signature_verifies_under_the_a1_key() -> None:
    cert = key.load_key(v.A1_ARMOR)
    result = verify_document(b"OpenPGP", a2(), cert)
    assert result.status == "valid"
    assert result.checked == ("hash", "left16", "signature")
    assert result.issuer == bytes.fromhex(v.A1_FINGERPRINT)
    assert result.issuer_hint == "match"
    assert result.created == 1442406293
    assert any("EdDSALegacy" in w for w in result.warnings)
    assert pgpenv.verify(b"OpenPGP", a2(), cert).valid  # the package-level entry point


def test_a2_other_document_and_flipped_signature_bits_are_invalid() -> None:
    cert = key.load_key(v.A1_ARMOR)
    wrong_document = verify_document(b"OpenPGp", a2(), cert)
    assert (wrong_document.status, wrong_document.checked) == ("invalid", ("hash",))
    assert "left 16" in (wrong_document.reason or "")
    sig = a2()
    forged = dataclasses.replace(sig, material=sig.material[:-1] + bytes([sig.material[-1] ^ 1]))
    result = verify_document(
        b"OpenPGP", forged, cert
    )  # left 16 bits still match: the maths decides
    assert (result.status, result.checked) == ("invalid", ("hash", "left16"))


def test_a3_direct_key_and_subkey_binding_verify_and_the_certificate_walk_agrees() -> None:
    cert = key.load_key(v.A3_ARMOR)
    direct = cert.signatures[0]
    assert verify_direct_key(direct, cert, cert).valid
    (entry,) = cert.subkeys
    (binding,) = entry.signatures
    result = verify_binding(binding, cert, entry.key)
    assert result.valid
    assert result.sig_version == 6
    assert result.warnings == ()
    walked = check_self_signatures(cert)
    assert [(r.target, r.verification.status) for r in walked if r.verification] == [
        ("direct", "valid"),
        ("subkey", "valid"),
    ]


def test_a3_binding_checked_over_the_wrong_keys_is_invalid_not_valid() -> None:
    cert = key.load_key(v.A3_ARMOR)
    (entry,) = cert.subkeys
    (binding,) = entry.signatures
    # hashing the subkey as the key and the primary as the subkey changes the signed octets
    swapped = verify_signature(binding, cert, key=entry.key, subkey=cert.primary)
    assert swapped.status == "invalid"


def test_a6_cleartext_message_verifies_with_the_a3_certificate() -> None:
    cert = key.load_key(v.A3_ARMOR)
    (result,) = verify_cleartext(v.A6_MESSAGE, cert)
    assert result.valid
    assert (result.sig_version, result.sig_type, result.pub_algo, result.hash_algo) == (
        6,
        1,
        27,
        10,
    )
    assert result.created == 1670947683
    parsed = cleartext.parse(v.A6_MESSAGE)
    (again,) = verify_cleartext(parsed, cert.primary)
    assert again.valid


def test_a6_edited_text_is_invalid_and_trailing_spaces_are_not_part_of_the_text() -> None:
    cert = key.load_key(v.A3_ARMOR)
    (bad,) = verify_cleartext(v.A6_MESSAGE.replace("tofu", "tofy"), cert)
    assert bad.status == "invalid"
    padded = v.A6_MESSAGE.replace(
        "- - tofu\n", "- - tofu \t\n"
    )  # sec. 7.1: removed before verifying
    (ok,) = verify_cleartext(padded, cert)
    assert ok.valid
    crlf = v.A6_MESSAGE.replace("\n", "\r\n")
    (also,) = verify_cleartext(crlf, cert)
    assert also.valid


A7_MESSAGE = """-----BEGIN PGP MESSAGE-----

xEYGAQobIHZJX1AhiJD39eLuPBgiUU9wUA9VHYblySHkBONKU/usyxhsTwYJppfk
1S36bHIrDB8eJ8GKVnCPZSXsJ7rZrMkBy0p1AAAAAABXaGF0IHdlIG5lZWQgZnJv
bSB0aGUgZ3JvY2VyeSBzdG9yZToKCi0gdG9mdQotIHZlZ2V0YWJsZXMKLSBub29k
bGVzCsKYBgEbCgAAACkFgmOYo2MiIQbLGGxPBgmml+TVLfpscisMHx4nwYpWcI9l
JewnutmsyQAAAABpNiB2SV9QIYiQ9/Xi7jwYIlFPcFAPVR2G5ckh5ATjSlP7rCfQ
b7gKqPxbyxbhljGygHQPnqau1eBzrQD5QVplPEDnemrnfmkrpx0GmhCfokxYz9jj
FtCgazStmsuOXF9SFQE=
-----END PGP MESSAGE-----
"""


def test_a7_inline_signed_message_verifies_over_its_literal_data() -> None:
    """The one-pass construction (appendix A.7): the same text signature, the document in a literal packet."""
    cert = key.load_key(v.A3_ARMOR)
    packets = list(iter_packets(armor.decode(A7_MESSAGE)))
    assert [p.tag for p in packets] == [4, 11, 2]
    literal = packets[1].body
    name_length = literal[1]
    data = literal[2 + name_length + 4 :]
    assert data == b"What we need from the grocery store:\n\n- tofu\n- vegetables\n- noodles\n"
    sig = signature.parse_signature(packets[2].body)
    result = verify_document(data, sig, cert)  # a text signature: line endings are made CR LF
    assert result.valid
    assert result.sig_type == 0x01


# ---- GnuPG fixtures in the repository ------------------------------------------------------------


def test_a_certificate_chooses_the_signing_key_by_the_issuer_subpackets() -> None:
    cert = key.load_key(fixture("ed25519.asc"))
    (sig,) = signatures_of(fixture("msg.txt.sig"))
    result = verify_document(fixture("msg.txt"), sig, cert)
    assert result.valid
    assert result.issuer_hint == "match"
    detached_armor = signatures_of(fixture("msg.txt.asc"))
    assert verify_document(fixture("msg.txt"), detached_armor[0], cert).valid
    (clear,) = verify_cleartext(fixture("msg.txt.clearsigned.asc"), cert)
    assert clear.valid


def test_a_signature_whose_issuer_is_not_among_the_keys_is_no_key() -> None:
    ed = key.load_key(fixture("ed25519.asc"))
    rsa_cert = key.load_key(fixture("rsa2048.asc"))
    p256 = key.load_key(fixture("nistp256.asc"))
    (sig,) = signatures_of(fixture("msg.txt.sig"))
    # with two candidate keys the issuer decides, and neither is the issuer
    result = verify_signature(sig, [rsa_cert, p256], document=fixture("msg.txt"))
    assert result.status == "no-key"
    assert result.issuer is None
    assert verify_signature(sig, [rsa_cert, ed], document=fixture("msg.txt")).valid
    # one key given: the caller chose it, so it is checked and the mismatch is reported
    chosen = verify_signature(sig, rsa_cert.primary, document=fixture("msg.txt"))
    assert chosen.status == "malformed"  # an EdDSALegacy signature, an RSA key
    assert chosen.issuer_hint == "mismatch"


def test_an_encryption_only_key_cannot_sign() -> None:
    ed = key.load_key(fixture("ed25519.asc"))
    encrypt_only = [e.key for e in ed.subkeys if e.key.algorithm == 18]
    assert encrypt_only
    (sig,) = signatures_of(fixture("msg.txt.sig"))
    assert verify_signature(sig, encrypt_only, document=fixture("msg.txt")).status == "no-key"


def test_the_gnupg_ed25519_walk_covers_bindings_back_signatures_and_a_revoked_subkey() -> None:
    cert = key.load_key(fixture("ed25519.asc"))
    walked = check_self_signatures(cert)
    kinds = [
        (r.target, r.signature.sig_type, r.verification.status if r.verification else None)
        for r in walked
    ]
    assert ("back", 0x19, "valid") in kinds
    assert ("subkey", 0x28, "valid") in kinds  # a subkey revocation
    assert ("subkey", 0x18, "valid") in kinds
    assert [r for r in walked if r.verification is None]  # a certification by rsa2048, listed only
    assert all(r.verification.status == "valid" for r in walked if r.verification)
    (entry,) = [e for e in cert.subkeys if any(s.embedded for s in e.signatures)]
    (binding,) = [s for s in entry.signatures if s.sig_type == 0x18]
    (back,) = verify_back_signatures(binding, cert, entry.key)
    assert back.valid
    assert back.issuer == entry.key.fingerprint  # made by the subkey, not the primary


def test_the_gnupg_nistp256_revocation_signature_is_a_valid_key_revocation() -> None:
    cert = key.load_key(fixture("nistp256.asc"))
    revocation = next(s for s in cert.signatures if s.sig_type == 0x20)
    assert verify_direct_key(revocation, cert, cert).valid
    # verification says who made it, not that it is in force
    other = key.load_key(fixture("nistp384.asc"))
    assert verify_direct_key(revocation, other, cert).status != "valid"


def test_a_third_party_certification_is_checked_against_its_issuer_key() -> None:
    ed = key.load_key(fixture("ed25519.asc"))
    rsa_cert = key.load_key(fixture("rsa2048.asc"))
    third = [
        (entry, s)
        for entry in ed.user_ids
        for s in entry.signatures
        if s.sig_type == 0x10
        and s.issuer_fingerprint
        and s.issuer_fingerprint[1] == rsa_cert.primary.fingerprint
    ]
    assert third
    entry, sig = third[0]
    result = verify_certification(sig, rsa_cert, ed, user_id=entry.body)
    assert result.valid
    assert result.issuer == rsa_cert.primary.fingerprint
    assert verify_certification(sig, rsa_cert, ed, user_id=entry.body + b"!").status == "invalid"


# ---- statuses and refusals -----------------------------------------------------------------------


def test_policy_decides_refused_unsupported_and_legacy() -> None:
    dsa = key.load_key(fixture("dsaelg.asc"))
    brainpool = key.load_key(fixture("brainpool.asc"))
    dsa_uid, bp_uid = dsa.user_ids[0], brainpool.user_ids[0]
    dsa_sig = next(s for s in dsa_uid.signatures if s.sig_type == 0x13)
    bp_sig = next(s for s in bp_uid.signatures if s.sig_type == 0x13)
    refused = verify_certification(dsa_sig, dsa, dsa, user_id=dsa_uid.body)
    assert refused.status == "refused"
    assert "dsa" in (refused.reason or "").lower()
    assert verify_certification(dsa_sig, dsa, dsa, user_id=dsa_uid.body, policy="legacy").valid
    # GnuPG 2.4.9 made this brainpoolP256r1 certification; sigwire's openpgp policy accepts the curve
    assert verify_certification(bp_sig, brainpool, brainpool, user_id=bp_uid.body).valid
    # a curve OID that is not in RFC 9580 Table 19 is unsupported, whatever sigwire could compute
    odd = dataclasses.replace(brainpool.primary, curve_oid=bytes.fromhex("2B2403030208010108"))
    odd_cert = dataclasses.replace(brainpool, primary=odd)
    unsupported = verify_certification(bp_sig, odd_cert, odd_cert, user_id=bp_uid.body)
    assert unsupported.status == "unsupported"
    assert "unknown curve" in (unsupported.reason or "")


def test_a_version_6_key_and_a_version_4_signature_do_not_pair_and_the_reverse() -> None:
    a1 = key.load_key(v.A1_ARMOR)
    a3 = key.load_key(v.A3_ARMOR)
    result = verify_document(b"OpenPGP", a2(), a3)
    assert result.status == "malformed"
    assert "Table 27" in (result.reason or "")
    reverse = verify_signature(a6_signature(), a1, document=v.A6_TEXT, text_is_canonical=True)
    assert reverse.status == "malformed"


def test_a_signature_with_problems_is_malformed_never_valid() -> None:
    cert = key.load_key(v.A1_ARMOR)
    sig = dataclasses.replace(a2(), problems=("an unknown critical subpacket",))
    result = verify_document(b"OpenPGP", sig, cert)
    assert result.status == "malformed"
    assert "5.2.5" in (result.reason or "")


def test_a_digest_shorter_than_the_algorithm_needs_is_malformed() -> None:
    """RFC 9580 sec. 5.2.3.4: an Ed25519 signature MUST use a hash of at least 256 bits."""
    cert = key.load_key(v.A3_ARMOR)
    sig = a6_signature()
    assert sig.hash_algo == 10
    # the same signature labelled SHA-224 (hash 11, 16-octet salt) with matching left 16 bits
    relabelled = dataclasses.replace(sig, hash_algo=11, salt=(sig.salt or b"")[:16])
    stream = signature.hash_stream(relabelled, document=v.A6_TEXT, text_is_canonical=True)
    short = dataclasses.replace(relabelled, left16=hashlib.sha224(stream).digest()[:2])
    result = verify_signature(short, cert, document=v.A6_TEXT, text_is_canonical=True)
    assert result.status == "malformed"
    assert "256" in (result.reason or "")


def test_unknown_hash_is_unsupported_and_a_standalone_signature_takes_no_document() -> None:
    cert = key.load_key(v.A1_ARMOR)
    unknown = dataclasses.replace(a2(), hash_algo=99)
    assert verify_document(b"OpenPGP", unknown, cert).status == "unsupported"
    standalone = dataclasses.replace(a2(), sig_type=0x02)
    with pytest.raises(SignatureError):
        verify_document(b"x", standalone, cert)


def test_misuse_raises_instead_of_answering() -> None:
    cert = key.load_key(v.A3_ARMOR)
    (binding,) = cert.subkeys[0].signatures
    with pytest.raises(SignatureError):
        verify_document(b"", binding, cert)  # a key signature is not a document signature
    with pytest.raises(SignatureError):
        verify_signature(binding, cert)  # a subkey binding needs the keys it covers
    with pytest.raises(SignatureError):
        verify_binding(cert.signatures[0], cert, cert.subkeys[0].key)
    with pytest.raises(SignatureError):
        verify_certification(cert.signatures[0], cert, cert, user_id=b"x")


def test_a_mutated_signature_never_raises_and_never_validates() -> None:
    """Hostile input is ordinary input: every damaged copy of a real signature gets a status."""
    cert = key.load_key(v.A1_ARMOR)
    original = a2()
    rng = random.Random(9580)
    seen = set()
    for _ in range(200):
        material = bytearray(original.material)
        for _ in range(rng.randint(1, 3)):
            material[rng.randrange(len(material))] ^= 1 << rng.randrange(8)
        cut = rng.choice([len(material), len(material), rng.randrange(len(material) + 1)])
        mutated = dataclasses.replace(original, material=bytes(material[:cut]))
        result = verify_document(b"OpenPGP", mutated, cert)
        assert result.status != "valid"
        seen.add(result.status)
    assert seen <= {"invalid", "malformed"}


# ---- version 3 signatures over keys --------------------------------------------------------------


def _mpi(value: int) -> bytes:
    size = (value.bit_length() + 7) // 8
    return struct.pack(">H", value.bit_length()) + value.to_bytes(size, "big")


def _v3_certificate(sig_type: int, user_id: bytes) -> tuple[bytes, bytes]:
    """A version 3 RSA key, one User ID and a version 3 self-certification, assembled from the prose of
    RFC 9580 sec. 5.2.4 without calling pgpenv: returns the packets and the octets that were signed."""
    private = rsa.generate_private_key(65537, 2048)
    numbers = private.public_key().public_numbers()
    created = 1_700_000_000
    key_body = (
        bytes([3]) + struct.pack(">IH", created, 0) + bytes([1]) + _mpi(numbers.n) + _mpi(numbers.e)
    )
    signed = (
        b"\x99"
        + struct.pack(">H", len(key_body))
        + key_body
        + user_id  # a version 3 certification: the User ID without header, marker or length
        + bytes([sig_type])
        + struct.pack(">I", created)  # the five-octet trailer, no salt
    )
    value = private.sign(signed, padding.PKCS1v15(), crypto_hashes.SHA256())
    sig_body = (
        bytes([3, 5, sig_type])
        + struct.pack(">I", created)
        + numbers.n.to_bytes(256, "big")[-8:]
        + bytes([1, 8])
        + hashlib.sha256(signed).digest()[:2]
        + _mpi(int.from_bytes(value, "big"))
    )
    return pkt(6, key_body) + pkt(13, user_id) + pkt(2, sig_body), signed


def test_v3_signature_over_a_v3_key_hash_stream() -> None:
    """SYNTHETIC: a throwaway RSA key made the v3 key and the signature, over octets assembled in the
    test from RFC 9580 sec. 5.2.4. It pins that pgpenv's recipe is the one the text states and that
    verification follows it. GnuPG 2.4.9 skips version 3 keys on import ("skipped PGP-2 keys") and no
    other OpenPGP implementation was at hand, so no independent verifier accepted it: the row is partial.
    """
    user_id = b"v3 test <v3@example.invalid>"
    packets, signed = _v3_certificate(0x13, user_id)
    cert = key.load_key(packets)
    assert cert.primary.version == 3
    (entry,) = cert.user_ids
    (sig,) = entry.signatures
    assert sig.version == 3
    assert signature.hash_stream(sig, key=cert.primary, user_id=entry.body) == signed
    result = verify_certification(sig, cert, cert, user_id=entry.body)
    assert result.valid, result
    assert result.issuer_hint == "match"  # the v3 key id is the low 64 bits of the modulus
    assert verify_certification(sig, cert, cert, user_id=entry.body + b"x").status == "invalid"
    v4_form = b"\xb4" + struct.pack(">I", len(user_id)) + user_id
    assert v4_form not in signed  # the version 4 marker and length are not part of a v3 recipe


def test_check_self_signatures_reports_a_v3_certification() -> None:
    packets, _ = _v3_certificate(0x10, b"walk")
    cert = key.load_key(packets)
    (walked,) = check_self_signatures(cert)
    assert walked.verification is not None
    assert walked.verification.valid


# ---- RSA with SHA-3 (RFC 9580 sec. 9.5, Table 24) ---------------------------------------------


@pytest.mark.parametrize(
    ("hash_id", "hasher", "name"),
    [(12, crypto_hashes.SHA3_256, "SHA3-256"), (14, crypto_hashes.SHA3_512, "SHA3-512")],
)
def test_v4_rsa_certification_with_sha3_verifies(hash_id: int, hasher: type, name: str) -> None:
    """SYNTHETIC: a throwaway RSA key made a version 4 self-certification with a SHA-3 hash, over octets
    assembled here from sec. 5.2.4; OpenSSL did the signing, so the DigestInfo prefix of Table 24 that
    sigwire uses was accepted by an independent implementation, but no real OpenPGP signature of this kind
    is known (GnuPG 2.4.9 offers no SHA-3)."""
    private = rsa.generate_private_key(65537, 3072)
    numbers = private.public_key().public_numbers()
    created = 1_700_000_000
    key_body = (
        bytes([4]) + struct.pack(">I", created) + bytes([1]) + _mpi(numbers.n) + _mpi(numbers.e)
    )
    user_id = b"sha3 test <sha3@example.invalid>"
    hashed_area = bytes([5, 2]) + struct.pack(">I", created)
    head = bytes([4, 0x13, 1, hash_id]) + struct.pack(">H", len(hashed_area)) + hashed_area
    stream = (
        bytes([0x99])
        + struct.pack(">H", len(key_body))
        + key_body
        + bytes([0xB4])
        + struct.pack(">I", len(user_id))
        + user_id
        + head
        + bytes([4, 0xFF])
        + struct.pack(">I", len(head))
    )
    value = private.sign(stream, padding.PKCS1v15(), hasher())
    digest = hashes_digest(name, stream)
    body = head + struct.pack(">H", 0) + digest[:2] + _mpi(int.from_bytes(value, "big"))
    cert = key.load_key(pkt(6, key_body) + pkt(13, user_id) + pkt(2, body))
    (entry,) = cert.user_ids
    (sig,) = entry.signatures
    assert signature.hash_stream(sig, key=cert.primary, user_id=entry.body) == stream
    result = verify_certification(sig, cert, cert, user_id=entry.body)
    assert result.valid, result
    assert verify_certification(sig, cert, cert, user_id=entry.body + b"x").status == "invalid"


def hashes_digest(name: str, data: bytes) -> bytes:
    return hashlib.new(name.lower().replace("-", "_"), data).digest()


# ---- Ed448 (RFC 9580 sec. 5.2.3.5, 12.7) ---------------------------------------------------------

# The public key of the RFC 8032 section 7.4 "Blank" test vector, whose secret key that RFC publishes.
ED448_PUBLIC = bytes.fromhex(
    "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6c"
    "d1fa1abeafe8256180"
)
# libgcrypt 1.12.2 signed SHA-512 of the stream assembled below (sec. 12.7: the digest is the message).
ED448_SIGNATURE = bytes.fromhex(
    "2a7d8c85a4222c0b6a248551ba42176435c5485e9e48f5f1b0967056cf91221b06c6013fe0d7ae73fcedacb7f1a347df"
    "b21d1444b7327d3b009f54fd16d644123d6d5c558f19cf3287fbd40d84e9db217b99324fbcd2a53c221ac85d0aa1ea3a"
    "f8099ff4c18844b4c675bec0d33125f22a00"
)


def _ed448_certificate(signature_octets: bytes) -> tuple[bytes, bytes]:
    created = 1_700_000_000
    key_body = bytes([4]) + struct.pack(">I", created) + bytes([28]) + ED448_PUBLIC
    user_id = b"ed448 test <ed448@example.invalid>"
    hashed_area = bytes([5, 2]) + struct.pack(">I", created)
    head = bytes([4, 0x13, 28, 10]) + struct.pack(">H", len(hashed_area)) + hashed_area
    stream = (
        bytes([0x99])
        + struct.pack(">H", len(key_body))
        + key_body
        + bytes([0xB4])
        + struct.pack(">I", len(user_id))
        + user_id
        + head
        + bytes([4, 0xFF])
        + struct.pack(">I", len(head))
    )
    digest = hashlib.sha512(stream).digest()
    body = head + struct.pack(">H", 0) + digest[:2] + signature_octets
    return pkt(6, key_body) + pkt(13, user_id) + pkt(2, body), stream


def test_ed448_certification_signed_by_libgcrypt_verifies() -> None:
    """Version 4 Ed448 self-certification whose 114 signature octets libgcrypt 1.12.2 made.

    Only the packets are assembled here (the same recipe as the SHA-3 test above); the signing key is the
    RFC 8032 section 7.4 "Blank" key and the signature came from ``tools/gcrypt_ed448.c`` in the sigwire
    project, an implementation independent of the OpenSSL behind ``cryptography``. The same program
    reproduces that RFC vector's published signature byte for byte. No OpenPGP implementation available
    here makes Ed448 (RFC 9580 has no sample, GnuPG 2.4.9 stops at Ed25519), so the row stays partial: this
    is a real Ed448 signature in an OpenPGP frame that only pgpenv has read.
    """
    packets, stream = _ed448_certificate(ED448_SIGNATURE)
    cert = key.load_key(packets)
    assert cert.primary.algorithm == 28
    (entry,) = cert.user_ids
    (sig,) = entry.signatures
    assert sig.material == ED448_SIGNATURE
    assert signature.hash_stream(sig, key=cert.primary, user_id=entry.body) == stream
    result = verify_certification(sig, cert, cert, user_id=entry.body)
    assert result.valid, result
    assert result.checked == ("hash", "left16", "signature")
    assert verify_certification(sig, cert, cert, user_id=entry.body + b"x").status == "invalid"
    flipped = bytearray(ED448_SIGNATURE)
    flipped[3] ^= 1
    bad_cert = key.load_key(_ed448_certificate(bytes(flipped))[0])
    (bad_entry,) = bad_cert.user_ids
    (bad_sig,) = bad_entry.signatures
    assert (
        verify_certification(bad_sig, bad_cert, bad_cert, user_id=bad_entry.body).status
        == "invalid"
    )


def test_ed448_with_a_hash_under_512_bits_is_malformed() -> None:
    """RFC 9580 sec. 5.2.3.5: a verifier MUST reject an Ed448 signature using a smaller digest."""
    packets, _ = _ed448_certificate(ED448_SIGNATURE)
    cert = key.load_key(packets)
    (entry,) = cert.user_ids
    (sig,) = entry.signatures
    relabelled = dataclasses.replace(sig, hash_algo=8)  # SHA-256, with matching left 16 bits
    stream = signature.hash_stream(relabelled, key=cert.primary, user_id=entry.body)
    short = dataclasses.replace(relabelled, left16=hashlib.sha256(stream).digest()[:2])
    result = verify_certification(short, cert, cert, user_id=entry.body)
    assert result.status == "malformed", result
    assert "512" in (result.reason or "")


# ---- the seam -------------------------------------------------------------------------------------


def test_the_seam_translates_sigwire_refusals_into_pgpenv_errors() -> None:
    with pytest.raises(UnsupportedAlgorithmError):
        crypto.policy("not-a-profile")
    openpgp = crypto.policy("openpgp")
    with pytest.raises(MalformedKeyMaterialError):
        crypto.dsa(1, 1, 1, 1, bytes(32), 1, 1, "sha256", openpgp)  # not DSA parameters at all
    small_order_key = (1).to_bytes(
        32, "little"
    )  # the neutral element: sigwire refuses it by policy
    with pytest.raises(PolicyRefusalError):
        crypto.ed25519(small_order_key, bytes(32), bytes(64), openpgp)
    assert crypto.policy(openpgp) is openpgp  # a policy object passes through


def test_importing_verification_loads_neither_cryptography_nor_sigwire() -> None:
    code = (
        "import sys, pgpenv, pgpenv.verification, pgpenv.crypto;"
        "bad = [m for m in ('cryptography', 'sigwire') if m in sys.modules];"
        "sys.exit(1 if bad else 0)"
    )
    root = pathlib.Path(pgpenv.__file__).resolve().parents[1]
    done = subprocess.run([sys.executable, "-c", code], check=False, cwd=str(root))  # noqa: S603
    assert done.returncode == 0


def test_certificate_and_key_types_are_the_public_ones() -> None:
    assert certificate.Certificate is not None
    assert key.PublicKey is not None

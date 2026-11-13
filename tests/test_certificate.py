"""M5: what the verified self-signatures of a certificate say (``pgpenv.validity``).

Real signatures come from GnuPG 2.4.9 (``tests/data/gnupg``). The certificates that retire a User ID
and that carry a signature expiry are SYNTHETIC: GnuPG was not asked to make them, so a throwaway RSA key
signs octets assembled here from RFC 9580 sec. 5.2.4, in the manner of ``tests/test_verification.py``.
"""

from __future__ import annotations

import dataclasses
import hashlib
import struct

from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from pgpenv import key
from pgpenv.certificate import Certificate
from pgpenv.inventory import inventory
from pgpenv.signature import Signature
from pgpenv.validity import assess

from .helpers import fixture, pkt

LATE = 4_000_000_000  # well after every expiry in the fixtures
EARLY = 1_000_000_000


def load(name: str) -> Certificate:
    return key.load_key(fixture(name))


# ---- binding -------------------------------------------------------------------------------------


def test_binding_signatures_are_checked() -> None:
    cert = load("ed25519.asc")
    state = assess(cert, at=EARLY)
    assert [s.bound for s in state.subkeys] == [True, True]
    assert all(s.binding_problem is None for s in state.subkeys)
    # a subkey with no binding signature is not bound, whatever the file says about it
    bare = dataclasses.replace(
        cert,
        subkeys=[dataclasses.replace(e, signatures=[]) for e in cert.subkeys],
    )
    unbound = assess(bare, at=EARLY).subkeys
    assert [s.bound for s in unbound] == [False, False]
    assert all("no verified binding" in (s.binding_problem or "") for s in unbound)
    assert [s.status(EARLY) for s in unbound] == ["unbound", "unbound"]


def test_a_signing_subkey_needs_its_back_signature() -> None:
    """Sec. 5.2.1.8: a binding for a signing subkey MUST carry an embedded 0x19 made by that subkey."""
    cert = load("ed25519.asc")
    (position,) = [i for i, e in enumerate(cert.subkeys) if any(s.embedded for s in e.signatures)]
    entry = cert.subkeys[position]
    stripped = [
        dataclasses.replace(
            s,
            hashed=tuple(p for p in s.hashed if p.type != 32),
            unhashed=tuple(p for p in s.unhashed if p.type != 32),
        )
        if s.sig_type == 0x18
        else s
        for s in entry.signatures
    ]
    subkeys = list(cert.subkeys)
    subkeys[position] = dataclasses.replace(entry, signatures=stripped)
    state = assess(dataclasses.replace(cert, subkeys=subkeys), at=EARLY)
    assert "back signature" in (state.subkeys[position].binding_problem or "")
    assert not state.subkeys[position].bound
    # the other subkey, which does not sign, is unaffected
    assert state.subkeys[1 - position].bound


def test_signatures_that_do_not_verify_are_listed_and_decide_nothing() -> None:
    cert = load("dsaelg.asc")  # DSA is refused by the openpgp policy (RFC 9580 sec. 12.5)
    refused = assess(cert, at=EARLY)
    assert refused.ignored
    assert not any(u.certified for u in refused.user_ids)
    assert [s.bound for s in refused.subkeys] == [False]
    legacy = assess(cert, at=EARLY, policy="legacy")
    assert not legacy.ignored
    assert all(u.certified for u in legacy.user_ids)
    assert all(s.bound for s in legacy.subkeys)


# ---- expiry --------------------------------------------------------------------------------------


def test_expiry_comes_from_a_checked_self_signature() -> None:
    cert = load("rsa2048.asc")
    (record,) = inventory(fixture("rsa2048.asc"))
    state = assess(cert, at=EARLY)
    # the claimed inventory and the checked assessment agree on a certificate whose signatures verify
    assert state.primary.expires == record.expires
    assert record.expires is not None
    assert state.primary.expiry_source == "user-id"
    assert state.primary.status(EARLY) == "ok"
    assert state.primary.status(state.primary.expires or 0) == "expired"
    assert state.primary.status(LATE) == "expired"
    assert [s.expires for s in state.subkeys] == [sub["expires"] for sub in record.subkeys]
    # damage the certification the expiry would have come from: it is ignored, so no expiry is claimed
    damaged = dataclasses.replace(
        cert,
        user_ids=[
            dataclasses.replace(
                u,
                signatures=[dataclasses.replace(s, left16=b"\x00\x00") for s in u.signatures],
            )
            for u in cert.user_ids
        ],
    )
    after = assess(damaged, at=EARLY)
    assert after.primary.expires is None
    assert after.primary.expiry_source is None
    assert after.ignored
    assert not any(u.certified for u in after.user_ids)


def test_a_key_with_no_expiry_stays_ok() -> None:
    cert = load("nistp384.asc")
    state = assess(cert, at=LATE)
    assert state.primary.expires is None
    assert state.primary.status(LATE) == "ok"


# ---- revocation ----------------------------------------------------------------------------------


def test_revocation_is_checked_before_it_is_believed() -> None:
    revoked = load("nistp256.asc")
    state = assess(revoked, at=EARLY)
    (revocation,) = state.primary.revocations
    assert revocation.reason == 2  # key material compromised: hard, whatever the time
    assert revocation.hard
    assert state.primary.status(EARLY) == "revoked"
    # the same revocation attached to another key does not verify there, so it revokes nothing
    other = load("nistp384.asc")
    forged = dataclasses.replace(
        other, signatures=[*other.signatures, *revoked_signatures(revoked)]
    )
    assert assess(forged, at=EARLY).primary.status(EARLY) == "ok"
    assert assess(forged, at=EARLY).primary.revocations == ()
    # and one that does not verify under its own key is not counted either
    damaged = dataclasses.replace(
        revoked,
        signatures=[
            dataclasses.replace(s, left16=b"\x00\x00") if s.sig_type == 0x20 else s
            for s in revoked.signatures
        ],
    )
    after = assess(damaged, at=EARLY)
    assert after.primary.revocations == ()
    assert after.primary.status(EARLY) == "ok"
    assert any(r.signature.sig_type == 0x20 for r in after.ignored)


def revoked_signatures(cert: Certificate) -> list[Signature]:
    return [s for s in cert.signatures if s.sig_type == 0x20]


def test_a_superseded_subkey_is_revoked_from_its_revocation_time_not_before() -> None:
    cert = load("ed25519.asc")
    state = assess(cert, at=EARLY)
    (revoked,) = [s for s in state.subkeys if s.revocations]
    (revocation,) = revoked.revocations
    assert revocation.reason == 1  # "key is superseded": old signatures stay valid (sec. 5.2.3.31)
    assert not revocation.hard
    assert revocation.created is not None
    assert revoked.status(revocation.created - 1) == "ok"
    assert revoked.status(revocation.created) == "revoked"
    assert revoked.status(LATE) == "revoked"


# ---- User ID self-certification ------------------------------------------------------------------


def test_user_id_self_signature_is_checked() -> None:
    cert = load("ed25519.asc")
    assert [(u.certified, u.retired) for u in assess(cert, at=EARLY).user_ids] == [
        (True, False),
        (True, False),
    ]
    bare = dataclasses.replace(
        cert, user_ids=[dataclasses.replace(u, signatures=[]) for u in cert.user_ids]
    )
    assert not any(u.certified for u in assess(bare, at=EARLY).user_ids)


def _mpi(value: int) -> bytes:
    return struct.pack(">H", value.bit_length()) + value.to_bytes(
        (value.bit_length() + 7) // 8, "big"
    )


def _rsa_certificate(sigs: list[tuple[int, int, bytes]]) -> Certificate:
    """SYNTHETIC: v4 RSA key, one User ID, and one self-signature per ``(type, created, extra subpackets)``."""
    private = rsa.generate_private_key(65537, 2048)
    numbers = private.public_key().public_numbers()
    created = 1_600_000_000
    key_body = (
        bytes([4]) + struct.pack(">I", created) + bytes([1]) + _mpi(numbers.n) + _mpi(numbers.e)
    )
    user_id = b"retire <retire@example.invalid>"
    packets = pkt(6, key_body) + pkt(13, user_id)
    for sig_type, when, extra in sigs:
        hashed = bytes([5, 2]) + struct.pack(">I", when) + extra
        head = bytes([4, sig_type, 1, 8]) + struct.pack(">H", len(hashed)) + hashed
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
        value = private.sign(stream, padding.PKCS1v15(), crypto_hashes.SHA256())
        body = (
            head
            + struct.pack(">H", 0)
            + hashlib.sha256(stream).digest()[:2]
            + _mpi(int.from_bytes(value, "big"))
        )
        packets += pkt(2, body)
    return key.load_key(packets)


def test_a_certification_revocation_retires_the_user_id_unless_certified_again() -> None:
    reason = bytes([2, 29, 32])  # sec. 5.2.3.31: code 32, "User ID information is no longer valid"
    certified = _rsa_certificate([(0x13, 1_650_000_000, b"")])
    assert [(u.certified, u.retired) for u in assess(certified, at=LATE).user_ids] == [
        (True, False)
    ]
    retired = _rsa_certificate([(0x13, 1_650_000_000, b""), (0x30, 1_660_000_000, reason)])
    (state,) = assess(retired, at=LATE).user_ids
    assert (state.certified, state.retired, state.certified_at) == (True, True, 1_650_000_000)
    # certified again after the revocation: the name is back in use
    again = _rsa_certificate(
        [(0x13, 1_650_000_000, b""), (0x30, 1_660_000_000, reason), (0x13, 1_670_000_000, b"")]
    )
    assert [(u.certified, u.retired) for u in assess(again, at=LATE).user_ids] == [(True, False)]
    # a tie goes to the revocation: the RFC gives no rule, so this module does
    tied = _rsa_certificate([(0x13, 1_660_000_000, b""), (0x30, 1_660_000_000, reason)])
    assert [u.retired for u in assess(tied, at=LATE).user_ids] == [True]


def test_an_expired_self_signature_is_not_considered() -> None:
    """Sec. 5.2.3.18: a self-signature past its own expiry decides nothing (here: no expiry for the key)."""
    expiry = bytes([5, 3]) + struct.pack(
        ">I", 1000
    )  # the signature expires 1000 s after its creation
    key_expiry = bytes([5, 9]) + struct.pack(">I", 5 * 86400)
    cert = _rsa_certificate([(0x13, 1_650_000_000, expiry + key_expiry)])
    before = assess(cert, at=1_650_000_000 + 500)
    assert before.primary.expires == 1_600_000_000 + 5 * 86400
    after = assess(cert, at=1_650_000_000 + 2000)
    assert after.primary.expires is None
    assert not any(u.certified for u in after.user_ids)

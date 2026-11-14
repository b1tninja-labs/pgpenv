"""The algorithm policy of RFC 9580 sec. 9.1 and 9.5, the creation-time rule, and the refusal of trust.

``verify.time``, ``policy.algorithms`` and ``wot.refuse`` rows. The one signature that is made here
(``_sha1_certificate``) is SYNTHETIC: a throwaway RSA key and OpenSSL signed octets assembled in the
test from RFC 9580 sec. 5.2.4, because no real SHA-1 signature is stored (GnuPG's are made in WSL by
``tests/test_verification_gnupg.py``, which skips without it).
"""

from __future__ import annotations

import dataclasses
import hashlib
import importlib
import inspect
import pkgutil
import struct

import pytest
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import pgpenv
from pgpenv import errors, key, policy, registry, signature, wot
from pgpenv.verification import WeakHashTime, verify_certification, verify_document

from . import vectors as v
from .helpers import fixture, pkt
from .test_verification import a2

CREATED = 1_100_000_000  # 2004-11-09
CUTOFF = 1_300_000_000  # a cut-off the caller chose; the RFC gives none
LATER = 1_700_000_000


def _mpi(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return struct.pack(">H", value.bit_length()) + raw


def _sha1_certificate(created: int) -> tuple[key.Certificate, bytes, signature.Signature]:
    private = rsa.generate_private_key(65537, 3072)
    numbers = private.public_key().public_numbers()
    key_body = (
        bytes([4]) + struct.pack(">I", created) + bytes([1]) + _mpi(numbers.n) + _mpi(numbers.e)
    )
    user_id = b"sha1 test <sha1@example.invalid>"
    hashed_area = bytes([5, 2]) + struct.pack(">I", created)
    head = bytes([4, 0x13, 1, 2]) + struct.pack(">H", len(hashed_area)) + hashed_area
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
    value = private.sign(stream, padding.PKCS1v15(), crypto_hashes.SHA1())  # noqa: S303
    digest = hashlib.sha1(stream, usedforsecurity=False).digest()
    body = head + struct.pack(">H", 0) + digest[:2] + _mpi(int.from_bytes(value, "big"))
    cert = key.load_key(pkt(6, key_body) + pkt(13, user_id) + pkt(2, body))
    (entry,) = cert.user_ids
    return cert, entry.body, entry.signatures[0]


# ---- policy.algorithms ---------------------------------------------------------------------------


def test_default_policy_refuses_md5_and_sha1_signatures() -> None:
    """The ``openpgp`` policy refuses MD5, SHA-1 and RIPEMD-160 before hashing anything (sec. 9.5).

    A signature relabelled with each weak hash would fail its left 16 bits if it were hashed, so
    ``refused`` shows the policy decided first. MD5 is ``malformed`` earlier still, by sec. 5.2.5.
    """
    cert = key.load_key(fixture("rsa2048.asc"))
    entry = cert.user_ids[0]
    sig = next(s for s in entry.signatures if s.sig_type == 0x13)
    for hash_id, name in ((2, "SHA-1"), (3, "RIPEMD-160")):
        relabelled = dataclasses.replace(sig, hash_algo=hash_id)
        result = verify_certification(relabelled, cert, cert, user_id=entry.body)
        assert result.status == "refused", (name, result)
        assert name in (result.reason or "")
        assert "9.5" in (result.reason or "")
        assert result.checked == ()
    md5 = dataclasses.replace(sig, hash_algo=1)
    assert verify_certification(md5, cert, cert, user_id=entry.body).status in {
        "refused",
        "malformed",
    }
    # the strong hash of the same signature is still verified
    assert verify_certification(sig, cert, cert, user_id=entry.body).valid


def test_a_real_sha1_signature_is_refused_by_default_and_checked_under_legacy() -> None:
    cert, user_id, sig = _sha1_certificate(CREATED)
    assert sig.hash_algo == 2
    refused = verify_certification(sig, cert, cert, user_id=user_id)
    assert refused.status == "refused"
    legacy = verify_certification(sig, cert, cert, user_id=user_id, policy="legacy")
    assert legacy.valid, legacy
    assert any("SHA-1" in w for w in legacy.warnings)


def test_requirements_follow_sec_9_1_and_9_5_and_rfc_9980() -> None:
    assert policy.hash_requirement(8) == "MUST"  # SHA2-256
    assert policy.hash_requirement(9) == policy.hash_requirement(10) == "SHOULD"
    assert policy.hash_requirement(12) == "MAY"  # SHA3-256
    for weak in (1, 2, 3):
        assert policy.hash_requirement(weak) == "MUST NOT generate"
        assert not policy.may_generate_signature(weak, 27)
    assert policy.hash_requirement(5) is None  # reserved in Table 23
    assert policy.pk_requirement(27) == policy.pk_requirement(25) == "MUST"  # Ed25519, X25519
    assert policy.pk_requirement(28) == policy.pk_requirement(26) == "SHOULD"
    assert policy.pk_requirement(1) == "SHOULD NOT generate"  # RSA: may be interpreted
    for deprecated in (2, 3, 16, 17):
        assert policy.pk_requirement(deprecated) == "MUST NOT generate"
    assert not policy.may_generate_signature(8, 17)  # DSA
    assert policy.may_generate_signature(8, 27)
    # RFC 9980 sec. 2.1, Tables 1 and 2
    assert (policy.pk_requirement(30), policy.pk_requirement(35)) == ("MUST", "MUST")
    assert (policy.pk_requirement(31), policy.pk_requirement(36)) == ("SHOULD", "SHOULD")
    assert {policy.pk_requirement(i) for i in (32, 33, 34)} == {"MAY"}
    assert policy.pk_requirement(99) is None


def test_every_hash_the_registry_names_has_a_requirement() -> None:
    assert all(policy.hash_requirement(i) is not None for i in registry.HASHES)
    assert all(policy.pk_requirement(i) is not None for i in registry.PK_ALGORITHMS)


# ---- verify.time ---------------------------------------------------------------------------------


def test_an_old_weak_hash_signature_is_accepted_only_with_a_cutoff_and_custody() -> None:
    """RFC 9580 sec. 9.5: MUST NOT validate a recent one; SHOULD NOT an old one unless it predates
    the weakness and the data was in custody. The RFC names no date, so the caller supplies it."""
    cert, user_id, sig = _sha1_certificate(CREATED)
    assert sig.created == CREATED

    def check(weak: WeakHashTime | None) -> tuple[str, str | None]:
        r = verify_certification(
            sig, cert, cert, user_id=user_id, policy="legacy", weak_hashes=weak
        )
        return r.status, r.reason

    assert check(None)[0] == "valid"  # no rule asked for: the policy alone decides
    assert check(WeakHashTime({2: CUTOFF}, custody=True))[0] == "valid"
    status, reason = check(WeakHashTime({2: CUTOFF}))
    assert status == "refused"
    assert "custody" in (reason or "")
    status, reason = check(WeakHashTime({}, custody=True))
    assert status == "refused"
    assert "no cut-off" in (reason or "")
    status, reason = check(
        WeakHashTime({2: CREATED}, custody=True)
    )  # created at the cut-off: recent
    assert status == "refused"
    assert "recent" in (reason or "")
    assert check(WeakHashTime({2: CREATED - 1}, custody=True))[0] == "refused"


def test_a_recent_weak_hash_signature_is_refused_whatever_custody_says() -> None:
    cert, user_id, sig = _sha1_certificate(LATER)
    weak = WeakHashTime({2: CUTOFF}, custody=True)
    result = verify_certification(
        sig, cert, cert, user_id=user_id, policy="legacy", weak_hashes=weak
    )
    assert result.status == "refused"
    assert "recent" in (result.reason or "")


def test_the_creation_time_rule_leaves_strong_hashes_alone() -> None:
    cert = key.load_key(v.A1_ARMOR)
    weak = WeakHashTime({}, custody=False)
    assert verify_document(b"OpenPGP", a2(), cert, weak_hashes=weak).valid


# ---- wot.refuse ----------------------------------------------------------------------------------


def _trust_signature(level: int, amount: int, regex: bytes | None = None) -> signature.Signature:
    hashed = bytes([5, 2]) + struct.pack(">I", CREATED)
    hashed += bytes([3, 5, level, amount])
    if regex is not None:
        hashed += bytes([len(regex) + 1, 6]) + regex
    head = bytes([4, 0x10, 1, 8]) + struct.pack(">H", len(hashed)) + hashed
    return signature.parse_signature(head + struct.pack(">H", 0) + b"\x00\x00" + _mpi(1))


def test_a_trust_signature_is_read_as_a_claim_and_never_evaluated() -> None:
    partial = wot.trust_claim(_trust_signature(1, 60, b"<[^>]+[@.]example\\.org>$\x00"))
    assert partial is not None
    assert (partial.level, partial.amount, partial.strength) == (1, 60, "partial")
    assert partial.scope == "<[^>]+[@.]example\\.org>$"  # carried, not interpreted
    assert partial.label == "claimed"
    complete = wot.trust_claim(_trust_signature(2, 120))
    assert complete is not None
    assert (complete.strength, complete.scope) == ("complete", None)
    assert wot.trust_claim(_trust_signature(1, 119)).strength == "partial"  # type: ignore[union-attr]
    plain = key.load_key(fixture("rsa2048.asc")).user_ids[0].signatures[0]
    assert wot.trust_claim(plain) is None


def test_no_function_reports_trust() -> None:
    """The three trust entry points refuse, and nothing else public answers with trust."""
    for refuse in (wot.trust_of, wot.is_trusted, wot.valid_path):
        with pytest.raises(errors.TrustRefusedError, match="never whether to trust"):
            refuse()
    assert issubclass(errors.TrustRefusedError, errors.PgpError)
    allowed = {
        ("wot", "trust_claim"),
        ("wot", "trust_of"),
        ("wot", "is_trusted"),
        ("wot", "valid_path"),
        ("wot", "TrustClaim"),
        ("errors", "TrustRefusedError"),
    }
    offenders: list[str] = []
    for info in pkgutil.iter_modules(pgpenv.__path__):
        if info.name.startswith("__"):
            continue
        module = importlib.import_module(f"pgpenv.{info.name}")
        for name, member in vars(module).items():
            if name.startswith("_") or getattr(member, "__module__", None) != module.__name__:
                continue
            if "trust" in name.lower() and (info.name, name) not in allowed:
                offenders.append(f"{info.name}.{name}")
            if dataclasses.is_dataclass(member):
                for f in dataclasses.fields(member):
                    if "trust" in f.name.lower() and (info.name, name) not in allowed:
                        offenders.append(f"{info.name}.{name}.{f.name}")
            if inspect.isfunction(member):
                returns = str(inspect.signature(member).return_annotation).lower()
                if "trust" in returns and (info.name, name) not in allowed:
                    offenders.append(f"{info.name}.{name} -> {returns}")
    assert not offenders, offenders

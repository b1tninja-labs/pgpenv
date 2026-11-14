"""the algorithm requirements of RFC 9580 sec. 9.1 and 9.5 and RFC 9980 sec. 2.1, as data and rules.

Two questions are kept apart because the RFC keeps them apart. *Requirement* is what an
implementation must offer: SHA2-256 and Ed25519 are MUST, SHA2-384 and SHA2-512 and Ed448 are
SHOULD, the rest MAY. *Use* is what it may do with an algorithm: MD5, SHA-1 and RIPEMD-160 must not
make a signature and must not validate a recent one (sec. 9.5), RSA is deprecated and DSA must not
be generated (sec. 9.1). :func:`hash_requirement` and :func:`pk_requirement` answer the first,
:func:`signature_refusal` the second, for verification. The ``openpgp`` verification policy
applies :func:`signature_refusal` before any hashing, so a weak-hash signature is ``refused`` and
not left for the primitive to notice; ``legacy`` does not (see :mod:`pgpenv.verification` for the
creation-time rule that can still hold it back).

The tables below are the RFC's, transcribed with their sections; nothing here is a judgement about
how weak an algorithm is beyond what the RFC says.
"""

from __future__ import annotations

from typing import Literal

__all__ = [
    "WEAK_HASHES",
    "Requirement",
    "hash_requirement",
    "may_generate_signature",
    "pk_requirement",
    "signature_refusal",
]

Requirement = Literal["MUST", "SHOULD", "MAY", "SHOULD NOT generate", "MUST NOT generate"]

# RFC 9580 sec. 9.5 (final paragraph): MD5, SHA-1 and RIPEMD-160.
WEAK_HASHES: dict[int, str] = {1: "MD5", 2: "SHA-1", 3: "RIPEMD-160"}

# RFC 9580 sec. 9.5: "MUST implement SHA2-256", "SHOULD implement SHA2-384 and SHA2-512".
_HASH_REQUIREMENT: dict[int, Requirement] = {8: "MUST", 9: "SHOULD", 10: "SHOULD"}

# RFC 9580 sec. 9.1 after Table 18, and RFC 9980 sec. 2.1 Tables 1 and 2.
_PK_REQUIREMENT: dict[int, Requirement] = {
    27: "MUST",  # Ed25519, for signatures
    25: "MUST",  # X25519, for encryption
    28: "SHOULD",
    26: "SHOULD",
    1: "SHOULD NOT generate",  # deprecated, "may be interpreted"
    2: "MUST NOT generate",
    3: "MUST NOT generate",
    16: "MUST NOT generate",
    17: "MUST NOT generate",
    30: "MUST",
    35: "MUST",
    31: "SHOULD",
    36: "SHOULD",
    32: "MAY",
    33: "MAY",
    34: "MAY",
}


def hash_requirement(algorithm: int) -> Requirement | None:
    """What sec. 9.5 asks of an implementation for this hash id, or None for an id it does not name.

    The weak hashes are ``MUST NOT generate`` (signatures, ECDH and S2K KDF uses); every other
    named hash is MAY.
    """
    if algorithm in WEAK_HASHES:
        return "MUST NOT generate"
    if algorithm in _HASH_REQUIREMENT:
        return _HASH_REQUIREMENT[algorithm]
    return "MAY" if algorithm in (11, 12, 14) else None


def pk_requirement(algorithm: int) -> Requirement | None:
    """What sec. 9.1 (and RFC 9980 sec. 2.1) asks for this public key algorithm id.

    Algorithms the RFCs mark neither required nor deprecated (ECDH, ECDSA) are MAY; an id in no
    table is None.
    """
    if algorithm in _PK_REQUIREMENT:
        return _PK_REQUIREMENT[algorithm]
    return "MAY" if algorithm in (18, 19, 22) else None


def may_generate_signature(hash_algorithm: int, pk_algorithm: int) -> bool:
    """False if sec. 9.5 or sec. 9.1 forbids *making* a signature with this hash or algorithm."""
    if hash_algorithm in WEAK_HASHES:
        return False
    return pk_requirement(pk_algorithm) != "MUST NOT generate"


def signature_refusal(hash_algorithm: int) -> str | None:
    """Why the ``openpgp`` policy will not validate a signature with this hash, or None.

    RFC 9580 sec. 9.5: "MUST NOT validate any recent signature that depends on MD5, SHA-1, or
    RIPEMD-160" and "SHOULD NOT validate any old signature ... unless the signature's creation
    date predates known weakness". The RFC gives no date and the signature's creation time is only
    a claim, so the default policy refuses every one, which satisfies both sentences.
    """
    weak = WEAK_HASHES.get(hash_algorithm)
    if weak is None:
        return None
    return (
        f"{weak} signatures are not validated under the openpgp policy (RFC 9580 sec. 9.5: MUST NOT "
        "validate a recent one, SHOULD NOT an old one)"
    )

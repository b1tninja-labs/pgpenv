"""signature verification (RFC 9580 sec. 5.2, 5.2.4, 7): what pgpenv checks and what it does not.

:func:`verify_signature` takes a decoded :class:`~pgpenv.signature.Signature`, the key that is said to
have made it and the data it covers, and answers with a :class:`Verification`. It does the OpenPGP
half of the work: refusing what sec. 5.2.5 and 5.2.3 make unusable, building the hashed octets
(:func:`pgpenv.signature.hash_stream`, sec. 5.2.4), hashing them in one context with ``hashlib``,
comparing the left 16 bits (sec. 5.2.3.6), applying the digest-size rules of sec. 5.2.3.2 to 5.2.3.5,
and decoding the key and signature material for the primitive. The mathematics is
:mod:`pgpenv.crypto`'s, which is sigwire's ``sigwire.verify``. Nothing here imports
``cryptography``, and nothing is loaded until the first call.

What a ``valid`` result means, and what it does not. It says that the signature is a good signature by
the *given key* over *exactly the data given*, under the policy named. It says nothing about whether
the key was valid, unexpired or unrevoked at the time (sec. 5.2.3.13, 5.2.3.31), whether the signer is
trusted, or whether the document is what the user meant: those are the M5 rows. The result carries only
facts that were checked, in ``checked``; the issuer subpackets are reported as a hint
(``issuer_hint``) because they are advisory (sec. 13.13), and a signature by a key other than the hint
is simply checked against the key it was given.

The answer is a *status*, never an exception, for everything the signature or the key does to
itself, because a stream of signatures must not stop at one bad one (sec. 5.2.5):

``valid``
    the signature verified;
``invalid``
    it did not: the left 16 bits, or the mathematics, disagree with the data and the key;
``malformed``
    the packet or the key is unusable in the sense of sec. 5.2.5 or the MUSTs of sec. 5.2.3: a
    signature with problems, a version that does not belong with the key (sec. 10.3.2.2, Table 27), a
    hash too short for the algorithm, an impossible key;
``unsupported``
    an algorithm, curve or hash this installation cannot compute (a curve OID outside RFC 9580
    Table 19, RIPEMD-160 without OpenSSL's legacy provider, SHA-3 under PKCS #1 v1.5, an unknown
    algorithm number);
``refused``
    well formed and supported, but the policy forbids it (MD5, SHA-1 and RIPEMD-160 signatures, RSA
    under 2048 bits, DSA: sec. 9.5, 12.4, 12.5);
``no-key``
    the signature names an issuer and none of the keys given matches it.

Only misuse raises: a document missing for a document signature, a user ID missing for a
certification, and the like, as :func:`pgpenv.signature.hash_stream` does.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, cast

from . import crypto
from .errors import (
    MalformedKeyMaterialError,
    PolicyRefusalError,
    SignatureError,
    UnsupportedAlgorithmError,
)
from .packet import iter_packets
from .policy import signature_refusal
from .registry import (
    CURVES,
    HASHES,
    PK_ALGORITHMS,
    PQ_KEY_VERSIONS,
    PQ_MIN_DIGEST_BITS,
    PQ_SIGNATURE_SIZES,
)
from .signature import Signature, hash_stream, parse_signature
from .wire import Mpi

if TYPE_CHECKING:
    from .certificate import Certificate
    from .cleartext import CleartextSigned
    from .key import PublicKey

__all__ = [
    "SelfSignature",
    "Status",
    "Verification",
    "WeakHashTime",
    "check_self_signatures",
    "verify_back_signatures",
    "verify_binding",
    "verify_certification",
    "verify_cleartext",
    "verify_direct_key",
    "verify_document",
    "verify_signature",
]

Status = Literal["valid", "invalid", "malformed", "unsupported", "refused", "no-key"]

_RSA = (1, 3)
_DOCUMENT_TYPES = (0x00, 0x01, 0x02)
_CERTIFICATION_TYPES = (0x10, 0x11, 0x12, 0x13)
# RFC 9580 sec. 10.3.2.2, Table 27: which signature versions a key version may have made.
_ALIGNED = {(2, 3), (3, 3), (4, 3), (4, 4), (6, 6)}
_WEAK_HASHES = {1: "MD5", 2: "SHA-1", 3: "RIPEMD-160"}


@dataclass(frozen=True, slots=True)
class Verification:
    """The result of checking one signature against one key. See the module docstring.

    ``checked`` lists the facts that were actually verified, in order: ``hash`` (the digest was
    computed), ``left16`` (the two quick-check octets match), ``signature`` (the primitive accepted
    it). ``issuer`` is the fingerprint of the key the signature was checked against, ``issuer_hint``
    whether the signature's own issuer subpackets named it (``match``, ``mismatch``, ``absent``),
    and ``warnings`` the deprecations that applied. ``created`` is the claimed creation time, which
    is not checked against anything.
    """

    status: Status
    reason: str | None
    sig_version: int
    sig_type: int
    pub_algo: int
    hash_algo: int
    issuer: bytes | None = None
    issuer_hint: str = "absent"
    created: int | None = None
    checked: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def valid(self) -> bool:
        return self.status == "valid"


@dataclass(frozen=True, slots=True)
class WeakHashTime:
    """The creation-time half of RFC 9580 sec. 9.5, for a policy that validates MD5, SHA-1 or RIPEMD-160.

    The RFC says an implementation "MUST NOT validate any recent signature" that depends on one of
    them and "SHOULD NOT validate any old signature ... unless the signature's creation date predates
    known weakness of the algorithm used, and the implementation is confident that the message has
    been in the secure custody of the user the whole time". It names no date, so ``cutoffs`` maps a
    hash id to the Unix time before which the caller says the weakness was not known, and ``custody``
    is the caller's statement that the data was kept safe. A signature with a weak hash is accepted
    for the primitive to check only if its hash has a cut-off, its creation time (a claim: nothing
    vouches for it) is before that, and ``custody`` is true; anything else is ``refused``.
    """

    cutoffs: Mapping[int, int]
    custody: bool = False


def _weak_hash_refusal(sig: Signature, policy: Any, weak_hashes: WeakHashTime | None) -> str | None:
    """Why a signature with MD5, SHA-1 or RIPEMD-160 must not be validated (sec. 9.5), or None."""
    name = _WEAK_HASHES.get(sig.hash_algo)
    if name is None:
        return None
    if policy == "openpgp":
        return signature_refusal(sig.hash_algo)
    if weak_hashes is None:
        return None
    cutoff = weak_hashes.cutoffs.get(sig.hash_algo)
    if cutoff is None:
        return (
            f"no cut-off date was given for {name}, so every {name} signature is recent (sec. 9.5)"
        )
    if sig.created is None:
        return (
            f"the {name} signature has no creation time, so it cannot be shown to predate {cutoff}"
        )
    if sig.created >= cutoff:
        return f"a {name} signature created at {sig.created}, not before {cutoff}, is recent (sec. 9.5)"
    if not weak_hashes.custody:
        return (
            f"an old {name} signature is accepted only if the data has been in secure custody the "
            "whole time (sec. 9.5), and the caller did not say so"
        )
    return None


def _public_keys(signer: Any) -> list[PublicKey]:
    """The keys a signer argument stands for: a key, or a certificate's primary key and subkeys."""
    if hasattr(signer, "primary"):
        return [signer.primary, *(entry.key for entry in signer.subkeys)]
    if isinstance(signer, (list, tuple)):
        out: list[PublicKey] = []
        for item in signer:
            out.extend(_public_keys(item))
        return out
    return [signer]


def _can_sign(key: PublicKey) -> bool:
    known = PK_ALGORITHMS.get(key.algorithm)
    return known is None or known.signs


def _hint(sig: Signature, key: PublicKey) -> str:
    fingerprint = sig.issuer_fingerprint
    if fingerprint is not None:
        return "match" if fingerprint[1] == key.fingerprint else "mismatch"
    keyid = sig.issuer_keyid
    if keyid is not None:
        return "match" if keyid == key.keyid else "mismatch"
    return "absent"


def _result(
    status: Status,
    reason: str | None,
    sig: Signature,
    key: PublicKey | None,
    checked: tuple[str, ...] = (),
    warnings: tuple[str, ...] = (),
) -> Verification:
    return Verification(
        status,
        reason,
        sig.version,
        sig.sig_type,
        sig.pub_algo,
        sig.hash_algo,
        None if key is None else key.fingerprint,
        "absent" if key is None else _hint(sig, key),
        sig.created,
        checked,
        warnings,
    )


def _mpis(sig: Signature) -> list[Mpi]:
    """The signature's MPIs; the algorithms that carry them (RSA, DSA, ECDSA, EdDSALegacy) all do."""
    return [part for part in sig.parts() if isinstance(part, Mpi)]


def _mpi_bytes(value: int, length: int) -> bytes | None:
    try:
        return value.to_bytes(length, "big")
    except OverflowError:
        return None


def _minimum_digest_bits(key: PublicKey) -> int | None:
    """The shortest digest the algorithm accepts, RFC 9580 sec. 5.2.3.2 to 5.2.3.5; None if unbounded."""
    algo = key.algorithm
    if algo == 19:
        curve = CURVES.get(key.curve_oid) if key.curve_oid is not None else None
        # "at least the curve's fsize ... except NIST P-521, for which at least 512 bits"
        return None if curve is None else min(curve.bits, 512)
    if algo in (22, 27):
        return 256
    if algo == 28:
        return 512
    if algo in PQ_SIGNATURE_SIZES:
        return PQ_MIN_DIGEST_BITS  # RFC 9980 sec. 5.3.1, 6.2.1, 9.4
    if algo == 17:
        q = key.fields.get("q")
        return q.bit_length() if isinstance(q, int) else None
    return None


def _dispatch(sig: Signature, key: PublicKey, digest: bytes, hash_name: str, policy: Any) -> bool:
    """Hand the decoded material of ``sig`` and ``key`` to the primitive for the key's algorithm."""
    algo = key.algorithm
    fields = key.fields
    if algo in _RSA:
        (value,) = _mpis(sig)
        n, e = fields["n"], fields["e"]
        signature = _mpi_bytes(value.value, (n.bit_length() + 7) // 8)
        if signature is None:
            return (
                False  # an integer larger than the modulus is not a signature (RFC 8017 sec. 8.2.2)
            )
        return crypto.rsa_pkcs1v15(n, e, digest, signature, hash_name, policy)
    if algo == 17:
        r, s = _mpis(sig)
        return crypto.dsa(
            fields["p"],
            fields["q"],
            fields["g"],
            fields["y"],
            digest,
            r.value,
            s.value,
            hash_name,
            policy,
        )
    if algo == 19:
        curve = CURVES.get(key.curve_oid) if key.curve_oid is not None else None
        if curve is None:
            raise UnsupportedAlgorithmError(f"unknown curve {key.curve}")
        name = curve.name.removeprefix("NIST ")
        point = fields["point"]
        if len(point) < 3 or point[0] != 4 or len(point) % 2 == 0:
            raise MalformedKeyMaterialError(
                "an ECDSA public key must be an uncompressed SEC1 point (sec. 11.2.1)"
            )
        half = (len(point) - 1) // 2
        r, s = _mpis(sig)
        return crypto.ecdsa(
            name,
            int.from_bytes(point[1 : 1 + half], "big"),
            int.from_bytes(point[1 + half :], "big"),
            digest,
            r.value,
            s.value,
            hash_name,
            policy,
        )
    if algo == 22:
        point = fields["point"]
        if len(point) != 33 or point[0] != 0x40:
            raise MalformedKeyMaterialError(
                "an Ed25519Legacy point is 0x40 and 32 octets (sec. 9.2.1)"
            )
        r, s = _mpis(sig)
        # sec. 5.2.3.3.1: native (little-endian) octet strings of up to 32 octets, sent as MPIs, so
        # leading zero octets of the wire value were dropped and have to be put back
        if len(r.octets) > 32 or len(s.octets) > 32:
            return False
        signature = r.octets.rjust(32, b"\x00") + s.octets.rjust(32, b"\x00")
        return crypto.ed25519(point[1:], digest, signature, policy)
    if algo == 27:
        return crypto.ed25519(fields["public"], digest, sig.material, policy)
    if algo == 28:
        return crypto.ed448(fields["public"], digest, sig.material, policy)
    if algo in PQ_SIGNATURE_SIZES:
        raise UnsupportedAlgorithmError(
            f"{PK_ALGORITHMS[algo].name} (RFC 9980) is read and its structure checked, "
            "but no ML-DSA or SLH-DSA verification primitive is installed"
        )
    raise UnsupportedAlgorithmError(f"public key algorithm {algo} has no signature verification")


def _check_pairing(sig: Signature, key: PublicKey) -> str | None:
    """A reason the signature and the key cannot belong together, or None."""
    if not sig.usable:
        return "unusable signature (sec. 5.2.5): " + "; ".join(sig.problems)
    if (key.version, sig.version) not in _ALIGNED:
        return (
            f"a version {sig.version} signature by a version {key.version} key is not one of the "
            "combinations of sec. 10.3.2.2, Table 27 (and sec. 5.2.5 for a version 6 key)"
        )
    same_family = sig.pub_algo == key.algorithm or (sig.pub_algo in _RSA and key.algorithm in _RSA)
    if not same_family:
        return (
            f"the signature names algorithm {sig.pub_algo} but the key is algorithm {key.algorithm}"
        )
    if sig.version == 3 and key.algorithm in (19, 22, 27, 28):
        return (
            "a version 3 signature must not be used with ECDSA or EdDSA (sec. 5.2.3.2 to 5.2.3.5)"
        )
    if sig.version == 6 and key.algorithm == 22:
        return "Ed25519Legacy must not be used in a version 6 signature (sec. 5.2.3.3.1)"
    return None


def verify_signature(
    sig: Signature,
    signer: PublicKey | Certificate | Sequence[Any],
    *,
    document: bytes | None = None,
    text_is_canonical: bool = False,
    key: PublicKey | None = None,
    subkey: PublicKey | None = None,
    user_id: bytes | None = None,
    attribute: bytes | None = None,
    confirmed: Signature | None = None,
    policy: Any = "openpgp",
    weak_hashes: WeakHashTime | None = None,
) -> Verification:
    """Check ``sig`` against ``signer`` over the data its type names (RFC 9580 sec. 5.2.4).

    ``signer`` is the key that made the signature, a certificate (its primary key and subkeys are the
    candidates) or a list of either. With more than one candidate the issuer fingerprint or key id of
    the signature chooses; if it names none of them the status is ``no-key``, and with no issuer
    information every candidate that can sign is tried. The data arguments are those of
    :func:`pgpenv.signature.hash_stream`: ``document`` for types 0x00 to 0x02; ``key`` (the key being
    certified or bound, which is not the signer for a certification by another key), ``subkey``,
    ``user_id`` or ``attribute`` for the key signatures; ``confirmed`` for 0x50. ``policy`` is
    ``"openpgp"`` (sec. 9.5, 12.4, 12.5), ``"legacy"`` (historical verification: SHA-1, MD5, DSA,
    short RSA) or a sigwire policy object. ``weak_hashes`` adds the creation-time rule of sec. 9.5
    for MD5, SHA-1 and RIPEMD-160 (:class:`WeakHashTime`). A status is returned for everything the signature and the
    key do to themselves; see the module docstring.
    """
    candidates = [c for c in _public_keys(signer) if _can_sign(c)]
    if not candidates:
        return _result("no-key", "no key that can sign was given", sig, None)
    if len(candidates) > 1 and (sig.issuer_fingerprint or sig.issuer_keyid) is not None:
        candidates = [c for c in candidates if _hint(sig, c) == "match"]
        if not candidates:
            return _result(
                "no-key",
                "the signature names an issuer that is not among the keys given",
                sig,
                None,
            )
    last: Verification | None = None
    for candidate in candidates:
        last = _verify_with(
            sig,
            candidate,
            document=document,
            text_is_canonical=text_is_canonical,
            key=key,
            subkey=subkey,
            user_id=user_id,
            attribute=attribute,
            confirmed=confirmed,
            policy=policy,
            weak_hashes=weak_hashes,
        )
        if last.valid:
            return last
    return cast("Verification", last)  # candidates is not empty


def _verify_with(
    sig: Signature,
    signer: PublicKey,
    *,
    document: bytes | None,
    text_is_canonical: bool,
    key: PublicKey | None,
    subkey: PublicKey | None,
    user_id: bytes | None,
    attribute: bytes | None,
    confirmed: Signature | None,
    policy: Any,
    weak_hashes: WeakHashTime | None = None,
) -> Verification:
    reason = _check_pairing(sig, signer)
    if reason is not None:
        return _result("malformed", reason, sig, signer)
    refusal = _weak_hash_refusal(sig, policy, weak_hashes)
    if refusal is not None:
        return _result("refused", refusal, sig, signer)
    info = HASHES.get(sig.hash_algo)
    if info is None or info.hashlib_name is None:
        return _result("unsupported", f"unknown hash algorithm {sig.hash_algo}", sig, signer)
    if (
        info.salt is not None
        and sig.version == 6
        and sig.salt is not None
        and len(sig.salt) != info.salt
    ):
        return _result(
            "malformed", "the salt length does not match the hash (sec. 5.2.5)", sig, signer
        )
    stream = hash_stream(
        sig,
        document=document,
        text_is_canonical=text_is_canonical,
        key=key,
        subkey=subkey,
        user_id=user_id,
        attribute=attribute,
        confirmed=confirmed,
    )
    try:
        digest = hashlib.new(info.hashlib_name, stream).digest()
    except ValueError:
        return _result(
            "unsupported",
            f"{info.name} is not available from this interpreter's hashlib",
            sig,
            signer,
        )
    checked: tuple[str, ...] = ("hash",)
    warnings: list[str] = []
    if sig.hash_algo in _WEAK_HASHES:
        warnings.append(f"{_WEAK_HASHES[sig.hash_algo]} is deprecated for signatures (sec. 9.5)")
    if signer.algorithm == 22:
        warnings.append("EdDSALegacy is deprecated (sec. 5.2.3.3)")
    if signer.algorithm in _RSA and signer.bits is not None and signer.bits < 3072:
        warnings.append("RSA keys under 3072 bits should not be used to verify (sec. 12.4)")
    if signer.algorithm == 17:
        warnings.append("DSA is deprecated and must not be used to verify (sec. 12.5)")
    if digest[:2] != sig.left16:
        return _result(
            "invalid",
            "the left 16 bits of the hash do not match (sec. 5.2.3.6)",
            sig,
            signer,
            checked,
            tuple(warnings),
        )
    checked = (*checked, "left16")
    minimum = _minimum_digest_bits(signer)
    if minimum is not None and 8 * len(digest) < minimum:
        return _result(
            "malformed",
            f"{info.name} is shorter than the {minimum} bits this algorithm needs (sec. 5.2.3.2 to 5.2.3.5)",
            sig,
            signer,
            checked,
            tuple(warnings),
        )
    try:
        ok = _dispatch(sig, signer, digest, info.hashlib_name, crypto.policy(policy))
    except PolicyRefusalError as error:
        return _result("refused", str(error), sig, signer, checked, tuple(warnings))
    except UnsupportedAlgorithmError as error:
        return _result("unsupported", str(error), sig, signer, checked, tuple(warnings))
    except (MalformedKeyMaterialError, SignatureError) as error:
        return _result(
            "malformed", f"{type(error).__name__}: {error}", sig, signer, checked, tuple(warnings)
        )
    if not ok:
        return _result(
            "invalid",
            "the signature does not verify under this key",
            sig,
            signer,
            checked,
            tuple(warnings),
        )
    return _result("valid", None, sig, signer, (*checked, "signature"), tuple(warnings))


def verify_document(
    data: bytes,
    sig: Signature,
    signer: PublicKey | Certificate | Sequence[Any],
    *,
    policy: Any = "openpgp",
    weak_hashes: WeakHashTime | None = None,
) -> Verification:
    """A binary (0x00), text (0x01) or standalone (0x02) signature over ``data`` (sec. 5.2.4).

    A text signature canonicalises line endings to CR LF before hashing; pass the document as it
    is. A standalone signature covers no document and ``data`` must be empty. Other signature types
    raise :class:`~pgpenv.errors.SignatureError`: they are over keys, see :func:`verify_binding`
    and :func:`verify_certification`.
    """
    if sig.sig_type not in _DOCUMENT_TYPES:
        raise SignatureError(
            f"signature type {sig.sig_type:#04x} is not a document signature; "
            "use verify_certification, verify_binding or verify_direct_key"
        )
    return verify_signature(sig, signer, document=data, policy=policy, weak_hashes=weak_hashes)


def verify_cleartext(
    message: CleartextSigned | bytes | str,
    signer: PublicKey | Certificate | Sequence[Any],
    *,
    policy: Any = "openpgp",
    weak_hashes: WeakHashTime | None = None,
) -> list[Verification]:
    """Every signature of a cleartext signed message, each checked over its signed text (sec. 7).

    ``message`` is the text of the message or a :class:`~pgpenv.cleartext.CleartextSigned`. The signed
    text is already canonical (CR LF line endings, trailing spaces and tabs removed, the line ending
    before the signature block dropped), so it is hashed as it stands. The legacy ``Hash`` headers are
    ignored (sec. 7.1). Signatures whose type is not 0x01 are reported ``malformed``: a cleartext
    signature is a text signature. One result per signature packet, in order; a damaged armor block
    raises :class:`~pgpenv.errors.CleartextError`.
    """
    from .cleartext import CleartextSigned
    from .cleartext import parse as parse_cleartext

    parsed = message if isinstance(message, CleartextSigned) else parse_cleartext(message)
    results: list[Verification] = []
    for block in parsed.signatures:
        for packet in iter_packets(block.data):
            if packet.tag != 2:
                continue
            sig = parse_signature(packet.body)
            if sig.sig_type != 0x01:
                results.append(
                    _result(
                        "malformed",
                        f"a cleartext signature is a text signature (0x01), not {sig.sig_type:#04x}",
                        sig,
                        None,
                    )
                )
                continue
            results.append(
                verify_signature(
                    sig,
                    signer,
                    document=parsed.text,
                    text_is_canonical=True,
                    policy=policy,
                    weak_hashes=weak_hashes,
                )
            )
    return results


def verify_certification(
    sig: Signature,
    signer: PublicKey | Certificate | Sequence[Any],
    target: PublicKey | Certificate,
    *,
    user_id: bytes | None = None,
    attribute: bytes | None = None,
    policy: Any = "openpgp",
    weak_hashes: WeakHashTime | None = None,
) -> Verification:
    """A certification (0x10 to 0x13) or certification revocation (0x30) of a User ID or attribute.

    ``target`` is the key the User ID belongs to (a certificate stands for its primary key); the
    signature hashes that key and the User ID (sec. 5.2.4), and ``signer`` made it: the same key for
    a self-certification, another for a third-party one. Pass ``user_id`` or ``attribute`` as the
    packet body bytes.
    """
    if sig.sig_type not in (*_CERTIFICATION_TYPES, 0x30):
        raise SignatureError(f"signature type {sig.sig_type:#04x} is not a certification")
    target_key = target.primary if hasattr(target, "primary") else target
    return verify_signature(
        sig,
        signer,
        key=target_key,
        user_id=user_id,
        attribute=attribute,
        policy=policy,
        weak_hashes=weak_hashes,
    )


def verify_direct_key(
    sig: Signature,
    signer: PublicKey | Certificate | Sequence[Any],
    target: PublicKey | Certificate,
    *,
    policy: Any = "openpgp",
    weak_hashes: WeakHashTime | None = None,
) -> Verification:
    """A direct key signature (0x1F) or key revocation (0x20) over ``target`` (sec. 5.2.4)."""
    if sig.sig_type not in (0x1F, 0x20):
        raise SignatureError(f"signature type {sig.sig_type:#04x} is not a direct key signature")
    target_key = target.primary if hasattr(target, "primary") else target
    return verify_signature(sig, signer, key=target_key, policy=policy, weak_hashes=weak_hashes)


def _is_pq(primary: PublicKey, subkey: PublicKey, sig: Signature) -> bool:
    """Whether a binding concerns an RFC 9980 algorithm: the signer, the signature or the subkey."""
    return any(
        algorithm in PQ_KEY_VERSIONS
        for algorithm in (primary.algorithm, subkey.algorithm, sig.pub_algo)
    )


def verify_binding(
    sig: Signature,
    primary: PublicKey | Certificate,
    subkey: PublicKey,
    *,
    policy: Any = "openpgp",
    weak_hashes: WeakHashTime | None = None,
) -> Verification:
    """A subkey binding (0x18) or subkey revocation (0x28): the primary key's signature over both keys."""
    if sig.sig_type not in (0x18, 0x28):
        raise SignatureError(f"signature type {sig.sig_type:#04x} is not a subkey signature")
    primary_key = primary.primary if hasattr(primary, "primary") else primary
    if sig.sig_type == 0x18 and sig.hash_algo in _WEAK_HASHES and _is_pq(primary_key, subkey, sig):
        # RFC 9980 sec. 7.2: a subkey binding over its algorithms with MD5, SHA-1 or RIPEMD-160
        # "MUST" be treated as invalid, whatever the policy says about the hash elsewhere
        return _result(
            "malformed",
            f"a subkey binding made with {_WEAK_HASHES[sig.hash_algo]} is invalid "
            "for a post-quantum algorithm (RFC 9980 sec. 7.2)",
            sig,
            primary_key,
        )
    return verify_signature(
        sig, primary_key, key=primary_key, subkey=subkey, policy=policy, weak_hashes=weak_hashes
    )


def verify_back_signatures(
    binding: Signature,
    primary: PublicKey | Certificate,
    subkey: PublicKey,
    *,
    policy: Any = "openpgp",
) -> list[Verification]:
    """The primary key binding signatures (0x19) embedded in a subkey binding, made by the subkey.

    A signing subkey proves it consents to be bound by signing the same two keys itself (sec. 5.2.1.9).
    Each embedded signature is checked against ``subkey``; the list is empty when the binding carries
    none, which for a signing subkey is a finding the caller has to make.
    """
    primary_key = primary.primary if hasattr(primary, "primary") else primary
    results = []
    for embedded in binding.embedded:
        if embedded.sig_type != 0x19:
            continue
        results.append(
            verify_signature(embedded, subkey, key=primary_key, subkey=subkey, policy=policy)
        )
    return results


@dataclass(frozen=True, slots=True)
class SelfSignature:
    """One self-signature of a certificate and what checking it came to.

    ``target`` says what it covers: ``direct``, ``user-id``, ``subkey`` (a binding or its
    revocation) or ``back`` (an embedded primary key binding). ``index`` locates it: the User ID or
    subkey position. ``verification`` is ``None`` for a certification the primary key did not make
    (a third-party signature the certificate carries); it cannot be checked without its issuer.
    """

    target: str
    index: int | None
    signature: Signature
    verification: Verification | None


def check_self_signatures(
    cert: Certificate, *, policy: Any = "openpgp"
) -> tuple[SelfSignature, ...]:
    """Verify every signature of ``cert`` that its own primary key should have made.

    That is the direct key signatures and revocations, the certifications of its User IDs and
    attributes, the subkey bindings and revocations, and the back signatures embedded in bindings.
    Certifications by another key are listed with ``verification=None`` and an issuer that is not the
    primary key; nothing is decided about them. This reports what verified, not what is in force: no
    expiry, revocation, preference or primary-user-ID decision is made here (the M5 rows).
    """
    primary = cert.primary
    results: list[SelfSignature] = []

    def by_primary(sig: Signature) -> bool:
        if sig.issuer_fingerprint is not None:
            return sig.issuer_fingerprint[1] == primary.fingerprint
        keyid = sig.issuer_keyid
        return keyid is None or keyid == primary.keyid

    for sig in cert.signatures:
        if sig.sig_type in (0x1F, 0x20):
            checked = (
                verify_direct_key(sig, primary, primary, policy=policy) if by_primary(sig) else None
            )
            results.append(SelfSignature("direct", None, sig, checked))
    for position, entry in enumerate(cert.user_ids):
        for sig in entry.signatures:
            if sig.sig_type not in (*_CERTIFICATION_TYPES, 0x30):
                continue
            if not by_primary(sig):
                results.append(SelfSignature("user-id", position, sig, None))
                continue
            is_id = entry.kind == "id"
            results.append(
                SelfSignature(
                    "user-id",
                    position,
                    sig,
                    verify_certification(
                        sig,
                        primary,
                        primary,
                        user_id=entry.body if is_id else None,
                        attribute=None if is_id else entry.body,
                        policy=policy,
                    ),
                )
            )
    for position, sub in enumerate(cert.subkeys):
        for sig in sub.signatures:
            if sig.sig_type not in (0x18, 0x28):
                continue
            results.append(
                SelfSignature(
                    "subkey", position, sig, verify_binding(sig, primary, sub.key, policy=policy)
                )
            )
            if sig.sig_type == 0x18:
                for embedded in sig.embedded:
                    if embedded.sig_type == 0x19:
                        back = verify_signature(
                            embedded, sub.key, key=primary, subkey=sub.key, policy=policy
                        )
                        results.append(SelfSignature("back", position, embedded, back))
    return tuple(results)

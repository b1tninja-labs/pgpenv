"""signature packets and the hashing rules that bind them (RFC 9580).

This module *reads* signature packets and builds the byte string a verifier hashes. It does not
check a signature: no cryptographic primitive belongs in a parser. ``verify`` here is a thin entry
point to :mod:`pgpenv.verification`, which hashes the stream and calls the verify-only primitives of
``sigwire[verify]`` through :mod:`pgpenv.crypto` (see docs/verify-seam.md).

:func:`parse_signature` decodes version 3, 4 and 6 packets (sec. 5.2.2, 5.2.3), splits the
hashed from the unhashed subpacket area, and decodes the subpackets this project understands.
Information in the unhashed area is not covered by the signature (sec. 5.2.3.6, 13.13), so every
accessor says which area it read from. A packet that is structurally impossible (a subpacket area
longer than the packet) raises :class:`SignatureError`; one that is merely malformed or unknown in
the sense of sec. 5.2.5 is returned with ``problems`` filled in, and ``usable`` is False, so a
keyring walk can note it and carry on as sec. 5.2.5 requires.

:func:`hash_stream` is the exact recipe of sec. 5.2.4: salt (v6), the data for the signature type,
and the trailer. RFC 9580 appendix A.3.1 and A.6 print the expected octets and the tests pin them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .errors import LimitError, PgpError, SignatureError
from .limits import DEFAULT_LIMITS, Limits
from .packet import decode_length
from .registry import (
    HASHES,
    PK_ALGORITHMS,
    PQ_MIN_DIGEST_BITS,
    PQ_SIGNATURE_SIZES,
    SUBPACKET_NAMES,
    hash_name,
)
from .wire import Mpi, read_mpi

if TYPE_CHECKING:
    from typing import Any

    Key = Any  # anything with ``version`` and ``body`` (a pgpenv.key.PublicKey)
    from .verification import Verification

    Policy = Any  # "openpgp", "legacy" or a sigwire policy object (pgpenv.crypto.policy)

__all__ = [
    "Notation",
    "Signature",
    "Subpacket",
    "canonicalize_text",
    "hash_stream",
    "hash_trailer",
    "key_hash_bytes",
    "parse_signature",
    "sign",
    "verify",
]

_KNOWN_SUBPACKETS = frozenset(SUBPACKET_NAMES)


@dataclass(frozen=True, slots=True)
class Notation:
    """A notation data subpacket (sec. 5.2.3.24)."""

    name: str
    value: bytes
    human_readable: bool
    flags: bytes


@dataclass(frozen=True, slots=True)
class Subpacket:
    """One signature subpacket. ``data`` is the body after the type octet; ``value`` is decoded.

    ``problem`` is set when the body diverges from the length or shape its type requires
    (sec. 5.2.5: a subpacket with a length that diverges from the expected length).
    """

    type: int
    critical: bool
    data: bytes
    hashed: bool
    value: object = None
    problem: str | None = None

    @property
    def name(self) -> str:
        return SUBPACKET_NAMES.get(self.type, f"unknown({self.type})")

    @property
    def known(self) -> bool:
        return self.type in _KNOWN_SUBPACKETS


class _MalformedError(Exception):
    """A subpacket body that does not match its type (turned into ``Subpacket.problem``)."""


def _u32(data: bytes) -> int:
    if len(data) != 4:
        raise _MalformedError(f"a time field is 4 octets, found {len(data)}")
    return int.from_bytes(data, "big")


def _bool(data: bytes) -> bool:
    if len(data) != 1:
        raise _MalformedError(f"a boolean subpacket is 1 octet, found {len(data)}")
    return data[0] != 0


def _text(data: bytes) -> str:
    return data.decode("utf-8", "replace")


def _fingerprint(data: bytes) -> tuple[int, bytes]:
    if not data:
        raise _MalformedError("an empty fingerprint subpacket")
    version, fingerprint = data[0], data[1:]
    expected = {4: 20, 6: 32}.get(version)
    if expected is not None and len(fingerprint) != expected:
        raise _MalformedError(
            f"a version {version} fingerprint is {expected} octets, found {len(fingerprint)}"
        )
    if expected is None and not 16 <= len(fingerprint) <= 64:
        raise _MalformedError(f"fingerprint of unknown key version {version}")
    return version, fingerprint


def _notation(data: bytes) -> Notation:
    if len(data) < 8:
        raise _MalformedError("a notation subpacket needs 8 octets of header")
    name_len = int.from_bytes(data[4:6], "big")
    value_len = int.from_bytes(data[6:8], "big")
    if len(data) != 8 + name_len + value_len:
        raise _MalformedError("notation lengths do not add up to the subpacket length")
    return Notation(
        _text(data[8 : 8 + name_len]),
        data[8 + name_len :],
        bool(data[0] & 0x80),
        data[:4],
    )


def _decode(kind: int, data: bytes, limits: Limits, depth: int) -> object:
    """Decode the body of a known subpacket type, or return None for an unknown one."""
    if kind in (2, 3, 9):
        return _u32(data)
    if kind in (4, 7, 25):
        return _bool(data)
    if kind == 5:
        if len(data) != 2:
            raise _MalformedError("a trust signature subpacket is 2 octets")
        return (data[0], data[1])
    if kind == 6:
        if not data.endswith(b"\x00"):
            raise _MalformedError("a regular expression lacks its NUL terminator")
        return _text(data[:-1])
    if kind in (11, 21, 22):
        return tuple(data)
    if kind == 39:
        if len(data) % 2:
            raise _MalformedError("AEAD ciphersuites come in pairs of octets")
        return tuple((data[i], data[i + 1]) for i in range(0, len(data), 2))
    if kind == 12:
        if len(data) != 22:
            raise _MalformedError("a revocation key subpacket is 22 octets")
        return (data[0], data[1], data[2:])
    if kind == 16:
        if len(data) != 8:
            raise _MalformedError("an issuer key id is 8 octets")
        return data
    if kind == 20:
        return _notation(data)
    if kind in (23, 27, 30):
        return data
    if kind in (24, 26, 28):
        return _text(data)
    if kind == 29:
        if not data:
            raise _MalformedError("a revocation reason needs a code octet")
        return (data[0], _text(data[1:]))
    if kind == 31:
        if len(data) < 2:
            raise _MalformedError("a signature target needs algorithm octets")
        return (data[0], data[1], data[2:])
    if kind == 32:
        try:
            return parse_signature(data, limits, depth + 1)
        except PgpError as error:
            raise _MalformedError(f"embedded signature: {error}") from None
    if kind in (33, 35):
        return _fingerprint(data)
    return None


def _parse_area(
    area: bytes, *, hashed: bool, limits: Limits, depth: int, version: int
) -> tuple[list[Subpacket], list[str]]:
    subpackets: list[Subpacket] = []
    problems: list[str] = []
    pos = 0
    label = "hashed" if hashed else "unhashed"
    while pos < len(area):
        if len(subpackets) >= limits.max_subpackets:
            raise LimitError(f"more than {limits.max_subpackets} subpackets in the {label} area")
        length, pos = decode_length(area, pos, what=f"{label} subpacket")
        if length == 0:
            raise SignatureError(f"a zero-length subpacket in the {label} area")
        if pos + length > len(area):
            raise SignatureError(f"a subpacket overruns the {label} area")
        type_octet = area[pos]
        kind, critical = type_octet & 0x7F, bool(type_octet & 0x80)
        data = area[pos + 1 : pos + length]
        pos += length
        value: object = None
        problem: str | None = None
        try:
            value = _decode(kind, data, limits, depth)
        except _MalformedError as error:
            problem = str(error)
        sub = Subpacket(kind, critical, data, hashed, value, problem)
        subpackets.append(sub)
        if problem is not None:
            problems.append(f"{label} subpacket {sub.name}: {problem}")
        if hashed and critical and not sub.known:
            problems.append(f"unknown critical subpacket {kind} in the hashed area")
        if kind == 33 and isinstance(value, tuple) and value[0] != version:
            problems.append(
                f"issuer fingerprint is for key version {value[0]} in a version {version} "
                "signature (sec. 5.2.3.35)"
            )
        if kind == 16 and version == 6:
            problems.append("a version 6 signature carries an issuer key id (sec. 5.2.3.12)")
    return subpackets, problems


@dataclass(frozen=True, slots=True)
class Signature:
    """A decoded signature packet body. Nothing here has been verified.

    ``body`` is the whole packet body; ``hashed_data`` is the part of it a signature covers
    (version octet through the hashed subpacket data, or for v3 the type and time), ``salt`` the
    v6 salt, ``material`` the algorithm-specific signature octets (MPIs, or the native 64 or 114
    octets of Ed25519 and Ed448, see erratum 8454), and ``left16`` the two quick-check octets.
    """

    version: int
    sig_type: int
    pub_algo: int
    hash_algo: int
    hashed: tuple[Subpacket, ...]
    unhashed: tuple[Subpacket, ...]
    left16: bytes
    salt: bytes | None
    material: bytes
    body: bytes
    hashed_data: bytes
    hashed_end: int = 0
    unhashed_end: int = 0
    created_v3: int | None = None
    issuer_keyid_v3: bytes | None = None
    problems: tuple[str, ...] = field(default_factory=tuple)

    @property
    def usable(self) -> bool:
        """False when the packet is malformed or unknown in the sense of sec. 5.2.5."""
        return not self.problems

    def _last(self, kind: int, *, hashed_only: bool = True) -> Subpacket | None:
        # sec. 5.2.3.9: use the last subpacket of a kind in the hashed section.
        for area in (self.hashed,) if hashed_only else (self.hashed, self.unhashed):
            found = [s for s in area if s.type == kind and s.problem is None]
            if found:
                return found[-1]
        return None

    def value(self, kind: int, *, hashed_only: bool = True) -> Any:
        sub = self._last(kind, hashed_only=hashed_only)
        return None if sub is None else sub.value

    @property
    def created(self) -> int | None:
        """Creation time in seconds since the epoch (hashed area, or the v3 field)."""
        if self.version == 3:
            return self.created_v3
        return self.value(2)

    @property
    def expires_after(self) -> int | None:
        """Signature expiration, in seconds after creation; None or 0 means it never expires."""
        return self.value(3)

    @property
    def key_expires_after(self) -> int | None:
        """Key expiration time in seconds after key creation (sec. 5.2.3.13); 0 means never."""
        return self.value(9)

    @property
    def key_flags(self) -> bytes | None:
        return self.value(27)

    @property
    def issuer_fingerprint(self) -> tuple[int, bytes] | None:
        """``(key version, fingerprint)``, hashed area preferred; see ``issuer_area``."""
        sub = self._last(33, hashed_only=False)
        return None if sub is None else sub.value  # type: ignore[return-value]

    @property
    def issuer_keyid(self) -> bytes | None:
        """The issuer key id: v3 field, subpacket 16, or derived from the issuer fingerprint."""
        if self.issuer_keyid_v3 is not None:
            return self.issuer_keyid_v3
        sub = self._last(16, hashed_only=False)
        if sub is not None:
            return sub.data
        fp = self.issuer_fingerprint
        if fp is not None:
            version, fingerprint = fp
            return fingerprint[-8:] if version == 4 else fingerprint[:8]
        return None

    @property
    def issuer_area(self) -> str | None:
        """Where the issuer was read from: ``v3``, ``hashed``, ``unhashed`` or ``derived``."""
        if self.issuer_keyid_v3 is not None:
            return "v3"
        for kind in (33, 16):
            sub = self._last(kind, hashed_only=False)
            if sub is not None:
                return "hashed" if sub.hashed else "unhashed"
        return None

    @property
    def embedded(self) -> tuple[Signature, ...]:
        return tuple(
            s.value
            for s in self.hashed + self.unhashed
            if s.type == 32 and s.problem is None and isinstance(s.value, Signature)
        )

    def parts(self) -> tuple[Mpi | bytes, ...]:
        """The signature material split per sec. 5.2.3: MPIs for RSA, DSA, ECDSA, EdDSALegacy."""
        if self.pub_algo in (1, 3):
            count = 1
        elif self.pub_algo in (17, 19, 22):
            count = 2
        else:
            return (self.material,)
        out: list[Mpi | bytes] = []
        pos = 0
        for _ in range(count):
            mpi, pos = read_mpi(
                self.material, pos, strict=self.version == 6, error=SignatureError, what="signature"
            )
            out.append(mpi)
        if pos != len(self.material):
            raise SignatureError("trailing octets after the signature MPIs")
        return tuple(out)


def _pq_signature_problems(
    version: int, sig_type: int, pub_algo: int, hash_algo: int, material: int
) -> list[str]:
    """The structural MUSTs of RFC 9980 for a signature by algorithm 30 to 34, as problems."""
    name = PK_ALGORITHMS[pub_algo].name
    found: list[str] = []
    if version != 6:
        found.append(f"{name} is used only with version 6 signatures (RFC 9980 sec. 5.3.1, 6.2.1)")
    expected = sum(PQ_SIGNATURE_SIZES[pub_algo])
    if material != expected:
        found.append(f"{name} signature is {expected} octets, found {material} (RFC 9980 sec. 11)")
    info = HASHES.get(hash_algo)
    if info is not None and 8 * info.digest_size < PQ_MIN_DIGEST_BITS:
        found.append(
            f"{name} needs a hash of at least {PQ_MIN_DIGEST_BITS} bits, "
            f"{info.name} has {8 * info.digest_size} (RFC 9980 sec. 5.3.1, 6.2.1, 9.4)"
        )
    if sig_type == 0x18 and hash_algo in (1, 2, 3):
        found.append(
            f"a subkey binding by {name} made with {hash_name(hash_algo)} is invalid (RFC 9980 sec. 7.2)"
        )
    return found


def parse_signature(body: bytes, limits: Limits = DEFAULT_LIMITS, depth: int = 0) -> Signature:
    """Decode a Signature packet body (RFC 9580 sec. 5.2); the packet header is not part of it."""
    if depth > limits.max_embedded_depth:
        raise LimitError(f"embedded signatures nested deeper than {limits.max_embedded_depth}")
    if not body:
        raise SignatureError("empty signature packet")
    version = body[0]
    if version == 3:
        return _parse_v3(body)
    if version not in (4, 6):
        raise SignatureError(f"unsupported signature version {version}")
    width = 2 if version == 4 else 4
    if len(body) < 4 + width:
        raise SignatureError("signature packet too short")
    sig_type, pub_algo, hash_algo = body[1], body[2], body[3]
    pos = 4
    hashed_len = int.from_bytes(body[pos : pos + width], "big")
    pos += width
    if pos + hashed_len > len(body):
        raise SignatureError("the hashed subpacket area is longer than the packet (sec. 5.2.5)")
    hashed_raw = body[pos : pos + hashed_len]
    hashed_end = pos + hashed_len
    pos = hashed_end
    if pos + width > len(body):
        raise SignatureError("no unhashed subpacket area length")
    unhashed_len = int.from_bytes(body[pos : pos + width], "big")
    pos += width
    if pos + unhashed_len > len(body):
        raise SignatureError("the unhashed subpacket area is longer than the packet")
    unhashed_raw = body[pos : pos + unhashed_len]
    pos += unhashed_len
    unhashed_end = pos
    if pos + 2 > len(body):
        raise SignatureError("no left 16 bits of the signed hash")
    left16 = body[pos : pos + 2]
    pos += 2
    problems: list[str] = []
    salt: bytes | None = None
    if version == 6:
        if pos >= len(body):
            raise SignatureError("no salt size octet in a version 6 signature")
        salt_len = body[pos]
        pos += 1
        if pos + salt_len > len(body):
            raise SignatureError("the salt runs past the end of the packet")
        salt = body[pos : pos + salt_len]
        pos += salt_len
        info = HASHES.get(hash_algo)
        if info is None or info.salt is None:
            problems.append(f"no salt size is defined for hash algorithm {hash_algo} (Table 23)")
        elif info.salt != salt_len:
            problems.append(f"salt of {salt_len} octets, hash algorithm needs {info.salt}")
    material = body[pos:]
    hashed, p1 = _parse_area(hashed_raw, hashed=True, limits=limits, depth=depth, version=version)
    unhashed, p2 = _parse_area(
        unhashed_raw, hashed=False, limits=limits, depth=depth, version=version
    )
    problems += p1 + p2
    if not any(s.type == 2 and s.problem is None for s in hashed):
        problems.append("no signature creation time in the hashed area (sec. 5.2.3.11)")
    native = {27: 64, 28: 114}.get(pub_algo)
    if native is not None and len(material) != native:
        problems.append(
            f"{PK_ALGORITHMS[pub_algo].name} signature is {native} octets, found {len(material)}"
        )
    if pub_algo in PQ_SIGNATURE_SIZES:
        problems += _pq_signature_problems(version, sig_type, pub_algo, hash_algo, len(material))
    if hash_algo == 1:
        problems.append("a signature using MD5, a hash known to be weak (sec. 5.2.5)")
    return Signature(
        version,
        sig_type,
        pub_algo,
        hash_algo,
        tuple(hashed),
        tuple(unhashed),
        left16,
        salt,
        material,
        body,
        body[:hashed_end],
        hashed_end,
        unhashed_end,
        None,
        None,
        tuple(problems),
    )


def _parse_v3(body: bytes) -> Signature:
    # sec. 5.2.2: version, hashed length (5), type, 4-octet time, 8-octet key id, algorithms, left 16 bits.
    if len(body) < 19:
        raise SignatureError("version 3 signature packet too short")
    if body[1] != 5:
        raise SignatureError(f"version 3 hashed material length is {body[1]}, it MUST be 5")
    problems: list[str] = []
    pub_algo, hash_algo = body[15], body[16]
    if hash_algo == 1:
        problems.append("a signature using MD5, a hash known to be weak (sec. 5.2.5)")
    return Signature(
        3,
        body[2],
        pub_algo,
        hash_algo,
        (),
        (),
        body[17:19],
        None,
        body[19:],
        body,
        body[2:7],
        0,
        0,
        int.from_bytes(body[3:7], "big"),
        body[7:15],
        tuple(problems),
    )


def canonicalize_text(data: bytes) -> bytes:
    """Convert every line ending (CR LF, CR or LF) to CR LF, as a text signature requires (sec. 5.2.4)."""
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r\n")


def key_hash_bytes(key: Key) -> bytes:
    """A key as it enters a signature hash: 0x99 and a 2-octet length, or 0x9B and 4 octets (sec. 5.2.4)."""
    body = key.body
    if key.version == 6:
        return b"\x9b" + len(body).to_bytes(4, "big") + body
    return b"\x99" + len(body).to_bytes(2, "big") + body


def hash_trailer(sig: Signature) -> bytes:
    """The trailer hashed after the data (sec. 5.2.4): v3 type and time, v4 and v6 the hashed fields."""
    if sig.version == 3:
        return sig.hashed_data
    return (
        sig.hashed_data
        + bytes((sig.version, 0xFF))
        + (len(sig.hashed_data) & 0xFFFFFFFF).to_bytes(4, "big")
    )


def hash_stream(
    sig: Signature,
    *,
    document: bytes | None = None,
    text_is_canonical: bool = False,
    key: Key = None,
    subkey: Key = None,
    user_id: bytes | None = None,
    attribute: bytes | None = None,
    confirmed: Signature | None = None,
) -> bytes:
    """The exact octets that are hashed for ``sig``, RFC 9580 sec. 5.2.4; hash them in one context.

    Which arguments are needed follows the signature type: ``document`` for 0x00, 0x01 (text is
    canonicalised unless ``text_is_canonical``) and 0x02 (none); ``key`` for 0x1F and 0x20;
    ``key`` and ``subkey`` for 0x18, 0x19 and 0x28; ``key`` and ``user_id`` (or ``attribute``) for
    0x10 to 0x13 and 0x30; ``confirmed`` for 0x50. ``key`` and ``subkey`` are
    :class:`pgpenv.key.PublicKey` values (anything with ``version`` and ``body``). A version 6
    signature hashes its salt first. A version 3 signature over a key hashes the key exactly as a
    version 4 one does (0x99, a 2-octet length, the key packet body: sec. 5.2.4 says the key is
    hashed that way for every signature made over a key and distinguishes versions only for the
    User ID, which a version 3 certification hashes without header, marker or length, and for the
    trailer, five octets). Raises :class:`SignatureError` for a type with no recipe in the RFC
    (0x40, 0xFF) and for a missing argument.
    """
    t = sig.sig_type
    prefix = sig.salt if sig.salt is not None else b""
    if t in (0x00, 0x01, 0x02):
        data = document if document is not None else b""
        if t == 0x02 and data:
            raise SignatureError("a standalone signature is over zero octets of document")
        if t == 0x01 and not text_is_canonical:
            data = canonicalize_text(data)
        return prefix + data + hash_trailer(sig)
    if t == 0xFF or t == 0x40:
        raise SignatureError(f"RFC 9580 gives no hashing recipe for signature type {t:#04x}")
    if t == 0x50:
        if confirmed is None:
            raise SignatureError("a third-party confirmation needs the confirmed signature")
        width = 2 if confirmed.version == 4 else 4
        body = (
            confirmed.body[: confirmed.hashed_end]
            + bytes(width)
            + confirmed.body[confirmed.unhashed_end :]
        )
        return prefix + b"\x88" + len(body).to_bytes(4, "big") + body + hash_trailer(sig)
    if key is None:
        raise SignatureError(f"signature type {t:#04x} is over a key; pass key=")
    parts = [prefix, key_hash_bytes(key)]
    if t in (0x18, 0x19, 0x28):
        if subkey is None:
            raise SignatureError(f"signature type {t:#04x} is over a subkey; pass subkey=")
        parts.append(key_hash_bytes(subkey))
    elif t in (0x10, 0x11, 0x12, 0x13, 0x30):
        if user_id is not None and attribute is None:
            marker, blob = b"\xb4", user_id
        elif attribute is not None and user_id is None:
            marker, blob = b"\xd1", attribute
        else:
            raise SignatureError("a certification is over exactly one of user_id and attribute")
        if sig.version == 3:
            # sec. 5.2.4: a version 3 certification hashes the contents of the User ID or User
            # Attribute packet without the packet header: no 0xB4 or 0xD1 and no length
            parts.append(blob)
        else:
            parts.append(marker + len(blob).to_bytes(4, "big") + blob)
    elif t not in (0x1F, 0x20):
        raise SignatureError(f"unknown signature type {t:#04x} has no hashing recipe")
    parts.append(hash_trailer(sig))
    return b"".join(parts)


def sign(data: bytes, key: Key, policy: Policy) -> Signature:
    """Pending behaviour defined by RFC 9580 sec. 5.2.

    Not implemented yet. See the ``signature.sign()`` row in ROADMAP.md; this stub raises on
    purpose so nothing downstream mistakes it for working code. Signing is not part of the
    verify-only plan and is deferred behind the owner's decision on private key handling.
    """
    raise NotImplementedError("sign() is not implemented: RFC 9580 sec. 5.2")


def verify(data: bytes, sig: Signature, key: Key, policy: Policy = "openpgp") -> Verification:
    """Check a document signature (types 0x00, 0x01, 0x02) against ``key``, RFC 9580 sec. 5.2.

    ``key`` is the public key that made the signature, a certificate (its primary key and subkeys
    are tried, chosen by the issuer subpackets) or a list of either. The answer is a
    :class:`pgpenv.verification.Verification`: a status (``valid``, ``invalid``, ``malformed``,
    ``unsupported``, ``refused`` or ``no-key``) and the facts that were checked. It says nothing about
    the key's validity, expiry, revocation or trust. ``policy`` is ``"openpgp"`` (RFC 9580 sec. 9.5,
    12.4, 12.5) or ``"legacy"``. This is a thin entry point; the key, cleartext and certificate
    checks, and the full account of what a result means, are in :mod:`pgpenv.verification`, which is
    loaded on the first call so that importing this package never imports ``cryptography``.
    """
    from .verification import verify_document

    return verify_document(data, sig, key, policy=policy)

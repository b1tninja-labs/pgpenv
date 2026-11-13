"""public keys, v4 and v6 fingerprints, subkeys (RFC 9580).

:func:`parse_public_key` decodes the body of a Public Key, Public Subkey, Secret Key or Secret
Subkey packet (sec. 5.5) into a :class:`PublicKey`: version, creation time, algorithm, the key
material split into fields, the fingerprint and the key id (sec. 5.5.4). Versions 4 and 6 are the
live formats; versions 2 and 3 are read-only (sec. 5.5.2: "MAY accept", never generate), and a v3
key is flagged because its fingerprint is MD5 and its key id is part of the modulus.

Fingerprints are computed here from the packet octets, never copied from a file:

* version 3: MD5 over the bodies of the RSA modulus and exponent MPIs, without their length
  octets (sec. 5.5.4.1); key id is the low 64 bits of the modulus;
* version 4: SHA-1 over 0x99, a 2-octet length and the packet body (sec. 5.5.4.2); key id is the
  low 64 bits of the fingerprint;
* version 6: SHA-256 over 0x9B, a 4-octet length and the packet body (sec. 5.5.4.3); key id is
  the high 64 bits.

A Secret Key packet is read only as far as its public part; the secret octets are never decoded,
copied into a result or logged. The fingerprint of a secret key is that of its public part.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .errors import KeyPacketError
from .limits import DEFAULT_LIMITS, Limits
from .registry import CURVES, NATIVE_KEY_SIZES, PK_ALGORITHMS, pk_name
from .wire import Mpi, read_mpi

if TYPE_CHECKING:
    from typing import Any

    from .certificate import Certificate

    Key = Any  # a PublicKey, or a Certificate (its primary key is used)

__all__ = [
    "PublicKey",
    "fingerprint",
    "key_id",
    "load_key",
    "load_keys",
    "parse_public_key",
]

_RSA = (1, 2, 3)


@dataclass(frozen=True, slots=True)
class PublicKey:
    """The public part of a key packet. ``body`` is exactly the octets the fingerprint covers.

    ``fields`` holds the decoded material: ``n`` and ``e`` (ints) for RSA, ``p q g y`` for DSA,
    ``oid`` (bytes) and ``point`` (bytes) for the elliptic curve algorithms, ``public`` (bytes)
    for X25519, X448, Ed25519 and Ed448. ``bits`` is the nominal key size (GnuPG's convention:
    255 for the Curve25519 family, the curve size for NIST and Brainpool curves).
    """

    version: int
    created: int
    algorithm: int
    body: bytes
    fingerprint: bytes
    keyid: bytes
    fields: dict[str, Any] = field(default_factory=dict)
    bits: int | None = None
    curve_oid: bytes | None = None
    is_subkey: bool = False
    secret: bool = False
    valid_days_v3: int | None = None
    problems: tuple[str, ...] = ()

    @property
    def algorithm_name(self) -> str:
        return pk_name(self.algorithm)

    @property
    def curve(self) -> str | None:
        if self.curve_oid is None:
            return None
        known = CURVES.get(self.curve_oid)
        return known.name if known else f"unknown OID {self.curve_oid.hex().upper()}"

    @property
    def deprecated(self) -> bool:
        """True for algorithms RFC 9580 sec. 9.1 and 5.5.5 call deprecated, or a deprecated curve."""
        algo = PK_ALGORITHMS.get(self.algorithm)
        curve = CURVES.get(self.curve_oid) if self.curve_oid is not None else None
        return bool((algo and algo.deprecated) or (curve and curve.deprecated))

    @property
    def fingerprint_hex(self) -> str:
        return self.fingerprint.hex().upper()

    @property
    def keyid_hex(self) -> str:
        return self.keyid.hex().upper()


def _curve_oid(data: bytes, pos: int, what: str) -> tuple[bytes, int]:
    if pos >= len(data):
        raise KeyPacketError(f"{what}: curve OID length octet missing")
    size = data[pos]
    if size in (0, 0xFF):
        raise KeyPacketError(f"{what}: curve OID length {size} is reserved (sec. 5.5.5.4)")
    if pos + 1 + size > len(data):
        raise KeyPacketError(f"{what}: curve OID cut off")
    return data[pos + 1 : pos + 1 + size], pos + 1 + size


def _material(
    algorithm: int, version: int, data: bytes, pos: int
) -> tuple[dict[str, Any], int, int | None, bytes | None, list[str]]:
    """Parse algorithm-specific public material starting at ``pos``.

    Returns ``(fields, end, bits, curve_oid, problems)``; for an unknown algorithm ``end`` is
    ``len(data)`` and the caller decides whether that is acceptable.
    """
    strict = version == 6
    problems: list[str] = []
    fields: dict[str, Any] = {}
    what = f"{pk_name(algorithm)} key"
    bits: int | None = None
    curve_oid: bytes | None = None

    def take(count: int) -> list[Mpi]:
        nonlocal pos
        out = []
        for _ in range(count):
            mpi, pos = read_mpi(data, pos, strict=strict, error=KeyPacketError, what=what)
            if not mpi.normalised:
                problems.append(f"MPI declares {mpi.declared_bits} bits, value has {mpi.bits}")
            out.append(mpi)
        return out

    if algorithm in _RSA:
        n, e = take(2)
        fields = {"n": n.value, "e": e.value, "n_octets": n.octets, "e_octets": e.octets}
        bits = n.bits
    elif algorithm == 17:
        p, q, g, y = take(4)
        fields = {"p": p.value, "q": q.value, "g": g.value, "y": y.value}
        bits = p.bits
    elif algorithm == 16:
        p, g, y = take(3)
        fields = {"p": p.value, "g": g.value, "y": y.value}
        bits = p.bits
    elif algorithm in (18, 19, 22):
        curve_oid, pos = _curve_oid(data, pos, what)
        (point,) = take(1)
        fields = {"oid": curve_oid, "point": point.octets}
        curve = CURVES.get(curve_oid)
        bits = curve.bits if curve else None
        if curve is not None and curve.deprecated and version == 6:
            raise KeyPacketError(f"{what}: a deprecated legacy curve in a version 6 key (sec. 9.2)")
        if algorithm == 18:
            if pos >= len(data):
                raise KeyPacketError(f"{what}: KDF parameters missing")
            size = data[pos]
            if size in (0, 0xFF) or pos + 1 + size > len(data):
                raise KeyPacketError(f"{what}: KDF parameter size {size} is invalid")
            params = data[pos + 1 : pos + 1 + size]
            pos += 1 + size
            if size != 3 or params[0] != 1:
                raise KeyPacketError(f"{what}: unsupported KDF parameters {params.hex()}")
            fields["kdf_hash"], fields["kdf_cipher"] = params[1], params[2]
    elif algorithm in NATIVE_KEY_SIZES:
        size, bits = NATIVE_KEY_SIZES[algorithm]
        if pos + size > len(data):
            raise KeyPacketError(
                f"{what}: public key needs {size} octets, {len(data) - pos} remain"
            )
        fields = {"public": data[pos : pos + size]}
        pos += size
    else:
        pos = len(data)
        problems.append(f"unknown public key algorithm {algorithm}; material kept raw")
    return fields, pos, bits, curve_oid, problems


def parse_public_key(
    body: bytes,
    *,
    subkey: bool = False,
    secret: bool = False,
    limits: Limits = DEFAULT_LIMITS,  # noqa: ARG001 - every parse path takes the bounds
) -> PublicKey:
    """Decode a key packet body (RFC 9580 sec. 5.5.2); for a secret packet only the public part.

    Raises :class:`KeyPacketError` when the body is truncated, has trailing octets after the
    public material (public packets only), names a reserved curve length, or uses a version this
    package cannot read (anything but 2, 3, 4 and 6).
    """
    if not body:
        raise KeyPacketError("empty key packet")
    version = body[0]
    if version in (2, 3):
        if len(body) < 8:
            raise KeyPacketError("version 3 key packet too short")
        created = int.from_bytes(body[1:5], "big")
        days = int.from_bytes(body[5:7], "big")
        algorithm = body[7]
        if algorithm not in _RSA:
            raise KeyPacketError(
                f"version {version} keys are RSA only, found algorithm {algorithm}"
            )
        start = 8
    elif version == 4:
        if len(body) < 6:
            raise KeyPacketError("version 4 key packet too short")
        created = int.from_bytes(body[1:5], "big")
        algorithm = body[5]
        days = None
        start = 6
    elif version == 6:
        if len(body) < 10:
            raise KeyPacketError("version 6 key packet too short")
        created = int.from_bytes(body[1:5], "big")
        algorithm = body[5]
        days = None
        count = int.from_bytes(body[6:10], "big")
        if 10 + count > len(body):
            raise KeyPacketError(f"key material count {count} exceeds the packet")
        start = 10
    else:
        raise KeyPacketError(f"unsupported key packet version {version}")

    if version == 6:
        region = body[: 10 + count]
        fields, end, bits, curve_oid, problems = _material(algorithm, version, region, start)
        if end != len(region):
            raise KeyPacketError("key material count does not match the algorithm's fields")
        public_end = len(region)
    else:
        fields, end, bits, curve_oid, problems = _material(algorithm, version, body, start)
        public_end = end
        if algorithm not in PK_ALGORITHMS and secret:
            raise KeyPacketError("cannot find the end of the public part of an unknown algorithm")
    if not secret and public_end != len(body):
        raise KeyPacketError(
            f"{len(body) - public_end} trailing octets after the public key material"
        )
    public_body = body[:public_end]

    if version == 6:
        fp = hashlib.sha256(b"\x9b" + len(public_body).to_bytes(4, "big") + public_body).digest()
        kid = fp[:8]
    elif version == 4:
        if len(public_body) > 0xFFFF:
            raise KeyPacketError("a version 4 key packet cannot exceed 65535 octets")
        fp = hashlib.sha1(
            b"\x99" + len(public_body).to_bytes(2, "big") + public_body, usedforsecurity=False
        ).digest()
        kid = fp[-8:]
    else:
        fp = hashlib.md5(fields["n_octets"] + fields["e_octets"], usedforsecurity=False).digest()
        kid = fields["n_octets"][-8:].rjust(8, b"\x00")
        problems.append(f"version {version} key: MD5 fingerprint, deprecated (sec. 5.5.2)")
    # the raw octets are for the v3 fingerprint only; callers get integers
    fields.pop("n_octets", None)
    fields.pop("e_octets", None)
    return PublicKey(
        version,
        created,
        algorithm,
        public_body,
        fp,
        kid,
        fields,
        bits,
        curve_oid,
        subkey,
        secret,
        days,
        tuple(problems),
    )


def fingerprint(key: Key) -> bytes:
    """The fingerprint of a key, RFC 9580 sec. 5.5.4: 16, 20 or 32 octets for key version 3, 4, 6.

    ``key`` is a :class:`PublicKey` or a certificate (its primary key). The value was computed
    from the packet when the key was parsed, over the packet octets as read.
    """
    primary: PublicKey = key.primary if hasattr(key, "primary") else key
    return primary.fingerprint


def key_id(key: Key) -> bytes:
    """The 8-octet key id of a key (sec. 5.5.4): low bits of the fingerprint (v4), high bits (v6)."""
    primary: PublicKey = key.primary if hasattr(key, "primary") else key
    return primary.keyid


def load_key(raw: bytes | str) -> Certificate:
    """Load the one OpenPGP certificate in ``raw`` (binary or armored), RFC 9580 sec. 5.5.

    Raises :class:`pgpenv.errors.PgpError` when ``raw`` holds no certificate or more than one;
    use :func:`load_keys` for a keyring. Nothing is verified: the result is what the file claims.
    """
    keys = load_keys(raw)
    if len(keys) != 1:
        from .errors import PgpError

        raise PgpError(f"expected one certificate, found {len(keys)}; use load_keys()")
    return keys[0]


def load_keys(raw: bytes | str, limits: Limits = DEFAULT_LIMITS) -> list[Certificate]:
    """Every certificate in ``raw`` (binary or armored, one or many), in file order."""
    from .certificate import parse_keyring  # certificate imports this module

    return parse_keyring(raw, limits).certificates

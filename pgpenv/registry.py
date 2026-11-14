"""The OpenPGP registries pgpenv names, as read from RFC 9580 on 2026-11-12.

Every table cites its section. A number that is not in a table is reported as ``unknown(N)`` by
the ``*_name`` helpers instead of being guessed at. The post-quantum algorithm identifiers 30 to 36
are RFC 9980 sec. 2.1 and sec. 11, read on 2026-11-13 from the RFC Editor's text (rfclib was
unreachable that day).
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "AEAD_NAMES",
    "COMPRESSION_NAMES",
    "CURVES",
    "HASHES",
    "KEY_FLAG_BITS",
    "PK_ALGORITHMS",
    "PQ_KEY_VERSIONS",
    "PQ_MIN_DIGEST_BITS",
    "PQ_PUBLIC_KEY_SIZES",
    "PQ_SIGNATURE_SIZES",
    "REVOCATION_REASONS",
    "SIGNATURE_TYPES",
    "SUBPACKET_NAMES",
    "SYMMETRIC_NAMES",
    "Curve",
    "HashInfo",
    "PkAlgorithm",
    "hash_name",
    "key_flag_names",
    "pk_name",
    "signature_type_name",
]


@dataclass(frozen=True, slots=True)
class PkAlgorithm:
    """RFC 9580 sec. 9.1, Table 18. ``deprecated`` follows the wording of sec. 9.1 and sec. 5.5.5."""

    id: int
    name: str
    deprecated: bool = False
    signs: bool = False
    encrypts: bool = False


PK_ALGORITHMS: dict[int, PkAlgorithm] = {
    a.id: a
    for a in (
        PkAlgorithm(1, "RSA", True, True, True),
        PkAlgorithm(2, "RSA Encrypt-Only", True, False, True),
        PkAlgorithm(3, "RSA Sign-Only", True, True, False),
        PkAlgorithm(16, "Elgamal", True, False, True),
        PkAlgorithm(17, "DSA", True, True, False),
        PkAlgorithm(18, "ECDH", False, False, True),
        PkAlgorithm(19, "ECDSA", False, True, False),
        PkAlgorithm(22, "EdDSALegacy", True, True, False),
        PkAlgorithm(25, "X25519", False, False, True),
        PkAlgorithm(26, "X448", False, False, True),
        PkAlgorithm(27, "Ed25519", False, True, False),
        PkAlgorithm(28, "Ed448", False, True, False),
        # RFC 9980 sec. 2.1, Tables 1 and 2, and the IANA additions of sec. 11.
        PkAlgorithm(30, "ML-DSA-65+Ed25519", False, True, False),
        PkAlgorithm(31, "ML-DSA-87+Ed448", False, True, False),
        PkAlgorithm(32, "SLH-DSA-SHAKE-128s", False, True, False),
        PkAlgorithm(33, "SLH-DSA-SHAKE-128f", False, True, False),
        PkAlgorithm(34, "SLH-DSA-SHAKE-256s", False, True, False),
        PkAlgorithm(35, "ML-KEM-768+X25519", False, False, True),
        PkAlgorithm(36, "ML-KEM-1024+X448", False, False, True),
    )
}

# RFC 9980 sec. 11 (IANA): public key octets, and for the signature algorithms the signature
# octets, of each post-quantum algorithm. Every field is a fixed-length octet string, concatenated
# in the order the section lists them (sec. 4.3.2.1, 5.3.2.1, 6.2.2.1, 5.3.1, 6.2.1); each pair is
# (traditional component, post-quantum component), with 0 where there is only one.
PQ_PUBLIC_KEY_SIZES: dict[int, tuple[int, int]] = {
    30: (32, 1952),
    31: (57, 2592),
    32: (0, 32),
    33: (0, 32),
    34: (0, 64),
    35: (32, 1184),
    36: (56, 1568),
}
PQ_SIGNATURE_SIZES: dict[int, tuple[int, int]] = {
    30: (64, 3309),
    31: (114, 4627),
    32: (0, 7856),
    33: (0, 17088),
    34: (0, 29792),
}
# RFC 9980 sec. 3.5, 4.3.2, 5.3.2, 6.2.2: the key versions an algorithm may appear in. 35 is also
# allowed in a version 4 encryption-capable subkey and nowhere else below version 6.
PQ_KEY_VERSIONS: dict[int, tuple[int, ...]] = {
    30: (6,),
    31: (6,),
    32: (6,),
    33: (6,),
    34: (6,),
    35: (4, 6),
    36: (6,),
}
# RFC 9980 sec. 5.3.1, 6.2.1, 9.4: a PQ(/T) signature is version 6 and hashes with >= 256 bits.
PQ_MIN_DIGEST_BITS = 256


def pk_name(algorithm: int) -> str:
    known = PK_ALGORITHMS.get(algorithm)
    return known.name if known else f"unknown({algorithm})"


@dataclass(frozen=True, slots=True)
class Curve:
    """RFC 9580 sec. 9.2, Table 19. ``bits`` is the nominal size GnuPG also reports."""

    oid: bytes
    name: str
    bits: int
    fsize: int
    deprecated: bool = False


CURVES: dict[bytes, Curve] = {
    c.oid: c
    for c in (
        Curve(bytes.fromhex("2A8648CE3D030107"), "NIST P-256", 256, 32),
        Curve(bytes.fromhex("2B81040022"), "NIST P-384", 384, 48),
        Curve(bytes.fromhex("2B81040023"), "NIST P-521", 521, 66),
        Curve(bytes.fromhex("2B2403030208010107"), "brainpoolP256r1", 256, 32),
        Curve(bytes.fromhex("2B240303020801010B"), "brainpoolP384r1", 384, 48),
        Curve(bytes.fromhex("2B240303020801010D"), "brainpoolP512r1", 512, 64),
        Curve(bytes.fromhex("2B06010401DA470F01"), "Ed25519Legacy", 255, 32, True),
        Curve(bytes.fromhex("2B060104019755010501"), "Curve25519Legacy", 255, 32, True),
    )
}

# Native-format algorithms (sec. 5.5.5.7 to 5.5.5.10): name, public key octets, nominal bits.
NATIVE_KEY_SIZES: dict[int, tuple[int, int]] = {
    25: (32, 255),
    26: (56, 448),
    27: (32, 255),
    28: (57, 448),
}


@dataclass(frozen=True, slots=True)
class HashInfo:
    """RFC 9580 sec. 9.5, Tables 23 and 24. ``salt`` is the v6 signature salt size, if defined."""

    id: int
    name: str
    text: str
    digest_size: int
    salt: int | None
    hashlib_name: str | None


HASHES: dict[int, HashInfo] = {
    h.id: h
    for h in (
        HashInfo(1, "MD5", "MD5", 16, None, "md5"),
        HashInfo(2, "SHA-1", "SHA1", 20, None, "sha1"),
        HashInfo(3, "RIPEMD-160", "RIPEMD160", 20, None, "ripemd160"),
        HashInfo(8, "SHA2-256", "SHA256", 32, 16, "sha256"),
        HashInfo(9, "SHA2-384", "SHA384", 48, 24, "sha384"),
        HashInfo(10, "SHA2-512", "SHA512", 64, 32, "sha512"),
        HashInfo(11, "SHA2-224", "SHA224", 28, 16, "sha224"),
        HashInfo(12, "SHA3-256", "SHA3-256", 32, 16, "sha3_256"),
        HashInfo(14, "SHA3-512", "SHA3-512", 64, 32, "sha3_512"),
    )
}


def hash_name(algorithm: int) -> str:
    known = HASHES.get(algorithm)
    return known.name if known else f"unknown({algorithm})"


# RFC 9580 sec. 5.2.1, Table 4.
SIGNATURE_TYPES: dict[int, str] = {
    0x00: "binary",
    0x01: "text",
    0x02: "standalone",
    0x10: "generic certification",
    0x11: "persona certification",
    0x12: "casual certification",
    0x13: "positive certification",
    0x18: "subkey binding",
    0x19: "primary key binding",
    0x1F: "direct key",
    0x20: "key revocation",
    0x28: "subkey revocation",
    0x30: "certification revocation",
    0x40: "timestamp",
    0x50: "third-party confirmation",
    0xFF: "reserved",
}


def signature_type_name(sig_type: int) -> str:
    return SIGNATURE_TYPES.get(sig_type, f"unknown({sig_type:#04x})")


# RFC 9580 sec. 5.2.3.7, Table 5.
SUBPACKET_NAMES: dict[int, str] = {
    2: "signature creation time",
    3: "signature expiration time",
    4: "exportable certification",
    5: "trust signature",
    6: "regular expression",
    7: "revocable",
    9: "key expiration time",
    11: "preferred symmetric ciphers (v1 SEIPD)",
    12: "revocation key (deprecated)",
    16: "issuer key id",
    20: "notation data",
    21: "preferred hash algorithms",
    22: "preferred compression algorithms",
    23: "key server preferences",
    24: "preferred key server",
    25: "primary user id",
    26: "policy uri",
    27: "key flags",
    28: "signer's user id",
    29: "reason for revocation",
    30: "features",
    31: "signature target",
    32: "embedded signature",
    33: "issuer fingerprint",
    35: "intended recipient fingerprint",
    39: "preferred aead ciphersuites",
}

# RFC 9580 sec. 5.2.3.29, Table 9: first octet bit, then (octet index, mask) for later octets.
KEY_FLAG_BITS: tuple[tuple[int, int, str], ...] = (
    (0, 0x01, "certify"),
    (0, 0x02, "sign"),
    (0, 0x04, "encrypt_communications"),
    (0, 0x08, "encrypt_storage"),
    (0, 0x10, "split"),
    (0, 0x20, "authenticate"),
    (0, 0x80, "shared"),
    (1, 0x04, "adsk_reserved"),
    (1, 0x08, "timestamping_reserved"),
)


def key_flag_names(flags: bytes) -> list[str]:
    """Names of the flags set in ``flags``; a list shorter than expected reads as zeros (sec. 5.2.3.29)."""
    return [
        name for octet, mask, name in KEY_FLAG_BITS if octet < len(flags) and flags[octet] & mask
    ]


# RFC 9580 sec. 5.2.3.31, Table 10.
REVOCATION_REASONS: dict[int, str] = {
    0: "no reason specified",
    1: "key is superseded",
    2: "key material has been compromised",
    3: "key is retired and no longer used",
    32: "user id information is no longer valid",
}

# RFC 9580 sec. 9.3, 9.4, 9.6.
SYMMETRIC_NAMES: dict[int, str] = {
    0: "plaintext",
    1: "IDEA",
    2: "TripleDES",
    3: "CAST5",
    4: "Blowfish",
    7: "AES-128",
    8: "AES-192",
    9: "AES-256",
    10: "Twofish",
    11: "Camellia-128",
    12: "Camellia-192",
    13: "Camellia-256",
}
COMPRESSION_NAMES: dict[int, str] = {0: "uncompressed", 1: "ZIP", 2: "ZLIB", 3: "BZip2"}
AEAD_NAMES: dict[int, str] = {1: "EAX", 2: "OCB", 3: "GCM"}

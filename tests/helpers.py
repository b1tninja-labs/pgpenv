"""Independent builders for synthesised packets: they do not use pgpenv's own encoders."""

from __future__ import annotations

import hashlib
import pathlib

DATA = pathlib.Path(__file__).resolve().parent / "data" / "gnupg"


def fixture(name: str) -> bytes:
    return (DATA / name).read_bytes()


def new_header(tag: int, length: int) -> bytes:
    if length < 192:
        return bytes((0xC0 | tag, length))
    if length < 8384:
        v = length - 192
        return bytes((0xC0 | tag, 192 + (v >> 8), v & 255))
    return bytes((0xC0 | tag, 255)) + length.to_bytes(4, "big")


def pkt(tag: int, body: bytes) -> bytes:
    return new_header(tag, len(body)) + body


def legacy_pkt(tag: int, body: bytes, length_type: int = 1) -> bytes:
    first = 0x80 | (tag << 2) | length_type
    if length_type == 0:
        return bytes((first, len(body))) + body
    if length_type == 1:
        return bytes((first,)) + len(body).to_bytes(2, "big") + body
    if length_type == 2:
        return bytes((first,)) + len(body).to_bytes(4, "big") + body
    return bytes((first,)) + body


def mpi(value: int) -> bytes:
    size = (value.bit_length() + 7) // 8
    return value.bit_length().to_bytes(2, "big") + value.to_bytes(size, "big")


def rsa_key_body(version: int, n: int, e: int = 65537, created: int = 1_700_000_000) -> bytes:
    if version == 3:
        return b"\x03" + created.to_bytes(4, "big") + b"\x00\x00" + b"\x01" + mpi(n) + mpi(e)
    material = mpi(n) + mpi(e)
    if version == 4:
        return b"\x04" + created.to_bytes(4, "big") + b"\x01" + material
    return (
        b"\x06" + created.to_bytes(4, "big") + b"\x01" + len(material).to_bytes(4, "big") + material
    )


def ed25519_v4_body(public: bytes = bytes(range(32)), created: int = 1_700_000_000) -> bytes:
    return b"\x04" + created.to_bytes(4, "big") + b"\x1b" + public


def subpacket(kind: int, data: bytes, *, critical: bool = False) -> bytes:
    length = len(data) + 1
    if length < 192:
        head = bytes((length,))
    elif length < 16320:
        v = length - 192
        head = bytes((192 + (v >> 8), v & 255))
    else:
        head = b"\xff" + length.to_bytes(4, "big")
    return head + bytes((kind | (0x80 if critical else 0),)) + data


def sig_v4_body(
    hashed: bytes,
    unhashed: bytes = b"",
    *,
    sig_type: int = 0x13,
    pub_algo: int = 27,
    hash_algo: int = 8,
    material: bytes = bytes(64),
) -> bytes:
    return (
        bytes((4, sig_type, pub_algo, hash_algo))
        + len(hashed).to_bytes(2, "big")
        + hashed
        + len(unhashed).to_bytes(2, "big")
        + unhashed
        + b"\x00\x00"
        + material
    )


def v4_fingerprint(body: bytes) -> str:
    return hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).hexdigest().upper()  # noqa: S324

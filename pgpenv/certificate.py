"""Transferable public keys and keyrings: packet sequences grouped into certificates (RFC 9580 sec. 10.1).

A certificate is a primary key packet followed by its signatures, user IDs and user attributes
with their certifications, and subkeys with their binding signatures. A keyring is any number of
them concatenated (sec. 10.1.5), in one binary file or several armor blocks.

:func:`parse_keyring` groups packets by that grammar without verifying anything. What it
enforces is what sec. 4.3 and sec. 10 say a consumer MUST do: a critical packet that does not
belong in a certificate rejects *that certificate* (it is reported in ``Keyring.rejected`` and the
walk resumes at the next primary key, because the packet framing is still trustworthy), an unknown
non-critical packet is ignored, and a malformed signature is skipped and noted (sec. 5.2.5)
instead of stopping the walk. A packet whose own length is wrong ends the stream: after a bad
length there is no trustworthy next offset (sec. 4.1), so everything before it is kept and the
rest is one rejection.

The grammar is applied leniently in two places, both documented here because they are
choices: Padding packets (21) are ignored wherever they appear, not only at the end, and a
signature of an unexpected type at a position (for instance a binding signature after a User ID)
is kept and noted in ``problems`` rather than dropped.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .armor import ArmorBlock, decode_blocks
from .errors import ArmorError, KeyPacketError, LimitError, PacketError, PgpError, SignatureError
from .key import PublicKey, parse_public_key
from .limits import DEFAULT_LIMITS, Limits
from .packet import Packet, iter_packets
from .signature import Signature, parse_signature

__all__ = [
    "Certificate",
    "Keyring",
    "Rejection",
    "SubkeyEntry",
    "UserId",
    "parse_keyring",
]

_PRIMARY_TAGS = (5, 6)
_SUBKEY_TAGS = (7, 14)
_IGNORED_TAGS = (10, 12, 21)  # marker, trust (sec. 5.10), padding
_SELF_CERT_TYPES = (0x10, 0x11, 0x12, 0x13)


@dataclass(slots=True)
class UserId:
    """A User ID (tag 13) or User Attribute (tag 17) packet and the signatures that follow it."""

    kind: str
    body: bytes
    offset: int
    signatures: list[Signature] = field(default_factory=list)

    @property
    def text(self) -> str | None:
        """The User ID as text (UTF-8, sec. 5.11); None for a User Attribute packet."""
        return self.body.decode("utf-8", "replace") if self.kind == "id" else None


@dataclass(slots=True)
class SubkeyEntry:
    """A subkey packet and the signatures that follow it (binding 0x18, revocation 0x28)."""

    key: PublicKey
    offset: int
    signatures: list[Signature] = field(default_factory=list)


@dataclass(slots=True)
class Certificate:
    """One transferable public key, as claimed by the file."""

    primary: PublicKey
    offset: int
    signatures: list[Signature] = field(default_factory=list)
    user_ids: list[UserId] = field(default_factory=list)
    subkeys: list[SubkeyEntry] = field(default_factory=list)
    ignored: list[tuple[int, int]] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    end: int = 0


@dataclass(frozen=True, slots=True)
class Rejection:
    """Something that was refused, with where and why."""

    offset: int
    reason: str
    block: int | None = None


@dataclass(slots=True)
class Keyring:
    """Everything found in one file: certificates, loose signatures, refusals, armor blocks."""

    certificates: list[Certificate] = field(default_factory=list)
    signatures: list[Signature] = field(default_factory=list)
    rejected: list[Rejection] = field(default_factory=list)
    blocks: list[ArmorBlock] = field(default_factory=list)
    other_packets: list[tuple[int, int]] = field(default_factory=list)
    packet_counts: dict[int, int] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)


def parse_keyring(raw: bytes | str, limits: Limits = DEFAULT_LIMITS) -> Keyring:
    """Parse a binary or armored keyring into certificates; nothing is verified (sec. 10.1)."""
    ring = Keyring()
    data = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
    if data and data[0] & 0x80:
        _walk(data, ring, limits, None)
        return ring
    try:
        blocks = decode_blocks(data, limits)
    except ArmorError as error:
        raise PgpError(f"neither a binary OpenPGP stream nor ASCII armor: {error}") from None
    if not blocks and data.strip():
        raise PgpError(
            "neither a binary OpenPGP stream nor ASCII armor: no armor header line found"
        )
    ring.blocks.extend(blocks)
    for number, block in enumerate(blocks):
        _walk(block.data, ring, limits, number)
    return ring


def _walk(data: bytes, ring: Keyring, limits: Limits, block: int | None) -> None:
    current: Certificate | None = None
    ctx: UserId | SubkeyEntry | None = None
    skipping = False
    last_end = 0
    iterator = iter_packets(data, limits)

    def finish() -> None:
        nonlocal current, ctx
        if current is not None:
            _check_structure(current)
            ring.certificates.append(current)
        current = None
        ctx = None

    def reject(offset: int, reason: str) -> None:
        nonlocal current, ctx, skipping
        ring.rejected.append(Rejection(offset, reason, block))
        current = None
        ctx = None
        skipping = True

    while True:
        try:
            packet = next(iterator)
        except StopIteration:
            break
        except LimitError:
            raise
        except PacketError as error:
            finish()
            ring.rejected.append(Rejection(last_end, str(error), block))
            return
        last_end = packet.end
        ring.packet_counts[packet.tag] = ring.packet_counts.get(packet.tag, 0) + 1
        if packet.tag in _PRIMARY_TAGS:
            finish()
            skipping = False
            if len(ring.certificates) >= limits.max_keys:
                raise LimitError(f"more than {limits.max_keys} keys")
            try:
                key = parse_public_key(packet.body, secret=packet.tag == 5, limits=limits)
            except KeyPacketError as error:
                reject(packet.offset, f"primary key packet: {error}")
                continue
            current = Certificate(key, packet.offset)
            current.end = packet.end
            continue
        if skipping:
            continue
        current, ctx = _place(packet, current, ctx, ring, limits, reject)
        if current is not None:
            current.end = packet.end
    finish()


def _place(
    packet: Packet,
    current: Certificate | None,
    ctx: UserId | SubkeyEntry | None,
    ring: Keyring,
    limits: Limits,
    reject: Callable[[int, str], None],
) -> tuple[Certificate | None, UserId | SubkeyEntry | None]:
    tag = packet.tag
    if tag == 2:
        try:
            sig = parse_signature(packet.body, limits)
        except (SignatureError, LimitError) as error:
            note = f"signature at offset {packet.offset} skipped: {error}"
            (current.problems if current is not None else ring.problems).append(note)
            return current, ctx
        if current is None:
            ring.signatures.append(sig)
            return current, ctx
        _attach(current, ctx, sig, limits, packet.offset)
        return current, ctx
    if current is None:
        # outside a certificate: a literal, a message packet, a stray user id
        if tag in _SUBKEY_TAGS or tag in (13, 17):
            reject(packet.offset, f"{packet.name} packet with no primary key before it")
        elif tag not in _IGNORED_TAGS:
            ring.other_packets.append((tag, packet.offset))
        return None, None
    if tag in _SUBKEY_TAGS:
        try:
            key = parse_public_key(packet.body, subkey=True, secret=tag == 7, limits=limits)
        except KeyPacketError as error:
            reject(current.offset, f"subkey packet at offset {packet.offset}: {error}")
            return None, None
        if key.version != current.primary.version:
            current.problems.append(
                f"version {key.version} subkey on a version {current.primary.version} "
                "primary key (sec. 10.1)"
            )
        entry = SubkeyEntry(key, packet.offset)
        current.subkeys.append(entry)
        return current, entry
    if tag in (13, 17):
        if len(current.user_ids) >= limits.max_user_ids:
            raise LimitError(f"more than {limits.max_user_ids} user ids on one key")
        uid = UserId("id" if tag == 13 else "attribute", packet.body, packet.offset)
        current.user_ids.append(uid)
        return current, uid
    if tag in _IGNORED_TAGS or not packet.critical:
        current.ignored.append((tag, packet.offset))
        return current, ctx
    reject(
        current.offset,
        f"critical packet {packet.name} (tag {tag}) at offset {packet.offset} does not belong in "
        "a transferable public key (RFC 9580 sec. 4.3, 10)",
    )
    return None, None


def _attach(
    cert: Certificate,
    ctx: UserId | SubkeyEntry | None,
    sig: Signature,
    limits: Limits,
    offset: int,
) -> None:
    total = (
        len(cert.signatures)
        + sum(len(u.signatures) for u in cert.user_ids)
        + sum(len(s.signatures) for s in cert.subkeys)
    )
    if total >= limits.max_signatures_per_key:
        raise LimitError(f"more than {limits.max_signatures_per_key} signatures on one key")
    t = sig.sig_type
    if ctx is None:
        cert.signatures.append(sig)
        if t not in (0x1F, 0x20):
            cert.problems.append(
                f"signature type {t:#04x} at offset {offset} directly on the primary key"
            )
    elif isinstance(ctx, UserId):
        ctx.signatures.append(sig)
        if t not in (*_SELF_CERT_TYPES, 0x30):
            cert.problems.append(f"signature type {t:#04x} at offset {offset} on a user id")
    else:
        ctx.signatures.append(sig)
        if t not in (0x18, 0x28):
            cert.problems.append(f"signature type {t:#04x} at offset {offset} on a subkey")


def _check_structure(cert: Certificate) -> None:
    primary = cert.primary
    types = {s.sig_type for s in cert.signatures}
    if primary.version == 6 and not types & {0x1F, 0x20}:
        cert.problems.append(
            "a version 6 key with no Direct Key signature (sec. 5.2.3.10: required before use)"
        )
    for entry in cert.subkeys:
        if not any(s.sig_type == 0x18 for s in entry.signatures):
            cert.problems.append(
                f"subkey {entry.key.fingerprint_hex} has no Subkey Binding signature (sec. 10.1.5)"
            )

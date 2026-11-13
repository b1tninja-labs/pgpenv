"""packet framing, tags, old and new format headers (RFC 9580).

A packet is a header (tag and length) followed by a body. ``iter_packets`` reads both header
formats, reassembles partial body lengths, and yields every packet it finds, including ones with
a tag this package has never heard of: an unknown tag is preserved as a ``Packet`` with its raw
body, because RFC 9580 sec. 4.3 says an unknown non-critical packet is ignored and an unknown
critical one rejects the sequence, and that decision belongs to the layer that knows the grammar,
not to the framing layer.

Framing is strict where the document is strict. The length in a header is the canonical source of
packet boundaries (sec. 4.1); a length that runs past the end of the input is a
:class:`TruncatedError`, never a short read. Nothing here imports outside the standard library.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import IO, TYPE_CHECKING

from .errors import LimitError, PacketError, TruncatedError
from .limits import DEFAULT_LIMITS, Limits

if TYPE_CHECKING:
    from collections.abc import Iterator

__all__ = [
    "DATA_TAGS",
    "TAGS",
    "Packet",
    "TagInfo",
    "decode_length",
    "encode_length",
    "encode_packet",
    "iter_packets",
    "parse_packets",
    "tag_info",
]


@dataclass(frozen=True, slots=True)
class TagInfo:
    """One row of the packet type registry (RFC 9580 sec. 5, Table 3)."""

    tag: int
    shorthand: str
    name: str
    critical: bool = True


# RFC 9580 sec. 5, Table 3. Tags 0, 19 and 20 are reserved; 22-39 are unassigned critical packets;
# 40-59 unassigned non-critical; 60-63 private or experimental use (sec. 4.3: 0-39 critical).
TAGS: dict[int, TagInfo] = {
    t.tag: t
    for t in (
        TagInfo(0, "RESERVED", "Reserved - this Packet Type ID MUST NOT be used"),
        TagInfo(1, "PKESK", "Public Key Encrypted Session Key Packet"),
        TagInfo(2, "SIG", "Signature Packet"),
        TagInfo(3, "SKESK", "Symmetric Key Encrypted Session Key Packet"),
        TagInfo(4, "OPS", "One-Pass Signature Packet"),
        TagInfo(5, "SECKEY", "Secret Key Packet"),
        TagInfo(6, "PUBKEY", "Public Key Packet"),
        TagInfo(7, "SECSUBKEY", "Secret Subkey Packet"),
        TagInfo(8, "COMP", "Compressed Data Packet"),
        TagInfo(9, "SED", "Symmetrically Encrypted Data Packet"),
        TagInfo(10, "MARKER", "Marker Packet"),
        TagInfo(11, "LIT", "Literal Data Packet"),
        TagInfo(12, "TRUST", "Trust Packet"),
        TagInfo(13, "UID", "User ID Packet"),
        TagInfo(14, "PUBSUBKEY", "Public Subkey Packet"),
        TagInfo(17, "UAT", "User Attribute Packet"),
        TagInfo(18, "SEIPD", "Symmetrically Encrypted and Integrity Protected Data Packet"),
        TagInfo(19, "RESERVED", "Reserved (formerly Modification Detection Code Packet)"),
        TagInfo(20, "RESERVED", "Reserved"),
        TagInfo(21, "PADDING", "Padding Packet"),
    )
}

# sec. 4.2.1.4: Partial Body Lengths are allowed only for literal, compressed and encrypted data.
DATA_TAGS = frozenset({8, 9, 11, 18})


def tag_info(tag: int) -> TagInfo:
    """The registry row for ``tag``; unassigned and private ranges get a synthesised row."""
    if tag in TAGS:
        return TAGS[tag]
    if not 0 <= tag <= 63:
        raise ValueError(f"packet tag {tag} is outside 0..63")
    if tag <= 39:
        return TagInfo(tag, "UNASSIGNED", "Unassigned Critical Packet", True)
    if tag <= 59:
        return TagInfo(tag, "UNASSIGNED", "Unassigned Non-Critical Packet", False)
    return TagInfo(tag, "PRIVATE", "Private or Experimental Use", False)


@dataclass(frozen=True, slots=True)
class Packet:
    """One framed packet: its tag, its reassembled body, and where it came from.

    ``offset`` and ``end`` are positions in the input (the first header octet and one past the
    last body octet), so a caller can slice the original bytes back out. ``legacy`` marks an
    old-format header (sec. 4.2.2), ``partial`` a body assembled from partial body lengths, and
    ``indeterminate`` a legacy packet that ran to the end of the input.
    """

    tag: int
    body: bytes
    offset: int = 0
    end: int = 0
    legacy: bool = False
    partial: bool = False
    indeterminate: bool = False

    @property
    def info(self) -> TagInfo:
        return tag_info(self.tag)

    @property
    def name(self) -> str:
        return self.info.shorthand

    @property
    def critical(self) -> bool:
        return self.tag <= 39

    @property
    def known(self) -> bool:
        """True when RFC 9580 assigns this tag a meaning (reserved tags are not known)."""
        info = TAGS.get(self.tag)
        return info is not None and info.shorthand != "RESERVED"


def decode_length(data: bytes, pos: int, *, what: str = "length") -> tuple[int, int]:
    """Decode a subpacket length (1, 2 or 5 octets) at ``pos``; return ``(length, next_pos)``.

    This is the length of a signature or user attribute subpacket (RFC 9580 sec. 5.2.3.7): the
    first octet below 192 is the length, 192 to 254 starts a two-octet length
    ``((o1 - 192) << 8) + o2 + 192``, and 255 starts a four-octet length. Unlike a packet header
    (sec. 4.2.1) there are no partial lengths here, so 224 to 254 is an ordinary two-octet form.
    """
    if pos >= len(data):
        raise TruncatedError(f"{what}: no length octet at offset {pos}")
    first = data[pos]
    if first < 192:
        return first, pos + 1
    if first < 255:
        if pos + 2 > len(data):
            raise TruncatedError(f"{what}: two-octet length cut off at offset {pos}")
        return ((first - 192) << 8) + data[pos + 1] + 192, pos + 2
    if pos + 5 > len(data):
        raise TruncatedError(f"{what}: five-octet length cut off at offset {pos}")
    return int.from_bytes(data[pos + 1 : pos + 5], "big"), pos + 5


def encode_length(length: int) -> bytes:
    """Encode a definite body or subpacket length as 1, 2 or 5 octets (RFC 9580 sec. 4.2.1)."""
    if length < 0 or length > 0xFFFFFFFF:
        raise ValueError(f"length {length} cannot be encoded in four octets")
    if length < 192:
        return bytes((length,))
    if length < 8384:
        value = length - 192
        return bytes((192 + (value >> 8), value & 0xFF))
    return b"\xff" + length.to_bytes(4, "big")


def encode_packet(packet: Packet) -> bytes:
    """Serialise ``packet`` in the current OpenPGP format, RFC 9580 sec. 4.2.

    The header is always the new format with a definite length, so a packet read from legacy or
    partial-length framing is transformed to the form sec. 4.2.1 recommends rather than
    reproduced byte for byte.
    """
    if not 0 <= packet.tag <= 63:
        raise ValueError(f"packet tag {packet.tag} is outside 0..63")
    return bytes((0xC0 | packet.tag,)) + encode_length(len(packet.body)) + packet.body


def _as_bytes(raw: bytes | bytearray | memoryview | IO[bytes], limits: Limits) -> bytes:
    if isinstance(raw, bytes):
        data = raw
    elif isinstance(raw, bytearray | memoryview):
        data = bytes(raw)
    else:
        data = raw.read(limits.max_input_bytes + 1)
    if len(data) > limits.max_input_bytes:
        raise LimitError(f"input of {len(data)} bytes exceeds the limit {limits.max_input_bytes}")
    return data


def iter_packets(
    raw: bytes | bytearray | memoryview | IO[bytes], limits: Limits = DEFAULT_LIMITS
) -> Iterator[Packet]:
    """Yield every packet in ``raw``, framed per RFC 9580 sec. 4.

    ``raw`` is a bytes-like object or a binary file; a file is read at most
    ``limits.max_input_bytes`` plus one byte. Both header formats are accepted (sec. 4.2),
    partial body lengths are reassembled (sec. 4.2.1.4) and unknown tags are yielded untouched.
    Packets are yielded as they are framed, so a caller sees everything before a malformed
    packet; the malformed one raises :class:`PacketError` (or :class:`TruncatedError`, or
    :class:`LimitError`) and the stream ends, because after a bad length there is no
    trustworthy next offset (sec. 4.1).
    """
    data = _as_bytes(raw, limits)
    n = len(data)
    pos = 0
    count = 0
    while pos < n:
        start = pos
        first = data[pos]
        pos += 1
        if not first & 0x80:
            raise PacketError(f"offset {start}: bit 7 of the packet header octet is clear")
        count += 1
        if count > limits.max_packets:
            raise LimitError(f"more than {limits.max_packets} packets")
        if first & 0x40:
            tag = first & 0x3F
            parts: list[bytes] = []
            total = 0
            chunks = 0
            while True:
                if pos >= n:
                    raise TruncatedError(f"offset {start}: packet header ends before its length")
                octet = data[pos]
                pos += 1
                final = True
                if octet < 192:
                    length = octet
                elif octet < 224:
                    if pos >= n:
                        raise TruncatedError(f"offset {start}: two-octet length cut off")
                    length = ((octet - 192) << 8) + data[pos] + 192
                    pos += 1
                elif octet == 255:
                    if pos + 4 > n:
                        raise TruncatedError(f"offset {start}: five-octet length cut off")
                    length = int.from_bytes(data[pos : pos + 4], "big")
                    pos += 4
                else:
                    final = False
                    length = 1 << (octet & 0x1F)
                    if tag not in DATA_TAGS:
                        raise PacketError(
                            f"offset {start}: partial body length on tag {tag}, which is not a "
                            "literal, compressed or encrypted data packet"
                        )
                    if chunks == 0 and length < 512:
                        raise PacketError(
                            f"offset {start}: the first partial body length is {length}, "
                            "below the 512 octet minimum"
                        )
                total += length
                if total > limits.max_packet_bytes:
                    raise LimitError(
                        f"offset {start}: packet body of {total}+ bytes exceeds the limit "
                        f"{limits.max_packet_bytes}"
                    )
                if pos + length > n:
                    raise TruncatedError(
                        f"offset {start}: packet claims {length} more octets, {n - pos} remain"
                    )
                parts.append(data[pos : pos + length])
                pos += length
                if final:
                    break
                chunks += 1
                if chunks > limits.max_partial_chunks:
                    raise LimitError(
                        f"offset {start}: more than {limits.max_partial_chunks} chunks"
                    )
            body = parts[0] if len(parts) == 1 else b"".join(parts)
            yield Packet(tag, body, start, pos, False, chunks > 0, False)
            continue
        tag = (first >> 2) & 0x0F
        length_type = first & 0x03
        indeterminate = length_type == 3
        if indeterminate:
            length = n - pos
        else:
            size = (1, 2, 4)[length_type]
            if pos + size > n:
                raise TruncatedError(f"offset {start}: legacy length cut off")
            length = int.from_bytes(data[pos : pos + size], "big")
            pos += size
        if length > limits.max_packet_bytes:
            raise LimitError(
                f"offset {start}: packet body of {length} bytes exceeds the limit "
                f"{limits.max_packet_bytes}"
            )
        if pos + length > n:
            raise TruncatedError(f"offset {start}: packet claims {length} octets, {n - pos} remain")
        yield Packet(tag, data[pos : pos + length], start, pos + length, True, False, indeterminate)
        pos += length


def parse_packets(
    raw: bytes | bytearray | memoryview | IO[bytes], limits: Limits = DEFAULT_LIMITS
) -> list[Packet]:
    """Every packet in ``raw`` as a list; raises on the first malformed one (see ``iter_packets``)."""
    return list(iter_packets(raw, limits))

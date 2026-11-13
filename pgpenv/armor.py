"""radix64 with CRC-24 headers and trailers (RFC 9580).

ASCII armor wraps binary OpenPGP data in an Armor Header Line, optional ``Key: value`` headers, a
blank line, base64 text and an Armor Tail Line (RFC 9580 sec. 6.2).

The checksum is advisory. RFC 9580 sec. 6.1 says an implementation MUST NOT reject an OpenPGP
object when the CRC24 footer is present, missing, malformed, or disagrees with the computed sum,
and that a producer SHOULD NOT generate it. So :func:`decode_blocks` reports the outcome in
``ArmorBlock.crc`` (``absent``, ``ok``, ``mismatch`` or ``malformed``) and returns the data
either way; a caller that wants to warn can, and one that does not is still correct. Everything
else is strict: a character outside the base64 alphabet, a wrong tail line or a block with no tail
is an :class:`ArmorError`, because the data after such damage cannot be trusted to be the data
that was armored.

The cleartext signature framework (sec. 7) lives in :mod:`pgpenv.cleartext`.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

from .errors import ArmorError, LimitError
from .limits import DEFAULT_LIMITS, Limits

__all__ = [
    "ARMOR_LABELS",
    "ArmorBlock",
    "crc24",
    "decode",
    "decode_blocks",
    "encode",
    "looks_armored",
]

# RFC 9580 sec. 6.2.1, Table 16 (plus the cleartext header of sec. 7, which has no data block).
ARMOR_LABELS = (
    "PGP MESSAGE",
    "PGP PUBLIC KEY BLOCK",
    "PGP PRIVATE KEY BLOCK",
    "PGP SIGNATURE",
)

_CRC24_INIT = 0xB704CE
_CRC24_GENERATOR = 0x864CFB
_BEGIN = re.compile(r"^-----BEGIN (PGP [A-Z ]+)-----$")
_B64_LINE = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
_B64_CHARS = re.compile(r"^[A-Za-z0-9+/]+$")
_LINES = re.compile(r"\r\n|\n|\r")


def crc24(data: bytes) -> int:
    """The OpenPGP CRC-24 of ``data`` (RFC 9580 sec. 6.1.1: init 0xB704CE, generator 0x864CFB)."""
    crc = _CRC24_INIT
    for octet in data:
        crc ^= octet << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc &= 0xFFFFFF
                crc ^= _CRC24_GENERATOR
    return crc & 0xFFFFFF


@dataclass(frozen=True, slots=True)
class ArmorBlock:
    """One decoded armor block.

    ``label`` is the text between ``BEGIN`` and the closing dashes (``PGP PUBLIC KEY BLOCK``).
    ``headers`` are the well-formed ``Key: value`` pairs in order; they are *not* covered by any
    signature (sec. 6.2.2). ``crc`` is the checksum outcome; ``notes`` records recoveries.
    """

    label: str
    headers: tuple[tuple[str, str], ...]
    data: bytes
    crc: str = "absent"
    notes: tuple[str, ...] = field(default_factory=tuple)
    line: int = 1


def looks_armored(data: bytes | str) -> bool:
    """True when ``data`` contains an armor header line (cheap check before choosing a decoder)."""
    text = data if isinstance(data, str) else data.decode("utf-8", "replace")
    return any(_BEGIN.match(line.rstrip(" \t")) for line in _LINES.split(text))


def decode_blocks(text: str | bytes, limits: Limits = DEFAULT_LIMITS) -> list[ArmorBlock]:
    """Every armor block in ``text``, in order; text outside blocks is ignored (RFC 9580 sec. 6.2).

    A ``-----BEGIN PGP SIGNED MESSAGE-----`` cleartext header is skipped, and its signature block
    is returned like any other. Raises :class:`ArmorError` for damage inside a block and
    :class:`LimitError` for oversize input; never for a checksum problem (sec. 6.1).
    """
    if isinstance(text, bytes | bytearray | memoryview):
        raw = bytes(text)
        if len(raw) > limits.max_input_bytes:
            raise LimitError(
                f"input of {len(raw)} bytes exceeds the limit {limits.max_input_bytes}"
            )
        text = raw.decode("utf-8", "replace")
    elif len(text) > limits.max_input_bytes:
        raise LimitError(f"input of {len(text)} characters exceeds the limit")
    lines = _LINES.split(text)
    blocks: list[ArmorBlock] = []
    index = 0
    while index < len(lines):
        match = _BEGIN.match(lines[index].rstrip(" \t"))
        if match is None or match.group(1) == "PGP SIGNED MESSAGE":
            index += 1
            continue
        if len(blocks) >= limits.max_armor_blocks:
            raise LimitError(f"more than {limits.max_armor_blocks} armor blocks")
        block, index = _read_block(lines, index, match.group(1), limits)
        blocks.append(block)
    return blocks


def _read_block(lines: list[str], begin: int, label: str, limits: Limits) -> tuple[ArmorBlock, int]:
    where = f"line {begin + 1} ({label})"
    index = begin + 1
    headers: list[tuple[str, str]] = []
    notes: list[str] = []
    # Armor headers up to the blank line (sec. 6.2.2: a key, a colon and a space, then the value).
    while True:
        if index >= len(lines):
            raise ArmorError(f"{where}: block ends before its blank line")
        line = lines[index]
        if len(line) > limits.max_armor_line_bytes:
            raise LimitError(f"{where}: armor line of {len(line)} characters")
        if line.strip(" \t") == "":
            index += 1
            break
        stripped = line.rstrip(" \t")
        if ": " in stripped:
            key, _, value = stripped.partition(": ")
            headers.append((key, value))
            index += 1
            continue
        if _B64_LINE.match(stripped) or stripped.startswith("-----END "):
            # sec. 6.2.2 asks an implementation to recover from a damaged header region.
            notes.append("no blank line between the armor headers and the data")
            break
        raise ArmorError(f"line {index + 1}: {stripped[:40]!r} is not an armor header")
    body: list[str] = []
    checksum: str | None = None
    tail = f"-----END {label}-----"
    while True:
        if index >= len(lines):
            raise ArmorError(f"{where}: no armor tail line (truncated?)")
        line = lines[index]
        if len(line) > limits.max_armor_line_bytes:
            raise LimitError(f"{where}: armor line of {len(line)} characters")
        stripped = line.strip(" \t")
        index += 1
        if stripped.startswith("-----END "):
            if stripped != tail:
                raise ArmorError(f"line {index}: expected {tail!r}, found {stripped[:40]!r}")
            break
        if checksum is not None:
            if stripped:
                raise ArmorError(f"line {index}: data after the checksum line")
            continue
        if stripped.startswith("=") and len(stripped) >= 3:
            checksum = stripped
            continue
        if not _B64_LINE.match("".join(stripped.split())):
            raise ArmorError(f"line {index}: a character outside the base64 alphabet")
        body.append("".join(stripped.split()))
    joined = "".join(body)
    try:
        data = base64.b64decode(joined, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ArmorError(f"{where}: base64 decoding failed ({error})") from None
    status = "absent"
    if checksum is not None:
        status = "malformed"
        digits = checksum[1:]
        if len(digits) == 4 and _B64_CHARS.match(digits):
            expected = int.from_bytes(base64.b64decode(digits), "big")
            status = "ok" if expected == crc24(data) else "mismatch"
    return ArmorBlock(label, tuple(headers), data, status, tuple(notes), begin + 1), index


def decode(text: str | bytes) -> bytes:
    """The data of the single armor block in ``text``, RFC 9580 sec. 6.2.

    Raises :class:`ArmorError` when ``text`` holds no block or more than one (use
    :func:`decode_blocks` for a file of several). A checksum problem does not raise (sec. 6.1).
    """
    blocks = decode_blocks(text)
    if len(blocks) != 1:
        raise ArmorError(f"expected exactly one armor block, found {len(blocks)}")
    return blocks[0].data


def _label_for(packets: bytes) -> str:
    if not packets:
        raise ArmorError("cannot infer the armor label of empty data; pass kind=")
    first = packets[0]
    tag = first & 0x3F if first & 0x40 else (first >> 2) & 0x0F
    return {6: "PGP PUBLIC KEY BLOCK", 5: "PGP PRIVATE KEY BLOCK", 2: "PGP SIGNATURE"}.get(
        tag, "PGP MESSAGE"
    )


def encode(
    packets: bytes,
    headers: dict[str, str] | None = None,
    *,
    kind: str | None = None,
    crc: bool = False,
    line_width: int = 76,
) -> str:
    """ASCII-armor ``packets`` per RFC 9580 sec. 6.2, lines of at most ``line_width`` characters.

    ``kind`` is one of :data:`ARMOR_LABELS`; when omitted it is inferred from the first packet
    (public key, private key or signature, else message). The CRC24 footer is left out unless
    ``crc=True``, because sec. 6.1 says it SHOULD NOT be generated and, for v6 keys, v6-only
    signatures and v2 SEIPD messages, MUST NOT be.
    """
    label = kind if kind is not None else _label_for(packets)
    if label not in ARMOR_LABELS:
        raise ArmorError(f"unknown armor label {label!r}")
    if not 4 <= line_width <= 76 or line_width % 4:
        raise ValueError("line_width must be a multiple of 4 between 4 and 76")
    out = [f"-----BEGIN {label}-----"]
    for key, value in (headers or {}).items():
        if not key or ":" in key or any(c in key + value for c in "\r\n"):
            raise ArmorError(f"armor header {key!r} contains a colon or a line break")
        out.append(f"{key}: {value}")
    out.append("")
    encoded = base64.b64encode(packets).decode("ascii")
    out.extend(encoded[i : i + line_width] for i in range(0, len(encoded), line_width))
    if crc:
        out.append("=" + base64.b64encode(crc24(packets).to_bytes(3, "big")).decode("ascii"))
    out.append(f"-----END {label}-----")
    return "\n".join(out) + "\n"

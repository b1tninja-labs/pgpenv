"""radix64 with CRC-24 headers and trailers (RFC 9580).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

__all__ = [
    "decode",
    "encode",
]


def encode(packets: bytes, headers: dict) -> str:
    """Pending behaviour defined by RFC 9580 sec. 6.2.

    Not implemented yet. See the ``armor.encode()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("encode() is not implemented: RFC 9580 sec. 6.2")


def decode(text: str) -> bytes:
    """Pending behaviour defined by RFC 9580 sec. 6.2.

    Not implemented yet. See the ``armor.decode()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("decode() is not implemented: RFC 9580 sec. 6.2")

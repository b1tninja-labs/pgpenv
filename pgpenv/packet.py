"""packet framing, tags, old and new format headers (RFC 9580).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import IO, Any

    Packet = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "encode_packet",
    "iter_packets",
]


def iter_packets(raw: IO) -> Iterator:
    """Pending behaviour defined by RFC 9580 sec. 4.

    Not implemented yet. See the ``packet.iter_packets()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("iter_packets() is not implemented: RFC 9580 sec. 4")


def encode_packet(packet: Packet) -> bytes:
    """Pending behaviour defined by RFC 9580 sec. 4.2.

    Not implemented yet. See the ``packet.encode_packet()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("encode_packet() is not implemented: RFC 9580 sec. 4.2")

"""Small readers for the data elements of RFC 9580 sec. 3: scalars and multiprecision integers."""

from __future__ import annotations

from dataclasses import dataclass

from .errors import PgpError

__all__ = [
    "Mpi",
    "read_mpi",
]


@dataclass(frozen=True, slots=True)
class Mpi:
    """A multiprecision integer as it appeared on the wire (RFC 9580 sec. 3.2).

    ``octets`` are the value octets exactly as read (they may carry leading zeros in sloppy
    input), ``declared_bits`` is the 2-octet bit count, and ``bits`` is the true length of the
    value. ``normalised`` is False when the two disagree, which a v6 packet must reject.
    """

    octets: bytes
    declared_bits: int

    @property
    def value(self) -> int:
        return int.from_bytes(self.octets, "big")

    @property
    def bits(self) -> int:
        return self.value.bit_length()

    @property
    def normalised(self) -> bool:
        return self.declared_bits == self.bits


def read_mpi(
    data: bytes, pos: int, *, strict: bool, error: type[PgpError], what: str
) -> tuple[Mpi, int]:
    """Read one MPI at ``pos``; return it and the next position.

    With ``strict`` the encoded bit count must match the value's real bit length, which RFC 9580
    sec. 3.2 requires when parsing an MPI in a version 6 key, signature or PKESK packet. Without
    it a mismatch is tolerated and visible through :attr:`Mpi.normalised`.
    """
    if pos + 2 > len(data):
        raise error(f"{what}: MPI length field cut off at offset {pos}")
    bits = int.from_bytes(data[pos : pos + 2], "big")
    size = (bits + 7) // 8
    if pos + 2 + size > len(data):
        raise error(f"{what}: MPI of {bits} bits needs {size} octets, {len(data) - pos - 2} remain")
    mpi = Mpi(data[pos + 2 : pos + 2 + size], bits)
    if strict and not mpi.normalised:
        raise error(f"{what}: MPI declares {bits} bits but its value has {mpi.bits}")
    return mpi, pos + 2 + size

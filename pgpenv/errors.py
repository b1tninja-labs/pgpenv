"""The exceptions pgpenv raises, in one place so a caller can catch the family.

Every parse path in this package raises one of these and nothing else: a malformed byte string is
an ordinary input, never a reason to see an IndexError or a struct.error from the standard library.
Each message names the offset or field, because a bare "malformed packet" cannot be debugged from a
keyring of two hundred keys.
"""

from __future__ import annotations

__all__ = [
    "ArmorError",
    "CleartextError",
    "KeyPacketError",
    "LimitError",
    "PacketError",
    "PgpError",
    "SignatureError",
    "TruncatedError",
]


class PgpError(ValueError):
    """Base class: the input is not a well-formed OpenPGP object."""


class PacketError(PgpError):
    """A packet header or framing rule (RFC 9580 sec. 4) was violated."""


class TruncatedError(PacketError):
    """The input ends inside a packet, or inside a partial-length chain."""


class ArmorError(PgpError):
    """ASCII armor (RFC 9580 sec. 6) was malformed."""


class CleartextError(ArmorError):
    """A cleartext signature framework message (RFC 9580 sec. 7) must not be validated."""


class KeyPacketError(PgpError):
    """A key material packet (RFC 9580 sec. 5.5) was malformed."""


class SignatureError(PgpError):
    """A signature packet (RFC 9580 sec. 5.2) was malformed."""


class LimitError(PgpError):
    """A bound from :class:`pgpenv.limits.Limits` was exceeded, so the input was refused."""

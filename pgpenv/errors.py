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
    "MalformedKeyMaterialError",
    "PacketError",
    "PgpError",
    "PolicyRefusalError",
    "SignatureError",
    "TruncatedError",
    "UnsupportedAlgorithmError",
    "VerificationError",
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


class VerificationError(PgpError):
    """The seam to the verifier (:mod:`pgpenv.crypto`) refused to answer; see the subclasses.

    :mod:`pgpenv.verification` turns each into a :class:`~pgpenv.verification.Verification` with a
    status of ``malformed``, ``unsupported`` or ``refused``, so a stream of signatures is never halted
    by one of them (RFC 9580 sec. 5.2.5). It reaches a caller only through :mod:`pgpenv.crypto`.
    """


class MalformedKeyMaterialError(VerificationError):
    """The key, or a digest, cannot be what its packet says (an even modulus, a point off the curve)."""


class UnsupportedAlgorithmError(VerificationError):
    """The algorithm, curve or hash is not implemented here, or not available to this interpreter."""


class PolicyRefusalError(VerificationError):
    """The input is well formed and supported but the policy in force forbids it (RFC 9580 sec. 9.5, 12.4, 12.5)."""

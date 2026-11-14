"""the web of trust: what a Trust Signature claims, and the refusal to turn claims into trust.

RFC 9580 sec. 5.2.3.21 defines the Trust Signature subpacket as an *assertion by the signer*: "the
signer asserts that the key is not only valid but also trustworthy at the specified level". Sec.
5.2.3.22 adds a regular expression that limits whom that assertion extends to. Whether a verifier
believes the assertion depends on trust anchors, on the user's own judgement and on a depth and
amount calculation that the RFC leaves to the implementation. pgpenv does none of that: this is the
``wot.refuse`` row. What it offers is the claim as written, labelled ``claimed``; every function
whose name or answer would be trust raises :class:`~pgpenv.errors.TrustRefusedError` rather than
answer, so a caller cannot read confidence out of a library that never computed any.

``tests/test_policy.py::test_no_function_reports_trust`` enforces that nothing public in the package
returns a trust, trusted or trustworthy verdict, apart from the refusals here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from .errors import TrustRefusedError
from .signature import Signature

__all__ = [
    "TrustClaim",
    "is_trusted",
    "trust_claim",
    "trust_of",
    "valid_path",
]

# RFC 9580 sec. 5.2.3.21: "values less than 120 indicate partial trust and values of 120 or greater
# indicate complete trust".
COMPLETE_TRUST = 120

_WHY = (
    "pgpenv reports what a signature claims, never whether to trust it: a Trust Signature is the "
    "signer's assertion (RFC 9580 sec. 5.2.3.21) and acting on it needs trust anchors and a policy "
    "that are the caller's. Use trust_claim() to read the assertion."
)


@dataclass(frozen=True, slots=True)
class TrustClaim:
    """A Trust Signature subpacket as written. Always a claim: ``label`` says so.

    ``level`` is the depth (0 is an ordinary validity signature, 1 a trusted introducer, 2 a meta
    introducer), ``amount`` the 0 to 255 trust amount, ``strength`` the RFC's reading of the amount
    (``partial`` under 120, ``complete`` from 120), ``scope`` the regular expression of sec.
    5.2.3.22 exactly as the signature carries it (``None`` if absent), never evaluated.

    """

    level: int
    amount: int
    strength: Literal["partial", "complete"]
    scope: str | None
    label: Literal["claimed"] = "claimed"


def trust_claim(sig: Signature) -> TrustClaim | None:
    """The Trust Signature of ``sig`` (hashed area), or None if it carries none."""
    value = sig.value(5)
    if value is None:
        return None
    level, amount = value
    scope = sig.value(6)
    return TrustClaim(level, amount, "complete" if amount >= COMPLETE_TRUST else "partial", scope)


def trust_of(*_args: Any, **_kwargs: Any) -> Any:
    """Refused: no key's trust is computed (RFC 9580 sec. 5.2.3.21 is an assertion, not a result)."""
    raise TrustRefusedError(_WHY)


def is_trusted(*_args: Any, **_kwargs: Any) -> Any:
    """Refused: see :func:`trust_of`."""
    raise TrustRefusedError(_WHY)


def valid_path(*_args: Any, **_kwargs: Any) -> Any:
    """Refused: no certification path is walked and no introducer depth is evaluated."""
    raise TrustRefusedError(_WHY)

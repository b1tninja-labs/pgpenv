"""What the *verified* self-signatures of a certificate say about its keys at a given time (M5).

``pgpenv.inventory`` reports what a certificate claims. This module reads the same signatures after
:func:`pgpenv.verification.check_self_signatures` has checked them, and lets only the ones that verified
decide anything:

* **binding** (RFC 9580 sec. 5.2.1.8, 5.2.3.10): a subkey is bound only by a verified Subkey Binding
  signature (0x18) by its primary key, and a binding for a signing subkey (Key Flags 0x02, sec. 5.2.3.29)
  must carry a verified embedded Primary Key Binding signature (0x19) made by the subkey, as sec. 5.2.1.8
  says it MUST;
* **expiry** (sec. 5.2.3.13): the Key Expiration Time of the newest verified self-signature that applies
  (the direct key signature, else the primary User ID's, else the newest User ID certification; for a
  subkey its newest verified binding), counted from the key's own creation time; a self-signature that has
  itself expired by then (sec. 5.2.3.18) is not considered, and neither is an expired certification or
  binding when deciding whether a User ID or subkey is certified or bound (a revocation counts whether or
  not it has expired: failing closed is this module's decision);
* **revocation** (sec. 5.2.1.11, 5.2.1.12, 5.2.3.31): only a verified revocation by the primary key counts
  (sec. 5.2.1.11 and 5.2.1.12 say others "should" not; the deprecated Revocation Key mechanism is not
  read). A revocation whose Reason is "superseded" (1) or "retired" (3) is *soft*: sec. 5.2.3.31 says old
  signatures stay valid, so it takes effect at its own creation time. Any other reason, or none, is *hard*
  here and applies at every time; the RFC states the consequence of a compromise (2) and says nothing
  about code 0 or a missing subpacket, so treating them as hard is this module's decision;
* **User ID self-certification** (sec. 5.2.3.10): a User ID is certified by a verified certification by the
  primary key, and retired by a verified Certification Revocation (0x30) at least as new as the newest such
  certification (the tie goes to the revocation; the RFC gives no tie rule).

Nothing here is trust: no certification by another key is counted, and ``wot.refuse`` stays true. A
signature that did not verify, or that the policy refused, is ignored and listed in ``ignored`` so a caller
can see what was left out and why. Time is an argument (seconds since the epoch); nothing reads the clock.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from .certificate import Certificate
from .signature import Signature
from .verification import SelfSignature, check_self_signatures

__all__ = ["CertificateState", "KeyState", "Revocation", "UserIdState", "assess"]

#: sec. 5.2.3.31 Table 10: the reasons after which "old signatures are still valid"
_SOFT_REASONS = frozenset({1, 3})
_SIGNING = 0x02  # sec. 5.2.3.29, Table 9


@dataclass(frozen=True, slots=True)
class Revocation:
    """A verified revocation signature, with the reason it gave (sec. 5.2.3.31)."""

    signature: Signature
    created: int | None
    reason: int | None
    reason_text: str | None
    hard: bool


@dataclass(frozen=True, slots=True)
class KeyState:
    """One key of a certificate (the primary or a subkey) as its verified self-signatures state it."""

    fingerprint: bytes
    is_subkey: bool
    bound: bool
    binding_problem: str | None
    expires: int | None
    expiry_source: str | None
    revocations: tuple[Revocation, ...]

    def revoked_at(self, at: int) -> bool:
        """True if a hard revocation exists, or a soft one created at or before ``at``."""
        return any(r.hard or (r.created is not None and r.created <= at) for r in self.revocations)

    def status(self, at: int) -> str:
        """``unbound``, ``revoked``, ``expired`` or ``ok``, in that order of precedence."""
        if not self.bound:
            return "unbound"
        if self.revoked_at(at):
            return "revoked"
        if self.expires is not None and self.expires <= at:
            return "expired"
        return "ok"


@dataclass(frozen=True, slots=True)
class UserIdState:
    """One User ID or attribute: certified by its own key, and whether that was later retired."""

    index: int
    certified: bool
    retired: bool
    certified_at: int | None


@dataclass(frozen=True, slots=True)
class CertificateState:
    primary: KeyState
    subkeys: tuple[KeyState, ...]
    user_ids: tuple[UserIdState, ...]
    ignored: tuple[SelfSignature, ...]


def _created(sig: Signature) -> int:
    return sig.created if sig.created is not None else 0


def _newest(items: Sequence[Any]) -> Any:
    return max(items, key=lambda item: _created(item.signature), default=None)


def _alive(sig: Signature, at: int) -> bool:
    """False for a signature that has expired by ``at`` (sec. 5.2.3.18; zero means it never does)."""
    after, created = sig.expires_after, sig.created
    return not after or created is None or created + after > at


def _revocation(sig: Signature) -> Revocation:
    reason = sig.value(29)
    code, text = (None, None) if reason is None else (reason[0], reason[1])
    return Revocation(sig, sig.created, code, text, hard=code is None or code not in _SOFT_REASONS)


def assess(cert: Certificate, *, at: int, policy: Any = "openpgp") -> CertificateState:
    """The state of every key and User ID of ``cert`` at time ``at``, from verified self-signatures only."""
    walked = check_self_signatures(cert, policy=policy)
    good = [r for r in walked if r.verification is not None and r.verification.valid]
    ignored = tuple(r for r in walked if r.verification is not None and not r.verification.valid)
    primary_key = cert.primary

    def valid_of(target: str, index: int | None, *types: int) -> list[SelfSignature]:
        return [
            r
            for r in good
            if r.target == target and r.index == index and r.signature.sig_type in types
        ]

    # the primary key: expiry source in the order the inventory uses, but from verified signatures only
    direct = [r for r in valid_of("direct", None, 0x1F) if _alive(r.signature, at)]
    certs = [
        r
        for position in range(len(cert.user_ids))
        for r in valid_of("user-id", position, 0x10, 0x11, 0x12, 0x13)
        if _alive(r.signature, at)
    ]
    chosen, source = _newest(direct), "direct-key"
    if chosen is None:
        chosen, source = _newest([r for r in certs if r.signature.value(25) is True]), "user-id"
    if chosen is None:
        chosen, source = _newest(certs), "user-id"
    after = None if chosen is None else chosen.signature.key_expires_after
    primary = KeyState(
        fingerprint=primary_key.fingerprint,
        is_subkey=False,
        bound=True,
        binding_problem=None,
        expires=primary_key.created + after if after else None,
        expiry_source=source if chosen is not None and after else None,
        revocations=tuple(_revocation(r.signature) for r in valid_of("direct", None, 0x20)),
    )

    subkeys: list[KeyState] = []
    for position, entry in enumerate(cert.subkeys):
        bindings = [r for r in valid_of("subkey", position, 0x18) if _alive(r.signature, at)]
        binding = _newest(bindings)
        problem: str | None = None
        if binding is None:
            problem = "no verified binding signature (sec. 5.2.3.10: each subkey MUST have one)"
        else:
            flags = binding.signature.key_flags
            signs = bool(flags) and bool(flags[0] & _SIGNING)
            backs = [r for r in good if r.target == "back" and r.index == position]
            if signs and not backs:
                problem = "a signing subkey's binding has no verified back signature (sec. 5.2.1.8)"
        after = None if binding is None else binding.signature.key_expires_after
        subkeys.append(
            KeyState(
                fingerprint=entry.key.fingerprint,
                is_subkey=True,
                bound=problem is None,
                binding_problem=problem,
                expires=entry.key.created + after if after else None,
                expiry_source="binding" if after else None,
                revocations=tuple(
                    _revocation(r.signature) for r in valid_of("subkey", position, 0x28)
                ),
            )
        )

    users: list[UserIdState] = []
    for position in range(len(cert.user_ids)):
        mine = _newest(
            [
                r
                for r in valid_of("user-id", position, 0x10, 0x11, 0x12, 0x13)
                if _alive(r.signature, at)
            ]
        )
        revoked = _newest(valid_of("user-id", position, 0x30))
        certified_at = None if mine is None else _created(mine.signature)
        retired = revoked is not None and (
            mine is None or _created(revoked.signature) >= _created(mine.signature)
        )
        users.append(UserIdState(position, mine is not None, retired, certified_at))
    return CertificateState(primary, tuple(subkeys), tuple(users), ignored)

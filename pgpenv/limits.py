"""bounds on packet size, nesting depth and key count on every parse path.

OpenPGP lengths are attacker-controlled: a five-octet length says four gigabytes, a signature
carries a four-octet subpacket area size, and a keyring is an unbounded concatenation. Every
parser in this package takes a :class:`Limits` and raises :class:`pgpenv.errors.LimitError` the
moment one bound is crossed, before the next packet is decoded. The defaults are generous enough
for the largest real keyrings (a distribution keyring is a few megabytes) and small enough that
a hostile file cannot make the parser allocate more than a few multiples of ``max_input_bytes``.

The acceptance sentence for :func:`check` is the one proposed in ROADMAP.md section 5 (design):
a packet stream that exceeds the packet size, nesting depth or key count bound raises before any
further packet is decoded. It is not accepted by the owner yet, so the row is partial.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import LimitError

__all__ = [
    "DEFAULT_LIMITS",
    "Limits",
    "ParsePlan",
    "check",
]


@dataclass(frozen=True, slots=True)
class Limits:
    """Upper bounds applied by every parse path. All values are inclusive maxima."""

    max_input_bytes: int = 64 * 1024 * 1024
    max_packet_bytes: int = 16 * 1024 * 1024
    max_packets: int = 2_000_000
    max_partial_chunks: int = 1_000_000
    max_subpackets: int = 4096
    max_embedded_depth: int = 3
    max_keys: int = 200_000
    max_user_ids: int = 20_000
    max_signatures_per_key: int = 200_000
    max_armor_line_bytes: int = 1024 * 1024
    max_armor_blocks: int = 100_000
    max_cleartext_lines: int = 5_000_000


DEFAULT_LIMITS = Limits()


@dataclass(frozen=True, slots=True)
class ParsePlan:
    """What a parser has observed so far; :func:`check` compares it with the bounds."""

    input_bytes: int = 0
    packet_bytes: int = 0
    packets: int = 0
    subpackets: int = 0
    depth: int = 0
    keys: int = 0
    user_ids: int = 0
    signatures: int = 0


def check(plan: ParsePlan, limits: Limits = DEFAULT_LIMITS) -> None:
    """Raise :class:`LimitError` when ``plan`` exceeds a bound in ``limits`` (design).

    ``plan`` carries the counters a parser has seen so far. Each counter is compared with its
    bound, and the first one over is named in the message; nothing is returned on success.
    """
    for observed, bound, what in (
        (plan.input_bytes, limits.max_input_bytes, "input size in bytes"),
        (plan.packet_bytes, limits.max_packet_bytes, "packet size in bytes"),
        (plan.packets, limits.max_packets, "packet count"),
        (plan.subpackets, limits.max_subpackets, "subpacket count in one area"),
        (plan.depth, limits.max_embedded_depth, "embedded signature depth"),
        (plan.keys, limits.max_keys, "key count"),
        (plan.user_ids, limits.max_user_ids, "user id count on one key"),
        (plan.signatures, limits.max_signatures_per_key, "signature count on one key"),
    ):
        if observed > bound:
            raise LimitError(f"{what} {observed} exceeds the limit {bound}")

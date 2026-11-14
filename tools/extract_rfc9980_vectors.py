"""Copy the armored examples of RFC 9980 appendix A into ``tests/data/rfc9980``.

Usage: ``python tools/extract_rfc9980_vectors.py PATH-TO-rfc9980.txt``. The text is the RFC Editor's
plain-text rendering. Each block is taken by the line number of its ``BEGIN`` line in that file (RFC
9980, June 2026) and is checked against its heading, so a different rendering fails loudly instead
of writing the wrong block. Only public keys and detached signatures are copied: they are what the
verification and key rows need, and the secret keys are 200 kilobytes of seed-format examples.
"""

from __future__ import annotations

import pathlib
import sys

# (output name, heading that must precede the block, line of its BEGIN armor header)
BLOCKS = (
    ("a1-public.asc", "A.1.2.", "PUBLIC KEY BLOCK", 1596),
    ("a2-public.asc", "A.2.2.", "PUBLIC KEY BLOCK", 1773),
    ("a3-public.asc", "A.3.2.", "PUBLIC KEY BLOCK", 2257),
    ("a3-detached.asc", "A.3.4.", "SIGNATURE", 2679),
    ("a4-public.asc", "A.4.2.", "PUBLIC KEY BLOCK", 3198),
    ("a4-detached.asc", "A.4.4.", "SIGNATURE", 3770),
    ("a5-public.asc", "A.5.2.", "PUBLIC KEY BLOCK", 4448),
    ("a5-detached.asc", "A.5.4.", "SIGNATURE", 5202),
    ("a6-public.asc", "A.6.2.", "PUBLIC KEY BLOCK", 6522),
    ("a6-detached.asc", "A.6.3.", "SIGNATURE", 7634),
    ("a7-public.asc", "A.7.2.", "PUBLIC KEY BLOCK", 9952),
    ("a7-detached.asc", "A.7.3.", "SIGNATURE", 11869),
)


def main() -> None:
    lines = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8-sig").splitlines()
    out = pathlib.Path(__file__).resolve().parent.parent / "tests" / "data" / "rfc9980"
    out.mkdir(parents=True, exist_ok=True)
    for name, heading, kind, number in BLOCKS:
        begin = lines[number - 1].strip()
        if begin != f"-----BEGIN PGP {kind}-----":
            raise SystemExit(f"{name}: line {number} is {begin!r}")
        earlier = [i for i in range(number - 1) if lines[i].startswith(heading)]
        if not earlier or number - 1 - earlier[-1] > 40:
            raise SystemExit(f"{name}: no heading {heading} just above line {number}")
        block = []
        for line in lines[number - 1 :]:
            block.append(line.strip())
            if line.strip() == f"-----END PGP {kind}-----":
                break
        else:
            raise SystemExit(f"{name}: no END line")
        (out / name).write_text("\n".join(block) + "\n", encoding="ascii", newline="\n")
        print(name, len(block), "lines")


if __name__ == "__main__":
    main()

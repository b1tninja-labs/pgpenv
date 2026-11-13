"""Command line entry point for pgpenv.

``python -m pgpenv inventory FILE [--json]`` prints what an OpenPGP file claims: keys,
fingerprints, algorithms, user IDs, certifications, revocations, subkeys and loose signatures.
Everything is *claimed*; no signature is verified (see ``pgpenv.inventory``).

Exit status: 0 when the file was read and nothing was refused, 1 when output was produced but
some content was refused (see ``rejected`` in the JSON), 2 for usage errors, unreadable files
and input that is not OpenPGP at all.
"""

from __future__ import annotations

import argparse
import json
import sys

from .errors import PgpError
from .inventory import Inventory, inventory_report

USAGE = """\
Examples:
  pgpenv inventory keyring.gpg --json
  pgpenv inventory archlinux.asc"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pgpenv",
        description="OpenPGP packet layer, v4 and v6 keys, encryption and signatures, AEAD encrypted sessions and the armored stream that carries them",
        epilog=USAGE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")
    inv = sub.add_parser(
        "inventory", help="list the keys and signatures a file claims (no verification)"
    )
    inv.add_argument(
        "file", help="binary or armored keyring, signature or cleartext message; - for stdin"
    )
    inv.add_argument("--json", action="store_true", help="emit the pkgtrust.keys/1 record")
    return parser


def _text(inv: Inventory) -> str:
    lines = [
        f"{inv.source.get('path')}: {len(inv.keys)} key(s), {len(inv.signatures)} loose signature(s) (all claimed)"
    ]
    for key in inv.keys:
        lines.append(
            f"  v{key.version} {key.fingerprint} {key.algorithm}"
            f"{f' {key.bits}' if key.bits else ''}{f' {key.curve}' if key.curve else ''}"
            f" created {key.created:d} flags {','.join(key.flags) or '-'}"
            f"{' REVOKED(claimed)' if key.revoked_claimed else ''}"
        )
        lines.extend(f"    uid {u['text']}" for u in key.user_ids)
        lines.extend(f"    sub {s['fingerprint']} {s['algorithm']['name']}" for s in key.subkeys)
    lines.extend(f"  rejected at offset {r['offset']}: {r['reason']}" for r in inv.rejected)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "inventory":
        parser.print_usage(sys.stderr)
        return 2
    try:
        data = sys.stdin.buffer.read() if args.file == "-" else open(args.file, "rb").read()  # noqa: SIM115
    except OSError as error:
        print(f"pgpenv: {error}", file=sys.stderr)
        return 2
    try:
        inv = inventory_report(data, path=None if args.file == "-" else args.file)
    except PgpError as error:
        print(f"pgpenv: {error}", file=sys.stderr)
        return 2
    print(json.dumps(inv.to_dict(), indent=2, sort_keys=False) if args.json else _text(inv))
    return 1 if inv.rejected else 0


if __name__ == "__main__":
    raise SystemExit(main())

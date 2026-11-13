"""the seam onto cryptography, pinned to an allowed algorithm list.

The owner's rule (2026-11-12): "we can use the cryptography package for RSA and AES and those
cryptographic primitives, but lets roll our own for everything else (even asn1 and cert parsing)".
So this module, and only this module, may import ``cryptography``, and only for primitives:
signature verification for M3 (reached through the sibling ``sigprim`` seam, see
docs/verify-seam.md) and the ciphers of M4. Packet framing, armor, key and signature parsing,
fingerprints and the inventory are pgpenv's own code and never import ``cryptography``;
``tests/test_inventory.py::test_parse_layer_imports_only_the_standard_library`` enforces it.

Nothing is implemented here yet: every object in this module is a placeholder until the
milestone named in ROADMAP.md lands.
"""

from __future__ import annotations

__all__: list[str] = []

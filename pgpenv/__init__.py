"""pgpenv -- OpenPGP messages and keys to RFC 9580.

RFC 9580 replaced RFC 4880 in July 2024 with version 6 keys, a revised algorithm policy and
new key material handling.
"""

from __future__ import annotations

from . import apps, armor, cli, crypto, key, limits, message, packet, session, signature
from .armor import decode, encode
from .key import fingerprint, load_key
from .limits import check
from .packet import encode_packet, iter_packets
from .session import decrypt, encrypt
from .signature import sign, verify

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "apps",
    "armor",
    "check",
    "cli",
    "crypto",
    "decode",
    "decrypt",
    "encode",
    "encode_packet",
    "encrypt",
    "fingerprint",
    "iter_packets",
    "key",
    "limits",
    "load_key",
    "message",
    "packet",
    "session",
    "sign",
    "signature",
    "verify",
]

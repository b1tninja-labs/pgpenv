"""pgpenv -- OpenPGP messages and keys to RFC 9580.

RFC 9580 replaced RFC 4880 in July 2024 with version 6 keys, a revised algorithm policy and
new key material handling.
"""

from __future__ import annotations

from . import (
    apps,
    armor,
    certificate,
    cleartext,
    cli,
    crypto,
    errors,
    inventory,
    key,
    limits,
    message,
    packet,
    registry,
    session,
    signature,
    wire,
)
from .armor import decode, encode
from .inventory import inventory_report
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
    "certificate",
    "check",
    "cleartext",
    "cli",
    "crypto",
    "decode",
    "decrypt",
    "encode",
    "encode_packet",
    "encrypt",
    "errors",
    "fingerprint",
    "inventory",
    "inventory_report",
    "iter_packets",
    "key",
    "limits",
    "load_key",
    "message",
    "packet",
    "registry",
    "session",
    "sign",
    "signature",
    "verify",
    "wire",
]

"""the seam onto sigwire.verify: integers and bytes in, one answer out.

The owner's rule (2026-11-12): "we can use the cryptography package for RSA and AES and those
cryptographic primitives, but lets roll our own for everything else (even asn1 and cert parsing)".
Signature verification is the sibling ``sigwire[verify]`` project (``D:\\code\\sigwire``), a strict seam
over ``cryptography``; this module, and only this module, imports it (and so ``cryptography``, which
the ciphers of M4 will also reach through here). Packet framing, armor, key and signature parsing,
fingerprints and the inventory are pgpenv's own code and never import it;
``tests/test_inventory.py::test_parse_layer_imports_only_the_standard_library`` enforces that, and
``test_importing_the_package_does_not_import_cryptography`` that ``import pgpenv`` stays free of it.
Every function here imports ``sigwire.verify`` when it is called, so nothing loads until a signature
is verified.

Each function takes what :mod:`pgpenv.key` and :mod:`pgpenv.signature` already hold (integers, octet
strings, a digest) and returns True or False. sigwire's refusals become pgpenv's:
``MalformedInput`` is :class:`~pgpenv.errors.MalformedKeyMaterialError`, ``Unsupported`` is
:class:`~pgpenv.errors.UnsupportedAlgorithmError` and ``PolicyRefusal`` is
:class:`~pgpenv.errors.PolicyRefusalError`. OpenPGP's own decisions (which hash a signature may use,
the left 16 bits, who the issuer is) are :mod:`pgpenv.verification`'s, not this module's.

The ``openpgp`` policy is sigwire's profile for RFC 9580 sec. 9.5, 12.4 and 12.5: RSA of at least
2048 bits with a SHA-2 or SHA-3 hash, ECDSA on the NIST curves, Ed25519 and Ed448, and no DSA.
``legacy`` is sigwire's profile for historical verification: 1024-bit RSA, SHA-1, DSA.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .errors import MalformedKeyMaterialError, PolicyRefusalError, UnsupportedAlgorithmError

__all__ = [
    "dsa",
    "ecdsa",
    "ed448",
    "ed25519",
    "policy",
    "rsa_pkcs1v15",
]


def policy(name: str | Any) -> Any:
    """The sigwire policy called ``name`` (``"openpgp"`` or ``"legacy"``); a policy object passes through."""
    from sigwire.verify import CONSUMERS, LEGACY

    if not isinstance(name, str):
        return name
    if name == "openpgp":
        return CONSUMERS["openpgp"]
    if name == "legacy":
        return LEGACY
    raise UnsupportedAlgorithmError(
        f"no verification policy called {name!r}; use 'openpgp' or 'legacy'"
    )


def _translated[T](call: Callable[[], T]) -> T:
    from sigwire.verify import MalformedInput, PolicyRefusal, Unsupported

    try:
        return call()
    except MalformedInput as error:
        raise MalformedKeyMaterialError(str(error)) from None
    except Unsupported as error:
        raise UnsupportedAlgorithmError(str(error)) from None
    except PolicyRefusal as error:
        raise PolicyRefusalError(str(error)) from None


def rsa_pkcs1v15(
    n: int, e: int, digest: bytes, signature: bytes, hash_name: str, policy_: Any
) -> bool:
    """RSASSA-PKCS1-v1_5 over a digest the caller computed (RFC 9580 sec. 5.2.3.1, RFC 8017 sec. 8.2)."""
    from sigwire.verify import rsa

    return _translated(
        lambda: rsa.verify_pkcs1v15(
            n, e, digest, signature, hash_name, prehashed=True, policy=policy_
        )
    )


def dsa(
    p: int, q: int, g: int, y: int, digest: bytes, r: int, s: int, hash_name: str, policy_: Any
) -> bool:
    """DSA over a digest (sec. 5.2.3.2). The ``openpgp`` policy refuses it (sec. 12.5)."""
    from sigwire.verify import dsa as backend

    return _translated(
        lambda: backend.verify(p, q, g, y, digest, r, s, hash_name=hash_name, policy=policy_)
    )


def ecdsa(
    curve: str, qx: int, qy: int, digest: bytes, r: int, s: int, hash_name: str, policy_: Any
) -> bool:
    """ECDSA over a digest on ``P-256``, ``P-384`` or ``P-521`` (sec. 5.2.3.2)."""
    from sigwire.verify import ecdsa as backend

    return _translated(
        lambda: backend.verify(curve, qx, qy, digest, r, s, hash_name=hash_name, policy=policy_)
    )


def ed25519(public: bytes, digest: bytes, signature: bytes, policy_: Any) -> bool:
    """Pure Ed25519 with the hash digest as the message (RFC 9580 sec. 12.7)."""
    from sigwire.verify import eddsa

    return _translated(lambda: eddsa.verify_ed25519(public, digest, signature, policy=policy_))


def ed448(public: bytes, digest: bytes, signature: bytes, policy_: Any) -> bool:
    """Pure Ed448 with the empty context and the hash digest as the message (sec. 12.7)."""
    from sigwire.verify import eddsa

    return _translated(lambda: eddsa.verify_ed448(public, digest, signature, policy=policy_))

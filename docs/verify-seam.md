# Verification: the `sigprim` seam (M3, not implemented)

`signature.verify()` is `[ ]` in ROADMAP.md and raises `NotImplementedError`. This page says exactly what it
will call, so the row can be built the day `sigprim` exists, and so `sigprim` is built to a stated demand.

## Why a separate project

The owner's rule (2026-11-12): "we can use the cryptography package for RSA and AES and those cryptographic
primitives, but lets roll our own for everything else (even asn1 and cert parsing)". So the parse layer here
is pgpenv's own code, and the cryptographic primitives sit behind one seam. The pkgtrust signature research
(recommendation b) proposed that seam be a sibling verify-only library, `sigprim`, at `D:\code\sigprim`,
shared with pkix and ctspy. On 2026-11-12 that directory did not exist yet, so the names below are
**proposed**, not read from code: reconcile them with sigprim's real API when it lands.

pgpenv stays responsible for everything *about* OpenPGP: parsing, choosing the hash, building the hashed
octets (`signature.hash_stream()`, already implemented and pinned to RFC 9580 appendix A.2, A.3.1 and A.6),
checking the left 16 bits, refusing weak or unknown algorithms. `sigprim` is responsible only for the
mathematics, taking integers and raw bytes and no ASN.1.

## What `verify(data, sig, key)` will do, in order

1. Refuse early, before any mathematics: `not sig.usable` (RFC 9580 sec. 5.2.5); a hash or public-key
   algorithm the policy refuses (sec. 9.5: MD5, SHA-1 and RIPEMD-160 must not validate a recent signature);
   a v6 signature by a non-v6 key or the reverse (sec. 5.2.5); the Ed25519/Ed448 minimum digest sizes
   (sec. 5.2.3.4, 5.2.3.5); the issuer not matching `key` by fingerprint or key id.
2. Build the octets: `stream = signature.hash_stream(sig, document=..., key=..., ...)`.
3. Hash them in one context with `hashlib` (`registry.HASHES[sig.hash_algo].hashlib_name`), or, for
   RIPEMD-160 (not reliably in `hashlib`), `sigprim.hashes.ripemd160`.
4. Compare the first two digest octets with `sig.left16`; a v6 signature MUST be rejected on a mismatch
   (sec. 5.2.3.6). For v4 it is a cheap early reject.
5. Dispatch on `sig.pub_algo` with the parts from `sig.parts()` and the key fields from
   `PublicKey.fields`:

| `pub_algo` | Call (proposed) | Inputs |
|---|---|---|
| 1, 3 RSA | `sigprim.rsa.verify_pkcs1_v15(n, e, signature_octets, digest, hash_oid_prefix)` | `n`, `e` from `fields`; the signature MPI left-padded to the modulus length; `registry` has the sec. 9.5 Table 24 prefixes to add |
| 17 DSA | `sigprim.dsa.verify(p, q, g, y, r, s, digest)` | MPIs from `sig.parts()`; hash digest at least as wide as `q` (sec. 5.2.3.2) |
| 19 ECDSA | `sigprim.ecdsa.verify(curve, point, r, s, digest)` | `curve` from `PublicKey.curve`; `point` is the SEC1 point in `fields["point"]`; truncation of the digest and the P-521 512-bit rule are sec. 5.2.3.2 |
| 22 EdDSALegacy (deprecated) | `sigprim.eddsa.ed25519_verify(public, digest, signature)` | `public` is the point with its 0x40 prefix removed; `signature` is the two MPIs `R` and `S`, each a native little-endian string of up to 32 octets that has to be padded back to 32 (sec. 5.2.3.3.1; check the padding direction against a GnuPG signature in `tests/data/gnupg` when implementing) |
| 27 Ed25519 | `sigprim.eddsa.ed25519_verify(public, digest, signature)` | `public` 32 octets, `signature` the native 64 octets (not MPIs: erratum 8454); the *message* given to EdDSA is the hash digest, not the document |
| 28 Ed448 | `sigprim.eddsa.ed448_verify(public, digest, signature)` | 57 and 114 octets; later |

   The result is a `Verification` carrying the facts checked (hash, algorithm, issuer, creation time)
   rather than a bare boolean, in the spirit of strategy.md: every answer carries its provenance.
6. Policy and time are the caller's: `verify` reports that a signature is cryptographically good under a
   key, and nothing about whether that key was valid, unexpired or unrevoked at `sig.created`. Those are
   the M5 rows (`cert.binding`, `cert.expiry`, `cert.revoked`), which also verify the self-signatures that
   the inventory only claims.

`cryptography` may supply RSA (and the AES of M4) behind `pgpenv/crypto.py` if `sigprim` has not appeared by
then; the other algorithms are rolled by us, per the owner's rule. Either way the parse layer does not
import it.

## What `sigprim` needs to offer, summarised

PKCS#1 v1.5 verification built by re-encoding and comparing (no parsing of the decrypted block), DSA, ECDSA
over P-256, P-384, P-521 and the Brainpool curves OpenPGP lists (RFC 9580 sec. 9.2), Ed25519 and later
Ed448, point-on-curve and range checks, and RIPEMD-160. Test material it should be checked against: RFC 8032
vectors (6 verified errata: read them first), RFC 6979 appendix A, Wycheproof, and the GnuPG-made
signatures already in `tests/data/gnupg` (whose left-16 recipe is pinned, and which a real verification
should accept).

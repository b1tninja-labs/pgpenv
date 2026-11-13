# Verification: the `sigwire[verify]` seam (M3, implemented 2026-11-13)

`pgpenv.verification` verifies signatures; `pgpenv/crypto.py` is the only module that reaches the
primitives, in the sibling `sigwire[verify]` project (`D:\code\sigwire`). The first pass of this page,
written on 2026-11-12, proposed the calls to a verify-only library then called `sigprim`. `sigprim` was
merged into sigwire on 2026-11-13 (PORTFOLIO.md section 9 item 15) and the name is retired; this page now
records what was built.

## Why a separate project

The owner's rule (2026-11-12): "we can use the cryptography package for RSA and AES and those cryptographic
primitives, but lets roll our own for everything else (even asn1 and cert parsing)". So the parse layer is
pgpenv's own code and the cryptographic primitives sit behind one seam. sigwire is that seam, shared with
ctspy and, as they migrate, pkix and signeddata: integers and bytes in, one policy table, five answers
out (`True`, `False`, `MalformedInput`, `Unsupported`, `PolicyRefusal`).

pgpenv stays responsible for everything *about* OpenPGP: choosing the hash, building the hashed octets
(`signature.hash_stream()`, RFC 9580 sec. 5.2.4), checking the left 16 bits, refusing what sec. 5.2.5 and
sec. 5.2.3 make unusable, and decoding the key and signature material for the primitive. sigwire does the
mathematics and the policy table.

## What `verify_signature(sig, signer, ...)` does, in order

1. Pick the key. `signer` is a key, a certificate (its primary key and subkeys) or a list. With more than one
   candidate that can sign, the issuer fingerprint or key id of the signature chooses; if it names none of them
   the status is `no-key`.
2. Refuse early, as statuses: a signature with `problems` (sec. 5.2.5); a signature and key version that are not a
   pair of sec. 10.3.2.2 Table 27; a signature algorithm that is not the key's; a version 3 signature with ECDSA
   or EdDSA (sec. 5.2.3.2 to 5.2.3.5); Ed25519Legacy in a version 6 signature (sec. 5.2.3.3.1).
3. Build the octets with `hash_stream` and hash them in one `hashlib` context (`unsupported` if the hash is
   unknown or the interpreter lacks it: RIPEMD-160 without OpenSSL's legacy provider).
4. Compare the first two digest octets with `left16`: a mismatch is `invalid` (a version 6 signature MUST be
   rejected, sec. 5.2.3.6; a version 4 one is a cheap early reject).
5. Apply the digest-size rules: ECDSA at least the curve's fsize and 512 bits for P-521, Ed25519 and
   EdDSALegacy 256 bits, Ed448 512 bits, DSA at least the bit length of q. A shorter hash is `malformed`.
6. Dispatch to `pgpenv.crypto` with the policy (`openpgp` by default, or `legacy`):

| algorithm | call | what pgpenv hands over |
|---|---|---|
| 1, 3 RSA | `sigwire.verify.rsa.verify_pkcs1v15(n, e, digest, signature, hash, prehashed=True)` | `n`, `e` from the key; the signature MPI as `ceil(bits / 8)` octets |
| 17 DSA | `sigwire.verify.dsa.verify(p, q, g, y, digest, r, s)` | the policy `openpgp` refuses it (sec. 12.5); `legacy` allows it |
| 19 ECDSA | `sigwire.verify.ecdsa.verify(curve, qx, qy, digest, r, s)` | the SEC1 point split in two; NIST curves only |
| 22 EdDSALegacy | `sigwire.verify.eddsa.verify_ed25519(public, digest, signature)` | the point without its `0x40` prefix; R and S padded on the left to 32 octets |
| 27 Ed25519 | `sigwire.verify.eddsa.verify_ed25519(public, digest, signature)` | 32 and 64 native octets (erratum 8454); the message is the digest (sec. 12.7) |
| 28 Ed448 | `sigwire.verify.eddsa.verify_ed448(public, digest, signature)` | 57 and 114 octets; no real signature pins it yet |

7. The answer is a `Verification`: `status` (`valid`, `invalid`, `malformed`, `unsupported`, `refused`,
   `no-key`), `reason`, the `checked` facts (`hash`, `left16`, `signature`), the key used, whether the issuer
   subpackets named it, the claimed creation time and the deprecation `warnings`.
8. Policy and time are the caller's: `valid` says a good signature by this key over this data, and nothing
   about whether the key was valid, unexpired or unrevoked at `sig.created`. Those are the M5 rows. The
   creation-time half of sec. 9.5 (a "recent" MD5 or SHA-1 signature MUST NOT validate, an "old" one SHOULD NOT)
   has no date in the RFC; the `openpgp` policy refuses those hashes outright and `legacy` allows them.

## What is open

- Brainpool curves (`verify.ecdsa.brainpool`) are done: sigwire carries brainpoolP256r1, P384r1 and P512r1 (RFC
  5639 sec. 3) in the `openpgp` and `legacy` policies, and GnuPG 2.4.9 signatures on all three verify.
- RSA with SHA3-256 and SHA3-512 (`verify.rsa.sha3`): RFC 9580 sec. 9.5 Table 24 gives the DigestInfo prefixes that
  sigwire's `sw.verify.seam.rsa.sha3-pkcs1` row was waiting for; they are in sigwire now, and the only evidence is
  synthetic (OpenSSL signed it).
- Ed448 (`verify.ed448`): no sample in RFC 9580, and GnuPG 2.4.9 makes none. The one real signature is
  libgcrypt's (`tests/test_verification.py::test_ed448_certification_signed_by_libgcrypt_verifies`): real Ed448,
  assembled into an OpenPGP packet that no other implementation read.
- Version 6 keys and signatures are covered by the RFC 9580 appendix A vectors only (A.3, A.6, A.7), because
  GnuPG 2.4 makes none; an interop run against Sequoia is the M6 row.

Test material: RFC 9580 appendix A.2, A.3, A.6 and A.7; the GnuPG 2.4.9 files in `tests/data/gnupg`; and the
WSL cross-check `tests/test_verification_gnupg.py`, which makes throwaway keys of every algorithm GnuPG offers,
signs a document three ways with several hashes and asks GnuPG itself for a verdict (skips without WSL).

# Changelog

The format follows Keep a Changelog, and this project adheres to Semantic Versioning.

## Unreleased

### Added

- M1: packet framing for the OpenPGP and Legacy header formats, partial body lengths, every RFC 9580
  packet tag recognised by type with unknown tags preserved (`packet`); ASCII armor with headers and an
  advisory CRC-24 (`armor`); the cleartext signature framework returning the exact signed text
  (`cleartext`); `limits.Limits` enforced on every parse path.
- M2: public key packets v4 and v6, and v2/v3 read-only, with computed fingerprints and key ids, algorithm
  and size, curve OIDs and the native Ed25519, Ed448, X25519 and X448 algorithms (`key`); signature packets
  v3, v4 and v6 with every subpacket decoded and the exact hashed-data recipe (`signature`); transferable
  public keys and keyrings, binary or armored (`certificate`).
- `pgpenv.inventory` and `python -m pgpenv inventory FILE [--json]`: the `pkgtrust.keys/1` record of what a
  file claims, never what is valid (docs/inventory.md).
- Tests: RFC 9580 appendix A vectors, synthesised packets, GnuPG-generated fixtures with a GnuPG
  cross-check, and a hostile corpus. Coverage floor raised from 45 to 85.
- docs/verify-seam.md: the `sigprim` calls `signature.verify()` will make.

### Changed

- `cryptography` stays a declared dependency, but the parse-and-inventory layer imports nothing outside the
  standard library and a test enforces it. The owner's rule of 2026-11-12 allows `cryptography` for
  primitives such as RSA and AES; everything else is this package's own code. Verification will use
  `sigprim`.
- README and ROADMAP: the CRC-24 promise is corrected (RFC 9580 sec. 6.1 says a reader MUST NOT reject on
  it) and the non-goal "pre-standard wire formats" is narrowed so that reading Legacy headers and v3 keys,
  which RFC 9580 still defines, stays in scope.

### Still raising `NotImplementedError`

`signature.sign`, `signature.verify`, `session.encrypt`, `session.decrypt`.

## 0.0.0 - 2026-11-05

### Added

- Package skeleton, obligation matrix and CI gates for pgpenv.
- `pgpenv.apps` namespace reserved for composition that is not protocol behaviour.

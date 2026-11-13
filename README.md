# pgpenv

<!-- PyPI badges go live with the first release. Until then a version badge renders
     "no version" on the landing page, which reads as a defect rather than a date, so
     the badges stay commented out until the tag exists.
-->

**Pre-alpha: reading and signature verification work; signing and encryption do not.** pgpenv parses OpenPGP
(RFC 9580) with the standard library alone: packet framing, ASCII armor, the cleartext signature
framework, v3, v4 and v6 public keys with computed fingerprints, signature packets with every
subpacket, keyrings, and an inventory of what a file *claims*. Signatures can be verified through the
sibling `sigwire[verify]` seam (`pgpenv.verification`: documents, cleartext messages, certifications, subkey
bindings and their back signatures, v3, v4 and v6), and the result is a status with the facts that were
checked, never a bare boolean. `signature.sign`, `session.encrypt` and `session.decrypt` raise
`NotImplementedError`, and the test suite records that rather than hiding it. Read
[ROADMAP.md](ROADMAP.md) before depending on any of it.

```bash
python -m pgpenv inventory keyring.gpg --json     # fingerprints, algorithms, user ids, certifications, revocations
```

The output is the `pkgtrust.keys/1` record, documented in [docs/inventory.md](docs/inventory.md). Every
field is claimed, never valid: a forged self-signature produces the same record as a real one.

pgpenv -- OpenPGP messages and keys to RFC 9580

RFC 9580 replaced RFC 4880 in July 2024 with version 6 keys, a revised algorithm policy and new key material handling. Python's answer has not moved since before that document existed: pgpy 0.6.0 was released 2022-11-24, and the openpgp name belongs to a 2005 package. Everything current is C or Rust (Sequoia, RNP, GnuPG), so a Python service either runs a subprocess with a keyring it does not want or ignores OpenPGP. pgpenv is scoped to the message and key layer: correct packets, honest verification, no daemon.

## The gap, with a date

PyPI was queried on 2026-11-05 for this name and for every neighbouring project. Landscape
claims rot quickly: two projects in this portfolio shipped within five days of the survey,
which is why the table below carries dates instead of adjectives.

| Project | Version | Last release | Why it is not this project |
|---|---|---|---|
| pgpy | 0.6.0 | 2022-11-24 | the incumbent, released before RFC 9580 existed |
| openpgp | 0.2.3 | 2005-07-01 | a squat on the obvious name |
| Sequoia, RNP, GnuPG | - | - | current and good, in C and Rust: subprocess or FFI from Python |

What this project intends to add:

- version 6 keys and packets, plus a v4 reader for material that already exists (done for reading);
  the v4 reader is the headline, because distribution keyrings are v4 and v3 and Legacy-format packets are
  still read (RFC 9580 sec. 4.2, 5.5.2 say a consumer MAY)
- AEAD encrypted sessions with the granularity rules the specification sets
- signature creation and verification that reports what it checked and what it refused
- key certifications and binding checks handled so the web of trust is not silently trusted
- armored streams with strict line discipline that survive truncated input. The CRC-24 is advisory, not a
  gate: RFC 9580 sec. 6.1 says an implementation MUST NOT reject an object because the checksum is present,
  missing, malformed or wrong, and that a producer SHOULD NOT generate it. pgpenv reports the outcome
  (`absent`, `ok`, `mismatch`, `malformed`) and returns the data either way

## Specification spine

Status and publication dates below were read from the RFC Editor record on 2026-11-05. A
section number is cited only where that section was read in full; everything else cites the
document, which is the honest grain size for a plan. See [docs/rfc-map.md](docs/rfc-map.md).

| Document | Status | Published | What it gives this project |
|---|---|---|---|
| RFC 9580 | Proposed Standard | 2024-07 | the current format: packets, v6 keys, algorithm policy, AEAD |
| RFC 4880 | Obsolete | 2007-11 | the v4 wire a decade of material is still wearing; readable, never writable |
| RFC 9980 | Proposed Standard | 2026-06 | post-quantum public key algorithms layered on RFC 9580; read before fixing the algorithm policy |

### Errata watch

- RFC 9580 carries 7 verified errata. Read them before writing a single parser, because several concern key material encoding.
- RFC 9580 obsoletes RFC 4880, RFC 5581 and RFC 6637: recipes copied from those documents may describe behaviour it removed.
- RFC 9980 extends RFC 9580 with ML-KEM, ML-DSA and SLH-DSA; it has no verified errata (1 on file) as of 2026-11-07 (rfclib).

## Module layout

| Module | Responsibility |
|---|---|
| `packet` | packet framing, tags, old and new format headers (RFC 9580) |
| `key` | public keys, v3, v4 and v6 fingerprints, key ids, subkeys (RFC 9580) |
| `signature` | signature packets, subpackets and the exact hashed data that binds them (RFC 9580) |
| `certificate` | transferable public keys and keyrings, binary or armored (RFC 9580 sec. 10.1) |
| `inventory` | the `pkgtrust.keys/1` record of what a file claims (docs/inventory.md) |
| `armor` | radix64 with an advisory CRC-24, headers and tails (RFC 9580 sec. 6) |
| `cleartext` | the cleartext signature framework and the exact signed text (RFC 9580 sec. 7) |
| `registry`, `wire`, `errors` | algorithm and type tables, MPIs, the exception family |
| `limits` | bounds on packet size, nesting depth and key count on every parse path |
| `session` | symmetric and public key session key handling, AEAD granularity (RFC 9580): not implemented |
| `message` | literals, compression and the nesting that makes MIME work safe: not implemented |
| `crypto` | the seam onto `sigwire[verify]` (RSA, ECDSA, EdDSA, DSA primitives over `cryptography`), imported lazily |
| `verification` | `verify_document`, `verify_cleartext`, `verify_certification`, `verify_binding`, `verify_back_signatures`, `check_self_signatures` (RFC 9580 sec. 5.2.4, 7) |

## What it does not do

- an agent, daemon or keyring service
- a mail user agent or any MIME handling
- writing Legacy-format packet headers, v2 or v3 keys or v3 signatures, or treating MD5 as sound. Reading
  Legacy headers and v3 keys is in scope: RFC 9580 sec. 4.2 and 5.5.2 still define them, and an inventory
  that skipped them would drop real keys without saying so
- a compliance claim: interoperability evidence ships with the release, not before it



## Dependencies, and why there is exactly one

The owner's rule (2026-11-12): "we can use the cryptography package for RSA and AES and those
cryptographic primitives, but lets roll our own for everything else (even asn1 and cert parsing)".

So the one declared runtime dependency is the sibling `sigwire[verify]`, a strict verify-only seam over
`cryptography` (see [docs/verify-seam.md](docs/verify-seam.md)); until it is published it is a sibling
checkout that pytest and mypy find by path, as ctspy's does. Everything this package reads, packet framing,
armor, key, signature and subpacket parsing, fingerprints (`hashlib`) and the inventory, is its own code
and imports nothing outside the standard library; a test fails if a parse module imports anything else.
Only `pgpenv/crypto.py` reaches sigwire, and only when a signature is verified: `import pgpenv` loads
neither sigwire nor `cryptography`.

## Install

```bash
git clone https://github.com/b1tninja/pgpenv.git
cd pgpenv
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
```

Not published to PyPI yet. The name is reserved for this repository's trusted publisher at
the moment of the first release.

## Development

All four gates must pass, on Linux and Windows alike:

```bash
ruff check . && ruff format --check .
mypy pgpenv tests
pytest -q --cov
python -O -m pytest -q
```

The last line is the one that matters most in a protocol library. `-O` strips `assert`, and a
parser whose bounds checks were asserts stops being a parser under production flags. Wire
paths raise named exceptions; asserts belong in tests and nowhere else.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

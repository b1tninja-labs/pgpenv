# pgpenv

<!-- PyPI badges go live with the first release. Until then a version badge renders
     "no version" on the landing page, which reads as a defect rather than a date, so
     the badges stay commented out until the tag exists.
-->

**Pre-alpha shell.** The package surface, the obligation matrix and the CI gates exist.
No protocol behaviour is implemented: every public function raises `NotImplementedError`,
and the test suite records that rather than hiding it. Read
[ROADMAP.md](ROADMAP.md) before depending on any of it.

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

- version 6 keys and packets, plus a v4 reader for material that already exists
- AEAD encrypted sessions with the granularity rules the specification sets
- signature creation and verification that reports what it checked and what it refused
- key certifications and binding checks handled so the web of trust is not silently trusted
- armored streams with CRC-24 and line discipline that survive truncated input

## Specification spine

Status and publication dates below were read from the RFC Editor record on 2026-11-05. A
section number is cited only where that section was read in full; everything else cites the
document, which is the honest grain size for a plan. See [docs/rfc-map.md](docs/rfc-map.md).

| Document | Status | Published | What it gives this project |
|---|---|---|---|
| RFC 9580 | Proposed Standard | 2024-07 | the current format: packets, v6 keys, algorithm policy, AEAD |
| RFC 4880 | Obsolete | 2007-10 | the v4 wire a decade of material is still wearing; readable, never writable |
| RFC 4880bis | n/a | - | placeholder row: replace with the successor documents this project must consult |

### Errata watch

- RFC 9580 carries 7 verified errata. Read them before writing a single parser, because several concern key material encoding.
- RFC 9580 obsoletes RFC 4880, RFC 5581 and RFC 6637: recipes copied from those documents may describe behaviour it removed.

## Module layout

| Module | Responsibility |
|---|---|
| `packet` | packet framing, tags, old and new format headers (RFC 9580) |
| `key` | public keys, v4 and v6 fingerprints, subkeys (RFC 9580) |
| `signature` | signature packets and the hashing rules that bind them (RFC 9580) |
| `session` | symmetric and public key session key handling, AEAD granularity (RFC 9580) |
| `message` | literals, compression and the nesting that makes MIME work safe |
| `armor` | radix64 with CRC-24 headers and trailers (RFC 9580) |
| `crypto` | the seam onto cryptography, pinned to an allowed algorithm list |
| `limits` | bounds on packet size, nesting depth and key count on every parse path |

## What it does not do

- an agent, daemon or keyring service
- a mail user agent or any MIME handling
- compatibility with pre-standard PGP wire formats
- a compliance claim: interoperability evidence ships with the release, not before it



## Why this project has a runtime dependency

OpenPGP without an AEAD, HKDF and EdDSA backend means writing those primitives, which is a worse project than this one. One pinned dependency with no ceiling.

Declared as a floor with no ceiling: the application that installs this library resolves the final set, and a ceiling inside a library guarantees a conflict the first time something else needs a newer line.
## Install

```bash
git clone https://github.com/b1tninja/pgpenv.cd pgpenv
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
mypy pgpenv
pytest -q --cov
python -O -m pytest -q
```

The last line is the one that matters most in a protocol library. `-O` strips `assert`, and a
parser whose bounds checks were asserts stops being a parser under production flags. Wire
paths raise named exceptions; asserts belong in tests and nowhere else.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

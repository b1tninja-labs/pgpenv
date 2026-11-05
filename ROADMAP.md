# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation pgpenv could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where |
|---|---|---|---|
| `packet.iter_packets()` | RFC 9580 | `[ ]` | `tests/test_obligations.py::iter_packets` |
| `packet.encode_packet()` | RFC 9580 | `[ ]` | `tests/test_obligations.py::encode_packet` |
| `key.load_key()` | RFC 9580 | `[ ]` | `tests/test_obligations.py::load_key` |
| `key.fingerprint()` | RFC 9580 | `[ ]` | `tests/test_obligations.py::fingerprint` |
| `signature.sign()` | RFC 9580 | `[ ]` | `tests/test_obligations.py::sign` |
| `signature.verify()` | RFC 9580 | `[ ]` | `tests/test_obligations.py::verify` |
| `session.encrypt()` | RFC 9580 | `[ ]` | `tests/test_obligations.py::encrypt` |
| `session.decrypt()` | RFC 9580 | `[ ]` | `tests/test_obligations.py::decrypt` |
| `armor.encode()` | RFC 9580 | `[ ]` | `tests/test_obligations.py::encode` |
| `armor.decode()` | RFC 9580 | `[ ]` | `tests/test_obligations.py::decode` |
| `limits.check()` | design | `[ ]` | `tests/test_obligations.py::check` |

## 2. Milestones

- M1 packet framing and armor with adversarial input tests
- M2 v6 key parsing and fingerprints, v4 read path included
- M3 signature create and verify against RFC 9580 test material
- M4 classic and AEAD session encryption
- M5 certifications and binding checks, then the policy object
- M6 publication: 0.1.0 with an interop matrix against Sequoia and GnuPG

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 9580 carries 7 verified errata. Read them before writing a single parser, because several concern key material encoding.
- RFC 9580 obsoletes RFC 4880, RFC 5581 and RFC 6637: recipes copied from those documents may describe behaviour it removed.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| an agent, daemon or keyring service | `[no]` | a named document requires it |
| a mail user agent or any MIME handling | `[no]` | a named document requires it |
| compatibility with pre-standard PGP wire formats | `[no]` | a named document requires it |
| a compliance claim: interoperability evidence ships with the release, not before it | `[no]` | a named document requires it |

## 5. Open questions

- which algorithm policy is default, and whether v4 writing is ever offered

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented

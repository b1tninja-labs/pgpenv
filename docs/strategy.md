# Strategy

The completeness matrix is [../ROADMAP.md](../ROADMAP.md). This document is *why* the rows
are ordered the way they are, and the rules that order has to respect.

## The constitution

1. **The core is the specification implementation.** `pgpenv/` holds codecs, state machines
   and the vocabulary of pgpenv. New core code appears when a document defines the
   behaviour, or when an ordering rule with no document earns an explicit convention label.
2. **Sans-IO before sockets.** Anything decidable from data plus a clock is implemented
   without touching a socket, so every timeout, retry and rollover is testable without
   sleeping or networking.
3. **Dependency-free by default.** An exception needs a sentence in README.md explaining why
   the rule was broken, and a floor with no ceiling.
4. **Positioning is correctness and legibility, not throughput.** The incumbents in this
   corner are usually stale, untyped, or welded to a product. This is the implementation that
   says how it knows what it claims.
5. **Every answer carries its provenance.** Verified or cached, which document, refused or
   believed. An answer without provenance is a guess with a confident type.

## The three tiers

| Tier | Home | Contents | Rule |
|---|---|---|---|
| Core | `pgpenv/` | codecs, state machines, policy objects | RFC-cited or convention-labelled |
| Apps | `pgpenv/apps/` | reusable assemblies that compose core | no new protocol surface |
| Examples | `examples/` | one runnable script per use case | configures; never restates logic |

## Interface grammar

One engine, three drives, never parallel implementations:

- **await** -- the native asyncio surface.
- **blocking** -- a facade owning a private loop, so a call from inside a caller's running
  loop works instead of deadlocking.
- **callback** -- plain callables, no third-party promise type.

## Naming

One string everywhere: the distribution, the import and the console script. A name that
means one thing in the installer, in `import` and on `PATH` is the only arrangement that
cannot surprise anyone, and it is also why this project does not sit one edit away from a
project that already exists.

## Dependencies

The standard library is enough for everything this package parses: packet framing, armor, CRC-24, key and
signature packets, fingerprints (`hashlib` provides MD5, SHA-1, SHA-256 and SHA-512) and the inventory. It is
not enough for the arithmetic of RSA, DSA, ECDSA and EdDSA verification or for AES, OCB and the other
ciphers of session encryption, and writing those is a worse project than this one. The owner's rule of
2026-11-12: "we can use the cryptography package for RSA and AES and those cryptographic primitives, but lets
roll our own for everything else (even asn1 and cert parsing)". So `cryptography` stays the one declared
runtime dependency, kept at a floor with no ceiling, reached only through `pgpenv/crypto.py` and the
sibling `sigprim` seam (docs/verify-seam.md), and never from the parse layer; a test fails if a parse
module imports it.


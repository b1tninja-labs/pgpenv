# Instructions for coding agents

OpenPGP packet layer, v4 and v6 keys, encryption and signatures, AEAD encrypted sessions and the armored stream that carries them.

State on 2026-11-13: the read side is built (M1 packets, armor, cleartext; M2 keys, signatures, keyrings,
the `pkgtrust.keys/1` inventory) and so is verification (M3: `pgpenv.verification`, through `sigwire[verify]`).
Signing and encryption are not: those functions still raise `NotImplementedError`. `docs/inventory.md` is the
shape; `docs/verify-seam.md` is what verification calls and decides.

Primary documents are listed in `docs/rfc-map.md` with statuses and known errata.
The obligation table in `ROADMAP.md` records what is owed, and `README.md` explains
what the library is for. Read those three before changing anything.

## Finding work

If the person gave you a task, do that task.

If you arrived with nothing to do, run this from this directory:

    python -m projecthub pickup --who <your name> --project pgpenv

Its output is your assignment: one row, already claimed for you, with what to build, the commands that prove
it and the ways to end it. The board decides the order of work, so the row it gives you is the row to work,
even if it is in another project. `NO WORK` is a real answer: ask the person what to work on.

Without the workspace beside this repository, read `.projecthub/packet.md` if it exists. If it does not, ask what
to work on.

## Commands

    python -m pip install -e ".[dev]"
    python -m pytest -q
    python -m pytest -q tests/test_roadmap_rows.py
    python -m pytest -q tests/test_public_api.py::test_stubs_are_loud
    python -m ruff check .
    python -m ruff format --check .
    python -m mypy pgpenv tests
    python -m pgpenv inventory FILE --json

Run them with `PYTHONDONTWRITEBYTECODE=1`. The GnuPG cross-check in `tests/test_inventory.py` runs
`wsl.exe -d archlinux gpg --with-colons --show-keys` and skips when it is unavailable; fixtures are
regenerated with `tools/gen_gpg_fixtures.sh` (see `tests/data/PROVENANCE.txt`).

The first line installs the dev extras. The six commands after it are the gates,
and all six must pass before a change is finished. CI runs the same set on Linux
and Windows, plus the suite under `python -O`.

## Invariants

These are the points where a plausible-looking change makes the project wrong
rather than merely incomplete.

1. **Roadmap honesty.** Never change a `ROADMAP.md` row from `[ ]` to `[ok]` unless
   the test named in its `Where` cell exists, passes, and would fail if the behaviour
   regressed. A Where cell marked `(to be written)` names a test nobody has written:
   write it, then drop the marker in the same commit that flips the row.
   `tests/test_roadmap_rows.py` checks only that every row names a callable the
   package defines; it cannot tell a passing test from a missing one, so this rule
   is the check. Do not weaken that test, skip it, or delete it to get a green run.
2. **No silent stubs.** Code that is not implemented raises `NotImplementedError`.
   Never return an empty value, an empty collection, or a result object that reports
   success. A protocol library that answers nothing is worse than one that refuses
   to answer, and `tests/test_public_api.py` enforces that every stub is loud.
3. **Normative text is never paraphrased from memory.** Fetch it with `rfclib` and
   cite the section. If the text you fetch does not say what the obligation claims,
   the obligation is wrong: fix the roadmap row and say so in the commit.
4. **Dependencies, and the parse layer imports nothing.** `pyproject.toml` here declares one runtime
   dependency, cryptography, with the justification in `docs/strategy.md`. The owner's rule (2026-11-12):
   "we can use the cryptography package for RSA and AES and those cryptographic primitives, but lets roll our
   own for everything else (even asn1 and cert parsing)". So `cryptography` is for primitives only, reached
   through `pgpenv/crypto.py`, which reaches the sibling `sigwire[verify]` (see `docs/verify-seam.md`) and imports
   it lazily so that `import pgpenv` loads neither it nor `cryptography`.
   Packet, armor, cleartext, key, signature, certificate and inventory code is our own, imports only the
   standard library, and `tests/test_inventory.py::test_parse_layer_imports_only_the_standard_library`
   fails if that changes. Adding another runtime dependency needs a paragraph in `docs/strategy.md`.
5. **Scope.** What is deliberately absent is listed under Non-goals in `README.md`.
   An agent that "helpfully" implements a non-goal has expanded the API surface that
   has to be supported forever.
6. **Claimed is not valid.** The inventory reports what a file says (`"label": "claimed"`). Never add a
   field, a word or a return value that implies a signature was checked unless a verification ran; the
   checked facts belong to M3 and M5 and get their own fields.
7. **A verification answer is a status with the facts checked.** `valid` means a good signature by the given key over
   exactly the data given; never add a field or word that implies the key was valid, unexpired, unrevoked or trusted
   (the M5 rows). Refusals for what the signature or key does to itself are statuses, not exceptions (RFC 9580
   sec. 5.2.5); only misuse raises.
8. **Hostile input is ordinary input.** Every parse path takes `limits.Limits` and raises a `PgpError`
   subclass, never IndexError or struct.error; a malformed packet inside a keyring rejects that certificate
   and the walk resumes. New parsers get a case in `tests/test_hostile.py`.

## Read before implementing

- RFC 9580 carries 7 verified errata. Read them before writing a single parser, because several concern key material encoding.
- RFC 9580 obsoletes RFC 4880, RFC 5581 and RFC 6637: recipes copied from those documents may describe behaviour it removed.
- RFC 9980 extends RFC 9580 with ML-KEM, ML-DSA and SLH-DSA; it has no verified errata (1 on file) as of 2026-11-07 (rfclib).

## Protocol work

`.clinerules/10-rfclib.md` describes the `rfclib` calls to make for each obligation
and lists the section refs for this project. If you are not running in Cline, the
same procedure applies: confirm the document, read its errata, pull the normative
statements, then write code.

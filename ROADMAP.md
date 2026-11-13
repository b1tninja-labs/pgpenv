# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation pgpenv could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

A Where cell marked `(to be written)` names the test that will pin the row once it exists; no
such test has been written yet, and the row cannot leave `[ ]` until it has. The Milestone
column places the row on the ladder in section 2, and `-` means it is not placed yet.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

Everything marked `[ok]` below was read against RFC 9580
through the RFC library on 2026-11-12, including its verified errata (see section 3), and is
pinned by RFC 9580 appendix A vectors, by synthesised packets, or by GnuPG 2.4.9 output used as
an oracle. The parse-and-inventory layer imports only the standard library; the sibling
`sigprim` project (not yet started at that date) will carry verification.

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `packet.iter_packets()` | RFC 9580 sec. 4 | `[ok]` | `tests/test_packets.py::test_new_and_old_format_headers_decode_to_the_same_packet`, `tests/test_packets.py::test_partial_body_concatenation_matches_rfc_4_2_3`, `tests/test_hostile.py::test_partial_body_abuse_is_refused` | M1 |
| `packet.encode_packet()` | RFC 9580 sec. 4.2 | `[ok]` | `tests/test_packets.py::test_rfc_4_2_3_length_examples`, `tests/test_packets.py::test_length_boundaries_round_trip` | M1 |
| `packet.tag_info()` | RFC 9580 sec. 4.3, 5 | `[ok]` | `tests/test_packets.py::test_unknown_tags_are_preserved_and_classified`, `tests/test_hostile.py::test_unknown_critical_packet_rejects_that_certificate_only` | M1 |
| `packet.decode_length()` | RFC 9580 sec. 5.2.3.7 | `[ok]` | `tests/test_signature.py::test_subpacket_length_forms` | M1 |
| `armor.decode()` | RFC 9580 sec. 6.2 | `[ok]` | `tests/test_armor.py::test_bad_crc_is_not_a_rejection`, `tests/test_armor.py::test_a1_block_decodes_and_first_packet_is_tag_6` | M1 |
| `armor.decode_blocks()` | RFC 9580 sec. 6, 6.2 | `[ok]` | `tests/test_armor.py::test_two_blocks_and_garbage_between_them`, `tests/test_armor.py::test_damaged_armor_is_refused`, `tests/test_hostile.py::test_armor_damage_corpus` | M1 |
| `armor.encode()` | RFC 9580 sec. 6.2 | `[ok]` | `tests/test_armor.py::test_encode_infers_the_label_and_wraps_at_76`, `tests/test_armor.py::test_encode_never_emits_a_crc_by_default_and_checks_out_when_asked` | M1 |
| `armor.crc24()` | RFC 9580 sec. 6.1 | `[ok]` | `tests/test_armor.py::test_crc24_known_values`, `tests/test_armor.py::test_gnupg_checksums_verify` | M1 |
| `cleartext.parse()` | RFC 9580 sec. 7 | `[ok]` | `tests/test_armor.py::test_a6_cleartext_returns_the_exact_signed_text`, `tests/test_armor.py::test_nonconformant_headers_refuse_validation`, `tests/test_armor.py::test_dash_escaping_trailing_whitespace_and_line_endings` | M1 |
| `limits.check()` | design | `[part]` | `tests/test_packets.py::test_check_names_the_bound_that_was_exceeded`, `tests/test_hostile.py::test_too_many_keys_users_and_signatures_raise_a_limit_error` | M1 |
| `key.parse_public_key()` | RFC 9580 sec. 5.5.2, 5.5.5 | `[ok]` | `tests/test_key.py::test_v3_key_is_read_flagged_and_fingerprinted_with_md5`, `tests/test_key.py::test_native_algorithm_sizes_are_exact`, `tests/test_key.py::test_fixture_keys_cover_the_algorithm_set`, `tests/test_key.py::test_v6_refuses_legacy_curves_and_unnormalised_mpis` | M2 |
| `key.fingerprint()` | RFC 9580 sec. 5.5.4 | `[ok]` | `tests/test_key.py::test_v6_fingerprint_matches_rfc9580_appendix_a3`, `tests/test_key.py::test_v4_fingerprint_matches_rfc9580_appendix_a1`, `tests/test_inventory.py::test_fingerprints_and_key_facts_agree_with_gnupg` | M2 |
| `key.key_id()` | RFC 9580 sec. 5.5.4 | `[ok]` | `tests/test_key.py::test_key_id_is_the_first_64_bits_for_v6_and_the_last_for_v4` | M2 |
| `key.load_key()` | RFC 9580 sec. 5.5 | `[ok]` | `tests/test_key.py::test_v6_fingerprint_matches_rfc9580_appendix_a3`, `tests/test_key.py::test_load_key_requires_exactly_one_certificate` | M2 |
| `certificate.parse_keyring()` | RFC 9580 sec. 10.1 | `[ok]` | `tests/test_hostile.py::test_unknown_critical_packet_rejects_that_certificate_only`, `tests/test_hostile.py::test_unknown_noncritical_marker_trust_and_padding_packets_are_ignored`, `tests/test_hostile.py::test_random_corruption_never_escapes_as_a_foreign_exception`, `tests/test_key.py::test_load_key_requires_exactly_one_certificate` | M2 |
| `signature.parse_signature()` | RFC 9580 sec. 5.2.2, 5.2.3, 13.13 | `[ok]` | `tests/test_signature.py::test_issuer_fingerprint_is_read_from_hashed_area`, `tests/test_signature.py::test_unhashed_only_issuer_is_flagged_untrusted`, `tests/test_signature.py::test_ed25519_signature_material_is_not_parsed_as_mpi`, `tests/test_signature.py::test_v3_signature_is_read` | M2 |
| `signature.hash_stream()` | RFC 9580 sec. 5.2.4 | `[part]` | `tests/test_signature.py::test_a3_hash_streams_match_the_rfc_dumps`, `tests/test_signature.py::test_every_gnupg_signature_hashes_to_its_left_16_bits`, `tests/test_armor.py::test_a6_cleartext_returns_the_exact_signed_text` | M3 |
| `inventory.inventory()` | pkgtrust.keys/1, RFC 9580 sec. 10.1 | `[ok]` | `tests/test_inventory.py::test_a3_record_matches_the_rfc`, `tests/test_inventory.py::test_certification_issuer_to_target_with_issuer_known_in_the_same_file`, `tests/test_inventory.py::test_revoked_primary_key_is_claimed_with_reason_and_not_called_valid` | M2 |
| `inventory.inventory_report()` | pkgtrust.keys/1 | `[ok]` | `tests/test_inventory.py::test_json_shape`, `tests/test_inventory.py::test_detached_signature_and_cleartext_inventory`, `tests/test_inventory.py::test_a_lone_revocation_certificate_is_a_loose_signature` | M2 |
| `cli.main()` | pkgtrust.keys/1 | `[ok]` | `tests/test_inventory.py::test_cli_inventory_json`, `tests/test_inventory.py::test_cli_exit_status_is_1_when_content_was_refused` | M2 |
| `signature.sign()` | RFC 9580 sec. 5.2 | `[ ]` | `tests/test_obligations.py::test_sign` (to be written) | M3 |
| `signature.verify()` | RFC 9580 sec. 5.2 | `[ ]` | `tests/test_obligations.py::test_verify` (to be written) | M3 |
| `sig.v3_key_recipe` | RFC 9580 sec. 5.2.4 | `[ ]` | `tests/test_signature.py::test_v3_signature_over_a_v3_key_hash_stream` (to be written) | M3 |
| `session.encrypt()` | RFC 9580 | `[ ]` | `tests/test_obligations.py::test_encrypt` (to be written) | M4 |
| `session.decrypt()` | RFC 9580 | `[ ]` | `tests/test_obligations.py::test_decrypt` (to be written) | M4 |
| `msg.sequence` | RFC 9580 sec. 10.3, 10.4 | `[ ]` | `tests/test_message.py::test_message_grammar` (to be written) | M4 |
| `algo.rfc9980` | RFC 9980 | `[ ]` | `tests/test_key.py::test_post_quantum_algorithm_ids_are_named` (to be written) | M5 |
| `cert.binding` | RFC 9580 sec. 5.2.3.10, 10.1.5 | `[ ]` | `tests/test_certificate.py::test_binding_signatures_are_checked` (to be written) | M5 |
| `cert.expiry` | RFC 9580 sec. 5.2.3.13 | `[ ]` | `tests/test_certificate.py::test_expiry_comes_from_a_checked_self_signature` (to be written) | M5 |
| `cert.revoked` | RFC 9580 sec. 5.2.1.11, 5.2.3.31 | `[ ]` | `tests/test_certificate.py::test_revocation_is_checked_before_it_is_believed` (to be written) | M5 |
| `cert.userid_selfsig` | RFC 9580 sec. 5.2.3.10 | `[ ]` | `tests/test_certificate.py::test_user_id_self_signature_is_checked` (to be written) | M5 |
| `policy.algorithms` | RFC 9580 sec. 9.1, 9.5 | `[ ]` | `tests/test_policy.py::test_default_policy_refuses_md5_and_sha1_signatures` (to be written) | M5 |
| `wot.refuse` | RFC 9580 sec. 5.2.3.21 | `[ ]` | `tests/test_policy.py::test_no_function_reports_trust` (to be written) | M5 |

### 1.1 Notes on the rows

- **Everything in the inventory is claimed.** `inventory()` never says `valid`: it reports that a
  self-signature, certification or revocation is *present*, with its issuer and times. Checked
  facts are the M3 and M5 rows. See [docs/inventory.md](docs/inventory.md).
- **`limits.check()` is `[part]`** because the acceptance sentence proposed in section 5 is not
  accepted by the owner yet. The bounds themselves (`Limits`) are enforced on every parse path
  and pinned by the hostile corpus.
- **`signature.hash_stream()` is `[part]`.** It builds the exact hashed octets for every
  signature type RFC 9580 gives a recipe for, and the tests check them against the appendix A.2,
  A.3.1 and A.6 dumps and against the two quick-check octets of every certification, binding,
  revocation and back-signature GnuPG wrote. Missing: version 3 signatures over keys (the
  RFC 9580 text read does not give that recipe, so it raises `NotImplementedError`), and types
  0x40 and 0xFF, for which the RFC gives none.
- **The GnuPG cross-check skips** (it is not a failure) when neither `wsl.exe -d archlinux gpg`
  nor a local `gpg` runs. On 2026-11-12 it ran against GnuPG 2.4.9 and agreed on every
  fingerprint, key id, algorithm, size, creation time, expiry and capability of 10 files.
  One deliberate exception is documented in the test: GnuPG prints an expiry for a *revoked*
  subkey that its binding signature does not carry.
- **`signature.verify()` stays `[ ]`.** It will not be written inside this package's parse
  layer. [docs/verify-seam.md](docs/verify-seam.md) lists the exact `sigprim` calls it will make.
- **M5 rows** answer the question section 5 asked: certifications and binding checks, then the
  policy object. They depend on M3. `wot.refuse` records that no function here reports trust.

## 2. Milestones

- M1 packet framing and armor with adversarial input tests -- done 2026-11-12, including the
  cleartext signature framework
- M2 v6 key parsing and fingerprints, v4 read path included -- done 2026-11-12 for keys,
  signatures, subpackets, keyrings and the claimed inventory; v3 read-only
- M3 signature create and verify against RFC 9580 test material -- the hashed-data recipe is in
  (`signature.hash_stream()`); verification waits for `sigprim`; creation is deferred
- M4 classic and AEAD session encryption
- M5 certifications and binding checks, then the policy object
- M6 publication: 0.1.0 with an interop matrix against Sequoia and GnuPG

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit (45 to 85 with M1
and M2; measured 91% on 2026-11-12).

## 3. Errata watch

- RFC 9580 carries 7 verified errata. Read them before writing a single parser, because several concern key material encoding.
- RFC 9580 obsoletes RFC 4880, RFC 5581 and RFC 6637: recipes copied from those documents may describe behaviour it removed.
- RFC 9980 extends RFC 9580 with ML-KEM, ML-DSA and SLH-DSA; it has no verified errata (1 on file) as of 2026-11-07 (rfclib).

The verified errata, read through `errata('RFC9580')` on 2026-11-12, and where each is handled:

| eid | Section | Effect | Handled |
|---|---|---|---|
| 8454 | 5.2.3 | Ed25519 and Ed448 signatures are native octet strings, not MPIs | pinned by `test_ed25519_signature_material_is_not_parsed_as_mpi` |
| 8465, 8466 | 5.5.3, 11.2 | an EC point is not always an MPI: the native algorithms (X25519, X448, Ed25519, Ed448) have none | pinned by `test_native_algorithm_sizes_are_exact` |
| 8847 | 9.1 | a v3 PKESK for X25519 and X448 carries a symmetric algorithm octet | M4, not read into code yet |
| 8814 | 5.6 | ZLIB compressed data is RFC 1950, not raw blocks | M4, not read into code yet |
| 9094 | 12.1 | RFC 8017 is PKCS#1 v2.2, not v2.1 | editorial; M3 |
| 8432 | 16.1 | broken link | editorial |

Sections 4 and 6.1 have no verified erratum (`errata('RFC9580§6.1')` and `§4.2` return none).

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| an agent, daemon or keyring service | `[no]` | a named document requires it |
| a mail user agent or any MIME handling | `[no]` | a named document requires it |
| generating Legacy-format packet headers, version 2 or 3 keys, or version 3 signatures; treating MD5-based material as valid | `[no]` | a named document requires it |
| a compliance claim: interoperability evidence ships with the release, not before it | `[no]` | a named document requires it |

The third row used to read "compatibility with pre-standard PGP wire formats". RFC 9580 sec. 4.2
says the Legacy packet format MAY be used when consuming packets, and sec. 5.5.2 says version 3
keys MAY be accepted, so *reading* both is in scope and tested (`test_legacy_format_headers_are_read`,
`test_v3_key_is_inventoried_with_its_weakness_noted`). A key inventory that skipped them would
drop real keys without saying so. Only writing them, and believing MD5, are non-goals.

## 5. Open questions

- which algorithm policy is default, and whether v4 writing is ever offered
- acceptance for `limits.check()` (Spec: design, placed on M1): proposed as 'a packet stream that exceeds the packet size, nesting depth or key count bound raises before any further packet is decoded'; implemented and tested as proposed, and the row stays `[part]` until the owner accepts a sentence (D24)
- the default bounds in `limits.Limits` (packet 16 MiB, 2,000,000 packets, 4096 subpackets per area, embedded depth 3, 200,000 keys) are conventions of this project, chosen to admit the largest real keyrings; the owner may want them smaller
- which self-signature supplies a key's claimed expiry and flags is a convention (docs/inventory.md), because RFC 9580 sec. 5.2.3.9 and 5.2.3.10 leave the choice to the implementation
- the RFC 9980 algorithm identifiers are not read yet, so post-quantum keys are reported as `unknown(N)` with raw material (row `algo.rfc9980`)

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented

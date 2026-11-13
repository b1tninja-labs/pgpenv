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
an oracle. The parse-and-inventory layer imports only the standard library; verification (M3, 2026-11-13) is the one place that imports anything else:
`pgpenv/crypto.py` reaches the sibling `sigwire[verify]` seam, and only when a signature is verified.

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
| `signature.verify()` | RFC 9580 sec. 5.2, 5.2.4 | `[ok]` | `tests/test_verification.py::test_a2_v4_ed25519legacy_signature_verifies_under_the_a1_key`, `tests/test_verification.py::test_a2_other_document_and_flipped_signature_bits_are_invalid`, `tests/test_verification.py::test_a_mutated_signature_never_raises_and_never_validates`, `tests/test_verification.py::test_misuse_raises_instead_of_answering`; a thin entry point to `pgpenv.verification.verify_document` (see the `verify.*` rows) | M3 |
| `sig.v3_key_recipe` | RFC 9580 sec. 5.2.4 | `[part]` | `tests/test_verification.py::test_v3_signature_over_a_v3_key_hash_stream`, `tests/test_signature.py::test_v3_signature_is_read` -- SYNTHETIC: a throwaway RSA key made the v3 key and its certification over octets assembled from the RFC prose; GnuPG 2.4.9 skips version 3 keys on import ("skipped PGP-2 keys") and no other OpenPGP implementation was available, so no independent verifier accepted it | M3 |
| `verify.document` binary, text and standalone signatures, v4 and v6 | RFC 9580 sec. 5.2.1.1 to 5.2.1.3, 5.2.4, 5.2.3.6; appendix A.2, A.7 | `[ok]` | `tests/test_verification.py::test_a2_v4_ed25519legacy_signature_verifies_under_the_a1_key`, `tests/test_verification.py::test_a7_inline_signed_message_verifies_over_its_literal_data`, `tests/test_verification.py::test_a_certificate_chooses_the_signing_key_by_the_issuer_subpackets`, `tests/test_verification_gnupg.py::test_gnupg_binary_and_text_signatures_verify_under_the_openpgp_policy` (RSA, ECDSA P-256, P-384 and P-521, Ed25519 by GnuPG 2.4.9 in WSL; the RFC's Ed25519Legacy and v6 Ed25519) | M3 |
| `verify.cleartext` every signature of a cleartext signed message | RFC 9580 sec. 7, 7.1; appendix A.6 | `[ok]` | `tests/test_verification.py::test_a6_cleartext_message_verifies_with_the_a3_certificate`, `tests/test_verification.py::test_a6_edited_text_is_invalid_and_trailing_spaces_are_not_part_of_the_text`, `tests/test_verification_gnupg.py::test_gnupg_cleartext_signatures_verify_and_gnupg_agrees` | M3 |
| `verify.binding` subkey binding (0x18) and subkey revocation (0x28) | RFC 9580 sec. 5.2.1.8, 5.2.1.12, 5.2.4; appendix A.3.1 | `[ok]` | `tests/test_verification.py::test_a3_direct_key_and_subkey_binding_verify_and_the_certificate_walk_agrees`, `tests/test_verification.py::test_a3_binding_checked_over_the_wrong_keys_is_invalid_not_valid`, `tests/test_verification.py::test_the_gnupg_ed25519_walk_covers_bindings_back_signatures_and_a_revoked_subkey` | M3 |
| `verify.back_signature` primary key binding (0x19) embedded in a binding, made by the subkey | RFC 9580 sec. 5.2.1.9 | `[ok]` | `tests/test_verification.py::test_the_gnupg_ed25519_walk_covers_bindings_back_signatures_and_a_revoked_subkey` (GnuPG 2.4.9 output) | M3 |
| `verify.certification` certifications (0x10 to 0x13), certification revocation (0x30), direct key (0x1F) and key revocation (0x20) | RFC 9580 sec. 5.2.1.4 to 5.2.1.7, 5.2.1.10, 5.2.1.11, 5.2.4 | `[ok]` | `tests/test_verification.py::test_a_third_party_certification_is_checked_against_its_issuer_key`, `tests/test_verification.py::test_the_gnupg_nistp256_revocation_signature_is_a_valid_key_revocation`, `tests/test_verification_gnupg.py::test_gnupg_made_certificates_have_valid_self_signatures_under_the_policy` | M3 |
| `verify.selfsigs` `check_self_signatures()`: every signature the primary key should have made, as facts, not as what is in force | RFC 9580 sec. 5.2.4, 10.1 | `[ok]` | `tests/test_verification.py::test_the_gnupg_ed25519_walk_covers_bindings_back_signatures_and_a_revoked_subkey`, `tests/test_verification.py::test_check_self_signatures_reports_a_v3_certification`; this reports what verified: no expiry, revocation or primary-user-ID decision, which are the M5 rows | M3 |
| `verify.status` five statuses plus `no-key`: `refused` (policy), `unsupported`, `malformed` (RFC 9580 sec. 5.2.5, 10.3.2.2 Table 27, the MUSTs of 5.2.3.2 to 5.2.3.5) | RFC 9580 sec. 5.2.3, 5.2.5, 9.5, 10.3.2.2, 12.4, 12.5 | `[ok]` | `tests/test_verification.py::test_policy_decides_refused_unsupported_and_legacy`, `tests/test_verification.py::test_a_version_6_key_and_a_version_4_signature_do_not_pair_and_the_reverse`, `tests/test_verification.py::test_a_signature_with_problems_is_malformed_never_valid`, `tests/test_verification.py::test_a_digest_shorter_than_the_algorithm_needs_is_malformed`, `tests/test_verification.py::test_a_signature_whose_issuer_is_not_among_the_keys_is_no_key`, `tests/test_verification_gnupg.py::test_the_legacy_policy_verifies_dsa_and_sha1_that_the_openpgp_policy_refuses` | M3 |
| `verify.seam` only `pgpenv/crypto.py` reaches `sigwire[verify]`, lazily; refusals become pgpenv errors | owner rule 2026-11-12; PORTFOLIO.md section 9 item 15 | `[ok]` | `tests/test_verification.py::test_the_seam_translates_sigwire_refusals_into_pgpenv_errors`, `tests/test_verification.py::test_importing_verification_loads_neither_cryptography_nor_sigwire`, `tests/test_inventory.py::test_parse_layer_imports_only_the_standard_library` | M3 |
| `verify.ecdsa.brainpool` ECDSA on brainpoolP256r1, P384r1, P512r1 | RFC 9580 sec. 9.2; RFC 5639 sec. 3 (read 2026-11-13) | `[ok]` | `tests/test_verification_gnupg.py::test_gnupg_binary_and_text_signatures_verify_under_the_openpgp_policy` (GnuPG 2.4.9 made keys and binary and text signatures on all three curves; `tests/test_verification_gnupg.py::test_gnupg_agrees_with_pgpenv_on_every_binary_signature` has GnuPG say "Good signature" for each), `tests/test_verification_gnupg.py::test_gnupg_cleartext_signatures_verify_and_gnupg_agrees`, `tests/test_verification.py::test_policy_decides_refused_unsupported_and_legacy` (the committed GnuPG brainpoolP256r1 certification verifies; a curve OID outside Table 19 stays `unsupported`); the curve constants and the `openpgp` and `legacy` policy cells are sigwire's (`sw.verify.seam.ecdsa.brainpool`) | M3 |
| `verify.ed448` Ed448 signatures | RFC 9580 sec. 5.2.3.5, 12.7 | `[part]` | `tests/test_verification.py::test_ed448_certification_signed_by_libgcrypt_verifies`, `tests/test_verification.py::test_ed448_with_a_hash_under_512_bits_is_malformed` -- the 114 signature octets are real Ed448 made by libgcrypt 1.12.2 (an implementation independent of OpenSSL; the same program reproduces the RFC 8032 section 7.4 "Blank" signature byte for byte) over the SHA-512 of a stream assembled in the test, with the RFC 8032 key; but no OpenPGP implementation available made an Ed448 packet (RFC 9580 has no sample, GnuPG 2.4.9 stops at Ed25519), so the framing was read by pgpenv alone | M3 |
| `verify.rsa.sha3` RSA PKCS #1 v1.5 with SHA3-256 and SHA3-512 | RFC 9580 sec. 9.5 Table 24 | `[part]` | `tests/test_verification.py::test_v4_rsa_certification_with_sha3_verifies` -- SYNTHETIC: a throwaway RSA key and OpenSSL made the signature over octets assembled in the test; the DigestInfo prefixes are RFC 9580 Table 24, added to sigwire for this (`sw.verify.seam.rsa.sha3-pkcs1`); no real OpenPGP SHA-3 signature is known (GnuPG 2.4.9 offers none); SHA3-224 and SHA3-384 have no DigestInfo anywhere in the RFCs read | M3 |
| `verify.time` the creation-time half of sec. 9.5: MUST NOT validate a recent MD5, SHA-1 or RIPEMD-160 signature, SHOULD NOT validate an old one unless it predates the weakness | RFC 9580 sec. 9.5 | `[ ]` | today the `openpgp` policy refuses those hashes outright and `legacy` allows them with a warning; the "recent" and "old" cut-off is a policy decision with no date given by the RFC (to be written) | M5 |
| `session.encrypt()` | RFC 9580 | `[ ]` | `tests/test_obligations.py::test_encrypt` (to be written) | M4 |
| `session.decrypt()` | RFC 9580 | `[ ]` | `tests/test_obligations.py::test_decrypt` (to be written) | M4 |
| `msg.sequence` | RFC 9580 sec. 10.3, 10.4 | `[ ]` | `tests/test_message.py::test_message_grammar` (to be written) | M4 |
| `algo.rfc9980` | RFC 9980 | `[ ]` | `tests/test_key.py::test_post_quantum_algorithm_ids_are_named` (to be written) | M5 |
| `cert.binding` a subkey is bound only by a verified 0x18 by its primary, and a signing subkey also needs a verified embedded 0x19 | RFC 9580 sec. 5.2.1.8, 5.2.3.10, 5.2.3.29 | `[ok]` | `tests/test_certificate.py::test_binding_signatures_are_checked`, `tests/test_certificate.py::test_a_signing_subkey_needs_its_back_signature`, `tests/test_certificate.py::test_signatures_that_do_not_verify_are_listed_and_decide_nothing` (GnuPG 2.4.9 keys; `pgpenv.validity.assess`) | M5 |
| `cert.expiry` expiry read from the newest verified self-signature that applies, counted from the key's own creation time; an expired self-signature decides nothing | RFC 9580 sec. 5.2.3.13, 5.2.3.18 | `[ok]` | `tests/test_certificate.py::test_expiry_comes_from_a_checked_self_signature` (GnuPG rsa2048, agreeing with the inventory; a damaged certification gives no expiry), `tests/test_certificate.py::test_an_expired_self_signature_is_not_considered` (synthetic) | M5 |
| `cert.revoked` only a verified revocation by the primary key counts; code 1 and 3 take effect at their own creation time, anything else at every time | RFC 9580 sec. 5.2.1.11, 5.2.1.12, 5.2.3.31 | `[ok]` | `tests/test_certificate.py::test_revocation_is_checked_before_it_is_believed` (GnuPG key revocation, reason 2, also attached to another key and damaged), `tests/test_certificate.py::test_a_superseded_subkey_is_revoked_from_its_revocation_time_not_before` (GnuPG subkey revocation, reason 1) | M5 |
| `cert.userid_selfsig` a User ID is certified by a verified self-certification and retired by a verified 0x30 at least as new | RFC 9580 sec. 5.2.3.10, 5.2.3.31 | `[part]` | `tests/test_certificate.py::test_user_id_self_signature_is_checked` (GnuPG certifications) -- the retirement and its tie rule are pinned by `tests/test_certificate.py::test_a_certification_revocation_retires_the_user_id_unless_certified_again` on SYNTHETIC signatures (throwaway RSA key); no GnuPG-made 0x30 is stored, and the tie rule is this module's decision because the RFC gives none | M5 |
| `cert.revoked.revocation-key` the deprecated Revocation Key (designated revoker) mechanism | RFC 9580 sec. 5.2.1.11 | `[ ]` | not read: a revocation by a designated revoker is ignored today (`tests/test_certificate.py::test_revocation_by_a_designated_revoker_is_counted` (to be written)) | M5 |
| `cert.revoked.direct-key-revocation` a 0x30 revoking a Direct Key signature (0x1F) cancels it | RFC 9580 sec. 5.2.1.13 | `[ ]` | `validity` reads 0x30 on User IDs only, so a revoked direct key signature still supplies the key's expiry (`tests/test_certificate.py::test_a_revoked_direct_key_signature_supplies_no_expiry` (to be written)) | M5 |
| `cert.userid_selfsig.real-retire` a GnuPG-made certification revocation (`gpg --quick-revoke-uid`) in `tests/data/gnupg` | RFC 9580 sec. 5.2.1.13 | `[ ]` | would move `cert.userid_selfsig` to `[ok]` (`tests/test_certificate.py::test_gnupg_retired_user_id_is_retired` (to be written)) | M5 |
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
  revocation and back-signature GnuPG wrote. Version 3 signatures over keys are built as well (the
  recipe is the one sec. 5.2.4 states for every key signature, with the version 3 certification
  hashing the User ID bare) but only a synthetic signature pins them, see `sig.v3_key_recipe`. Missing: types
  0x40 and 0xFF, for which the RFC gives no recipe.
- **The GnuPG cross-check skips** (it is not a failure) when neither `wsl.exe -d archlinux gpg`
  nor a local `gpg` runs. On 2026-11-12 it ran against GnuPG 2.4.9 and agreed on every
  fingerprint, key id, algorithm, size, creation time, expiry and capability of 10 files.
  One deliberate exception is documented in the test: GnuPG prints an expiry for a *revoked*
  subkey that its binding signature does not carry.
- **Verification (M3) is a status, not a boolean.** `verify_document`, `verify_cleartext`,
  `verify_binding`, `verify_back_signatures`, `verify_certification`, `verify_direct_key` and
  `check_self_signatures` (`pgpenv.verification`) return a `Verification`: `valid`, `invalid`, `malformed`,
  `unsupported`, `refused` or `no-key`, with the facts that were checked (`hash`, `left16`, `signature`)
  and the deprecations that applied. `valid` means a good signature by the given key over exactly the data
  given, nothing about the key's validity, expiry, revocation or trust. The primitives are sigwire's
  (`docs/verify-seam.md`). Evidence: RFC 9580 appendix A.2, A.3, A.6 and A.7, and GnuPG 2.4.9 in WSL for RSA,
  ECDSA P-256, P-384 and P-521, Ed25519 and (under the `legacy` policy) DSA; v6 keys and signatures are
  covered by the RFC vectors only, because GnuPG 2.4 makes none. Skips when WSL or GnuPG is missing.
- **M5 rows** answer the question section 5 asked: certifications and binding checks, then the
  policy object. They depend on M3. `wot.refuse` records that no function here reports trust.

## 2. Milestones

- M1 packet framing and armor with adversarial input tests -- done 2026-11-12, including the
  cleartext signature framework
- M2 v6 key parsing and fingerprints, v4 read path included -- done 2026-11-12 for keys,
  signatures, subpackets, keyrings and the claimed inventory; v3 read-only
- M3 signature create and verify against RFC 9580 test material -- verification done 2026-11-13
  (`pgpenv.verification`, through `sigwire[verify]`); Brainpool is done, Ed448 and SHA-3 under RSA are `[part]`
  rows above (signatures no other OpenPGP implementation read); creation is deferred
- M4 classic and AEAD session encryption
- M5 certifications and binding checks, then the policy object -- binding, expiry, revocation and
  User ID certification done 2026-11-13 as `pgpenv.validity.assess` (the policy object, `verify.time` and
  `wot.refuse` are open)
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
| 9094 | 12.1 | RFC 8017 is PKCS#1 v2.2, not v2.1 | editorial; read for M3, nothing in the code depends on the version |
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

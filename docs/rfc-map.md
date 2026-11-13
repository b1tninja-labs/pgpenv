# Where every claim in this repository comes from

| Document | Status | Published | Verified against the publisher record on |
|---|---|---|---|
| RFC 9580 | Proposed Standard | 2024-07 | 2026-11-05 |
| RFC 4880 | Obsolete | 2007-11 | 2026-11-05 |
| RFC 9980 | Proposed Standard | 2026-06 | 2026-11-05 |

Citation rules, in the order they most often get broken:

1. Cite the document. A secondary write-up is a lead, not a source.
2. A section number is cited only if that section was read in full.
3. Errata are checked at each milestone freeze, not once at the start.
4. Where a claim came from a body outside the RFC series, that body is named here.

Re-verify with the RFC library rather than memory: `info('RFCnnnn')` for current status, `errata('RFCnnnn')` for corrections, and `read('RFCnnnn', view='normative')` for the MUST and SHOULD statements that become obligation rows.

## Sections read in full, and what was built from them

Read through rfclib on 2026-11-12 (RFC 9580 is current, Proposed Standard, 7 verified errata, obsoletes RFC 4880, RFC 5581 and RFC 6637). A section is cited in code only if it is in this table.

| RFC 9580 section | Read | Used by |
|---|---|---|
| 3.1, 3.2, 3.5 scalars, MPIs, time | yes | `wire.read_mpi`, key and signature parsers (v6 MPIs must be normalised) |
| 4 (4.1 to 4.3) packet headers, lengths, partial bodies, criticality | yes | `packet.iter_packets`, `encode_packet`, `tag_info`, `decode_length` |
| 5 table of packet types | yes | `packet.TAGS` |
| 5.2 (5.2.1 to 5.2.5) signature types, v3 and v4/v6 layouts, subpackets, computing signatures, malformed signatures | yes | `signature.parse_signature`, `hash_stream`, `registry.SIGNATURE_TYPES`, `SUBPACKET_NAMES` |
| 5.5 (5.5.1 to 5.5.5) key packets, fingerprints, key ids, algorithm-specific material | yes | `key.parse_public_key` |
| 5.10, 5.11, 5.12 trust, user id, user attribute | yes | `certificate.parse_keyring` (trust ignored, uid text, uat kept opaque) |
| 6 (6.1, 6.2) armor, checksum, headers | yes | `armor`: the CRC-24 is advisory, a reader MUST NOT reject on it (6.1) |
| 7 (7.1 to 7.3) cleartext signature framework | yes | `cleartext.parse` |
| 9.1 to 9.6 algorithm, curve, hash tables | yes (9.3, 9.4, 9.6 for names only) | `registry` |
| 10.1 transferable public keys | yes | `certificate` |
| 13.13 hashed versus unhashed subpackets | via 5.2.3.6 and 5.2.5 | `Signature.issuer_area` |
| Appendix A.1, A.2, A.3, A.3.1, A.6, A.7 | yes | `tests/vectors.py` |

Not read yet, so not implemented: 5.1, 5.3, 5.4, 5.6 to 5.9, 5.13 and 5.14 (message packets), 10.2 to 10.4, 11 and 12 (ECDH and algorithm notes), 13.1 to 13.12, appendix A.4, A.5 and A.8 to A.12, and all of RFC 9980.

Errata in this scope (`errata('RFC9580')`, 7 verified): 8454 (native Ed25519/Ed448 signatures, section 5.2.3), 8465 and 8466 (EC points are not always MPIs, 5.5.3 and 11.2), both handled. 8847 (9.1) and 8814 (5.6) concern encryption and compression and wait for M4. `errata('RFC9580§6.1')` and `§4.2` returned none.

Body outside the RFC series: GnuPG 2.4.9 (libgcrypt 1.12.2), run in WSL archlinux, is the oracle for the cross-check and generated the fixtures in `tests/data/gnupg`; see `tests/data/PROVENANCE.txt`. The `pkgtrust.keys/1` shape comes from the pkgtrust signature research of 2026-11-12, not from an RFC (docs/inventory.md).


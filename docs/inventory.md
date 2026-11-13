# The inventory: `pkgtrust.keys/1`

`python -m pgpenv inventory FILE --json` and `pgpenv.inventory.inventory_report(data)` describe what an
OpenPGP file *claims*. They are the read-only half of OpenPGP: no signature is verified, so nothing is ever
called valid, and a forged self-signature produces the same record as a real one. The record is the shape
proposed in the pkgtrust signature research (2026-11-12, section 2). Verification is a second pass
(ROADMAP.md M3, through `sigwire[verify]`; done 2026-11-13, see docs/verify-seam.md) whose results will be separate fields with their own labels.

What it is made from: fingerprints, key ids, sizes and curves are computed from the key packets by pgpenv
(RFC 9580 sec. 5.5.4), never copied from a file. Everything else is read from packets and subpackets as
written.

## Using it

```bash
python -m pgpenv inventory keyring.gpg --json      # binary or armored, one key or many
python -m pgpenv inventory InRelease --json        # cleartext message: signatures plus signed-text hash
python -m pgpenv inventory package.sig --json      # a detached signature: a loose "signatures" entry
python -m pgpenv inventory - < keys.asc            # standard input
```

Exit status: 0 read and nothing refused; 1 output produced but some content was refused (see `rejected`);
2 usage error, unreadable file, or input that is not OpenPGP at all. A refused certificate does not stop the
next one: the walk resumes at the next primary key.

In code:

```python
from pgpenv.inventory import inventory, inventory_report
records = inventory(open("keyring.gpg", "rb").read())      # list[KeyRecord]
report = inventory_report(data, path="keyring.gpg")        # also rejected, loose signatures, armor facts
```

## The document

```text
{
  "schema": "pkgtrust.keys/1",
  "label": "claimed",
  "generator": {"name": "pgpenv", "version": "..."},
  "source": {"path": str|null, "bytes": int, "sha256": hex},
  "armor": [{"label": "PGP PUBLIC KEY BLOCK", "headers": [[k, v]], "crc": "absent|ok|mismatch|malformed", "notes": []}],
  "keys": [ KeyRecord ],
  "signatures": [ SignatureRecord ],        # signatures outside any certificate: detached, cleartext, revocation certificates
  "cleartext": null | {"accepted": bool, "signed_text_bytes", "signed_text_sha256", "hash_headers", "warnings"} | {"accepted": false, "refusal": str},
  "rejected": [{"offset": int, "block": int|null, "reason": str}],
  "other_packets": [{"tag": int, "name": str, "offset": int}],   # critical packets outside a certificate (literal data, ...)
  "packet_counts": {"PUBKEY(6)": n, ...},
  "problems": [str]
}
```

Times are given twice, as `X` (seconds since the epoch, or `null`) and `X_utc` (`YYYYMMDDTHHMMSSZ`, the form
pkgtrust's other records use). Hex is upper case, except `left16` and `signed_text_sha256`.

### KeyRecord

| Field | Meaning |
|---|---|
| `label` | always `"claimed"` |
| `fingerprint`, `keyid` | computed: v3 MD5, v4 SHA-1 (0x99), v6 SHA-256 (0x9B); key id is the low 64 bits (v3, v4) or high (v6) |
| `version` | key packet version (3, 4 or 6; 2 is read as 3) |
| `algorithm` | `{id, name, bits, curve, deprecated}`. `bits` is the RSA/DSA/Elgamal modulus size or the nominal curve size (255 for the Curve25519 family, as GnuPG reports); `deprecated` follows RFC 9580 sec. 9.1 and 5.5.5 |
| `secret_material_present` | the file held a Secret Key packet. Only its public part was read; no secret octet is copied anywhere |
| `created`, `expires` | key creation; expiry from the chosen self-signature, or the v3 validity field, `null` = none |
| `expiry_source` | `direct_key`, `primary_user_id`, `user_id`, `v3_key_packet` or `null`: which claim `expires` and `flags` came from |
| `flags`, `flags_raw` | names from the Key Flags subpacket (`certify`, `sign`, `encrypt_communications`, `encrypt_storage`, `authenticate`, `split`, `shared`, ...) and the raw octets |
| `self_signature_hashes` | hash algorithms used by the key's self-signatures, e.g. `["SHA2-512"]` (is the key only SHA-1 signed?) |
| `revoked_claimed` | a revocation signature *by the key itself* is present |
| `user_ids` | `{kind: id|attribute, text, self_signed, primary_claimed, newest_self_signature(_utc), revoked_claimed, signature_count}` |
| `certifications` | one per certification signature (types 0x10 to 0x13): `{target_fingerprint, user_id, type, type_name, self, issuer_keyid, issuer_fingerprint, issuer_area, created, expires, hash_name, exportable, trust, issuer_in_file}`. The issuer may be a key the file does not contain; the id is recorded anyway and `issuer_in_file` says whether it is there |
| `revocations` | key (0x20), subkey (0x28) and certification (0x30) revocations: `{scope, target_fingerprint, user_id, reason_code, reason, reason_text, self, issuer_*, created, hash_name}` |
| `subkeys` | `{fingerprint, keyid, version, algorithm, created, expires, flags, binding{created, hash_name, back_signature_embedded, issuer_*}, revoked_claimed, revocations, problems}` |
| `problems` | what the parser noted: malformed or skipped signatures, a v6 key with no direct key signature, a subkey with no binding, deprecated versions |
| `offset` | where the certificate starts in the (decoded) stream |

`issuer_area` is `hashed`, `unhashed`, `v3` or `null`. An issuer read only from the unhashed area is
advisory: it is not covered by the signature (RFC 9580 sec. 5.2.3.6, 13.13).

### SignatureRecord

`{label, version, type, type_name, pub_algo(_name), hash_algo/hash_name, created(_utc), expires(_utc),
issuer_keyid, issuer_fingerprint, issuer_area, signer_user_id, key_flags, key_expires_after, primary_user_id,
exportable, revocable, revocation{code, reason, text}, preferences{hash, symmetric, aead}, notations,
unhashed_subpackets[{type, name, critical}], embedded_signatures, salt_length, left16, usable, problems}`.
`usable: false` means the packet is malformed or unknown in the sense of RFC 9580 sec. 5.2.5 (an unknown
critical subpacket in the hashed area, a diverging subpacket length, a salt that does not match the hash,
MD5): a verifier must ignore it, and `problems` says why.

## How the claimed facts are chosen

RFC 9580 leaves the selection to the implementation (sec. 5.2.3.9, 5.2.3.10), so these are conventions of
this project:

- expiry and flags of the primary key come from the newest direct key self-signature if there is one (what
  sec. 5.2.3.10 recommends for version 6), else the newest self-certification on the User ID marked primary,
  else the newest self-certification on any User ID;
- a subkey's expiry and flags come from its newest binding signature (type 0x18), relative to the subkey's
  own creation time; with no Key Expiration subpacket the claim is "never expires" (sec. 5.2.3.13);
- when several subpackets of one kind sit in the hashed area, the last wins (sec. 5.2.3.9);
- a certification is `self` when its issuer fingerprint, or failing that its issuer key id, equals the
  primary key's; binding, direct key and revocation signatures are by the primary key by definition and are
  `self` unless they name another issuer;
- a revocation by another key is listed but does not set `revoked_claimed`.

## What is not here, deliberately

No trust, no validity, no web of trust (`wot.refuse` in ROADMAP.md). No decompression: a Compressed Data
packet is recognised by tag and left alone. No secret key material. Unknown non-critical packets, Marker,
Trust and Padding packets are ignored but counted in `packet_counts`; an unknown or misplaced *critical*
packet rejects its certificate (RFC 9580 sec. 4.3, 10).

## Cross-check

`tests/test_inventory.py::test_fingerprints_and_key_facts_agree_with_gnupg` compares fingerprint, key id,
algorithm, size, creation time, expiry and capabilities with `gpg --with-colons --show-keys` (GnuPG 2.4.9 in
WSL `archlinux` on 2026-11-12) for ten inputs, and skips if no `gpg` runs. See `tests/data/PROVENANCE.txt`.

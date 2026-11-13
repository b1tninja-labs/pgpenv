"""Key and signature inventory: what an OpenPGP file claims, in the ``pkgtrust.keys/1`` shape.

Everything here is *claimed*. Nothing is verified: a fingerprint is computed by pgpenv from the
key packet, but a self-signature, a certification or a revocation is reported as present, with its
issuer, its time and its subpackets, and never as valid. The same record would be produced for a
forged signature. Verification is a separate pass (ROADMAP.md M3, ``sigprim``), and its results
will be separate fields with their own labels, so a consumer cannot mistake one for the other.

How the claimed facts are chosen, which are conventions of this project because RFC 9580 leaves
the selection to the implementation (sec. 5.2.3.9, 5.2.3.10):

* *expiry and flags of the primary key* come from the newest direct key self-signature if there is
  one (what sec. 5.2.3.10 recommends for version 6), else from the newest self-certification on the
  User ID marked primary, else from the newest self-certification on any User ID; ``expiry_source``
  says which. A missing or zero Key Expiration subpacket means no expiry.
* *a subkey's expiry and flags* come from its newest binding signature (type 0x18).
* *revoked_claimed* is true when the key, subkey or User ID carries a revocation signature issued
  by the key itself. A revocation by another key is listed with ``self: false`` and does not set
  the flag, because only the (deprecated) Revocation Key mechanism lets another key revoke.
* *self* for a certification means the issuer fingerprint, or failing that the issuer key id,
  equals the primary key's. Binding, direct key and revocation signatures are made by the primary
  key by definition, so they count as self unless they name a different issuer.

Times are given twice: ``created`` in seconds since the epoch and ``created_utc`` as
``YYYYMMDDTHHMMSSZ``, the form pkgtrust's other records use.
"""

from __future__ import annotations

import datetime as dt
import hashlib
from dataclasses import dataclass, field
from typing import Any

from .certificate import Certificate, Keyring, parse_keyring
from .cleartext import parse as parse_cleartext
from .errors import CleartextError
from .key import PublicKey
from .limits import DEFAULT_LIMITS, Limits
from .packet import tag_info
from .registry import (
    AEAD_NAMES,
    REVOCATION_REASONS,
    SYMMETRIC_NAMES,
    hash_name,
    key_flag_names,
    pk_name,
    signature_type_name,
)
from .signature import Notation, Signature

__all__ = [
    "SCHEMA",
    "Inventory",
    "KeyRecord",
    "inventory",
    "inventory_report",
]

SCHEMA = "pkgtrust.keys/1"
_CERT_TYPES = (0x10, 0x11, 0x12, 0x13)


def _utc(epoch: int | None) -> str | None:
    if epoch is None:
        return None
    return dt.datetime.fromtimestamp(epoch, dt.UTC).strftime("%Y%m%dT%H%M%SZ")


def _times(prefix: str, epoch: int | None) -> dict[str, Any]:
    return {prefix: epoch, f"{prefix}_utc": _utc(epoch)}


def _hex(value: bytes | None) -> str | None:
    return None if value is None else value.hex().upper()


@dataclass(slots=True)
class KeyRecord:
    """One certificate as claimed by the file. See the module docstring for how fields are chosen."""

    fingerprint: str
    keyid: str
    version: int
    algorithm_id: int
    algorithm: str
    bits: int | None
    curve: str | None
    deprecated_algorithm: bool
    secret_material_present: bool
    created: int
    expires: int | None
    expiry_source: str | None
    flags: list[str]
    flags_raw: str | None
    self_signature_hashes: list[str]
    user_ids: list[dict[str, Any]] = field(default_factory=list)
    certifications: list[dict[str, Any]] = field(default_factory=list)
    revocations: list[dict[str, Any]] = field(default_factory=list)
    subkeys: list[dict[str, Any]] = field(default_factory=list)
    revoked_claimed: bool = False
    problems: list[str] = field(default_factory=list)
    offset: int = 0
    label: str = "claimed"

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "label": self.label,
            "fingerprint": self.fingerprint,
            "keyid": self.keyid,
            "version": self.version,
            "algorithm": {
                "id": self.algorithm_id,
                "name": self.algorithm,
                "bits": self.bits,
                "curve": self.curve,
                "deprecated": self.deprecated_algorithm,
            },
            "secret_material_present": self.secret_material_present,
            **_times("created", self.created),
            **_times("expires", self.expires),
            "expiry_source": self.expiry_source,
            "flags": self.flags,
            "flags_raw": self.flags_raw,
            "self_signature_hashes": self.self_signature_hashes,
            "revoked_claimed": self.revoked_claimed,
            "user_ids": self.user_ids,
            "certifications": self.certifications,
            "revocations": self.revocations,
            "subkeys": self.subkeys,
            "problems": self.problems,
            "offset": self.offset,
        }
        return out


@dataclass(slots=True)
class Inventory:
    """The result for one file: key records, loose signatures, refusals and armor facts."""

    keys: list[KeyRecord] = field(default_factory=list)
    signatures: list[dict[str, Any]] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    armor: list[dict[str, Any]] = field(default_factory=list)
    other_packets: list[dict[str, Any]] = field(default_factory=list)
    packet_counts: dict[str, int] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)
    cleartext: dict[str, Any] | None = None
    source: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from . import __version__  # the package imports this module before it defines the version

        return {
            "schema": SCHEMA,
            "label": "claimed",
            "generator": {"name": "pgpenv", "version": __version__},
            "source": self.source,
            "armor": self.armor,
            "keys": [k.to_dict() for k in self.keys],
            "signatures": self.signatures,
            "cleartext": self.cleartext,
            "rejected": self.rejected,
            "other_packets": self.other_packets,
            "packet_counts": self.packet_counts,
            "problems": self.problems,
        }


def _is_self(sig: Signature, key: PublicKey, *, by_position: bool) -> bool:
    fp = sig.issuer_fingerprint
    if fp is not None:
        return fp[1] == key.fingerprint
    kid = sig.issuer_keyid
    if kid is not None:
        return kid == key.keyid
    return by_position


def _issuer(sig: Signature) -> dict[str, Any]:
    fp = sig.issuer_fingerprint
    return {
        "issuer_keyid": _hex(sig.issuer_keyid),
        "issuer_fingerprint": _hex(fp[1]) if fp else None,
        "issuer_area": sig.issuer_area,
    }


def _expiry(sig: Signature) -> int | None:
    created, after = sig.created, sig.expires_after
    return created + after if created is not None and after else None


def _newest(sigs: list[Signature]) -> Signature | None:
    best: Signature | None = None
    for sig in sigs:
        if best is None or (sig.created or 0) >= (best.created or 0):
            best = sig
    return best


def _notation_view(n: Notation) -> dict[str, Any]:
    return {
        "name": n.name,
        "human_readable": n.human_readable,
        "value": n.value.decode("utf-8", "replace") if n.human_readable else n.value.hex(),
    }


def signature_record(sig: Signature) -> dict[str, Any]:
    """A signature as claimed: its fields, issuer, times and subpackets; never ``valid``."""
    notations = [
        _notation_view(s.value) for s in sig.hashed + sig.unhashed if isinstance(s.value, Notation)
    ]
    prefs: dict[str, Any] = {}
    hashes = sig.value(21)
    if hashes is not None:
        prefs["hash"] = [hash_name(h) for h in hashes]
    ciphers = sig.value(11)
    if ciphers is not None:
        prefs["symmetric"] = [SYMMETRIC_NAMES.get(c, f"unknown({c})") for c in ciphers]
    aead = sig.value(39)
    if aead is not None:
        prefs["aead"] = [f"{SYMMETRIC_NAMES.get(c, c)}+{AEAD_NAMES.get(m, m)}" for c, m in aead]
    reason = sig.value(29)
    flags = sig.key_flags
    return {
        "label": "claimed",
        "version": sig.version,
        "type": sig.sig_type,
        "type_name": signature_type_name(sig.sig_type),
        "pub_algo": sig.pub_algo,
        "pub_algo_name": pk_name(sig.pub_algo),
        "hash_algo": sig.hash_algo,
        "hash_name": hash_name(sig.hash_algo),
        **_times("created", sig.created),
        **_times("expires", _expiry(sig)),
        **_issuer(sig),
        "signer_user_id": sig.value(28),
        "key_flags": key_flag_names(flags) if flags is not None else None,
        "key_expires_after": sig.key_expires_after,
        "primary_user_id": sig.value(25),
        "exportable": sig.value(4),
        "revocable": sig.value(7),
        "revocation": (
            {
                "code": reason[0],
                "reason": REVOCATION_REASONS.get(reason[0], f"unknown({reason[0]})"),
                "text": reason[1],
            }
            if reason is not None
            else None
        ),
        "preferences": prefs,
        "notations": notations,
        "unhashed_subpackets": [
            {"type": s.type, "name": s.name, "critical": s.critical} for s in sig.unhashed
        ],
        "embedded_signatures": len(sig.embedded),
        "salt_length": None if sig.salt is None else len(sig.salt),
        "left16": sig.left16.hex(),
        "usable": sig.usable,
        "problems": list(sig.problems),
    }


def _cert_entry(
    sig: Signature, cert: Certificate, uid_text: str | None, primary_self: bool
) -> dict[str, Any]:
    trust = sig.value(5)
    return {
        "target_fingerprint": cert.primary.fingerprint_hex,
        "user_id": uid_text,
        "type": sig.sig_type,
        "type_name": signature_type_name(sig.sig_type),
        "self": primary_self,
        **_issuer(sig),
        **_times("created", sig.created),
        **_times("expires", _expiry(sig)),
        "hash_name": hash_name(sig.hash_algo),
        "exportable": sig.value(4),
        "trust": None if trust is None else {"level": trust[0], "amount": trust[1]},
        "issuer_in_file": None,
    }


def _revocation_entry(
    sig: Signature, scope: str, target: str, key: PublicKey, uid_text: str | None
) -> dict[str, Any]:
    reason = sig.value(29)
    return {
        "scope": scope,
        "target_fingerprint": target,
        "user_id": uid_text,
        "type": sig.sig_type,
        **_times("created", sig.created),
        "reason_code": None if reason is None else reason[0],
        "reason": None
        if reason is None
        else REVOCATION_REASONS.get(reason[0], f"unknown({reason[0]})"),
        "reason_text": None if reason is None else reason[1],
        "self": _is_self(sig, key, by_position=True),
        **_issuer(sig),
        "hash_name": hash_name(sig.hash_algo),
    }


def _key_choice(cert: Certificate) -> tuple[Signature | None, str | None]:
    """The self-signature a primary key's expiry and flags are read from, and its source label."""
    primary = cert.primary
    direct = [
        s for s in cert.signatures if s.sig_type == 0x1F and _is_self(s, primary, by_position=True)
    ]
    chosen = _newest(direct)
    if chosen is not None:
        return chosen, "direct_key"
    selfcerts = [
        (uid, s)
        for uid in cert.user_ids
        for s in uid.signatures
        if s.sig_type in _CERT_TYPES and _is_self(s, primary, by_position=False)
    ]
    flagged = [s for _, s in selfcerts if s.value(25) is True]
    chosen = _newest(flagged)
    if chosen is not None:
        return chosen, "primary_user_id"
    chosen = _newest([s for _, s in selfcerts])
    return (chosen, "user_id") if chosen is not None else (None, None)


def _subkey_record(cert: Certificate, entry: Any) -> dict[str, Any]:
    key = entry.key
    bindings = [
        s
        for s in entry.signatures
        if s.sig_type == 0x18 and _is_self(s, cert.primary, by_position=True)
    ]
    chosen = _newest(bindings)
    expires = None
    flags: bytes | None = None
    if chosen is not None:
        flags = chosen.key_flags
        after = chosen.key_expires_after
        expires = key.created + after if after else None
    revocations = [
        _revocation_entry(s, "subkey", key.fingerprint_hex, cert.primary, None)
        for s in entry.signatures
        if s.sig_type == 0x28
    ]
    return {
        "fingerprint": key.fingerprint_hex,
        "keyid": key.keyid_hex,
        "version": key.version,
        "algorithm": {
            "id": key.algorithm,
            "name": key.algorithm_name,
            "bits": key.bits,
            "curve": key.curve,
            "deprecated": key.deprecated,
        },
        "secret_material_present": key.secret,
        **_times("created", key.created),
        **_times("expires", expires),
        "flags": key_flag_names(flags) if flags is not None else [],
        "flags_raw": _hex(flags),
        "binding": None
        if chosen is None
        else {
            **_times("created", chosen.created),
            "hash_name": hash_name(chosen.hash_algo),
            "back_signature_embedded": any(e.sig_type == 0x19 for e in chosen.embedded),
            **_issuer(chosen),
        },
        "revoked_claimed": any(r["self"] for r in revocations),
        "revocations": revocations,
        "problems": list(key.problems),
    }


def _record(cert: Certificate) -> KeyRecord:
    key = cert.primary
    chosen, source = _key_choice(cert)
    flags = chosen.key_flags if chosen is not None else None
    after = chosen.key_expires_after if chosen is not None else None
    rec = KeyRecord(
        fingerprint=key.fingerprint_hex,
        keyid=key.keyid_hex,
        version=key.version,
        algorithm_id=key.algorithm,
        algorithm=key.algorithm_name,
        bits=key.bits,
        curve=key.curve,
        deprecated_algorithm=key.deprecated,
        secret_material_present=key.secret,
        created=key.created,
        expires=key.created + after if after else None,
        expiry_source=source,
        flags=key_flag_names(flags) if flags is not None else [],
        flags_raw=_hex(flags),
        self_signature_hashes=[],
        problems=[*key.problems, *cert.problems],
        offset=cert.offset,
    )
    if key.valid_days_v3:
        rec.expires = key.created + key.valid_days_v3 * 86400
        rec.expiry_source = "v3_key_packet"
    hashes: set[str] = set()
    for sig in cert.signatures:
        if sig.sig_type == 0x1F:
            hashes.add(hash_name(sig.hash_algo))
        elif sig.sig_type == 0x20:
            rec.revocations.append(_revocation_entry(sig, "key", key.fingerprint_hex, key, None))
    for uid in cert.user_ids:
        text = uid.text if uid.text is not None else "[user attribute]"
        selfs = [
            s
            for s in uid.signatures
            if s.sig_type in _CERT_TYPES and _is_self(s, key, by_position=False)
        ]
        uid_revs = [
            _revocation_entry(s, "certification", key.fingerprint_hex, key, text)
            for s in uid.signatures
            if s.sig_type == 0x30
        ]
        for s in selfs:
            hashes.add(hash_name(s.hash_algo))
        newest = _newest(selfs)
        rec.user_ids.append(
            {
                "kind": uid.kind,
                "text": uid.text,
                "self_signed": bool(selfs),
                "primary_claimed": any(s.value(25) is True for s in selfs),
                **_times("newest_self_signature", newest.created if newest else None),
                "revoked_claimed": any(r["self"] for r in uid_revs),
                "signature_count": len(uid.signatures),
            }
        )
        for s in uid.signatures:
            if s.sig_type in _CERT_TYPES:
                rec.certifications.append(
                    _cert_entry(s, cert, text, _is_self(s, key, by_position=False))
                )
        rec.revocations.extend(uid_revs)
    for entry in cert.subkeys:
        rec.subkeys.append(_subkey_record(cert, entry))
        for s in entry.signatures:
            if s.sig_type == 0x18:
                hashes.add(hash_name(s.hash_algo))
    rec.self_signature_hashes = sorted(hashes)
    rec.revoked_claimed = any(r["scope"] == "key" and r["self"] for r in rec.revocations)
    return rec


def inventory_report(
    data: bytes | str, limits: Limits = DEFAULT_LIMITS, *, path: str | None = None
) -> Inventory:
    """Inventory one file (binary or armored keyring, detached signature, or cleartext message).

    Never raises for malformed *content*: a refused certificate or a damaged tail is recorded in
    ``rejected``. Raises :class:`pgpenv.errors.PgpError` only when the input is neither binary
    OpenPGP nor armor, and :class:`pgpenv.errors.LimitError` when a bound is exceeded.
    """
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    ring: Keyring = parse_keyring(raw, limits)
    inv = Inventory()
    inv.source = {"path": path, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    inv.keys = [_record(c) for c in ring.certificates]
    inv.signatures = [signature_record(s) for s in ring.signatures]
    inv.rejected = [
        {"offset": r.offset, "block": r.block, "reason": r.reason} for r in ring.rejected
    ]
    inv.armor = [
        {
            "label": b.label,
            "headers": [list(h) for h in b.headers],
            "crc": b.crc,
            "notes": list(b.notes),
        }
        for b in ring.blocks
    ]
    inv.other_packets = [
        {"tag": t, "name": tag_info(t).shorthand, "offset": o} for t, o in ring.other_packets
    ]
    inv.packet_counts = {
        tag_info(t).shorthand + f"({t})": n for t, n in sorted(ring.packet_counts.items())
    }
    inv.problems = list(ring.problems)
    if b"-----BEGIN PGP SIGNED MESSAGE-----" in raw:
        try:
            ct = parse_cleartext(raw, limits)
        except CleartextError as error:
            inv.cleartext = {"accepted": False, "refusal": str(error)}
        else:
            inv.cleartext = {
                "accepted": True,
                "signed_text_bytes": len(ct.text),
                "signed_text_sha256": hashlib.sha256(ct.text).hexdigest(),
                "hash_headers": list(ct.hash_names),
                "warnings": list(ct.warnings),
            }
    known = {k.fingerprint for k in inv.keys} | {k.keyid for k in inv.keys}
    for k in inv.keys:
        known |= {s["fingerprint"] for s in k.subkeys} | {s["keyid"] for s in k.subkeys}
    for k in inv.keys:
        for c in k.certifications:
            ident = c["issuer_fingerprint"] or c["issuer_keyid"]
            c["issuer_in_file"] = None if ident is None else ident in known
    return inv


def inventory(keyring_bytes: bytes | str, limits: Limits = DEFAULT_LIMITS) -> list[KeyRecord]:
    """The :class:`KeyRecord` of every certificate in ``keyring_bytes`` (binary or armored).

    RFC 9580 sec. 10.1. Everything is claimed, nothing verified. Certificates that had to be
    refused are not in the list; use :func:`inventory_report` to see why.
    """
    return inventory_report(keyring_bytes, limits).keys

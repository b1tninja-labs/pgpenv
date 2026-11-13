"""The inventory layer: claimed facts in the pkgtrust.keys/1 shape, and GnuPG as the oracle."""

from __future__ import annotations

import ast
import hashlib
import io
import json
import pathlib
import shutil
import subprocess
import sys

import pytest

import pgpenv
from pgpenv import cli
from pgpenv.errors import PgpError
from pgpenv.inventory import SCHEMA, inventory, inventory_report

from . import vectors as v
from .helpers import DATA, fixture

FIXTURES = sorted(p.name for p in DATA.glob("*.pgp") if p.name not in ("ring.pgp", "msg.txt.sig"))


def by_fpr(records):
    return {r.fingerprint: r for r in records}


def test_inventory_returns_one_record_per_certificate():
    records = inventory(fixture("ring.pgp"))
    assert [r.algorithm for r in records] == ["RSA", "EdDSALegacy", "ECDSA", "DSA"]
    assert all(r.label == "claimed" for r in records)
    assert (
        inventory(fixture("ring.asc")) == records
    )  # armored and binary agree, offsets aside? same bytes inside


def test_a3_record_matches_the_rfc():
    (rec,) = inventory(v.A3_ARMOR)
    assert rec.fingerprint == v.A3_PRIMARY_FINGERPRINT
    assert rec.keyid == v.A3_PRIMARY_FINGERPRINT[:16]
    assert (rec.version, rec.algorithm, rec.bits) == (6, "Ed25519", 255)
    assert rec.flags == ["certify", "sign"]
    assert rec.expires is None
    assert rec.expiry_source == "direct_key"
    assert rec.self_signature_hashes == ["SHA2-512"]
    (sub,) = rec.subkeys
    assert sub["fingerprint"] == v.A3_SUBKEY_FINGERPRINT
    assert sub["flags"] == ["encrypt_communications", "encrypt_storage"]
    assert sub["binding"]["hash_name"] == "SHA2-512"
    assert rec.created == 1669824483


def test_ed25519_fixture_claims_flags_expiry_subkeys_and_a_revoked_subkey():
    (rec,) = inventory(fixture("ed25519.pgp"))
    assert rec.expires == rec.created + 365 * 86400
    assert rec.expiry_source in ("primary_user_id", "user_id")
    assert [u["text"] for u in rec.user_ids] == [
        "pgpenv fixture ed25519 <ed25519@example.invalid>",
        "second identity <ed25519-2@example.invalid>",
    ]
    assert all(u["self_signed"] for u in rec.user_ids)
    assert [s["algorithm"]["name"] for s in rec.subkeys] == ["ECDH", "EdDSALegacy"]
    assert rec.subkeys[0]["algorithm"]["curve"] == "Curve25519Legacy"
    assert rec.subkeys[1]["binding"]["back_signature_embedded"] is True
    assert rec.subkeys[1]["revoked_claimed"] is True
    assert rec.subkeys[1]["revocations"][0]["reason_code"] == 1
    assert rec.subkeys[0]["revoked_claimed"] is False
    assert rec.revoked_claimed is False


def test_certification_issuer_to_target_with_issuer_known_in_the_same_file():
    ring = by_fpr(inventory(fixture("ring.pgp")))
    rsa = next(r for r in ring.values() if r.algorithm == "RSA")
    ed = next(r for r in ring.values() if r.algorithm == "EdDSALegacy")
    others = [c for c in ed.certifications if not c["self"]]
    assert len(others) == 2  # the RSA key certified both user ids
    cert = others[0]
    assert cert["issuer_fingerprint"] == rsa.fingerprint
    assert cert["target_fingerprint"] == ed.fingerprint
    assert cert["user_id"].startswith("pgpenv fixture ed25519")
    assert cert["issuer_in_file"] is True
    assert cert["type"] == 0x10
    alone = inventory(fixture("ed25519.pgp"))[0]
    assert [c["issuer_in_file"] for c in alone.certifications if not c["self"]] == [False, False]


def test_revoked_primary_key_is_claimed_with_reason_and_not_called_valid():
    (rec,) = inventory(fixture("nistp256.pgp"))
    assert rec.revoked_claimed is True
    (rev,) = [r for r in rec.revocations if r["scope"] == "key"]
    assert rev["reason_code"] == 2
    assert rev["reason_text"] == "key replaced by a later key"
    assert rev["self"] is True
    assert "valid" not in json.dumps(rec.to_dict()).replace("invalid", "").replace("valid_", "")


def test_a_lone_revocation_certificate_is_a_loose_signature():
    inv = inventory_report(fixture("nistp256-revcert.asc"))
    assert inv.keys == []
    (sig,) = inv.signatures
    assert sig["type"] == 0x20
    assert sig["type_name"] == "key revocation"
    assert sig["revocation"]["text"] == "key replaced by a later key"
    assert sig["issuer_keyid"]
    assert sig["label"] == "claimed"


def test_detached_signature_and_cleartext_inventory():
    for name in ("msg.txt.asc", "msg.txt.sig"):
        inv = inventory_report(fixture(name))
        (sig,) = inv.signatures
        assert (sig["hash_name"], sig["pub_algo_name"]) == ("SHA2-512", "EdDSALegacy")
        assert sig["issuer_area"] == "hashed"
        assert [u["name"] for u in sig["unhashed_subpackets"]] == ["issuer key id"]
    inv = inventory_report(fixture("msg.txt.clearsigned.asc"))
    assert inv.cleartext["accepted"] is True
    assert (
        inv.cleartext["signed_text_sha256"]
        == hashlib.sha256(b"pgpenv fixture message\r\n").hexdigest()
    )
    assert inv.cleartext["hash_headers"] == ["SHA512"]
    assert len(inv.signatures) == 1


def test_json_shape():
    inv = inventory_report(fixture("ring.asc"), path="ring.asc")
    doc = json.loads(json.dumps(inv.to_dict()))
    assert doc["schema"] == SCHEMA == "pkgtrust.keys/1"
    assert doc["label"] == "claimed"
    assert doc["generator"]["name"] == "pgpenv"
    assert doc["source"]["sha256"] == hashlib.sha256(fixture("ring.asc")).hexdigest()
    assert doc["armor"][0]["crc"] == "ok"
    key = doc["keys"][0]
    for field in [
        "fingerprint",
        "keyid",
        "version",
        "algorithm",
        "created",
        "created_utc",
        "expires",
        "expires_utc",
        "expiry_source",
        "flags",
        "user_ids",
        "certifications",
        "revocations",
        "subkeys",
        "problems",
        "revoked_claimed",
    ]:
        assert field in key, field
    assert key["fingerprint"] == key["fingerprint"].upper()
    assert key["created_utc"] == "20240301T120000Z"
    assert set(key["algorithm"]) == {"id", "name", "bits", "curve", "deprecated"}
    assert set(doc) >= {"keys", "signatures", "rejected", "armor", "cleartext", "packet_counts"}


def test_v3_key_is_inventoried_with_its_weakness_noted():
    from .helpers import pkt, rsa_key_body

    uid = pkt(13, b"old key <old@example.invalid>")
    body = rsa_key_body(3, (1 << 2047) | 5)
    (rec,) = inventory(pkt(6, body) + uid)
    assert (rec.version, len(rec.fingerprint)) == (3, 32)
    assert any("MD5" in p for p in rec.problems)
    assert rec.user_ids[0]["text"] == "old key <old@example.invalid>"


def test_legacy_format_headers_are_read():
    from .helpers import legacy_pkt, pkt

    ring = fixture("ed25519.pgp")
    # re-frame the primary key and uid packets in the legacy format: same inventory
    from pgpenv.packet import parse_packets

    packets = parse_packets(ring)
    legacy = b"".join(
        legacy_pkt(p.tag, p.body, 1) if p.tag < 16 else pkt(p.tag, p.body) for p in packets
    )
    assert [r.fingerprint for r in inventory(legacy)] == [r.fingerprint for r in inventory(ring)]


def test_non_openpgp_input_is_refused_cleanly():
    with pytest.raises(PgpError):
        inventory_report(b"just some text\n")
    assert inventory_report(b"").keys == []


# --- the standard-library-only promise ---------------------------------------------------------


def test_parse_layer_imports_only_the_standard_library():
    """The owner allows cryptography for primitives (RSA, AES); the parse layer needs none."""
    root = pathlib.Path(pgpenv.__file__).parent
    allowed = set(sys.stdlib_module_names) | {"pgpenv"}
    offenders = []
    for path in sorted(root.glob("*.py")):
        if path.name == "crypto.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module.split(".")[0]]
            offenders += [f"{path.name}: {n}" for n in names if n not in allowed]
    if offenders:
        pytest.fail("non-standard-library imports in the parse layer: " + ", ".join(offenders))


def test_importing_the_package_does_not_import_cryptography():
    code = "import sys, pgpenv; sys.exit(1 if 'cryptography' in sys.modules else 0)"
    done = subprocess.run([sys.executable, "-c", code], check=False, cwd=str(DATA.parents[2]))  # noqa: S603
    assert done.returncode == 0


# --- command line ------------------------------------------------------------------------------


def run_cli(capsys, *argv):
    code = cli.main(list(argv))
    return code, capsys.readouterr()


def test_cli_inventory_json(capsys):
    code, out = run_cli(capsys, "inventory", str(DATA / "ring.asc"), "--json")
    assert code == 0
    doc = json.loads(out.out)
    assert doc["schema"] == "pkgtrust.keys/1"
    assert len(doc["keys"]) == 4


def test_cli_inventory_text_and_errors(capsys):
    code, out = run_cli(capsys, "inventory", str(DATA / "nistp256.asc"))
    assert code == 0
    assert "REVOKED(claimed)" in out.out
    code, out = run_cli(capsys, "inventory", str(DATA / "does-not-exist"))
    assert code == 2
    assert "pgpenv:" in out.err
    code, out = run_cli(capsys)
    assert code == 2


def test_cli_exit_status_is_1_when_content_was_refused(capsys, tmp_path):
    bad = tmp_path / "cut.pgp"
    bad.write_bytes(fixture("ed25519.pgp")[:-5])
    code, out = run_cli(capsys, "inventory", str(bad), "--json")
    assert code == 1
    assert json.loads(out.out)["rejected"]


def test_cli_reads_stdin(capsys, monkeypatch):
    class Stdin:
        buffer = io.BytesIO(fixture("rsa2048.pgp"))

    monkeypatch.setattr(sys, "stdin", Stdin)
    code, out = run_cli(capsys, "inventory", "-", "--json")
    assert code == 0
    assert json.loads(out.out)["keys"][0]["algorithm"]["name"] == "RSA"


# --- GnuPG as the oracle -----------------------------------------------------------------------


def gpg_colons(data: bytes):
    wsl = shutil.which("wsl.exe") or shutil.which("wsl")
    cmd = (
        [wsl, "-d", "archlinux", "gpg", "--with-colons", "--show-keys"]
        if wsl
        else [shutil.which("gpg") or "", "--with-colons", "--show-keys"]
    )
    if not cmd[0]:
        pytest.skip("neither wsl.exe nor gpg is available")
    try:
        done = subprocess.run(cmd, input=data, capture_output=True, timeout=60, check=False)  # noqa: S603
    except (OSError, subprocess.TimeoutExpired):
        pytest.skip("gpg could not be run")
    if done.returncode != 0 or b"pub:" not in done.stdout:
        pytest.skip("gpg is not usable here: " + done.stderr.decode(errors="replace")[:200])
    return [line.split(":") for line in done.stdout.decode().splitlines()]


CAPS = {
    "certify": "c",
    "sign": "s",
    "authenticate": "a",
    "encrypt_communications": "e",
    "encrypt_storage": "e",
}


def gpg_expectations(rows):
    """[(kind, fpr, keyid, algo, bits, created, expires, caps)] for pub and sub lines, in order."""
    out = []
    for i, row in enumerate(rows):
        if row[0] in ("pub", "sub") and rows[i + 1][0] == "fpr":
            caps = "".join(sorted({c for c in row[11] if c.islower()}))
            # GnuPG prints a revoked subkey's expiry from somewhere other than its binding signature
            # (here the primary's one-year expiry); RFC 9580 sec. 5.2.3.13 reads the binding, so skip it
            expires = -1 if row[0] == "sub" and row[1] == "r" else int(row[6] or 0)
            out.append(
                (
                    row[0],
                    rows[i + 1][9],
                    row[4],
                    int(row[3]),
                    int(row[2]),
                    int(row[5]),
                    expires,
                    caps,
                )
            )
    return out


def our_expectations(records):
    out = []
    for rec in records:
        caps = "".join(sorted({CAPS[f] for f in rec.flags}))
        out.append(
            (
                "pub",
                rec.fingerprint,
                rec.keyid,
                rec.algorithm_id,
                rec.bits,
                rec.created,
                rec.expires or 0,
                caps,
            )
        )
        for sub in rec.subkeys:
            scaps = "".join(sorted({CAPS[f] for f in sub["flags"]}))
            expires = -1 if sub["revoked_claimed"] or rec.revoked_claimed else sub["expires"] or 0
            out.append(
                (
                    "sub",
                    sub["fingerprint"],
                    sub["keyid"],
                    sub["algorithm"]["id"],
                    sub["algorithm"]["bits"],
                    sub["created"],
                    expires,
                    scaps,
                )
            )
    return out


@pytest.mark.parametrize("name", [*FIXTURES, "ring.pgp"])
def test_fingerprints_and_key_facts_agree_with_gnupg(name):
    data = fixture(name)
    theirs = gpg_expectations(gpg_colons(data))
    ours = our_expectations(inventory(data))
    assert ours == theirs


def test_rfc_a1_fingerprint_agrees_with_gnupg():
    rows = gpg_colons(v.A1_PACKET)
    fprs = [r[9] for r in rows if r[0] == "fpr"]
    assert fprs == [inventory(v.A1_PACKET)[0].fingerprint] == [v.A1_FINGERPRINT]

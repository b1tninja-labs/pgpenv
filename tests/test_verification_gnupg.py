"""Verification against GnuPG: keys and signatures GnuPG made, checked by pgpenv, and GnuPG's own verdict.

The module generates throwaway keys in a temporary GNUPGHOME inside WSL (``wsl.exe -d archlinux gpg``),
signs a small document with each (binary, text mode and cleartext, with a spread of hashes), exports the
public keys and asks GnuPG to verify its own output. pgpenv must then agree: ``valid`` where GnuPG says
good, and a refusal where the policy says so. Everything skips when WSL or GnuPG is missing. Nothing is
written into the repository: the work happens under pytest's temporary directory.

Version 6 keys and signatures are not here, because GnuPG 2.4 makes none; RFC 9580 appendix A covers
those (``tests/test_verification.py``).
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess

import pytest

from pgpenv import key, signature
from pgpenv.armor import decode
from pgpenv.packet import iter_packets
from pgpenv.verification import (
    check_self_signatures,
    verify_cleartext,
    verify_document,
)

DISTRO = os.environ.get("PGPENV_WSL_DISTRO", "archlinux")
DOCUMENT = b"first line\nsecond line  \nthird line\n"

# name, Key-Type, key parameters, expected status of the primary key's checks under the openpgp policy
ALGORITHMS = {
    "rsa2048": ("RSA", "Key-Length: 2048", "valid"),
    "rsa3072": ("RSA", "Key-Length: 3072", "valid"),
    "nistp256": ("ECDSA", "Key-Curve: nistp256", "valid"),
    "nistp384": ("ECDSA", "Key-Curve: nistp384", "valid"),
    "nistp521": ("ECDSA", "Key-Curve: nistp521", "valid"),
    "ed25519": ("EDDSA", "Key-Curve: ed25519", "valid"),
    "brainpool": ("ECDSA", "Key-Curve: brainpoolP256r1", "unsupported"),
    "dsa2048": ("DSA", "Key-Length: 2048", "refused"),
}

SCRIPT = """\
set -eu
out="$1"
GNUPGHOME="$(mktemp -d)"; export GNUPGHOME; chmod 700 "$GNUPGHOME"
trap 'rm -rf "$GNUPGHOME"' EXIT
g() { gpg --batch --yes --quiet --no-tty --pinentry-mode loopback --passphrase "" "$@"; }
printf 'first line\\nsecond line  \\nthird line\\n' > "$out/doc"
@NAMES@
"""

PER_KEY = """\
n="{name}"
printf '%s\\n' "Key-Type: {ktype}" "{kparams}" "Key-Usage: cert,sign" "Name-Real: pgpenv verify $n" \\
    "Name-Email: $n@example.invalid" "Expire-Date: 0" "%commit" > "$GNUPGHOME/$n.params"
g --gen-key "$GNUPGHOME/$n.params"
fpr=$(gpg --batch --with-colons --list-keys "$n@example.invalid" | awk -F: '/^fpr/ {{print $10; exit}}')
g --export "$fpr" > "$out/$n.pub"
for h in {hashes}; do
    g --local-user "$fpr" --digest-algo $h --detach-sign --output "$out/$n.$h.bin.sig" "$out/doc"
    g --local-user "$fpr" --digest-algo $h --textmode --detach-sign --output "$out/$n.$h.txt.sig" "$out/doc"
    g --local-user "$fpr" --digest-algo $h --clearsign --output "$out/$n.$h.clear.asc" "$out/doc"
    g --verify "$out/$n.$h.bin.sig" "$out/doc" 2> "$out/$n.$h.bin.verdict" || echo "BAD" >> "$out/$n.$h.bin.verdict"
    g --verify "$out/$n.$h.clear.asc" 2> "$out/$n.$h.clear.verdict" || echo "BAD" >> "$out/$n.$h.clear.verdict"
done
"""

HASHES = {
    "rsa2048": "SHA256 SHA384 SHA512 SHA1",
    "rsa3072": "SHA256 SHA512",
    "nistp256": "SHA256 SHA384 SHA512",
    "nistp384": "SHA384 SHA512",
    "nistp521": "SHA512",
    "ed25519": "SHA256 SHA512",
    "brainpool": "SHA256",
    "dsa2048": "SHA256",
}


def _wsl_path(path: pathlib.Path) -> str:
    drive, rest = os.path.splitdrive(str(path))
    return f"/mnt/{drive[:1].lower()}" + rest.replace("\\", "/")


@pytest.fixture(scope="module")
def gnupg_output(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    wsl = shutil.which("wsl.exe") or shutil.which("wsl")
    if wsl is None:
        pytest.skip("wsl.exe is not available")
    probe = subprocess.run(  # noqa: S603
        [wsl, "-d", DISTRO, "gpg", "--version"], capture_output=True, text=True, check=False
    )
    if probe.returncode != 0:
        pytest.skip("GnuPG is not available in WSL")
    out = tmp_path_factory.mktemp("gnupg")
    names = "".join(
        PER_KEY.format(name=name, ktype=ktype, kparams=kparams, hashes=HASHES[name])
        for name, (ktype, kparams, _) in ALGORITHMS.items()
    )
    script = out / "run.sh"
    script.write_bytes(SCRIPT.replace("@NAMES@", names).encode("utf-8"))
    done = subprocess.run(  # noqa: S603
        [wsl, "-d", DISTRO, "sh", _wsl_path(script), _wsl_path(out)],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if done.returncode != 0:
        pytest.skip(f"GnuPG could not make the fixtures: {done.stderr.strip()[:300]}")
    return out


def _cases() -> list[tuple[str, str]]:
    return [(name, h) for name, hashes in HASHES.items() for h in hashes.split()]


def _signature_of(path: pathlib.Path) -> signature.Signature:
    raw = path.read_bytes()
    data = decode(raw) if raw[:1] == b"-" else raw
    (packet,) = [p for p in iter_packets(data) if p.tag == 2]
    return signature.parse_signature(packet.body)


def _expected(name: str, digest: str) -> str:
    """The status pgpenv should give: the policy's refusal of SHA-1 comes before the key's."""
    status = ALGORITHMS[name][2]
    if status == "valid" and digest == "SHA1":
        return "refused"
    return status


@pytest.mark.parametrize(("name", "digest"), _cases())
def test_gnupg_binary_and_text_signatures_verify_under_the_openpgp_policy(
    gnupg_output: pathlib.Path, name: str, digest: str
) -> None:
    cert = key.load_key((gnupg_output / f"{name}.pub").read_bytes())
    expected = _expected(name, digest)
    binary = _signature_of(gnupg_output / f"{name}.{digest}.bin.sig")
    assert binary.sig_type == 0x00
    result = verify_document(DOCUMENT, binary, cert)
    assert result.status == expected, result
    text = _signature_of(gnupg_output / f"{name}.{digest}.txt.sig")
    assert text.sig_type == 0x01
    assert verify_document(DOCUMENT, text, cert).status == expected
    if expected == "valid":
        assert result.checked == ("hash", "left16", "signature")
        assert result.issuer_hint == "match"
        assert verify_document(DOCUMENT + b"x", binary, cert).status == "invalid"
        # a text signature canonicalises line endings, so CR LF and LF are the same document
        assert verify_document(DOCUMENT.replace(b"\n", b"\r\n"), text, cert).valid


@pytest.mark.parametrize(("name", "digest"), _cases())
def test_gnupg_cleartext_signatures_verify_and_gnupg_agrees(
    gnupg_output: pathlib.Path, name: str, digest: str
) -> None:
    cert = key.load_key((gnupg_output / f"{name}.pub").read_bytes())
    message = (gnupg_output / f"{name}.{digest}.clear.asc").read_bytes()
    (result,) = verify_cleartext(message, cert)
    assert result.status == _expected(name, digest), result
    verdict = (gnupg_output / f"{name}.{digest}.clear.verdict").read_text(encoding="utf-8")
    assert "Good signature" in verdict
    if result.valid:
        # the trailing spaces of line two are not part of the signed text (RFC 9580 sec. 7.1)
        tampered = message.replace(b"third line", b"third lime")
        (bad,) = verify_cleartext(tampered, cert)
        assert bad.status == "invalid"


def test_gnupg_agrees_with_pgpenv_on_every_binary_signature(gnupg_output: pathlib.Path) -> None:
    for name, digest in _cases():
        verdict = (gnupg_output / f"{name}.{digest}.bin.verdict").read_text(encoding="utf-8")
        assert "Good signature" in verdict, (name, digest, verdict)


@pytest.mark.parametrize("name", [n for n, (_, _, status) in ALGORITHMS.items()])
def test_gnupg_made_certificates_have_valid_self_signatures_under_the_policy(
    gnupg_output: pathlib.Path, name: str
) -> None:
    cert = key.load_key((gnupg_output / f"{name}.pub").read_bytes())
    results = check_self_signatures(cert)
    assert results  # at least the User ID certification
    assert {r.verification.status for r in results if r.verification} == {ALGORITHMS[name][2]}


def test_the_legacy_policy_verifies_dsa_and_sha1_that_the_openpgp_policy_refuses(
    gnupg_output: pathlib.Path,
) -> None:
    dsa = key.load_key((gnupg_output / "dsa2048.pub").read_bytes())
    sig = _signature_of(gnupg_output / "dsa2048.SHA256.bin.sig")
    result = verify_document(DOCUMENT, sig, dsa, policy="legacy")
    assert result.valid
    assert any("DSA" in warning for warning in result.warnings)
    rsa = key.load_key((gnupg_output / "rsa2048.pub").read_bytes())
    sha1 = _signature_of(gnupg_output / "rsa2048.SHA1.bin.sig")
    legacy = verify_document(DOCUMENT, sha1, rsa, policy="legacy")
    assert legacy.valid
    assert any("SHA-1" in warning for warning in legacy.warnings)
    assert verify_document(DOCUMENT, sha1, rsa).status == "refused"

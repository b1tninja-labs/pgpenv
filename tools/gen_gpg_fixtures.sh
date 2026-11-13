#!/bin/sh
# Regenerate tests/data/gnupg/*.pgp and *.asc with GnuPG (run inside WSL or any POSIX shell).
#
#   wsl.exe -d archlinux sh /mnt/d/code/pgpenv/tools/gen_gpg_fixtures.sh /mnt/d/code/pgpenv/tests/data/gnupg
#
# Every key here is a throwaway generated for this repository, with a fake system time so the
# creation dates are stable. Only the public parts are exported; the secret keys live in a
# temporary GNUPGHOME that is deleted at the end. The keys are random, so re-running changes
# every fingerprint: the tests read the expected values from GnuPG at run time, never from here.
set -eu

out="${1:?usage: gen_gpg_fixtures.sh OUTPUT_DIR}"
mkdir -p "$out"
GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
chmod 700 "$GNUPGHOME"
trap 'rm -rf "$GNUPGHOME"' EXIT

g() { gpg --batch --yes --quiet --no-tty --pinentry-mode loopback --passphrase "" "$@"; }
T="--faked-system-time 20240301T120000"

gen() { # name keytype keyspec subkeytype subkeyspec expire usage uid...
    name="$1"; shift
    {
        echo "%no-protection"
        echo "Key-Type: $1"
        echo "$2"
        echo "Key-Usage: cert,sign"
        echo "Subkey-Type: $3"
        echo "$4"
        echo "Subkey-Usage: encrypt"
        echo "Expire-Date: $5"
        echo "Name-Real: pgpenv fixture $name"
        echo "Name-Email: $name@example.invalid"
        echo "%commit"
    } > "$GNUPGHOME/$name.params"
    g $T --gen-key "$GNUPGHOME/$name.params"
}

gen rsa2048 RSA "Key-Length: 2048" RSA "Subkey-Length: 2048" 2040-01-01
gen rsa4096 RSA "Key-Length: 4096" RSA "Subkey-Length: 3072" 0
gen ed25519 EDDSA "Key-Curve: ed25519" ECDH "Subkey-Curve: cv25519" 1y
gen nistp256 ECDSA "Key-Curve: nistp256" ECDH "Subkey-Curve: nistp256" 0
gen nistp384 ECDSA "Key-Curve: nistp384" ECDH "Subkey-Curve: nistp384" 0
gen nistp521 ECDSA "Key-Curve: nistp521" ECDH "Subkey-Curve: nistp521" 0
gen brainpool ECDSA "Key-Curve: brainpoolP256r1" ECDH "Subkey-Curve: brainpoolP256r1" 0
gen dsaelg DSA "Key-Length: 2048" ELG "Subkey-Length: 2048" 0

fpr() { gpg --batch --with-colons --list-keys "$1@example.invalid" | awk -F: '/^fpr/ {print $10; exit}'; }

# a second user id, an extra signing subkey (so a primary key binding signature is embedded), and a
# subkey that is then revoked
ED=$(fpr ed25519)
g $T --quick-add-uid "$ED" "second identity <ed25519-2@example.invalid>"
g $T --quick-add-key "$ED" ed25519 sign 0
SUBS=$(gpg --batch --with-colons --list-keys "$ED" | awk -F: '/^sub/ {n++} END {print n}')
printf 'key %s\nrevkey\ny\n2\nsuperseded by a later subkey\n\ny\nsave\n' "$SUBS" |
    g $T --command-fd 0 --edit-key "$ED" >/dev/null 2>&1 || true

# a certification of one key by another
RSA=$(fpr rsa2048)
g $T --local-user "$RSA" --quick-sign-key "$ED"

# a revoked primary key with a reason (gen-revoke refuses --batch, so it is driven through --command-fd)
NIST=$(fpr nistp256)
printf 'y
1
key replaced by a later key

y
' |
    gpg --yes --quiet --pinentry-mode loopback --passphrase "" $T --command-fd 0         --output "$GNUPGHOME/nistp256.rev" --gen-revoke "$NIST" >/dev/null 2>&1
g $T --import "$GNUPGHOME/nistp256.rev" >/dev/null 2>&1

for n in rsa2048 rsa4096 ed25519 nistp256 nistp384 nistp521 brainpool dsaelg; do
    f=$(fpr "$n")
    gpg --batch --export "$f" > "$out/$n.pgp"
    gpg --batch --armor --export "$f" > "$out/$n.asc"
done

# a keyring of several keys, binary and armored, and a lone revocation certificate
cat "$out/rsa2048.pgp" "$out/ed25519.pgp" "$out/nistp384.pgp" "$out/dsaelg.pgp" > "$out/ring.pgp"
gpg --batch --armor --export "$(fpr rsa2048)" "$(fpr ed25519)" "$(fpr nistp384)" "$(fpr dsaelg)" > "$out/ring.asc"
cp "$GNUPGHOME/nistp256.rev" "$out/nistp256-revcert.asc"
# a detached signature and a cleartext signature made by the ed25519 key
echo "pgpenv fixture message" > "$GNUPGHOME/msg.txt"
g $T --local-user "$ED" --detach-sign --armor --output "$out/msg.txt.asc" "$GNUPGHOME/msg.txt"
g $T --local-user "$ED" --detach-sign --output "$out/msg.txt.sig" "$GNUPGHOME/msg.txt"
g $T --local-user "$ED" --clearsign --output "$out/msg.txt.clearsigned.asc" "$GNUPGHOME/msg.txt"
cp "$GNUPGHOME/msg.txt" "$out/msg.txt"
ls -l "$out"

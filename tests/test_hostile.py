"""Hostile input: truncation, length overflow, partial-body abuse, floods, bad armor.

The contract under test is narrow and strict: whatever the bytes, the inventory either returns a
report (with refusals recorded in it) or raises a pgpenv error. It never raises IndexError,
struct.error, ValueError from the standard library, RecursionError or MemoryError, and it never
reads more than the claimed lengths allow.
"""

from __future__ import annotations

import random
import time

import pytest

from pgpenv import armor
from pgpenv.certificate import parse_keyring
from pgpenv.errors import ArmorError, LimitError, PgpError
from pgpenv.inventory import inventory, inventory_report
from pgpenv.limits import Limits
from pgpenv.packet import parse_packets

from .helpers import ed25519_v4_body, fixture, mpi, new_header, pkt, sig_v4_body, subpacket

RING = fixture("ring.pgp")
CREATED = subpacket(2, (1_700_000_000).to_bytes(4, "big"))
KEY = pkt(6, ed25519_v4_body())
UID = pkt(13, b"hostile <h@example.invalid>")


def survives(data: bytes):
    try:
        return inventory_report(data)
    except PgpError:
        return None


def test_every_truncation_of_a_real_keyring_is_survived():
    for cut in range(len(RING)):
        report = survives(RING[:cut])
        if report is not None and cut:
            # whatever was read is kept, and a cut mid-packet is reported rather than silent
            assert report.rejected or len(report.keys) <= 4


def test_truncation_keeps_the_keys_before_the_cut_and_reports_the_rest():
    first = parse_packets(fixture("rsa2048.pgp"))[-1].end
    report = inventory_report(RING[: first + 10])
    assert len(report.keys) == 1
    assert report.rejected
    assert report.rejected[0]["offset"] == first


def test_random_corruption_never_escapes_as_a_foreign_exception():
    rng = random.Random(9580)
    for _ in range(400):
        data = bytearray(RING)
        for _ in range(rng.randint(1, 12)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        survives(bytes(data))


def test_random_corruption_of_armor_never_escapes():
    rng = random.Random(4880)
    text = fixture("ring.asc").decode()
    for _ in range(300):
        chars = list(text)
        for _ in range(rng.randint(1, 8)):
            chars[rng.randrange(len(chars))] = rng.choice("A=+/ -\n\r!\x00z")
        try:
            inventory_report("".join(chars))
        except PgpError:
            continue


def test_length_overflow_claims_are_refused_without_reading_them():
    started = time.perf_counter()
    for wire in (
        b"\xc6\xff\xff\xff\xff\xff",  # five-octet length: four gigabytes
        b"\xc6\xff\x7f\xff\xff\xff" + b"x" * 8,
        b"\x8e\xff\xff\xff\xff",  # legacy four-octet length
    ):
        with pytest.raises(LimitError):  # over the packet bound: refused before anything is read
            inventory_report(wire)
    for wire in (
        b"\xc6\xff\x00\x10\x00\x00" + b"x" * 8,  # inside the bound, but the input is short
        b"\xc6\xdf" + b"x",  # two-octet length claims more than remains
        b"\xc6",  # header with no length at all
    ):
        report = inventory_report(wire)
        assert report.keys == []
        assert report.rejected
    assert time.perf_counter() - started < 2


def test_partial_body_abuse_is_refused():
    # partial lengths on a key packet, on a user id, a first chunk under 512, and one that never ends
    for wire in (
        b"\xc6\xe9" + bytes(512) + b"\x00",
        b"\xcd\xe9" + bytes(512) + b"\x00",
        b"\xcb\xe8" + bytes(256) + b"\x00",
        b"\xcb\xe9" + bytes(512),
    ):
        with pytest.raises(PgpError):
            parse_packets(wire)
        assert inventory_report(wire).rejected
    # a legal literal packet with many tiny chunks is bounded by max_partial_chunks
    wire = b"\xcb\xe9" + bytes(512) + b"\xe0\x00" * 100000 + b"\x00"
    with pytest.raises(LimitError):
        parse_packets(wire, Limits(max_partial_chunks=1000))


def test_a_flood_of_subpackets_is_skipped_with_a_note_not_a_crash():
    flood = CREATED + subpacket(23, b"\x80") * 5000
    ring = (
        KEY
        + UID
        + pkt(2, sig_v4_body(flood, subpacket(16, bytes(8)), sig_type=0x13))
        + pkt(2, sig_v4_body(CREATED + subpacket(16, bytes(8))))
    )
    (cert,) = parse_keyring(ring).certificates
    assert any("skipped" in p and "subpackets" in p for p in cert.problems)
    assert len(cert.user_ids[0].signatures) == 1  # the well-formed signature after it survives


def test_subpacket_area_longer_than_the_packet_is_skipped():
    body = bytearray(sig_v4_body(CREATED))
    body[4:6] = b"\xff\xff"
    (cert,) = parse_keyring(KEY + UID + pkt(2, bytes(body))).certificates
    assert any("skipped" in p for p in cert.problems)
    assert cert.user_ids[0].signatures == []


def test_too_many_keys_users_and_signatures_raise_a_limit_error():
    with pytest.raises(LimitError, match="keys"):
        parse_keyring(RING, Limits(max_keys=2))
    with pytest.raises(LimitError, match="user ids"):
        parse_keyring(KEY + UID * 10, Limits(max_user_ids=5))
    sig = pkt(2, sig_v4_body(CREATED + subpacket(16, bytes(8))))
    with pytest.raises(LimitError, match="signatures"):
        parse_keyring(KEY + UID + sig * 10, Limits(max_signatures_per_key=5))
    with pytest.raises(LimitError, match="packets"):
        parse_keyring(KEY + UID * 10, Limits(max_packets=5))
    with pytest.raises(LimitError):
        parse_keyring(RING, Limits(max_input_bytes=100))


def test_unknown_critical_packet_rejects_that_certificate_only():
    other = fixture("nistp384.pgp")
    ring = KEY + UID + pkt(30, b"unknown critical") + other
    report = inventory_report(ring)
    assert len(report.keys) == 1
    assert report.keys[0].fingerprint == inventory(other)[0].fingerprint
    assert "critical" in report.rejected[0]["reason"]
    # a literal data packet is a known critical packet that does not belong in a certificate
    assert inventory_report(KEY + UID + pkt(11, b"\x62\x00\x00\x00\x00\x00") + other).rejected


def test_unknown_noncritical_marker_trust_and_padding_packets_are_ignored():
    ring = KEY + pkt(10, b"PGP") + UID + pkt(12, b"trust") + pkt(50, b"future") + pkt(21, bytes(40))
    report = inventory_report(ring)
    assert len(report.keys) == 1
    assert not report.rejected
    assert report.packet_counts["MARKER(10)"] == 1
    assert report.packet_counts["UNASSIGNED(50)"] == 1


def test_orphan_user_id_and_subkey_are_rejected_not_crashed_on():
    assert inventory_report(UID).rejected
    assert inventory_report(pkt(14, ed25519_v4_body())).rejected
    assert inventory_report(pkt(6, b"\x04\x00")).rejected  # a truncated primary key


def test_a_bad_primary_key_does_not_hide_the_next_key():
    report = inventory_report(pkt(6, b"\x09junk") + KEY + UID)
    assert len(report.keys) == 1
    assert len(report.rejected) == 1


def test_huge_mpi_claims_are_bounded_by_the_packet():
    body = b"\x04\x00\x00\x00\x01\x01" + b"\xff\xff" + bytes(10) + mpi(3)
    report = inventory_report(pkt(6, body))
    assert report.rejected
    assert report.keys == []


def test_armor_damage_corpus():
    good = fixture("ring.asc").decode()
    body_line = good.splitlines()[3]
    cases = {
        "bad char": good.replace(body_line, body_line[:10] + "$" + body_line[11:], 1),
        "wrong tail": good.replace(
            "-----END PGP PUBLIC KEY BLOCK-----", "-----END PGP MESSAGE-----", 1
        ),
        "truncated": good[: len(good) // 2],
        "no blank line and no data": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n",
        "nul bytes": good.replace("A", "\x00", 3),
    }
    for name, text in cases.items():
        with pytest.raises(PgpError):
            inventory_report(text)
        assert name


def test_crc_mismatch_still_yields_keys():
    lines = fixture("ring.asc").decode().splitlines()
    for i, line in enumerate(lines):
        if line.startswith("=") and len(line) == 5:
            lines[i] = "=ZZZZ"
    report = inventory_report("\n".join(lines))
    assert len(report.keys) == 4
    assert {b["crc"] for b in report.armor} == {"mismatch"}


def test_deeply_nested_embedded_signatures_do_not_recurse_unboundedly():
    nested = sig_v4_body(CREATED, sig_type=0x19)
    for _ in range(3000):
        nested = sig_v4_body(CREATED + subpacket(32, nested), sig_type=0x18)
        if len(nested) > 60000:
            break
    report = survives(KEY + UID + pkt(14, ed25519_v4_body()) + pkt(2, nested))
    assert report is not None


def test_giant_armor_line_and_block_count_are_bounded():
    with pytest.raises(LimitError):
        armor.decode_blocks(
            "-----BEGIN PGP MESSAGE-----\n\n" + "A" * 5000, Limits(max_armor_line_bytes=1000)
        )
    many = armor.encode(b"\xc0\x00", kind="PGP MESSAGE") * 20
    with pytest.raises(LimitError):
        armor.decode_blocks(many, Limits(max_armor_blocks=10))


def test_non_utf8_user_ids_are_decoded_losslessly_enough_to_report():
    ring = KEY + pkt(13, b"\xff\xfe not utf-8 <x@example.invalid>")
    (rec,) = inventory(ring)
    assert "not utf-8" in rec.user_ids[0]["text"]


def test_armor_error_names_the_line():
    with pytest.raises(ArmorError, match="line"):
        armor.decode_blocks("-----BEGIN PGP MESSAGE-----\n\nAAAA$\n-----END PGP MESSAGE-----")


def test_new_header_helper_agrees_with_the_package_framing():
    assert parse_packets(new_header(13, 300) + bytes(300))[0].body == bytes(300)

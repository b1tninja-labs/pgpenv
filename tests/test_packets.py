"""Packet framing: RFC 9580 sec. 4 (headers, lengths, partial bodies, criticality)."""

from __future__ import annotations

import ast
import io
import pathlib
import time

import pytest

from pgpenv import limits, packet
from pgpenv.errors import LimitError, PacketError, TruncatedError
from pgpenv.limits import Limits, ParsePlan
from pgpenv.packet import Packet, encode_packet, iter_packets, parse_packets

from .helpers import legacy_pkt, new_header, pkt


def test_new_and_old_format_headers_decode_to_the_same_packet():
    body = b"hello user"
    for length_type in (0, 1, 2):
        (old,) = parse_packets(legacy_pkt(13, body, length_type))
        (new,) = parse_packets(pkt(13, body))
        assert (old.tag, old.body) == (new.tag, new.body) == (13, body)
        assert old.legacy
        assert not new.legacy


def test_rfc_4_2_3_length_examples():
    assert new_header(11, 100)[1:] == b"\x64"
    assert encode_packet(Packet(11, bytes(1723)))[1:3] == b"\xc5\xfb"
    assert encode_packet(Packet(11, bytes(100000)))[1:6] == b"\xff\x00\x01\x86\xa0"
    for n in (100, 1723, 100000):
        (p,) = parse_packets(encode_packet(Packet(11, bytes(n))))
        assert len(p.body) == n


@pytest.mark.parametrize("length", [0, 191, 192, 8383, 8384, 70000])
def test_length_boundaries_round_trip(length):
    body = bytes(length)
    wire = encode_packet(Packet(2, body))
    assert wire == pkt(2, body)
    (p,) = parse_packets(wire)
    assert p.body == body
    assert p.end == len(wire)


def test_partial_body_concatenation_matches_rfc_4_2_3():
    data = bytes(i % 251 for i in range(100000))
    wire = (
        b"\xcb\xef"
        + data[:32768]
        + b"\xe1"
        + data[32768:32770]
        + b"\xe0"
        + data[32770:32771]
        + b"\xf0"
        + data[32771 : 32771 + 65536]
        + b"\xc5\xdd"
        + data[32771 + 65536 :]
    )
    (p,) = parse_packets(wire)
    assert (p.tag, p.partial) == (11, True)
    assert p.body == data


def test_last_partial_length_is_refused():
    wire = b"\xcb\xe9" + bytes(512)  # a partial header with nothing after it: the chain never ends
    with pytest.raises(TruncatedError):
        parse_packets(wire)


def test_first_partial_below_512_refused():
    with pytest.raises(PacketError, match="512"):
        parse_packets(b"\xcb\xe8" + bytes(256) + b"\xc0")


def test_partial_on_a_signature_packet_refused():
    with pytest.raises(PacketError, match="partial"):
        parse_packets(b"\xc2\xe9" + bytes(512) + b"\x00")


def test_truncated_body_raises_without_allocating_the_claimed_size():
    started = time.perf_counter()
    with pytest.raises(LimitError):  # 4 GiB is over the default bound: refused before any read
        parse_packets(b"\xc6\xff\xff\xff\xff\xff" + b"0123456789")
    with pytest.raises(TruncatedError):  # inside the bound, but the input is ten octets
        parse_packets(b"\xc6\xff\x00\x10\x00\x00" + b"0123456789")
    assert time.perf_counter() - started < 1.0


def test_max_packet_bound():
    with pytest.raises(LimitError):
        parse_packets(pkt(11, bytes(1000)), Limits(max_packet_bytes=999))
    parse_packets(pkt(11, bytes(1000)), Limits(max_packet_bytes=1000))


def test_unknown_tags_are_preserved_and_classified():
    wire = pkt(63, b"private") + pkt(45, b"x") + pkt(30, b"y") + pkt(0, b"") + pkt(19, b"")
    packets = parse_packets(wire)
    assert [p.tag for p in packets] == [63, 45, 30, 0, 19]
    assert [p.critical for p in packets] == [False, False, True, True, True]
    assert [p.known for p in packets] == [False] * 5
    assert packets[0].body == b"private"
    assert packet.tag_info(21).shorthand == "PADDING"


def test_every_assigned_tag_is_named():
    for tag in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 17, 18, 21):
        assert Packet(tag, b"").known
    assert Packet(6, b"").name == "PUBKEY"
    assert Packet(17, b"").name == "UAT"


def test_indeterminate_legacy_length_reads_to_the_end():
    (p,) = parse_packets(legacy_pkt(11, b"tail of the file", 3))
    assert p.indeterminate
    assert p.body == b"tail of the file"
    # the new format has no such form: octet 0xff is a five-octet length
    with pytest.raises(TruncatedError):
        parse_packets(b"\xcb\xff")


def test_bit_seven_clear_is_refused_and_earlier_packets_are_yielded():
    iterator = iter_packets(pkt(13, b"a") + b"\x01\x02")
    assert next(iterator).tag == 13
    with pytest.raises(PacketError):
        next(iterator)


def test_file_object_input_and_offsets():
    wire = pkt(13, b"one") + pkt(13, b"two")
    ps = parse_packets(io.BytesIO(wire))
    assert [(p.offset, p.end) for p in ps] == [(0, 5), (5, 10)]


def test_partial_chunk_bound():
    wire = b"\xcb\xe9" + bytes(512) + (b"\xe0\x00" * 20) + b"\xc0"
    with pytest.raises(LimitError):
        parse_packets(wire, Limits(max_partial_chunks=10))


def test_check_names_the_bound_that_was_exceeded():
    limits.check(ParsePlan(packets=5, keys=1))
    with pytest.raises(LimitError, match="key count"):
        limits.check(ParsePlan(keys=3), Limits(max_keys=2))
    with pytest.raises(LimitError, match="embedded signature depth"):
        limits.check(ParsePlan(depth=9))


def test_package_code_has_no_assert():
    """python -O strips assert, so a bounds check written as one would vanish in production."""
    root = pathlib.Path(packet.__file__).parent
    offenders = [
        f"{path.name}:{node.lineno}"
        for path in root.rglob("*.py")
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.Assert)
    ]
    if offenders:
        pytest.fail("assert statements in package code: " + ", ".join(offenders))

"""cleartext signature framework: the exact signed text (RFC 9580 sec. 7).

A cleartext signed message is ``-----BEGIN PGP SIGNED MESSAGE-----``, optional legacy ``Hash``
headers, a blank line, dash-escaped text, and one or more armored signatures. :func:`parse`
returns the bytes a verifier must feed to the hash, which are not the bytes on the page:

* dash-escaping is reversed (a leading ``- `` is removed, sec. 7.2);
* trailing spaces and tabs are removed from every line (sec. 7.1);
* line endings become CR LF (sec. 7.1, a text signature is over canonical line endings);
* the line ending before ``-----BEGIN PGP SIGNATURE-----`` is not part of the text (sec. 7.1).

Because that last rule makes the ending of the final text line indistinguishable from the
separator unless the text has an empty line before the signature, the text of a message whose
last line is ``abc`` followed by a newline is ``abc`` plus CR LF, and the page shows a blank line
before the signature header. The RFC 9580 appendix A.6 vector pins this.

The framework refuses what sec. 6.2.2.3 and 7.1 say a verifier MUST decline: a Hash header that is
not a comma separated list of hash names, and any other armor header between the cleartext header
and the blank line. It raises :class:`CleartextError` rather than returning text a caller might
verify. The legacy ``Hash`` header is otherwise ignored when well formed (sec. 7.1), so the
hash algorithm comes from the signature packet, never from this header.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .armor import ArmorBlock, decode_blocks
from .errors import ArmorError, CleartextError, LimitError
from .limits import DEFAULT_LIMITS, Limits

__all__ = [
    "HASH_NAMES",
    "CleartextSigned",
    "parse",
]

# RFC 9580 sec. 9.5, Table 23, the "Text Name" column.
HASH_NAMES = frozenset(
    {"MD5", "SHA1", "RIPEMD160", "SHA256", "SHA384", "SHA512", "SHA224", "SHA3-256", "SHA3-512"}
)

_HEADER = b"-----BEGIN PGP SIGNED MESSAGE-----"
_SIG_BEGIN = b"-----BEGIN PGP SIGNATURE-----"
_LINES = re.compile(rb"\r\n|\n")


@dataclass(frozen=True, slots=True)
class CleartextSigned:
    """A parsed cleartext signed message.

    ``text`` is the exact octet string that is hashed (after the v6 salt, before the trailer).
    ``hash_names`` is what the legacy Hash headers listed, for display only. ``signatures`` are
    the armor blocks that follow. ``warnings`` records lines the RFC says SHOULD be flagged.
    """

    text: bytes
    hash_names: tuple[str, ...]
    signatures: tuple[ArmorBlock, ...]
    warnings: tuple[str, ...] = field(default_factory=tuple)


def parse(data: bytes | str, limits: Limits = DEFAULT_LIMITS) -> CleartextSigned:
    """Parse a cleartext signed message and return the exact signed text, RFC 9580 sec. 7."""
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    if len(raw) > limits.max_input_bytes:
        raise LimitError(f"input of {len(raw)} bytes exceeds the limit {limits.max_input_bytes}")
    lines = _LINES.split(raw)
    if len(lines) > limits.max_cleartext_lines:
        raise LimitError(f"more than {limits.max_cleartext_lines} lines")
    start = next((i for i, line in enumerate(lines) if line.rstrip(b" \t") == _HEADER), None)
    if start is None:
        raise CleartextError("no -----BEGIN PGP SIGNED MESSAGE----- line")
    index = start + 1
    hash_names: list[str] = []
    while True:
        if index >= len(lines):
            raise CleartextError("the message ends before the blank line after its headers")
        line = lines[index].rstrip(b" \t")
        index += 1
        if line == b"":
            break
        key, sep, value = line.partition(b": ")
        if not sep or key != b"Hash":
            raise CleartextError(
                f"armor header {line[:40]!r} between the cleartext header and the blank line: "
                "only a well-formed Hash header is permitted (RFC 9580 sec. 7.1)"
            )
        names = value.decode("ascii", "replace").split(",")
        if not value or any(name not in HASH_NAMES for name in names):
            raise CleartextError(f"non-conformant Hash header {value[:60]!r} (sec. 6.2.2.3)")
        hash_names.extend(names)
    text_lines: list[bytes] = []
    warnings: list[str] = []
    while True:
        if index >= len(lines):
            raise CleartextError("no -----BEGIN PGP SIGNATURE----- line after the text")
        line = lines[index]
        if line.rstrip(b" \t") == _SIG_BEGIN:
            break
        if line.startswith(b"- "):
            line = line[2:]
        elif line.startswith(b"-"):
            if line.startswith(b"-----"):
                raise CleartextError(
                    f"line {index + 1} of the text starts with an armor-looking dash run but is "
                    "not dash-escaped (RFC 9580 sec. 7.2)"
                )
            warnings.append(f"line {index + 1} starts with '-' followed by a non-space")
        text_lines.append(line.rstrip(b" \t"))
        index += 1
    try:
        signatures = decode_blocks(b"\n".join(lines[index:]), limits)
    except ArmorError as error:
        raise CleartextError(f"the signature block is damaged: {error}") from None
    if not signatures or any(b.label != "PGP SIGNATURE" for b in signatures):
        raise CleartextError("the message has no PGP SIGNATURE armor block")
    return CleartextSigned(
        b"\r\n".join(text_lines), tuple(hash_names), tuple(signatures), tuple(warnings)
    )

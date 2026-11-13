"""Test vectors copied from RFC 9580 appendix A (read through rfclib on 2026-11-12).

Appendix A is non-normative but the RFC publishes it for exactly this use. Each constant names
its appendix section.
"""

from __future__ import annotations

# A.1 Sample Version 4 Ed25519Legacy Key: the Public Key packet, hex as printed.
A1_PACKET = bytes.fromhex(
    "98330453f35f0b16092b06010401da470f01010740"
    "3f098994bdd916ed4053197934e4a87c80733a1280d62f8010992e43ee3b2406"
)
A1_FINGERPRINT = "C959BDBAFA32A2F89A153B678CFDE12197965A9A"
A1_ARMOR = """-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEU/NfCxYJKwYBBAHaRw8BAQdAPwmJlL3ZFu1AUxl5NOSofIBzOhKA1i+AEJku
Q+47JAY=
-----END PGP PUBLIC KEY BLOCK-----
"""

# A.2 Sample Version 4 Ed25519Legacy Signature over "OpenPGP".
A2_PACKET = bytes.fromhex(
    "885e0400160800060502"
    "55f95f95000a09108cfde12197965a9af62200ff56f90cca98e2102637bd983fdb16c131dfd27ed82bf4dde5"
    "606e0d756aed33660100d09c4fa11527f038e0f57f2201d82f2ea2c9033265fa6ceb489e854bae61b404"
)
A2_HASHED_INPUT = bytes.fromhex("4f70656e504750040016080006050255f95f9504ff0000000c")
A2_DIGEST = "f6220a3f757814f4c2176ffbb68b00249cd4ccdc059c4b34ad871f30b1740280"
A2_ARMOR = """-----BEGIN PGP SIGNATURE-----

iF4EABYIAAYFAlX5X5UACgkQjP3hIZeWWpr2IgD/VvkMypjiECY3vZg/2xbBMd/S
ftgr9N3lYG4NdWrtM2YBANCcT6EVJ/A44PV/IgHYLy6iyQMyZfps60iehUuuYbQE
-----END PGP SIGNATURE-----
"""

# A.3 Sample Version 6 Certificate: Ed25519 primary, Direct Key signature, X25519 subkey, binding.
A3_PRIMARY_FINGERPRINT = "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9"
A3_SUBKEY_FINGERPRINT = "12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885"
A3_ARMOR = """-----BEGIN PGP PUBLIC KEY BLOCK-----

xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf
GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy
KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw
gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE
QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn
+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh
BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8
j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805
I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==
-----END PGP PUBLIC KEY BLOCK-----
"""
# A.3.1 hashed data streams, as printed (salt first), for the Direct Key and Subkey Binding signatures.
A3_DIRECT_KEY_STREAM = bytes.fromhex(
    """
10 3e 2d 7d 22 7e c0 e6
d7 ce 44 71 db 36 bf c9
70 83 25 36 90 27 14 98
a7 ef 05 76 c0 7f aa e1
9b 00 00 00 2a 06 63 87
7f e3 1b 00 00 00 20 f9
4d a7 bb 48 d6 0a 61 e5
67 70 6a 65 87 d0 33 19
99 bb 9d 89 1a 08 24 2e
ad 84 54 3d f8 95 a3 06
1f 1b 0a 00 00 00 42 05
82 63 87 7f e3 03 0b 09
07 05 15 0a 0e 08 0c 02
16 00 02 9b 03 02 1e 09
22 21 06 cb 18 6c 4f 06
09 a6 97 e4 d5 2d fa 6c
72 2b 0c 1f 1e 27 c1 8a
56 70 8f 65 25 ec 27 ba
d9 ac c9 05 27 09 02 07
02 06 ff 00 00 00 4a
    """
)
A3_SUBKEY_BINDING_STREAM = bytes.fromhex(
    """
a6 e9 18 6d 9d 59 35 fc
8f e5 63 14 cd b5 27 48
6a 5a 51 20 f9 b7 62 a2
35 a7 29 f0 39 01 0a 56
9b 00 00 00 2a 06 63 87
7f e3 1b 00 00 00 20 f9
4d a7 bb 48 d6 0a 61 e5
67 70 6a 65 87 d0 33 19
99 bb 9d 89 1a 08 24 2e
ad 84 54 3d f8 95 a3 9b
00 00 00 2a 06 63 87 7f
e3 19 00 00 00 20 86 93
24 83 67 f9 e5 01 5d b9
22 f8 f4 80 95 dd a7 84
98 7f 2d 59 85 b1 2f ba
d1 6c af 5e 44 35 06 18
1b 0a 00 00 00 2c 05 82
63 87 7f e3 02 9b 0c 22
21 06 cb 18 6c 4f 06 09
a6 97 e4 d5 2d fa 6c 72
2b 0c 1f 1e 27 c1 8a 56
70 8f 65 25 ec 27 ba d9
ac c9 06 ff 00 00 00 34
    """
)

# A.6 Sample Cleartext Signed Message (dash-escaped, with the blank line before the signature).
A6_MESSAGE = """-----BEGIN PGP SIGNED MESSAGE-----

What we need from the grocery store:

- - tofu
- - vegetables
- - noodles

-----BEGIN PGP SIGNATURE-----

wpgGARsKAAAAKQWCY5ijYyIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJAAAAAGk2IHZJX1AhiJD39eLuPBgiUU9wUA9VHYblySHkBONKU/usJ9BvuAqo
/FvLFuGWMbKAdA+epq7V4HOtAPlBWmU8QOd6aud+aSunHQaaEJ+iTFjP2OMW0KBr
NK2ay45cX1IVAQ==
-----END PGP SIGNATURE-----
"""
A6_TEXT = b"What we need from the grocery store:\r\n\r\n- tofu\r\n- vegetables\r\n- noodles\r\n"
A6_SHA512 = (
    "69365bf44a97af1f0844f1f6ab83fdf6b36f26692efaa621a8aac91c4e29ea07"
    "e894cabc6e2f20eedfce6c03b89141a2cc7cbe245e6e7a5654addbec5000b89b"
)

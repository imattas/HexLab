# EBCDIC CP1140 string detection

The bounded string scanner recognizes IBM EBCDIC CP1140 alongside CP037,
CP500, and CP1047. CP1140 uses the CP037 mapping except that byte `0x9F`
decodes as U+20AC EURO SIGN instead of U+00A4 INTERNATIONAL CURRENCY SIGN.
The mapping follows IBM's CP1140 description: [IBM Enterprise COBOL currency
signs](https://www.ibm.com/docs/en/cobol-zos/6.3.0?topic=arithmetic-using-currency-signs).

Candidates retain their original byte extent and are decoded to Unicode for
previews. ASCII-only runs are still classified as ASCII; EBCDIC candidates may
contain only mapped control characters, subject to the scanner's existing
single-byte EBCDIC policy. The scan budget includes this additional decoding
pass. Detection is heuristic: bytes can be valid under multiple single-byte
encodings.

String encodings are serialized in derived caches. Cache version 75 recognizes
the new enum value and older cache versions cannot mislabel CP1140 rows.

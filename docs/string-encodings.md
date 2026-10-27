# String encoding candidates

String discovery reports the encoding used to decode each candidate. UTF-8 is
validated strictly; UTF-16LE and UTF-16BE reject isolated surrogates and scan
both possible two-byte alignments; UTF-32LE and UTF-32BE reject invalid
scalars. Unicode NUL code units terminate candidates. Each record retains the
original source byte start and length, its encoding and termination state, and
the mapped address when one exists. ASCII-only text is reported as ASCII,
while multibyte candidates keep their explicit byte order.

Windows-1252 is also scanned as a heuristic single-byte candidate. Bytes in
the printable Latin-1 range map to the same Unicode scalar, and the Windows
C1 punctuation mappings are decoded with a fixed table independent of the
host locale. Undefined Windows-1252 C1 slots terminate a candidate. Candidates
must contain at least one non-ASCII scalar, so the ASCII pass remains the
source of ASCII-only records. This heuristic can produce overlapping candidates
when arbitrary binary data resembles text; overlapping candidates are retained
instead of silently choosing an encoding.

Windows-1251 is scanned as a second single-byte heuristic, with an explicit
fixed mapping for Cyrillic letters and punctuation. Its undefined byte 0x98
ends a candidate. As with Windows-1252, emitted candidates must contain a
non-ASCII scalar, previews are UTF-8, and candidates may overlap other encoding
interpretations. These code-page labels identify plausible byte mappings;
they do not prove the source file's declared encoding or locale.

Windows-1250 is also scanned for Central European text, using a fixed mapping
and breaking runs at undefined bytes. Windows-1254 adds the Turkish Windows
code page, including dotted/dotless I and G-breve/S-cedilla letters. Both emit
only runs containing a non-ASCII scalar, retain original file/address extents,
and use UTF-8 previews. These mappings are heuristic; overlapping
interpretations are retained.

Windows-1253 and Windows-1255 add Greek and Hebrew Windows-code-page
candidates. Both use explicit fixed tables, end a candidate at undefined byte
positions, require at least one non-ASCII scalar, and retain the original byte
extent with a UTF-8 preview. They are heuristic candidates and may overlap the
other encodings. Their persisted `StringEncoding` values are appended as 10 and
11; derived-cache version 26 accepts them while older cache payloads are
recomputed.

Windows-1256 adds an Arabic Windows-code-page candidate using the Unicode
Consortium's historical Microsoft [CP1256 mapping table](https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1256.TXT).
It emits UTF-8 previews with original byte extents and requires a non-ASCII
scalar. Because this mapping defines every byte, arbitrary binary data can
yield candidates; the result is a code-page interpretation, not locale or
language classification. Its persisted encoding value is 12, and derived-cache
version 27 makes earlier payloads recompute.

Windows-1257 adds a Baltic code-page candidate using the Unicode Consortium's
historical Microsoft [CP1257 mapping table](https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1257.TXT).
Undefined byte positions break runs; emitted runs need a non-ASCII scalar and
retain their source extents with UTF-8 previews. The persisted encoding value is
13, and derived-cache version 28 causes older payloads to recompute. This is a
heuristic mapping and can produce overlapping interpretations of binary data.

Windows-1258 adds a Vietnamese code-page candidate from the Unicode
Consortium's historical Microsoft [CP1258 mapping table](https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1258.TXT).
Undefined byte positions break runs. Its five combining marks are retained as
separate Unicode scalars in UTF-8 previews; the scanner does not compose them
into precomposed Vietnamese letters. The persisted encoding value is 14, and
derived-cache version 29 causes older payloads to recompute. This remains a
heuristic mapping, not locale classification.

ISO-8859-2 (Latin-2) adds Central European single-byte candidates using the
Unicode Consortium's [8859-2 mapping table](https://www.unicode.org/Public/MAPPINGS/ISO8859/8859-2.TXT).
The scanner maps all bytes through a fixed table, lets the printable-scalar
filter split control characters, and emits candidates only when they contain a
non-ASCII scalar. Its persisted encoding value is 15, and derived-cache version
30 causes older payloads to recompute. As with other legacy encodings, these
are heuristic interpretations and can overlap.

ISO-8859-5 adds Cyrillic single-byte candidates using the Unicode Consortium's
[8859-5 mapping table](https://www.unicode.org/Public/MAPPINGS/ISO8859/8859-5.TXT).
The fixed mapping preserves the standard's control positions, which the
printable-scalar filter uses to split runs; emitted candidates need at least one
non-ASCII scalar and retain the original byte extent with a UTF-8 preview. Its
persisted encoding value is 16, and derived-cache version 31 recomputes older
payloads. These are heuristic byte interpretations rather than language
classification.

DOS code pages 437 and 850 add fixed OEM candidates for text originating in
legacy PC software. Their high-byte mappings use the Unicode Consortium's
[CP437 mapping table](https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP437.TXT)
and [CP850 mapping table](https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP850.TXT).
ISO-8859-15 adds the Latin-9 repertoire, including the euro and replacement
characters, using the Unicode Consortium's
[8859-15 mapping table](https://www.unicode.org/Public/MAPPINGS/ISO8859/8859-15.TXT).
All three use the same printable-scalar splitter and require at least one
non-ASCII scalar. The DOS and ISO mappings are heuristic, can overlap other
candidates, and do not classify a file's locale. Their persisted encoding
values are 17, 18, and 19; derived-cache version 32 recomputes older payloads.

`hexlab_cli disassemble <path> --show-strings` lists candidate encoding names,
file offsets, extents, and previews. The desktop Strings view uses the same
Windows-1253, Windows-1255, Windows-1256, Windows-1257, Windows-1258,
ISO-8859-2, ISO-8859-5, DOS-437, DOS-850, and ISO-8859-15 labels.

All encoding passes use the same file-backed scan domains, string-record budget,
and cancellation checks. Returned previews are UTF-8, while each record retains
the source byte length and encoding identity.

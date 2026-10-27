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

`hexlab_cli disassemble <path> --show-strings` lists candidate encoding names,
file offsets, extents, and previews. The desktop Strings view uses the same
Windows-1253, Windows-1255, Windows-1256, and Windows-1257 labels.

All encoding passes use the same file-backed scan domains, string-record budget,
and cancellation checks. Returned previews are UTF-8, while each record retains
the source byte length and encoding identity.

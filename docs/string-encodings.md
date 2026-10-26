# String encoding candidates

String discovery reports the encoding used to decode each candidate. UTF-8 is
validated strictly; UTF-16 rejects isolated surrogates; UTF-32 rejects invalid
scalars. ASCII-only text is reported as ASCII, while multibyte candidates keep
their explicit byte order.

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

All encoding passes use the same file-backed scan domains, string-record budget,
and cancellation checks. Returned previews are UTF-8, while each record retains
the source byte length and encoding identity.

# String encoding candidates

String discovery reports the encoding used to decode each candidate. UTF-8 is
validated strictly; UTF-16LE and UTF-16BE reject isolated surrogates and scan
both possible two-byte alignments; UTF-32LE and UTF-32BE reject invalid
scalars. Unicode NUL code units terminate candidates. At the beginning of a
scan domain, a matching UTF-8, UTF-16, or UTF-32 byte-order mark is skipped and
is excluded from the candidate's source extent; UTF-16/32 detection still
checks both byte orders and alignments for BOM-less data. Each record retains the
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

Windows-936 (GBK) adds a bounded multibyte candidate for legacy Simplified
Chinese data. The lead/trail byte ranges use a fixed 126-by-190 mapping table
generated from Python's `gbk` codec, with the single-byte 0x80 euro mapping
handled separately. Invalid pairs and non-printable values split runs; emitted
candidates need at least one non-ASCII scalar, retain original file/address
extents, and produce UTF-8 previews. A candidate with the exact same extent as
a strict UTF-8 result is suppressed, so valid UTF-8 text is not re-labeled as
GBK. Encoding ID 44 is appended, and derived-cache version 93 recomputes older
scans. The mapping is provenance for the byte-to-Unicode interpretation; this
is still a heuristic candidate and does not infer locale or language. Arbitrary
binary may still produce overlapping legacy-codepage candidates.

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
ISO-8859-2, ISO-8859-5, ISO-8859-9, DOS-437, DOS-850, DOS-866, DOS-852,
KOI8-R, and ISO-8859-15 labels.

All encoding passes use the same file-backed scan domains, string-record budget,
and cancellation checks. Returned previews are UTF-8, while each record retains
the source byte length and encoding identity.


ISO-8859-9 (Latin-5) adds Turkish single-byte candidates using the Unicode
Consortium's [8859-9 mapping table](https://www.unicode.org/Public/MAPPINGS/ISO8859/8859-9.TXT).
It follows Latin-1 except for the six Turkish G-breve, dotted/dotless I, and
S-cedilla replacements. C1 controls are split by the shared printable-scalar
filter. Candidates require a non-ASCII scalar, keep original source extents,
and use UTF-8 previews. Persisted encoding value 20 and derived-cache version
33 cause older cache payloads to recompute. This is a heuristic mapping and
does not classify file locale.

DOS-866 and DOS-852 add fixed OEM mappings for Cyrillic and Central European
DOS text, sourced from the Unicode Consortium's historical Microsoft
[CP866 table](https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP866.TXT)
and [CP852 table](https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP852.TXT).
KOI8-R adds the fixed Cyrillic mapping described by
[RFC 1489](https://datatracker.ietf.org/doc/html/rfc1489) and the Unicode
Consortium's [vendor mapping](https://www.unicode.org/Public/MAPPINGS/VENDORS/MISC/KOI8-R.TXT).
All three preserve the existing single-byte candidate rules: the shared
printable-scalar filter splits control values, candidates need at least one
non-ASCII scalar, and records keep source extents with UTF-8 previews. They
share the global inspection and result budgets. Persisted values 21, 22, and
23 are appended without renumbering prior encodings; derived-cache version 35
recomputes older payloads. These are heuristic mappings and do not infer a
file's declared encoding or locale.

KOI8-U adds the Ukrainian Cyrillic variant from RFC 2319 and the Unicode
Consortium's [KOI8-U mapping](https://www.unicode.org/Public/MAPPINGS/VENDORS/MISC/KOI8-U.TXT).
Its four added Ukrainian letters replace eight box-drawing characters in the
KOI8-R high-byte repertoire. The fixed mapping uses the same printable-scalar
splitter, non-ASCII candidate requirement, source extents, and UTF-8 previews.
KOI8-U uses persisted encoding ID 37; derived-cache version 61 recomputes
older payloads. CLI, Python, and desktop encoding labels include KOI8-U. The
candidate remains heuristic and does not classify file language or locale.

CLI, desktop Strings, and Python API encoding labels expose DOS-866, DOS-852,
and KOI8-R. The supported legacy set remains incomplete and does not perform
locale or language classification.

Mac Roman adds the fixed Apple Macintosh Roman mapping for legacy Macintosh
resources and executables. The table follows the Unicode Consortium's
[Apple Roman mapping](https://www.unicode.org/Public/MAPPINGS/VENDORS/APPLE/ROMAN.TXT),
including its private-use Apple logo glyph. Candidates use the common
printability splitter and non-ASCII requirement, retain original extents, and
produce UTF-8 previews. Encoding ID 24 is appended to the persisted enum and
derived-cache version 36 recomputes older cached scans. Labels are available in
the CLI, Python API, desktop Strings view, and general desktop encoding
formatter; locale is not inferred.

ISO-8859-1 (Latin-1) adds a direct byte-to-scalar candidate for legacy Western
European data. C0 and C1 controls are split by the shared printability filter;
records with non-ASCII content retain source offsets and lengths and expose
UTF-8 previews. Its persisted encoding value is 25, and derived-cache version
37 causes older cached scans to be recomputed. The label is exposed by the CLI,
desktop Strings view, desktop encoding formatter, and Python API. This remains a
heuristic candidate and does not infer the source locale.

ISO-8859-3 (Latin-3) adds a fixed single-byte candidate using the Unicode
Consortium's [8859-3 mapping table](https://www.unicode.org/Public/MAPPINGS/ISO8859/8859-3.TXT).
The scanner applies the Latin-3 letter substitutions and breaks runs at its
seven undefined byte positions; C0/C1 controls are split by the common
printability filter. Candidates require non-ASCII content and retain source
extents with UTF-8 previews. Persisted encoding value 26 and derived-cache
version 38 cause older cached scans to recompute. CLI, desktop, and Python
labels expose ISO-8859-3. It remains a heuristic mapping, not locale
classification.

ISO-8859-4 (Latin-4) adds a Baltic/Nordic single-byte candidate using the
Unicode Consortium's [8859-4 mapping table](https://www.unicode.org/Public/MAPPINGS/ISO8859/8859-4.TXT).
The fixed mapping retains its Latin-1-compatible positions and substitutes the
Latin-4 letters; control characters are split by the shared printability
filter. Candidates require a non-ASCII scalar and retain original source
extents with UTF-8 previews. Persisted encoding value 27 and derived-cache
version 39 cause older cached scans to recompute. CLI, desktop, and Python
labels expose ISO-8859-4. It remains a heuristic mapping, not locale
classification.

ISO-8859-6 adds Arabic single-byte candidates using the Unicode Consortium's
[8859-6 mapping table](https://www.unicode.org/Public/MAPPINGS/ISO8859/8859-6.TXT).
Defined Arabic letters, vowel marks, punctuation, and currency/spacing values
map to Unicode scalars; unassigned byte positions end a candidate, while
control characters are split by the shared printable-scalar filter. Candidates
require non-ASCII content and retain their source extents with UTF-8 previews.
Persisted encoding value 28 is appended without renumbering earlier values;
derived-cache version 41 recomputes older payloads. This is a heuristic byte
mapping, not a determination of file locale or language.


ISO-8859-6 labels are available in the CLI, Python API, and desktop Strings encoding filter.

ISO-8859-7 adds bounded Greek single-byte candidates using the Unicode Consortium's
ISO 8859-7:2003 table. Undefined bytes split candidates, and controls continue to
use the shared printable-scalar handling. The encoding is persisted as ID 29 and
the derived cache format advances to version 42. CLI, Python, and desktop labels
are available. This is a candidate scan, not locale detection or language
classification.


ISO-8859-10, ISO-8859-13, ISO-8859-14, and ISO-8859-16 add fixed single-byte
candidates using the Unicode Consortium mappings for [8859-10](https://www.unicode.org/Public/MAPPINGS/ISO8859/8859-10.TXT),
[8859-13](https://www.unicode.org/Public/MAPPINGS/ISO8859/8859-13.TXT),
[8859-14](https://www.unicode.org/Public/MAPPINGS/ISO8859/8859-14.TXT), and
[8859-16](https://www.unicode.org/Public/MAPPINGS/ISO8859/8859-16.TXT).
The scanner keeps stable encoding IDs 30-33, uses the common printable-scalar and
work-budget rules, and exposes names through CLI, Python, and the desktop filter.
Derived-cache version 44 causes prior scans to be recomputed. These candidates
remain heuristic and do not infer locale or language.

ISO-8859-8 adds fixed Hebrew single-byte candidates from the Unicode
Consortium's [8859-8 mapping](https://www.unicode.org/Public/MAPPINGS/ISO8859/8859-8.TXT).
Undefined byte positions split runs; printable filtering removes controls while
preserving Hebrew letters, punctuation, and directional marks. Candidates still
require non-ASCII content and retain the original source extent with UTF-8
previews. Encoding ID 34 is appended without renumbering earlier values, and
derived-cache version 47 invalidates scans created before this decoder. CLI,
Python, and desktop labels expose ISO-8859-8. This is a bounded encoding
candidate, not locale or language detection.

ISO-8859-11 adds Thai single-byte candidates from the Unicode Consortium's
[8859-11 mapping](https://www.unicode.org/Public/MAPPINGS/ISO8859/8859-11.TXT).
The mapping follows TIS 620-2533 with the ISO-defined no-break space at 0xa0;
reserved byte positions split candidates. Runs require non-ASCII content and
retain source extents with UTF-8 previews. Encoding ID 35 is appended, and
derived-cache version 57 recomputes older string scans. CLI, Python, and
desktop labels and the desktop filter expose ISO-8859-11. The result is a
mapping candidate and does not classify text language or locale.

Windows-874 adds the Thai Windows code-page interpretation using the Unicode
Consortium's [CP874 mapping table](https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP874.TXT).
It shares the ISO-8859-11 Thai assignments, but maps the defined Windows C1
punctuation positions (including euro and quotation marks) and terminates runs
at undefined positions. Candidates require non-ASCII content and retain source
extents with UTF-8 previews. Persisted encoding value 36 is appended without
renumbering earlier values; derived-cache version 58 recomputes earlier cached
scans. CLI, Python, and desktop labels/filter expose Windows-874. This is a
candidate mapping and does not classify file locale or language.

Mac Cyrillic adds the Mac OS 9 and later Cyrillic mapping from Apple's
[Unicode Consortium vendor table](https://www.unicode.org/Public/MAPPINGS/VENDORS/APPLE/CYRILLIC.TXT).
The fixed mapping includes the Ukrainian ghe-with-upturn letters and the euro
sign variant at byte `0xff`; earlier localized Mac Cyrillic variants are not
guessed. Candidates require non-ASCII text, preserve source byte extents, and
emit UTF-8 previews. Encoding ID 38 is appended, and derived-cache version 62
admits the new value while retaining compatible reads of older cache versions.
CLI, Python, and the desktop encoding filter label it **Mac Cyrillic**. This
remains a heuristic candidate and does not infer locale or language.

EBCDIC CP037 adds IBM US/Canada single-byte candidates using the Unicode
Consortium's [CP037 mapping](https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/EBCDIC/CP037.TXT).
Unlike ASCII-compatible encodings, ordinary English letters in CP037 occupy
non-ASCII byte values but decode to ASCII Unicode scalars, so candidates do not
require a non-ASCII decoded character. Each candidate run must contain at least
one source byte at or above `0x80`; this avoids labeling purely ASCII byte runs
as CP037 while still allowing ordinary EBCDIC text. Controls and line separators
still split runs through the shared printable filter. Encoding ID 39 is appended, and
derived-cache version 66 recomputes earlier string scans while retaining older
supported payload versions. CLI, Python, and desktop filters label it
**EBCDIC CP037**. Detection is heuristic and does not identify a file's locale
or prove that a candidate originated on an EBCDIC system.

EBCDIC CP500 adds the IBM International single-byte mapping. Its decoder shares
the CP037 mapping and overrides the seven punctuation positions that differ in
the Unicode Consortium's [CP500 mapping table](https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/EBCDIC/CP500.TXT). Candidate runs use the same non-ASCII-source-byte requirement and printable-scalar filtering as CP037. Encoding ID 40 is appended; derived-cache version 68 accepts this value while preserving reads of older supported versions. CLI, Python, and desktop filters label it **EBCDIC CP500**. Detection remains heuristic and cannot distinguish locale or establish the original encoding.

EBCDIC CP1047 adds the IBM open-systems single-byte mapping from ICU's
[`ibm-1047_P100-1995.ucm`](https://github.com/unicode-org/icu-data/blob/main/charset/data/ucm/ibm-1047_P100-1995.ucm),
which records the IBM CDRA source mapping. It uses the same non-ASCII-source
byte gate and printable-scalar splitting as CP037/CP500. Encoding ID 41 is
appended; derived-cache version 72 accepts the new value while retaining
compatible reads of supported older versions. CLI, Python, and desktop string
filters label it **EBCDIC CP1047**. Detection remains heuristic and does not
identify a file's locale or prove that a candidate originated on EBCDIC media.

EBCDIC candidates also apply a small per-run plausibility gate because a
single high-bit byte can otherwise cause arbitrary binary to decode as a
printable run. A run must contain at least two Latin letters, or consist of at
least eight decimal digits; it must still contain a high-bit source byte and
pass the shared printable filter. This keeps short words and longer numeric
fields while suppressing many punctuation-heavy fragments. The rule is a
candidate-quality heuristic, not language detection, and can omit unusual
symbol-only EBCDIC text.

Windows-932 (CP932, Microsoft Shift-JIS) adds a bounded multibyte candidate
using the fixed Unicode Consortium
[CP932 mapping table](https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP932.TXT).
The scanner accepts the defined lead/trail byte ranges, maps single-byte
characters and double-byte pairs, and splits a run at invalid or unmapped
sequences. NUL terminates a run; emitted candidates require non-ASCII content,
retain original byte extents, and use UTF-8 previews. Persisted encoding ID 43
is appended, derived-cache version 89 recomputes older scans, and CLI, Python,
and desktop filters expose **Windows-932**. This is a candidate byte mapping,
not source-encoding, language, or locale classification; vendor-specific
extensions outside the Unicode CP932 table remain unsupported.

CLI and Python string records also expose a `script_hint`, derived from the
retained UTF-8 preview (up to 256 Unicode scalars). It reports a coarse script
family for Latin, Cyrillic, Greek, Hebrew, Arabic, Thai, Han, Kana, Hangul,
Armenian, the major Indic scripts, Lao, Tibetan, Myanmar, Georgian, Ethiopic,
Cherokee, Canadian Aboriginal syllabics, Khmer, Mongolian, Syriac, Thaana, N'Ko,
Tifinagh, Vai, Yi, Adlam, Osage, and Ol Chiki; recognized but not separately
listed blocks report Other. Text containing more than one recognized family is
Mixed. Punctuation and digits do not select a family. Unknown is returned for
empty or malformed UTF-8 previews and previews without recognized letters.
This is a bounded Unicode-block display hint, not full Unicode Script-property,
language, or locale detection, and Kana plus Han may therefore be reported as
Mixed for Japanese text.

# Windows-1252 text search

Literal text search accepts UTF-8 query text and can encode it as Windows-1252
for scanning legacy single-byte data. The encoder covers ASCII, U+00A0 through
U+00FF, and the defined punctuation/letter mappings in bytes `0x80` through
`0x9f`. Undefined Windows-1252 byte positions have no Unicode scalar mapping;
a query containing a scalar outside the encoding is rejected instead of being
substituted or truncated.

The encoding is available as `TextEncoding::windows1252`, CLI
`--encoding windows1252`, Python `search_text(..., encoding="windows1252")`,
and the desktop Find encoding picker. Existing query fingerprinting includes
the appended encoding value and compiled bytes, so paged cursors remain bound
to the exact text encoding. Case-insensitive mode folds ASCII letters only;
all non-ASCII Windows-1252 characters remain exact, with no locale-sensitive
or Unicode case folding.

This adds a query encoding, not an encoding detector. It does not match UTF-8
representations of the same characters or provide other Windows code pages.

# ISO-8859-1 text search

Literal text search accepts strict UTF-8 query text and can encode it as
ISO-8859-1 (Latin-1). Each Unicode scalar from U+0000 through U+00FF maps to
the byte with the same value; a query containing a larger scalar is rejected
instead of being substituted or truncated. Case-insensitive searches fold
ASCII letters only; other bytes remain exact.

Use `TextEncoding::iso8859_1`, CLI `--encoding iso8859_1`, Python
`search_text(..., encoding="iso8859_1")`, or the desktop Find encoding
picker. The encoding is appended after Windows-1252, preserving all existing
encoding values and cursor fingerprints. Paged cursors remain bound to the
compiled query bytes and selected encoding.

This is a query encoder, not an encoding detector. It does not normalize text,
fold non-ASCII case, or match the UTF-8 bytes for the same characters.

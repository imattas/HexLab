# Windows-1250 string detection

The bounded string scanner now recognizes Windows-1250 single-byte text in
addition to ASCII, UTF-8, UTF-16/32, Windows-1251, and Windows-1252. It decodes
the complete defined Windows-1250 byte mapping to Unicode for previews and
reports the original byte extent and encoding on each candidate.

Undefined code-page bytes break a candidate. ASCII-only runs remain classified
as ASCII, and a Windows-1250 row is emitted only when it contains at least one
non-ASCII scalar. NUL terminates a candidate; other non-printable scalars split
it. Code-page detection is heuristic, so bytes that are valid in several
single-byte encodings can produce multiple candidates. The scan work budget
counts inspections made by this additional encoding pass.

String encoding values are persisted in derived caches. The derived-cache
version advances to 23 so older builds reject records that may contain the new
encoding value instead of mislabeling or misreading them.

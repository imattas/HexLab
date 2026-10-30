# PE Rich header

The PE loader API can inspect the optional Rich header encoded in the DOS stub.
The parser validates `MZ`, `e_lfanew`, the PE signature, the `Rich` marker and
XOR key, the decoded `DanS` marker and its three zero padding DWORDs, and a
complete bounded table of product/count pairs. Each pair retains the decoded
32-bit `comp.id` and object count; its high and low 16-bit halves are shown as
the product and build fields. Source file offset, byte size, and XOR key are
also reported.

The metadata describes values embedded in the file and does not verify a
compiler's identity or authorship. Inputs without a Rich marker return an
empty optional. A present but malformed marker sequence returns an error.
Parsing scans at most the first 1 MiB of the DOS stub before `e_lfanew` and
retains at most 4,096 rows. A longer stub without a marker reports the scan
limit instead of claiming the header is absent. CLI inspection displays at
most 128 rows.

# PE Security directory certificates

The PE Security data directory (index 4) is file-backed rather than RVA-based.
HexLab validates its 8-byte file-offset and size alignment, full file extent,
and bounded record count, then walks `WIN_CERTIFICATE` entries. Each record must
contain the eight-byte header, declare a length of at least eight bytes, use
revision `0x0100` or `0x0200`, and have a nonzero certificate type. The record
length must fit the table; the next record begins at the checked 8-byte aligned
end. The table must be consumed exactly.

Metadata retains each header's length, revision, type, file source span, and
the raw certificate payload span. The desktop Certificates page shows those
fields and navigates to the payload bytes. Common X.509, PKCS#7, TS, and EFI
type values receive labels; other nonzero types remain opaque and visible.

This is structural parsing only. HexLab does not decode certificate formats,
verify cryptographic signatures, validate Authenticode digests, or build a
certificate trust chain. Invalid alignment, truncated records, unsupported
revisions, zero types, or out-of-file extents make PE metadata partial while
leaving the mapped image available.

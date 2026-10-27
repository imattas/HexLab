# Mach-O code-signature metadata

`LC_CODE_SIGNATURE` remains a linkedit declaration and is now inspected as a
bounded big-endian embedded-signature SuperBlob when its payload is at most
16 MiB. The loader validates the SuperBlob length and index table, caps the
blob count at 4,096, checks each indexed blob header and extent, and reports
whether blob ranges overlap. Each row retains its SuperBlob index, slot type,
blob magic, relative blob offset, absolute source file offset, and blob size.

For CodeDirectory blobs (`0xfade0c02`) at least 44 bytes long, the CLI also
shows the encoded version, flags, 32-bit code limit, code-slot count, hash
size/type, platform, and page-size exponent. Other blob kinds stay visible as
uninterpreted rows and make protection metadata incomplete. Signature payloads
larger than 16 MiB are retained as declarations only. Parsed bytes and rows
count against the loader's 64 MiB metadata budget.

This is structural metadata only. HexLab does not compute CodeDirectory
hashes, verify CMS/signature blobs, validate entitlements or requirements, or
establish signer identity or trust. Newer CodeDirectory extensions such as
64-bit code limits are not interpreted; the displayed limit is the legacy
32-bit field. Malformed SuperBlob/index/blob extents are rejected by the
loader, while unsupported blob kinds are retained and mark the metadata
incomplete.

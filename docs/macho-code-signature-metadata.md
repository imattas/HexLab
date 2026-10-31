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

The read-only `verify_macho_code_directory_hashes` API and CLI verify
contiguous code-page hashes for CodeDirectory SHA-256 (type 2) and truncated
SHA-256 (type 3), through version `0x20300`. Version `0x20300` reads the
64-bit `codeLimit64` at its versioned offset and uses it when nonzero, falling
back to the legacy 32-bit `codeLimit` when zero. The CLI reports both encoded
limits and the effective limit. Verification checks the versioned header size,
the absence of a scatter vector, code-limit/page-size slot count, bounded
hash-array extent, selected-slice extent, and each page hash. CLI work is
capped at 256 MiB and eight CodeDirectory blobs per image, with at most 16
mismatch slots displayed per blob.

This does not verify CMS/signature blobs, validate entitlements or
requirements, or establish signer identity or trust. SHA-1/SHA-384, scatter
vectors, and CodeDirectory versions newer than `0x20300` remain unsupported.
Malformed SuperBlob/index/blob extents are rejected by the loader, while
unsupported blob kinds are retained and mark the metadata incomplete.

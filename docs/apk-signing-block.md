# APK Signing Block inventory

`inspect_apk_signing_block` locates the APK Signing Block immediately before
the ZIP central directory. It reads the ZIP32 EOCD or ZIP64 end records, checks
the single-disk archive layout, and validates the `APK Sig Block 42` footer,
mirrored little-endian 64-bit size fields, and each length-prefixed ID/value
pair. Pair IDs must be unique. Each retained value is opaque and carries the
pair's source offset.

The defaults cap the block and aggregate pair values at 64 MiB and the pair
count at 4,096. Absence of the footer magic is reported as `present == false`;
inconsistent sizes, truncated pairs, duplicate IDs, or invalid ZIP extents are
reported as malformed input.

This inspects container framing only. It does not parse v2/v3 signer records,
verify APK content digests or signatures, validate certificates or publisher
trust, inspect the separate v4 `.idsig` file, or connect signing-block
verification to extracted DEX payloads. The block structure follows the
[Android Open Source Project APK Signature Scheme v2 documentation](https://source.android.com/docs/security/features/apksigning/v2).

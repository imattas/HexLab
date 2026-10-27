# Mach-O build-version metadata

Mach-O loading retains `LC_BUILD_VERSION` and the legacy `LC_VERSION_MIN_*`
commands in `MachOMetadata::build_versions`. Each record includes the command
index and file offset, numeric platform identifier, minimum OS version, SDK
version, and (for modern commands) the ordered tool/version records. Unknown
platform and tool IDs remain numeric so newer SDK values stay inspectable.

The parser validates the fixed header, bounds the tool count to 4096, checks the
full tool array against the command extent, and charges records and payload bytes
to the loader metadata budget. Extra bytes after a modern command's declared
`ntools` records are preserved as an incomplete command set; truncated tool
arrays are rejected. Legacy macOS, iOS, tvOS, and watchOS commands are mapped
to their corresponding platform IDs and retain their packed A.B.C versions.

CLI Mach-O inspection prints each build record and its tools. Version words are
rendered as `major.minor.patch`; platform and tool IDs are intentionally shown
as numbers. These declarations describe the build target only. They do not
select a runtime, validate an SDK, or prove that code is compatible with the
reported platform.

`LC_SOURCE_VERSION` is retained separately as a packed 64-bit source version
and decoded into its A.B.C.D.E fields (24 bits for A, 10 bits for each
remaining component). The parser requires the exact 16-byte command size and
charges the record to the metadata budget. CLI inspection prints both the
decoded components and the original packed word. This identifies source
version metadata; it does not validate a source revision or build provenance.

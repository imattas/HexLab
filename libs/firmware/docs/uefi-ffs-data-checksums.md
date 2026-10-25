# UEFI FFS file-data checksums

The PI firmware-volume inventory now validates the FFS `IntegrityCheck.Checksum.File` field when a file's normalized state includes `EFI_FILE_DATA_VALID`. The result is exposed as `UefiFfsFile::data_checksum_valid` and printed by `hexlab_cli firmware inspect ... --format uefi` as `data-checksum=valid|not-valid`.

When `FFS_ATTRIB_CHECKSUM` is set, the parser computes the 8-bit two's-complement checksum over the complete FFS file-data range (all bytes after the short or extended FFS header). When the attribute is clear, it checks the required fixed value `0xAA`. For files without the data-valid state bit, the result is not applicable and the API field is empty. A mismatch is reported as metadata and does not discard the containing volume or file, so inspection can still show the affected file and its sections.

The validation uses constant additional memory and is bounded by the already validated file extent and input-size limit. It does not validate PE/TE image checksums, authentication signatures, or capsule-level integrity. The field definition follows the [UEFI PI specification's FFS integrity definitions](https://uefi.org/specs/PI/1.10/V3_Code_Definitions.html#efi-ffs-integrity-check) and TianoCore's [FFS header definitions](https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Pi/PiFirmwareFile.h).

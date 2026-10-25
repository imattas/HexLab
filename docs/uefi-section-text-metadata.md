# UEFI section text and subtype metadata

The firmware-volume inventory reads three additional PI section forms without
copying or decoding their payloads:

- `EFI_SECTION_USER_INTERFACE` exposes its null-terminated UTF-16 name.
- `EFI_SECTION_VERSION` exposes its 16-bit build number and null-terminated
  UTF-16 version text.
- `EFI_SECTION_FREEFORM_SUBTYPE_GUID` exposes its subtype GUID and adjusts the
  reported payload range to begin after the GUID.

Text is limited to 4,096 UTF-16 code units, must contain a terminator, may only
have zero or erased-byte padding after that terminator, and must use valid
surrogate pairs. The CLI prints human-readable UTF-8 while escaping quotes,
backslashes, controls, line separators, and bidirectional control characters.
Malformed text or truncated subtype-GUID sections are reported as malformed
section streams on their containing FFS file.

Section rows also include names for common PI section type values while keeping
the numeric type as the stable identifier. Standard EFI compression type `1`
is decoded under strict source, output, and work caps to inventory nested
section metadata; child offsets are marked as decoded-stream-relative. Tiano
custom compression and GUID-defined sections remain opaque. Decoding does not
imply payload execution or PE/TE image loading. See
[bounded UEFI standard compression](uefi-standard-compression.md) for limits
and details.

The section layouts follow the [UEFI PI Specification 1.9, Firmware Storage
Formats](https://uefi.org/sites/default/files/resources/UEFI_PI_Spec_Final_Draft_1.9.pdf).

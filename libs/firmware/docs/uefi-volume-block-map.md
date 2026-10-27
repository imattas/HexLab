# UEFI firmware-volume block maps

`UefiFirmwareVolume::block_map` retains each non-terminating `{NumBlocks,
BlockLength}` row from the validated FV header. The parser still verifies that
all rows fit within the declared header, that the `{0,0}` terminator is
present, and that the overflow-checked sum of `NumBlocks * BlockLength` equals
`FvLength`. The terminator is represented by the end of the vector rather than
as a data row.

The CLI prints each row and its mapped byte extent so mixed erase geometries
remain visible during inspection. It does not infer physical addresses or
write operations from these logical-volume blocks. The row layout and
run-length encoding follow the [PI 1.10 `EFI_FIRMWARE_VOLUME_HEADER` block-map
definition](https://uefi.org/specs/PI/1.10/V3_Code_Definitions.html#efi-firmware-volume-header).

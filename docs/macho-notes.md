# Mach-O `LC_NOTE` metadata

The loader recognizes `LC_NOTE` commands with the fixed 40-byte layout. It
retains the command index and file provenance, the exact 16-byte `data_owner`
field, and the declared data span. The payload offset and size are validated
against the selected thin or universal slice before the row is published;
payload bytes remain opaque and are not copied or interpreted.

CLI inspection prints each note owner, payload file offset and size, and load
command file offset. Owners are displayed as escaped text so embedded NUL and
nonprinting bytes do not disappear. This is bounded inventory metadata, not a
decoder for core-file notes or other owner-specific payload formats.

The command layout follows Apple's [`note_command` definition in `loader.h`](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h).

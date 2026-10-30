# GNU ELF ABI tag notes

The ELF loader recognizes notes with owner `GNU` and type
`NT_GNU_ABI_TAG` (1) in `PT_NOTE`, `PT_GNU_PROPERTY`, and `SHT_NOTE` ranges.
The descriptor must contain at least four 32-bit words. Those words are
decoded using the ELF byte order as OS identifier, ABI major, minor, and
subminor versions. Any trailing descriptor bytes are retained as an opaque
extension. Each result includes the note and descriptor file offsets and its
program/section source; duplicate views of the same file note are merged.

The CLI names the currently standardized OS identifiers Linux (0), GNU/Hurd
(1), Solaris 2 (2), and FreeBSD (3), and prints unknown identifiers
numerically. A tag is a compatibility/version claim in the file. It does not
prove that a particular runtime, loader, or kernel accepts the image.

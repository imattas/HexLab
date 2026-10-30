# Wide values in composite debugger locals

DWARF composite locals may contain a `DW_OP_implicit_value` fragment wider
than 64 bits. The Locals view displays the exact captured bytes for such a
piece, in target byte order, alongside its destination bit offset and size.
The preview is capped at 32 bytes per piece and indicates when bytes are
omitted. No live target memory read is performed for an implicit value.

Memory-backed and register-backed pieces continue to show bounded previews
from their respective sources. This display does not combine pieces into a
decoded aggregate; it preserves each piece's location and bit layout.

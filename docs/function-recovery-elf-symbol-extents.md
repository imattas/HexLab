# ELF function-symbol extents in function recovery

Defined ELF `STT_FUNC` symbols with nonzero sizes now provide a bounded
function extent when stronger unwind metadata is unavailable. The start still
passes through the ordinary function-root checks. A symbol extent is accepted
only when all nonzero-sized `STT_FUNC` aliases at that address agree, the
entire range fits in one initialized executable segment and the image's code
policy, and no unwind range or explicit function decision already supplies a
boundary.

The size limits CFG ownership; it does not imply that every byte in the extent
is an instruction. Recovery still decodes typed control flow and stops at
invalid, unsupported, or truncated instructions. Empty sizes, conflicting
aliases, invalid extents, and ranges crossing segment or initialized-byte
boundaries do not constrain recovery. `STT_GNU_IFUNC` symbols remain roots for
their resolver code, but their sizes are not used as function extents because
the runtime-selected implementation is separate.

This helps keep adjacent ELF functions separate when a binary has useful
symbol sizes but no validated FDE for the function. It does not infer sizes
from names, byte patterns, or neighboring symbols.

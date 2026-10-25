# Runtime initializer function roots

Function discovery now uses additional loader-declared routine roots that can
exist without ordinary function symbols.

For executable and shared-object ELF images, nonzero `DT_INIT` and `DT_FINI`
virtual addresses become initializer seeds. The analyzer validates each seed
against the current image mapping and requires initialized executable bytes
before decoding. `DT_PREINIT_ARRAY`, `DT_INIT_ARRAY`, and `DT_FINI_ARRAY` are
also read as bounded pointer tables. Their declared size must be an exact
multiple of the ELF pointer width and contain no more than 65,536 entries.
Each slot must be fully file-backed and readable. The relocation index is
consulted before reading stored bytes; exact symbol relocations and
base-relative relocations are resolved using the image load bias. An opaque,
overlapping, or ambiguous relocation is not treated as a raw pointer. For an
unrelocated PIE pointer, the analyzer accepts a rebased or link-time address
only when exactly one interpretation maps to initialized executable bytes.
Each resulting root records its array slot as the seed source and retains its
file offset, initializer family, table index, dynamic tag, and exact relocation
row IDs. Mach-O seeds also retain classic/chained dyld origin row IDs. These
records are serialized with derived function facts, so navigation can return
from a function root to its initializer slot and fixup evidence. Every target
still passes the usual current-image code-context, initialized-byte,
executable-permission, and relocation code-start checks before becoming a
function root. Unrelocated ambiguity in PIE address interpretation does not
seed either candidate.

For Mach-O images, `LC_ROUTINES` and `LC_ROUTINES_64` module initializer
addresses are retained as separate metadata from process entry commands. A
nonzero address is published as a root only when it maps to initialized
executable bytes. Malformed or unmapped nonzero addresses leave metadata
incomplete and do not become function roots. File-backed `__mod_init_func`
sections (section type `S_MOD_INIT_FUNC_POINTERS`) are scanned in pointer-width
slots, capped at 65,536 entries per section. Mach-O relocation and dyld fixup
metadata is consulted for each slot. A resolved target becomes a root with
the slot address as its source and retains file offset, section/index, and
relocation/dyld-origin row IDs; unresolved fixups are left opaque. Existing PE
TLS callback roots remain in place.

Initializer seeds have distinct provenance in function records and use the
same bounded root budget, mode/context checks, ownership rules, and decode
policy as other metadata roots. They do not infer function extents by
themselves; an unwind range or explicit chunk is still required to establish
an exact boundary.

This work does not interpret runtime language-specific initializer dispatch.
PE TLS roots remain limited to callbacks represented by the existing TLS
directory metadata.


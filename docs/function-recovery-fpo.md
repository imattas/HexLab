# PE x86 FPO function recovery

Validated legacy `IMAGE_DEBUG_TYPE_FPO` records in x86 PE images now seed
function recovery. Each record contributes a function entry at its image RVA
and an exact ownership extent from `cbProcSize`; the RVA is translated against
the image's mapped base. Recovery checks that the entire range is backed by
initialized executable bytes before using it as a chunk boundary. The seed
retains the debug-record row and file source span as unwind evidence.

FPO frame fields (`cbLocals`, `cbParams`, prolog size, saved-register count,
SEH/base-pointer flags, and frame kind) remain descriptive metadata. Stack
unwinding, local-variable recovery, and caller/callee reconstruction do not yet
consume those fields. Non-x86 PE images do not use FPO records, and malformed
or partially backed ranges do not create roots. This support complements the
existing AMD64 and ARM64 PE exception-table roots; it does not infer extents
when the FPO directory is absent.

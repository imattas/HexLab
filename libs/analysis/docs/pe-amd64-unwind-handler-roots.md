# PE AMD64 unwind-handler roots

AMD64 PE `RUNTIME_FUNCTION` rows can use `UNWIND_INFO` with `UNW_FLAG_EHANDLER` or
`UNW_FLAG_UHANDLER`. The associated handler is invoked by the Windows exception
runtime and may not have an ordinary direct call into it.

When a parsed AMD64 runtime-function row retains a direct `handler_rva` and its
source is represented by one four-byte file span, function recovery translates
the RVA against the image's current mapped base and adds an unwind-metadata
root. The seed keeps the handler-RVA bytes as unwind provenance. Normal root
validation rechecks the mapped target against initialized executable code,
current execution context, explicit data decisions, and the function budget;
repeated references to one handler coalesce into one root.

This covers the top-level handler named by an AMD64 `UNWIND_INFO` record. It
does not seed per-scope `handler_rva` entries in `__C_specific_handler` scope
tables or C++ catch funclets, does not interpret language-specific payloads to
infer more functions, and does not add exception edges to the recovered CFG.
PE ARM64 xdata handlers are outside this increment.

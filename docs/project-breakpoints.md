# Project breakpoints

Project breakpoints are stored in the image's virtual address space, including their kind, enabled state, byte width, condition text, logpoint mode and literal output message. The configured ignore threshold is also saved. Editing these fields is a regular project command, so changes participate in transactional history and undo/redo.

The Debugger panel's **Apply Project** action resolves the active source image against the debugger's loaded module list. Each project address is translated to the matching runtime address for that session only. If source provenance or module mapping does not match, the breakpoint is skipped and the original saved address is retained. Applying is explicit; a changed image base never rewrites project addresses.

Breakpoints added directly with a runtime address are saved to the active project only when the debugger can verify a matching image mapping. Otherwise they remain session-only. **Save Rule** applies the editor fields to the selected runtime breakpoint and persists them only when that same verified mapping exists. Loading rejects malformed stored rule values; applying a rule that the current debugger cannot configure removes the partially added runtime breakpoint and counts it as skipped. Disabled hardware/watch breakpoints are retained but may be skipped by backends that cannot represent them as disabled.

Hit counts are runtime observations and are not persisted or included in undo/redo. The configured ignore threshold is project data; each newly created runtime breakpoint starts with a fresh hit count of zero. Logpoint messages are literal text, limited to 1024 UTF-8 bytes; conditions are limited to 256 UTF-8 bytes.

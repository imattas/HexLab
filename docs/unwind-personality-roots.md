# Exception personality function roots

Function recovery treats a directly resolved `.eh_frame` personality routine
as a code root because language runtimes call it while handling exceptions.
ELF roots require a direct, nonzero personality pointer retained by a validated
FDE. Mach-O roots require a resolved personality address and its encoded
personality field source. The root carries the pointer field's section and file
extent as unwind provenance, so it can be explained and cached with the other
unwind roots.

Indirect ELF pointer encodings remain unresolved and do not create a root.
Candidates still pass ordinary executable mapping and execution-context
checks. This does not model personality semantics, LSDA dispatch, landing pads,
or exception propagation.

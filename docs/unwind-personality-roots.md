# Exception personality function roots

Function recovery treats a resolved `.eh_frame` personality routine as a code
root because language runtimes call it while handling exceptions. ELF direct
roots require a nonzero personality pointer retained by a validated FDE.
Indirect ELF encodings follow the pointer slot only through one exact supported
relocation or an immutable, readable, file-backed slot without a relocation;
the resulting address must be file-backed executable code in the same image
space. An unresolved relocation is never replaced with its encoded addend.
Mach-O roots require a resolved personality address and its encoded personality
field source. Each root carries the pointer field's section and file extent as
unwind provenance, so it can be explained and cached with the other unwind
roots.

Candidates must pass executable mapping checks. This does not model personality
semantics, LSDA dispatch, landing pads, or exception propagation. Writable
runtime-populated pointer slots, unsupported relocations, unresolved symbols,
and targets outside the image remain without a root.

# PE CHPE code-range analysis

The loader publishes validated CHPE code-map rows as an authoritative image execution profile. Each row selects the decoder context for its virtual range: ARM64 rows use the A64 decoder, ARM64EC rows use the A64 decoder, and AMD64 rows use the x86-64 decoder. Bytes outside declared rows have no instruction context. The image limits every decode window to the end of its selected row, and function recovery stops when control flow crosses an execution-context boundary. Calls can still identify entries in another range, which are analyzed under that entry's own context.

The profile retains the image's normal segment-to-file provenance. The mapping fingerprint includes every execution range and context, so derived analysis caches cannot reuse facts across changed CHPE maps. Rebasing and ARM64X effective-byte overlays preserve the profile and the existing base/effective storage semantics.

ARM64EC currently shares the ARM64/A64 processor context because the processor model has no distinct ARM64EC ABI identity. It receives correct A64 instruction decoding, but ARM64EC-specific ABI and cross-ABI call semantics are not selected by the CHPE range kind yet. Analysis is limited to validated CHPE rows; gaps are intentionally undecodable.

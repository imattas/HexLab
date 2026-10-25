# ARM64 PE Exception Metadata and Function Roots

## Goal

Recognize the ARM64 PE exception directory as bounded metadata and use each validated `.pdata` function start as provenance-bearing function-discovery evidence. Preserve the existing AMD64 behavior and treat malformed exception metadata atomically: the PE image remains loadable, diagnostics mark metadata incomplete, and no partial ARM64 records or roots escape.

## Scope and compatibility

The ARM64 path applies to PE32+ images whose machine is `0xaa64`. Its exception directory is an ordered array of 8-byte records. The first word is a function-start RVA; the second word is tagged as an `.xdata` RVA (`00`), packed unwind word (`01` or `10`), or a parent `.pdata` link (`11`). ARM64 record metadata is stored separately from the existing AMD64 `PeRuntimeFunction` model so that architecture-specific encodings cannot be confused.

Each function record must start in initialized executable bytes. Packed lengths and unpacked xdata function lengths must be nonzero, aligned, within the image, and entirely contained by one initialized executable segment. Rows must be sorted by start RVA. All reads, extent arithmetic, row counts, xdata scope counts, unwind-code counts, recursion, and link traversal are bounded. A malformed row or xdata record rejects the whole directory metadata batch while preserving the image and adding the loader's normal directory diagnostic.

For tag `00`, decode the version-zero xdata header, optional extension header, ordered epilog scopes, unwind-code stream, and optional handler RVA. Decode unwind-code boundaries using the ARM64 opcode size classes and retain each code's opcode and original bytes; this is metadata decoding, not evaluation of stack/register effects or language-specific handler payload parsing. Unsupported versions, reserved opcodes, invalid scope ordering/indexes, truncation, or out-of-range handler/function references reject the batch. Packed rows retain their tag, function length, CR/H/RegI/RegF/frame-size fields. Parent links are resolved to a validated row with cycle and depth checks; linked rows still represent their own function start and retain their direct link provenance.

Function recovery adds each validated ARM64 `.pdata` start as `FunctionSeedKind::unwind`, with the table row's directory index and file extent in the existing `FunctionSeedUnwindEvidence`. This reuses the existing durable seed evidence shape and avoids a cache schema change. Existing entry, export, symbol, and user roots remain unchanged. RVA-to-VA translation uses the image's actual mapped base.

## Explicit non-goals

This feature does not execute unwind codes against a register context, implement exception dispatch, interpret handler-specific payloads, infer leaf functions omitted from `.pdata`, merge duplicate/overlapping rows, or add ARM32 support. It does not change processor decoding or generic architecture dispatch.

## Validation and test strategy

Synthetic PE32+ ARM64 fixtures exercise packed single-prolog and fragment forms, unpacked xdata including scopes and handler presence, and linked pdata rows. Tests assert exact normalized fields and source byte spans, roots with unwind provenance, correct rebasing, and structural equality across independent loads. Malformed cases cover table-size remainder, row ordering, invalid executable extents, invalid tag payloads, zero/overflowing or out-of-image ranges, misaligned/uninitialized xdata, unsupported versions, extended-header truncation, invalid scope/code indexes, reserved opcode, handler validation, dangling/cyclic/deep links, and atomic failure. The AMD64 exception tests remain green.

## External format reference

The record tags, xdata header/scope layout, code encodings, and packed fields follow [Microsoft's ARM64 exception handling documentation](https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling?view=msvc-170). The implementation stores normalized values and source spans and does not claim runtime unwinding.

# Mach-O read-only section contributions

## Goal
Extend the bounded Mach-O static linker to accept the common `__TEXT,__cstring`, `__literal4`, `__literal8`, and `__literal16` object sections alongside `__const`. Preserve each source section's identity, alignment, bytes, and contribution offset so defined symbols and relocations continue to resolve after merging.

## Design
Keep the output's existing single read-only segment and `__const` output section. Model every supported source read-only section as an individual contribution within that output section. Each contribution records its source section ordinal, alignment, size, merged offset, and bytes. The existing relocation and symbol pipeline maps through this record, avoiding special-case arithmetic at each use site.

Recognize only exact `__TEXT` section/segment pairs. `__const` must be S_REGULAR, `__cstring` S_CSTRING_LITERALS, and literal sections their matching fixed-width section type; literal byte counts must be multiples of the element size and cstring data must end in NUL. Unsupported section classes stay explicit rejections. Read-only input sections become ordinary bytes in the final executable's read-only `__const` mapping; the output need not preserve literal-pool section types for further relocatable linking.

## Limits and behavior
Existing object, symbol, relocation, output-size, cancellation, architecture, and address limits remain in force. Contributions are aligned and appended in input object/section order. Relocations may originate in or target any supported read-only contribution using existing relocation families. Strong/weak symbol resolution and executable layout are unchanged. No schema or public format changes.

## Failure cases
Reject malformed section types, nonterminated cstring payloads, literal sizes not divisible by 4/8/16, duplicate/unsupported section layout conflicts, out-of-range source bytes, and relocation fields outside their source contribution before publishing output.


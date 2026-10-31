# ARM64 PE exception metadata

For PE32+ ARM64 images (`Machine = 0xaa64`), HexLab reads the exception directory as a bounded ordered array of 8-byte `.pdata` records. Each record preserves its function-start RVA and source file span. The two low bits of its unwind word select an aligned `.xdata` RVA (`00`), packed canonical unwind data (`01` or `10`), or a parent `.pdata` row link (`11`).

Packed records retain the function length, saved integer and floating-point register counts, parameter-home flag, frame-chain/return flag, frame size, and whether the row describes the normal single-prolog form or a fragment without a prolog. Parent links are resolved only to aligned rows in the same exception directory; the loader rejects cycles and excessive link depth.

Unpacked records decode version-zero `.xdata`: function length, exception-handler presence, compact or extended epilog/code counts, ordered epilog scopes, and bounded unwind-code byte sequences. Each code retains its opcode, encoded bytes, and source span. The loader validates opcode lengths, scope bounds and code indexes, aligned function extents, and optional handler targets. Handler language data following the handler RVA is outside the normalized metadata extent and is not interpreted.

Every accepted start must point to initialized executable bytes, and known packed/xdata function extents must remain inside one initialized executable segment. The loader builds the entire directory in temporary metadata and publishes it only after every row, xdata record, and link validates. Malformed directories mark PE metadata incomplete and add a diagnostic while preserving otherwise usable image bytes.

Each validated non-link ARM64 `.pdata` start becomes a `FunctionSeedKind::unwind` root only when its source spans provide exactly eight nonempty bytes without extent overflow. Its seed evidence retains the pdata row index, first source file offset, and eight-byte record extent. A normalized row missing that provenance is skipped and marks function recovery incomplete; its function range is not applied as an ownership bound. Root addresses are computed using the image's loaded base, so rebasing is reflected in recovered functions. The validated function length bounds control-flow recovery unless an explicit user chunk definition overrides the metadata. Functions omitted from `.pdata` (such as leaf functions) are not inferred by this feature.

Flag-3 link rows describe jump islands, not independent functions. Function
recovery follows each validated parent-link chain and adds the island's mapped
executable interval to the parent function's chunks. The interval ends at the
next strictly ordered `.pdata` start, matching the interval used by the PE
unwinder. Recovery requires the complete interval to be aligned, initialized,
executable, and contained in one image segment. A final link row without a
source-backed end remains unassigned and marks analysis incomplete. The link
row's file provenance is retained as an additional unwind seed on the parent
function. See Microsoft's [Arm64 pdata link format](https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling?view=msvc-170#pdata-record-links).

The metadata reader preserves decoded operations for the debugger-independent live evaluator documented in [PE live-context unwinding](pe-live-unwind.md). That evaluator handles common register/stack recovery, but does not implement exception dispatch or interpret handler-specific payloads. The record layouts and unwind-code sizes follow [Microsoft's ARM64 exception handling documentation](https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling?view=msvc-170).

# Mach-O classic bind resolution

`resolve_macho_dyld_binds` computes values for classic dyld bind and lazy-bind fixups using runtime symbol addresses explicitly supplied by the caller. Inputs are matched by the exact `(library ordinal, symbol name)` pair. Multiple entries for a pair are accepted only if they provide the same address; conflicting addresses produce an `ambiguous_import` result. Missing symbols remain unresolved, including weak imports; the resolver never invents a zero address or searches host paths.

The resolver handles `BIND_TYPE_POINTER` (4- or 8-byte pointer according to the selected slice), `BIND_TYPE_TEXT_ABSOLUTE32`, and `BIND_TYPE_TEXT_PCREL32`. It adds the encoded signed dyld addend with checked arithmetic. PC-relative values use `target - (preferred fixup address + image slide)` and must fit signed 32 bits. Absolute32 and 32-bit pointer values must fit their encoded width. Results include the computed target, integer value to encode, original opcode record file offset, mapped fixup address, optional file-backed location, symbol, ordinal, flags, and status. `value_to_write` is a host integer representation of the field bits; byte order must follow the selected Mach-O slice if a caller later encodes it.

This is analysis-only: no file or image bytes are changed, dyld opcodes are not patched, and symbol addresses are not discovered automatically. Lazy-bind streams are reported as requests, not executed. Weak-bind/coalescing streams are not treated as ordinary imports. Callers must supply runtime symbol addresses and the image slide when resolving PC-relative binds. The opcode tuple and bind types follow Apple's [`mach-o/loader.h`](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h); opcode iteration and the three bind type names are also represented in LLVM's [Mach-O object reader](https://github.com/llvm/llvm-project/blob/main/llvm/lib/Object/MachOObjectFile.cpp).

Default limits cap fixups at 1,000,000, supplied imports at 1,000,000, aggregate supplied symbol names at 16 MiB, each symbol at 64 KiB, and result rows plus copied symbol names at 64 MiB. Cancellation is checked while indexing imports and processing fixups. The CLI prints at most 1,024 rows:

```text
hexlab_cli macho bind-targets app --image-slide 0x100000 \
  --import 1 _malloc 0x7ff800001234
```

Special dylib ordinals such as self, main executable, flat lookup, and weak lookup can be supplied explicitly as negative ordinal values. This does not implement dyld's runtime search order or two-level namespace provider selection.

# WebAssembly `dylink.0` metadata

The loader recognizes the `dylink.0` custom section and retains its bounded
subsection metadata in `WasmMetadata::dylink`. It parses the v1 dynamic-linking
subsection framing and IDs 1 through 5:

- memory and table size/alignment requirements (ID 1), preserving the encoded
  values as supplied;
- ordered needed-library names (ID 2);
- ordered dynamic export names and symbol flags (ID 3);
- ordered dynamic import module/name pairs and symbol flags (ID 4);
- ordered runtime-path strings (ID 5).

Each string and symbol row retains its source offset. Repeated list and symbol
subsections append in source order. A duplicate memory-info subsection, a
malformed subsection, invalid UTF-8, unsupported symbol flag bits, or trailing
bytes causes the `dylink.0` metadata to be ignored atomically with an
informational diagnostic. Unknown subsection IDs are retained as opaque bytes
with their IDs and source offsets, up to a 4 MiB aggregate payload limit.

The parser caps subsection and item counts at one million and charges decoded
strings to the loader's aggregate WebAssembly name budget. A second `dylink.0`
custom section is ignored with a diagnostic. Unknown subsection IDs, including
target-architecture metadata, remain opaque; runtime paths are retained
exactly and are never expanded or used for filesystem lookup.

This is descriptive metadata support only. It does not load needed modules,
resolve dynamic symbols, allocate shared memory/table ranges, apply
relocations, or implement a runtime linker. The subsection layout follows the
[WebAssembly tool-conventions Dynamic Linking document](https://github.com/WebAssembly/tool-conventions/blob/main/DynamicLinking.md#the-dylink0-section).

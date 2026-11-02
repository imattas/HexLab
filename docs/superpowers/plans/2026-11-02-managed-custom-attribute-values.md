# Managed custom-attribute value implementation plan

**Goal:** Add bounded inert decoding for common fixed custom-attribute values and expose it in project inspection.

**Approach:** Reuse constructor signatures from `parse_managed_call_signatures`; decode only exact primitive/string/SZARRAY shapes, retain raw blobs and mark named arguments or unsupported signatures as partial/opaque.

**Files:**

- Modify: `libs/loaders/include/hexlab/loaders/managed.hpp`
- Modify: `libs/loaders/src/managed.cpp`
- Modify: `libs/loaders/include/hexlab/loaders/cil.hpp`
- Modify: `libs/loaders/src/cil.cpp`
- Modify: `apps/cli/project_arguments.cpp`
- Modify: `apps/cli/project_commands.cpp`
- Modify: `apps/cli/project_output.cpp`
- Modify: `docs/managed-metadata.md`
- Create: this spec and plan

## Steps

1. Add a typed recursive value record plus decode status and diagnostic while preserving raw serialized bytes.
2. Parse fixed arguments from constructor signature types with strict extents and bounds. For unsupported constructor types, keep the raw value and report unsupported. For recognized signatures, validate the two-byte named-argument count; leave those values opaque and report partial when nonzero.
3. Add an `inspect_managed_custom_attributes(LoadedImage)` wrapper and `project custom-attributes` text output with bounded rows and per-value summaries.
4. Document supported forms, provenance, safety and residuals.
5. Compile loader and CLI targets on Windows and WSL with `BUILD_TESTING=OFF`; review and commit locally. No tests, CI or push.

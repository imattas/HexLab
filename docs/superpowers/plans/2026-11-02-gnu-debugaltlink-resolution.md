# GNU debugaltlink resolution implementation plan

**Goal:** Resolve one local DWZ alternate-debug companion from `.gnu_debugaltlink` metadata through bounded, identity-checked discovery.

**Approach:** Reuse the existing offline debug-companion catalog with an explicit expected build ID and relative filename. Keep alternate-link discovery separate from ordinary `.gnu_debuglink` CRC checks, permit ET_REL DWZ files, and add a CLI subcommand.

**Files:**

- Modify: `libs/loaders/include/hexlab/loaders/elf_debug_companions.hpp`
- Modify: `libs/loaders/src/elf_debug_companions.cpp`
- Modify: `apps/cli/elf_debug_companion_command.cpp`
- Modify: `docs/elf-debug-link-metadata.md`
- Modify: `docs/elf-debug-companion-verification.md`
- Create: this spec and plan

## Steps

1. Add an exported alternate-companion resolver. Require all `.gnu_debugaltlink` rows to agree on a nonempty <=64-byte alternate build ID. Follow only a safe relative filename; if it is absolute or contains traversal, skip that probe while retaining explicit candidate and build-ID lookup. Continue using the catalog's byte/path limits, canonical-root checks, hashing, cancellation, and unique-selection rule.
2. Factor the current catalog's expected build-ID and optional filename inputs so alternate discovery uses the alternate identity and never applies the primary debuglink CRC. Permit ET_REL candidates while preserving machine/class/order/flags/ABI checks and file-backed debug metadata requirements.
3. Add `elf debug-alt-companions`, sharing explicit `--candidate`, `--debug-dir`, `--sysroot` and `--json` handling with `elf debug-companions`.
4. Document filename/path policy, candidate identity, limits, and the fact that selected storage is not yet imported as supplementary DWARF.
5. Compile affected loader and CLI targets on Windows and WSL, both with `BUILD_TESTING=OFF`; inspect the diff and commit locally. No CI, tests, or push.

## Residual scope

DWARF supplementary-reference resolution and external DWARF import remain
separate work. Absolute and traversal filenames from `.gnu_debugaltlink` are not opened;
users can name those files explicitly with `--candidate`.

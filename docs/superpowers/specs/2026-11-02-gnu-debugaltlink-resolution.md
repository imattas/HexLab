# GNU debugaltlink resolution

## Goal

Allow a caller to resolve the supplementary DWARF file named by an ELF
`.gnu_debugaltlink` section using the same bounded local catalog used for GNU
separate-debug files.

## Requirements

- Match the candidate's GNU build ID to the alternate build ID retained in the
  primary's `.gnu_debugaltlink` record. The primary executable's build ID and
  any `.gnu_debuglink` CRC do not replace this identity.
- Inspect only explicit candidate paths, a safe relative filename adjacent to
  the primary, and caller-supplied debug directories/build-ID paths. Unsafe
  section filenames are not followed, but do not disable explicit candidates
  or build-ID-directory lookup.
- Reject conflicting alternate-link records, malformed IDs,
  incompatible ELF identity, missing debug metadata, ambiguous matches, and
  incomplete reads using the existing structured report states.
- Permit an alternate debug artifact to be ET_REL while requiring matching
  machine, class, byte order, flags, OSABI and ABI version.
- Expose the operation as `hexlab_cli elf debug-alt-companions` with text and
  JSON output.
- Do not import or merge DWARF as part of discovery.

## Verification

Compile the loader and CLI on Windows and WSL with `BUILD_TESTING=OFF`.
Preserve existing debuglink discovery behavior and all generated output.

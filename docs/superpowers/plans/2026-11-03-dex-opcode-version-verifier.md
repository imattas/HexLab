# DEX opcode version verification implementation plan

**Goal:** Reject instructions introduced after the containing DEX version even
when the operand decoder cannot represent an earlier instruction.

**Design:** Add an allocation-free successful encoding inspection API in the
processor library. It reports checked instruction/payload extents independently
of operand decoding, rejects reserved encodings and truncation, and enforces
038/039 introduction versions. Run this inspection over every code item before
the existing bounded structural and register-category passes. Retain the raw
decoder and legacy optimized-opcode compatibility; DEX header versions do not
establish an optimized runtime version.

**Constraints:** No tests added or run, no push. Build Windows Debug processor
and loader targets with `BUILD_TESTING=OFF`.

- [x] Add shared encoding inspection and explicit version-aware decode API.
- [x] Validate complete method encoding streams with exact error provenance.
- [x] Update DEX documentation and both capability entries.
- [x] Build affected Windows targets, review the diff, and commit locally.

Windows Debug `hexlab_loaders` (including `hexlab_processors`) configured with
`BUILD_TESTING=OFF` and linked successfully. No tests added or run. The build
reports existing DLL-interface, narrowing, shadowing, and deprecated API warnings.

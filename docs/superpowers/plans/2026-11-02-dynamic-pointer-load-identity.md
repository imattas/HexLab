# Dynamic pointer-load identity

- [x] Reuse bounded pointer-relative ranges to recognize exact source locations.
- [x] Canonicalize pointer results at the same exact source range and whole-memory version during provenance propagation.
- [x] Retain opaque roots for multi-address ranges, unproven bases, and changed memory versions.
- [x] Document equality proof conditions and external-mutation boundary.
- [x] Compile the decompiler target on Windows and WSL with tests disabled; no tests, CI, or push.

# Bounded RSP memory transfer plan

**Goal:** Make multi-packet remote memory reads and writes obey one deadline, negotiated packet ceilings, checksum recovery bounds, and explicit partial-write failure semantics.

**Architecture:** Keep the existing serialized RSP Client and X-to-M compatibility fallback. Compute packet sizes from actual headers, share the client's timeout across every chunk, and bound corrupt response recovery in the common transaction path. Preserve the special ACK grace for zero-timeout asynchronous stop polling only.

**Constraints:** No tests are added or run, as requested. Build Windows and WSL debugger targets with BUILD_TESTING=OFF. Live stub interoperability and connection recovery after an interrupted in-flight transaction remain unverified; the caller must reconnect before retrying such a transfer.

- [x] Tighten common transaction deadline and corrupt-packet recovery bounds.
- [x] Bound reads/writes to 16 MiB, allow ranges ending at UINT64_MAX, and size every chunk using its actual header.
- [x] Preserve acknowledged write progress and uncertainty in error messages; cancel before a subsequent chunk.
- [x] Update protocol/API documentation and capability evidence.
- [x] Build Windows and WSL debugger targets without tests, inspect the diff, and commit locally.

Build evidence: Windows x64 Debug MSVC 19.44 and WSL Ubuntu 24.04 Debug GCC 13.3 `hexlab_debugger` builds exited 0 with `BUILD_TESTING=OFF`. WSL used Unix Makefiles because Ninja is absent. No tests or live stub session were run.

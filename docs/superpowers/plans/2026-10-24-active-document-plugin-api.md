# Active document plugin API plan

## Files

- `libs/plugins/include/hexlab/plugins/plugin_abi.h`: append versioned C records and host table pointer.
- `libs/plugins/include/hexlab/plugins/plugins.hpp` / `src/plugins.cpp`: host callback bridge and manager service setter.
- `libs/plugins/include/hexlab/plugins/sdk.hpp`: checked C++ client wrapper.
- `apps/desktop/plugins_view.hpp/.cpp`, `apps/desktop/main_frame.cpp`: publish immutable active document state and owner-thread navigation dispatch with stale-token checks.
- `docs/plugin-sdk.md`: ABI contract, lifetime and example.

## Tasks

- [x] Add append-only ABI 1.15 active document records/table and C++ client helpers.
- [x] Implement host-side validation, bounded byte reads, status mapping, and exception containment.
- [x] Connect desktop snapshot publication and synchronized, timeout-bounded navigation marshaling.
- [x] Document compatibility, threading, stale-token handling, and usage.
- [ ] Review lifetimes, tab/document revision checks, callbacks, and prefix compatibility; root compiles affected libraries and desktop components.

## Constraints

No tests added/run. No changes to project exchange, `out/`, or build tree by this lane. Root performs compile-only verification.

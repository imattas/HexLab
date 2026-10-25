# Active document plugin API design

## Intent

Give trusted native plugins access to the document the user is currently viewing without requiring each plugin to reopen a project by path. This supports plugins that inspect bytes and navigate the current disassembly while preserving the host's document and UI ownership.

## Goals

- Add an optional, append-only ABI 1.15 `active_document_api` table to `HexLabHostApi`.
- Query a fixed-size summary and receive an opaque freshness token for the active document.
- Read bounded bytes from the effective image by address or file offset.
- Request navigation only while the same document and revision token remains active; marshal off-thread requests to the wx owner thread with a bounded wait.
- Keep old 1.x plugins compatible through `struct_size` and table-version checks.
- Provide a move-only C++ SDK wrapper and usage documentation.

## Non-goals

- No mutable image, project, database, or UI handles cross the C ABI.
- No direct wxWidgets access, arbitrary project open, process memory, or plugin data persistence is added here.
- This is an in-process trusted-plugin interface, not a sandbox.

## Approaches considered

1. **Append a dedicated active-document service table (selected).** It makes query/read/navigation capabilities explicit and independently versioned, follows existing project/debugger tables, and keeps the host ABI append-only. The cost is a small desktop bridge to marshal navigation safely.
2. **Reuse `project_api` handles.** This avoids a new table but forces plugins to reopen a path, can observe a different project view, and cannot bind actions to the active document revision.
3. **Pass a document pointer into action callbacks.** This is simple but leaks C++ lifetime and host object details across the module boundary and is unsafe across tab switches.

## API behavior

The table exposes `query`, `read`, and `navigate` callbacks. `query` returns a document ID, nonzero monotonically assigned open generation (independent of edit revision), project edit/byte/decision revisions, primary address space, width, byte order, architecture/mode identifiers, image size, and file size. The token is value-only and is not a retained handle. `read` accepts only address or file locations, caps each request at 1 MiB, reads the current effective document view, and revalidates active identity and token after the bounded read. `navigate` accepts the same location forms and succeeds only when the token still identifies the active document and matching revisions.

Status `0` means success, `-1` means malformed arguments or unsupported location, `-2` means no active document or a host/UI operation failed, and `-3` means the document token is stale. Off-thread navigation is posted to the wx owner thread and waits at most five seconds; UI-thread callers execute directly. The bridge never captures a raw MainFrame without a synchronized invalidation point. Every call snapshots/validates current state; plugins must query again after `-3`.

## Compatibility and constraints

`HEXLAB_PLUGIN_ABI_MINOR` advances from 14 to 15. `active_document_api` is appended after all existing `HexLabHostApi` fields. Hosts and plugins check `struct_size` before reading it. Existing ABI 1.0–1.14 descriptors retain their exact prefixes. Fixed strings are UTF-8, NUL-terminated, and rejected on overflow rather than truncated. No host-owned pointers are returned.

## Verification

Source review covers table sizing and old prefixes, snapshot pinning, exact active token validation, bounds and address-space checks, wx dispatch timeout/destruction races, and exception containment. Per repository instruction, no tests are added or run; root owns compile-only verification.

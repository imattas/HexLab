# Python automation v1

The automation.python capability gets a synchronous worker/console API for real
projects. A new automation library wraps ProjectStore/ProjectSession, preserving
space-aware Location, immutable snapshots, command validation, history, readonly
enforcement and patched exports. It owns its session and store; it never accesses
SQLite directly. Consumers must call it on one owning worker thread. GUI actors
are not bypassed or exposed as script objects.

The recommended design is a native C++ bridge plus optional embedded CPython
console. A subprocess CLI wrapper cannot expose retained snapshots or typed
commands; a mandatory Python-linked engine would violate optional embedding.
Python therefore lives only in the new console executable. Its built-in hexlab
module exposes Project objects through owned capsules and a shipped Python facade.
API_VERSION=1 and a native version negotiation argument reject unknown versions.
This is a versioned source API with the repository's rebuilt-consumer ABI rules,
not a replacement for the separately versioned allocator-neutral plugin C ABI.

The first API includes project open/import, raw/profile mapping, metadata snapshots,
bounded bytes/instruction/function queries, logical selector resolution, validated
commands, history, analysis refresh, checkpoint, and original-byte patched export.
Python objects return detached dictionaries/bytes rather than borrowed C++ pointers.
Scripts run trusted with ordinary Python permissions. No sandbox, forced script
termination, GUI console integration, live actor attachment, debugger scripting,
or full analysis/type object binding is claimed.

The runner uses Python's normal source execution with script arguments and an
interactive REPL when no script is supplied. Exceptions print tracebacks and exit
nonzero. Project errors retain numeric ErrorCode and message in hexlab.Error.
No Python discovery/link/runtime dependency exists when embedding is disabled.

The subsystem can be added with add_subdirectory(automation) after workspace, or
built standalone against a complete source build. Focused C++ and Python tests
create real temporary projects, inspect decoded functions, mutate names/comments
and bytes, exercise undo/redo and readonly reopen, resolve segment aliases, verify
bounded queries and exact exports. Production builds and full-suite integration
remain the parent worker's final integration gate. Standing task authorization
removes approval checkpoints and prohibits invented commits in this unborn repo.

# Native automation workflow checkpoints

`Project::save_workflow_state` and `Project::load_workflow_state` preserve an
application's bounded cursor, review queue, or other opaque state across host
process restarts. The service is part of the native C++ automation SDK. A state
file is separate from the project database; project backups and Save As do not
automatically copy it. Python bindings are not provided for this service yet.

Open the same project in the next process, then load the checkpoint with the
same application name and application schema version. Loading verifies the
project UUID and **exact current edit revision** before returning the payload.
An edited project, including one changed and then undone, rejects an older
checkpoint with `conflict`. A backup preserving the UUID and revision can use
the checkpoint; a recovery copy with a fresh UUID cannot. The caller must handle
application payload validation and migrations explicitly.

```cpp
auto project = hexlab::automation::Project::open("input.hxproj");
if (!project) return project.error();
auto snapshot = project.value()->snapshot();
if (!snapshot) return snapshot.error();
std::string cursor = "64";
auto saved = project.value()->save_workflow_state(
    "inventory-0001.state", "mytool.annotation-inventory", 1,
    std::as_bytes(std::span(cursor.data(), cursor.size())),
    snapshot.value()->state->revisions.edit);
// Check saved before exiting. In a later process, reopen input.hxproj and call:
auto loaded = project.value()->load_workflow_state(
    "inventory-0001.state", "mytool.annotation-inventory", 1);
```

The methods follow `Project` thread ownership. Saving requires a live owner
and accepts a read-only project, since it writes a separate file. Captured
owners may load a checkpoint matching their pinned generation but cannot save
one. Saving does not edit the project or create a history step. Native project
edits already commit through their normal database transactions; this service
does not make a combined transaction with project edits or an output sink.

## Restartable example

Configure with `-DHEXLAB_BUILD_AUTOMATION_EXAMPLES=ON` and build the
`hexlab_resume_inventory` target. With the HexLab runtime DLLs available, run:

```text
hexlab_resume_inventory input.hxproj inventory-0001.state
hexlab_resume_inventory input.hxproj inventory-0002.state inventory-0001.state
hexlab_resume_inventory input.hxproj inventory-0003.state inventory-0002.state
```

Each invocation opens the project read-only, exports up to 64 durable annotation
rows, and saves the next decimal row offset in a schema-1 payload. Stop once it
reports `inventory complete`. An exact multiple of 64 needs one extra invocation
to discover the empty final page. Rows contain the annotation ID and quoted name
and comment; this example is a diagnostic listing, not a formal interchange
format. Newlines in annotation text may span physical output lines.

Supply a **new destination file each time**. Checkpoints are immutable. Keep the
last successful checkpoint and resume from it after a process failure. Output
is flushed before checkpoint publication, so a crash in between can replay rows;
use the annotation ID to deduplicate in a real output sink. Exactly-once export
requires an application-owned transaction covering output and progress. This
example uses durable annotation order rather than transient analysis pages,
whose order and membership may change when analysis options change.

## Bounds and format

* Envelope format version: `workflow_state_format_version == 1`, independently
  versioned from `api_version` and the application's nonzero 32-bit schema.
* Application name: 1–128 ASCII letters, digits, `.`, `_`, or `-`.
* Payload: 0–1,048,576 bytes. Oversized input and files fail before payload
  allocation. Checkpoint reads never allocate based on unvalidated length fields.
* All integers are unsigned little-endian. The 48-byte header is: eight ASCII
  bytes `HLWFSTAT`, envelope version (u32), project UUID (16 raw bytes), edit
  revision (u64), application schema (u32), name length (u32), payload length
  (u32). The name and payload follow, then a 32-byte SHA-256 of all preceding
  bytes. Truncation, invalid lengths, trailing data, and checksum mismatches fail.
* Unknown envelope or application schemas return `unsupported`; a namespace,
  UUID, or revision mismatch returns `conflict`. A checksum mismatch returns
  `integrity`. A checksum detects damage; it does not authenticate hostile files.
* Cancellation is checked before I/O and before publication/return. Maximum I/O
  and hashing work between checks is about 1 MiB. After publication, a save
  succeeds even if cancellation arrives concurrently.

The destination parent directory must already exist. A complete staged file is
flushed and synchronized before publication. Windows uses `MoveFileExW` with
`MOVEFILE_WRITE_THROUGH` and no replace flag. POSIX uses a same-filesystem hard
link followed by parent-directory synchronization; the filesystem must support
hard links. Existing destinations, including concurrent checkpoint publications,
are never replaced. Normal failure/cancellation removes the owned staging file
and directory. Abrupt process termination can leave a `.hexlab-workflow-*`
staging directory; it is never treated as a checkpoint and can be removed after
confirming the writer has stopped. A POSIX directory synchronization failure is
reported as `io` with an explicit message that publication already happened.
Durability ultimately depends on the filesystem and storage honoring sync calls.

# Plugin panel workflow

## Reviewed plugin cleanup

**Review Unload With Dependents...** prepares a data-only plan for the selected
plugin and its transitive loaded consumers. **Review Unload All...** prepares
the reverse-activation-order plan for every loaded module. Planning runs on the
existing serialized worker and does not stop modules or cancel analysis.

The review dialog lists every plugin ID in the exact consumer-first removal
order and the direct provider dependencies that will stay loaded. IDs are quoted;
control/non-ASCII bytes and quote/backslash characters are escaped so a module
cannot insert a fake plan row or hide an ID behind failed UTF-8 decoding. Unrelated
plugins also stay loaded when reviewing a selected plugin. The review explains
that registered actions, loaders, processors, and analysis providers belonging
to the removed modules disappear. Cancel is the default button; only **Unload
reviewed set** starts cleanup. Cancel leaves the loaded inventory unchanged.

Before removing anything, the manager checks the originating manager instance,
its inventory/semantic generation, and the freshly recomputed removal order
and retained providers under one lifecycle lock. A module load, unload,
quarantine/generation change, expired manager, or modified plan rejects the
review without removing modules. Review again to accept the new state.

Planning and execution are bounded to 256 loaded modules, 4,096 resolved
dependency edges, and 64 KiB of loaded plugin-ID bytes. The complete ID list
must fit the dialog's 128 KiB text budget; oversized reviews fail rather than
silently approve an omitted set. At most one plan/operation is pending. The
status control retains only the most recent message, limited to 16,384
characters with an explicit truncation marker.

Accepted cleanup uses the same cancel/quiesce/unload/refresh callbacks as other
desktop lifecycle changes. Module stop callbacks run on the lifecycle worker,
and provider availability and loaded inventory refresh afterward. If cleanup
stops partway through, the result reports the removed count and failure and
the remaining loaded rows are shown; any actual removal still invalidates
extension consumers and refreshes open-project analysis. An unexpected exception
is conservatively treated as a possible inventory change and triggers refresh.
Cleanup does not force-stop or sandbox native code, kill plugin worker threads,
delete module files, or persist a disabled policy for already-loaded plugin
IDs. A plugin must finish its own workers and return from `stop` cooperatively.

**Unload Selected** retains its existing single-plugin behavior and refuses a
provider with live consumers. The lower-level legacy unload APIs remain
available; the reviewed APIs are described in
[plugin dependency activation](plugin-dependency-activation.md#reviewed-cleanup-api).

## Actions and candidate review

The desktop Plugins panel lists registered actions and analysis providers for
loaded modules. Select an action or provider and use its Run button, or
double-click the selected row (Enter activates it as well). Both routes use the
same serialized plugin worker as the corresponding button, so the panel stays
responsive while plugin code runs and reports callback failures in the status
area.

The action list has a live filter that searches the plugin ID, action ID, and
label using case-insensitive ASCII substring matching. The count shows visible
matches over the complete registered-action list. Filtering only changes the
rows shown; action registration, plugin lifecycle state, and the selected
action's invocation semantics are unchanged.
Use **Copy Action Details** to copy the selected row as labeled TSV with its
plugin ID, action ID, and label. This copies the displayed registration metadata
without invoking plugin code; output is capped at 64 KiB, and clipboard errors
are reported in the status area.

Analysis providers still require a saved project path in the **Project file**
field. The host opens that project read-only for the provider call. Plugin
callbacks execute in-process and are not sandboxed.

Select a row in **Loaded plugins** to inspect its full details. The details
area shows the exact UTF-8 module path used for activation and explicitly says
that publisher identity is not verified. It also shows declared and legacy
capabilities, required capabilities, providers resolved at activation, loader
and processor registrations, actions, analysis providers, and extension
registrations disabled after validation failures. The path is diagnostic
provenance: it is not a signature, trust decision, or promise that the file
still contains the bytes that were loaded.
The compact inventory columns remain useful for scanning; the details area
preserves complete identifiers and failure reasons that may be clipped in a
column. Details are refreshed after each serialized lifecycle operation, so a
selection that disappears after unload returns to the selection prompt.
Use **Copy loaded plugin details** to copy the selected read-only details pane
as UTF-8 for review or troubleshooting. The action uses the displayed details
without loading or querying plugin code, and rejects output above 64 KiB rather
than copying a partial report. Clipboard-open and copy failures appear in the
plugin status area.

The discovered-candidate list has a separate review pane. Before activation it
shows the exact module path, sidecar identity, SHA-256 pin and scan-time result,
declared capabilities, and per-requirement preflight provider. Selecting a
candidate does not load it. Candidate activation rechecks any declared SHA-256
pin immediately before and after native module open, then verifies module
identity and capability declarations before calling `start`. A failed pin
check stops candidate activation. Direct **Load Plugin** remains an explicit
path-based load and does not use a scanned sidecar. Sidecars are unsigned and
do not establish publisher identity or sandbox native code.

Use **Filter discovered modules** to narrow the scanned candidate list by path,
sidecar name or ID, version, declared capability/preflight summary, expected or
observed SHA-256, manifest error, or blocked/enabled state. The count reports
visible candidates over the full scan result. Filtering is case-insensitive
ASCII substring matching with a 2,048-character query limit and changes only
the displayed list; selection,
dependency planning, activation, and block/enable actions map back to the
original candidate records. It does not scan directories, reload sidecars, or
load modules. A selected candidate remains selected when it still matches the
new query; otherwise its details and activation actions are cleared.
**Save Scan Report...** still covers the full scanned candidate set, including
rows hidden by this filter.

The candidate pane can persist a per-user **Block Future Activation** choice
for a selected module path. Blocked candidates are labeled in the list and are
excluded from direct or dependency activation until **Enable Candidate** is
selected. Dependency previews then report a blocked provider as unavailable.
The setting is keyed by the absolute, lexically normalized path and a SHA-256
key in the existing desktop preferences. Blocking does not unload a matching
module that is already running; it is a convenience policy, not a trust or
security boundary. It does not automatically load plugins at startup.

**Install Copy...** is available for a selected, enabled candidate with a
valid sidecar and a matching SHA-256 pin. It copies the module and sidecar into
the per-user `plugins/<plugin-id>` directory adjacent to the plugin-state
directory. Files are staged in a temporary sibling directory, re-scanned, and
published only when the copied identity, capability declarations, and module
hash match the reviewed candidate. An existing ID directory is left untouched;
replacement and update are not supported yet. Installation does not load or
execute the module. The panel switches to the installed candidate so the user
can inspect it and explicitly choose **Load Selected Candidate**. The sidecar
hash is an integrity pin, not a publisher signature, and is required here to
bind the copied bytes to the reviewed scan. Candidates with malformed or
missing sidecars, missing hash pins, hash mismatches, or blocked source paths
cannot be installed through this action.

After scanning a directory, **Save Scan Report...** writes the currently
displayed candidate snapshot as UTF-8 TSV. It includes each exact module path,
sidecar status and declared identity, expected and observed SHA-256 values,
scan-time integrity result, the bounded capability/preflight summary, manifest
error text, and the saved activation preference. Tabs, quotes, and line breaks
are escaped using TSV quoting. Export is limited to 4,096 candidates, 128 KiB
per field, and 4 MiB total. The operation only saves advisory scan metadata;
it does not reload, validate, or execute candidate modules.

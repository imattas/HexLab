# Activate native plugins with their dependencies

The desktop Plugins panel can load a selected plugin and the providers required
by its transitive capability dependencies in one operation. Scan a directory,
select the consumer module, and choose **Preview Dependencies** to inspect the
provider-first activation order. Preview reads the scanned sidecar declarations
and currently loaded metadata; it never opens a native module. Choose **Load
With Dependencies** to activate that group on the plugin lifecycle worker.

The candidate list distinguishes compatible host capabilities, loaded plugin
providers, candidate providers that have not been loaded, missing providers,
and multiple providers. These statuses describe each direct requirement;
**Preview Dependencies** also checks transitive dependencies and cycles.
After a load or unload attempt, the desktop refreshes availability against the
current inventory using the same scanned manifest snapshot and preserves the
selected candidate. Refresh does not read files or execute modules. Scan again
to pick up changed sidecar files.

Only candidates from the explicit directory scan participate. Every newly
activated module needs a valid `.hexlab-plugin` sidecar. Modules without one can
still be loaded individually with **Load Selected Candidate**. Dependency loading
does not search other directories, download modules, or choose between competing
versions. Requirements are capability versions, not plugin package versions.

For each required capability, resolution proceeds as follows:

1. Use a compatible host capability when one exists.
2. Otherwise reuse exactly one compatible loaded provider.
3. Otherwise select exactly one compatible candidate from the supplied scan.
4. Plan that provider's own dependencies before the consumer.

Compatible means the same capability ID and major version, with a provided minor
version at least as high as the required minor version. Missing providers,
multiple compatible providers, repeated candidate plugin IDs, dependency cycles,
and ambiguities introduced by other modules in the selected group reject the
entire plan before opening native code. Unrelated modules are never activated.
Remove an unwanted duplicate from the scanned directory or load the intended
provider individually before planning again to disambiguate candidate providers.

For example, if `review` requires `symbols.api@1.2`, `symbols` provides
`symbols.api@1.3` and requires `decoder.api@1.0`, and `decoder` provides
`decoder.api@1.0`, the plan is `decoder`, `symbols`, `review`. If `decoder` is
already loaded, only `symbols` and `review` are newly activated.

Activation recomputes the plan against the current loaded set while holding one
lifecycle lock. A prior preview is advisory and may no longer be current. After
opening each module, HexLab queries its ABI and compares its ID, name, version,
provided capability declarations, and required capability declarations with the
planned manifest. A mismatch rejects that module before its `start` callback.
Normal ABI, extension, and required-capability checks still apply.

If a module cannot be queried or started, HexLab stops newly activated consumers
before their providers and removes only modules activated by that operation.
Existing loaded plugins stay loaded. A failing `start` receives the normal
`stop` cleanup callback before dependency rollback. Registered image providers,
processor callbacks, actions, and analysis providers disappear with their owning
modules. Native library initialization, query callbacks, and earlier plugin
actions may already have performed external work; inventory rollback cannot undo
those side effects. A sidecar is advisory metadata, not authentication or a
sandbox.

**Unload Selected** retains its existing refusal to remove a provider with live
consumers. **Review Unload With Dependents...** previews the selected plugin and
all loaded plugins that depend on it; after acceptance it stops consumers first. It preserves
providers that the selected plugin uses and any unrelated plugins. Desktop
shutdown also stops consumers before providers on the same lifecycle thread used
for activation.

## Reviewed cleanup API

`PluginManager::plan_unload(root_plugin_id, all)` returns the exact consumer-first
IDs plus directly retained providers without stopping code. `all=true` ignores
the root and reviews the whole loaded inventory. The plan contains an opaque
weak manager identity and generation. `unload_reviewed(plan)` holds the lifecycle
lock, checks that same manager/generation, recomputes the set/order, and rejects
any stale or changed plan before removal. Plans are limited to 256 loaded
modules, 4,096 resolved edges and 64 KiB of loaded IDs.

Successful execution returns `PluginUnloadResult::removed`. A normal failure
after cleanup starts is returned in `failure` together with the exact removed
prefix, allowing clients to invalidate providers even after partial cleanup.
Pre-execution validation errors return an error without removing anything.
Callers should refresh inventory after an unexpected exception; native code is
trusted and neither unload API guarantees that a plugin's `stop` callback returns.
The desktop prepares plans off the UI thread and asks the user to accept the
complete bounded list before invoking this API.

## C++ host API

`PluginManager::plan_activation(candidates, root_path)` returns the selected
candidate closure in activation order without executing code. `root_path` must
exactly match a supplied candidate path. The API accepts up to 4096 candidates,
with at most 256 newly activated modules in the closure. Manifest capability
tables are bounded to 256 provided and 256 required entries.

`PluginManager::refresh_requirement_preflight(candidates)` recomputes advisory
statuses in caller-owned candidates using host, loaded, and candidate provider
precedence. It accepts up to 16384 candidates and validates the 256-entry
capability and requirement bounds before replacing any status tables. It does
not plan a load or verify a native module. Directory discovery uses the same
preflight implementation; the desktop invokes it again on the lifecycle worker
after activation, rollback, and unload.

`PluginManager::load_with_dependencies(candidates, root_path)` replans and returns
the newly loaded `PluginInfo` records in provider-first order. On failure it
returns an error after rolling back the new inventory. It never silently loads
a candidate whose queried metadata differs from its planned manifest.

`PluginManager::unload_with_dependents(plugin_id)` returns removed IDs in
consumer-first order. `unload_all()` removes all modules in reverse activation
order. Manager destruction follows the same reverse order, while callers remain
responsible for invoking lifecycle operations on a thread compatible with any
thread-affine plugin resources. The desktop adapter already does so.

These are host-side orchestration APIs; no plugin C ABI change is required.
Each started module receives a stable borrowed host table that remains valid
through its `stop` callback, even as activation grows the loaded inventory or
an earlier unrelated plugin is removed. A plugin must finish its worker threads
before `stop` returns and must not use the host table afterward.

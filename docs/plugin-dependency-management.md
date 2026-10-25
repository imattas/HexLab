# Plugin Capability Dependencies

HexLab checks every plugin's versioned required-capability declarations before
starting it. A requirement can be satisfied by a capability declared by the
host, or by exactly one plugin that is already loaded and declares a compatible
version. A provider must declare the same capability ID and major version, and
its minor version must be at least the requested minor version.

Load providers before consumers. Missing and ambiguous providers reject the
consumer before its `start` callback runs. `PluginInfo::resolved_dependencies`
reports the loaded plugin IDs that satisfied consumer requirements. Host
capabilities do not appear in that list. The desktop plugin page displays these
provider IDs alongside required capabilities.

HexLab refuses to unload a provider while a loaded consumer depends on it. The
consumer must be unloaded first. This keeps the loaded plugin set consistent
with the capability checks performed at activation.

The desktop can explicitly activate a selected scanned module with its
transitive dependencies, preview that provider-first plan, or unload a selected
provider with its consumers. See [dependency activation](plugin-dependency-activation.md)
for provider precedence, manifest verification and rollback. Candidate
availability is advisory and refreshes after lifecycle changes; it does not
substitute for the transitive activation plan.

This is dependency validation and lifetime ordering. It does not discover or
activate modules without an explicit host request, transfer function pointers
or other services between plugins, or sandbox native modules. A capability
provider should only be treated as a
prerequisite marker unless the consumer receives its service through another
documented interface.

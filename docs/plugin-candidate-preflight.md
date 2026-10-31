# Plugin candidate capability preflight

The desktop Plugins panel can scan a plugin directory without loading its
native modules. For each candidate with a valid `.hexlab-plugin` sidecar, it
shows declared capabilities and a scan-time preflight for each required
capability:

- **host**: the running HexLab host declares a compatible major version and at
  least the requested minor version;
- **plugin `<id>`**: exactly one currently loaded plugin declares a compatible
  capability;
- **unavailable**: no compatible host or loaded plugin provider was found;
- **multiple providers**: more than one loaded plugin appears to provide the
  capability.

The preflight reads sidecar data only. Directory scanning does not open or run
candidate code, and a sidecar does not prove that its native module has the
declared identity or ABI. The table labels identity as unverified. Choosing
**Load Selected Candidate** is still an explicit action; the manager then
queries the native module and rechecks required capabilities against the
current host and loaded plugins. Load can fail if the module disagrees with its
sidecar or the providers changed after the scan.

Sidecars are bounded to 64 KiB and at most 256 provided or required capability
records. A directory scan examines at most 4096 entries in the desktop flow.
Malformed or missing sidecars remain visible as candidates with an unverified
identity and no capability preflight. The **Check Authenticode Trust** action
checks the selected file using Windows' generic Authenticode trust policy,
without opening the module as code. It uses cached trust data only and does not
check revocation. A positive result reflects the current Windows trust store;
it is informational and does not gate activation. Other platforms report that
the provider is unsupported. Neither a sidecar hash nor this check provides
process isolation: native modules still run in-process.

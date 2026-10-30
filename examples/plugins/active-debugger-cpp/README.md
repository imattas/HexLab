# Active debugger C++ plugin

This standalone C++ module demonstrates the read-only ABI 1.17
`ActiveDebuggerClient`. Its **Inspect Active Debugger** action queries one
snapshot token, pages the first 64 stopped threads, reads up to 96 registers
for the first thread, and uses a recognized `pc`/`rip`/`eip` value for an exact
16-byte memory read. Every operation reuses the same snapshot token. If the
process resumes or the session/document changes, the plugin reports the stale
snapshot and asks the user to invoke the action again.

The sample never launches, resumes, writes, or sets breakpoints in a process.
It reports a missing PC register or unavailable memory without guessing an
architecture-specific register layout.

Build and install it against a HexLab installation that includes the plugin
SDK package:

```sh
cmake -S examples/plugins/active-debugger-cpp -B build/active-debugger-plugin \
  -DCMAKE_PREFIX_PATH=/path/to/hexlab-install
cmake --build build/active-debugger-plugin
cmake --install build/active-debugger-plugin --prefix /path/to/plugin-install
```

Scan the installed `lib/hexlab/plugins` directory in HexLab, load the module,
stop a process, then invoke **Inspect Active Debugger** from the plugin action
menu. The result is written to the host log. If the package is copied between
machines, rebuild it against each installation's matching SDK headers.

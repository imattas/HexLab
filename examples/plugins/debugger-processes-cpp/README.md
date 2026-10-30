# Debugger process inventory C++ plugin

This standalone module demonstrates a short lived owned `DebuggerClient`
session and its process-page wrapper. It only queries the selected backend's
process inventory; it does not launch, attach, modify, or interrupt a process.
The session is closed by RAII before the action callback returns. The plugin
requires `debugger.api` v1.8 and is rejected by hosts that do not provide that
contract.

On a debugger session that has been launched or attached, ABI 1.31 clients can
also retrieve a full event message without the legacy 256-byte truncation:

```cpp
if (debugger.supports_event_text()) {
    HexLabDebugEventText event{};
    if (debugger.wait_event_text(1000, event) == 0) {
        // Use event.sequence with continue_event or single_step_event.
        // event.message can contain up to 4096 UTF-8 bytes.
    }
}
```

The process inventory action below does not launch or attach to a target, so it
does not wait for events itself.

Build and install it against a HexLab installation that includes the plugin
SDK package:

```sh
cmake -S examples/plugins/debugger-processes-cpp -B build/debugger-processes-plugin \
  -DCMAKE_PREFIX_PATH=/path/to/hexlab-install
cmake --build build/debugger-processes-plugin
cmake --install build/debugger-processes-plugin --prefix /path/to/plugin-install
```

Load the installed module and invoke **List Debugger Processes**. Results are
reported as a page count in the host log; pages contain at most 32 records in
this example.

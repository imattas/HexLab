# Active document C++ plugin

This standalone C++ module demonstrates the versioned `ActiveDocumentClient`
API. Its **Inspect Active File Prefix** action obtains a document snapshot,
reads up to 16 bytes from the effective file view using that snapshot token,
and writes the bytes to the host log. If the active document changes between
the query and read, it reports the stale-token result and asks the user to
invoke the action again.

Build and install it against a HexLab installation that includes the plugin
SDK package:

```sh
cmake -S examples/plugins/active-document-cpp -B build/active-document-plugin \
  -DCMAKE_PREFIX_PATH=/path/to/hexlab-install
cmake --build build/active-document-plugin
cmake --install build/active-document-plugin --prefix /path/to/plugin-install
```

Scan the installed `lib/hexlab/plugins` directory in HexLab, load the module,
and invoke **Inspect Active File Prefix** with a binary open. The plugin reads
only the current document's file view and does not open project paths or retain
the active-document token across invocations.

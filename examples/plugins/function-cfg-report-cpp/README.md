# Function CFG Report C++ plugin

This standalone C++ analysis-provider example uses the SDK `ProjectClient` to
open a saved project read-only, analyze it, page through recovered functions,
and query each function's basic blocks, block instructions, and successor
edges. It also queries outgoing references for each block's first byte through
the bounded virtual-range API. It reports unresolved-address edges and marks
output when its explicit function, block, or page limits stop the scan.

The plugin declares requirements for `project.api` v1.0, `project.cfg` v1.21,
`project.instruction-text` v1.30, `project.string-preview` v1.32, and
`project.references.range` v1.0, so a host without the required services
rejects it before the provider is registered.
The provider checks the actual project table tails through `ProjectClient` and
passes zero-initialized records for every page. CFG instruction pages use the
ABI 1.30 record, which carries up to 1023 bytes of formatted UTF-8 instruction
text. ABI 1.32 string pages carry previews up to 1023 bytes. The original ABI
1 records remain available with their 255-byte content bounds.

Build and install against a HexLab installation with the matching native SDK:

```sh
cmake -S examples/plugins/function-cfg-report-cpp -B build/function-cfg-report-plugin \
  -DCMAKE_PREFIX_PATH=/path/to/hexlab-install
cmake --build build/function-cfg-report-plugin
cmake --install build/function-cfg-report-plugin --prefix /path/to/plugin-install
```

Scan and load the installed module, then run the **Function CFG Report**
analysis provider on a saved project. The provider returns aggregate counts;
it does not persist or modify project data. Function discovery may be
incomplete, and the sample's fixed scan limits are not a complete-project
verification. String preview inspection is capped at the first 64 records.

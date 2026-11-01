# Native SDK analysis export

The optional `hexlab_analysis_export` example runs the native analysis engine
for an existing `.hxproj` project and streams a detached snapshot to JSON. It
exports revision metadata, function summaries, decoded instructions and their
bytes, mapped segments, references, and discovered strings under the
`hexlab.native-analysis.v1` schema.

Build the optional native SDK examples with
`-DHEXLAB_BUILD_AUTOMATION_EXAMPLES=ON`, then run:

```text
hexlab_analysis_export project.hxproj analysis.json
```

The exporter analyzes the live project, captures the resulting revision, then
reads from that immutable capture. Each native API page contains at most 4,096
rows, so the exporter does not retain a whole project table in memory. Its
`analysis_complete` field summarizes function, reference, and string scan
completeness; individual function rows also retain their completeness flag.
Numeric address spaces and enum values use the public SDK's numeric values.
Instruction encodings are emitted as lowercase hexadecimal, including full
length bytecode encodings.

The destination must not already exist. Output is written under a unique
temporary directory beside the destination and atomically published only after
the complete JSON document has been flushed; it will not replace an output
created concurrently. Failure leaves no partial output at the requested path.
This example is a starting point for SDK integrations;
it does not include CFG block tables, debug variable locations, or arbitrary
project annotations.

# Native SDK analysis export

The optional `hexlab_analysis_export` example runs the native analysis engine
for an existing `.hxproj` project and streams a detached snapshot to JSON. It
exports revision metadata, function summaries, decoded instructions and their
bytes, CFG blocks and typed successor edges, mapped segments, references,
discovered strings, annotations, type definitions, and type assignments under
the `hexlab.native-analysis.v1` schema.

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
length bytecode encodings. Blocks and edges are separate tables keyed by stable
function and block IDs, so loops and shared tails remain explicit. Type rows
include their ID, declaration kind, target layout size when known, and the
public type formatter's declaration text.

The destination must not already exist. Output is written under a unique
temporary directory beside the destination and atomically published only after
the complete JSON document has been flushed; it will not replace an output
created concurrently. Failure leaves no partial output at the requested path.
The export does not include debug variable locations, plugin-owned metadata, or
historical state. Annotation and type rows reflect the captured project
revision; the exporter does not alter the source project.

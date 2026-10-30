# JVM build provenance attributes

HexLab retains the JDK-specific class-level `CompilationID` and `SourceID`
attributes exposed by the JDK Class-File API. Each payload is exactly a
two-byte constant-pool index that must resolve to `CONSTANT_Utf8`. An
attribute may occur once per class; the parser rejects occurrences on fields,
methods, or inside `Code` attributes.

The model preserves the decoded value, its constant-pool index, and the file
offset of the index in the attribute payload. CLI output bounds the displayed
value to 192 bytes, escapes unsafe characters, and reports the complete byte
length and reference offset.

The strings are treated as opaque provenance. Their spelling is retained
without interpreting numeric timestamps, validating the producer, resolving a
source path, or incorporating either value into class identity. Absence is
distinct from a present empty string. Other JDK-specific class-file attributes
without a dedicated decoder remain available as opaque file-backed payloads.

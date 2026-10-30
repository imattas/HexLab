# PE bound import metadata

HexLab parses the PE bound-import directory (data-directory index 11) into
`PeMetadata::bound_imports`. Each module record preserves its timestamp, module
name, source span, and all immediately following forwarder-reference records.
Module-name offsets are interpreted relative to the directory start, as required
by the PE format.

The parser requires a zero descriptor terminator inside the declared directory,
bounds every forwarder array and name string to that directory, rejects
nonzero reserved forwarder fields, and retains file-offset provenance for every
descriptor and string. CLI output prints descriptor offsets and every source
span for module and forwarder names as `name-source=offset+size` pairs, including
multiple spans if a name crosses mapped extents. A malformed directory marks optional PE metadata partial
and emits a diagnostic; it does not discard the mapped image. This parser does
not bind imports or validate a bound directory against another image.

Validation: `hexlab_loader_tests` covers PE32 and PE32+, module/forwarder values,
source spans, bad relative offsets, unterminated names, truncated forwarder
arrays, reserved bits, and a missing in-directory terminator.

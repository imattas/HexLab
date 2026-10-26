# Mach-O export trie names

The export-trie reader preserves names and terminal source locations while
marking an export or stream incomplete when an exported or re-exported name is
not valid UTF-8. This follows the Mach-O export-terminal format, which defines
the re-export import name as a zero-terminated UTF-8 string. Names remain byte
preserving in metadata so malformed input can still be inspected.

For known terminal flag combinations, the reader validates that the terminal
payload is consumed exactly even when another semantic check makes the export
incomplete, such as an address outside mapped segments or a duplicate name.
Unknown flags or unsupported flag combinations retain partial metadata and do
not claim that the unrecognized terminal layout was fully validated.

The reader does not resolve re-exports against external dylib files, execute
stub resolvers, or reinterpret absolute and thread-local values as image
addresses.

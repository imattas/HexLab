# Managed CIL user strings

Managed method inspection decodes CLR `#US` heap entries as bounded UTF-16 code-unit strings and resolves `ldstr` operands through their `0x70xxxxxx` metadata tokens. The reserved heap index zero is skipped. Entry lengths and the trailing kind byte are validated; malformed UTF-16 byte lengths, invalid kind bytes, out-of-heap entries, oversized entries, excessive aggregate code units, and invalid token offsets fail closed. A zero-filled tail is treated as metadata heap padding.

Only methods that contain `ldstr` require the user-string heap to parse and resolve successfully. The catalog is shared by all method records instead of copied per method. The CIL stack analysis models the loaded value as an opaque managed reference, so compatible joins and `dup` work without claiming CLR object-layout knowledge. Pseudocode prints the recovered content as an escaped string literal, preserving control characters and UTF-16 surrogate code units in deterministic escapes. The original user-string token is retained in the decompilation reference list.

This does not resolve `#Strings` heap identifiers as runtime strings, model interning or object identity, or infer `System.String` call effects. Calls consuming strings still use the existing metadata-signature stack-effect rules.

# Mach-O `LC_DYLD_ENVIRONMENT` metadata

The Mach-O loader retains the required-dyld load command `LC_DYLD_ENVIRONMENT`
(`0x80000027`) as a dedicated environment-text record. It is kept separate
from `LC_RPATH` and other filesystem path commands so the value is not treated
as a path. The desktop Mach-O metadata table labels these rows **Dyld
environment**; CLI inspection prints `dyld-environment`, the decoded value,
the `lc_str` offset, and the command's source file offset.

The parser requires the fixed 12-byte command header, then validates the
32-bit string offset against the command extent and requires a NUL terminator
within the existing bounded string scan. An offset into the fixed header, an
offset at or beyond the command end, a missing terminator, or an oversized
string makes the command malformed. Parsed text is metadata only: HexLab does
not apply these environment values, launch a loader, or modify process
environment state.

# Desktop source view

The Binary notebook includes a **Source** page. When the current address has a
PE/PDB, ELF/DWARF, or Mach-O/DWARF line mapping, the page displays the mapped
local source file with up to twenty surrounding lines on either side. The
current source line is selected as disassembly navigation changes. Selecting
a mapped source line navigates back to its address in the disassembly.

The source page lists every source path present in the document's line table.
Use **Filter source files** to narrow the picker by a case-insensitive match
against the full debug path, then choose a path to inspect its first mapped line, or the closest preceding line
for the current address when that file has a mapping in the same address space.
The filter only changes the visible picker entries; it does not alter line
mappings. Address navigation clears a filter that hides the current mapped
file, selects that file in the picker, and keeps source-line clicks navigating
to the corresponding machine address.

Source paths come from the binary's debug information and are treated only as
informational local file paths. The view rejects Windows network shares and
device namespace paths (including canonical targets reached through a local
alias), requires a regular file, limits the path to 32 KiB, and reads no more
than 1 MiB per selection. It does not fetch, execute, or build source. Missing
files, rejected paths, out-of-range line numbers, and files above the size
limit are reported in the page rather than silently showing unrelated
content. The debug format does not always provide an exact end address for a
line, so address selection uses the nearest preceding source row in the same
address space; this is a best-effort mapping for optimized code and gaps.

When a source line has several distinct machine addresses, **Previous address**
and **Next address** move through those mappings in address order. The selected
address stays synchronized with disassembly, bytes, pseudocode, and the graph.
Selecting a different visible source line starts at its first mapped address in
the active address space.

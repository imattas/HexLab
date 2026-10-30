# ELF program-header security metadata

The ELF inspection output now lists program headers with their raw type, flags,
file extent, virtual address extent, and alignment. It decodes the standard
read/write/execute flag bits and names common program-header types, including
`PT_GNU_STACK` and `PT_GNU_RELRO`. Output is capped at 256 rows; the omitted
count is reported when the file contains more headers.

For `PT_GNU_STACK`, the execute bit is shown as an executable-stack request.
This is a declaration carried by the file and does not establish what policy a
particular kernel or runtime loader will enforce. For `PT_GNU_RELRO`, the
program header's address and memory size are shown as a RELRO candidate range.
The loader may make an appropriate range read-only after relocation, but this
inspection does not model runtime mapping, relocation completion, or page
rounding, and therefore does not claim that the range is protected in a running
process.

All displayed extents and flags come from the existing bounded program-header
parser. The CLI summary does not infer a security verdict, reject unusual
headers, or validate that a RELRO range maps to a particular set of load
segments.

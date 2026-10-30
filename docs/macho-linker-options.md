# Mach-O linker options

The loader now decodes `LC_LINKER_OPTION` in `MH_OBJECT` files. It retains each
nonempty NUL-terminated option string with the load-command index, option index,
string file offset, and command file offset. The declared count must match the
number of nonempty strings. Zero bytes between strings and at the end of the
command are accepted as padding.

Parsing is bounded to 4096 options, 4096 bytes per option, and a 1 MiB command.
Malformed extents, missing terminators, count mismatches, and over-limit input
are rejected. The CLI escapes non-printable option bytes and caps displayed
rows at 256.

This is descriptive metadata. HexLab does not pass these strings to a system
linker or treat them as executable commands. The command layout and object-file
scope follow LLVM's [`linker_option_command`](https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/MachO.h)
and its [Mach-O object reader validation](https://github.com/llvm/llvm-project/blob/main/llvm/lib/Object/MachOObjectFile.cpp).

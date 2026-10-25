import pathlib
import struct
import sys


path = pathlib.Path(sys.argv[1])
mode = sys.argv[2] if len(sys.argv) > 2 else "text-relocation"
data = path.read_bytes()
assert data[:7] == b"\x7fELF\x02\x01\x01", "output is not ELF64 little-endian"
is_executable = mode.startswith("executable")
assert struct.unpack_from("<H", data, 16)[0] == (2 if is_executable else 1), "output ELF type is incorrect"
assert struct.unpack_from("<H", data, 18)[0] == 62, "output is not x86-64"
shoff = struct.unpack_from("<Q", data, 40)[0]
shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 58)
assert shentsize == 64 and shnum == 6 and shstrndx == 5, "unexpected linked section table"


def section(index):
    return struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * shentsize)


shstr = section(shstrndx)
names = data[shstr[4] : shstr[4] + shstr[5]]


def name(offset):
    end = names.index(0, offset)
    return names[offset:end].decode("ascii")


sections = {name(section(i)[0]): section(i) for i in range(shnum)}
text = sections[".text"]
data_section = sections[".data"]
base = 0x400000
if is_executable:
    assert text[3] == base + text[4], "ET_EXEC .text address does not map its file offset"
    assert data_section[3] == base + data_section[4], "ET_EXEC .data address does not map its file offset"
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    assert phoff == 64 and phentsize == 56 and phnum == 2, "unexpected ET_EXEC program header table"
    text_load = struct.unpack_from("<IIQQQQQQ", data, phoff)
    data_load = struct.unpack_from("<IIQQQQQQ", data, phoff + phentsize)
    assert text_load[:4] == (1, 5, 0, base), "text PT_LOAD must map the ELF header and executable text"
    assert text_load[5] == text[4] + text[5] and text_load[6] == text_load[5], "text PT_LOAD extent is incorrect"
    assert data_load[:4] == (1, 6, data_section[4], data_section[3]), "data PT_LOAD mapping/permissions are incorrect"
    assert data_load[5] == data_section[5] and data_load[6] == data_section[5], "data PT_LOAD extent is incorrect"
assert data_section[2] == 3, f"expected writable allocated data flags, got {data_section[2]}"
assert data_section[8] == 4 and data_section[4] % 4 == 0, "output .data alignment is incorrect"
data_bytes = data[data_section[4] : data_section[4] + data_section[5]]
if mode in ("data-relocation", "executable-data-relocation"):
    expected_data = b"\x0c\x00\x00\x00" + bytes(12) + bytes(4) + b"TWO!"
    assert data_bytes == expected_data, f"R_X86_64_PC32 data relocation/provider rebasing or merged bytes are incorrect: {data_bytes.hex()}"
elif mode == "executable-absolute-relocation":
    expected_data = bytes(20) + b"TWO!"
    assert data_bytes == expected_data, "unexpected PC-relative data relocation in absolute relocation executable"
else:
    assert data_bytes == b"ROOTONE!TWO!", "merged writable data bytes are incorrect"
assert text[8] == 32, f"expected merged .text alignment 32, got {text[8]}"
assert text[4] % text[8] == 0, "output .text file offset does not satisfy sh_addralign"
text_bytes = data[text[4] : text[4] + text[5]]
assert len(text_bytes) == 24, f"expected three concatenated 8-byte text sections, got {len(text_bytes)}"
if mode == "executable-absolute-relocation":
    expected_absolute = data_section[3] + 16 - 4
    assert text_bytes[:8] == struct.pack("<Q", expected_absolute), "R_X86_64_64 was not rebased to the executable data symbol"
    assert text_bytes[8:] == b"\x90" * 16, "unexpected text bytes after absolute relocation"
else:
    assert text_bytes[:4] == (b"\x90" * 4 if mode.endswith("data-relocation") else b"\x04\x00\x00\x00"), f"R_X86_64_PC32 result not applied to the right output section: {text_bytes[:4].hex()}"
    assert text_bytes[4:] == b"\x90" * 20, "unexpected text bytes after relocation"
assert ".rela.text" not in sections, "fully resolved output must not retain relocations"

sym = sections[".symtab"]
assert sym[7] == 2, f"expected null plus one local symbol before globals, got sh_info={sym[7]}"
strtab = sections[".strtab"]
symbol_strings = data[strtab[4] : strtab[4] + strtab[5]]
symbols = {}
for index, at in enumerate(range(sym[4] + 24, sym[4] + sym[5], 24), start=1):
    name_offset, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", data, at)
    assert (info >> 4 == 0) == (index < sym[7]), "local/global symbol order disagrees with symtab sh_info"
    if name_offset:
        end = symbol_strings.index(0, name_offset)
        symbols[symbol_strings[name_offset:end].decode("ascii")] = (shndx, value)
text_base = text[3] if is_executable else 0
data_base = data_section[3] if is_executable else 0
assert symbols.get("root_symbol") == (1, text_base)
assert symbols.get("root_local") == (1, text_base + 4)
assert symbols.get("first_needed") == (1, text_base + 8)
assert symbols.get("second_needed") == (1, text_base + 16)
assert symbols.get("root_data") == (2, data_base)
if mode in ("data-relocation", "executable-data-relocation", "executable-absolute-relocation"):
    assert symbols.get("first_data") == (2, data_base + 16)
    assert symbols.get("second_data") == (2, data_base + 20)
else:
    assert symbols.get("first_data") == (2, data_base + 4)
    assert symbols.get("second_data") == (2, data_base + 8)
if is_executable:
    entry = struct.unpack_from("<Q", data, 24)[0]
    assert entry == symbols["root_symbol"][1], "e_entry does not resolve to the requested root symbol"

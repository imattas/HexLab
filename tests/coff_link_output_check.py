import pathlib
import struct
import sys

image = pathlib.Path(sys.argv[1]).read_bytes()
check_bss = len(sys.argv) > 2 and sys.argv[2] == "bss"
assert image[:2] == b"MZ", "missing DOS signature"
pe = struct.unpack_from("<I", image, 0x3C)[0]
assert image[pe:pe + 4] == b"PE\0\0", "missing PE signature"
machine, section_count, _, _, _, optional_size, characteristics = struct.unpack_from("<HHIIIHH", image, pe + 4)
assert machine == 0x8664 and section_count == (3 if check_bss else 2) and optional_size == 240
assert characteristics & 0x0002 and characteristics & 0x0001
optional = pe + 24
assert struct.unpack_from("<H", image, optional)[0] == 0x20B
entry = struct.unpack_from("<I", image, optional + 16)[0]
image_base = struct.unpack_from("<Q", image, optional + 24)[0]
sections = optional + optional_size
text_name = image[sections:sections + 8].rstrip(b"\0")
text_virtual_size, text_rva, text_raw_size, text_raw = struct.unpack_from("<IIII", image, sections + 8)
assert text_name == b".text" and entry == text_rva and text_raw == (0x400 if check_bss else 0x200)
text = image[text_raw:text_raw + text_virtual_size]
if check_bss:
    assert text[:3] == b"\x48\x8d\x05" and text[-1] == 0xc3
    state_displacement = struct.unpack_from("<i", text, 3)[0]
    data_header = sections + 40
    bss_header = sections + 80
    assert image[data_header:data_header + 8].rstrip(b"\0") == b".data"
    assert image[bss_header:bss_header + 8].rstrip(b"\0") == b".bss"
    bss_size, bss_rva, bss_raw_size, bss_raw = struct.unpack_from("<IIII", image, bss_header + 8)
    bss_flags = struct.unpack_from("<I", image, bss_header + 36)[0]
    assert (bss_size, bss_raw_size, bss_raw, bss_flags) == (16, 0, 0, 0xC0000080)
    assert struct.unpack_from("<I", image, optional + 12)[0] == 16
    assert text_rva + 7 + state_displacement == bss_rva
    call_offset = 8
    displacement = struct.unpack_from("<i", text, call_offset)[0]
    helper_rva = text_rva + call_offset + 4 + displacement
    assert helper_rva == text_rva + 13, f"REL32 helper target incorrect: {helper_rva:#x}"
else:
    assert text[:1] == b"\xe8" and text[5] == 0xc3 and text[-1] == 0xc3
    displacement = struct.unpack_from("<i", text, 1)[0]
    helper_rva = text_rva + 5 + displacement
    assert helper_rva == text_rva + 6, f"REL32 target incorrect: {helper_rva:#x}"
assert image_base == 0x140000000
print("valid static PE32+ AMD64 image with resolved REL32 call and BSS" if check_bss else
      "valid static PE32+ AMD64 image with resolved REL32 call")

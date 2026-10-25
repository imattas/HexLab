import argparse
import pathlib
import struct


def elf64(definitions, undefined, relocation=False, relocation_type=2, text_alignment=1, locals_=(), data_symbol=None, data_payload=b"", relocation_target="text", relocation_offset=0, relocation_symbol_name=None):
    names = ["", *locals_, *definitions, *undefined, *([data_symbol] if data_symbol else [])]
    strings = bytearray(b"\0")
    offsets = {}
    for name in names[1:]:
        offsets[name] = len(strings)
        strings.extend(name.encode("ascii") + b"\0")

    header_size = 64
    text = b"\x90" * 8
    text_offset = header_size
    data_offset = text_offset + len(text)
    strings_offset = data_offset + len(data_payload)
    symbols_offset = strings_offset + len(strings)
    symbol_data = bytearray(24)
    for name in locals_:
        symbol_data.extend(struct.pack("<IBBHQQ", offsets[name], 0x02, 0, 1, 4, 0))
    for name in definitions:
        symbol_data.extend(struct.pack("<IBBHQQ", offsets[name], 0x10, 0, 1, 0, 0))
    for name in undefined:
        symbol_data.extend(struct.pack("<IBBHQQ", offsets[name], 0x10, 0, 0, 0, 0))
    if data_symbol:
        symbol_data.extend(struct.pack("<IBBHQQ", offsets[data_symbol], 0x11, 0, 2, 0, len(data_payload)))
    rela_offset = symbols_offset + len(symbol_data)
    relocation_symbol = 1 + len(locals_) + len(definitions)
    if relocation_symbol_name is not None:
        relocation_symbol += undefined.index(relocation_symbol_name)
    rela = struct.pack("<QQq", relocation_offset, (relocation_symbol << 32) | relocation_type, -4) if relocation else b""
    rela_name = ".rela.data" if relocation_target == "data" else ".rela.text"
    shstrings = b"\0.text\0.data\0.strtab\0.symtab\0" + rela_name.encode("ascii") + b"\0.shstrtab\0"
    shstr_offset = rela_offset + len(rela)
    sections_offset = (shstr_offset + len(shstrings) + 7) & ~7
    shnum = 7 if relocation else 6
    shstr_index = 6 if relocation else 5
    data = bytearray(sections_offset + shnum * 64)
    data[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHI", data, 16, 1, 62, 1)
    struct.pack_into("<Q", data, 40, sections_offset)
    struct.pack_into("<HHHHHH", data, 52, 64, 0, 0, 64, shnum, shstr_index)
    data[text_offset : text_offset + len(text)] = text
    data[data_offset : data_offset + len(data_payload)] = data_payload
    data[strings_offset : strings_offset + len(strings)] = strings
    data[symbols_offset : symbols_offset + len(symbol_data)] = symbol_data
    data[rela_offset : rela_offset + len(rela)] = rela
    data[shstr_offset : shstr_offset + len(shstrings)] = shstrings

    def section(index, kind, offset, size, name=0, link=0, info=0, stride=0, flags=0, alignment=0):
        at = sections_offset + index * 64
        struct.pack_into("<I", data, at, name)
        struct.pack_into("<I", data, at + 4, kind)
        struct.pack_into("<Q", data, at + 8, flags)
        struct.pack_into("<QQ", data, at + 24, offset, size)
        struct.pack_into("<II", data, at + 40, link, info)
        struct.pack_into("<Q", data, at + 48, alignment)
        struct.pack_into("<Q", data, at + 56, stride)

    section(1, 1, text_offset, len(text), name=1, flags=6, alignment=text_alignment)
    section(2, 1, data_offset, len(data_payload), name=7, flags=3, alignment=4)
    section(3, 3, strings_offset, len(strings), name=13)
    section(4, 2, symbols_offset, len(symbol_data), name=21, link=3, info=1 + len(locals_), stride=24, alignment=8)
    if relocation:
        section(5, 4, rela_offset, len(rela), name=29, link=4, info=2 if relocation_target == "data" else 1, stride=24, alignment=8)
        section(6, 3, shstr_offset, len(shstrings), name=40 if relocation_target == "text" else 40, alignment=1)
    else:
        section(5, 3, shstr_offset, len(shstrings), name=35, alignment=1)
    return bytes(data)


def ar_member(name, payload):
    header = (name + "/").encode("ascii").ljust(16, b" ")
    header += b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6)
    header += b"100644".ljust(8) + str(len(payload)).encode("ascii").ljust(10) + b"`\n"
    return header + payload + (b"\n" if len(payload) & 1 else b"")


def coff64(text, symbols, relocations=(), bss_size=0):
    """Small AMD64 COFF object with optional zero-initialized .bss."""
    header_size, section_size = 20, 40
    section_count = 2 if bss_size else 1
    raw_offset = header_size + section_size * section_count
    reloc_offset = raw_offset + len(text)
    symbol_offset = reloc_offset + len(relocations) * 10
    strings = bytearray(b"\0\0\0\0")
    names = {}
    entries = list(symbols)
    if bss_size:
        entries.insert(0, (".bss", 0, 2, 3, bss_size))
    for item in entries:
        name = item[0]
        if len(name) > 8:
            names[name] = len(strings)
            strings.extend(name.encode() + b"\0")
    struct.pack_into("<I", strings, 0, len(strings))
    rows = bytearray()
    indices = {}
    symbol_count = 0
    for item in entries:
        name, value, section = item[:3]
        storage = item[3] if len(item) > 3 else 2
        auxiliary = item[4] if len(item) > 4 else 0
        indices[name] = len(rows) // 18
        if name in names:
            row_name = struct.pack("<II", 0, names[name])
        else:
            row_name = name.encode().ljust(8, b"\0")
        rows.extend(row_name + struct.pack("<IhHBB", value, section, 0 if storage == 3 else 0x20, storage, 1 if auxiliary else 0))
        symbol_count += 1
        if auxiliary:
            aux_row = bytearray(18)
            struct.pack_into("<I", aux_row, 0, auxiliary)
            rows.extend(aux_row)
            symbol_count += 1
    out = bytearray(symbol_offset + len(rows) + len(strings))
    struct.pack_into("<HHIIIHH", out, 0, 0x8664, section_count, 0, symbol_offset, symbol_count, 0, 0)
    out[20:28] = b".text\0\0\0"
    struct.pack_into("<IIIIIIHHI", out, 28, 0, 0, len(text), raw_offset, reloc_offset if relocations else 0, 0,
                     len(relocations), 0, 0x60000020)
    if bss_size:
        out[60:68] = b".bss\0\0\0\0"
        struct.pack_into("<IIIIIIHHI", out, 68, 0, 0, bss_size, 0, 0, 0, 0, 0, 0xC0000080)
    out[raw_offset:raw_offset + len(text)] = text
    for i, (offset, symbol, kind) in enumerate(relocations):
        struct.pack_into("<IIH", out, reloc_offset + i * 10, offset, indices[symbol], kind)
    out[symbol_offset:symbol_offset + len(rows)] = rows
    out[symbol_offset + len(rows):] = strings
    return bytes(out)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=pathlib.Path, required=True)
    args = parser.parse_args()
    args.artifacts.mkdir(parents=True, exist_ok=True)
    (args.artifacts / "link-root.o").write_bytes(
        elf64(["root_symbol"], ["first_needed"], relocation=True, text_alignment=32, locals_=["root_local"],
              data_symbol="root_data", data_payload=b"ROOT")
    )
    (args.artifacts / "link-unsupported.o").write_bytes(
        elf64(["root_symbol"], ["first_needed"], relocation=True, relocation_type=999, data_symbol="bad_data", data_payload=b"BAD!")
    )
    (args.artifacts / "link-data-relocation.o").write_bytes(
        elf64(["root_symbol"], ["first_needed", "first_data"], relocation=True, relocation_target="data",
              text_alignment=32, locals_=["root_local"], data_symbol="root_data", data_payload=bytes(16),
              relocation_symbol_name="first_data")
    )
    (args.artifacts / "link-exec-relocation.o").write_bytes(
        elf64(["root_symbol"], ["first_needed", "first_data"], relocation=True, relocation_type=1,
              relocation_target="text", text_alignment=32, locals_=["root_local"], data_symbol="root_data",
              data_payload=bytes(16), relocation_symbol_name="first_data")
    )
    (args.artifacts / "link-out-of-bounds.o").write_bytes(
        elf64(["root_symbol"], ["first_needed"], relocation=True, relocation_offset=7,
              data_symbol="bad_data", data_payload=b"BAD!")
    )
    (args.artifacts / "link-data-out-of-bounds.o").write_bytes(
        elf64(["root_symbol"], ["first_needed"], relocation=True, relocation_target="data", relocation_offset=2,
              data_symbol="bad_data", data_payload=b"BAD!")
    )
    archive = b"!<arch>\n"
    archive += ar_member("first.o", elf64(["first_needed"], ["second_needed"], data_symbol="first_data", data_payload=b"ONE!"))
    archive += ar_member("second.o", elf64(["second_needed"], ["not_available"], data_symbol="second_data", data_payload=b"TWO!"))
    (args.artifacts / "link-lib.a").write_bytes(archive)
    good_archive = b"!<arch>\n"
    good_archive += ar_member("first.o", elf64(["first_needed"], ["second_needed"], data_symbol="first_data", data_payload=b"ONE!"))
    good_archive += ar_member("second.o", elf64(["second_needed"], [], data_symbol="second_data", data_payload=b"TWO!"))
    (args.artifacts / "link-good.a").write_bytes(good_archive)
    data_archive = b"!<arch>\n"
    data_archive += ar_member("first.o", elf64(["first_needed"], ["second_needed", "second_data"], relocation=True,
                                                   relocation_target="data", relocation_symbol_name="second_data",
                                                   data_symbol="first_data", data_payload=b"ONE!"))
    data_archive += ar_member("second.o", elf64(["second_needed"], [],
                                                    data_symbol="second_data", data_payload=b"TWO!"))
    (args.artifacts / "link-data-good.a").write_bytes(data_archive)
    (args.artifacts / "coff-root.obj").write_bytes(coff64(b"\xe8\0\0\0\0\xc3", [("_start", 0, 1), ("_helper", 0, 0)], [(1, "_helper", 4)]))
    (args.artifacts / "coff-lib.lib").write_bytes(b"!<arch>\n" + ar_member("helper.obj", coff64(b"\xc3", [("_helper", 0, 1)])))
    (args.artifacts / "coff-bss-root.obj").write_bytes(
        coff64(b"\x48\x8d\x05\0\0\0\0\xe8\0\0\0\0\xc3",
               [("_start", 0, 1), ("_state", 0, 2), ("_helper", 0, 0)],
               [(3, "_state", 4), (8, "_helper", 4)], bss_size=16))
    (args.artifacts / "coff-bss-out-of-range.obj").write_bytes(
        coff64(b"\x48\x8d\x05\0\0\0\0\xe8\0\0\0\0\xc3",
               [("_start", 0, 1), ("_state", 17, 2), ("_helper", 0, 0)],
               [(3, "_state", 4), (8, "_helper", 4)], bss_size=16))


if __name__ == "__main__":
    main()

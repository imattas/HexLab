"""Generated AArch64 archive links, with independently decoded output checks.

Breaks caught: missing architecture dispatch, wrong relocation bitfields/ranges,
lost transitive members, incorrect final section addresses, and unsafe output on
rejected relocations. No fixture is executed.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import subprocess

from archive_link_select_fixtures import ar_member


def object_(symbols, text, data=b"", text_rela=(), data_rela=(), machine=183):
    strings = bytearray(b"\0")
    symtab = bytearray(24)
    indices = {"": 0}
    for name, section, value, binding in symbols:
        indices[name] = len(symtab) // 24
        name_offset = len(strings)
        strings.extend(name.encode() + b"\0")
        symtab.extend(struct.pack("<IBBHQQ", name_offset, binding << 4, 0, section, value, 0))
    shstrings = b"\0.text\0.data\0.strtab\0.symtab\0.rela.text\0.rela.data\0.shstrtab\0"
    out = bytearray(64)
    sections = [(0,) * 10]
    for name, kind, flags, payload, link, info, alignment, stride in [
        (".text", 1, 6, text, 0, 0, 16, 0),
        (".data", 1, 3, data, 0, 0, 16, 0),
        (".strtab", 3, 0, strings, 0, 0, 1, 0),
        (".symtab", 2, 0, symtab, 3, 1, 8, 24),
        (".rela.text", 4, 0, b"".join(struct.pack("<QQq", at, indices[sym] << 32 | typ, add)
                                     for at, typ, sym, add in text_rela), 4, 1, 8, 24),
        (".rela.data", 4, 0, b"".join(struct.pack("<QQq", at, indices[sym] << 32 | typ, add)
                                     for at, typ, sym, add in data_rela), 4, 2, 8, 24),
        (".shstrtab", 3, 0, shstrings, 0, 0, 1, 0),
    ]:
        out.extend(bytes((-len(out)) % alignment))
        offset = len(out)
        out.extend(payload)
        sections.append((shstrings.index(name.encode() + b"\0"), kind, flags, 0,
                         offset, len(payload), link, info, alignment, stride))
    out.extend(bytes((-len(out)) % 8))
    shoff = len(out)
    for section in sections:
        out.extend(struct.pack("<IIQQQQIIQQ", *section))
    out[:16] = b"\x7fELF\2\1\1" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", out, 16, 1, machine, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 8, 7)
    return bytes(out)


def decode(path):
    blob = path.read_bytes()
    assert blob[:7] == b"\x7fELF\2\1\1"
    header = struct.unpack_from("<HHIQQQIHHHHHH", blob, 16)
    assert header[1] == 183, header
    shoff, shnum, shstr = header[5], header[11], header[12]
    rows = [struct.unpack_from("<IIQQQQIIQQ", blob, shoff + 64 * i) for i in range(shnum)]
    names = blob[rows[shstr][4]:rows[shstr][4] + rows[shstr][5]]
    sections = {names[row[0]:].split(b"\0")[0].decode(): row for row in rows}
    payloads = {name: blob[row[4]:row[4] + row[5]] for name, row in sections.items()}
    symbols = {}
    for offset in range(24, len(payloads[".symtab"]), 24):
        name, info, other, section, value, size = struct.unpack_from("<IBBHQQ", payloads[".symtab"], offset)
        name = payloads[".strtab"][name:].split(b"\0")[0].decode()
        symbols[name] = (section, value)
    return header, sections, payloads, symbols


def invoke(cli, *args, error=None):
    result = subprocess.run([str(cli), "archive", *map(str, args)], capture_output=True, text=True, timeout=20)
    if error is None:
        assert result.returncode == 0, (args, result.stdout, result.stderr)
        assert not result.stderr, result.stderr
    else:
        assert result.returncode == 1 and error in result.stderr, (args, result.stdout, result.stderr)
    return result.stdout


def run(cli, artifacts):
    artifacts.mkdir(parents=True, exist_ok=True)
    root_symbols = [("_start", 1, 0, 1), ("target", 0, 0, 1), ("payload", 0, 0, 1), ("constant", 0, 0, 1)]
    words = (0x94000000, 0x14000000, 0x90000009, 0x91000129, 0xF940012A, 0, 0, 0)
    relocs = [(0, 283, "target", 0), (4, 282, "target", 0), (8, 275, "payload", 4096),
              (12, 277, "payload", 0), (16, 286, "payload", 0), (20, 261, "target", 0),
              (24, 260, "payload", 0)]
    data_relocs = [(0, 257, "payload", 8), (8, 258, "constant", -7), (12, 0, "", 0)]
    root = artifacts / "root.o"
    root.write_bytes(object_(root_symbols, struct.pack("<8I", *words), bytes(16), relocs, data_relocs))
    first = object_([("target", 1, 0, 1), ("leaf", 0, 0, 1)], struct.pack("<4I", 0x94000000, 0xD65F03C0, 0, 0),
                    b"FIRST!!!", [(0, 283, "leaf", 0)])
    second = object_([("leaf", 1, 0, 1), ("payload", 2, 0, 1), ("constant", 0xFFF1, 0x12345678, 1)],
                     struct.pack("<2I", 0xD65F03C0, 0), b"SECOND-PAYLOAD!!")
    archive = artifacts / "lib.a"
    archive.write_bytes(b"!<arch>\n" + ar_member("first.o", first) + ar_member("second.o", second))
    selected = invoke(cli, "link-select", archive, "--root-object", root)
    assert "name=first.o triggered-by=target" in selected and "name=second.o" in selected, selected
    for action in ("link", "link-exec"):
        output = artifacts / (action + ".elf")
        output.unlink(missing_ok=True)
        args = [action, archive, "--root-object", root]
        if action == "link-exec":
            args += ["--entry", "_start"]
        invoke(cli, *args, "--output", output)
        header, sections, payloads, symbols = decode(output)
        executable = action == "link-exec"
        if executable:
            blob = output.read_bytes()
            rx = struct.unpack_from("<IIQQQQQQ", blob, header[4])
            rw = struct.unpack_from("<IIQQQQQQ", blob, header[4] + 56)
            assert rx[1] == 5 and rw[1] == 6
            assert rx[7] == rw[7] == 65536, "AArch64 load segments must support 64KiB host pages"
            assert (rx[3] + rx[6] + 65535) // 65536 <= rw[3] // 65536, "RX/RW segments share a page"
            assert rx[2] % 65536 == rx[3] % 65536 and rw[2] % 65536 == rw[3] % 65536
        assert header[0] == (2 if executable else 1)
        assert len(payloads[".text"]) == 56 and len(payloads[".data"]) == 48
        assert symbols["target"] == (1, 0x4000D0 if executable else 32)
        assert symbols["leaf"] == (1, 0x4000E0 if executable else 48)
        assert symbols["payload"] == (2, 0x410020 if executable else 32)
        assert symbols["constant"] == (0xFFF1, 0x12345678)
        expected = (0x94000008, 0x14000007, 0xB0000089 if executable else 0xB0000009,
                    0x91008129, 0xF940112A, 12)
        assert struct.unpack_from("<6I", payloads[".text"]) == expected
        assert struct.unpack_from("<Q", payloads[".text"], 24)[0] == (65368 if executable else 8)
        assert struct.unpack_from("<I", payloads[".text"], 32)[0] == 0x94000004
        assert struct.unpack_from("<QI", payloads[".data"]) == (0x410028 if executable else 40, 0x12345671)
        assert payloads[".data"][16:24] == b"FIRST!!!" and payloads[".data"][32:] == b"SECOND-PAYLOAD!!"
        assert not any(row[1] in (4, 9) for row in sections.values())
        if executable:
            assert header[3] == 0x4000B0
            assert sections[".text"][3:5] == (0x4000B0, 176)
            assert sections[".data"][3:5] == (0x410000, 65536)
    audit = invoke(cli, "link-audit", archive, "--root-object", root)
    assert "unsupported-relocations=0" in audit and "unresolved-relocations=0" in audit, audit

    def rejected(name, blob, error):
        path = artifacts / (name + ".o")
        path.write_bytes(blob)
        output = artifacts / (name + ".elf")
        output.unlink(missing_ok=True)
        invoke(cli, "link", archive, "--root-object", path, "--output", output, error=error)
        assert not output.exists(), "Rejected link created an output"

    for name, typ, addend, offset, error in [
        ("branch-range", 283, 1 << 27, 0, "branch relocation overflows"),
        ("branch-align", 283, 1, 0, "branch target is not instruction aligned"),
        ("field-bound", 257, 0, 28, "relocation field exceeds"),
        ("unsupported", 999, 0, 0, "Unsupported AArch64 ELF relocation type 999"),
        ("page-range", 275, 1 << 33, 8, "page relocation overflows"),
        ("load-align", 286, 1, 16, "load/store target is not 8-byte aligned"),
        ("abs32-range", 258, 1 << 32, 20, "ABS32 relocation overflows"),
        ("prel32-range", 261, 1 << 32, 20, "PREL32 relocation overflows"),
        ("instruction-align", 283, 0, 1, "relocation place is not instruction aligned"),
        ("branch-opcode", 283, 0, 4, "branch relocation has incompatible instruction"),
        ("page-negative-range", 275, -(1 << 32) - 4096, 8, "page relocation overflows"),
        ("add-opcode", 277, 0, 0, "low12 relocation requires unshifted ADD"),
        ("load-opcode", 286, 0, 0, "load/store relocation requires 64-bit"),
        ("abs32-negative-range", 258, -(1 << 31) - 33, 20, "ABS32 relocation overflows"),
    ]:
        rejected(name, object_(root_symbols, struct.pack("<8I", *words), bytes(16),
                               [(offset, typ, "target", addend)]), error)
    rejected("mixed-machine", object_(root_symbols, struct.pack("<8I", *words), machine=62),
             "requires ELF64 little-endian x86-64 ET_REL")
    for name, offset, typ, addend, expected in [
        ("backward-branch", 4, 282, 0, 0x17FFFFFF),
        ("call-negative-bound", 0, 283, -(1 << 27), 0x96000000),
        ("call-positive-bound", 0, 283, (1 << 27) - 4, 0x95FFFFFF),
        ("page-negative-bound", 8, 275, -(1 << 32), 0x90800009),
        ("abs32-negative-bound", 20, 258, -(1 << 31), 0x80000000),
        ("abs32-positive-bound", 20, 258, (1 << 32) - 1, 0xFFFFFFFF),
        ("prel32-negative-bound", 20, 261, -(1 << 31) + 20, 0x80000000),
        ("abs64-negative", 24, 257, -1, 0xFFFFFFFFFFFFFFFF),
        ("prel64-wrap", 24, 260, -(1 << 63), 0x7FFFFFFFFFFFFFE8),
    ]:
        path = artifacts / (name + ".o")
        path.write_bytes(object_([("_start", 1, 0, 1)], struct.pack("<8I", *words), bytes(16),
                                 [(offset, typ, "_start", addend)]))
        output = artifacts / (name + ".elf")
        output.unlink(missing_ok=True)
        invoke(cli, "link", archive, "--root-object", path, "--output", output)
        text = decode(output)[2][".text"]
        assert struct.unpack_from("<Q" if typ in (257, 260) else "<I", text, offset)[0] == expected, name
    print("AArch64 archive selection, ET_REL/ET_EXEC relocations, audit, 15 rejections, and 9 signed/boundary cases passed")


def oracle(cli, artifacts, clang, lld, readobj):
    manifest = json.loads((pathlib.Path(__file__).parent / "fixtures/elf_oracle/tools.json").read_text())
    commands = []

    def command(argv):
        result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=30)
        commands.append({"argv": list(map(str, argv)), "status": result.returncode,
                         "stdout_sha256": hashlib.sha256(result.stdout).hexdigest()})
        assert result.returncode == 0, (argv, result.stderr.decode(errors="replace"))
        return result.stdout

    for key, path in (("clang", clang), ("lld", lld), ("readobj", readobj)):
        assert hashlib.sha256(path.read_bytes()).hexdigest() == manifest["tools"][key], f"Unpinned {key}"
        assert manifest["version"] in command([path, "--version"]).decode()
    sources = {
        "root": """.text
.p2align 4
.globl _start
_start:
bl target
b target
adrp x9, payload+4096
add x9, x9, :lo12:payload
ldr x10, [x9, :lo12:payload]
.word target - .
.xword payload - .
.data
.p2align 4
.xword payload+8
.word constant-7
.word 0
""",
        "first": """.text
.p2align 4
.globl target
target:
bl leaf
ret
.xword 0
.data
.p2align 4
.ascii "FIRST!!!"
""",
        "second": """.text
.p2align 4
.globl leaf
leaf:
ret
.word 0
.globl constant
.set constant, 0x12345678
.data
.p2align 4
.globl payload
payload:
.ascii "SECOND-PAYLOAD!!"
""",
    }
    for name, source in sources.items():
        src = artifacts / ("clang-" + name + ".s")
        src.write_text(source)
        command([clang, "-target", "aarch64-unknown-linux-gnu", "-c", src, "-o", artifacts / ("clang-" + name + ".o")])
    archive = artifacts / "clang-lib.a"
    archive.write_bytes(b"!<arch>\n" + ar_member("first.o", (artifacts / "clang-first.o").read_bytes()) +
                        ar_member("second.o", (artifacts / "clang-second.o").read_bytes()))
    output = artifacts / "clang-linked.elf"
    output.unlink(missing_ok=True)
    invoke(cli, "link-exec", archive, "--root-object", artifacts / "clang-root.o", "--entry", "_start", "--output", output)
    script = artifacts / "layout.ld"
    script.write_text("SECTIONS { .text 0x4000b0 : { *(.text) } .data 0x410000 : { *(.data) } /DISCARD/ : { *(.comment) *(.note*) } }")
    reference = artifacts / "lld-linked.elf"
    command([lld, "--no-relax", "--entry=_start", "-T", script, artifacts / "clang-root.o",
             artifacts / "clang-first.o", artifacts / "clang-second.o", "-o", reference])
    actual, expected = decode(output), decode(reference)
    for section in (".text", ".data"):
        assert actual[1][section][3] == expected[1][section][3]
        assert actual[2][section] == expected[2][section], f"LLD {section} byte mismatch"
    for symbol in ("_start", "target", "leaf", "payload", "constant"):
        assert actual[3][symbol] == expected[3][symbol], f"LLD symbol mismatch: {symbol}"
    assert actual[0][3] == expected[0][3]
    for path, decoded in ((output, actual), (reference, expected)):
        blob = path.read_bytes()
        header = decoded[0]
        programs = [struct.unpack_from("<IIQQQQQQ", blob, header[4] + i * header[8]) for i in range(header[9])]
        loads = [row for row in programs if row[0] == 1]
        assert [row[1] for row in loads] == [5, 6]
        for section, row in zip((".text", ".data"), loads):
            address = decoded[1][section][3]
            size = decoded[1][section][5]
            assert row[3] <= address and address + size <= row[3] + row[6]
            assert row[7] == 65536 and row[2] % row[7] == row[3] % row[7]
        assert (loads[0][3] + loads[0][6] + 65535) // 65536 <= loads[1][3] // 65536
    (artifacts / "llvm-readobj.txt").write_bytes(command([readobj, "--file-headers", "--program-headers", "--sections", "--symbols", output]))
    (artifacts / "llvm-readobj-lld.txt").write_bytes(command([readobj, "--program-headers", reference]))
    (artifacts / "oracle-commands.json").write_text(json.dumps(commands, indent=2))
    print("Pinned clang/LLD AArch64 oracle: identical .text/.data bytes, entry, five symbols; matching segment permissions/alignment/coverage")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", type=pathlib.Path, required=True)
    parser.add_argument("--artifacts", type=pathlib.Path, required=True)
    parser.add_argument("--clang", type=pathlib.Path)
    parser.add_argument("--lld", type=pathlib.Path)
    parser.add_argument("--readobj", type=pathlib.Path)
    args = parser.parse_args()
    run(args.cli, args.artifacts)
    if args.clang or args.lld or args.readobj:
        assert args.clang and args.lld and args.readobj, "All three pinned oracle tools are required"
        oracle(args.cli, args.artifacts, args.clang, args.lld, args.readobj)

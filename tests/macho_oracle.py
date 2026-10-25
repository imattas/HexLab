"""Pinned test-only LLVM comparison. Mach-O inputs are data, never commands."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

COMMANDS = []
ALLOWED = set()
MUTATIONS = set()
ARTIFACTS = None


class Mismatch(RuntimeError):
    pass


def require(ok, label):
    if not ok:
        raise Mismatch(label)


def equal(actual, expected, label):
    require(actual == expected, f"{label}: original={actual!r}; independent={expected!r}")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(argv, output=None, failure=False):
    require(str(Path(argv[0]).resolve()) in ALLOWED, "Attempt to execute an input rather than an allowed tool")
    result = subprocess.run([str(v) for v in argv], capture_output=True, timeout=30)
    COMMANDS.append({"argv": [str(v) for v in argv], "status": result.returncode,
                     "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                     "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()})
    if output:
        Path(str(output) + ".stdout").write_bytes(result.stdout)
        Path(str(output) + ".stderr").write_bytes(result.stderr)
    if not failure:
        require(result.returncode == 0, f"Command failed: {argv}\n{result.stderr.decode(errors='replace')}")
    return result


def verify_tool(path, expected, version):
    require(path.is_file(), f"Missing required oracle tool: {path}")
    equal(digest(path), expected, f"Tool SHA256 {path}")
    observed = run([path, "--version"]).stdout.decode(errors="strict")
    require(version in observed, f"Unexpected tool version: {observed}")
    return {"path": str(path.resolve()), "sha256": expected, "version": observed}


def blocks(text, name):
    """Read named LLVM text blocks, retaining nested text for scalar extraction."""
    found = []
    for match in re.finditer(r"(?m)^\s*" + re.escape(name) + r"\s*\{", text):
        start = match.end()
        depth = 1
        end = start
        while depth and end < len(text):
            depth += (text[end] == "{") - (text[end] == "}")
            end += 1
        require(depth == 0, f"Unterminated LLVM {name} block")
        found.append(text[start:end - 1])
    return found


def number(text, key, default=None, assignment=False):
    separator = r"\s*=\s*" if assignment else r"(?:\s*:\s*|\s+\[\s*)"
    match = re.search(r"(?m)^\s*" + re.escape(key) + separator + r"([^\r\n]+)", text)
    if not match:
        require(default is not None, f"LLVM field missing: {key}\n{text}")
        return default
    value = match.group(1)
    parenthesis = re.search(r"\((-?(?:0x[0-9A-Fa-f]+|\d+))\)", value)
    if parenthesis:
        return int(parenthesis.group(1), 0)
    scalar = re.match(r"-?(?:0x[0-9A-Fa-f]+|\d+)", value)
    require(scalar is not None, f"LLVM scalar missing: {key}: {value}")
    return int(scalar.group(), 0)


def name(text, key):
    match = re.search(r"(?m)^[ \t]*" + re.escape(key) + r":[ \t]*([^\r\n]*)", text)
    require(match is not None, f"LLVM name missing: {key}")
    return match.group(1).split(" (")[0].strip()


def command_blocks(text):
    return re.findall(r"(?ms)^Load command \d+\r?\n(.*?)(?=^Load command \d+\r?$|\Z)", text)


def command_scalar(text, key):
    match = re.search(r"(?m)^\s*" + re.escape(key) + r"\s+(-?(?:0x[0-9A-Fa-f]+|\d+))", text)
    require(match is not None, f"LLVM command field missing: {key}")
    return int(match.group(1), 0)


CMD = {"LC_SEGMENT": 1, "LC_SYMTAB": 2, "LC_DYSYMTAB": 11, "LC_LOAD_DYLIB": 12, "LC_ID_DYLIB": 13,
       "LC_LOAD_DYLINKER": 14, "LC_SEGMENT_64": 25, "LC_UUID": 27, "LC_CODE_SIGNATURE": 29,
       "LC_DYLD_INFO_ONLY": 0x80000022, "LC_VERSION_MIN_MACOSX": 36, "LC_FUNCTION_STARTS": 38,
       "LC_MAIN": 0x80000028, "LC_DATA_IN_CODE": 41, "LC_BUILD_VERSION": 50,
       "LC_DYLD_EXPORTS_TRIE": 0x80000033, "LC_DYLD_CHAINED_FIXUPS": 0x80000034}


def command_type(block):
    match = re.search(r"(?m)^\s*cmd\s+(.*)$", block)
    require(match is not None, "LLVM command name missing")
    text = match.group(1).strip()
    if text in CMD:
        return CMD[text]
    literal = re.search(r"0x[0-9A-Fa-f]+", text)
    require(literal is not None, f"Unmapped LLVM command: {text}")
    return int(literal.group(), 16)


def permissions(text, key):
    value = name(text, key)
    equal(len(value), 3, "LLVM protection field width")
    return sum(bit for letter, bit in zip(value, [1, 2, 4]) if letter != "-")


def compare(actual, readobj, private, dyld, binary, base, order):
    header, = blocks(readobj, "MachHeader")
    wide = "AddressSize: 64bit" in readobj
    caps = re.search(r"(?m)^[ \t]*MH_\S+\s+\S+\s+\S+\s+(\S+)", private)
    require(caps is not None, "LLVM Mach header capability column absent")
    capability = 0x80000000 if caps.group(1) == "LIB64" else int(caps.group(1), 0) << 24
    expected = {"class": 64 if wide else 32, "order": order,
                "cpu": number(header, "CpuType"), "subtype": number(header, "CpuSubType") | capability,
                "type": number(header, "FileType"), "commands": number(header, "NumOfLoadCommands"),
                "command_bytes": number(header, "SizeOfLoadCommands"), "flags": number(header, "Flags"),
                "reserved": number(header, "Reserved", 0)}
    equal(actual["header"], expected, "Mach header")
    commands = command_blocks(private)
    equal(len(commands), expected["commands"], "LLVM command count")
    offset = base + (32 if wide else 28)
    section_sources = []
    for index, (row, command) in enumerate(zip(actual["commands"], commands, strict=True)):
        size = command_scalar(command, "cmdsize")
        equal(row, [index, command_type(command), size, offset], "Command envelope/source")
        if command_type(command) in (1, 25):
            section_sources.extend(offset + (72 if wide else 56) + n * (80 if wide else 68)
                                   for n in range(command_scalar(command, "nsects")))
        offset += size
    equal(offset - base - (32 if wide else 28), expected["command_bytes"], "Command byte total")

    segments = blocks(readobj, "Segment")
    equal(len(actual["segments"]), len(segments), "Segment count")
    for row, segment in zip(actual["segments"], segments, strict=True):
        equal(row["name"], name(segment, "Name"), "Segment name")
        equal(row["fields"], [number(segment, k) for k in ["vmaddr", "vmsize", "fileoff", "filesize"]] +
              [permissions(segment, "maxprot"), permissions(segment, "initprot"), number(segment, "flags"),
               number(segment, "nsects")], "Original segment scalar fields")

    sections = blocks(readobj, "Section")
    equal(len(actual["sections"]), len(sections), "Section count")
    for index, (row, section) in enumerate(zip(actual["sections"], sections, strict=True)):
        equal([row["name"], row["segment"]], [name(section, "Name"), name(section, "Segment")], "Section names")
        fields = [index + 1] + [number(section, k) for k in ["Address", "Size", "Offset", "Alignment", "RelocationOffset", "RelocationCount"]]
        fields += [number(section, "Type") | (number(section, "Attributes") << 8)]
        fields += [number(section, k, 0) for k in ["Reserved1", "Reserved2", "Reserved3"]]
        equal(row["fields"], fields, "Original section scalar fields")
        equal(row["source"], section_sources[index], "Section declaration physical source")

    symbols = blocks(readobj, "Symbol")
    equal(len(actual["symbols"]), len(symbols), "Symbol count")
    symtabs = [c for c in commands if command_type(c) == 2]
    require(len(symtabs) <= 1, "Fixture unexpectedly has multiple symbol tables")
    endian = "<" if order == 1 else ">"
    if symtabs:
        table = symtabs[0]
        symoff, count = command_scalar(table, "symoff"), command_scalar(table, "nsyms")
        equal(count, len(symbols), "LLVM symbol table count")
        for index, (row, symbol) in enumerate(zip(actual["symbols"], symbols, strict=True)):
            source = base + symoff + index * (16 if wide else 12)
            raw = list(struct.unpack_from(endian + ("IBBHQ" if wide else "IBBHI"), binary, source))
            equal(row["fields"], [index, *raw], "Original nlist scalar words at LLVM table offset")
            equal(row["source"], source, "nlist physical source")
            equal(row["name"], name(symbol, "Name"), "LLVM symbol name")
            equal(raw[4], number(symbol, "Value"), "LLVM symbol value")
            equal(raw[2], number(symbol, "Section", 0), "LLVM symbol section")
            equal(raw[1] & 14, number(symbol, "Type") & 14, "LLVM nlist type")
            equal(bool(raw[1] & 1), bool(re.search(r"(?m)^\s*Extern\s*$", symbol)), "LLVM external nlist bit")
            address = None
            if raw[1] & 0xE0 == 0 and raw[1] & 14 == 14:
                address = [raw[2], raw[4] - number(sections[raw[2] - 1], "Address")] if expected["type"] == 1 else [0, raw[4]]
            equal(row["address"], address, "Object section-domain or linked symbol address")

    relocs = blocks(readobj, "Relocation")
    equal(len(actual["relocations"]), len(relocs), "Relocation count")
    for row, reloc in zip(actual["relocations"], relocs, strict=True):
        fields = row["fields"]
        equal(fields[1:5], [number(reloc, k) for k in ["Offset", "Type", "Length", "PCRel"]], "Relocation encoding interpretation")
        if re.search(r"(?m)^\s*Symbol:", reloc):
            equal([fields[5], fields[7]], [1, number(reloc, "Symbol")], "External relocation symbol identity")
        elif re.search(r"(?m)^\s*Section:", reloc):
            equal([fields[5], fields[7]], [0, number(reloc, "Section")], "Internal relocation section identity")
        else:
            equal([fields[6], row["value"]], [1, number(reloc, "Value")], "Scattered relocation value")
        require(row["source_kind"] == 0, "Fixture has unexpected non-section relocations")
        section = sections[row["owner"] - 1]
        source = base + number(section, "RelocationOffset") + fields[0] * 8
        equal(row["source"], source, "Relocation physical source")
        equal(fields[8:10], list(struct.unpack_from(endian + "II", binary, source)), "Literal relocation words at LLVM source")

    dynamic = blocks(readobj, "Dysymtab")
    equal(len(actual["dynamic"]), len(dynamic), "Dynamic-symbol declarations")
    for row, table in zip(actual["dynamic"], dynamic, strict=True):
        equal(row["ranges"], [[number(table, k), number(table, n)] for k, n in
              [("ilocalsym", "nlocalsym"), ("iextdefsym", "nextdefsym"), ("iundefsym", "nundefsym")]], "Dynamic symbol groups")
        for declared, (off, count) in zip(row["tables"], [("tocoff", "ntoc"), ("modtaboff", "nmodtab"),
                ("extrefsymoff", "nextrefsyms"), ("indirectsymoff", "nindirectsyms"), ("extreloff", "nextrel"), ("locreloff", "nlocrel")], strict=True):
            equal(declared[:2], [number(table, off), number(table, count)], "Dysymtab raw table offset/count")
        indirect_offset, count = number(table, "indirectsymoff"), number(table, "nindirectsyms")
        equal(row["indirect"], list(struct.unpack_from(endian + str(count) + "I", binary, base + indirect_offset)) if count else [], "Original indirect symbol entries")

    dice = blocks(readobj, "Entry")
    equal([row[:4] for row in actual["data_in_code"]], [[number(row, k) for k in ["Index", "Offset", "Length", "Kind"]] for row in dice], "Original data-in-code rows")
    for row in actual["data_in_code"]:
        if expected["type"] == 1:
            candidates = [base + number(s, "Offset") + row[1] - number(s, "Address") for s in sections
                          if number(s, "Type") not in (1, 12, 18) and number(s, "Address") <= row[1] and
                          row[1] + row[2] <= number(s, "Address") + number(s, "Size")]
            equal(row[4], candidates[0] if len(candidates) == 1 else None, "Object data-in-code physical backing")

    library_commands = [c for c in commands if command_type(c) in (12, 13)]
    equal(len(actual["libraries"]), len(library_commands), "Library declarations")
    ordinal = 0
    for row, command in zip(actual["libraries"], library_commands, strict=True):
        command_id = command_type(command)
        match = re.search(r"(?m)^\s*name\s+(.*?)\s+\(offset", command)
        require(match is not None, "LLVM library name absent")
        equal(row["name"], match.group(1), "Original library path")
        versions = []
        for key in ["current", "compatibility"]:
            match = re.search(r"(?m)^\s*" + key + r" version\s+(\d+)\.(\d+)\.(\d+)", command)
            require(match is not None, "LLVM library version absent")
            major, minor, patch = map(int, match.groups())
            versions.append(major << 16 | minor << 8 | patch)
        equal(row["fields"], [command_id, command_scalar(command, "time stamp"), *versions], "Library raw command/version scalars")
        if command_id == 12:
            ordinal += 1
        equal(row["ordinal"], ordinal if command_id == 12 else None, "Declared library ordinal")
    compare_dyld(actual, dyld)


def compare_dyld(actual, text):
    ordinals = {Path(r["name"]).stem: r["ordinal"] for r in actual["libraries"] if r["ordinal"] is not None}
    ordinals.update({"flat-namespace": -2, "weak": -3, "main-executable": -1, "this-image": 0})
    exports = []
    match = re.search(r"(?ms)^Exports trie:\r?\n(.*?)(?=^\S[^\r\n]*:\r?$|\Z)", text)
    if match:
        exports = re.findall(r"(?m)^(0x[0-9a-fA-F]+)\s+(\S+)([^\r\n]*)", match.group(1))
    equal(sorted((r["name"], r["address"][1] if r["address"] else None, r["flags"]) for r in actual["exports"]),
          sorted((n, int(v, 16), 4 if "weak_def" in flags else 0) for v, n, flags in exports), "Exports and preferred addresses")
    expected_fixups = []
    for heading, kind in [("Rebase", 0), ("Bind", 1), ("Weak bind", 2), ("Lazy bind", 3)]:
        match = re.search(r"(?ms)^" + heading + r" table:\r?\n(.*?)(?=^\S[^\r\n]*:\r?$|\Z)", text)
        if not match:
            continue
        for line in match.group(1).splitlines():
            parts = line.split()
            if len(parts) < 3 or not parts[2].startswith("0x"):
                continue
            address = int(parts[2], 16)
            symbol = "" if kind == 0 else parts[-1]
            addend = int(parts[4], 0) if kind in (1, 2) else 0
            ordinal = ordinals[parts[5] if kind == 1 else parts[3]] if kind in (1, 3) else None
            field_type = 1 if kind == 3 else {"pointer": 1, "text_abs32": 2, "text_pcrel32": 3}[parts[3]]
            expected_fixups.append((kind, (0, address), field_type, symbol, ordinal, addend))
    equal(sorted((r["kind"], tuple(r["address"]), r["type"], r["symbol"], r["ordinal"], r["addend"]) for r in actual["fixups"]),
          sorted(expected_fixups), "Classic dyld emissions")
    headers = re.findall(r"(?ms)^chained fixups header[^\r\n]*\r?\n(.*?)(?=^chained starts in image|\Z)", text)
    equal(actual["chain_headers"], [[number(b, k, assignment=True) for k in
          ["fixups_version", "starts_offset", "imports_offset", "symbols_offset", "imports_count", "imports_format", "symbols_format"]] for b in headers], "Chained header raw fields")
    starts = re.findall(r"(?ms)^chained starts in segment (\d+)[^\r\n]*\r?\n(.*?)(?=^chained starts in segment|^dyld chained import|^\S[^\r\n]*:\r?$|\Z)", text)
    equal(len(actual["chain_starts"]), len(starts), "Chained starts count")
    for row, (segment, block) in zip(actual["chain_starts"], starts, strict=True):
        equal(row["fields"], [int(segment)] + [number(block, k, assignment=True) for k in
              ["segment_offset", "page_size", "pointer_format", "page_count", "max_valid_pointer"]], "Chained segment starts")
        equal(row["pages"], [int(value, 0) for value in re.findall(r"page_start\[\d+\]\s*=\s*(0x[0-9A-Fa-f]+|\d+)", block)], "Chained page starts")
    imports = re.findall(r"(?ms)^dyld chained import\[(\d+)\]\r?\n(.*?)(?=^dyld chained import|^\S[^\r\n]*:\r?$|\Z)", text)
    equal(len(actual["chain_imports"]), len(imports), "Chained import count")
    for row, (index, block) in zip(actual["chain_imports"], imports, strict=True):
        match = re.search(r"name_offset\s*=\s*\d+\s+\(([^)]*)\)", block)
        require(match is not None, "LLVM chained import name absent")
        equal(row["name"], match.group(1), "Chained import name")
        equal(row["fields"], [int(index), number(block, "lib_ordinal", assignment=True),
              number(block, "weak_import", assignment=True), number(block, "addend", 0, assignment=True)], "Chained import scalars")
    pointers = re.findall(r"(?m)^\S+\s+\S+\s+(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s+(bind|rebase)\s+([^\r\n]*)", text)
    equal(sorted((r["address"][1], r["raw"], bool(r["bind"])) for r in actual["chain_pointers"]),
          sorted((int(address, 16), int(raw, 16), kind == "bind") for address, raw, kind, tail in pointers), "Raw chained pointer words and bind class")
    by_address = {int(address, 16): (kind, tail.split()) for address, raw, kind, tail in pointers}
    bases = [r["fields"][0] for r in actual["segments"] if r["fields"][2] == 0 and r["fields"][3] != 0]
    for row in actual["chain_pointers"]:
        equal(row["address"][0], 0, "Chained pointer address domain")
        require(not row["authenticated"] and not row["non_pointer"], "Fresh fixture unexpectedly requires authenticated/non-pointer interpretation")
        kind, fields = by_address[row["address"][1]]
        if kind == "bind":
            require(row["import"] is not None and row["import"] < len(actual["chain_imports"]), "Chained import association absent")
            imported = actual["chain_imports"][row["import"]]
            equal((imported["name"], imported["fields"][1], row["addend"] + imported["fields"][3]),
                  (fields[-1], ordinals[fields[-2]], int(fields[0], 0)), "Chained symbol/library/addend association")
        else:
            require(row["format"] in (2, 6) and row["target"] is not None, "Unexpected fresh chained rebase format")
            target = row["target"] | row["high8"] << 56
            if row["format"] == 6:
                require(len(bases) == 1, "No unique header-mapped preferred base")
                target += bases[0]
            equal(target, int(fields[-1], 0), "Preferred chained rebase target")


def negative_mutations(actual, compare_args):
    candidates = [("header", lambda v: v["header"].__setitem__("flags", v["header"]["flags"] ^ 1))]
    for field, index in [("segments", 1), ("sections", 2), ("symbols", 5), ("relocations", 2)]:
        if actual[field]:
            candidates.append((field, lambda v, field=field, index=index: v[field][0]["fields"].__setitem__(index, v[field][0]["fields"][index] + 1)))
    if actual["exports"]:
        candidates.append(("exports", lambda v: v["exports"][0].__setitem__("flags", v["exports"][0]["flags"] ^ 4)))
    if actual["fixups"]:
        candidates.append(("fixups", lambda v: v["fixups"][0].__setitem__("addend", v["fixups"][0]["addend"] + 1)))
    if actual["chain_headers"]:
        candidates.append(("chain_headers", lambda v: v["chain_headers"][0].__setitem__(4, v["chain_headers"][0][4] + 1)))
    if actual["chain_pointers"]:
        candidates.append(("chain_pointers", lambda v: v["chain_pointers"][0].__setitem__("raw", v["chain_pointers"][0]["raw"] ^ 1)))
    if actual["chain_imports"]:
        candidates.append(("chain_imports", lambda v: v["chain_imports"][0]["fields"].__setitem__(1, v["chain_imports"][0]["fields"][1] + 1)))
    if actual["chain_starts"]:
        candidates.append(("chain_starts", lambda v: v["chain_starts"][0]["fields"].__setitem__(3, v["chain_starts"][0]["fields"][3] + 1)))
    if actual["libraries"]:
        candidates.append(("libraries", lambda v: v["libraries"][0]["fields"].__setitem__(2, v["libraries"][0]["fields"][2] + 1)))
    for field, mutate in candidates:
        if field in MUTATIONS:
            continue
        changed = copy.deepcopy(actual)
        mutate(changed)
        try:
            compare(changed, *compare_args)
        except Mismatch:
            MUTATIONS.add(field)
        else:
            raise Mismatch(f"Verifier accepted forged semantic {field}")


def inspect(args, path, thin=None, slice_index=None, descriptors=None, order=1):
    source = thin or path
    stem = args.artifacts / ("_".join(path.relative_to(args.artifacts).parts) + (f"-slice{slice_index}" if slice_index is not None else ""))
    readobj = run([args.readobj, "--file-headers", "--sections", "--symbols", "--relocations", "--expand-relocs",
                   "--macho-segment", "--macho-dysymtab", "--macho-data-in-code", source], str(stem) + ".llvm-readobj").stdout.decode()
    private = run([args.objdump, "--macho", "--private-headers", source], str(stem) + ".llvm-private").stdout.decode()
    dyld = run([args.objdump, "--macho", "--dyld-info", "--rebase", "--bind", "--weak-bind", "--lazy-bind",
                "--exports-trie", "--chained-fixups", source], str(stem) + ".llvm-dyld").stdout.decode()
    original = json.loads(run([args.probe, path] + ([slice_index] if slice_index is not None else []), str(stem) + ".original").stdout)
    equal(original["selected"], slice_index if slice_index is not None else 0, "Selected slice identity")
    base = descriptors[slice_index][3] if descriptors else 0
    if descriptors:
        equal(original["slices"], descriptors, "Literal full-width universal descriptors")
        equal(path.read_bytes()[base:base + source.stat().st_size], source.read_bytes(), "Actual selected slice bytes")
    compare_args = (readobj, private, dyld, path.read_bytes(), base, order)
    compare(original, *compare_args)
    negative_mutations(original, compare_args)
    args.inputs.append({"path": str(path), "sha256": digest(path), "bytes": path.stat().st_size, "slice": slice_index,
                        "llvm_source": str(source), "llvm_source_sha256": digest(source),
                        "counts": {k: len(original[k]) for k in ["segments", "sections", "symbols", "relocations", "fixups", "exports", "chain_headers", "chain_pointers"]}})
    return original


def universal(paths, wide, big):
    endian = ">" if big else "<"
    data = bytearray(4096)
    struct.pack_into(endian + "II", data, 0, 0xcafebabf if wide else 0xcafebabe, len(paths))
    rows = []
    for index, path in enumerate(paths):
        payload = path.read_bytes()
        offset = (len(data) + 4095) & ~4095
        data.extend(b"\0" * (offset - len(data)))
        data.extend(payload)
        cpu, subtype = struct.unpack_from("<II", payload, 4)
        rows.append([index, cpu, subtype, offset, len(payload), 12, 0])
        if wide:
            struct.pack_into(endian + "IIQQII", data, 8 + index * 32, cpu, subtype, offset, len(payload), 12, 0)
        else:
            struct.pack_into(endian + "IIIII", data, 8 + index * 20, cpu, subtype, offset, len(payload), 12)
    return data, rows


def main():
    global ARTIFACTS
    parser = argparse.ArgumentParser()
    for argument in ["clang", "readobj", "objdump", "lld", "probe", "sources", "artifacts"]:
        parser.add_argument("--" + argument, type=Path, required=True)
    parser.add_argument("--runtime-dir", type=Path)
    args = parser.parse_args()
    args.artifacts.mkdir(parents=True, exist_ok=True)
    ARTIFACTS = args.artifacts
    (args.artifacts / "report.json").unlink(missing_ok=True)
    (args.artifacts / "failure.json").unlink(missing_ok=True)
    args.inputs = []
    for tool in [args.clang, args.readobj, args.objdump, args.lld, args.probe]:
        ALLOWED.add(str(tool.resolve()))
    pins = json.loads((args.sources / "tools.json").read_text())
    tools = {key: verify_tool(getattr(args, key), value, pins["version"]) for key, value in pins["tools"].items()}
    for bad, expected in [(args.artifacts / "required-tool-is-missing.exe", pins["tools"]["readobj"]),
                          (args.readobj, "0" * 64)]:
        try:
            verify_tool(bad, expected, pins["version"])
        except Mismatch:
            pass
        else:
            raise Mismatch("Missing/mismatched oracle was silently accepted")
    objects = []
    for architecture, target, minimum in [("i386", "i386-apple-darwin", "10.15"),
                                          ("x86_64", "x86_64-apple-darwin", "13.0"),
                                          ("arm64", "arm64-apple-darwin", "13.0")]:
        directory = args.artifacts / architecture
        directory.mkdir(exist_ok=True)
        for name in ["consumer", "provider"]:
            output = directory / (name + ".o")
            run([args.clang, "--target=" + target, "-O0", "-fPIC", "-fno-stack-protector", "-fno-unwind-tables",
                 "-fno-asynchronous-unwind-tables", "-c", args.sources / (name + ".c"), "-o", output])
            inspect(args, output)
            if name == "consumer":
                objects.append(output)
        if architecture == "i386":
            unsupported = run([args.lld, "-arch", "i386", "-dylib", "-platform_version", "macos", minimum, minimum,
                               "-o", directory / "unsupported.dylib", directory / "provider.o"], directory / "unsupported-link", failure=True)
            require(unsupported.returncode != 0 and b"missing or unsupported -arch i386" in unsupported.stderr,
                    "Recheck observed ld64.lld i386 architecture limitation")
            continue
        common = [args.lld, "-arch", architecture, "-platform_version", "macos", minimum, minimum]
        provider = directory / "libprovider.dylib"
        run([*common, "-dylib", "-install_name", "@rpath/libprovider.dylib", "-current_version", "1.2.3", "-compatibility_version", "1.0.0", "-o", provider, directory / "provider.o"])
        inspect(args, provider)
        for chained in [False, True]:
            for executable in [False, True]:
                output = directory / (("executable" if executable else "consumer") + ("-chained" if chained else "-classic") + ".macho")
                options = ["-e", "_entry"] if executable else ["-dylib", "-install_name", "@rpath/libconsumer.dylib"]
                run([*common, *options, "-fixup_chains" if chained else "-no_fixup_chains", "-undefined", "dynamic_lookup",
                     "-o", output, directory / "consumer.o", "-L" + str(directory), "-lprovider"])
                inspect(args, output)
    for wide in [False, True]:
        output = args.artifacts / ("relocations64.o" if wide else "relocations32.o")
        run([args.clang, "--target=" + ("x86_64" if wide else "i386") + "-apple-darwin", "-c",
             args.sources / ("relocations64.s" if wide else "relocations32.s"), "-o", output])
        inspect(args, output)
    guard = args.artifacts / "guard-x64.o"
    run([args.clang, "--target=x86_64-apple-darwin", "-c", args.sources.parent / "macho_guard_x64.s", "-o", guard])
    observed = inspect(args, guard)
    equal(observed["code_exclusions"], [[1, 5, 4]], "Compiler-declared data guard in object section domain")
    for wide in [False, True]:
        for big in [False, True]:
            path = args.artifacts / (f"fat{64 if wide else 32}-" + ("big" if big else "swapped") + ".macho")
            payload, descriptors = universal(objects, wide, big)
            path.write_bytes(payload)
            envelope = run([args.objdump, "--macho", "--universal-headers", path], str(path) + ".llvm-envelope", failure=True)
            if big:
                require(envelope.returncode == 0 and b"Fat headers" in envelope.stdout, "LLVM did not inspect a big-endian universal envelope")
                envelope_text = envelope.stdout.decode()
                equal(command_scalar(envelope_text, "nfat_arch"), len(descriptors), "LLVM universal architecture count")
                require(("FAT_MAGIC_64" in envelope_text) == wide, "LLVM universal class mismatch")
                architectures = re.findall(r"(?ms)^architecture (\S+)\r?\n(.*?)(?=^architecture |\Z)", envelope_text)
                equal(len(architectures), len(descriptors), "LLVM universal descriptor count")
                for row, (architecture, block) in zip(descriptors, architectures, strict=True):
                    cpu, subtype = {"i386": (7, 3), "x86_64": (0x01000007, 3), "arm64": (0x0100000c, 0)}[architecture]
                    align = re.search(r"align\s+2\^(\d+)", block)
                    require(align is not None, "LLVM universal alignment absent")
                    equal(row[1:6], [cpu, subtype, command_scalar(block, "offset"), command_scalar(block, "size"), int(align.group(1))], "LLVM ordered universal descriptor")
            else:
                require(b"is not an object file" in envelope.stdout or envelope.returncode != 0,
                        "Recheck observed LLVM swapped universal-envelope limitation")
            for index, source in enumerate(objects):
                inspect(args, path, source, index, descriptors)
    for wide in [False, True]:
        for big in [False, True]:
            endian = ">" if big else "<"
            header = struct.pack(endian + ("IIIIIIII" if wide else "IIIIIII"),
                0xfeedfacf if wide else 0xfeedface, 0x01000007 if wide else 7, 3, 1, 0, 0, 0, *([0] if wide else []))
            path = args.artifacts / (f"thin{64 if wide else 32}-" + ("big" if big else "little") + ".macho")
            path.write_bytes(header)
            inspect(args, path, order=2 if big else 1)
    partial = args.artifacts / "unknown-command.macho"
    partial.write_bytes(struct.pack("<IIIIIIIIII", 0xfeedfacf, 0x01000007, 3, 1, 1, 8, 0, 0, 0x70000001, 8))
    unknown = inspect(args, partial)
    require(not unknown["complete"] and unknown["diagnostics"], "Unknown command did not retain explicit partial metadata")
    malformed = [("truncated", b"\xcf\xfa\xed")]
    bad_extent = bytearray(objects[1].read_bytes())
    struct.pack_into("<I", bad_extent, 20, 0xffffffff)
    malformed.append(("command-extent", bad_extent))
    bad_size = bytearray(objects[1].read_bytes())
    struct.pack_into("<I", bad_size, 36, 4)
    malformed.append(("command-size", bad_size))
    for label, payload in malformed:
        bad = args.artifacts / (label + ".macho")
        bad.write_bytes(payload)
        for tool, options in [(args.probe, []), (args.readobj, ["--file-headers"])]:
            result = run([tool, *options, bad], str(bad) + "." + tool.stem, failure=True)
            require(result.returncode != 0, f"Malformed {label} was accepted by {tool}")
    equal(MUTATIONS, {"header", "segments", "sections", "symbols", "relocations", "exports", "fixups", "chain_headers", "chain_pointers", "chain_imports", "chain_starts", "libraries"}, "Negative semantic projection coverage")
    sources = sorted(args.sources.glob("*")) + [args.sources.parent / "macho_guard_x64.s",
               args.sources.parent.parent / "macho_oracle_probe.cpp", Path(__file__).resolve()]
    report = {"schema": 1, "status": "passed", "tools": tools, "python": sys.version, "inputs_executed": False,
              "sources": [{"path": str(path), "sha256": digest(path), "bytes": path.stat().st_size} for path in sources if path.is_file()],
              "probe": {"path": str(args.probe.resolve()), "sha256": digest(args.probe), "bytes": args.probe.stat().st_size},
              "runtime": [{"path": str(path), "sha256": digest(path)} for path in sorted((args.runtime_dir or args.probe.parent).glob("hexlab_*.dll"))],
              "commands": COMMANDS, "inputs": args.inputs, "semantic_forgeries_rejected": sorted(MUTATIONS),
              "negative_checks": {"missing_tool": True, "wrong_tool_hash": True, "malformed_original_and_llvm": [label for label, data in malformed], "unknown_command_partial": True},
              "limits": ["LLVM lacks swapped universal-envelope recognition: all selected children still compare against observed LLVM thin inputs; literal descriptor expectations are separate.",
                         "ld64.lld rejects i386 linking; i386 compiler objects and raw relocations remain differential inputs.",
                         "LLVM text output normalizes thin magic; input byte order is additionally asserted from the independent literal/target expectation.",
                         "Metadata/static projections only; no Mach-O input execution, runtime linking, PAC validation or full CPU decoding claim."]}
    (args.artifacts / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS {len(args.inputs)} Mach-O differential inputs; {len(MUTATIONS)} semantic forgeries rejected; missing/mismatched/malformed oracle checks passed")


if __name__ == "__main__":
    try:
        main()
    except (Mismatch, OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError) as error:
        if ARTIFACTS is not None:
            (ARTIFACTS / "failure.json").write_text(json.dumps({"schema": 1, "status": "failed", "error": str(error),
                 "commands": COMMANDS, "inputs_executed": False}, indent=2) + "\n")
        print(f"Mach-O oracle FAILED: {error}", file=sys.stderr)
        sys.exit(1)

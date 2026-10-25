"""Test-only differential oracle. No ELF input is ever an executable command."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

COMMANDS = []
ALLOWED = set()


class Mismatch(RuntimeError):
    pass


def require(ok, message):
    if not ok:
        raise Mismatch(message)


def equal(actual, expected, label):
    require(actual == expected, f"{label}: original={actual!r}, oracle={expected!r}")


def run(command, output=None, accept_failure=False):
    require(str(Path(command[0]).resolve()) in ALLOWED, "Attempt to execute a non-tool input in oracle runner")
    result = subprocess.run([str(arg) for arg in command], capture_output=True, timeout=30)
    COMMANDS.append({"argv": [str(arg) for arg in command], "status": result.returncode,
                     "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                     "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()})
    if output:
        Path(str(output) + ".stdout").write_bytes(result.stdout)
        Path(str(output) + ".stderr").write_bytes(result.stderr)
    if not accept_failure:
        require(result.returncode == 0, f"Command failed {command}: {result.stderr.decode(errors='replace')}")
    return result


def tool(path, digest, version):
    require(path.is_file(), f"Missing required test-only oracle tool: {path}")
    equal(hashlib.sha256(path.read_bytes()).hexdigest(), digest, f"Tool SHA256 {path.name}")
    observed = run([path, "--version"]).stdout.decode()
    require(version in observed, f"Unexpected oracle tool version: {observed}")
    return {"path": str(path), "sha256": digest, "version": observed}


def actual_count(value):
    # LLVM includes the extended carrier after the raw ELF sentinel, e.g. '0 (8)'.
    return int(re.findall(r"0x[0-9a-fA-F]+|\d+", str(value))[-1], 0)


def scalar(value):
    return value["Value"] if isinstance(value, dict) else value


def addend_bits(value, width):
    if width == 32 and 0x80000000 <= value <= 0xFFFFFFFF:
        value -= 1 << 32
    return value & ((1 << 64) - 1)


def virtual_file(programs, address):
    matches = {p[1] + address - p[2] for p in programs if p[0] == 1 and p[2] <= address < p[2] + p[4]}
    require(len(matches) == 1, f"Oracle address has no unique initialized backing: {address:#x}")
    return matches.pop()


def dynamic_entries(text):
    rows = []
    for line in text.splitlines():
        match = re.match(r"\s*(0x[0-9a-fA-F]+)\s+(\S+)\s+(.*)$", line)
        if not match:
            continue
        tag, kind, value = int(match[1], 16), match[2], match[3].strip()
        string = re.search(r"\[(.*)\]", value)
        if tag in (1, 14, 15, 29):
            require(string is not None, f"Oracle dynamic string missing: {line}")
            rows.append((tag, None, string[1]))
        else:
            if kind == "PLTREL":
                number = {"REL": 17, "RELA": 7}[value]
            else:
                token = re.match(r"(?:0x[0-9a-fA-F]+|\d+)", value)
                require(token is not None, f"Unsupported oracle numeric output: {line}")
                number = int(token[0], 0)
            rows.append((tag, number, None))
    return rows


def dynamic_relocations(text):
    rows = []
    for body in re.findall(r"\bRelocation \{(.*?)\}", text, re.S):
        offset = re.search(r"Offset: (0x[0-9a-fA-F]+)", body)
        kind = re.search(r"Type: \S+ \((\d+)\)", body)
        symbol = re.search(r"Symbol: .*?\((\d+)\)", body)
        addend = re.search(r"Addend: (0x[0-9a-fA-F]+)", body)
        require(offset and kind and symbol, f"Unrecognized expanded oracle relocation: {body}")
        rows.append({"offset": int(offset[1], 16), "type": int(kind[1]), "symbol": int(symbol[1]),
                     "rela": addend is not None, "addend": int(addend[1], 16) if addend else None})
    require("Dynamic Relocations {" in text, "Oracle dynamic-relocation output marker missing")
    return rows


def compare(original, oracle, dynamic, dyn_relocs, data):
    h = oracle["ElfHeader"]
    width = 32 if h["Ident"]["Class"]["Value"] == 1 else 64
    header = {"class": width, "order": h["Ident"]["DataEncoding"]["Value"],
              "type": int(re.search(r"0x([0-9a-fA-F]+)", h["Type"])[1], 16),
              "machine": h["Machine"]["Value"], "entry": h["Entry"], "flags": h["Flags"]["Value"],
              "program_offset": h["ProgramHeaderOffset"], "section_offset": h["SectionHeaderOffset"],
              "section_names": actual_count(h["StringTableSectionIndex"])}
    equal(original["header"], header, "ELF header")
    programs = []
    for item in oracle["ProgramHeaders"]:
        p = item["ProgramHeader"]
        programs.append([scalar(p[k]) for k in ("Type", "Offset", "VirtualAddress", "PhysicalAddress", "FileSize", "MemSize", "Flags", "Alignment")])
    equal(original["programs"], programs, "program records")
    equal(len(programs), actual_count(h["ProgramHeaderCount"]), "extended program count")
    sections = []
    for item in oracle["Sections"]:
        s = item["Section"]
        sections.append([s["Index"], s["Name"]["Name"]] + [scalar(s[k]) for k in ("Type", "Flags", "Address", "Offset", "Size", "Link", "Info", "AddressAlignment", "EntrySize")])
    equal(original["sections"], sections, "section records")
    equal(len(sections), actual_count(h["SectionHeaderCount"]), "extended section count")
    equal(len(original["dynamic"]), 1 if dynamic else 0, "dynamic table count")
    if dynamic:
        observed = original["dynamic"][0]["entries"]
        equal(len(observed), len(dynamic), "dynamic entry count")
        for ours, expected in zip(observed, dynamic):
            equal(ours[0], expected[0], "dynamic tag")
            equal(ours[2] if expected[2] is not None else ours[1], expected[2] if expected[2] is not None else expected[1], "dynamic value/string")
    tags = {tag: value for tag, value, _ in dynamic}
    groups = [(s[0], s[5], s[10], oracle["Symbols" if s[2] == 2 else "DynamicSymbols"]) for s in sections if s[2] in (2, 11)]
    require(sum(s[2] == 2 for s in sections) <= 1 and sum(s[2] == 11 for s in sections) <= 1,
            "Fixture has multiple same-kind symbol tables; oracle grouping must be extended explicitly")
    if 6 in tags and not any(s[2] == 11 for s in sections):
        groups.append((None, virtual_file(programs, tags[6]), tags[11], oracle["DynamicSymbols"]))
    equal(len(original["symbol_tables"]), len(groups), "bounded/unbounded symbol table descriptors")
    total_symbols = 0
    for section, file, stride, symbols in groups:
        tables = [t for t in original["symbol_tables"] if t["section"] == section and t["file"] == file]
        equal(len(tables), 1, "symbol table namespace")
        table = tables[0]
        equal(table["stride"], stride, "symbol stride")
        bounded = section is not None or any(tag in tags for tag in (4, 39, 0x6FFFFEF5))
        equal(table["count"], len(symbols) if bounded else None, "symbol count honesty")
        equal(table["address"], None if section is not None else [0, tags[6]], "symbol table virtual namespace")
        ours = [s for s in original["symbols"] if s["section"] == section and s["file"] == file]
        equal(len(ours), len(symbols), "symbol record count")
        total_symbols += len(ours)
        for index, (actual, item) in enumerate(zip(ours, symbols)):
            s = item["Symbol"]
            equal(actual["index"], index, "symbol index")
            # LLVM supplies a display label for unnamed STT_SECTION symbols.
            raw_name = "" if s["Type"]["Value"] == 3 and s["Name"]["Value"] == 0 else s["Name"]["Name"]
            equal(actual["name"], raw_name, "symbol raw name")
            fields = [s["Name"]["Value"], s["Value"], s["Size"], s["Binding"]["Value"], s["Type"]["Value"], s["Other"]["Value"], s["Section"]["Value"]]
            equal(actual["fields"], fields, "symbol value/binding/type/visibility/section")
            defined = fields[6] not in (0, 0xFFF1, 0xFFF2) and fields[4] != 6
            if defined:
                if sections:
                    section = sections[fields[6]]
                    offset = fields[1] if header["type"] == 1 else fields[1] - section[4]
                    defined = bool(section[3] & 2) and 0 <= offset < section[6]
                if header["type"] != 1:
                    defined = defined and any(p[0] == 1 and p[2] <= fields[1] < p[2] + p[5] for p in programs)
            expected_address = [fields[6], fields[1]] if defined and header["type"] == 1 else [0, fields[1]] if defined else None
            equal(actual["address"], expected_address, "symbol domain/address honesty")
    equal(len(original["symbols"]), total_symbols, "no extra inferred symbols")
    expected_relocations = []
    for table in oracle["Relocations"]:
        section = table["SectionIndex"]
        target = sections[section][8]
        matches = [t for t in original["relocation_tables"] if t["section"] == section]
        equal(len(matches), 1, "section relocation table identity")
        descriptor = matches[0]
        equal(descriptor["target_section"], target if target else None, "declared relocation target section")
        equal(descriptor["symbol_table"]["section"], sections[section][7], "relocation symbol namespace")
        equal(len(descriptor["rows"]), len(table["Relocs"]), "relocation row count")
        for index, item in enumerate(table["Relocs"]):
            r = item["Relocation"]
            expected = {"offset": r["Offset"], "type": r["Type"]["Value"], "symbol": r["Symbol"]["Value"],
                        "rela": "Addend" in r, "addend": r.get("Addend")}
            actual = original["relocations"][descriptor["rows"][index]]
            compare_relocation(actual, expected, header, sections, programs, data, target or None)
            expected_relocations.append(descriptor["rows"][index])
    equal(len(original["dynamic_rows"]), len(dyn_relocs), "dynamic relocation count")
    for index, expected in zip(original["dynamic_rows"], dyn_relocs):
        compare_relocation(original["relocations"][index], expected, header, sections, programs, data, None)
        expected_relocations.append(index)
    equal(set(expected_relocations), set(range(len(original["relocations"]))), "no unverified/invented relocation rows")


def compare_relocation(actual, expected, header, sections, programs, data, target):
    for field in ("offset", "type", "symbol", "rela"):
        equal(actual[field], expected[field], f"relocation {field}")
    offset = expected["offset"]
    if header["type"] == 1 or (target is not None and not sections[target][3] & 2):
        place = [target, offset] if sections[target][3] & 2 else None
        file = sections[target][5] + offset
    else:
        place, file = [0, offset], virtual_file(programs, offset)
    equal(actual["place"], place, "relocation place domain")
    equal(actual["file_place"], file, "canonical relocation field backing")
    known_widths = {3: {1: 4, 2: 4, 3: 4, 4: 4, 6: 4, 7: 4, 8: 4, 9: 4, 10: 4},
                    62: {1: 8, 2: 4, 4: 4, 6: 8, 7: 8, 8: 8, 9: 4, 10: 4, 11: 4}}
    width = known_widths.get(header["machine"], {}).get(expected["type"])
    if width:
        equal(actual["width"], width, "psABI relocation field width")
    if expected["rela"]:
        equal(actual["addend_bits"], addend_bits(expected["addend"], header["class"]), "signed explicit addend")
    elif header["type"] != 1 and target is not None:
        equal(actual["addend_bits"], None, "retained linked field is not an original implicit addend")
    elif expected["type"] in (6, 7):
        # GLOB_DAT/JUMP_SLOT use S; the lazy pointer contents are not A.
        equal(actual["addend_bits"], None, "no invented implicit addend for runtime symbol slot")
    elif width:
        raw = data[file:file + width]
        equal(len(raw), width, "initialized implicit field extent")
        equal(actual["addend_bits"], int.from_bytes(raw, "little" if header["order"] == 1 else "big", signed=True) & ((1 << 64) - 1), "original implicit addend bytes")


def inspect(args, path, baseline=None):
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    output = args.artifacts / (str(len(args.observed)) + "-" + path.parent.name + "-" + path.name.replace(".", "-"))
    native = run([args.probe, path], output.with_suffix(".original"))
    actual = json.loads(native.stdout)
    llvm = run([args.readobj, "--elf-output-style=JSON", "--file-headers", "--program-headers", "--sections", "--symbols", "--dyn-symbols", "--relocations", path], output.with_suffix(".llvm-json"))
    oracle = json.loads(llvm.stdout)[0]
    dyn = run([args.readobj, "--dynamic-table", path], output.with_suffix(".llvm-dynamic"))
    rel = run([args.readobj, "--expand-relocs", "--dyn-relocations", path], output.with_suffix(".llvm-dynrel"))
    entries, relocations = dynamic_entries(dyn.stdout.decode()), dynamic_relocations(rel.stdout.decode())
    symbol_comparison = "direct observed LLVM JSON"
    tags = {tag: value for tag, value, _ in entries}
    if baseline and not oracle["Sections"] and not oracle["DynamicSymbols"] and 0x6FFFFEF5 in tags and 4 not in tags:
        source, original_oracle, original_entries = baseline
        equal(path.read_bytes(), without_section_headers(source.read_bytes()), "GNU-only oracle baseline permits ONLY section-header field removal")
        equal(entries, original_entries, "unchanged GNU-only dynamic entries")
        tables = [s["Section"] for s in original_oracle["Sections"] if s["Section"]["Type"]["Value"] == 11]
        equal(len(tables), 1, "GNU-only original independently inspected DYNSYM source")
        mapped = [[scalar(p["ProgramHeader"][k]) for k in ("Type", "Offset", "VirtualAddress", "PhysicalAddress", "FileSize", "MemSize", "Flags", "Alignment")] for p in oracle["ProgramHeaders"]]
        equal(virtual_file(mapped, tags[6]), tables[0]["Offset"], "unchanged GNU-only symbol table physical backing")
        require(original_oracle["DynamicSymbols"], "GNU-only independent baseline has no symbol facts")
        oracle["DynamicSymbols"] = original_oracle["DynamicSymbols"]
        symbol_comparison = "LLVM original DYNSYM JSON plus verified header-only section removal; observed GNU-only sectionless array is empty"
    compare(actual, oracle, entries, relocations, path.read_bytes())
    equal(hashlib.sha256(path.read_bytes()).hexdigest(), before, "inspection preserves original ELF bytes")
    args.observed.append({"file": str(path), "sha256": before, "symbols": len(actual["symbols"]), "relocations": len(actual["relocations"]), "symbol_comparison": symbol_comparison})
    print(f"PASS {path.name}: {len(actual['symbols'])} symbols, {len(actual['relocations'])} relocations", flush=True)
    return actual, oracle, entries, relocations


def without_section_headers(original):
    data = bytearray(original)
    wide = data[4] == 2
    for begin, length in ((40 if wide else 32, 8 if wide else 4), (58 if wide else 46, 6)):
        data[begin:begin + length] = bytes(length)
    return bytes(data)


def sectionless(source, output):
    output.write_bytes(without_section_headers(source.read_bytes()))


def main():
    parser = argparse.ArgumentParser()
    for name in ("clang", "lld", "readobj", "probe", "generator", "sources", "artifacts"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    ALLOWED.update(str(getattr(args, name).resolve()) for name in ("clang", "lld", "readobj", "probe", "generator"))
    args.artifacts.mkdir(parents=True, exist_ok=True)
    args.observed = []
    manifest = json.loads((args.sources / "tools.json").read_text())
    tools = {name: tool(getattr(args, name), digest, manifest["version"]) for name, digest in manifest["tools"].items()}
    # A missing required tool must be an explicit failure, never a skip/fallback.
    try:
        tool(args.artifacts / "required-missing-oracle.exe", "0" * 64, manifest["version"])
    except Mismatch as error:
        require("Missing required" in str(error), "Missing-tool failure did not identify the tool")
    else:
        raise Mismatch("Missing-tool contract accepted an absent oracle")
    authored = args.artifacts / "authored"
    run([args.generator, authored])
    for name in ("object32.o", "object64.o", "shared32.so", "shared64.so", "exec32.elf", "exec64.elf", "big64.elf", "unbounded64.so"):
        inspect(args, authored / name)
    data = bytearray((authored / "object64.o").read_bytes())
    data[60:64] = b"\x00\x00\xff\xff"
    data[544:552] = (8).to_bytes(8, "little")
    data[552:556] = (4).to_bytes(4, "little")
    extended = authored / "extended64.o"
    extended.write_bytes(data)
    inspect(args, extended)
    for tool_path, options in ((args.probe, []), (args.readobj, ["--file-headers"])):
        bad = run([tool_path, *options, authored / "bad.elf"], accept_failure=True)
        require(bad.returncode != 0, "Malformed ELF was accepted by original loader or independent oracle")
    mutations = 0
    for architecture in ("i386", "x86_64"):
        directory = args.artifacts / architecture
        directory.mkdir(exist_ok=True)
        for source in ("consumer", "provider"):
            run([args.clang, "--target=" + architecture + "-unknown-linux-gnu", "-O0", "-fPIC", "-fno-asynchronous-unwind-tables", "-fno-stack-protector", "-c", args.sources / (source + ".c"), "-o", directory / (source + ".o")])
            result = inspect(args, directory / (source + ".o"))
            if source == "consumer":
                original, oracle, entries, relocations = result
                require(any(r["unresolved"] and not r["external"] and any(o["name"] == "external_call" and o["type"] == 4 for o in r["origins"]) for r in original["control_origins"]), "Compiler external CALL lost original ELF provenance or acquired a guessed library")
                for field in ("header", "symbols", "relocations"):
                    mutated = copy.deepcopy(original)
                    if field == "header":
                        mutated[field]["machine"] += 1
                    elif field == "symbols":
                        mutated[field][1]["fields"][1] += 1
                    else:
                        mutated[field][0]["type"] += 1
                    try:
                        compare(mutated, oracle, entries, relocations, (directory / "consumer.o").read_bytes())
                    except Mismatch:
                        mutations += 1
                    else:
                        raise Mismatch(f"Differential verifier accepted forged {field}")
        machine = "elf_i386" if architecture == "i386" else "elf_x86_64"
        run([args.lld, "-m", machine, "-shared", "-soname", "libprovider.so", "-o", directory / "libprovider.so", directory / "provider.o"])
        inspect(args, directory / "libprovider.so")
        for style in ("both", "gnu", "sysv"):
            linked = directory / ("consumer-" + style + ".so")
            run([args.lld, "-m", machine, "-shared", "--hash-style=" + style, "--rpath=$ORIGIN", "-o", linked, directory / "consumer.o", "-L" + str(directory), "-lprovider"])
            linked_result = inspect(args, linked)
            original = linked_result[0]
            stripped = directory / ("consumer-" + style + "-sectionless.so")
            sectionless(linked, stripped)
            without_sections = inspect(args, stripped, (linked, linked_result[1], linked_result[2]))[0]
            dynamic_symbols = [s for s in original["symbols"] if s["section"] is not None and original["sections"][s["section"]][2] == 11]
            equal([(s["name"], s["fields"]) for s in without_sections["symbols"]], [(s["name"], s["fields"]) for s in dynamic_symbols], "independent sectionless dynamic symbols")
        executable = directory / "consumer.exec"
        run([args.lld, "-m", machine, "--hash-style=both", "--rpath=$ORIGIN", "-e", "exported_function", "-o", executable, directory / "consumer.o", "-L" + str(directory), "-lprovider"])
        inspect(args, executable)
        debug_object = directory / "retained-debug.o"
        run([args.clang, "--target=" + architecture + "-unknown-linux-gnu", "-g", "-O0", "-fPIC",
             "-fno-stack-protector", "-c", args.sources / "retained.c", "-o", debug_object])
        for shared in (False, True):
            baseline = None
            for retained in (False, True):
                output = directory / ("debug" + (".so" if shared else ".exec") + ("-retained" if retained else ""))
                options = (["-shared"] if shared else ["-e", "_start"])
                if retained:
                    options += ["--emit-relocs"]
                run([args.lld, "-m", machine, *options, debug_object, "-o", output])
                observed = inspect(args, output)[0]
                if baseline is None:
                    baseline = observed
                else:
                    equal(observed["functions"], baseline["functions"],
                          "retained debug/static relocation records preserve linked recovery")
    many_source = args.artifacts / "many-sections.c"
    many_source.write_text("\n".join("void f%d(void){}" % i for i in range(4100)))
    many_object = args.artifacts / "many-sections.o"
    run([args.clang, "--target=x86_64-unknown-linux-gnu", "-ffunction-sections",
         "-fno-asynchronous-unwind-tables", "-c", many_source, "-o", many_object])
    many = inspect(args, many_object)[0]
    equal(len(many["functions"]), 4100, "compiler function-section recovery exceeds old domain cap")
    equal(mutations, 6, "negative semantic mutation checks")
    report = {"schema": 1, "tools": tools, "python": sys.version, "inputs_executed": False, "commands": COMMANDS, "inputs": args.observed,
              "negative_checks": {"missing_tool": True, "malformed_original_and_oracle": True, "forged_semantic_records": mutations}}
    (args.artifacts / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS {len(args.observed)} ELF differential inputs; 6 semantic forgeries rejected; malformed/missing oracle rejected")


if __name__ == "__main__":
    try:
        main()
    except (Mismatch, ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print(f"ELF oracle FAILED: {error}", file=sys.stderr)
        sys.exit(1)

"""Test-only compiler/disassembler comparison. Never executes the ARM input."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def normalized(text):
    text = re.sub(r"<[^>]*>|//.*|@.*", "", text).replace("#", "").strip()
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"(?<![a-zA-Z0-9_])(-?(?:0x[0-9a-f]+|[0-9]+))\b",
                  lambda match: str(int(match.group(), 0)), text)
    if text.startswith(("add ", "adds ", "sub ", "subs ")):
        text = re.sub(r"(?<![a-zA-Z0-9_])(-?\d+),\s*lsl\s+(\d+)$",
                      lambda match: str(int(match[1]) << int(match[2])), text)
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"\s*,\s*", ",", text)
    # Exact observed spellings only: three A64 and nine A32 projections.
    aliases = {"nop": "hint 0", "movz x0,4660": "mov x0,4660", "movn w2,0": "mov w2,-1",
        "mov r0,-16777216": "mov r0,4278190080", "movs r0,-16777216": "movs r0,4278190080",
        "lsls r0,r1,r2": "movs r0,r1,lsl r2", "lsr r0,r1,32": "mov r0,r1,lsr 32",
        "asr r0,r1,32": "mov r0,r1,asr 32", "rrx r0,r1": "mov r0,r1,rrx",
        "push {r4,lr}": "stmdb sp!,{r4,lr}", "pop {r4,pc}": "ldmia sp!,{r4,pc}",
        "stm r1,{r0,r2}": "stmia r1,{r0,r2}"}
    return aliases.get(text, text)


def main():
    p = argparse.ArgumentParser()
    for name in ("clang", "objdump", "probe", "source", "tools", "artifacts"):
        p.add_argument("--" + name, required=True, type=Path)
    p.add_argument("--architecture", choices=("a64", "a32", "thumb"), default="a64")
    p.add_argument("--projections", type=int)
    args = p.parse_args()
    args.artifacts.mkdir(parents=True, exist_ok=True)
    report_path = args.artifacts / "report.json"
    report_path.unlink(missing_ok=True)
    commands = []

    def run(argv, input_text=None):
        result = subprocess.run([str(x) for x in argv], input=input_text, text=True, capture_output=True, timeout=30)
        commands.append({"argv": [str(x) for x in argv], "stdin": input_text, "exit": result.returncode,
                         "stdout": result.stdout, "stderr": result.stderr})
        if result.returncode:
            raise RuntimeError(result.stderr or "required tool failed")
        return result.stdout

    try:
        pins = json.loads(args.tools.read_text())["tools"]
        for name in ("clang", "objdump"):
            if digest(getattr(args, name)) != pins[name]:
                raise RuntimeError("missing/mismatched required tool: " + name)
        obj = args.artifacts / "scalar.o"
        target = "aarch64-none-elf" if args.architecture == "a64" else "armv7-none-eabi"
        run([args.clang, "-target", target, "-c", args.source, "-o", obj])
        disassembler_options = ["--disassembler-options=no-aliases"] if args.architecture == "a64" else []
        llvm = run([args.objdump, "-d", *disassembler_options, obj])
        (args.artifacts / "llvm.txt").write_text(llvm)
        if args.architecture == "thumb":
            records = [(int(m[1],16), int(m[2],16) | (int(m[3],16)<<16 if m[3] else 0), m[4], 4 if m[3] else 2) for m in
                       re.finditer(r"^\s*([0-9a-f]+):\s+([0-9a-f]{4})(?:\s+([0-9a-f]{4}))?\s+(.+)$",llvm,re.M)]
        else:
            records = [(int(m[1], 16), int(m[2], 16), m[3],4) for m in
                       re.finditer(r"^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(.+)$", llvm, re.M)]
        expected_count = args.projections if args.projections is not None else (27 if args.architecture == "a64" else 15)
        if not 1 <= expected_count <= 4096 or len(records) != expected_count:
            raise RuntimeError("compiler/disassembler instruction count changed")
        output = run([args.probe], "".join(f"{at:x} {word:x}" + (f" {size:x}" if args.architecture=="thumb" else "")+"\n" for at, word, _,size in records))
        (args.artifacts / "hexlab.txt").write_text(output)
        actual = [line.split("\t", 2) for line in output.splitlines()]
        if len(actual) != len(records):
            raise RuntimeError("decoder projection count differs")
        def projection(text,at,expected=False):
            text=normalized(text)
            if args.architecture=="thumb":
                text=re.sub(r"^([a-z]+)\.w\b",r"\1",text)
                if expected and text.startswith("adr "):
                    head,offset=text.rsplit(",",1)
                    text=head+","+str(((at+4)&~3)+int(offset))
            return text
        for (at, word, expected,size), got in zip(records, actual):
            if int(got[0], 16) != at or int(got[1], 16) != word or projection(got[2],at) != projection(expected,at,True):
                raise RuntimeError(f"projection mismatch at {at:x}: {got} versus {expected}")
        if normalized(actual[0][2].replace("0x8", "0xc")) == normalized(records[0][2]):
            raise RuntimeError("semantic mutation was not rejected")
        if normalized("add r0, r1, r2, lsl 2") == normalized("add r0, r1, r8"):
            raise RuntimeError("register/shift mutation was not rejected")
        identities = [{"path": str(path.resolve()), "sha256": digest(path)} for path in
                      (args.clang, args.objdump, args.probe, args.source, args.tools, Path(__file__), obj,
                       args.probe.parent / "hexlab_core.dll", args.probe.parent / "hexlab_processors.dll")]
        report_path.write_text(json.dumps({"status": "passed", "projections": len(records),
            "inputs_executed": False, "identities": identities, "commands": commands,
            "architecture": args.architecture,
            "limits": "Unlinked object word/text comparison; relocation operands reflect raw encodings, not linked targets. Three exact A64 and nine exact A32 spellings. Thumb probe carries explicit IT state, checks narrow/wide lengths, and projects ADR offsets to aligned PC+4 targets; .w is an encoding-width spelling. Typed effects tested separately. No CPU execution."}, indent=2))
        print(f"PASS {len(records)} compiler {args.architecture} words/text projections; changed branch target rejected")
    except Exception as error:
        (args.artifacts / "failure.json").write_text(json.dumps({"error": str(error), "commands": commands}, indent=2))
        raise


if __name__ == "__main__":
    main()

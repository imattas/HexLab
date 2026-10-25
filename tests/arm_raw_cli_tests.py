import argparse
import hashlib
import json
import subprocess
import uuid
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    args.artifacts.mkdir(parents=True, exist_ok=True)
    stem = args.artifacts / uuid.uuid4().hex
    binary = stem.with_suffix(".bin")
    profile = stem.with_suffix(".profile")
    project = stem.with_suffix(".hxproj")
    binary.write_bytes(bytes.fromhex("0000a0e11eff2fe100bf704711223344"))
    profile.write_text("hexlab-arm-profile 1\nbase 7 0x1000\npermissions r-x\nentry 0x1008 thumb-clear\n"
                       "ranges 3\nrange 0x1000 0x8 a32\nrange 0x1008 0x4 thumb\nrange 0x100c 0x4 data\n", encoding="utf8")
    original = hashlib.sha256(binary.read_bytes()).hexdigest()
    commands = []

    def check(status, expected, *arguments):
        command = [str(args.cli), *map(str, arguments)]
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf8", errors="strict", timeout=20)
        commands.append({"command": command, "status": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        if result.returncode != status or expected not in result.stdout + result.stderr:
            raise RuntimeError(f"CLI expectation {status}/{expected}: {commands[-1]}")

    try:
        check(0, "ARM profile: ranges=3 roots=1", "inspect", binary, "--format", "raw", "--arm-profile", profile)
        check(2, "profile", "inspect", binary, "--format", "raw", "--arm-profile", profile, "--base", "0x1000")
        check(2, "profile", "inspect", binary, "--format", "raw", "--arm-profile", profile, "--profile", profile)
        check(2, "raw", "inspect", binary, "--arm-profile", profile)
        check(0, "Saved:", "project", "create", project, "--input", binary, "--format", "raw", "--arm-profile", profile)
        check(0, "ARM profile: ranges=3 roots=1", "project", "inspect", project)
        check(0, "Edit revision: 1", "project", "rename", project, "--at", "va:7:0x1008", "--name", "thumb_entry")
        if hashlib.sha256(binary.read_bytes()).hexdigest() != original:
            raise RuntimeError("CLI mutated original raw input")
        binary.unlink()
        profile.unlink()
        check(0, "thumb_entry", "project", "inspect", project, "--readonly")
        check(0, "mode=thumb", "project", "inspect", project, "--readonly")
        (args.artifacts / "report.json").write_text(json.dumps({"status": "passed", "commands": commands,
            "inputs_executed": False, "input_sha256": original}, indent=2), encoding="utf8")
        print(f"PASS {len(commands)} ARM-profile CLI checks including source/profile-missing readonly reopen")
    except Exception:
        (args.artifacts / "failure.json").write_text(json.dumps({"commands": commands}, indent=2), encoding="utf8")
        raise
    finally:
        for path in (binary, profile, project, Path(str(project) + "-wal"), Path(str(project) + "-shm")):
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()


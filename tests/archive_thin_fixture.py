#!/usr/bin/env python3
"""Create a small GNU thin archive and its external member for CLI tests."""
import argparse
from pathlib import Path


def ar_header(name: str, size: int) -> bytes:
    fields = (
        name.ljust(16), "0".ljust(12), "0".ljust(6), "0".ljust(6),
        "100644".ljust(8), str(size).ljust(10), "`\n",
    )
    header = "".join(fields).encode("ascii")
    if len(header) != 60:
        raise ValueError("invalid ar header width")
    return header


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    root = args.directory / "root"
    root.mkdir(parents=True, exist_ok=True)
    payload = b"thin member\n"
    (root / "member.o").write_bytes(payload)
    archive = b"!<thin>\n" + ar_header("member.o/", len(payload))
    args.directory.mkdir(parents=True, exist_ok=True)
    (args.directory / "libthin.a").write_bytes(archive)


if __name__ == "__main__":
    main()

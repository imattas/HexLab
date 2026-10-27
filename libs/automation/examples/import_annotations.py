"""Import a bounded JSON batch of project names, comments, and bookmarks.

Usage: hexlab_python import_annotations.py project.hxproj annotations.json
Manifest format: [{"location":{"va":{"space":0,"offset":"0x401000"}},"name":"entry","comment":"checked","bookmark":"review"}]
A file-offset location is {"location":{"file_offset":"0x20"}}. Set bookmark to null to remove one.
"""
import argparse
import json
from pathlib import Path
import hexlab

MAX_MANIFEST_BYTES = 16 * 1024 * 1024


def number(value, field):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(field + " must be an integer or base-prefixed integer string")
    return int(value, 0) if isinstance(value, str) else value


def location(value):
    if not isinstance(value, dict) or len(value) != 1:
        raise ValueError("location must contain exactly one of va or file_offset")
    if "va" in value:
        va = value["va"]
        if not isinstance(va, dict) or set(va) != {"space", "offset"}:
            raise ValueError("va location must contain space and offset")
        return hexlab.Address(number(va["space"], "space"), number(va["offset"], "offset"))
    if "file_offset" in value:
        return hexlab.FileOffset(number(value["file_offset"], "file_offset"))
    raise ValueError("location must contain exactly one of va or file_offset")


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("project")
parser.add_argument("manifest")
parser.add_argument("--group", type=int, default=0, help="persistent undo group")
args = parser.parse_args()
manifest_path = Path(args.manifest)
size = manifest_path.stat().st_size
if size > MAX_MANIFEST_BYTES:
    parser.error("manifest exceeds 16 MiB")
with manifest_path.open("rb") as source:
    encoded = source.read(MAX_MANIFEST_BYTES + 1)
if len(encoded) > MAX_MANIFEST_BYTES:
    parser.error("manifest grew beyond 16 MiB while reading")
try:
    document = json.loads(encoded.decode("utf-8"))
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    parser.error("invalid UTF-8 JSON manifest: " + str(error))
if not isinstance(document, list) or len(document) > 4096:
    parser.error("manifest must be an array with at most 4096 rows")
rows = []
names_by_space = {}
for index, item in enumerate(document):
    if not isinstance(item, dict) or "location" not in item:
        parser.error(f"row {index} must be an object with location")
    row = {key: item[key] for key in ("name", "comment", "bookmark") if key in item}
    row["location"] = location(item["location"])
    if isinstance(row.get("name"), str) and row["name"]:
        address = row["location"]
        if isinstance(address, hexlab.Address):
            key = (address.space, row["name"])
            previous = names_by_space.get(key)
            if previous is not None and previous[0] != address.offset:
                parser.error(
                    f"name conflict '{row['name']}' in address space {address.space}: "
                    f"rows {previous[1]} and {index} target different addresses"
                )
            names_by_space[key] = (address.offset, index)
    rows.append(row)
with hexlab.Project.open(args.project, readonly=False) as project:
    revision = project.snapshot()["edit_revision"]
    updated = project.apply_annotations(rows, group=args.group, expected_revision=revision)
    project.save()
    print("applied", len(rows), "rows; edit revision", updated["edit_revision"], "history cursor", updated["history_cursor"])

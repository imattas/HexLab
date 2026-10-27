"""Import a bounded JSON batch of project names, comments, and bookmarks.

Usage: hexlab_python import_annotations.py project.hxproj annotations.json [--merge replace|preserve]
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
parser.add_argument("--merge", choices=("replace", "preserve"), default="replace",
                    help="replace existing fields (default) or preserve them and fill blanks")
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
manifest_row_count = 0
names_by_space = {}
fields_by_location = {}
conflicts = []
for index, item in enumerate(document):
    manifest_row_count += 1
    if not isinstance(item, dict) or "location" not in item:
        parser.error(f"row {index} must be an object with location")
    row = {key: item[key] for key in ("name", "comment", "bookmark") if key in item}
    row["location"] = location(item["location"])
    address = row["location"]
    location_key = (("va", address.space, address.offset) if isinstance(address, hexlab.Address)
                    else ("file_offset", address.offset))
    for field, value in row.items():
        if field == "location":
            continue
        key = (location_key, field)
        previous = fields_by_location.get(key)
        if previous is not None and previous[0] != value:
            conflicts.append(
                f"{field} conflict at {location_key}: rows {previous[1]} and {index} "
                f"specify different values"
            )
        fields_by_location[key] = (value, index)
    if isinstance(row.get("name"), str) and row["name"]:
        if isinstance(address, hexlab.Address):
            key = (address.space, row["name"])
            previous = names_by_space.get(key)
            if previous is not None and previous[0] != address.offset:
                conflicts.append(
                    f"name conflict '{row['name']}' in address space {address.space}: "
                    f"rows {previous[1]} and {index} target different addresses"
                )
            names_by_space[key] = (address.offset, index)
    rows.append(row)
if conflicts:
    parser.error("manifest contains conflicting edits: " + "; ".join(conflicts))


def existing_location_key(value):
    # Project snapshots use compact tagged tuples; manifests use dictionaries.
    if isinstance(value, tuple) and len(value) == 3 and value[0] == "va":
        return ("va", value[1], value[2])
    if isinstance(value, tuple) and len(value) == 2 and value[0] == "file":
        return ("file_offset", value[1])
    raise ValueError("project snapshot contains an unsupported annotation location")


with hexlab.Project.open(args.project, readonly=False) as project:
    snapshot = project.snapshot()
    revision = snapshot["edit_revision"]
    skipped_fields = 0
    if args.merge == "preserve":
        annotations = snapshot["annotations"]
        bookmarks = snapshot["bookmarks"]
        # The preview is deliberately bounded. Never infer that a field is
        # absent when the project snapshot was truncated.
        if (snapshot["annotation_count"] > len(annotations) or
                snapshot["bookmark_count"] > len(bookmarks)):
            parser.error("--merge preserve requires at most 4096 existing annotations and bookmarks")
        current_annotations = {}
        current_bookmarks = set()
        names_in_project = {}
        for current in annotations:
            key = existing_location_key(current["location"])
            current_annotations[key] = current
            if key[0] == "va" and current["name"]:
                names_in_project[(key[1], current["name"])] = key
        for current in bookmarks:
            current_bookmarks.add(existing_location_key(current["location"]))

        merged_rows = []
        for row in rows:
            address = row["location"]
            key = (("va", address.space, address.offset) if isinstance(address, hexlab.Address)
                   else ("file_offset", address.offset))
            current = current_annotations.get(key, {})
            merged = {"location": address}
            for field in ("name", "comment", "bookmark"):
                if field not in row:
                    continue
                value = row[field]
                has_current = (key in current_bookmarks if field == "bookmark"
                               else bool(current.get(field)))
                if has_current:
                    skipped_fields += 1
                    continue
                if field == "name" and value:
                    old_location = names_in_project.get((address.space, value))
                    if old_location is not None and old_location != key:
                        skipped_fields += 1
                        continue
                if field in ("name", "comment") and value == "":
                    skipped_fields += 1
                    continue
                # A missing bookmark has nothing to remove; omit it so the
                # projected batch contains only real additions.
                if field == "bookmark" and value is None:
                    skipped_fields += 1
                    continue
                merged[field] = value
            if len(merged) > 1:
                merged_rows.append(merged)
        rows = merged_rows
        if not rows:
            print("no annotation changes; skipped", skipped_fields, "fields")
            raise SystemExit(0)

    updated = project.apply_annotations(rows, group=args.group, expected_revision=revision)
    project.save()
    print("applied", len(rows), "of", manifest_row_count, "rows; skipped", skipped_fields,
          "fields; edit revision", updated["edit_revision"], "history cursor", updated["history_cursor"])

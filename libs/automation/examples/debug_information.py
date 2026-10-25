"""Preview loader debug imports and inspect persisted variables.

Usage: hexlab_python debug_information.py sample.hxproj [--kind dwarf|symbols]
       [--apply] [--group INTEGER] [--locations]
"""
import argparse
from dataclasses import asdict
import json
import hexlab

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("project")
parser.add_argument("--kind", choices=("dwarf", "symbols"), default="dwarf")
parser.add_argument("--apply", action="store_true", help="commit the import and reanalyze")
parser.add_argument("--group", type=lambda value: int(value, 0), default=0)
parser.add_argument("--locations", action="store_true", help="also print location ranges and decoded operations")
args = parser.parse_args()
if not 0 <= args.group < 1 << 64:
    parser.error("--group must be an unsigned 64-bit integer")

with hexlab.Project.open(args.project, readonly=not args.apply) as project:
    preview = project.preview_debug_import(args.kind)
    print(json.dumps(asdict(preview), ensure_ascii=False, indent=2))
    if args.apply:
        if not preview.ready:
            raise SystemExit("import unavailable: " + preview.reason)
        project.import_debug_info(args.kind, expected_revision=preview.edit_revision, group=args.group)
        project.analyze()
    revision = project.snapshot()["edit_revision"]
    for variable in project.iter_debug_variables(expected_revision=revision):
        print(f"{variable.function_entry}: {variable.name!r}, parameter={variable.is_parameter}, "
              f"type_id={variable.type_id}, CFA={variable.cfa_offset}, "
              f"operations={variable.operation_count}, ranges={variable.location_range_count}")
        if variable.expression_size:
            prefix = project.read_debug_expression(variable.id, 0, min(32, variable.expression_size),
                                                    expected_revision=revision)
            print(f"  default expression prefix ({len(prefix)}/{variable.expression_size} bytes): {prefix.hex()}")
        if args.locations:
            for operation in project.iter_debug_location_operations(variable.id, expected_revision=revision):
                print("  default operation:", operation)
            ranges = project.iter_debug_location_ranges(variable.id, expected_revision=revision)
            for index, pc_range in enumerate(ranges):
                print(f"  range {index}: [{pc_range.begin:#x}, {pc_range.end:#x}), "
                      f"{pc_range.expression_size} expression bytes")
                for operation in project.iter_debug_location_operations(
                        variable.id, range_index=index, expected_revision=revision):
                    print("    operation:", operation)

"""Usage: hexlab_python prototype.py writable.hxproj space address convention"""
import sys
import hexlab

if len(sys.argv) != 5:
    raise SystemExit("usage: hexlab_python prototype.py project.hxproj space address convention")

space = int(sys.argv[2], 0)
offset = int(sys.argv[3], 0)
convention = sys.argv[4]
if convention not in hexlab.FUNCTION_CONVENTIONS:
    raise SystemExit("convention must be one of " + ", ".join(hexlab.FUNCTION_CONVENTIONS))

u32 = hexlab.TypeSpec.integer("u32", 4, alignment=4, signed=False)
prototype = hexlab.TypeSpec.function(
    u32,
    [("context", hexlab.TypeSpec.pointer(hexlab.TypeSpec.void(), 8, alignment=8)),
     ("flags", u32)],
    convention=convention,
)

with hexlab.Project.open(sys.argv[1], readonly=False) as project:
    type_id = project.define_type("decode_result_fn", prototype)
    project.assign_type(hexlab.Address(space, offset), type_id)
    stored = next(row for row in project.snapshot()["types"] if row["id"] == type_id)
    print("assigned", stored["name"], "to", hexlab.Address(space, offset))
    print("calling convention:", stored["type"].arguments[3])

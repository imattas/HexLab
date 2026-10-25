"""Usage: hexlab_python annotate.py input.hxproj

Use a disposable/writable project: this script creates one normal history group.
"""
import sys
import hexlab

if len(sys.argv) != 2:
    raise SystemExit("usage: hexlab_python annotate.py input.hxproj")

with hexlab.Project.open(sys.argv[1], readonly=False) as project:
    before = project.snapshot()
    print("format:", before["format"], "input bytes:", before["input_size"])
    functions = project.functions(count=16)
    for function in functions:
        address = function["entry"]
        project.comment(address, "Reviewed by Python automation v1", group=20261021)
        print("function", function["id"], address, "complete:", function["complete"])
    project.save()
    print("annotated:", len(functions), "history:", project.snapshot()["history_cursor"])

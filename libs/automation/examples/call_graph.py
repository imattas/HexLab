"""Usage: hexlab_python call_graph.py existing.hxproj space address

The address can be anywhere inside the starting function. Output includes only
functions reached through resolved direct calls; no project data is modified.
The captured reader remains valid after the source owner closes.
"""
import sys
import hexlab

if len(sys.argv) != 4:
    raise SystemExit("usage: hexlab_python call_graph.py project.hxproj space address")

entry = hexlab.Address(int(sys.argv[2], 0), int(sys.argv[3], 0))
with hexlab.Project.open(sys.argv[1]) as project:
    reader = project.capture(expected_revision=project.snapshot()["edit_revision"])
with reader:
    graph = reader.call_graph(entry, max_functions=512, max_edges=8192)
    for function in graph["nodes"]:
        name = reader.presentation(function["entry"])["name"]
        print("function", function["entry"], name,
              "blocks:", function["block_count"],
              "complete:", function["complete"])
    for edge in graph["edges"]:
        print("call", edge["caller"], "at", edge["source"],
              "->", edge["target_function"] or edge["target"])
    print("graph complete:", graph["complete"],
          "unresolved calls:", graph["unresolved_call_count"],
          "truncated:", graph["truncated_reason"])

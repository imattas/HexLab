"""Usage: hexlab_python function_graph.py existing.hxproj space address

Addresses accept decimal or 0x-prefixed hexadecimal. The supplied address may
be inside a function. This script opens the project read-only.
"""
import sys
import hexlab

if len(sys.argv) != 4:
    raise SystemExit("usage: hexlab_python function_graph.py project.hxproj space address")

address = hexlab.Address(int(sys.argv[2], 0), int(sys.argv[3], 0))
with hexlab.Project.open(sys.argv[1]) as project:
    function = project.function_at(address)
    if function is None:
        raise SystemExit("no recovered function contains this address")
    print("function", project.presentation(function["entry"])["name"],
          function["entry"], "blocks:", function["block_count"],
          "complete:", function["complete"])
    for block in project.iter_function_blocks(address):
        label = block["presentation"]
        print("block", block["id"], block["begin"], label["name"], label["comment"])
        for instruction in project.iter_block_instructions(block["id"]):
            print(" ", instruction["address"], instruction["text"])
        for edge in project.iter_block_successors(block["id"]):
            print(" ", edge["kind"], edge["source"], "->", edge["target"],
                  "block:", edge["block"])
        if block["stop"] is not None:
            print("  stop:", block["stop"]["reason"], block["stop"]["detail"])

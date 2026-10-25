"""Usage: hexlab_python inspect_stack.py existing.hxproj [space] [address]

Print recovered stack-frame summaries, local slots, and a bounded number of
instruction-level access sites for a project or one selected function.
"""
import sys
import hexlab

if len(sys.argv) not in (2, 4):
    raise SystemExit("usage: hexlab_python inspect_stack.py project.hxproj [space address]")

with hexlab.Project.open(sys.argv[1]) as project:
    if len(sys.argv) == 4:
        address = hexlab.Address(int(sys.argv[2], 0), int(sys.argv[3], 0))
        functions = [project.function_at(address)]
        if functions[0] is None:
            raise SystemExit("no recovered function contains this address")
    else:
        functions = project.iter_functions(page_size=256)

    for function in functions:
        entry = function["entry"]
        frame = project.stack_frame(entry)
        if frame is None:
            continue
        print(f"function {entry}: complete={frame.complete}, "
              f"max_stack_allocation={frame.maximum_stack_allocation_bytes}, "
              f"slots={frame.slot_count}")
        for index, slot in enumerate(project.iter_stack_slots(entry, page_size=256)):
            print(f"  slot {index}: SP{slot.offset_from_entry_sp:+#x} width={slot.width} "
                  f"read={slot.read} written={slot.written} address_taken={slot.address_taken} "
                  f"sites={slot.access_count}")
            for site_index, site in enumerate(
                    project.iter_stack_slot_accesses(entry, index, page_size=256)):
                if site_index == 16:
                    print("    ... additional sites omitted")
                    break
                behavior = ",".join(name for name, enabled in
                                     (("read", site.read), ("write", site.written),
                                      ("address", site.address_taken)) if enabled)
                print(f"    {site.instruction}: {behavior or 'access'}")

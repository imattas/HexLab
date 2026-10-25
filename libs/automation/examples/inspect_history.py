"""Read-only command history and exact-step state inspection.

Usage: hexlab_python inspect_history.py sample.hxproj --preview 3 --read-offset 0
No live history cursor is moved and no commands are submitted.
"""
import argparse
import pprint
import hexlab

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("project")
parser.add_argument("--after-step", type=int, default=0)
parser.add_argument("--count", type=int, default=32, help="history and state rows per displayed page (1..1024)")
parser.add_argument("--preview", type=int, help="exact durable step, including zero or a redo position")
parser.add_argument("--max-steps", type=int, default=256)
parser.add_argument("--max-delta-bytes", type=int, default=16 * 1024 * 1024)
parser.add_argument("--read-offset", type=lambda value: int(value, 0), help="historical file byte offset")
parser.add_argument("--read-count", type=int, default=32)
args = parser.parse_args()
if not 1 <= args.count <= 1024:
    parser.error("--count must be in 1..1024")
if args.read_offset is not None and args.preview is None:
    parser.error("--read-offset requires --preview")

with hexlab.Project.open(args.project) as project:
    page = project.history(after_step=args.after_step, count=args.count)
    print("project", page.project_uuid, "cursor", page.history_cursor,
          "history count", page.history_count, "source revisions", page.source_revisions)
    for row in page.entries:
        pprint.pprint(row)
    if page.next is not None:
        print("continue with --after-step", page.next)
    if args.preview is not None:
        with project.preview_history(args.preview, max_steps=args.max_steps,
                                     max_delta_bytes=args.max_delta_bytes,
                                     expected_revision=page.source_revisions["edit"]) as historical:
            pprint.pprint(historical.snapshot())
            for table in ("annotations", "bookmarks", "types", "type_assignments",
                          "patches", "regions", "function_decisions", "user_references"):
                print(table, "(first page)")
                pprint.pprint(getattr(historical, table)(count=args.count))
            if args.read_offset is not None:
                print("historical bytes:", historical.read(hexlab.FileOffset(args.read_offset), args.read_count).hex())

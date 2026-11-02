"""Export one durable annotation page and persist its restart cursor.

Usage: hexlab_python resume_inventory.py project.hxproj NEW.state [PREVIOUS.state]
Use a fresh NEW.state path each run. Output rows may replay after a crash; deduplicate by ID.
"""
import argparse
import json
import hexlab

APPLICATION = "hexlab.examples.python-annotation-inventory"
SCHEMA = 1
PAGE_SIZE = 64

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("project")
parser.add_argument("new_state")
parser.add_argument("previous_state", nargs="?")
args = parser.parse_args()

with hexlab.Project.open(args.project) as project:
    snapshot = project.snapshot()
    revision = snapshot["edit_revision"]
    cursor = 0
    if args.previous_state:
        state = project.load_workflow_state(args.previous_state, APPLICATION, SCHEMA)
        if state.edit_revision != revision:
            raise RuntimeError("checkpoint revision differs from the open project")
        try:
            cursor = int(state.payload.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            raise ValueError("checkpoint payload is not a decimal annotation cursor") from None
        if cursor < 0:
            raise ValueError("checkpoint cursor must be nonnegative")

    rows = project.annotations(start=cursor, count=PAGE_SIZE)
    for row in rows:
        print(json.dumps(row, ensure_ascii=True, sort_keys=True))
    next_cursor = cursor + len(rows)
    saved = project.save_workflow_state(
        args.new_state, APPLICATION, SCHEMA, str(next_cursor).encode("ascii"),
        expected_revision=revision)
    print(f"saved cursor {next_cursor} at edit revision {saved.edit_revision}; "
          f"{'inventory complete' if len(rows) < PAGE_SIZE else 'continue with this checkpoint'}")

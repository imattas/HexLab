"""Inspect and restore one validated project recovery artifact.

Usage: hexlab_python restore_recovery.py RECOVERY_DIRECTORY OUTPUT --index N
The source artifact is retained; OUTPUT becomes an independent fresh-UUID project.
"""
import argparse
import hexlab

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("directory", help="directory containing HexLab recovery artifacts")
parser.add_argument("output", help="destination for the independent recovered project")
parser.add_argument("--index", type=int, required=True,
                    help="candidate index from this inspection result")
parser.add_argument("--replace", action="store_true",
                    help="atomically replace an existing output project")
args = parser.parse_args()

scan = hexlab.Project.inspect_recovery_directory(args.directory)
print("scan complete:", scan["complete"], "visited:", scan["visited_entries"],
      "rejected:", scan["rejected_entries"])
for index, candidate in enumerate(scan["candidates"]):
    print(index, candidate["kind"], "uuid=" + candidate["uuid"],
          "revisions=" + str(candidate["revisions"]), candidate["path"])
if not scan["complete"]:
    parser.error("recovery scan was incomplete; no restore was attempted")
if not 0 <= args.index < len(scan["candidates"]):
    parser.error("--index is outside the candidate list")

candidate = scan["candidates"][args.index]
restored = hexlab.Project.restore_recovery_artifact(
    candidate["path"], args.output, replace=args.replace)
print("restored:", restored["path"], "uuid=" + restored["uuid"],
      "source retained:", candidate["path"])

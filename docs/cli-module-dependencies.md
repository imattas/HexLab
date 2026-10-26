# Module dependency inventory

The command hexlab_cli modules <binary>... loads supplied images without
running analysis and prints direct dependency names from parsed metadata. PE
imports, ELF DT_NEEDED entries, and Mach-O dependency load commands are
included. Each name is resolved against other supplied file basenames using
case-insensitive matching.

Use hexlab_cli modules --graph <root> <supplied>... to recursively display the
dependency graph reachable from the first supplied image. The root is also part
of the candidate set. Each graph node receives its zero-based position in the
input list. The identity table marks normalized duplicate paths separately
from distinct paths that share a basename. An edge reports an unresolved
name, ambiguous provider IDs, a cycle, an already-expanded node, or a depth
limit. Dependency names are ordered by case-insensitive basename and then
exact spelling; provider identities follow input order.

Graph mode is bounded to 4,096 supplied images, 100,000 raw and unique
dependency rows, 16 MiB of dependency-name bytes, and 64 recursive levels.
Ambiguous-provider ID display is capped at 100,000 IDs across the report. The
summary reports the number of expanded nodes and whether supplied files were
unreachable or beyond the depth limit. Malformed or missing images report the
loader diagnostic and stop the command.

This remains an explicit file-set view, not a system loader simulation. It
does not search host library paths, discover files recursively from disk,
validate ABI compatibility, or resolve imported symbols beyond the existing
supplied-file resolution report. The one-shot command remains available without
the --graph switch.

Examples:

    hexlab_cli modules app.exe vendor.dll
    hexlab_cli modules --graph app.exe vendor.dll helper.dll

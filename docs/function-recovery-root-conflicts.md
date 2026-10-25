# Function root conflicts

Function recovery combines user function/code decisions, image entries, symbols,
unwind ranges, runtime callbacks and initializer fixups, and trusted direct calls.
Seeds at one address are retained together on the resulting function record, so
independent evidence corroborates a single function instead of creating duplicate
records.

An explicit user data region has precedence over any inferred root at that
address. Recovery now emits a function candidate for each metadata root rejected
by that boundary, preserving its root kind and source address. Unwind candidates
include the source section and record file offset. Initializer candidates include
the initializer slot file offset and any relocation or dyld fixup row identifiers.
This makes conflicts inspectable while keeping the selected data interpretation
in force. User function and code decisions continue through the normal permission
checks and report their own invalid-root candidates.

These candidates explain the direct conflict at the root address; they do not
claim that surrounding bytes have been fully classified or that the rejected
metadata is malformed. Normal image mapping, executable-byte, code-start,
execution-context, and analysis-budget checks still apply independently.

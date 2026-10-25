# Binary comparison function filters

The comparison window's **Functions** page can narrow results by match status,
minimum confidence, and text. The text filter checks the displayed status,
confidence, names, and old/new entry addresses. The visible/total count updates
as filters change.

Minimum confidence applies to matched and ambiguous candidates, which have a
scored correspondence. Added and removed functions remain visible under the
confidence threshold because the matcher has no candidate score for them;
choose a status filter to hide those rows. Confidence remains the matcher's
heuristic score and is not a probability or proof of semantic equivalence.

Filtering changes only the displayed rows. It does not alter the comparison
report, saved session, CSV export, or navigation targets. Selecting a visible
matched row continues to show its bounded instruction and block alignment.

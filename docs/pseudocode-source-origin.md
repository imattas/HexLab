# Pseudocode to Source navigation

Select a pseudocode line with a validated instruction-origin annotation, then
choose **Open Source at Origin** to open the Source page at that instruction's
mapped source file and line. The action is enabled only when the currently
rendered instruction origin resolves through the Source view's existing line
mapping rules to one unambiguous row. Synthetic/unmapped pseudocode lines,
missing debug mappings, and ambiguous overlapping inline scopes leave the
action disabled.

The action carries the rendered document ID and revision plus the project UUID
and edit/byte/decision revisions. The desktop checks the token before opening
Source and checks it again after address navigation. A closed, replaced,
inactive, or revised document/project cancels the action and leaves the Source
page unchanged. Source selection uses the same nearest-preceding mapping and
inline-scope selection as ordinary address synchronization; the workflow does
not run a second source query or invent a line mapping.

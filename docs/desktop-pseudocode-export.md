# Desktop pseudocode export

The desktop pseudocode view can copy the currently rendered pseudocode to the system clipboard or save it to a UTF-8 source/text file. Both actions are enabled only after a function has rendered successfully. The saved text includes the visible pseudocode annotations and current project-derived names and types.

When part of the pseudocode is selected, **Copy selection with addresses** copies that excerpt with a `/* address */` prefix on each line that maps to an instruction origin. Lines without a mapped origin are copied without a prefix. This keeps the selection and instruction provenance together when sharing a small excerpt.

The export is a presentation snapshot. It does not claim that the generated text is compiler-ready or equivalent to the original source, and it does not add an export record to project history.

# Pseudocode stack-slot access navigation

The stack-slot panel exposes **Previous access** and **Next access** controls
for the selected slot. They visit the slot's deduplicated instruction origins
in address order and wrap at either end. Slots without validated access sites
disable both controls.

Navigation uses the pseudocode view's current rendered document and project
revision token. If the document or project changes before the main frame handles
the request, the existing stale-navigation guard rejects it. These controls
navigate only; they do not change annotations, local names, or type assignments.

# Desktop multi-document workflow

The desktop keeps each open binary or project in its own tab. Select a tab to switch its active document; that document keeps its own selection and back/forward navigation history. Opening a binary or project adds a tab while its load is in progress, and the tab label shows opening, saving, unsaved, read-only, or error state where applicable.

To close a particular document, right-click its tab and choose **Close Document**, or middle-click the tab. The tab menu also offers **Close Other Documents** and **Close All Documents**. Batch closing follows the existing per-document close flow in tab order: pending saves finish first, and each edited untitled document prompts to save, discard, or cancel. Cancel stops the remaining batch; documents already closed earlier in the batch stay closed. Closing the active tab activates another open document and restores its navigation state. Closing an inactive tab leaves the active document selected.

The manager enforces a bounded open-document capacity. Opening a project already present in the same manager activates the existing tab instead of adding a second copy. Opening failures remove the failed tab and report the error while preserving the other documents.

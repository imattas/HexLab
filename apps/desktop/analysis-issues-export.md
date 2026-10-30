# Exporting analysis findings

The Analysis Issues pane can export the currently visible findings as UTF-8 TSV.
The export follows the active kind, severity and review-state filters, text search and pinned function scope, and is captured before
the save dialog opens so asynchronous UI updates cannot silently change its rows.

The file includes the finding kind and severity, review state, address, related
address, function entry, and details. Backslashes, tabs, carriage returns, and newlines in fields are escaped,
so each finding remains one physical line. When collection reached its view cap,
the header records that coverage is bounded. The exporter uses the shared atomic
file-publication path and refuses to overwrite protected project files. For a
file-only tab, it also protects the backing path from the captured document
snapshot, so choosing the input binary as the report destination is rejected.
The same active-document/snapshot check applies after the save dialog for both
project and file-only exports.

Header comments also record the kind, severity and review-state filters, search text and function scope,
including a partial scope-coverage notice when applicable. Scoping filters only
the loaded bounded collection. See [Reviewing analysis findings](analysis-issues-navigation.md)
for queue navigation, function membership and document-specific selection state.

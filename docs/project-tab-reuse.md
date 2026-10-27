# Reusing open project tabs

`DocumentManager::open_project` reuses the existing document when the requested
path resolves to the same underlying project file and the requested open mode
matches. This applies while the original open is still pending as well as after
it has completed. The existing tab becomes active and its document ID is
returned, avoiding a second actor and a redundant writer lease.

An open request with a different mode remains a separate request. Failed
entries are not reused, so callers can retry after correcting the underlying
open failure. Imported binary documents are unaffected.

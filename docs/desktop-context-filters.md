# Desktop metadata context filters

The **Types**, **Assignments**, and **Importable symbols** pages in the
metadata notebook retain their current text filters for each of up to 32 open
documents during the session. They also save the most recently edited filter
set to the user's wxWidgets configuration, so those three searches are restored
when the desktop starts again. The preferences are local to the application
profile and are not written into project databases or exported with a project.

Each filter accepts at most 2,048 characters. On startup, a saved value beyond
that bound is ignored. Changing a filter updates the local preference while
refreshing only its corresponding table (or the assignments view); switching
documents continues to restore that document's in-session values. The saved
cross-session set seeds the first document attached after startup, after which
document-local session state takes precedence.

The Imports and Exports pages also retain their filter pair for each of the 32
most recently visited document IDs during the current desktop session. For a
document belonging to a project, the pair is additionally saved under that
project's UUID in the local desktop profile as soon as either filter changes.
Other documents in the same project restore the same pair after restart, while a
different project starts with its own saved pair. Switching to a document with
no project preference or session-cache entry clears both fields once a filter
pair has been established in the session, so a query for one image cannot
accidentally hide rows in another. Standalone documents keep the existing
session-only per-document cache and desktop-wide startup seed. The project UUID
preferences remain local to this desktop profile; they are not embedded in or
exported with a project. Each value remains capped at 2,048 characters, and an
over-limit saved value is ignored.

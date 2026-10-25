# Persistent debugger state

Project breakpoints are stored in the project database. Their address, kind,
enabled state, hardware watch size, condition, logpoint message, and ignore
count are restored with the project; runtime breakpoint IDs are recreated by
the active backend. Use **Apply Project** in the debugger panel after launching
or attaching to install the saved breakpoints into the current target.

Watch expressions are stored in the desktop application's local configuration,
keyed by the project's database UUID. They follow that project when it is
renamed or moved and are loaded when its document becomes active. Each project
has a limit of 64 expressions with a maximum of 256 bytes each. Invalid,
duplicate, or over-limit stored entries are skipped during restore. They are
expressions only; evaluated values are transient and are refreshed against the
currently selected stopped thread. This local watch list is not synchronized
through project collaboration or project exports.

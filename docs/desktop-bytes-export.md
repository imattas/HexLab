# Bytes page export

The Bytes view offers **Export bytes page...** for the currently displayed
page. It writes the page's byte values, in display order, as raw binary with no
header, address prefix, or text encoding. A page contains at most 256 bytes;
the exported file therefore contains between 1 and 256 bytes. The page is
captured before the save dialog opens, so later cursor movement does not change
the bytes being written.

Zero-filled cells are exported as zero bytes, matching the values shown in the
Bytes view. Project patches are reflected because the page is read from the
current document snapshot. The destination is published through the shared
atomic file-publication path, which refuses protected input and project paths.
Export does not modify the document or project and is available for standalone
and project documents.

This action exports only the displayed page. It does not export an arbitrary
selected range or the entire image; use a separate export workflow for those
tasks.

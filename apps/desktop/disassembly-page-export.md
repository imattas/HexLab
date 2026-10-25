# Disassembly page export

The Disassembly view can export its currently displayed page as UTF-8 TSV. The
export captures the page before opening the save dialog, so navigation while
the dialog is open cannot change the exported rows.

Each row contains the address or file offset, bytes, rendered instruction or
data text, and analysis status. Backslashes, tabs, carriage returns, and
newlines inside fields are escaped so one listing row remains one TSV record.
The export is limited to the page already shown by the view (at most 256 rows).
Project and input paths remain protected by the shared file publication layer.

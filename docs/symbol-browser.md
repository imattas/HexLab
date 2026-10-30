# Symbol browser

The desktop Symbols pane lists the symbols exposed by the active binary format: PE exports, ELF symbols, or Mach-O symbols. Use the filter above the table to narrow that list while browsing.

Filtering is case-insensitive and matches text shown in any of the three columns: address or record location, symbol name, and state/forwarder details. The status line reports the number of visible symbols and the total. Clear the filter to restore the full list.

Rows retain their normal activation behavior while filtered. Selecting an address in another desktop view synchronizes to a matching visible symbol when one exists. A symbol hidden by the filter cannot be selected in the table until the filter is cleared. The filter narrows the existing format-specific symbol inventory; it does not discover additional symbols or alter the underlying analysis.

The filter is capped at 2,048 characters. For saved projects, its value is stored
in local desktop configuration under the project UUID and restored when that
project is opened again. Open documents also keep separate filter values for
the current desktop session. File-only documents use the desktop-wide saved
filter as their startup seed; per-document values are session-only. These
preferences do not modify or travel with the project file.

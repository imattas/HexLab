# Minidump Linux proc-status stream

The Breakpad `MD_LINUX_PROC_STATUS` stream (`0x47670004`) is exposed as
`MinidumpMetadata::linux_proc_status`. The loader retains up to the first 1 MiB
of the `/proc/<pid>/status` payload as raw bytes in a string, and parses
bounded `key: value` lines while retaining the file offset of each line. Keys
are limited to 128 ASCII letters, digits, or underscores; values are limited
to 4 KiB; at most 4,096 rows are retained. Repeated keys remain separate rows
in source order.

Truncated payloads, malformed nonempty lines, or fields beyond these limits
set `complete=false` and add a diagnostic. The CLI prints at most 64 fields;
quoted output escapes nonprintable bytes. Values remain descriptive text: the
loader does not interpret Linux credentials, capabilities, signal masks, or
security controls and does not read `/proc` from the host.

The stream identifier and its `/proc/$x/status` payload are defined by the
[Google Breakpad Minidump stream declarations](https://chromium.googlesource.com/chromiumos/platform/google-breakpad/+/9ebdd71b16596258703a7fcda5f9afc887f09972/src/google_breakpad/common/minidump_format.h).

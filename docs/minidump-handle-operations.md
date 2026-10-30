# Minidump handle operation traces

The loader parses standard stream 18, `HandleOperationListStream`, into
`MinidumpMetadata::handle_operations`. The optional list distinguishes an
explicitly captured empty list from an absent stream. Each operation retains
the 64-bit handle, 32-bit process/thread IDs, raw operation type, alignment/spare
field, backtrace depth/index and all 32 fixed-width 64-bit return-address slots.
Only the first `backtrace_depth` slots describe collected addresses. Unused
slots are preserved without inventing additional frames. The wire layout is
independent of the loader host's pointer width and SystemInfo architecture.

The 16-byte list header must advertise a header size from 16 through 4,096,
an entry size from 288 through 4,096 and a zero reserved field. Each entry's
documented 288-byte AVRF prefix is decoded; header/entry extension bytes remain
opaque and inspectable through the source extents. The complete declared table
must fit the stream. Trailing stream bytes remain opaque. Duplicate stream 18
directories, truncated tables and depths above `AVRF_MAX_TRACES` (32) are
malformed. The parser caps entries at 65,536, charges the table read and retained
model against the shared 64 MiB metadata budget before allocation, and checks
cancellation for each operation.

Header and record file offsets/sizes retain original dump provenance. Each
record also supplies the return-address array's file offset; address slot N is
the eight-byte source range at that offset plus `8*N`. Extended entry sizes do
not change the fixed prefix offsets. Unknown operation values and nonzero
alignment/spare storage are retained; they are not rejected or interpreted as
future operation semantics. Duplicate handles, repeated IDs and return
addresses outside captured memory are valid historical metadata.

CLI inspection reports list presence/count, up to 128 operations, all collected
addresses (at most 32 each), exact source offsets and omitted operation counts.
Operation values 0–3 are labelled unused, open, close and bad-reference;
other values are labelled unknown while displaying the original number.
These are Application Verifier trace records supplied by the dump, without
chronology reconstruction, handle-lifetime matching, live stack unwinding,
symbolization, module loading or a claim that an operation succeeded.

The Minidump desktop view includes a **Handle operation traces** page. It lists
the captured handle, process/thread IDs, operation type, trace depth/index,
first return address and record offset. Selecting a row shows every captured
trace address (up to the format limit) and the record/array provenance. **Go to
operation record bytes** opens the bounded source record; **Go to first mapped
trace address** navigates to the first address backed by captured image bytes.
The view distinguishes an absent stream from a present empty list and does not
infer a live stack or whether a historical operation succeeded.

The table displays at most 4,096 rows and reports the shown and declared counts.
Its status also counts repeated nonzero `(process ID, handle)` pairs, non-unused
operations with a zero handle, and operation values outside 0–3. Selecting a
repeated, zero-handle, or unknown-operation row calls out that raw-record fact in
the details pane. These flags describe repetition or unusual raw values only;
they do not reject records, infer chronology, or imply corruption.

The fixed layout and meanings follow Microsoft's
[MINIDUMP_HANDLE_OPERATION_LIST](https://learn.microsoft.com/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_handle_operation_list),
[AVRF_HANDLE_OPERATION](https://learn.microsoft.com/windows/win32/api/avrfsdk/ns-avrfsdk-avrf_handle_operation),
[AVRF_BACKTRACE_INFORMATION](https://learn.microsoft.com/windows/win32/api/avrfsdk/ns-avrfsdk-avrf_backtrace_information)
and [eHANDLE_TRACE_OPERATIONS](https://learn.microsoft.com/windows/win32/api/avrfsdk/ne-avrfsdk-ehandle_trace_operations)
definitions. Other unimplemented streams, ARM64EC overlays, compacted XSAVE,
scalable state and PDB loading remain unsupported.

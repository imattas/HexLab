# GDB Remote Serial Protocol packet handling

The desktop debugger saves the remote host, port, local packet ceiling, and
the no-ack, non-stop, and thread-event choices in the application configuration
under the active project UUID. It also saves the target working directory and
the bounded root `target.xml` annex plus a summary of its architecture, pointer
width, byte order, and negotiated packet size. The XML is retained as
inspection metadata only; every connection renegotiates and uses the live
server description. The local packet ceiling is limited to 128 bytes through
1 MiB and is further capped by the server's advertised `PacketSize`. Remote
environment values are intentionally not persisted because they can contain
credentials.

The TCP connector applies one deadline to both name resolution and socket
connection, and checks the caller's stop token while waiting for DNS. The
operating-system resolver itself cannot be interrupted on every supported host,
so it runs in a detached worker from a process-wide pool capped at four active
lookups. A timed-out or canceled lookup may continue in the background and
occupy one slot until the OS resolver returns; further connects wait within
their own deadline rather than starting unbounded resolver threads.

`rsp::Client::read_feature_annex()` reads `qXfer:features:read` annexes in
multiple packets. Its `chunk` argument is a maximum and is reduced to fit both
the local and peer `PacketSize` ceilings, leaving room for worst-case escaping
and the `m`/`l` marker. Every encoded request is checked against the negotiated
limit. Replies must start with `m` or `l`, cannot exceed the requested chunk or
aggregate limit, and non-final chunks must make forward progress. Only `l`
completes the annex; an empty first reply means unsupported, while an empty
reply after partial data is malformed. The shared transaction path validates
RSP framing/checksums, ACK retries, cancellation, and packet decoding for each
chunk. The default aggregate cap is 1 MiB; target XML includes use the same
reader and share an aggregate document budget.

The other qXfer readers use the same negotiated chunk ceiling for libraries,
memory maps, threads, OS data, executable paths, auxv, and siginfo. Their
`chunk` arguments are maximums and shrink to fit the local and peer
`PacketSize`, reserving a reply marker plus worst-case escaping. Each encoded
request is checked against the negotiated ceiling before transmission. Binary
objects remain bounded by their own byte caps; text annexes retain their
marker, progress, and aggregate-size checks.

The common send path also enforces the negotiated limit on the encoded wire
payload. Commands containing bytes that require RSP escaping cannot pass a
check based only on their shorter, unescaped spelling.

Extended-remote launch applies environment and working-directory settings as
one best-effort configuration batch before `vRun`. The client remembers values
only after the remote acknowledges them; GDB provides no standard query for
the current working directory or environment and no atomic transaction. If a
later packet fails, HexLab restores the previously acknowledged values when
it has them. On a fresh connection, the original remote values cannot be read,
so rollback requests the target-default directory and environment baseline and
reports that the originals were unknown. A rollback packet failure is included
in the returned error and leaves the affected setting's state unknown. In all
cases the failed launch is not sent.

Register reads preserve GDB's unavailable-register encoding. With usable
target XML, a register-sized slice made entirely of `x`/`X` characters is
shown as **Unavailable**; placeholder bytes are never evaluated as a value.
Mixed unavailable markers and hex digits within one register are rejected as
malformed. When target XML is absent, the bulk `g` packet has no register
boundaries, so only a wholly unavailable packet can be represented as one
unavailable synthetic register. Expressions and register edits reject
unavailable values. Stubs that omit XML and return a mixture of valid and
unavailable register bytes remain unsupported because those bytes cannot be
assigned safely to individual registers.

Register edits prefer the single-register `p`/`P` packets so each write can be
rolled back independently. If the stub explicitly returns the empty
unsupported response to a `p` read, the backend can instead use a complete
`g`/`G` transaction when the `g` packet exactly matches target XML and every
register is available. It patches only requested register bytes, preserves all
other bytes, and attempts to restore the original complete packet if `G` fails
after transmission. A malformed or unavailable bulk snapshot is never used for
this fallback.

When the remote does not provide `qXfer:threads:read` XML, the thread list uses
`qThreadExtraInfo,<thread-id>` to replace synthetic thread labels with the
stub's hex-encoded descriptions. Empty replies keep the synthetic label. Each
description is capped at 4 KiB, and at most the first 64 enumerated threads
are queried per refresh, with a shared two-second deadline; larger lists retain
synthetic labels for the rest. An empty response or a non-cancellation request
error stops further optional queries for that refresh. Malformed hex and
embedded NUL descriptions are rejected; other ASCII control bytes are replaced
with spaces before the label reaches the UI.

`qSupported` negotiation treats the response as a bounded capability snapshot.
Feature names must use the protocol token alphabet, each advertised name may
appear once, and tokens must have either a `+`/`-` support marker or a nonempty
value. Known boolean features (`QNonStop`, `QThreadEvents`, and
`QStartNoAckMode`) require support markers. `PacketSize` must be a nonzero
hexadecimal value; malformed or duplicate advertisements fail negotiation
instead of silently reverting to a potentially unsafe default. Unrecognized
well-formed tokens remain available in the capability map.

For `qXfer:threads:read`, the backend also accepts the GDB XML thread `core`
attribute as an unsigned decimal processor number. It carries that optional
number through `ThreadInfo` and shows it in the desktop thread list. Missing
attributes leave the field blank, including legacy `qfThreadInfo` results;
empty, signed, non-decimal, or out-of-range values reject the XML snapshot.

Shared-library enumeration accepts either `qXfer:libraries:read` or the
Solaris/GDB `qXfer:libraries-svr4:read` object. The client tries the standard
object first and falls back to the svr4 object only when the first request is
explicitly unsupported. Both objects use the same bounded chunk, progress,
marker, and 1 MiB aggregate checks; returned `<library>` names and segment
addresses flow through the existing XML validation and module model. A malformed
standard object is reported as malformed rather than hidden by a fallback.

`rsp::Client::read_memory(address, size)` splits reads larger than one RSP packet
into ordered `m` requests sized for both the local and peer `PacketSize`. It
checks every decoded chunk against the requested length, supports cancellation
between chunks, and caps one call at 16 MiB. A zero-byte request returns an
empty result without I/O; overflowing and over-limit ranges are rejected.

`rsp::Client::memory_crc32(address, length)` requests a remote CRC-32 through
`qCRC:ADDR,LENGTH`, allowing callers to compare a memory range without reading
the bytes back. The client rejects empty or address-overflowing ranges before
I/O, treats an empty reply as unsupported, and accepts only a `C`-prefixed
hexadecimal value that fits in 32 bits. The API does not inspect the target
memory map, so callers remain responsible for selecting a readable range.

`rsp::Client::read_memory_tags(address, length, type, max_tag_bytes)` sends the
GDB `qMemTags` query only after the peer advertises `memory-tagging+`. The
address range must be non-empty and non-overflowing. Replies must begin with
the `m` marker and contain valid hex; decoded tag bytes are returned without
assuming an architecture-specific granule size or tag encoding. The default
reply cap is 256 KiB, with a 1 MiB API ceiling and a further limit from the
local packet decoder. An empty reply despite advertisement is unsupported.
Checksums, framing, escaping, retries, and cancellation use the shared RSP
transaction path. This read API does not write tags or determine whether an
address belongs to a tagged mapping. See the [GDB memory-tag packet reference](https://sourceware.org/gdb/current/onlinedocs/gdb.html/General-Query-Packets.html#qMemTags).

`rsp::Client::is_address_tagged(address)` sends `qIsAddressTagged:ADDR` to
check whether one target address belongs to a memory-tagged region. Only the
exact two-character replies `00` (not tagged) and `01` (tagged) are accepted;
an empty reply is unsupported and every other payload is malformed. The request
uses the shared bounded RSP transaction path and obeys the negotiated packet
ceiling. This query reports mapping tag eligibility only; it does not read the
allocation tag or prove that a particular access will pass tag checking. See
the [GDB qIsAddressTagged packet reference](https://sourceware.org/gdb/current/onlinedocs/gdb.html/General-Query-Packets.html#qIsAddressTagged).

`rsp::Client::search_memory(address, length, pattern)` uses the standard
`qSearch:memory` packet to locate the first exact byte sequence in a target
range. The range and pattern must be non-empty and must fit the configured and
negotiated packet limits; packet escaping is included in that limit. A match is
returned as an address, no match as an empty optional, and an empty remote reply
as `unsupported`. Replies with malformed addresses or a match outside the
requested range are rejected. This API does not fall back to downloading the
range, so it does not add network traffic proportional to the searched size.
See the [GDB qSearch:memory packet reference](https://sourceware.org/gdb/current/onlinedocs/gdb.html/General-Query-Packets.html).

`rsp::Client::read_remote_file(path, maximum_size)` uses Host I/O
`vFile:open`, chunked `vFile:pread`, and `vFile:close` to copy a remote file
into caller-owned bytes. Paths are opaque non-NUL bytes encoded as hex. Read
chunks account for negotiated `PacketSize` and worst-case binary escaping;
the default aggregate cap is 64 MiB (the API accepts up to 256 MiB). It checks
the returned byte count against the binary attachment, probes one byte beyond
the cap to distinguish an exact-limit file from a larger one, honors
cancellation between chunks, and attempts close on every post-open failure.
Unsupported `vFile` packets return `unsupported`; remote errno and close errors
are preserved. This API reads the remote stub's filesystem and does not use
process-relative `vFile:setfs`. See the [GDB Host I/O packet reference](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Host-I_002fO-Packets.html).

The same operation is available as `DebugSession::read_remote_file(path,
maximum_size)` for a connected remote debugging session. The session wrapper
limits reads to 64 MiB; its default is 16 MiB. The desktop **Remote file** tab
reads at most 1 MiB per request and renders bounded hex/ASCII rows. It reads
the remote stub's filesystem, not a path inside the inferior. Native backends
and remote stubs without the vFile packets return `unsupported`. Changing the
path, switching sessions, or disconnecting invalidates an in-flight display
result; a stale read is not shown in the new session.

`rsp::Client::read_remote_file_range(path, offset, size)` uses the same bounded
Host I/O lifecycle to retrieve a byte range without downloading the file prefix.
It accepts 1 byte through 256 MiB, rejects ranges that overflow the 64-bit file
offset, honors cancellation between packets, and returns a shorter buffer when
the remote file reaches EOF before the requested size. This is useful for
inspecting remote binaries with large sparse or irrelevant regions.

`rsp::Client::stat_remote_file(descriptor)` requests `vFile:fstat` for an
already-open remote descriptor and returns the protocol-defined fields for
device, inode, mode, links, ownership, size, block geometry, and timestamps. The
client requires a 64-byte binary attachment and decodes the specified
big-endian field layout; malformed lengths and replies are rejected. The caller
owns opening and closing the descriptor. An empty packet reply reports
`unsupported`, while remote errno is returned as an I/O error. This preserves
the RSP file-I/O representation rather than assuming the remote host's native
`struct stat` layout. See the [GDB Host I/O `vFile:fstat` reference](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Host-I_002fO-Packets.html)
and [protocol `struct stat` definition](https://sourceware.org/gdb/current/onlinedocs/gdb.html/struct-stat.html).

`rsp::Client::stat_remote_file_path(path, follow_symlinks)` reads the same
fixed 64-byte metadata attachment directly by path using `vFile:stat` or
`vFile:lstat`. Paths are hex-encoded, must be 1..16 KiB without NUL, and the
whole request must fit the negotiated packet limit. `stat` follows a symbolic
link; `lstat` reports the link itself. Empty replies report unsupported,
remote errno is returned as an I/O error, and malformed attachment sizes are
rejected. This avoids opening a remote descriptor solely to inspect metadata;
the remote path namespace and timestamp width still come from the target's
RSP file-I/O implementation. See the [GDB Host I/O packet reference](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Host-I_002fO-Packets.html).

`DebugSession::stat_remote_file(path, follow_symlinks)` exposes this path query
for an active remote session. It returns typed device, inode, mode, ownership,
size, block geometry, and timestamp fields without opening the file or reading
its contents. The default follows symlinks; pass `false` to inspect the link
itself. The wrapper bounds paths to 16 KiB, rejects NUL bytes, and honors
cancellation before the request. Native backends and remote stubs without the
corresponding `vFile` operation return `unsupported`.

`rsp::Client::read_remote_symlink(path, maximum_size)` and
`DebugSession::read_remote_symlink` use Host I/O `vFile:readlink` to retrieve a
symbolic link's target as raw target bytes. The path is hex-encoded, must contain
1..16 KiB of non-NUL bytes, and the target defaults to a 16 KiB cap (the API
allows up to 1 MiB). The returned byte count must exactly match the binary
attachment and stay within the caller's limit; remote errno, unsupported
packets, malformed replies, and cancellation remain distinct errors. The
operation does not resolve or normalize the returned path, and callers should
interpret it using the remote host's path rules. Native backends report
unsupported. See the [GDB Host I/O packet reference](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Host-I_002fO-Packets.html).

`rsp::Client::write_remote_file_range(path, offset, bytes, flags, mode)` writes
remote file data through `vFile:open`, binary `vFile:pwrite` chunks, and
`vFile:close`. The caller supplies target-specific open flags and creation mode
because RSP does not standardize their numeric values. Paths are hex encoded;
payload chunks reserve worst-case RSP escaping space under negotiated
`PacketSize` and are capped at 64 KiB. The API accepts 1 byte through 256 MiB,
rejects 64-bit offset overflow before I/O, checks each reported write count for
an exact full write, honors cancellation between chunks, and attempts close
after every post-open failure. A failed operation may have written a prefix;
RSP offers no rollback for remote file writes.

`rsp::Client::program_flash(address, bytes)` uses the remote flash programming
sequence `vFlashErase`, ordered binary `vFlashWrite` packets, and `vFlashDone`.
The address range must be nonempty, non-overflowing, and no larger than 256
MiB. Each write reserves worst-case RSP escaping space under the configured
and negotiated packet limits, and the client requires exact `OK` replies.
Cancellation and write failures still trigger a best-effort `vFlashDone`; any
failure after erase reports that flash contents may be unpredictable. Erase
ranges must match the target memory map's flash block boundaries, and the
ordered write chunks must not overlap. The API does not validate map geometry,
roll back a failed flash operation, or read back programmed bytes, so callers
must select a target-specific valid range and perform readback separately when
verification is required. Empty or rejected flash packets are reported as
unsupported or I/O errors; there is no fallback to ordinary `M`/`X` memory
writes. See the [GDB flash packet specification](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Packets.html).

Callers with a memory-map snapshot can use
`rsp::Client::program_flash_in_regions(address, bytes, regions)` for a
preflighted path. It rejects an empty or overflowing request unless the full
byte range is contained in exactly one region whose type is `flash`; these
checks happen before any erase packet is sent. A typical caller obtains the
snapshot from `DebugSession::memory_regions()` and passes that vector to the
client. The caller must keep the snapshot current and ensure the range meets
the target's erase-block rules: the map API currently does not expose flash
block geometry, and this helper does not refresh maps, infer geometry, or
verify programmed contents. Failures after erase retain the partial-program
warning described above.

For callers that need a verified flash write, `rsp::Client::program_flash_verified_in_regions(address, bytes, regions)` performs the same single-flash-region containment check, confirms that the peer answers `qCRC`, and only then starts erase/program. After `vFlashDone` succeeds, it requests `qCRC` again and compares the target range with the standard reflected CRC-32 of the input bytes (polynomial `0xedb88320`, initial/final XOR `0xffffffff`). Missing `qCRC` support is therefore reported before erase. A transport error during final verification or a CRC mismatch is reported after programming and cannot restore the prior flash contents. The memory-map snapshot may be stale, and target-specific erase-block alignment remains the caller's responsibility; this workflow does not provide rollback or byte-for-byte readback.

## Launching on a connected remote target

In a live RSP session, the existing **Launch** command can start a new remote
inferior through `vRun`; local launch from an idle session is unchanged. The
backend enables extended-remote mode lazily with `!` if the connection did not
already negotiate it, then hex-encodes the executable path and each argument as
separate `vRun` fields. This preserves spaces and packet metacharacters without
shell quoting. The encoded request must fit the negotiated `PacketSize`, and
the client caps argument count at 4,096 and rejects embedded NUL bytes.

The remote must return an initial `T` or `S` stop reply. Non-stop sessions
require its exact thread ID, and multiprocess sessions require `pPID.TID` so
thread and process ownership are not guessed; successful launch replaces the
session's previous thread identities and stop state. A
live inferior, pending stop/event, or HexLab-owned breakpoint prevents launch,
avoiding discarded stop context or stale breakpoint IDs. A fresh extended
connection with no inferior can launch directly; after a `W`/`X` exit reply is
acknowledged, the same connection can launch another inferior. If extended
mode or `vRun` is unsupported, the request returns that error and never falls
back to local process launch.

When `qSupported` advertises `QSetWorkingDir+`, remote launch sends
`QSetWorkingDir:` after entering extended mode and before `vRun`. The target
working-directory bytes are hex encoded independently, preserving spaces and
packet metacharacters without local path expansion or shell interpretation.
The client rejects embedded NUL, paths over 16 KiB, and packets exceeding the
negotiated `PacketSize` before sending the directory request. Only exact `OK`
permits launch; an empty reply reports unsupported, and other replies or
transport failures stop launch with their error.

Every advertised launch sets the directory, including an empty request to
restore the server's default when `Target::working_directory` is empty. This
also prevents a failed prior `vRun` from silently supplying its directory to a
later launch. A stub without the advertisement keeps ordinary default-directory
launches and rejects nonempty working-directory requests before `vRun`.
`rsp::Client::set_working_directory` exposes the same bounded packet operation
for callers managing their own extended-mode lifecycle. Shell-startup options
and live stub validation remain pending. The packet and
empty-reset behavior follow the
[GDB QSetWorkingDir specification](https://sourceware.org/gdb/current/onlinedocs/gdb.html/General-Query-Packets.html).

### Remote launch environment

`Target::remote_environment` provides explicit set/unset changes to the remote
server's default environment for `DebugSession::launch` on a connected session:

```cpp
hexlab::debugger::Target target{"/opt/example", {}, "/opt"};
target.remote_environment = {
    {"MODE", std::string("inspect")},
    {"EMPTY", std::string{}},            // Set an empty value.
    {"REMOVE_ME", std::nullopt}          // Remove the variable.
};
auto launched = session.launch(target);
```

The desktop launch panel exposes these settings directly. **Working directory**
accepts the target-side path. **Remote environment** accepts one `NAME=VALUE`
set operation per line or `-NAME` to remove a variable; `NAME=` sets an empty
value, blank lines are ignored, and lines beginning with `#` are comments. A
live summary reports the set/unset counts without displaying values. Syntax,
duplicate names, NUL bytes, per-name/value limits, change count, and aggregate
bytes are checked while editing and again before launch; the editor input is
bounded to 256 KiB. Target-specific feature availability and negotiated packet
size are checked when launching. These lines are sent only when the active
connection is remote; a local launch uses the working directory and the local
process environment as before.
For values that need bytes not convenient to enter as text, use
`NAME=hex:<hex-digits>` with an even number of hexadecimal digits. This decodes
the bytes before the ordinary NUL, batch-size, and packet-size checks; for
example, `TOKEN=hex:6162` sets the two bytes `ab`. A decoded NUL is rejected
because environment values cannot contain it. A literal value beginning with
`hex:` can itself be entered in hexadecimal form.

The client requires advertised `QEnvironmentReset+` and the corresponding
`QEnvironmentHexEncoded+` or `QEnvironmentUnset+` for each requested operation.
It validates and encodes the entire batch before sending any environment
request: at most 256 unique, case-sensitive names, 64 KiB total name/value
bytes, 4 KiB per name, and 16 KiB per value. Names cannot be empty or contain
`=` or NUL; values cannot contain NUL. Each encoded packet must fit the
negotiated `PacketSize`. Names and values are opaque target bytes; no local
environment is copied and no shell or local path expansion occurs.

After entering extended mode, every launch on a server advertising reset sends
`QEnvironmentReset`, then separately hex-encoded set/unset packets, before the
working-directory request and `vRun`. An empty change list still sends reset.
Reset restores the server's environment baseline; it does not request an empty
environment. Only exact `OK` permits progress. Empty, rejected, malformed, or
failed packet transactions prevent `vRun`; unsupported features are never
silently ignored. Servers without reset support retain default-environment
launches but reject nonempty changes. Native launch rejects this remote-only
field before starting a process.

This is a sequence of server settings, not an atomic remote transaction. If a
set/unset packet fails or the caller cancels mid-batch, the client resets the
environment and reapplies the last acknowledged change set when this client
knows it. On a fresh connection the prior environment is not queryable, so it
can only restore the target-default baseline; the error says so explicitly.
If cleanup or reapplication fails, the returned error includes the failure and
marks the remote state unknown. The initial reset is also treated as
potentially ambiguous if its reply is lost. Each later launch performs its own
reset before applying values. The low-level `rsp::Client::set_environment` API
exposes these rollback details in its error. When the stub rejects a setting,
the error includes up to 96 bytes of its reply, with non-printable bytes escaped;
the encoded request is never included, since it may contain environment values.
This is diagnostic text only and does not make an otherwise unsuccessful
setting operation safe to continue. The desktop launch panel accepts
line-based set/unset entries; Python automation accepts an ordered sequence of
`(name, value-or-None)` pairs through `DebuggerSession.launch`. The desktop does
not persist environment values, which may contain credentials. Windows Debug
build coverage does not establish interoperability with a live UNIX-like
gdbserver.
Packet behavior follows the [GDB environment packet specification](https://sourceware.org/gdb/current/onlinedocs/gdb.html/General-Query-Packets.html).

## Remote process enumeration and attach

When the stub advertises `qXfer:osdata:read`, HexLab reads the `processes`
annex and exposes the validated PID/command rows in the desktop process list.
After connecting, select a listed process and press **Attach** to attach the
existing RSP connection to that inferior. This uses `vAttach;PID` and requires
`multiprocess+` plus a successful `!` extended-remote request, since `vAttach`
is an extended-mode packet. In all-stop mode the returned `T`/`S` stop reply
must identify a concrete `pPID.TID` in the requested process. In non-stop mode,
the server may return `OK`; the process becomes selected and later stop
notifications arrive through the ordinary event path. A missing or foreign
thread identity in an all-stop reply, unsupported packet, or process absent
from the current process list fails closed.

The session's process identity changes only after a valid attach reply or a
successful PID-qualified selection of an already attached inferior. Thread
enumeration filters to that PID, and thread tokens retain their complete
`pPID.TID` wire identity. Register reads/writes and thread-qualified resume
operations select or validate those tokens against the selected inferior.
For each PID, the RSP backend retains whether it has attached that inferior,
its cached stop reply, and its thread run states. Switching saves the selected
inferior's state first. A PID already attached on this connection is selected
with `HgpPID.-1` and its cached stop/thread state is restored; a PID not yet
attached is selected with `vAttach;PID`. Thread run-state snapshots remain
keyed by their full `pPID.TID` IDs, so a stop or detach in one inferior does
not rewrite another inferior's thread state. A cached inferior is reusable
only while the stub accepts PID-qualified general-thread selection. If it
does not, HexLab returns the server's explicit unsupported/error result and
does not silently issue a second attach. Process discovery and attach are unavailable when
the stub omits the `osdata` annex or multiprocess support; the initial inferior
from a normal single-process connection remains supported as before.

`DebugSession::detach_remote_process(pid)` detaches a different listed process
on the same multiprocess connection with `D;pid`. The currently selected
process remains attached, its pending stop and breakpoints remain valid, and
the session can continue using it. Thread tokens and run-state entries for the
detached PID are discarded so callers cannot reuse stale identities; already
queued stop notifications with that PID are discarded as well. The API
rejects the selected PID; use selected-process detach or ordinary session
`detach()` to end the active debug session. This operation requires process enumeration so the PID is
checked against the remote process list before sending the detach request.
Explicit per-PID detach sends `D;pid`; if the server returns an empty response,
HexLab reports `unsupported` and does not fall back to `D`, which would detach
the entire connection. PID-scoped termination similarly uses `vKill;pid`; an
unsupported response is returned without sending global `k`. After successful
PID-scoped termination, only that inferior's threads are marked exited and the
RSP connection remains available for enumeration or another attach.

For `detach()` on a multiprocess extended-remote connection, HexLab first
attempts `D;pid` for the selected inferior. If accepted and another process is
listed, it attaches the first remaining PID and keeps the RSP connection and
`DebugSession` active on that process. Breakpoints must be removed before this
selection change. The PID-qualified form follows the GDB packet definition
([GDB RSP detach packet](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Packets.html)).

If no other process is listed or process enumeration is unavailable, detach
ends the session as before. If the server rejects `D;pid`, HexLab tries plain
`D` to end the whole remote session and records a fallback explanation in
`DebugSession::last_diagnostic()`; remaining inferiors are not preserved.
Other protocol errors are returned without fallback. If selected-process
detach succeeds but attaching the next process fails, HexLab closes the
connection and returns that attach error. Single-process connections continue
to use `D`.

The desktop process row selects the PID used by **Attach**. After a remote
process is attached, refreshing the list selects the active process by default.
**Detach secondary** is enabled only when the selected row is a different,
currently listed PID in a live remote session; it never detaches the active
process. The backend revalidates the PID against a fresh process list before
sending `D;pid`. If the remote list changed, the error is reported and the UI
refreshes while preserving the active session.

HexLab's RSP client validates packet framing and checksums, reverses byte escaping, and expands the standard response run-length encoding before command-specific parsing. For example, a response payload `0* ` expands to `0000`: the byte after `*` encodes three additional copies using its ASCII value minus 29. A literal asterisk must be escaped by the peer and remains literal after unescaping.

Run-length expansion is bounded independently of the wire packet size. `rsp::Client` applies its configured maximum packet size to the decoded response as well as the received frame, so a compact packet cannot expand into unbounded memory. Standalone `decode_packet` calls default to a 1 MiB decoded-payload limit and may pass a smaller limit. Invalid/truncated run-length sequences return `malformed`; payload expansion beyond the limit returns `resource_limit`.

This covers response-data RLE defined by GDB. Packet encoding intentionally continues to send ordinary escaped payloads; it does not attempt to compress requests. Cisco-specific legacy RLE and interoperability with a live remote stub are not covered by this feature.

At connection setup, the remote backend uses the stub's `vContSupported` feature
and queries `vCont?` before choosing continue and step packet forms. It sends
`vCont;c` only when the `c` action is advertised, with a legacy `c` fallback
otherwise. The `vCont?` reply lists supported action kinds; the packet grammar
allows an action to name a thread even when the reply lists only the unqualified
kind. Thus an advertised `s` permits `vCont;s:<thread>` for a stop that identifies
its thread. If the thread is unknown, HexLab uses legacy `s` with the peer's
current selection. A stop with a known thread is never
single-stepped through the all-thread `vCont;s` form or an ambiguous legacy
current-thread selection. Support for one `vCont` action is not treated as
support for every action.

Continue retains process-wide debugger semantics. Single-process connections
use `vCont;c` or legacy `c`. A peer that negotiates multiprocess support receives
`vCont;c:pPID.-1` for the process identified by the initial stop, so continuing
one session does not resume other inferiors. That path requires an advertised
`c` action and a current stop belonging to the same process; otherwise it
reports unsupported without sending a resume packet. Stepping likewise rejects
a missing or foreign process identity in multiprocess mode. The shared session
API also exposes `continue_thread_execution(sequence, thread)`. This operation
requires an opaque thread token obtained from the event or thread listing and
an advertised `c` action, then sends exactly one `vCont;c:<wire-thread-id>`
action. The full `pPID.TID` identity is retained in the token mapping and checked
against the session process before sending. It never falls back to global
continue. `resume_threads(sequence, actions)` submits one complete mixed schedule: each
action names an exact session thread and chooses continue (`c`), single-step
(`s`), or remain stopped (`t`). The backend requires the corresponding action
to be advertised by `vCont?`, rejects duplicate/unknown/foreign thread tokens,
and sends the whole schedule in one `vCont;...` packet. The thread owning the
pending stop must appear in the schedule. If validation or transmission fails,
the pending event remains available for retry. The API tracks expected step
completions by thread, so an intervening stop from another thread does not
consume the step expectation. Session state remains a coarse running/stopped
summary; use `thread_run_states()` for the backend's known per-thread state.
The low-level `rsp::Client::send_vcont_actions` helper independently validates
each exact wire identity and rejects repeated IDs (including equivalent
hexadecimal spellings such as `a` and `0A`) before sending the packet.
Stop actions are sent explicitly as `t:TID` or `t:pPID.TID`; they are never
implemented by dropping that thread from the packet. The full process-qualified
identity is checked against the selected inferior before transmission. At least
one action must continue or step a thread. HexLab's own all-stop server also
accepts explicit `t` in mixed schedules, such as `vCont;t:TID;c` or
`vCont;c:TID;t`, and advertises `t` through `vCont?`. Its selectors are plain
hexadecimal thread IDs, `0` for the event owner, and `-1` or an omitted selector
for all live threads; it does not negotiate multiprocess or non-stop mode.
Native backends implement bounded exact schedules described in
[Native thread schedules](../libs/debugger/docs/thread-resume-schedules.md).
A schedule is validated as one operation; it does not promise processor-atomic
execution or rollback of instructions already executed after an OS resume.
Stop signals are retained with the pending event. `continue_execution` and
`single_step_execution` use the caller's disposition: `handled` suppresses a
pending signal, while `not_handled` sends its signal number back to the stub.
The RSP backend uses the signal-bearing `Cxx`/`Sxx` `vCont` forms only when
the stub advertises those actions. For a single-process peer without the
matching `vCont` action, the standard legacy `Cxx`/`Sxx` packet is used where
the resume path can target the stopped thread safely. For scheduled resumes,
an omitted disposition preserves and redelivers the pending signal, while
`handled` suppresses it. A schedule may set a disposition only on the thread
owning the pending stop. Signal actions require exactly two hex digits and an
exact, validated thread identity. If the peer does not advertise the required
signal action, resume returns unsupported and leaves the stop pending. A
schedule cannot use `stop` for the pending signal's owner: that action cannot
redeliver the signal, and acknowledging the stop would otherwise discard its
disposition state. Rejecting it keeps the event available for retry.

The local `hexlab-debug-server` advertises `C`/`S` signal actions only when its
active backend supports scheduled signal disposition. It accepts legacy
`Cxx`/`Sxx` and thread-qualified `vCont;Cxx:tid`/`vCont;Sxx:tid` actions. Signal
zero suppresses the stopped signal; a nonzero signal is accepted only when it
matches the signal number on the pending exception event, because the shared
debugger API can redeliver that event's signal but cannot substitute a
different one. An unqualified signal action is rejected for a multi-thread
target to prevent broadcasting the event owner's signal. Ordinary `c`/`s`
actions suppress the owner's pending signal, matching the RSP zero-signal
behavior. A stopped owner with no matching explicit action keeps its pending
signal queued when another thread is selected to run. Rejected actions leave
the stop event available for retry.
Multiprocess `W`/`X` exits retain their `process` field and only transition the
session to exited when that field identifies its process. Missing or foreign
exit identity reports unsupported rather than marking another process exited.

The initial `ProcessInfo` uses the process component of `pPID.TID` when present.
Stopped events retain that process component separately from the opaque local
thread token. Register selection requires a known token returned by a stop or
thread listing; an unknown token is rejected rather than interpreted as a raw
wire ID. Stop and enumeration IDs must name concrete positive threads, not the
`0`/`-1` selector forms.

Register snapshots use the bulk `g` packet when available. If the stub returns
the protocol's empty unsupported-packet response and target XML supplies a
register layout, the backend falls back to bounded `p` reads for each register
(at most 256 registers) and validates every reply against its declared width.
A malformed non-empty `g` response is rejected instead of hidden by the
fallback. Without usable target XML, the client continues to expose the raw
bulk-register bytes because it has no safe way to identify individual
registers.

## Linux auxiliary vector

When `qSupported` advertises `qXfer:auxv:read`, the debugger's **Auxv** tab
retrieves the target's Linux auxiliary vector through `qXfer:auxv:read`. The
client requests bounded chunks using the negotiated packet limit and accepts
the protocol's `m`/`l` continuation markers. Empty first replies mean the
annex is unavailable; malformed markers, zero-progress continuation, truncated
annexes, and data beyond the 1 MiB cap are errors. The transfer uses the normal
RSP transaction path, so stop notifications remain queued and transport errors
or disconnects are reported; the desktop drops stale refresh results after a
session change.

Decoding requires usable target XML metadata that identifies a supported
32-bit or 64-bit architecture and declares byte order (or names an architecture
with an explicit byte order). PowerPC word width comes from an explicit 32/64
architecture marker or a 32/64-bit PC register; ambiguous width is unsupported.
Each entry is read as two target words, capped at 4,096 entries, and the sequence must end with a final
`AT_NULL` record whose value is zero. The UI presents numeric type IDs and
hexadecimal values, including the terminator. Unsupported architectures,
missing target XML, and stubs that do not advertise the annex return
`unsupported`; no host architecture, pointer width, or byte order is guessed. Other operating
systems' auxv formats and architecture-specific symbolic names are not decoded.

## Signal information

When `qSupported` advertises `qXfer:siginfo:read`, a stopped remote session
can retrieve the signal-information object through `DebugSession::signal_info()`.
HexLab preserves the target's opaque bytes because the object follows the target
operating system's and architecture's `siginfo_t` layout. The reader uses
bounded binary qXfer chunks and caps the object at 64 KiB. The Signal info view
can optionally decode the fixed three-int header as Linux 32-bit or 64-bit
`siginfo_t` after explicit user selection. Remote decoding requires a declared
byte order in the target description; the signal-specific union remains raw,
and the selected Linux layout is not inferred from architecture alone.
Unsupported or empty annexes report `unsupported`.

When `qSupported` advertises `qXfer:osdata:read`, `DebugSession::processes()`
reads the standard `processes` annex and returns its decimal PID values with
the optional `command` column as each process name. The bounded XML reader
accepts the standard `osdata.dtd` declaration and predefined/numeric XML
entities, rejects malformed or duplicate PIDs, and caps the document at 1 MiB
and the process list at 4,096 entries. Missing command columns fall back to
`process <pid>`. Stubs without this feature continue to report process
enumeration as unsupported; listing does not attach to or change the selected
remote process.

For other target-provided operating-system tables, `DebugSession::os_data(type)`
reads the named annex (for example `cpus` or `procgroups`) and preserves each
`<item>` as named `column` values. The root `<osdata type="...">` must match
the requested type. XML is capped at 1 MiB, each response chunk is bounded by
the negotiated packet size, and results are capped at 4,096 rows, 64 columns
per row, and 4,096 bytes per column. Entity expansion is limited to the five
predefined XML entities and numeric character references; DTDs are not fetched
or expanded. The process convenience API continues to require a unique positive
decimal `pid` column and uses `command` when available.

The desktop debugger exposes the generic API in the **OS data** tab beside
Memory and Auxv. Enter an annex type such as `cpus` or `procgroups` and choose
**Read table** (or press Enter). Results render each target row with its column
names and values (embedded control characters are escaped onto one display
line per column). The request runs on the serialized inspection worker; a
result is discarded if the target session changes, a newer request starts, or
the type field changes while the read is in flight. Display text is capped at
4 MiB, while the protocol reader's stricter document, row, column, and value
bounds remain in force. Unsupported annexes and targets show the backend error
in the view.

If the stub also advertises `qXfer:exec-file:read`, the process list enriches
the selected process name with its full target-side executable path. Multiprocess
sessions query the selected hexadecimal PID; a single-process session uses the
empty annex for the current inferior. The transfer uses bounded `m`/`l` chunks,
rejects zero-progress, malformed, embedded-NUL, and oversized replies, and does
not query every listed process. An unsupported or empty annex keeps the existing
`command`/`process <pid>` label. The path is target-side metadata and does not
load that executable or change the host image being analyzed. This follows the
[GDB executable-file read packet](https://sourceware.org/gdb/current/onlinedocs/gdb.html/General-Query-Packets.html).

Remote target XML architecture names are mapped conservatively to HexLab's
architecture enum for x86/x86-64, AArch32/AArch64, RV32/RV64, MIPS32/MIPS64,
and PowerPC. Variant suffixes are accepted only for the corresponding GDB
architecture family; unknown names remain `unknown`. Repeated recognized
architecture declarations must agree or the target description is rejected
as malformed. This metadata does not infer an execution mode. Byte order comes
from the target XML `endian` attribute, or from an explicit AArch64 endian
architecture name when that attribute is absent; conflicting declarations
are rejected. The name field follows GDB's target-description architecture element, which uses
an architecture accepted by GDB's `set architecture` command
([GDB target-description format](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Target-Description-Format.html)).

Remote hardware execute and data watchpoints retain owned IDs, kind and size.
RSP has no standard `qSupported` feature token for individual watchpoint kinds,
so support is negotiated by sending the requested `Z2`, `Z3`, or `Z4` tuple:
`OK` records ownership, while the protocol's empty unsupported-packet response
returns `unsupported` and records no local breakpoint. The backend sends the
requested byte length unchanged; the stub remains responsible for accepting or
rejecting the target's alignment and hardware range constraints. The public
RSP client also rejects zero-length and address-overflowing tuples before I/O.
The common `DebugSession::set_breakpoint_enabled` operation sends `z` to
disable or `Z` to re-enable the exact owned tuple, preserving its local ID.
Duplicate wire tuples (including hardware/execute aliases) report conflict
before sending another `Z` packet, preventing one local owner from removing a
trap still claimed by another. Empty or overflowing ranges are rejected.
In multiprocess mode, breakpoint changes require a current stopped thread in
the session process and explicitly select it before sending `Z`/`z`, since
register inspection may have selected another inferior. Foreign-process stop
reasons never acquire this session's breakpoint IDs.
For targets identified as AArch64 by target XML, execute size `1` in the shared
API becomes instruction kind `4` in `Z1`/`z1`; software `Z0`/`z0` likewise uses
four bytes. Watchpoint sizes remain byte lengths. Stop replies with a watchpoint
reason and an address within an enabled owned range populate `breakpoint_ids`.
The stop parser accepts `watch`, `rwatch`, and `awatch` reason values only as
one to sixteen hexadecimal digits and rejects duplicate stop fields (including
duplicate watchpoint reasons). A malformed reason therefore fails the stop
transaction instead of reaching breakpoint ownership matching.
Execute/software hits require an explicit matching reason and `pc` address;
generic traps or replies without an address do not guess ownership.

Memory writes use the binary `X` packet first and fall back to hexadecimal `M`
when a peer replies with the protocol's empty unsupported-packet response. Both
forms are split into bounded chunks using the peer's advertised `PacketSize`;
binary chunk sizing reserves worst-case RSP escaping expansion, so arbitrary
bytes cannot exceed the negotiated wire payload limit.

When `qSupported` advertises `QNonStop+`, the remote backend requests `QNonStop:1`; peers that do not support the request remain in all-stop mode. In non-stop mode, `%Stop:` notifications use the normal RSP checksum and escaping rules and carry no `+`/`-` acknowledgement byte. HexLab acknowledges each stop through the `vStopped` sequence, including additional synchronous stop replies and the terminating `OK`. Stop notifications that arrive while another command response is being read are retained for the next `wait_stop_reply` call, and the backend maps them through the regular `DebugSession` event path. The pending queue is bounded to 4,096 stop replies and to the configured aggregate packet-byte budget; exceeding either bound returns `resource_limit` from the in-flight operation. The session exposes one stop event at a time, while the remote target may continue other threads; unqualified continue resumes the exact stopped thread in non-stop mode. `DebugSession::thread_run_states()` provides a token-keyed snapshot with `unknown`, `running`, `stopped`, and `exited` states for every RSP thread known to the session. Thread-list XML seeds or refreshes the snapshot when it includes state; stop notifications update the owning thread; thread-created/thread-exited reasons update lifecycle state; and successful resume schedules update only the threads named by their actions. An all-stop notification marks all known threads stopped, while non-stop notifications change only their identified thread. `request_interrupt()` does not predict a stop: state changes only as stop notifications arrive. The snapshot retains known exited threads and may omit threads not yet observed or enumerated. When a legacy all-stop step has no identified thread, the backend marks active-thread states `unknown` rather than guessing which one ran. `SessionState` remains a coarse session summary, and the common API still acknowledges one stop event at a time, so simultaneous pending-event ownership is not modeled. A multiprocess target that reports no initial stop and therefore provides no process identity is rejected rather than assigned to an arbitrary process.

`DebugSession::request_thread_interrupt(thread)` adds an explicit thread-targeted
stop request for remote targets. It requires a running session, an exact known
running thread token, negotiated non-stop mode, and `vCont;t` support. HexLab
sends `vCont;t:THREAD-ID` and waits for the peer's asynchronous stop reply; it
does not mark the thread stopped when sending the request. A reply with signal
zero for the requested thread becomes an `interrupted` event. Other backends,
all-stop RSP peers, and peers without the advertised `t` action return
unsupported. The operation is rejected while another stop event is awaiting
acknowledgement, so it does not provide simultaneous pending-event ownership.
At most 4,096 requested thread IDs are retained until corresponding stop
replies arrive. The current API has no per-request cancellation token; the
transport's configured RSP timeout still bounds the packet exchange.
See the [GDB vCont packet reference](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Packets.html).

Notification packets are also consumed while the client waits for an ACK in
ACK mode, for both ordinary requests and resume packets. Valid stop notifications
are queued without acknowledging them, then the ACK wait continues. This avoids
discarding a stop that races with the packet ACK. A command response packet
received before its ACK is reported as a protocol error instead of silently
being consumed. Notification payloads retain the same queue-count and aggregate
byte limits.

## Target termination

`DebugSession::terminate()` is distinct from detach: it requests target process
termination and transitions the session to `exited` only after the backend
accepts the request. Native backends still report termination as unsupported
until they implement their platform-specific process control.

For a remote stub that advertised `multiprocess+`, HexLab uses `vKill;pid` with
the process component from the initial stopped thread ID (`pPID.TID`). It
requires an `OK` response and will not fall back to `k`, because `k` may kill
more than the selected process on multiprocess targets. After a successful
`vKill;pid`, the selected inferior's known threads are marked exited and the
multiprocess connection stays open so the caller can enumerate or attach to a
remaining inferior. If no process component was supplied, termination reports
unsupported rather than guessing.

For a single-process RSP connection, HexLab sends the `k` kill request. The
protocol defines no packet reply for `k`; successful transport write is treated
as request acceptance, and the connection is closed locally. Since remote stubs
may close the connection after receiving the request, HexLab does not wait for
an ACK or stop reply. This follows the packet's no-reply semantics in the
[GDB Remote Serial Protocol packet reference](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Packets.html).

## Remote console output packets

The client recognizes GDB `O<hex-data>` console-output packets while waiting for
an acknowledgement, an ordinary command reply, or a stop notification. In
acknowledgement mode it acknowledges valid output packets and continues waiting
for the command's real response; in no-ack mode it likewise consumes the packet
as asynchronous output. The payload is decoded to raw bytes and queued under a
1 MiB aggregate bound. Malformed hexadecimal and queue overflow fail the
in-flight protocol operation instead of becoming a misleading command result.

`RspBackend` delivers queued bytes as `EventKind::output` events. Rendered event
messages stay within the common 4 KiB debugger-message limit; because escaping
can use four characters per byte, a chunk may contain at most 1 KiB of raw
console data. The desktop debugger's existing output pane displays these events.
Newline, carriage return, and tab remain readable; other control bytes and
non-ASCII bytes are rendered as `\\xNN` because the remote console byte
encoding is not declared by RSP. Output events do not consume stop-event tokens
or change the session's running/stopped state. If a stop reply follows queued
output, the backend retains it and returns it after the output chunks have been
drained.

While the target is stopped, `rsp::Client::run_monitor_command()` sends a
printable, non-NUL command as hex in `qRcmd,COMMAND`. The client captures only
console bytes received during that transaction, including intermediate
`O<hex-data>` packets and an optional final hex-encoded output reply; `OK`
means there is no final output payload. Empty replies report unsupported, and
malformed command replies fail without being treated as output. Commands are
limited to 4,096 bytes and the negotiated packet size; captured output is
limited to 1 MiB. `DebugSession::run_remote_monitor_command()` is available
only while stopped, and native backends report unsupported. The desktop
**Remote monitor** tab sends a command asynchronously and displays up to 64 KiB
of its output, escaping non-printable bytes; results are discarded if the
session or pending stop changes before completion. Monitor command names and
semantics are stub-specific, and HexLab does not provide a command allowlist.
The remote stub may let a command alter or resume the target; HexLab does not
infer those side effects or refresh stop ownership from the command response,
so use commands that leave the current stop intact.
See the [GDB qRcmd packet reference](https://sourceware.org/gdb/current/onlinedocs/gdb.html/General-Query-Packets.html).

## Passed signals

After negotiation, callers can replace the remote target's `QPassSignals` set
when the stub advertises `QPassSignals+`. The client requires 1–256 strictly
increasing signal numbers in the 8-bit RSP signal range, encodes each as
hexadecimal, checks the negotiated `PacketSize`, and treats only an exact `OK`
as success. An empty or malformed list is rejected before I/O. The target then
passes listed signals directly to the inferior while reporting other signals
to the debugger; each packet replaces the previous list. The client does not
change signal handling unless the caller explicitly invokes this API. See the
[GDB QPassSignals packet](https://sourceware.org/gdb/current/onlinedocs/gdb.html/General-Query-Packets.html#QPassSignals).

`DebugSession::set_remote_pass_signals()` exposes this operation to C++ session
clients. It is accepted only while a target is stopped, validates the complete
1–256 item strictly increasing list before sending a packet, and forwards
cancellation to the RSP client. Native backends return `unsupported`; remote
stubs without the advertised feature also return `unsupported`. An acknowledged
packet replaces the stub's previous pass-through list. RSP has no standard
readback, so the API reports the packet result and does not claim to know the
stub's signal policy after a transport failure.

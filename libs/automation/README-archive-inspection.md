# Native archive inspection

`Archive` provides thread-affine, read-only access to Unix `ar` archives through
the native automation SDK. The `hexlab_archive_inspect` example uses the symbol
index to resolve exported names to member metadata, then reads at most eight
bytes from each matching regular member. It never buffers a whole object.

Build with `HEXLAB_BUILD_AUTOMATION_EXAMPLES=ON`, then run:

```text
hexlab_archive_inspect library.a
hexlab_archive_inspect library.a initialize
```

The optional argument filters symbol names by substring. Symbol and member
queries are paged (up to 4096 rows); member reads are limited to 1 MiB per call
and reject reads extending past the member. The example reads only the first
eight bytes. An archive without a symbol index still reports its summary and
returns no symbol rows. Incomplete indexes remain explicitly reported by the
summary and the available indexed rows are shown.

`Archive::open` currently accepts Unix `ar` archives, including GNU thin and
AIX big archives recognized by the loader. The API can list special members,
but `read_member` supports regular members only; thin external members require
external-root resolution and are not read by this service. This example does
not extract members, open them as projects, or interpret object formats. Keep
each `Archive` object on the thread that opened it; page calls made on another
thread return a conflict error. The API's opening operation accepts a stop
token, while the current synchronous summary/page/member-read calls have no
cancellation parameter.

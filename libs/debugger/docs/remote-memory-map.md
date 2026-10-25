# Remote memory maps

`hexlab_debug_server` exports the native target's memory regions using
`qXfer:memory-map:read`. A HexLab remote session can therefore populate its
memory-region view and run `DebugSession::search_memory()` with the same
readable, writable, and executable filters as a native session. No UI or
session API changes are required.

## Negotiation and transfer

The server advertises `qXfer:memory-map:read+` in `qSupported` only when the
backend returns a nonempty, valid map that fits the transfer bounds. An
unsupported, oversized, overlapping, or malformed native map is not
advertised or partially exported.

The request format is `qXfer:memory-map:read::OFFSET,LENGTH`, with hexadecimal
offsets and lengths. A zero offset starts a new snapshot; subsequent chunks
read that same XML string, even if the client repeats a chunk or reaches the
end. Successful execution resume discards the snapshot. A fresh transfer
after the next stop reads the updated native map.

Replies use the standard `m` (more) and `l` (last) markers. The server may
return fewer bytes than requested: each chunk contains at most 4095 XML
bytes, reserving space for the marker and worst-case RSP escaping within
the advertised 8192-byte packet bound. An offset at or beyond the XML end
returns `l`. Invalid hexadecimal ranges, zero lengths, out-of-bounds
offsets, and inspection failures return `E01`. Requests for an unadvertised
memory map return the empty unsupported reply.

## Region metadata

Each native region becomes one XML `memory` element. Writable regions use
the standard `ram` type; other regions use `rom`. HexLab adds two properties
to preserve information that those standard types cannot express:

```xml
<memory-map>
  <memory type="rom" start="0x140001000" length="0x2000">
    <property name="permissions">r-x</property>
    <property name="hexlab-type">image/committed</property>
  </memory>
  <memory type="rom" start="0x140003000" length="0x1000">
    <property name="permissions">---</property>
    <property name="hexlab-type">private/reserved</property>
  </memory>
</memory-map>
```

`permissions` has exactly three positions: `r` or `-`, `w` or `-`, and `x`
or `-`. These flags override type-derived defaults in the HexLab client.
This preserves execute-only, guarded, reserved, and inaccessible regions
without making them eligible for readable-memory search. `hexlab-type`
preserves the native descriptive label, including paths and an empty
label. XML entities in labels are escaped by the server and decoded by
the client.

Maps from other RSP servers remain supported. Without the properties,
HexLab retains the previous defaults: every region is readable, only
`ram` is writable, no region is assumed executable, and the XML memory
type is the label. Unknown properties are ignored. Duplicate recognized
properties, invalid permission values, invalid XML entities, and
overlapping or wrapping regions produce errors instead of a partial map.
Other RSP clients may ignore the properties and see only the standard
`ram`/`rom` approximation.

## Bounds and validation follow-up

The XML object is limited to 1 MiB and each native label to 32 KiB. Both
server and client enforce the session limit of 65536 regions. The byte
limit often imposes a lower practical region limit. The server sorts
regions by start address and rejects zero-length, overlapping, or wrapping
extents. Native labels containing XML-forbidden ASCII control characters
are rejected. No region is dropped to fit the limits.

The implementation touches the existing debugger library and server
targets only. Build those targets serially before checking a live remote
connection. Useful checks are a multi-chunk map transfer; `r-x`, `rw-`,
`--x`, and `---` permission round trips; labels containing `&` and `<`;
snapshot continuity across chunks; and map refresh after a resume/stop.
Also retain coverage for standard property-free maps and malformed or
overlapping input. No build or tests were run as part of this change.

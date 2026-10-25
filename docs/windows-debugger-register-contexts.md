# Windows debugger register contexts

The native Windows backend reads and writes registers for one selected thread
through `Backend::read_registers(ThreadId)` and
`Backend::write_registers(ThreadId, span)`. The desktop register list uses
those same per-thread values: each row retains its API name, group, byte order,
and exact byte width; the editor submits only the selected value and refreshes
that thread after a successful write.

For native x64 targets, the backend exposes general-purpose registers, the
FXSAVE x87/control state (`fcw`, `fsw`, `ftw`, `fop`, `fip`, `fdp`, `mxcsr`,
and `st0`-`st7`), and `xmm0`-`xmm15`. When the host CPU and Windows extended
context APIs enable AVX, it also exposes `ymm0`-`ymm15`. FXSAVE scalar fields
are little-endian; x87 values are 10 bytes, MXCSR is 4 bytes, XMM values are
16 bytes, and YMM values are 32 bytes. XMM and YMM writes address overlapping
low lanes; submitting both aliases for one index is accepted only when those
low 16 bytes agree. YMM writes require a pending debug stop and an available
AVX XState component.

For x86 targets under a 64-bit debugger (WOW64) and for a 32-bit debugger, the
backend exposes x86 general registers and the 32-bit FXSAVE view: x87/control
state, `mxcsr`, `st0`-`st7`, and `xmm0`-`xmm7`. Register writes validate names,
byte widths, and little-endian encoding before applying the complete thread
context. AVX/YMM state for WOW64 and 32-bit debugger builds is not exposed.

Windows ARM64 builds expose `x0`-`x30`, `sp`, `pc`, `cpsr`, `v0`-`v31`,
`fpcr`, and `fpsr`; `x18` remains read-only because Windows reserves it as the
thread environment pointer. The ARM64-specific branch remains conditional on
an ARM64 build and still needs target-host validation. ARM32 thread-context
mapping remains unsupported and returns an explicit error. The backend does
not claim a complete Windows XSAVE view: AVX-512/ZMM/opmask, WOW64 AVX, and
ARM32 context state remain unavailable.

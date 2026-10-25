# Windows x64 SIMD register inspection

The native Windows x64 backend exposes `xmm0` through `xmm15` as sixteen
little-endian bytes in the `vector` group. At a stopped debug event, supported
systems additionally expose `ymm0` through `ymm15` as thirty-two bytes. A YMM
value consists of its XMM lower half followed by its AVX upper half. AVX and
AVX2 share this register-state layout; AVX2 instruction support is not required
to inspect YMM storage.

The x64 build resolves `GetEnabledXStateFeatures`, `InitializeContext`,
`GetXStateFeaturesMask`, `LocateXStateFeature` and `SetXStateFeaturesMask`
dynamically from kernel32. YMM support requires all five APIs, CPUID XSAVE,
OSXSAVE and AVX bits, and OS-enabled SSE plus AVX state. Missing APIs or
unavailable state do not create synthetic YMM registers: general-register and
XMM reads retain their existing fallback, while an explicit YMM write returns
`unsupported`. YMM writes require a pending stopped debug event and a native
x64 target; another target/build is unsupported and a running target is busy.

The extended context follows Windows' two-call size/initialization protocol,
with a one-MiB allocation ceiling. The returned context pointer must be aligned,
inside the allocation and carry every requested context flag. The AVX feature
must have the x64 256-byte extent, remain within that allocation, and not overlap
the legacy context. No feature offsets are hardcoded. The requested mask is
checked before capture; the returned validity mask is checked afterward. When
the AVX valid bit is absent, Windows reports architectural INIT state and the
upper halves are zero; the undefined saved feature bytes are never exposed.

Lower XMM halves come from the captured legacy floating-point component;
upper halves come from AVX XSTATE feature 2. Only that extended feature is
requested. The legacy snapshot retains x87 and MXCSR state for preservation,
but neither is exposed for editing by this feature.

`write_registers` accepts exactly 32 bytes for `ymm0` through `ymm15`, with
little-endian byte order when specified. It captures all sixteen upper halves,
changes only the requested register bytes, and preserves every other upper
half. XMM-only edits retain their existing legacy-context path and leave upper
YMM state untouched. Matching XMM/YMM aliases may be edited in one batch;
conflicting lower halves or conflicting duplicate vector values reject the
whole batch before `SetThreadContext`. Invalid names, widths or vector byte
orders also reject the batch. Input order does not change alias results.

A YMM batch commits once, with only AVX selected in the extended feature mask.
Legacy context flags are narrowed to floating-point state plus any integer or
control group explicitly edited in the same batch. Unedited legacy fields are
retained from the stopped-thread snapshot. No debug-register or additional
XSTATE component is submitted, and editing a saved XMM/YMM value does not
simulate a VEX instruction's upper-lane clearing behavior.

WOW64 x86 keeps its existing general-register set. ARM targets and non-x64
builds do not gain YMM access. ZMM, opmask, AVX-512 upper state, x87 editing and
MXCSR editing remain outside this slice. Unsupported context layouts and
feature availability produce `unsupported`; other native context failures
retain Win32 error details. No builds or tests were run for this change, and
live Windows AVX INIT/non-INIT reads, alias writes and unrelated-state
preservation still require runtime validation.

References: [Microsoft XSTATE context workflow](https://learn.microsoft.com/en-us/windows/win32/debug/working-with-xstate-context),
[context validity masks](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getxstatefeaturesmask),
[feature location and bounds](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-locatexstatefeature),
and [feature selection for context updates](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setxstatefeaturesmask).

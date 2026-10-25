# PE live-context unwinding

`hexlab/image/pe_unwind.hpp` exposes a debugger-independent, one-frame PE unwinder. Callers provide a stopped-thread register snapshot as named byte arrays and a callback that reads exact target-memory ranges. The input snapshot is copied; errors never return partial caller state. AMD64 names include `rax` through `r15`, `rsp`, `rip`, and `xmm6` through `xmm15`; ARM64 names include `x0` through `x30`, `sp`, `pc`, `fp`, `lr`, `d0` through `d31`, and extended `q`, `z`, `p`, `sve_vl`, `vg`, and `sm` state as required by metadata. PE scalar and vector values are little-endian.

AMD64 metadata evaluation applies parsed `UWOP_PUSH_NONVOL`, stack allocation, frame-register setup, nonvolatile GPR saves, XMM128 saves, and machine-frame operations. It honors the current PC within the prolog, evaluates chained unwind records with a 32-record bound, then recovers the return address and caller stack pointer. ARM64 evaluation handles canonical packed records including saved integer/floating-point registers and frame-chain forms, resolves validated `.pdata` parent links, and evaluates xdata allocation, GPR/FP save, frame-pointer, `save_next`, SVE vector/predicate, and end-marker opcodes. ARM64 prolog/epilog position selects the applicable portion of its unwind sequence. `alloc_z`, `save_zreg`, and `save_preg` require an `sve_vl` context value in bytes, a multiple of 16 from 16 to 256. `pac_sign_lr` and packed CR=2 report unsupported because authentication keys are not part of the supplied snapshot.

All reads are limited to the exact scalar or vector width needed, with an upper bound of 256 bytes. Address arithmetic is checked. Missing/wrong-width registers, short reads, out-of-range PCs, invalid metadata, excessive operation/link depth, absent SVE state, and unsupported authentication return explicit `Result` errors. FH3 and ARM64 language metadata and actual handler invocation remain outside this API.

For AMD64 FH4 C++ records, `plan_pe_fh4_exception` complements the one-frame
OS unwinder. It uses the stopped PC to select the function's current EH state,
follows bounded unwind-map prior-state links, and returns source-backed cleanup
actions in execution order. Destructor-object actions resolve their frame
object address; destructor-pointer actions read one 64-bit stack slot through
the supplied memory reader and preserve both slot and object addresses. It also
returns all handlers attached to active try states with their type descriptor,
catch object, handler RVA, and continuation addresses. A supplied decorated
exception type is compared by exact identity; absent type info leaves typed
catches indeterminate. The API never calls cleanup or catch code. Type
conversions and rethrow processing remain unsupported and are reported
conservatively. Callers can identify the exception kind as C++, non-C++, or
unknown. The plan reports a source-backed `handler_candidate` only for the
first provable match in serialized try/handler order: exact decorated type or
catch-all with no earlier unresolved candidate. It reports `ambiguous` when
earlier type matching, unsupported adjectives, or an unknown exception kind
prevents safe selection. For non-C++ exceptions, an FH4 EHs bit yields
`continue_search` while retaining active-handler metadata. For C++ exceptions
with no provable active match, a `noexcept` function that is not a catch
funclet yields `terminate_noexcept`; otherwise the plan says to continue
searching outer frames. These are metadata classifications only: the API does
not perform OS dispatch, match C++ base-class conversions, process rethrows,
or invoke cleanup/catch code. The `non_cxx` kind describes ordinary foreign
exceptions; longjmp and unwind-consolidation records are not separately modeled
and should be passed as `unknown`.

The evaluator source is registered in the image library, and `hexlab_pe_live_unwind_tests` is registered as CTest `pe_live_unwind`.

The unwind encodings and partial-prolog/epilog rules follow [Microsoft's ARM64 exception-handling reference](https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling?view=msvc-170) and the AMD64 `UNWIND_INFO` format. The live evaluator consumes HexLab's validated normalized metadata; it does not parse PE bytes itself.

The desktop debugger adapts stopped-thread registers and exact process-memory reads into this API for AMD64 and ARM64 PE modules. It builds a caller chain only while recovered PCs stay in the selected module, SP advances, and PCs remain unique. The caller SP is exposed as that frame's CFA, while recovered registers are retained on the selectable frame for DWARF local evaluation. ARM64 native `X29`/`X30` names are normalized to the API's `fp`/`lr` aliases. Unsupported recipes stop the walk without adding a guessed frame.

# x87 Environment Reset Semantics

The caller-driven `evaluate_x87_clear_exceptions` helper models FNCLEX's
status-word update. It clears FSW bits 0–7 (IE, DE, ZE, OE, UE, PE, SF, ES)
and bit 15 (B), while preserving TOP and condition codes C0–C3. The decoder
therefore reports FSW as both read and written for FNCLEX.

`evaluate_x87_initialize` models FNINIT's default control and abstract stack
state: FCW is `0x037f`, FSW is zero, TOP is zero, and all eight physical
register tags are empty. The register payload bits are unspecified by this
abstract result; callers should not interpret them as zero. FIP, FDP, FOP,
MXCSR, and machine exception delivery are outside this helper. The existing
`transfer_x87_stack_state` analysis already applies the same TOP/tag reset for
decoded FNINIT/FINIT.

These are instruction-result helpers. The waiting FINIT/FCLEX aliases may
first deliver a previously pending exception; `evaluate_x87_pending_exception`
remains the caller-owned mechanism for that sequencing. FNINIT/FNCLEX do not
generate a new arithmetic exception as part of these reset operations.

The reset values and cleared status bits follow Intel's [x87 instruction
reference](https://cdrdv2-public.intel.com/671110/325383-sdm-vol-2abcd.pdf),
entries FCLEX/FNCLEX and FINIT/FNINIT.

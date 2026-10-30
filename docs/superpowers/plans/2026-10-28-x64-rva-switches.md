# x86-64 base-relative dword switch implementation plan

Implement the dispatched switch-analysis slice in the shared workspace. Keep
`analysis.switches` partial and retain the existing ambiguity fallback. No tests,
commits, or artifact deletion are requested.

- Extend the existing same-block RIP-relative LEA reaching-definition recognizer
  to distinguish signed MOVSXD table offsets from unsigned MOV dword entries.
  Require the exact contiguous load/add/jump tail and validated register widths.
- Compute unsigned-form table addresses from the proven base plus the checked
  indexed-load displacement; add each zero-extended dword to the proven base.
  Reject associated relocation/fixup slots because their equations do not prove
  this unsigned base-relative encoding. Preserve executable decode checks,
  4096-entry bounds, guard proof, cancellation, and verified-prefix diagnostics.
- Expose encoding, selector-use and base-definition addresses, selector width,
  and base relocation rows through the analysis API and CLI JSON. Document the
  supported form and remaining gaps.
- Coordinate a serial focused analysis/CLI build with the parent agent; inspect
  compiler output and the final diff. Do not add or run tests.

Validation: the parent-coordinated serial Windows Debug `hexlab_cli` build in
`.agent-x86-bmi1-build` exited 0. Its log records compilation of the switch and
CLI sources and a successful CLI link. Focused `git diff --check` passed with
only the repository's LF/CRLF warnings. No tests were added or run.

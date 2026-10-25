# Analysis, Debugger, and Managed-Code Wave

## Objective

Advance three major HexLab subsystems toward an IDA-class native analysis environment: general static analysis, interactive debugging, and managed-code exception analysis.

## Workstreams

1. **Analysis engine:** inspect function recovery and reference propagation for a high-impact cross-CFG or cross-function gap. Implement an end-to-end bounded improvement that reduces unresolved control/data references across supported architectures. Own `libs/analysis` and analysis docs only.
2. **Debugger workflow:** the desktop debugger currently performs register, memory, module, region, and local inspection synchronously. Implement a substantial responsive inspection workflow with safe stale-result handling across session/thread changes. Own debugger library code, `apps/desktop/debugger*`, and debugger docs only.
3. **Managed-code analysis:** CIL metadata, method decoding, lifting, and finally/catch handling already exist, while exceptional dispatch and filter/fault clauses remain incomplete. Extend bounded managed exception/control-flow analysis end to end through body decoding and lifting. Own managed loader and CIL-lifting sources/docs only.

## Constraints

- The desktop may be launched if visual inspection materially helps, but keep work headless otherwise.
- Leave `out/` untouched.
- Do not add or run tests. Focused Debug compilation is allowed.
- Keep file ownership separate; root owns `docs/capabilities.csv` and integration review.
- Preserve cancellation, byte/record/work budgets, and conservative rejection of malformed control-flow metadata.

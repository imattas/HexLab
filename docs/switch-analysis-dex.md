# DEX switch analysis

`analyze_switch_tables` now returns a `SwitchSite` for a DEX `packed-switch`
or `sparse-switch` instruction when its payload can be validated. The site
reports the dispatch address, payload address, selector virtual register,
case count, signed case keys (stored in the generic unsigned `index` field by
their 32-bit representation), decoded destinations, and the instruction's
fall-through address as the default destination when it can be represented.

These cases come from DEX payload metadata, not from interpreting the payload
as pointer or relative-offset slots. The site uses `decoded_metadata` as its
entry encoding. Payload validation remains bounded to 1024 cases and checks
payload kind, alignment, method containment, initialized bytes, key ordering,
case-target bounds, and exclusion of payload bytes as targets. Malformed
payloads return the existing validation error. The analyzer does not infer a
selector value range, resolve switch targets through later code, or add JVM
`tableswitch`/`lookupswitch` support.

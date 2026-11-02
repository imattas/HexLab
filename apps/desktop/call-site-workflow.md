# Inspect calls across analysis views

Use **Navigate > Inspect Calls in Function...** (`Ctrl+Alt+C`) from a mapped
listing or graph selection. The Functions table's recovered-function context
menu exposes the same command. In the decompiler, **Inspect calls...** uses
the rendered function and selects the call matching the selected source line's
verified instruction origin, when one exists. An unmapped source line opens
the current function's call list without inventing a source address.

The browser shows incoming, outgoing, and recursive call sites from the
immutable recovered-function snapshot. Filter by direction, caller, target,
call instruction address, or assigned prototype. Direct, external, unresolved
indirect, and tail-candidate facts remain distinguishable. External identities
are labels; the browser never converts import ordinals or Wasm function indices
to executable addresses.

Select a call and choose a destination:

| Action | Result |
| --- | --- |
| Call listing / Enter | Open the exact call instruction in Disassembly. |
| Caller CFG | Switch to the function CFG at the call instruction, requesting the CFG even if the Graph page previously showed a call graph. |
| Caller pseudocode | Show the docked decompiler at the call instruction. |
| Call evidence | Open outgoing xrefs at the call instruction, including unresolved or imported provenance. |
| Callee pseudocode | Show the recovered callee body, enabled only for an identified recovered function. |
| Target xrefs | Open incoming xrefs at the concrete target address. |
| Target prototype | Select the assigned type definition in Types & Symbols; reveal the address's Assignments page when it has no available definition. |

Navigation synchronizes the shared address selection, Functions context,
listing, graph, and pseudocode through the normal MainFrame path and adds the
destination to navigation history. Prototype edits use the existing undoable
type editor and assignment commands; reopen Inspect calls to see the updated
prototype after editing. Explicit prototype navigation clears a type or
assignment filter if needed to reveal the destination.

The chooser retains its source snapshot while open. A document switch, close,
new document revision, or replacement project snapshot cancels the chosen
navigation before applying it. Pseudocode entry additionally checks its
document and project revision token. Address-space IDs are retained throughout.
Overlapping function ownership requires entering through a specific rendered
function rather than guessing an owner.
Destination graph/decompiler ownership still uses the existing address-based
resolver; shared bodies can select its first recovered owner. The browser does
not add a function-ID override to those views.

The browser requires fresh or incomplete current function analysis with an
exact matching analysis key. It scans at most 1,000,000 recovered call facts
and displays at most 4,096 related rows, with a visible omission notice.
Snapshots above 100,000 functions or 262,144 function chunks are rejected with an explanatory message.
Incomplete analysis is labeled, and address-dependent actions stay disabled
for symbolic/unresolved destinations. This workflow does not recover new
indirect targets, edit generated pseudocode, or promise complete call coverage.

Implementation is confined to desktop components. `call_site_browser.cpp`
owns the bounded immutable chooser; MainFrame owns revision checks and view
dispatch; PseudocodeView supplies verified origins; TypeSymbolsView reveals
the target assignment/definition. Validation for this change is local Windows
and WSL desktop compilation. No tests were added or run, as requested; GUI
interaction has not been validated in this session.

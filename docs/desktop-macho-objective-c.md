# Desktop Mach-O Objective-C inspection

The Binary Metadata notebook includes an Objective-C page for the currently
displayed Mach-O document snapshot. The bounded `scan_macho_objc_classes`
scanner runs when this page is selected; before the first selection, the page
shows a prompt instead of scanning during ordinary document loading. Results
are cached for that immutable document snapshot and refreshed when a different
snapshot is selected. The page shows classes, metaclasses, categories,
protocols, methods, properties, ivars, class/category protocol references, and
protocol adoption references. It reports scanner completeness and field
statuses directly, alongside section/index or record-entry provenance.

Activate an addressable row to navigate through the desktop's existing address
navigation callback. Method rows prefer a validated implementation address and
fall back to the method entry. Rows without a validated target remain visible
and are not navigable. The desktop retains the flattened rows for the same
document snapshot so refreshing other Binary Metadata pages does not rescan it.

The flattened desktop view is capped at 250,000 rows. This is a presentation
limit only; it does not change the scanner result, its budgets, or project
persistence. A partial or unavailable scan remains labeled with its status and
reason. Unsupported runtime forms are shown only as the scanner reports them;
the view does not infer runtime relationships.

The page filter searches kind, owner, name, address, status, provenance, and details
case-insensitively. Filtering is debounced while typing and preserves each
visible row's original address target. The filter affects only the displayed
rows; it does not change the scan or type-import plan.

Use **Copy selected row** to copy the selected visible record as labeled text,
including its full kind, owner, name, address, status, provenance, and details
fields. This preserves long metadata values that may be clipped in the table.
After copying, the status line reports the clipboard result; the filter and
underlying scan remain unchanged.

Selecting a method row with a validated implementation enables **Pseudocode at
implementation**. It navigates through the existing document/revision guard,
selects that implementation, and opens the synchronized pseudocode page. Rows
with only a method-entry address cannot invoke this action.

The **Import Objective-C types** action writes eligible declarations into the
current project through the normal project command/history path. It creates
`ObjC2.Class.<name>` declarations with an exact instance size when every
decoded ivar has a supported type, matching encoded size, and a resolved,
non-overlapping offset. Unmodeled bytes are retained as opaque byte arrays so
the imported offsets and extent remain exact. Parsed instance method
signatures are attached to the class aggregate. Class methods are attached to
an incomplete `ObjC2.Meta.<name>` aggregate only when the scanner validated a
metaclass address. The parsed method signature retains its receiver and
selector parameters.

The action accepts only a scan of the currently displayed document snapshot.
Names above the project's 512-byte limit and method lists above the persistent
type codec's 100,000-method limit are skipped with diagnostics. Layouts above
the codec's 100,000-member limit retain eligible method signatures as
incomplete aggregates. An ineligible
record does not prevent eligible declarations from the same scan from being
imported. The planner also respects the project's type-record limit.

Types retain project provenance naming the Mach-O ObjC2 class-list or
metaclass record, its class-list index, metadata address, and instance size
when known. Reimporting identical definitions is a no-op. A same-name type
with different content or provenance is reported as a conflict and left
untouched. The import reports records skipped because their layouts or
addresses are not proven. If multiple runtime records resolve to the same
class name, all records for that name are skipped so duplicate declarations
cannot make the atomic project import fail. It does not infer superclass storage, property
backing ivars, protocol conformance methods, category overrides, or a
metaclass object layout. When an instance layout cannot be represented but
parsed instance methods exist, the class declaration is retained as an
incomplete aggregate with those methods.

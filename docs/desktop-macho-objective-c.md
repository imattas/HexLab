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
Click a column header to sort the displayed rows by that column. Clicking the
same header reverses the direction; choosing another column starts ascending.
Text comparisons are case-insensitive, with exact text and original scan order
as deterministic tie-breakers. Sorting composes with the current filter and
retains the selected record when it remains visible; navigation, pseudocode,
and copy actions continue to resolve through the original scan-row mapping.

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

Validated class property declarations also synthesize instance getter and,
unless readonly, setter signatures on the class aggregate. Explicit method
encodings take precedence when they declare the same selector. These
signatures retain typed `self`, `_cmd`, and setter value parameters; property
metadata does not add or rename instance storage.

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
cannot make the atomic project import fail.

Superclass storage is imported when each superclass address links exactly to a
scanned class with a unique resolved name and validated instance layout. The
planner builds ancestors before descendants regardless of class-list order.
Each derived aggregate embeds its concrete superclass storage at offset zero
as `__objc_super`; inherited ivars remain visible inside that member. The
embedded aggregate contains storage only, so inherited methods retain their
own class declarations. Its bytes do not depend on resolving a same-name
project definition. Any gap after the base and before local ivars remains
opaque. Local ivars must begin at or beyond `class_ro_t.instanceStart`, and
the superclass size cannot exceed that boundary.

The superclass walk is iterative and capped at 32 classes, including the root.
Cycles, unresolved or unscanned bases, ambiguous class identities, invalid
ancestor layouts, conflicting generated member names, and overlapping base
storage produce skip diagnostics and retain eligible local methods in an
incomplete class declaration. Superclass alignment and runtime instance
sliding are not inferred. The existing byte alignment and exact runtime
metadata offsets are preserved. Property backing ivars, protocol conformance
methods, category overrides, and metaclass object layouts are not inferred.

For each class's directly adopted protocols, the scanner now checks required
instance and class method selectors against that class's validated methods and
the validated methods of scanned categories attached to it. Each requirement
reports its selector, implementation entry, and status in the Binary Metadata
protocol-reference row. Missing selectors are reported only when the overall
scan and relevant method lists are complete; otherwise the result is explicitly
unverified. This does not follow inherited protocol adoption or prove runtime
conformance across dynamically loaded libraries. The type-import action creates
an incomplete `ObjC2.Protocol.<name>` aggregate for each uniquely named,
address-validated protocol record. It retains parsed required and optional
instance/class method signatures, plus accessor signatures for parsed protocol
properties. Protocol declarations carry the protolist section, index, metadata
address, and runtime record size when known as project provenance. Duplicate protocol
names, unresolved records, and protocols without parsed signatures are skipped.
If the same instance or class selector has differing parsed method/property
signatures, the protocol is not imported and the conflict is reported with the
selector name; identical repeated signatures are coalesced.
The type system has no required-versus-optional method marker, so imported
signatures do not retain that distinction. Adopted-protocol inheritance and
runtime conformance are not encoded as storage or inheritance relationships.

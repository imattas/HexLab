# Desktop Mach-O Objective-C inspection

The Binary Metadata notebook includes an Objective-C page for the currently
displayed Mach-O document snapshot. The page uses the existing bounded
`scan_macho_objc_classes` result and shows classes, metaclasses, categories,
protocols, methods, and properties. It reports scanner completeness and field
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

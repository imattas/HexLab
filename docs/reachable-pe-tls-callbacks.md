# PE TLS callbacks in reachable analysis

Entry-seeded reachable instruction analysis treats validated PE TLS callbacks
as additional roots. The callback's normalized RVA is translated using the
mapped image base, preferring the mapped headers segment when present and
otherwise using the PE preferred base. A callback is queued only when its
result resolves to an allowed initialized executable code start.

This captures callback bodies that the loader invokes before or after the
ordinary PE entry point. It does not model the TLS callback parameters,
callback ordering, detach notifications, or runtime execution conditions.
Invalid or overflowing callback targets are skipped, and indirect control
flow inside callback code still follows the normal explicit-stop rules.

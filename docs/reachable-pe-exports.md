# PE exports in reachable analysis

Entry-seeded reachable instruction analysis includes every address-bearing PE
export as a root. This finds exported routines even when the image has no
usable symbol or debug records for them. The root is queued only when its
address is an allowed initialized executable code start. Multiple names or
ordinals for the same address are deduplicated in the returned candidate list
and instruction traversal.

Forwarded exports have no code address in the current image and are not roots.
This does not follow the forwarder into another supplied module, infer internal
function boundaries, or model export invocation order. Indirect branches from
an exported routine still use the ordinary reachable-analysis resolution and
stop behavior.

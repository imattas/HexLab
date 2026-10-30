# DEX annotation directory graph

The DEX loader retains the reachable annotation container graph alongside the
existing deduplicated annotation items and flattened target links. This exposes
information that flattening loses: an explicitly present empty set, an empty
directory/list, and null annotation-set references at particular parameter
positions. It applies to the ordinary supported DEX v035–v040 files and does
not extend optimized/container loading or verifier behavior.

`DexClassDefinition::annotations_offset` preserves the original class_def
pointer: zero means no directory. Each `DexAnnotationDirectory` retains the
owning class_def index, complete source extent, class-set offset and ordered
field/method/parameter-method entry arrays. Entries retain the member index,
target container offset and exact eight-byte row location. Field/method
entries target sets; parameter-method entries target set-ref lists. Directories
are retained per owning class_def, even if multiple classes reference the same
physical directory.

`DexAnnotationSet` retains its complete source extent and ordered indexes into
`DexMetadata::annotations`; its vector may be empty. Set entry N occupies four
bytes at `file_offset + 4 + 4*N`, and its original target offset is the referenced
annotation item's file offset. `DexAnnotationSetRefList` retains every original
32-bit set offset, including zero positions. Its slot N uses the same four-byte
source formula. A nonzero slot can reference a present empty set; zero means
absent annotations for that prototype parameter. Slots exclude an implicit
receiver and must match the method prototype's parameter count, rather than
Dalvik register-word count. Sets and set-ref lists are deduplicated by physical
offset and retained in first-encounter order. Annotation items also retain their
complete visibility-plus-encoded-annotation byte size.

The existing parser checks container alignment/data-section extents, ordered
member indexes and actual ownership, declared members, prototype slot counts,
strict annotation type ordering and element-name ordering. The graph adds no
unchecked offset walks: it is published only after those validations succeed.
Set caching now stores indexes into the retained catalog instead of copying a
set's index vector for every target. A shared set still yields the appropriate
flattened links for each owning class/member/parameter.

Container objects, directory rows, set indexes and retained parameter offsets
are charged before allocation to the existing 64 MiB annotation-model budget.
The existing caps remain: 250,000 annotation items; one million unique sets,
set entries, directory entries, visited parameter slots and flattened links.
Directories are also bounded by the 250,000-class limit and model budget;
reachable ref lists are bounded by directory entries and model budget. Existing
encoded-value limits remain 250,000 nodes, 64 MiB accounted data and 64 nesting
levels, shared with other encoded-value users. Cancellation checks remain on
directory, set, item and parameter loops. Only graph containers reachable from
class_def annotation pointers are retained; this is not an inventory of every
unreferenced item advertised by map_list.

CLI file/project inspection prints at most 128 directories, sets, parameter
lists, annotation items and flattened links per category. Container entries are
capped at 16 per directory category/set/list and 256 overall; value previews at 16 per visited list,
256 total and eight nesting levels. It reports physical extents, member targets,
parameter positions, present-empty sets, absent parameter slots, visibility
labels, annotation type/element names and raw encoded-value bits or indexes.
Names use the existing 160-byte escaped preview. Omission counts distinguish
top-level rows from entries in shown containers and immediate values in visited
lists, without traversing pruned subtrees. Scalar/IEEE payloads remain raw bits.

No annotation declaration validation, retention-policy enforcement, bootstrap
execution, external type binding, application semantics or bytecode verifier
claim is made. There is no dedicated desktop annotation page in this slice.
The layout follows AOSP's [DEX annotation containers and items](https://source.android.com/docs/core/runtime/dex-format#annotations_directory_item).

For method targets, a system-visibility `dalvik.annotation.Throws` annotation
is additionally decoded into a declared-exception row. The loader requires one
`value` element encoded as an array of class-value entries, validates every
type_id index, and retains the method index plus the array-value and annotation
link offsets. The original annotation item and graph are preserved unchanged.
Rows and their type indexes share the existing 64 MiB annotation-model budget
and a one-million-row ceiling. CLI output is capped at 256 methods and 16 type
descriptors per method, with omission counts. This is metadata presentation
only: the loader does not resolve the class hierarchy, prove that listed types
derive from `Throwable`, or treat the annotation as verifier evidence. Other
visibility values and annotation types remain available in the raw graph.

#include "hexlab/workspace/project.hpp"
#include "hexlab/workspace/listing.hpp"
#include "hexlab/workspace/navigation.hpp"
#include "hexlab/analysis/derived_cache.hpp"
#include "hexlab/analysis/relocations.hpp"
#include "support/macho_chained_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/fixture_files.hpp"
#include "support/checks.hpp"
using namespace hexlab;
using namespace hexlab_test;
using namespace hexlab_test::macho_fixture;
namespace {
template <class T> T take(Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message);
    return std::move(value.value());
}
constexpr Address slot{{0}, UINT64_C(0x100000000)};
constexpr Address entry{{0}, slot.offset + 256};
constexpr Address callee{{0}, slot.offset + 332};
std::vector<std::byte> flow(bool bound) {
    auto data = chained();
    put(data, symtab_command(true) + 12, 0, 4, false);
    const auto main = append_command(data, true, false, 0x80000028, 24);
    put(data, main + 8, 1024, 8, false);
    put(data, 768, (UINT64_C(2) << 51) | callee.offset, 8, false);
    data[1024] = std::byte{0xff};
    data[1025] = std::byte{0x15};
    put(data, 1026, static_cast<std::uint32_t>((bound ? slot.offset + 8 : slot.offset) - (entry.offset + 6)), 4, false);
    data[1030] = data[1100] = data[1116] = std::byte{0xc3};
    return data;
}
void calls_and_slots() {
    for (bool bound : {false, true}) {
        const auto loaded = take(load_macho(std::make_shared<MemoryStorage>(flow(bound)), {}, {}));
        const auto functions = take(recover_functions(*loaded.image, loaded.metadata, {}, {}, {}));
        const auto expected = bound ? std::optional<Address>{} : std::optional{callee};
        check(functions->calls.size() == 1 && functions->calls[0].target == expected,
              "shared recovery uses actual dyld pointer value and never a runtime bind placeholder");
        const auto coarse = take(analyze(*loaded.image, loaded.metadata, {}, {}));
        bool edge_found = false;
        for (const auto &edge : coarse.edges)
            if (edge.from == entry && (edge.kind == EdgeKind::call || edge.kind == EdgeKind::unresolved_call))
                edge_found = edge.to == expected;
        check(edge_found, "coarse and rooted recovery agree on dyld indirect targets");
        DocumentSnapshot doc;
        doc.image = loaded.image;
        doc.metadata = loaded.metadata;
        const auto page = take(make_listing_page(doc, entry, 1));
        check(page.rows.size() == 1 && page.rows[0].control_target == expected,
              "manual listing Follow shares dyld source resolution");
        const auto refs = take(derive_references(*loaded.image, *functions, loaded.metadata, {}, {}));
        bool code = false, memory = false;
        const Address stored_at{{0}, slot.offset + (bound ? 8 : 0)};
        for (const auto &ref : refs->all()) {
            if (ref.source != Location{entry})
                continue;
            if (ref.kind == ReferenceKind::memory_read)
                memory = std::holds_alternative<Location>(ref.target) &&
                         std::get<Location>(ref.target) == Location{stored_at} && ref.provenance.dyld != nullptr;
            if (ref.kind == ReferenceKind::call) {
                code = ref.provenance.dyld && ref.association == Location{stored_at};
                if (bound)
                    code = code && std::holds_alternative<UnresolvedTarget>(ref.target) &&
                           std::get<UnresolvedTarget>(ref.target).reason == UnresolvedReason::macho_dyld &&
                           ref.provenance.dyld->resolution.binding &&
                           ref.provenance.dyld->resolution.binding->name == "_ext";
                else
                    code = code && std::holds_alternative<Location>(ref.target) &&
                           std::get<Location>(ref.target) == Location{callee};
            }
        }
        check(memory && code,
              "reads target the slot, calls target its proven contents, and both own original dyld provenance");
        const auto pure = take(decode_at(*loaded.image, entry));
        check(pure.instruction && !pure.instruction->direct_target && pure.instruction->bytes[0] == std::byte{0xff},
              "pure instruction bytes and decode-only indirect status remain unchanged");
    }
}
std::vector<std::byte> encoded(unsigned variant) {
    auto data = dyld(true);
    put(data, symtab_command(true) + 12, 0, 4, false);
    segment(data, true, false, 32, slot.offset - 768, 4096, 0, 4096, 7, 0, 3);
    const auto bss = 32 + 72 + 2 * 80;
    put(data, bss + 48, 784, 4, false);
    put(data, bss + 64, 0, 4, false);
    const auto main = append_command(data, true, false, 0x80000028, 24);
    put(data, main + 8, 1024, 8, false);
    if (variant == 0) {
        data[1024] = std::byte{0xe8};
        put(data, 1025, 0, 4, false);
        stream(data, true, false, 0, {0x13, 0x20, 0x81, 0x08, 0x51, 0});
        data[1029] = std::byte{0xc3};
    } else if (variant == 1) {
        data[1024] = std::byte{0x48};
        data[1025] = std::byte{0xb8};
        put(data, 1026, callee.offset, 8, false);
        stream(data, true, false, 0, {0x11, 0x20, 0x82, 0x08, 0x51, 0});
        data[1034] = std::byte{0xc3};
    } else {
        data[1024] = std::byte{0x0f};
        data[1025] = std::byte{0x84};
        put(data, 1026, 0, 4, false);
        stream(data, true, false, 0, {0x13, 0x20, 0x81, 0x08, 0x51, 0});
        data[1030] = std::byte{0xc3};
    }
    data[1100] = std::byte{0xc3};
    return data;
}
void encoded_fields() {
    for (unsigned variant = 0; variant < 3; ++variant) {
        const auto loaded = take(load_macho(std::make_shared<MemoryStorage>(encoded(variant)), {}, {}));
        const auto functions = take(recover_functions(*loaded.image, loaded.metadata, {}, {}, {}));
        const auto refs = take(derive_references(*loaded.image, *functions, loaded.metadata, {}, {}));
        bool expected = false;
        for (const auto &ref : refs->all()) {
            if (ref.source != Location{entry} || !ref.provenance.dyld)
                continue;
            if (variant == 0)
                expected = ref.kind == ReferenceKind::call && std::holds_alternative<UnresolvedTarget>(ref.target) &&
                           ref.provenance.dyld->use == MachODyldUse::encoded_field;
            else if (variant == 1)
                expected = ref.kind == ReferenceKind::dyld_fixup && std::holds_alternative<Location>(ref.target) &&
                           std::get<Location>(ref.target) == Location{callee};
            else
                expected = ref.kind == ReferenceKind::dyld_fixup && !ref.operand_index &&
                           ref.provenance.dyld->use == MachODyldUse::instruction_bytes;
        }
        check(expected, "encoded pointer, relative branch and rewritten opcode retain distinct owned meanings");
        if (variant == 0)
            check(functions->calls.size() == 1 && !functions->calls[0].target,
                  "relative CALL fixup cannot produce a false zero-displacement callee");
        if (variant == 1)
            check(functions->instructions.size() == 2,
                  "fixup inside an immediate field permits decoding the complete instruction and return");
        if (variant == 2)
            check(functions->instructions.size() == 1 && functions->calls.empty() && functions->blocks.size() == 1 &&
                      functions->blocks[0]->successors.empty(),
                  "opcode rewrite stops automatic traversal before false conditional edges");
        const auto wire = take(encode_reference_index(*refs, {}));
        check(take(encode_reference_index(*take(decode_reference_index(wire, {})), {})) == wire,
              "decoded encoded-field and opcode provenance roundtrip canonically");
    }
}
void storage_and_cancellation() {
    auto data = flow(false);
    put(data, 768, (UINT64_C(2) << 51) | (slot.offset + 8), 8, false);
    auto loaded = take(load_macho(std::make_shared<MemoryStorage>(data), {}, {}));
    auto functions = take(recover_functions(*loaded.image, loaded.metadata, {}, {}, {}));
    check(functions->calls.size() == 1 && !functions->calls[0].target,
          "a pointer to another fixup slot cannot become a code callee");
    const auto first_main = 32 + field32(data, 20) - 24;
    put(data, first_main + 8, 768, 8, false);
    loaded = take(load_macho(std::make_shared<MemoryStorage>(data), {}, {}));
    functions = take(recover_functions(*loaded.image, loaded.metadata, {}, {}, {}));
    check(functions->instructions.empty(), "entry points inside known dyld storage never decode pointer words as code");
    const auto resolver = take(RelocationResolver::create(*loaded.image, loaded.metadata, {}));
    std::stop_source canceled;
    canceled.request_stop();
    const auto start = resolver.code_start(slot, canceled.get_token());
    check(!start && start.error().code == ErrorCode::canceled, "dyld code-start lookup honors cancellation");
}
void project_follow_and_patch() {
    FixtureFile input(flow(false));
    const auto path = std::filesystem::path(input.path.wstring() + L".flow.hxproj");
    auto store = take(database::ProjectStore::create(path, {}));
    auto source = take(FileStorage::open(input.path));
    take(store->import_input(*source, {Format::macho, {}, {}}, input.path, {}));
    source.reset();
    auto session = take(ProjectSession::attach(store, {}, {}));
    take(session->execute(Rename{entry, "dyld_call_owner"}, 0, {}));
    check(take(project_follow_target(*session->snapshot(), entry)) == callee,
          "actual project Follow uses the proven callee rather than its pointer slot");
    take(session->execute(PatchBytes{FileOffset{768}, bytes({0x5c})}, 0, {}));
    const auto stale = project_follow_target(*session->snapshot(), entry);
    check(!stale && stale.error().code == ErrorCode::conflict,
          "pointer-byte patches immediately block stale project Follow");
    take(session->refresh_analysis({}));
    check(take(project_follow_target(*session->snapshot(), entry)) == Address{{0}, callee.offset + 16},
          "refresh rederives the call target from patched pointer bytes");
    take(session->undo({}));
    take(session->refresh_analysis({}));
    check(take(project_follow_target(*session->snapshot(), entry)) == callee,
          "undo restores source-proven original callee navigation");
    const auto before = session->snapshot()->state;
    session.reset();
    store.reset();
    check(std::filesystem::remove(input.path), "owned source removed before readonly embedded-input reopen");
    store = take(database::ProjectStore::open(path, database::ProjectMode::read_only, {}));
    session = take(ProjectSession::attach(store, {}, {}));
    const auto snapshot = session->snapshot();
    check(snapshot->derived_cache_status == database::CacheStatus::hit &&
              take(project_follow_target(*snapshot, entry)) == callee && snapshot->state->uuid == before->uuid &&
              snapshot->state->revisions == before->revisions && *snapshot->state->user == *before->user &&
              snapshot->state->history_cursor == before->history_cursor,
          "readonly cache restores decoded dyld navigation, UUID, revisions and user history");
    session.reset();
    store.reset();
    std::error_code ignored;
    for (auto suffix : {L"", L"-wal", L"-shm"}) {
        auto file = path;
        file += suffix;
        std::filesystem::remove(file, ignored);
    }
}
void source_bound_query_cache() {
    for (unsigned variant = 0; variant < 4; ++variant) {
        const auto data = variant == 3 ? flow(false) : encoded(variant);
        const auto loaded = take(load_macho(std::make_shared<MemoryStorage>(data), {}, {}));
        AnalysisKey key;
        key.input = {loaded.image->storage()->size(), take(hash_source(*loaded.image->storage(), {}))};
        key.engine_fingerprint = function_engine_fingerprint();
        auto proposal = take(
            analyze_derived(loaded.image, std::make_shared<const ImageMetadata>(loaded.metadata), {}, {}, key, {}));
        const auto wire = take(encode_derived(proposal, {}));
        check(bool(decode_derived(wire, *loaded.image, loaded.metadata, {}, {}, key, {})),
              "source-bound derived cache accepts genuine decoded dyld query semantics");
        auto rows = std::vector<Reference>(proposal.references->all().begin(), proposal.references->all().end());
        bool changed = false;
        for (auto &ref : rows) {
            if (ref.source != Location{entry} || !ref.provenance.dyld || ref.provenance.dyld->queries.empty())
                continue;
            auto proof = std::make_shared<MachODyldReferenceProvenance>(*ref.provenance.dyld);
            // Still overlaps the same original fixup and stays within the instruction.
            // A checksum and freshly assigned IDs cannot prove this narrower query was decoded.
            --proof->queries[0].width;
            if (proof->queries[0].field)
                --proof->queries[0].field->size;
            ref.provenance.dyld = std::move(proof);
            ref.id = {0};
            changed = true;
        }
        check(changed, "query-forgery regression actually changes decoded source provenance");
        auto index = ReferenceIndex::create(std::move(rows), key, proposal.references->complete(), {});
        bool rejected = !index;
        if (index) {
            proposal.references = std::move(index.value());
            const auto forged = take(encode_derived(proposal, {}));
            rejected = !decode_derived(forged, *loaded.image, loaded.metadata, {}, {}, key, {});
        }
        check(rejected, "recomputed IDs and valid checksum cannot forge decoded dyld query spans");
    }
}
} // namespace
int main() {
    return run([] {
        calls_and_slots();
        encoded_fields();
        storage_and_cancellation();
        project_follow_and_patch();
        source_bound_query_cache();
    });
}

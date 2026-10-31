#include "hexlab/analysis/derived_cache.hpp"
#include "hexlab/analysis/graph.hpp"
#include "hexlab/loaders/pe.hpp"
#include "hexlab/workspace/project.hpp"
#include "hexlab/workspace/listing.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include "support/pe_fixture.hpp"
#include <algorithm>
using namespace hexlab;
using namespace hexlab_test;
namespace {
constexpr DecodeContext legacy{Architecture::x86, ExecutionMode::x86_32, ByteOrder::little};
std::shared_ptr<const Image> image32(std::vector<std::byte> data) {
    auto source = std::make_shared<MemoryStorage>(std::move(data));
    ImageLayout layout{{{0}, 32, 1, ByteOrder::little},
                       Architecture::x86,
                       ExecutionMode::x86_32,
                       {{"code", {{0}, 0x1000}, source->size(), {0}, source->size(), true, false, true}},
                       {{{0}, 0x1000}}};
    return Image::create(source, std::move(layout)).value();
}
AnalysisKey key_for(const Image &image) {
    AnalysisKey key;
    key.input = {image.storage()->size(), hash_source(*image.storage(), {}).value()};
    key.engine_fingerprint = function_engine_fingerprint();
    return key;
}
void recovery_tests() {
    auto image = image32(bytes({0x40, 0xe8, 1, 0, 0, 0, 0xc3, 0xc3}));
    auto decoded = decode_at(*image, {{0}, 0x1000});
    check(decoded && decoded.value().instruction && decoded.value().instruction->opcode == Opcode::inc,
          "shared decode treats legacy 40 as INC");
    auto reached = analyze(*image, {}, {});
    check(reached && reached.value().instructions.size() == 4,
          "legacy reachable analysis follows call and continuation");
    auto key = key_for(*image);
    auto metadata = std::make_shared<const ImageMetadata>();
    auto result = analyze_derived(image, metadata, {}, {}, key, {});
    check(bool(result), "legacy complete-derived service accepts explicit mode");
    if (!result)
        return;
    auto &p = result.value();
    check(p.context == legacy && p.functions->functions.size() == 2 && p.functions->calls.size() == 1,
          "legacy recovery discovers separate caller and callee");
    check(std::all_of(p.functions->instructions.begin(), p.functions->instructions.end(),
                      [](auto &f) { return f->instruction.context == legacy; }),
          "every recovered fact carries legacy context");
    check(p.references->incoming(Address{{0}, 0x1007}, {}).value().total == 1, "legacy call has literal typed target");
    auto encoded = encode_derived(p, {}).value();
    auto restored = decode_derived(encoded, *image, *metadata, {}, {}, key, {});
    check(restored && restored.value().context == legacy && restored.value().functions->instructions.size() == 4,
          "legacy cache validates and restores actual typed facts");
    auto graph = build_graph(*p.functions, *p.references, GraphKind::image_calls, {}, {}, {}, {}).value();
    check(graph->nodes.size() == 2 && graph->edges.size() == 1, "legacy call graph reflects recovered functions");
    AnalysisDecisions decisions;
    decisions.regions.push_back({1, {{0}, 0x1000}, 1, RegionKind::data});
    auto blocked = recover_functions(*image, {}, decisions, {}, {}).value();
    check(blocked->instructions.empty(), "legacy manual data prevents rooted traversal");
    auto truncated = recover_functions(*image32(bytes({0xe8, 1})), {}, {}, {}, {}).value();
    check(truncated->instructions.empty() && !truncated->complete,
          "legacy truncated transfer publishes no invented instruction");
    auto loop = recover_functions(*image32(bytes({0xeb, 0xfe})), {}, {}, {}, {}).value();
    check(loop->instructions.size() == 1 && loop->blocks.size() == 1 && loop->complete,
          "legacy loop recovery terminates");
    auto shared_bytes = std::vector<std::byte>(17);
    shared_bytes[0] = std::byte{0xeb};
    shared_bytes[1] = std::byte{14};
    shared_bytes[8] = std::byte{0xeb};
    shared_bytes[9] = std::byte{6};
    shared_bytes[16] = std::byte{0xc3};
    ImageMetadata exports;
    exports.exports.push_back({1, "second", Address{{0}, 0x1008}, {}});
    auto shared = recover_functions(*image32(shared_bytes), exports, {}, {}, {}).value();
    check(shared->functions.size() == 2 &&
              std::any_of(shared->blocks.begin(), shared->blocks.end(),
                          [](auto &block) { return block->begin.offset == 0x1010 && block->owners.size() == 2; }),
          "legacy shared tail records both function owners");
    auto partial = recover_functions(*image32(bytes({0xc5, 0xf8, 0x77})), {}, {}, {}, {}).value();
    check(partial->instructions.size()==1 && partial->instructions[0]->instruction.opcode==Opcode::x86_opaque &&
              !partial->complete && !partial->functions.empty() &&
              partial->functions[0]->stops[0].reason == FunctionStopReason::unsupported,
          "opaque legacy decode retains exact boundary and explicit partial frontier");
    std::stop_source stop;
    stop.request_stop();
    auto canceled = analyze_derived(image, metadata, {}, {}, key, stop.get_token());
    check(!canceled && canceled.error().code == ErrorCode::canceled, "legacy recovery observes cancellation");
}
void atomic_integer_recovery_tests() {
    auto image = image32(bytes({0x0f, 0xc1, 0xc8,       // xadd eax, ecx
                                0xf0, 0x0f, 0xb1, 0x08, // lock cmpxchg [eax], ecx
                                0xc3}));
    auto metadata = std::make_shared<const ImageMetadata>();
    auto recovered = analyze_derived(image, metadata, {}, {}, key_for(*image), {});
    check(bool(recovered), "legacy atomic update stream recovers through shared analysis");
    if (!recovered)
        return;
    const auto &instructions = recovered.value().functions->instructions;
    auto xadd = std::find_if(instructions.begin(), instructions.end(), [](const auto &i) {
        return i->instruction.opcode == Opcode::xadd;
    });
    auto cmpxchg = std::find_if(instructions.begin(), instructions.end(), [](const auto &i) {
        return i->instruction.opcode == Opcode::cmpxchg;
    });
    check(instructions.size() == 3 && xadd != instructions.end() && cmpxchg != instructions.end() &&
              (*cmpxchg)->instruction.lock_prefix && (*cmpxchg)->instruction.memory_read &&
              (*cmpxchg)->instruction.memory_write && (*cmpxchg)->instruction.context == legacy,
          "analysis publishes atomic update opcodes, lock and memory effects with the x86-32 context");
    auto encoded = encode_derived(recovered.value(), {});
    if (!encoded) {
        check(false, "atomic update facts encode into the complete-derived cache");
    } else {
        auto restored = decode_derived(encoded.value(), *image, *metadata, {}, {}, key_for(*image), {});
        check(restored && std::any_of(restored.value().functions->instructions.begin(),
                                      restored.value().functions->instructions.end(), [](const auto &i) {
                                          return i->instruction.opcode == Opcode::cmpxchg && i->instruction.lock_prefix;
                                      }),
              "complete-derived cache roundtrip retains new atomic opcode identity and lock semantics");
    }
}
void reference_tests() {
    // Absolute disp32, absolute disp16, BX+SI and a signed imm8 widening to 32.
    auto image = image32(
        bytes({0x8b, 0x05, 0x34, 0x12, 0, 0, 0x67, 0x8b, 0x06, 0x34, 0x12, 0x67, 0x8b, 0, 0x83, 0xc0, 0xff, 0xc3}));
    auto p = analyze_derived(image, std::make_shared<const ImageMetadata>(), {}, {}, key_for(*image), {});
    check(bool(p), "legacy reference source recovers");
    if (!p)
        return;
    auto &refs = *p.value().references;
    check(refs.incoming(Address{{0}, 0x1234}, {}).value().total == 2,
          "legacy displacement-only references never add IP");
    auto dynamic = refs.outgoing(Address{{0}, 0x100b}, {}).value();
    check(dynamic.rows.size() == 1 && std::holds_alternative<UnresolvedTarget>(dynamic.rows[0].target),
          "legacy BX+SI expression remains unresolved");
    auto &expression = std::get<MemoryOperand>(std::get<UnresolvedTarget>(dynamic.rows[0].target).expression);
    check(expression.address_width == 16 && !expression.ip_relative,
          "16-bit addressing is retained in typed reference");
    auto &instruction = p.value().functions->instructions[3]->instruction;
    auto immediate = std::get<ImmediateOperand>(instruction.operands[1]);
    check(immediate.encoded_width == 8 && immediate.effective_width == 32 && immediate.is_signed &&
              immediate.value == UINT32_MAX,
          "legacy signed immediate preserves encoded and effective widths");
}
void incremental_tests() {
    auto image = image32(bytes({0x40, 0x90, 0xc3}));
    auto metadata = std::make_shared<const ImageMetadata>();
    auto key = key_for(*image);
    auto p = analyze_derived(image, metadata, {}, {}, key, {});
    check(bool(p), "legacy incremental basis recovers");
    if (!p)
        return;
    AnalysisBasis old{image, metadata, {}, {}, {}, key, p.value().functions, p.value().references, p.value().strings};
    old.metadata_reads_complete = true;
    auto next = image32(bytes({0x48, 0x90, 0xc3}));
    auto revised = key;
    ++revised.byte_revision;
    FileRange change{{0}, 1};
    auto plan = plan_invalidation(old, std::span(&change, 1), {}, revised, {}).value();
    auto changed = reanalyze(old, next, metadata, {}, plan, revised, {}).value();
    check(changed.counters.reused_instructions == 2 && changed.counters.decoded_instructions == 1 &&
              changed.functions->instructions[0]->instruction.opcode == Opcode::dec,
          "legacy local patch reuses unaffected facts");
    auto foreign_layout = image->layout();
    foreign_layout.architecture = Architecture::x86_64;
    foreign_layout.mode = ExecutionMode::x86_64;
    foreign_layout.space.width_bits = 64;
    auto foreign = Image::create(image->storage(), foreign_layout).value();
    auto same = plan_invalidation(old, {}, old.decisions, key, {}).value();
    auto unexpected_context = reanalyze(old, foreign, metadata, {}, same, key, {});
    check(unexpected_context && unexpected_context.value().context == foreign->decode_context() &&
              unexpected_context.value().counters.reused_instructions == 0,
          "unannounced mode changes force a fresh analysis without reusing old facts");
    auto fresh_key = key;
    ++fresh_key.byte_revision;
    ReadSet header;
    header.include({0}, 1).value();
    old.metadata_reads = header;
    auto full = plan_invalidation(old, std::span(&change, 1), {}, fresh_key, {}).value();
    auto replacement = reanalyze(old, foreign, metadata, {}, full, fresh_key, {}).value();
    check(replacement.context == foreign->decode_context() && replacement.counters.reused_instructions == 0,
          "loader-invalidated mode change retires every legacy fact");
}
void document_tests() {
    auto data = pe_fixture(false);
    data[0x200] = std::byte{0x40};
    FixtureFile file(data);
    OpenRequest request;
    request.path = file.path;
    auto document = load_document(request, {}, {}).value();
    check(document->image->decode_context() == legacy && document->analysis &&
              document->analysis->instructions[0].opcode == Opcode::inc,
          "PE32 document enables real legacy analysis");
    auto listing = make_listing_page(*document, Address{{0}, 0x401000}, 2).value();
    check(listing.rows.size() == 2 && listing.rows[0].instruction && listing.rows[0].instruction->context == legacy,
          "PE32 listing carries source context");
}
void source_boundary_tests() {
    struct ShortStorage final : ByteStorage {
        std::shared_ptr<const ByteStorage> source;
        explicit ShortStorage(std::shared_ptr<const ByteStorage> input) : source(std::move(input)) {}
        uint64_t size() const noexcept override { return source->size(); }
        Result<ByteView> read_at(FileOffset at, size_t count) const override {
            auto view = source->read_at(at, count);
            if (!view)
                return view.error();
            if (count)
                view.value().bytes = view.value().bytes.first(count - 1);
            return view;
        }
    };
    auto original = image32(bytes({0x90, 0xc3}));
    auto broken = Image::create(std::make_shared<ShortStorage>(original->storage()), original->layout()).value();
    auto decoded = decode_at(*broken, {{0}, 0x1000});
    check(!decoded && decoded.error().code == ErrorCode::io,
          "short backing read cannot fabricate a decoded instruction");
    check(!analyze(*broken, {}, {}), "reachable analysis rejects short backing reads");
    check(!recover_functions(*broken, {}, {}, {}, {}), "function recovery rejects short backing reads");
    auto supported_layout = original->layout();
    supported_layout.mode = ExecutionMode::x86_16;
    supported_layout.space.width_bits = 16;
    auto supported = Image::create(original->storage(), supported_layout).value();
    auto reached16 = analyze(*supported, {}, {});
    auto recovered16 = recover_functions(*supported, {}, {}, {}, {});
    check(reached16 && reached16.value().instructions.size() == 2 && recovered16 &&
              recovered16.value()->instructions.size() == 2 &&
              recovered16.value()->instructions[0]->instruction.context.mode == ExecutionMode::x86_16,
          "shared services accept a declared default16 logical domain");
    for (auto context : {DecodeContext{Architecture::x86, ExecutionMode::unknown, ByteOrder::little},
                         DecodeContext{Architecture::x86, ExecutionMode::x86_32, ByteOrder::big},
                         DecodeContext{Architecture::x86_64, ExecutionMode::x86_32, ByteOrder::little}}) {
        auto layout = original->layout();
        layout.architecture = context.architecture;
        layout.mode = context.mode;
        layout.space.order = context.order;
        auto unsupported = Image::create(original->storage(), layout).value();
        auto result = decode_at(*unsupported, {{0}, 0x1000});
        check(!result && result.error().code == ErrorCode::unsupported && !analyze(*unsupported, {}, {}),
              "shared consumers reject unsupported context combinations");
    }
}
struct ProjectFixture {
    FixtureFile input;
    std::filesystem::path path;
    std::shared_ptr<database::ProjectStore> store;
    std::shared_ptr<ProjectSession> session;
    explicit ProjectFixture(std::vector<std::byte> data) : input(data), path(input.path.wstring() + L".mode.hxproj") {
        store = database::ProjectStore::create(path, {}).value();
        auto source = FileStorage::open(input.path).value();
        store->import_input(*source, {Format::pe, {}}, input.path, {}).value();
        session = ProjectSession::attach(store, {}, {}).value();
    }
    ~ProjectFixture() {
        session.reset();
        store.reset();
        std::error_code ignored;
        for (auto suffix : {L"", L"-wal", L"-shm"}) {
            auto file = path;
            file += suffix;
            std::filesystem::remove(file, ignored);
        }
    }
};
void project_tests() {
    auto pe64 = pe_fixture();
    put(pe64, 0xb0, 0x400000, 8);
    pe64[0x200] = std::byte{0x40};
    ProjectFixture f(pe64);
    const Address entry{{0}, 0x401000};
    auto before = f.session->snapshot();
    check(before->functions && before->functions->instructions.size() == 1 &&
              before->functions->instructions[0]->instruction.length == 2,
          "long-mode source treats 40 as prefix before header edit");
    f.session->execute(Rename{entry, "mode_entry"}, 0, {}).value();
    auto header = pe_fixture(false);
    header.resize(0x200);
    f.session->execute(PatchBytes{FileOffset{0}, header}, 0, {}).value();
    auto revised = f.session->refresh_analysis({}).value();
    check(revised->loaded && revised->loaded->image->decode_context() == legacy && revised->functions &&
              revised->functions->instructions.size() == 2 && revised->last_reanalysis.reused_instructions == 0 &&
              revised->loader_parses > before->loader_parses,
          "effective PE64-to-PE32 header patch reparses and retires old facts");
    check(presentation_name(*revised, entry) == "mode_entry" && revised->state->revisions.bytes == 1,
          "mode-bearing header edit retains authoritative annotation and byte history");
    check(action_availability(revised.get(), ProjectActionKind::define_function, entry).enabled &&
              bool(f.session->execute(DefineFunction{entry}, 0, {})),
          "legacy code decision is enabled and validated by shared decoder");
    auto manual_project = std::make_shared<ProjectSnapshot>(*revised);
    manual_project->functions.reset();
    DocumentSnapshot manual;
    manual.image = revised->loaded->image;
    manual.project = manual_project;
    auto listing = make_listing_page(manual, entry, 2).value();
    check(listing.rows.size() == 2 && listing.rows[0].instruction &&
              listing.rows[0].instruction->opcode == Opcode::inc && listing.rows[0].instruction->context == legacy &&
              !listing.rows[0].reachable,
          "project manual listing dispatches legacy mode without rooted facts");
    f.session->refresh_analysis({}).value();
    f.session->undo({}).value();
    f.session->undo({}).value();
    auto restored = f.session->refresh_analysis({}).value();
    check(restored->loaded->image->decode_context() == before->loaded->image->decode_context() &&
              restored->functions->instructions.size() == 1 && presentation_name(*restored, entry) == "mode_entry",
          "undo header edit restores long-mode facts and keeps annotation");
    f.session->redo({}).value();
    auto redone = f.session->refresh_analysis({}).value();
    check(redone->functions && redone->functions->instructions.size() == 2 &&
              redone->loaded->image->decode_context() == legacy,
          "redo header edit restores legacy facts");
}
std::shared_ptr<const Image> boundary_image(uint64_t high, std::vector<std::byte> high_bytes,
                                            std::vector<std::byte> low_bytes) {
    const auto low_size = low_bytes.size(), high_size = high_bytes.size();
    low_bytes.insert(low_bytes.end(), high_bytes.begin(), high_bytes.end());
    auto storage = std::make_shared<MemoryStorage>(std::move(low_bytes));
    ImageLayout layout{{{0}, 32, 1, ByteOrder::little},
                       Architecture::x86,
                       ExecutionMode::x86_32,
                       {{"low", {{0}, 0}, low_size, {0}, low_size, true, false, true},
                        {"high", {{0}, high}, high_size, {low_size}, high_size, true, false, true}},
                       {{{0}, high}}};
    return Image::create(storage, std::move(layout)).value();
}
void continuation_tests() {
    const auto verify = [](std::shared_ptr<const Image> image, uint64_t from, uint64_t target, size_t count,
                           BlockEdgeKind expected_kind) {
        auto flat = analyze(*image, {}, {}).value();
        check(flat.instructions.size() == count && std::any_of(flat.edges.begin(), flat.edges.end(),
                                                               [&](auto &edge) {
                                                                   return edge.from == Address{{0}, from} &&
                                                                          edge.to == Address{{0}, target} &&
                                                                          edge.kind == EdgeKind::fallthrough;
                                                               }),
              "legacy reachable continuation uses architectural IP and return-slot width");
        auto key = key_for(*image);
        auto metadata = std::make_shared<const ImageMetadata>();
        auto recovered = analyze_derived(image, metadata, {}, {}, key, {}).value();
        bool edge_found = false;
        for (auto &block : recovered.functions->blocks)
            for (auto &edge : block->successors)
                if (edge.target == Address{{0}, target} && edge.kind == expected_kind)
                    edge_found = true;
        check(recovered.functions->instructions.size() == count && edge_found,
              "legacy rooted CFG reaches the architectural continuation");
        auto encoded = encode_derived(recovered, {}).value();
        auto restored = decode_derived(encoded, *image, *metadata, {}, {}, key, {}).value();
        check(restored.functions->instructions.size() == count,
              "boundary continuation survives canonical cache reconstruction");
    };
    verify(boundary_image(UINT32_MAX, bytes({0x90}), bytes({0xc3})), UINT32_MAX, 0, 2, BlockEdgeKind::fallthrough);
    verify(boundary_image(UINT32_MAX - 1, bytes({0x74, 0}), bytes({0xc3})), UINT32_MAX - 1, 0, 2,
           BlockEdgeKind::conditional_false);
    auto low = std::vector<std::byte>(12);
    low[0] = std::byte{0xc3};
    low[11] = std::byte{0xc3};
    verify(boundary_image(UINT32_MAX - 4, bytes({0xe8, 11, 0, 0, 0}), low), UINT32_MAX - 4, 0, 3,
           BlockEdgeKind::call_continuation);
    low = std::vector<std::byte>(18);
    low[4] = std::byte{0xc3};
    low[16] = std::byte{0x66};
    low[17] = std::byte{0xc3};
    verify(boundary_image(0x10000, bytes({0x66, 0xe8, 12, 0}), low), 0x10000, 4, 3, BlockEdgeKind::call_continuation);
    low = std::vector<std::byte>(17);
    low[16] = std::byte{0xc3};
    verify(boundary_image(0x10000, bytes({0x66, 0x0f, 0x84, 11, 0, 0xc3}), low), 0x10000, 0x10005, 3,
           BlockEdgeKind::conditional_false);
}
} // namespace
void far_cache_tests() {
    for (auto raw : {bytes({0x9a, 0x78, 0x56, 0x34, 0x12, 8, 0, 0xc3}), bytes({0xff, 0x1d, 0, 0x20, 0, 0, 0xc3})}) {
        auto image = image32(raw);
        auto key = key_for(*image);
        auto metadata = std::make_shared<const ImageMetadata>();
        auto proposal = analyze_derived(image, metadata, {}, {}, key, {});
        check(proposal.has_value(), "typed far transfer retains a partial function proposal");
        if (!proposal)
            throw std::runtime_error(proposal.error().message);
        auto payload = encode_derived(proposal.value(), {});
        check(payload.has_value(), "canonical v3 encodes typed immediate and memory far forms");
        if (!payload)
            throw std::runtime_error(payload.error().message);
        auto decoded = decode_derived(payload.value(), *image, *metadata, {}, {}, key, {});
        check(decoded.has_value(), "v3 reconstructs original far operands and stack metadata");
        if (!decoded)
            throw std::runtime_error(decoded.error().message);
        const auto &i = decoded.value().functions->instructions.front()->instruction;
        check(i.stack_slot_count == 2 && i.stack_value_width == 32 && !i.direct_target &&
                  (std::holds_alternative<FarPointerOperand>(i.operands[0]) ||
                   std::holds_alternative<FarMemoryOperand>(i.operands[0])),
              "cache preserves selector pointer identity without a fabricated resolved target");
    }
}
int main() {
    return run([] {
        recovery_tests();
        atomic_integer_recovery_tests();
        reference_tests();
        incremental_tests();
        document_tests();
        project_tests();
        source_boundary_tests();
        continuation_tests();
        far_cache_tests();
    });
}

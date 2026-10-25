#include "hexlab/workspace/project.hpp"
#include "hexlab/loaders/x86_raw_profile.hpp"
#include "hexlab/workspace/project_graph.hpp"
#include "hexlab/workspace/listing.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include <algorithm>
using namespace hexlab;
using namespace hexlab_test;
namespace {
std::shared_ptr<const Image> mixed_image() {
    auto storage = std::make_shared<MemoryStorage>(
        bytes({0xb8, 0x34, 0x12, 0xc3, 0xb8, 0x78, 0x56, 0x34, 0x12, 0xc3, 0x48, 0x89, 0xc8, 0xc3}));
    ImageLayout layout{{{7}, 16, 1, ByteOrder::little},
                       Architecture::x86,
                       ExecutionMode::x86_16,
                       {{"16", {{7}, 0x1000}, 4, {0}, 4, true, false, true},
                        {"32", {{2}, 0x1000}, 6, {4}, 6, true, false, true},
                        {"64", {{9}, 0x1000}, 4, {10}, 4, true, false, true},
                        {"data", {{1}, 0x1000}, 4, {0}, 4, true, false, false}},
                       {{{7}, 0x1000}, {{2}, 0x1000}, {{9}, 0x1000}}};
    layout.domains = {{{{2}, 32, 1, ByteOrder::little}, {Architecture::x86, ExecutionMode::x86_32}},
                      {{{9}, 64, 1, ByteOrder::little}, {Architecture::x86_64, ExecutionMode::x86_64}},
                      {{{1}, 16, 1, ByteOrder::little}, {Architecture::x86, ExecutionMode::unknown}}};
    auto made = Image::create(storage, std::move(layout));
    if (!made)
        throw std::runtime_error(made.error().message);
    return made.value();
}
void mixed_contexts() {
    auto image = mixed_image();
    auto recovered = recover_functions(*image, {}, {}, {}, {}).value();
    check(recovered->functions.size() == 3 && recovered->conflicts.empty() &&
              std::all_of(recovered->blocks.begin(), recovered->blocks.end(),
                          [](const auto &block) { return block->owners.size() == 1; }),
          "same-offset functions in different domains retain separate ownership without overlap conflicts");
    const auto fact = [&](Address address) -> const Instruction * {
        for (const auto &i : recovered->instructions)
            if (i->instruction.address == address)
                return &i->instruction;
        return nullptr;
    };
    for (auto id : {2u, 7u, 9u}) {
        auto i = fact({{id}, 0x1000});
        check(i && i->context == image->context_at({{id}, 0x1000}).value() && i->length == (id == 2 ? 5 : 3) &&
                  i->opcode == Opcode::mov,
              "rooted recovery uses each domain's actual16/32/64 context at equal offsets");
    }
    ProjectSnapshot snapshot;
    snapshot.state = std::make_shared<const database::ProjectState>();
    snapshot.original = snapshot.effective = image->storage();
    snapshot.loaded = std::make_shared<const LoadedImage>(LoadedImage{image});
    snapshot.status = DerivedStatus::fresh;
    snapshot.mode = database::ProjectMode::read_write;
    auto boundaries = std::make_shared<FunctionSnapshot>();
    for (auto id : {2u, 7u, 9u}) {
        const Address at{{id}, 0x1000};
        auto decoded = decode_instruction(image->context_at(at).value(), image->read(at, id == 2 ? 6 : 4).value(), at);
        auto i = std::make_shared<InstructionFact>();
        i->instruction = *decoded.instruction;
        boundaries->instructions.push_back(i);
    }
    snapshot.functions = boundaries;
    check(!action_availability(&snapshot, ProjectActionKind::define_function, Address{{7}, 0x1001}).enabled &&
              !action_availability(&snapshot, ProjectActionKind::define_function, Address{{2}, 0x1001}).enabled,
          "command gates reject instruction interiors using full space/offset ordering");
    check(!action_availability(&snapshot, ProjectActionKind::define_function, Address{{1}, 0x1000}).enabled,
          "unknown data domain never inherits the primary code context in action gates");
    snapshot.functions = std::make_shared<const FunctionSnapshot>();
    check(!validate_command(snapshot, DefineRegion{{{2}, 0x1000}, 3, RegionKind::code}),
          "code command cannot truncate a32-bit instruction by decoding it in primary16 mode");
    check(bool(validate_command(snapshot, DefineRegion{{{2}, 0x1000}, 5, RegionKind::code})),
          "code command accepts the complete instruction in its actual domain");
    check(!validate_command(snapshot, DefineRegion{{{1}, 0x1000}, 3, RegionKind::code}),
          "code command rejects unknown data context even when primary mode supports decoding");
}
void persistent_flow(const X86RawProfile &, const std::vector<std::byte> &);
void far_flow(bool protected_mode) {
    auto input = bytes({0x9a, 0, 0, 0x01, 0x10, 0xc3});
    input.resize(16, std::byte{0x90});
    const auto target_bytes = protected_mode ? bytes({0xb8, 0x78, 0x56, 0x34, 0x12, 0xcb}) : bytes({0x90, 0xcb});
    input.insert(input.end(), target_bytes.begin(), target_bytes.end());
    X86RawProfile p{X86ImageEnvironment::real386,
                    A20Policy::enabled,
                    0x10000,
                    {{7}, 0},
                    {},
                    {{{7}, 0x1000, true, "caller", {}}, {{2}, 0x1001, true, "callee", {}}}};
    if (protected_mode) {
        p.environment = X86ImageEnvironment::protected386;
        p.stack_selector = std::uint16_t{0x18};
        p.domains = {{{7},
                      8,
                      true,
                      "caller",
                      X86SegmentDescriptor{0x10000, 0xffff, true, true, true, false, false, false, false, 0}},
                     {{2},
                      0x10,
                      true,
                      "callee",
                      X86SegmentDescriptor{0x10010, 0xffff, true, true, true, false, false, true, false, 0}},
                     {{3},
                      0x18,
                      false,
                      "stack",
                      X86SegmentDescriptor{0, 0xffff, true, false, true, true, false, false, false, 0}}};
        input[3] = std::byte{0x10};
        input[4] = std::byte{0};
    }
    auto storage = std::make_shared<MemoryStorage>(input);
    auto image = load_raw(storage, make_x86_raw_options(p).value(), {}).value();
    const Address destination{{2}, 0};
    auto functions = recover_functions(*image, {}, {}, {}, {}).value();
    auto references = derive_references(*image, *functions, {}, {}, {}).value();
    check(references->incoming(destination, {}).value().total == 1,
          "far control reference uses the same declared logical target as recovery");
    check(functions->functions.size() == 2 && functions->calls.size() == 1 && functions->calls[0].target == destination,
          "declared ordinary far call seeds a logical callee in its own domain");
    auto reached = std::find_if(functions->instructions.begin(), functions->instructions.end(),
                                [&](const auto &fact) { return fact->instruction.address == destination; });
    check(reached != functions->instructions.end() &&
              (*reached)->instruction.context.mode == (protected_mode ? ExecutionMode::x86_32 : ExecutionMode::x86_16),
          "far target decodes with destination CS.D while pure far instruction retains its typed pointer");
    auto legacy = analyze(*image, {}, {}).value();
    check(std::any_of(legacy.edges.begin(), legacy.edges.end(),
                      [&](const auto &edge) {
                          return edge.from == p.entry && edge.to == destination && edge.kind == EdgeKind::call;
                      }),
          "reachable analysis shares logical far target resolution");
    auto source = decode_at(*image, p.entry).value().instruction.value();
    check(!source.direct_target && std::holds_alternative<FarPointerOperand>(source.operands[0]),
          "profile resolution never rewrites pure decoder target or flattens selector identity");
    auto jump_bytes = input;
    jump_bytes[0] = std::byte{0xea};
    auto jump_image =
        load_raw(std::make_shared<MemoryStorage>(jump_bytes), make_x86_raw_options(p).value(), {}).value();
    auto jump = recover_functions(*jump_image, {}, {}, {}, {}).value();
    check(std::any_of(jump->blocks.begin(), jump->blocks.end(),
                      [&](const auto &block) {
                          return std::any_of(block->successors.begin(), block->successors.end(), [&](const auto &edge) {
                              return edge.source == p.entry && edge.target == destination &&
                                     edge.kind == BlockEdgeKind::jump;
                          });
                      }),
          "far jump preserves the destination domain in block successors");
    const auto unresolved = [&](const X86RawProfile &changed, const std::vector<std::byte> &data) {
        auto loaded =
            load_raw(std::make_shared<MemoryStorage>(data), make_x86_raw_options(changed).value(), {}).value();
        auto result = recover_functions(*loaded, {}, {}, {}, {}).value();
        auto refs = derive_references(*loaded, *result, {}, {}, {}).value();
        auto outgoing = refs->outgoing(changed.entry, {}).value();
        check(outgoing.rows.size() == 1 && std::holds_alternative<UnresolvedTarget>(outgoing.rows[0].target) &&
                  std::holds_alternative<FarPointerOperand>(
                      std::get<UnresolvedTarget>(outgoing.rows[0].target).expression),
              "unresolved far control reference retains the encoded selector and offset expression");
        auto encoded = encode_reference_index(*refs, {}).value();
        check(encode_reference_index(*decode_reference_index(encoded, {}).value(), {}).value() == encoded,
              "typed far reference has a canonical cache roundtrip");
        return result->calls.size() == 1 && !result->calls[0].target;
    };
    auto missing = input;
    missing[3] = std::byte{0xf0};
    missing[4] = std::byte{0xff};
    check(unresolved(p, missing), "undeclared selector stays unresolved even when canonical bytes are present");
    auto data_target = p;
    data_target.domains[1].executable = false;
    if (protected_mode) {
        data_target.domains[1].descriptor->executable = false;
        data_target.domains[1].descriptor->writable = true;
    }
    check(unresolved(data_target, input), "declared data selector never becomes a far code target");
    const auto indirect_bytes = bytes({0x66, 0xff, 0x1e, 0, 0, 0xc3});
    auto indirect_image =
        load_raw(std::make_shared<MemoryStorage>(indirect_bytes), make_x86_raw_options(p).value(), {}).value();
    auto indirect = recover_functions(*indirect_image, {}, {}, {}, {}).value();
    auto indirect_refs = derive_references(*indirect_image, *indirect, {}, {}, {}).value();
    check(indirect_refs->all().size() == 2 &&
              std::all_of(indirect_refs->all().begin(), indirect_refs->all().end(),
                          [](const auto &r) {
                              const auto *u = std::get_if<UnresolvedTarget>(&r.target);
                              const auto *m = u ? std::get_if<FarMemoryOperand>(&u->expression) : nullptr;
                              return m && m->offset_width == 32 && m->address.data_width == 48 &&
                                     !m->address.resolved_address;
                          }),
          "far indirect call preserves separate pointer-slot read and unresolved target without guessing DS state");
    auto indirect_payload = encode_reference_index(*indirect_refs, {}).value();
    check(encode_reference_index(*decode_reference_index(indirect_payload, {}).value(), {}).value() == indirect_payload,
          "48-bit stored far pointer expressions survive canonical reference caching");
    for (std::size_t n = 0; n < indirect_payload.size(); ++n)
        check(!decode_reference_index(std::span(indirect_payload).first(n), {}),
              "every truncated far-expression reference payload is rejected");
    auto malformed = indirect_refs->all()[0];
    malformed.id = {0};
    auto &expression = std::get<UnresolvedTarget>(malformed.target).expression;
    std::get<FarMemoryOperand>(expression).address.data_width = 32;
    check(!ReferenceIndex::create({malformed}, {}, true, {}),
          "far pointer-slot expression must include the full offset and selector width");
    if (protected_mode) {
        auto privileged = p;
        privileged.domains[1].descriptor->dpl = 1;
        privileged.domains[1].selector = 0x11;
        auto other_level = input;
        other_level[3] = std::byte{0x11};
        check(unresolved(privileged, other_level), "privilege-changing far target stays unresolved");
        auto conforming = p;
        conforming.domains[1].descriptor->conforming = true;
        check(unresolved(conforming, input), "conforming-code transfer is outside ordinary same-level resolution");
        auto limited = p;
        limited.domains[1].descriptor->effective_limit = 0;
        auto outside = input;
        outside[1] = std::byte{1};
        check(unresolved(limited, outside), "far target beyond destination segment limit stays unresolved");
    }
    persistent_flow(p, input);
}
void persistent_flow(const X86RawProfile &p, const std::vector<std::byte> &input) {
    FixtureFile marker(std::span<const std::byte>{});
    const std::filesystem::path path = marker.path.wstring() + L".far.hxproj";
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() {
            std::error_code ignored;
            for (auto suffix : {L"", L"-wal", L"-shm"}) {
                auto side = path;
                side += suffix;
                std::filesystem::remove(side, ignored);
            }
        }
    } cleanup{path};
    auto store = database::ProjectStore::create(path, {}).value();
    MemoryStorage source(input);
    store->import_input(source, {Format::raw, make_x86_raw_options(p).value()}, {}, {}).value();
    auto session = ProjectSession::attach(store, {}, {}).value();
    const Address target{{2}, 0};
    auto initial = session->snapshot();
    auto caller_graph = make_project_graph(*initial, GraphKind::function_cfg, p.entry, {}, {}).value();
    auto callee_graph = make_project_graph(*initial, GraphKind::function_cfg, target, {}, {}).value();
    check(std::any_of(callee_graph.model->nodes.begin(), callee_graph.model->nodes.end(),
                      [&](const auto &node) {
                          return node.selection == Location{target} &&
                                 node.label == format_location(target, initial->loaded->image.get());
                      }),
          "profile graph labels use the same selector coordinates as native listing and navigation");
    check(caller_graph.model->function != callee_graph.model->function && !callee_graph.model->nodes.empty() &&
              std::all_of(callee_graph.model->nodes.begin(), callee_graph.model->nodes.end(),
                          [&](const auto &node) {
                              const auto *at = node.selection ? std::get_if<Address>(&*node.selection) : nullptr;
                              return at && at->space == target.space;
                          }),
          "CFG selection distinguishes caller and callee at equal offsets in different domains");
    auto calls = make_project_graph(*initial, GraphKind::image_calls, {}, {}, {}).value();
    GraphLabels bad_formatter;
    bad_formatter.location_formatter = [](Location) -> std::string {
        throw std::runtime_error("Test formatter failure");
    };
    check(!build_graph(*initial->functions, *initial->references, GraphKind::image_calls, {}, {}, bad_formatter, {}),
          "graph formatting failures return a typed error instead of escaping the worker API");
    check(std::any_of(calls.model->edges.begin(), calls.model->edges.end(),
                      [&](const auto &edge) {
                          return edge.selection == Location{p.entry} && edge.target_location == Location{target};
                      }),
          "image call graph preserves source and target domains for far references");
    DocumentSnapshot document;
    document.project = initial;
    document.image = initial->loaded->image;
    auto listing = make_listing_page(document, target, 1).value();
    check(listing.rows.size() == 1 && listing.rows[0].location == Location{target} && listing.rows[0].reachable &&
              listing.rows[0].instruction &&
              listing.rows[0].instruction->context == initial->loaded->image->context_at(target).value(),
          "listing a nonprimary far callee returns its own instruction context and location");
    const auto size = input.size() - 16;
    const auto apply = [&](const ProjectCommand &command) {
        session->execute(command, 0, {}).value();
        return session->refresh_analysis({}).value();
    };
    check(apply(DefineRegion{target, size, RegionKind::data})->functions->functions.size() == 1,
          "persistent data decision blocks only the far callee domain");
    check(apply(DefineRegion{target, size, RegionKind::code})->functions->functions.size() == 2,
          "persistent code conversion decodes the far callee in its own mode");
    apply(DefineFunction{target});
    auto chunks = apply(SetFunctionChunks{target, {{target, size}}});
    check(chunks->state->user->decisions.functions[0].chunks == std::vector<DecisionRange>{{target, size}},
          "far callee explicit function chunks retain their domain");
    check(apply(SuppressFunction{target, true})->functions->functions.size() == 1,
          "suppressing a far callee preserves its caller");
    session->undo({}).value();
    check(session->refresh_analysis({}).value()->functions->functions.size() == 2,
          "undo restores far callee recovery and ownership");
    session->redo({}).value();
    check(session->refresh_analysis({}).value()->functions->functions.size() == 1,
          "redo reapplies far callee suppression");
    apply(SuppressFunction{target, false});
    apply(Rename{p.entry, "entry"});
    apply(Rename{target, "entry"});
    auto before = apply(Comment{target, "far target"});
    const auto revisions = before->state->revisions;
    const auto history = before->state->history_cursor;
    session.reset();
    store.reset();
    store = database::ProjectStore::open(path, database::ProjectMode::read_only, {}).value();
    session = ProjectSession::attach(store, {}, {}).value();
    auto after = session->snapshot();
    check(after->derived_cache_status == database::CacheStatus::hit && after->functions->functions.size() == 2 &&
              after->references->incoming(target, {}).value().total == 1,
          "readonly reopen validates mixed-domain functions and far references from complete cache");
    check(after->state->revisions == revisions && after->state->history_cursor == history &&
              presentation_name(*after, p.entry) == "entry" && presentation_name(*after, target) == "entry" &&
              presentation_at(*after, target).comment == "far target",
          "same-offset names in different code domains and user history remain independent");
}
void near_continuation() {
    // Literal386 D0 case: ordinary EIP is32 bits, but CALL16 pushes low16
    // return0023 and takes the16-bit target0080. Matches the executed oracle.
    auto input = std::vector<std::byte>(0x10024, std::byte{0x90});
    input[0x23] = input[0x80] = std::byte{0xc3};
    input[0x10020] = std::byte{0xe8};
    input[0x10021] = std::byte{0x5d};
    input[0x10022] = std::byte{0};
    X86RawProfile p{
        X86ImageEnvironment::protected386,
        A20Policy::enabled,
        0,
        {{7}, 0x10020},
        std::uint16_t{0x10},
        {{{7}, 8, true, "code", X86SegmentDescriptor{0, UINT32_MAX, true, true, true, false, false, false, false, 0}},
         {{2},
          0x10,
          false,
          "stack",
          X86SegmentDescriptor{0, 0xffff, true, false, true, true, false, false, false, 0}}}};
    auto image = load_raw(std::make_shared<MemoryStorage>(input), make_x86_raw_options(p).value(), {}).value();
    auto functions = recover_functions(*image, {}, {}, {}, {}).value();
    check(functions->functions.size() == 2 && functions->calls.size() == 1 &&
              functions->calls[0].target == Address{{7}, 0x80},
          "near16 recovery uses the masked taken target even with a high valid EIP");
    check(std::any_of(functions->blocks.begin(), functions->blocks.end(),
                      [&](const auto &block) {
                          return std::any_of(block->successors.begin(), block->successors.end(), [&](const auto &edge) {
                              return edge.source == p.entry && edge.kind == BlockEdgeKind::call_continuation &&
                                     edge.target == Address{{7}, 0x23};
                          });
                      }),
          "near16 call recovery follows the low16 pushed return rather than ordinary high EIP");
    input[0xffff] = std::byte{0x90};
    input[0x10000] = std::byte{0xc3};
    p.entry.offset = 0xffff;
    image = load_raw(std::make_shared<MemoryStorage>(input), make_x86_raw_options(p).value(), {}).value();
    auto sequential = recover_functions(*image, {}, {}, {}, {}).value();
    check(sequential->instructions.size() == 2 &&
              sequential->instructions[1]->instruction.address == Address{{7}, 0x10000},
          "ordinary D0 fallthrough preserves full EIP when the declared CS limit permits it");
}
} // namespace
int main() {
    return run([] {
        mixed_contexts();
        near_continuation();
        far_flow(false);
        far_flow(true);
    });
}

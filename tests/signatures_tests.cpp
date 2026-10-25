#include "hexlab/analysis/signatures.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
#include <array>
using namespace hexlab;
using namespace hexlab_test;


void reusable_function_signatures() {
    // Two copies deliberately distinguish entry recognition from arbitrary
    // executable-byte scanning. Calls and RIP addresses differ after linking.
    const std::array<unsigned char, 16> code{0xe8,0x20,0,0,0,0x48,0x8d,0x05,0x30,0,0,0,0x83,0xc0,1,0xc3};
    std::vector<std::byte> original;
    for (unsigned copy = 0; copy < 2; ++copy)
        for (const auto byte : code) original.push_back(std::byte{byte});
    auto storage = std::make_shared<MemoryStorage>(original);
    const ImageLayout layout{{{0},64,1,ByteOrder::little},Architecture::x86_64,ExecutionMode::x86_64,
        {{"text",{{0},0x1000},32,{0},32,true,false,true}},{{{0},0x1000}}};
    auto image = Image::create(storage, layout);
    check(bool(image), "create reusable function signature image");
    if (!image) return;
    auto block = std::make_shared<BasicBlock>(); block->id = {1}; block->begin = {{0},0x1000};
    for (const auto [offset, length] : std::array<std::pair<unsigned,unsigned>,4>{
             std::pair{0,5}, std::pair{5,7}, std::pair{12,3}, std::pair{15,1}}) {
        const auto decoded = decode_instruction(image.value()->decode_context(),
            std::span<const std::byte>(original).subspan(offset,length), {{0},0x1000+offset});
        check(decoded.instruction.has_value(), "function signature fixture instruction decodes");
        if (!decoded.instruction) return;
        block->instructions.push_back(std::make_shared<const InstructionFact>(InstructionFact{offset+1,*decoded.instruction,{}}));
    }
    auto function = std::make_shared<FunctionRecord>(); function->id = {7}; function->entry = block->begin;
    function->blocks = {{1}};
    FunctionSnapshot snapshot; snapshot.blocks = {block}; snapshot.functions = {function};
    auto made = create_function_signature(*image.value(), *storage, *function, snapshot, "Runtime.Helper", "test-library v1");
    check(made && made.value().pattern.size() == 16, "extract complete instruction-aligned entry prefix");
    if (!made) return;
    for (unsigned n = 0; n < 16; ++n) {
        const bool wildcard = (n >= 1 && n < 5) || (n >= 8 && n < 12);
        check(made.value().pattern[n].mask == static_cast<std::byte>(wildcard ? 0u : 255u),
              "only proven call and RIP displacement fields are wildcarded");
    }
    auto call_block = std::make_shared<BasicBlock>(*block);
    call_block->instructions.resize(1);
    call_block->successors = {{{{0},0x1000}, Address{{0},0x1005}, BlockId{2}, BlockEdgeKind::call_continuation}};
    auto continuation = std::make_shared<BasicBlock>(*block);
    continuation->id = {2}; continuation->begin = {{0},0x1005};
    continuation->instructions.erase(continuation->instructions.begin());
    auto split_function = *function; split_function.blocks.push_back({2});
    auto split_snapshot = snapshot; split_snapshot.blocks = {call_block, continuation};
    const auto through_call = create_function_signature(*image.value(), *storage, split_function, split_snapshot,
                                                        "Runtime.Helper", "test-library v1");
    check(through_call && through_call.value() == made.value(),
          "recovered contiguous call continuation contributes the same verified function prefix");
    auto exported = serialize_signature_definitions(std::span<const SignatureDefinition>(&made.value(),1));
    auto imported = exported ? parse_signature_definitions(exported.value()) : Result<std::vector<SignatureDefinition>>(exported.error());
    check(imported && imported.value().size() == 1 && imported.value()[0] == made.value(),
          "extracted signature round-trips through reusable catalog text");
    original[1] = std::byte{0x55}; original[8] = std::byte{0x66};
    auto relinked = std::make_shared<MemoryStorage>(original);
    auto relinked_image = Image::create(relinked,layout);
    if (!relinked_image || !imported) return;
    auto recognized = recognize_function_signatures(*relinked_image.value(), *relinked, snapshot, imported.value());
    check(recognized && recognized.value().functions.size() == 1 &&
              recognized.value().functions[0].function == FunctionId{7} &&
              !recognized.value().functions[0].ambiguous && recognized.value().functions[0].candidates.size() == 1,
          "relinked function matches at its recovered entry while an interior duplicate is excluded");
    auto collision = made.value(); collision.name = "Other.Library.Helper";
    imported.value().push_back(collision);
    auto ambiguous = recognize_function_signatures(*relinked_image.value(), *relinked, snapshot,
                                                    SignatureCatalog{1, imported.value()});
    check(ambiguous && ambiguous.value().functions.size() == 1 && ambiguous.value().functions[0].ambiguous &&
              ambiguous.value().functions[0].candidates.size() == 2 &&
              ambiguous.value().functions[0].candidates[0].name == "Runtime.Helper" &&
              ambiguous.value().functions[0].candidates[1].name == "Other.Library.Helper",
          "colliding library definitions retain both provenance-bearing candidates as ambiguity");
    original[14] = std::byte{2};
    auto changed = std::make_shared<MemoryStorage>(original);
    auto changed_image = Image::create(changed,layout);
    auto mismatch = recognize_function_signatures(*changed_image.value(),*changed,snapshot,imported.value());
    check(mismatch && mismatch.value().functions.empty(), "changed semantic immediate does not match normalized signature");
    check(!create_function_signature(*relinked_image.value(), *relinked, *function, snapshot, "bad", "stale"),
          "stale instruction facts cannot produce an effective-byte signature");
    check(!create_function_signature(*image.value(), *storage, *function, snapshot, "weak", "test", {5,2}),
          "overly wildcarded short function prefix is rejected");
    auto short_prefix = create_function_signature(*image.value(), *storage, *function, snapshot, "prefix", "test", {14,4});
    check(short_prefix && short_prefix.value().pattern.size() == 12,
          "byte budget stops at a whole-instruction boundary");
    auto missing = snapshot;
    missing.blocks.clear();
    check(!create_function_signature(*image.value(), *storage, *function, missing, "missing", "test"),
          "missing function entry evidence is rejected");
    auto gap = std::make_shared<BasicBlock>(*block);
    gap->instructions.erase(gap->instructions.begin() + 1);
    missing.blocks = {gap};
    check(!create_function_signature(*image.value(), *storage, *function, missing, "gap", "test"),
          "gapped function instructions cannot create a catalog signature");
    auto segmented_block = std::make_shared<BasicBlock>(*block);
    auto segmented_fact = std::make_shared<InstructionFact>(*block->instructions.front());
    segmented_fact->instruction.context.segmented_memory = true;
    segmented_block->instructions.front() = segmented_fact;
    missing.blocks = {segmented_block};
    check(create_function_signature(*image.value(), *storage, *function, missing, "segmented", "test").error().code == ErrorCode::unsupported,
          "unsupported segmented extraction is explicit");
    SignatureLimits limited; limited.max_candidates = 1;
    check(recognize_function_signatures(*image.value(), *storage, snapshot, imported.value(), limited).error().code == ErrorCode::resource_limit,
          "function recognition preserves bounded scanner work limits");
    auto duplicate = snapshot;
    duplicate.functions.push_back(function);
    check(!recognize_function_signatures(*image.value(), *storage, duplicate, imported.value()),
          "duplicate recovered function entries are reported as invalid evidence");
    auto incomplete = snapshot; incomplete.complete = false;
    const auto partial = recognize_function_signatures(*image.value(), *storage, incomplete, imported.value());
    check(partial && !partial.value().complete && partial.value().functions.size() == 1,
          "incomplete analysis remains explicit while verified recognition candidates are retained");
    auto invalid = made.value(); invalid.name = "bad|name";
    check(!serialize_signature_definitions(std::span<const SignatureDefinition>(&invalid,1)),
          "catalog serialization rejects unrepresentable metadata");
    std::stop_source stop; stop.request_stop();
    check(create_function_signature(*image.value(),*storage,*function,snapshot,"stop","test",{},stop.get_token()).error().code == ErrorCode::canceled &&
              recognize_function_signatures(*image.value(),*storage,snapshot,imported.value(),{},stop.get_token()).error().code == ErrorCode::canceled,
          "extraction and entry recognition honor cancellation");
}

int main() {
    reusable_function_signatures();
    auto parsed = parse_signature_definitions(
        "# examples\nLiteral|vendor-db|AA B1 C3|\nMasked|manual|AA B? C3|AA B1 C3\n");
    check(bool(parsed) && parsed.value().size() == 2, "parse literal, nibble mask, and exclusion definitions");
    if (parsed) {
        const auto text = serialize_signature_definitions(parsed.value());
        const auto restored = text ? parse_signature_definitions(text.value()) : Result<std::vector<SignatureDefinition>>(text.error());
        check(restored && restored.value() == parsed.value(), "catalog serialization preserves nibble masks and exclusion patterns");
        SignatureCatalog catalog{1, parsed.value()};
        const auto catalog_text = serialize_signature_catalog(catalog);
        const auto catalog_restored = catalog_text ? parse_signature_catalog(catalog_text.value()) : Result<SignatureCatalog>(catalog_text.error());
        check(catalog_restored && catalog_restored.value().format_version == 1 &&
                  catalog_restored.value().definitions == parsed.value(),
              "versioned catalog round trip retains multiple definitions and provenance");
        SignatureCatalog scoped{2, parsed.value(), Architecture::x86_64, ExecutionMode::x86_64};
        const auto scoped_text = serialize_signature_catalog(scoped);
        const auto scoped_restored = scoped_text ? parse_signature_catalog(scoped_text.value())
            : Result<SignatureCatalog>(scoped_text.error());
        check(scoped_restored && scoped_restored.value().format_version == 2 &&
                  scoped_restored.value().target_architecture == Architecture::x86_64 &&
                  scoped_restored.value().target_mode == ExecutionMode::x86_64 &&
                  scoped_restored.value().definitions == parsed.value(),
              "version 2 catalog round trip retains processor and mode scope");
        if (catalog_text) {
            auto crlf_catalog = catalog_text.value();
            for (std::size_t newline = 0; (newline = crlf_catalog.find('\n', newline)) != std::string::npos; newline += 2)
                crlf_catalog.insert(newline, 1, '\r');
            const auto crlf_restored = parse_signature_catalog(crlf_catalog);
            check(crlf_restored && crlf_restored.value().definitions == parsed.value(),
                  "versioned catalogs parse with Windows CRLF line endings");
        }
        check(!parse_signature_catalog("# HexLab signature catalog v3\n" + std::string("A|source|AA|\n")),
              "unknown catalog versions are rejected explicitly");
        const auto legacy_catalog = parse_signature_catalog("# old catalog\nA|source|AA|\n");
        check(legacy_catalog && legacy_catalog.value().definitions.size() == 1,
              "catalog reader remains compatible with legacy definition files");
        check(!parse_signature_catalog("# HexLab signature catalog v2\nA|source|AA|\n"),
              "scoped catalogs require target metadata");
        check(!serialize_signature_catalog(SignatureCatalog{3, parsed.value()}),
              "unsupported catalog versions cannot be written");
    }

    for (const auto bad : {"bad", "x|source|?? ??|", "x|source|AA|GG", "x|source|AA|;AA", "x|source|AA|\nx|other|BB|"})
        check(!parse_signature_definitions(bad), "reject malformed, unanchored, invalid, empty, or duplicate definitions");

    auto storage = std::make_shared<MemoryStorage>(std::vector<std::byte>{
        std::byte{0xaa}, std::byte{0xb1}, std::byte{0xc3}, std::byte{0xaa}, std::byte{0xb2}, std::byte{0xc3},
        std::byte{0xaa}, std::byte{0xb1}});
    ImageLayout layout{{{0}, 64, 1, ByteOrder::little}, Architecture::x86_64, ExecutionMode::x86_64,
                       {{"text", {{0}, 0x1000}, 6, {0}, 6, true, false, true},
                        {"data", {{0}, 0x2000}, 2, {6}, 2, true, false, false}}, {{{0}, 0x1000}}};
    auto image = Image::create(storage, layout);
    check(bool(image), "create executable and non-executable mapped regions");
    if (!image || !parsed) return 1;
    const SignatureCatalog multi_entry_catalog{1, parsed.value()};
    auto scan = scan_executable_signatures(*image.value(), *storage, multi_entry_catalog);
    check(bool(scan), "scan executable segments");
    const SignatureCatalog wrong_target{2, parsed.value(), Architecture::arm64, ExecutionMode::a64};
    check(scan_executable_signatures(*image.value(), *storage, wrong_target).error().code == ErrorCode::invalid_argument,
          "scoped catalog refuses a mismatched image architecture and mode");
    if (scan) {
        check(scan.value().matches.size() == 2, "literal and masked positive with same-offset exclusion");
        check(scan.value().matches.size() >= 1 && scan.value().matches[0].name == "Literal" && scan.value().matches[0].offset == FileOffset{0} &&
                  scan.value().matches[0].address == Address{{0}, 0x1000},
              "literal match reports file and virtual coordinates");
        check(scan.value().matches.size() >= 2 && scan.value().matches[1].name == "Masked" && scan.value().matches[1].offset == FileOffset{3} &&
                  scan.value().matches[1].address == Address{{0}, 0x1003},
              "nibble mask and negative match filter the first occurrence");
    }
    auto boundary = parse_signature_definitions("Boundary|test|C3 AA B1|");
    check(bool(boundary), "parse boundary pattern");
    if (boundary) {
        auto bounded = scan_executable_signatures(*image.value(), *storage, boundary.value());
        check(bool(bounded) && bounded.value().matches.empty(),
              "patterns do not cross executable segment bounds or scan non-executable bytes");
    }
    auto indexed_definitions = parse_signature_definitions("Indexed|fixture|AA ?? BB CC|");
    auto indexed_storage = std::make_shared<MemoryStorage>(std::vector<std::byte>{
        std::byte{0x90}, std::byte{0xaa}, std::byte{0x11}, std::byte{0xbb}, std::byte{0xcc},
        std::byte{0x90}, std::byte{0xaa}, std::byte{0x22}, std::byte{0xbb}, std::byte{0xcc}});
    ImageLayout indexed_layout{{{0}, 64, 1, ByteOrder::little}, Architecture::x86_64, ExecutionMode::x86_64,
                               {{"text", {{0}, 0x4000}, 10, {0}, 10, true, false, true}}, {{{0}, 0x4000}}};
    auto indexed_image = Image::create(indexed_storage, indexed_layout);
    check(indexed_definitions && indexed_image, "prepare exact-run anchor fixture");
    if (indexed_definitions && indexed_image) {
        auto indexed = scan_executable_signatures(*indexed_image.value(), *indexed_storage, indexed_definitions.value());
        check(indexed && indexed.value().matches.size() == 2 && indexed.value().candidates == 2,
              "longest exact run indexes only candidate starts that can match");
        check(indexed && indexed.value().matches[0].offset == FileOffset{1} &&
                  indexed.value().matches[1].offset == FileOffset{6},
              "indexed candidates retain ascending file-offset order");
    }
    std::stop_source stop;
    stop.request_stop();
    check(scan_executable_signatures(*image.value(), *storage, parsed.value(), {}, stop.get_token()).error().code ==
              ErrorCode::canceled,
          "cancellation is observed before scanning");
    check(scan_executable_signatures(*image.value(), *storage, multi_entry_catalog, {}, stop.get_token()).error().code ==
              ErrorCode::canceled,
          "versioned multi-entry catalog scan preserves cancellation");
    SignatureLimits tiny;
    tiny.max_candidates = 1;
    check(scan_executable_signatures(*image.value(), *storage, parsed.value(), tiny).error().code == ErrorCode::resource_limit,
          "candidate budget is enforced");
    SignatureLimits tiny_index;
    tiny_index.max_scanned_bytes = 1;
    check(scan_executable_signatures(*image.value(), *storage, parsed.value(), tiny_index).error().code == ErrorCode::resource_limit,
          "index byte budget bounds sparse-signature scans");
    return failures == 0 ? 0 : 1;
}

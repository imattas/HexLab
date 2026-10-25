#include "hexlab/analysis/string_references.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"

#include <algorithm>
#include <vector>

using namespace hexlab;
using namespace hexlab_test;

int main() {
    return run([] {
        std::vector<Reference> refs{
            {{0}, Address{{0}, 0x1000}, 1u, Location{Address{{0}, 0x2002}},
             ReferenceKind::memory_read, OperandAccess::read, {ReferenceProvenanceKind::decoded, 1, 0}, {}},
            {{0}, FileOffset{0x20}, {}, Location{FileOffset{0x31}}, ReferenceKind::user_data,
             OperandAccess::address, {ReferenceProvenanceKind::user, 0, 9}, {}},
            {{0}, Address{{0}, 0x1008}, 0u, ExternalIdentity{"lib", "symbol", {}}, ReferenceKind::imported_call,
             OperandAccess::address, {ReferenceProvenanceKind::import_slot, 2, 0}, Location{Address{{0}, 0x3000}}}};
        auto index = ReferenceIndex::create(std::move(refs), {}, false, {});
        check(bool(index), "fixture references validate");
        if (!index) return;
        StringScan strings;
        strings.complete = false;
        strings.records = {
            {StringEncoding::ascii, "hello", 5, 5, FileOffset{0x10}, Address{{0}, 0x2000}, true},
            {StringEncoding::utf16le, "hello", 5, 10, FileOffset{0x30}, {}, true},
            {StringEncoding::ascii, "alias", 5, 5, FileOffset{0x10}, Address{{1}, 0x2000}, true}};
        auto found = find_string_references(*index.value(), strings, {});
        check(found && found.value().records.size() == 2,
              "resolved address and file-offset targets match string extents; external references are excluded");
        if (found) {
            check(!found.value().complete, "partial inputs keep string-reference scan partial");
            check(found.value().records[0].string_index == 0 && found.value().records[0].operand_index == std::uint32_t{1} &&
                      found.value().records[1].string_index == 1,
                  "interior targets preserve source operand and matching string index");
        }
        std::stop_source stopped;
        stopped.request_stop();
        auto canceled = find_string_references(*index.value(), strings, stopped.get_token());
        check(!canceled && canceled.error().code == ErrorCode::canceled,
              "string-reference workflow observes cancellation before scanning");

        std::vector<std::byte> image_bytes{
            std::byte{0x48}, std::byte{0xb8}, std::byte{0x20}, std::byte{0x10}, std::byte{0}, std::byte{0},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}, // movabs rax, 0x1020
            std::byte{0x8a}, std::byte{0x00},                       // mov al, [rax]
            std::byte{0xc3}};                                       // ret
        image_bytes.resize(0x25, std::byte{0});
        image_bytes[0x20] = std::byte{'H'};
        image_bytes[0x21] = std::byte{'e'};
        image_bytes[0x22] = std::byte{'x'};
        image_bytes[0x23] = std::byte{'!'};
        const auto image = memory_image(std::move(image_bytes));
        const auto functions = recover_functions(*image, {}, {}, {}, {}).value();
        const auto image_references = derive_references(*image, *functions, {}, {}, {}).value();
        AnalysisOptions options;
        const auto discovered_strings = find_strings(*image, options, {});
        check(bool(discovered_strings), "end-to-end string scan completes for the x86 fixture");
        if (discovered_strings) {
            const auto text = std::find_if(discovered_strings.value().records.begin(),
                                           discovered_strings.value().records.end(),
                                           [](const auto &record) { return record.preview == "Hex!"; });
            check(text != discovered_strings.value().records.end(), "ASCII string is discovered in the mapped image");
            const auto associations = find_string_references(*image_references, discovered_strings.value(), {});
            check(associations && associations.value().records.size() == 1 && text != discovered_strings.value().records.end() &&
                      associations.value().records[0].string_index ==
                          static_cast<std::size_t>(text - discovered_strings.value().records.begin()),
                  "CFG-propagated x86 memory references associate with the discovered string extent");
        }
    });
}

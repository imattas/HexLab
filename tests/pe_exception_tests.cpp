#include "hexlab/analysis/functions.hpp"
#include "hexlab/loaders/pe.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include "support/pe_fixture.hpp"

#include <algorithm>
#include <vector>

using namespace hexlab;
using namespace hexlab_test;

namespace {
std::vector<std::byte> exception_fixture() {
    auto data = pe_metadata_fixture(true);
    const auto directories = 0x108u;
    put(data, directories + 3 * 8, 0x2390, 4);
    put(data, directories + 3 * 8 + 4, 24, 4);
    // Two AMD64 RUNTIME_FUNCTION entries cover two adjacent functions.
    put(data, 0x790, 0x1000, 4);
    put(data, 0x794, 0x1002, 4);
    put(data, 0x798, 0x2300, 4);
    put(data, 0x79c, 0x1002, 4);
    put(data, 0x7a0, 0x1004, 4);
    put(data, 0x7a4, 0x2300, 4);
    data[0x200] = std::byte{0x90};
    data[0x201] = std::byte{0xc3};
    data[0x202] = std::byte{0x90};
    data[0x203] = std::byte{0xc3};
    return data;
}

void set_runtime_function_extent(std::vector<std::byte> &data, std::uint32_t function_size) {
    const auto first_end = std::uint32_t{0x1000} + function_size;
    const auto second_end = first_end + function_size;
    put(data, 0x794, first_end, 4);
    put(data, 0x79c, first_end, 4);
    put(data, 0x7a0, second_end, 4);
}

Result<LoadedImage> load_fixture(const std::vector<std::byte> &data) {
    FixtureFile file(data);
    return load_pe(FileStorage::open(file.path).value(), {});
}

std::vector<std::byte> arm64_exception_fixture() {
    auto data = pe_metadata_fixture(true);
    put(data, 0x84, 0xaa64, 2);
    put(data, 0x108 + 3 * 8, 0x2390, 4);
    put(data, 0x108 + 3 * 8 + 4, 8, 4);
    put(data, 0x790, 0x1000, 4);
    // Packed type 1, 8-byte function, two integer and three FP saves, homes
    // parameters, chained frame, and a 32-byte frame.
    put(data, 0x794, 1u | (2u << 2) | (2u << 13) | (2u << 16) |
                         (1u << 20) | (3u << 21) | (2u << 23), 4);
    return data;
}

void set_arm64_row(std::vector<std::byte> &data, std::size_t index,
                   std::uint32_t begin_rva, std::uint32_t unwind_word) {
    const auto row = 0x790 + index * 8;
    put(data, row, begin_rva, 4);
    put(data, row + 4, unwind_word, 4);
}

std::vector<std::byte> arm64_xdata_fixture() {
    auto data = arm64_exception_fixture();
    put(data, 0x794, 0x2300, 4); // xdata tag 00
    // 16-byte function, one epilog scope, one code word, handler present.
    put(data, 0x700, 4u | (1u << 20) | (1u << 22) | (1u << 27), 4);
    put(data, 0x704, 2u, 4); // epilog starts at +8, code index 0
    data[0x708] = std::byte{0xe4}; // END followed by three padding bytes
    put(data, 0x70c, 0x1000, 4);
    return data;
}

void arm64_exception_directory_is_supported() {
    const auto loaded = load_fixture(arm64_exception_fixture()).value();
    check(loaded.metadata_complete,
          "ARM64 PE exception directory is parsed instead of marked unsupported");
    check(loaded.metadata.pe->arm64_exception_functions.size() == 1,
          "ARM64 packed pdata rows are preserved as typed metadata");
    if (loaded.metadata.pe->arm64_exception_functions.empty()) return;
    const auto &function = loaded.metadata.pe->arm64_exception_functions.front();
    check(function.kind == PeArm64UnwindKind::packed_single && function.begin_rva == 0x1000 &&
              function.function_length == 8 && function.packed_unwind &&
              function.packed_unwind->function_length == 2 && function.packed_unwind->reg_f == 2 &&
              function.packed_unwind->reg_i == 2 && function.packed_unwind->homes_parameters &&
              function.packed_unwind->cr == 3 && function.packed_unwind->frame_size == 2 &&
              function.source.spans == std::vector<PeSourceSpan>{{{0x790}, 8}},
          "packed unwind fields and pdata source provenance are retained");
    const auto equal = load_fixture(arm64_exception_fixture()).value();
    check(loaded.metadata.pe->arm64_exception_functions == equal.metadata.pe->arm64_exception_functions,
          "independently loaded ARM64 pdata metadata compares structurally");

    auto fragment = arm64_exception_fixture();
    put(fragment, 0x794, 2u | (2u << 2) | (2u << 13) | (2u << 16) |
                             (1u << 20) | (3u << 21) | (2u << 23), 4);
    auto fragment_loaded = load_fixture(fragment).value();
    check(fragment_loaded.metadata_complete &&
              fragment_loaded.metadata.pe->arm64_exception_functions.front().kind ==
                  PeArm64UnwindKind::packed_fragment,
          "ARM64 packed tag 2 is preserved as a no-prolog fragment record");

    auto xdata = load_fixture(arm64_xdata_fixture()).value();
    check(xdata.metadata_complete && xdata.metadata.pe->arm64_exception_functions.size() == 1,
          "ARM64 unpacked xdata entry is parsed");
    if (!xdata.metadata.pe->arm64_exception_functions.empty()) {
        const auto &record = xdata.metadata.pe->arm64_exception_functions.front();
        check(record.kind == PeArm64UnwindKind::xdata && record.function_length == 16 && record.xdata &&
                  record.xdata->version == 0 && record.xdata->has_exception_data &&
                  record.xdata->epilog_count == 1 && record.xdata->code_words == 1 &&
                  record.xdata->epilog_scopes.size() == 1 &&
                  record.xdata->epilog_scopes.front().start_offset == 8 &&
                  record.xdata->unwind_codes.size() == 1 &&
                  record.xdata->unwind_codes.front().opcode == 0xe4 &&
                  record.xdata->handler_rva == std::optional<std::uint32_t>{0x1000} &&
                  record.xdata->source.spans == std::vector<PeSourceSpan>{{{0x700}, 16}},
              "xdata header, epilog scope, unwind code, handler, and source extent are decoded");
    }

    auto extended = arm64_xdata_fixture();
    put(extended, 0x700, 4u, 4); // both compact counts zero: extended header follows
    put(extended, 0x704, 1u | (1u << 16), 4); // one scope and one code word
    put(extended, 0x708, 2u, 4);
    put(extended, 0x70c, 0xe4, 4);
    auto extended_loaded = load_fixture(extended).value();
    check(extended_loaded.metadata_complete,
          "ARM64 extended xdata header is accepted");
    check(extended_loaded.metadata.pe->arm64_exception_functions.size() == 1 &&
              extended_loaded.metadata.pe->arm64_exception_functions.front().xdata &&
              extended_loaded.metadata.pe->arm64_exception_functions.front().xdata->extended_header &&
              extended_loaded.metadata.pe->arm64_exception_functions.front().xdata->epilog_scopes.size() == 1 &&
              extended_loaded.metadata.pe->arm64_exception_functions.front().xdata->unwind_codes.size() == 1,
          "ARM64 extended xdata header decodes its scopes and code array");

    auto reserved_extended = arm64_xdata_fixture();
    put(reserved_extended, 0x700, 4u, 4);
    put(reserved_extended, 0x704, 0x01010001u, 4); // reserved high byte must be zero
    put(reserved_extended, 0x708, 2u, 4);
    put(reserved_extended, 0x70c, 0xe4, 4);
    auto reserved_extended_loaded = load_fixture(reserved_extended).value();
    check(!reserved_extended_loaded.metadata_complete &&
              reserved_extended_loaded.metadata.pe->arm64_exception_functions.empty(),
          "reserved ARM64 extended-header bits reject the table atomically");

    auto opcode_lengths = arm64_xdata_fixture();
    // Three-byte save_any_xreg, four-byte alloc_l, and one-byte end fill two
    // code words. The function itself remains a 16-byte mapped range.
    put(opcode_lengths, 0x700, 4u | (1u << 22) | (2u << 27), 4);
    put(opcode_lengths, 0x704, 2u, 4);
    put(opcode_lengths, 0x708, 0xe00000e7u, 4);
    put(opcode_lengths, 0x70c, 0xe4030201u, 4);
    auto opcode_loaded = load_fixture(opcode_lengths).value();
    check(opcode_loaded.metadata_complete &&
              opcode_loaded.metadata.pe->arm64_exception_functions.front().xdata->unwind_codes.size() == 3 &&
              opcode_loaded.metadata.pe->arm64_exception_functions.front().xdata->unwind_codes[0].encoding.size() == 3 &&
              opcode_loaded.metadata.pe->arm64_exception_functions.front().xdata->unwind_codes[1].encoding.size() == 4 &&
              opcode_loaded.metadata.pe->arm64_exception_functions.front().xdata->unwind_codes[2].opcode == 0xe4,
          "ARM64 xdata decoder respects 3-byte, 4-byte, and 1-byte unwind encodings");

    auto linked = arm64_exception_fixture();
    put(linked, 0x108 + 3 * 8 + 4, 16, 4);
    set_arm64_row(linked, 1, 0x1010, 0x2393);
    auto linked_loaded = load_fixture(linked).value();
    check(linked_loaded.metadata_complete &&
              linked_loaded.metadata.pe->arm64_exception_functions.size() == 2 &&
              linked_loaded.metadata.pe->arm64_exception_functions[1].kind == PeArm64UnwindKind::pdata_link &&
              linked_loaded.metadata.pe->arm64_exception_functions[1].linked_record_index ==
                  std::optional<std::uint32_t>{0},
          "ARM64 pdata links resolve to validated directory rows");

    auto functions = recover_functions(*linked_loaded.image, linked_loaded.metadata, {}, {}, {}).value();
    bool found_parent_root = false;
    bool found_link_root = false;
    for (const auto &entry : functions->functions) {
        for (const auto &seed : entry->seeds) {
            if (entry->entry.offset == 0x140001000ULL && seed.kind == FunctionSeedKind::unwind &&
                seed.unwind_evidence == FunctionSeedUnwindEvidence{0, 0x790, 8})
                found_parent_root = true;
            if (entry->entry.offset == 0x140001010ULL && seed.kind == FunctionSeedKind::unwind)
                found_link_root = true;
        }
    }
    check(found_parent_root && !found_link_root && !functions->complete,
          "an unbounded final ARM64 pdata link leaves the proven parent root and marks recovery partial");

    FixtureFile file(linked);
    const auto rebased = load_pe_at_base(FileStorage::open(file.path).value(), 0x180000000ULL, {}).value();
    functions = recover_functions(*rebased.image, rebased.metadata, {}, {}, {}).value();
    check(std::any_of(functions->functions.begin(), functions->functions.end(), [](const auto &entry) {
              return entry->entry.offset == 0x180001000ULL &&
                  std::any_of(entry->seeds.begin(), entry->seeds.end(), [](const auto &seed) {
                      return seed.kind == FunctionSeedKind::unwind &&
                          seed.unwind_evidence == FunctionSeedUnwindEvidence{0, 0x790, 8};
                  });
          }), "ARM64 pdata roots use the actual rebased image base");
}

void malformed_arm64_exception_metadata_is_atomic() {
    auto data = arm64_xdata_fixture();
    put(data, 0x108 + 3 * 8 + 4, 7, 4);
    auto loaded = load_fixture(data).value();
    check(!loaded.metadata_complete && loaded.metadata.pe->arm64_exception_functions.empty(),
          "partial ARM64 pdata rows reject the table atomically");
    auto functions = recover_functions(*loaded.image, loaded.metadata, {}, {}, {}).value();
    check(std::none_of(functions->functions.begin(), functions->functions.end(), [](const auto &entry) {
              return std::any_of(entry->seeds.begin(), entry->seeds.end(), [](const auto &seed) {
                  return seed.kind == FunctionSeedKind::unwind;
              });
          }), "malformed ARM64 exception tables contribute no partial unwind roots");

    data = arm64_exception_fixture();
    put(data, 0x794, 0x200000, 4); // reserved tag 00 but xdata reference out of image
    loaded = load_fixture(data).value();
    check(!loaded.metadata_complete && loaded.metadata.pe->arm64_exception_functions.empty(),
          "out-of-image ARM64 xdata references reject the table atomically");

    data = arm64_xdata_fixture();
    put(data, 0x700, 4u | (1u << 18) | (1u << 22) | (1u << 27), 4); // unsupported version
    loaded = load_fixture(data).value();
    check(!loaded.metadata_complete && loaded.metadata.pe->arm64_exception_functions.empty(),
          "unsupported ARM64 xdata versions reject the table atomically");

    data = arm64_xdata_fixture();
    put(data, 0x704, (1u << 18) | 2u, 4); // reserved scope bits
    loaded = load_fixture(data).value();
    check(!loaded.metadata_complete && loaded.metadata.pe->arm64_exception_functions.empty(),
          "reserved ARM64 epilog scope bits reject the table atomically");

    data = arm64_xdata_fixture();
    put(data, 0x704, 2u | (1u << 22), 4); // code index 1 is not an opcode boundary
    loaded = load_fixture(data).value();
    check(!loaded.metadata_complete && loaded.metadata.pe->arm64_exception_functions.empty(),
          "invalid ARM64 epilog code indexes reject the table atomically");

    data = arm64_xdata_fixture();
    put(data, 0x700, 4u, 4); // extension follows
    put(data, 0x704, 0xffffu, 4); // excessive scope count exceeds the image extent
    loaded = load_fixture(data).value();
    check(!loaded.metadata_complete && loaded.metadata.pe->arm64_exception_functions.empty(),
          "oversized ARM64 xdata scope arrays are rejected before allocation");

    data = arm64_xdata_fixture();
    put(data, 0x700, 4u, 4); // extension follows
    put(data, 0x704, 0u, 4); // empty extension counts
    loaded = load_fixture(data).value();
    check(!loaded.metadata_complete && loaded.metadata.pe->arm64_exception_functions.empty(),
          "empty ARM64 xdata extension counts are rejected");

    data = arm64_xdata_fixture();
    put(data, 0x700, 4u | (2u << 22) | (1u << 27), 4); // two unsorted scopes
    put(data, 0x704, 2u, 4);
    put(data, 0x708, 1u, 4);
    loaded = load_fixture(data).value();
    check(!loaded.metadata_complete && loaded.metadata.pe->arm64_exception_functions.empty(),
          "unordered ARM64 xdata epilog scopes reject the table atomically");

    data = arm64_xdata_fixture();
    data[0x708] = std::byte{0xed}; // reserved opcode
    loaded = load_fixture(data).value();
    check(!loaded.metadata_complete && loaded.metadata.pe->arm64_exception_functions.empty(),
          "reserved ARM64 unwind opcodes reject the table atomically");

    data = arm64_xdata_fixture();
    put(data, 0x708, 0x0080e7, 3); // reserved save_any extension form
    loaded = load_fixture(data).value();
    check(!loaded.metadata_complete && loaded.metadata.pe->arm64_exception_functions.empty(),
          "reserved ARM64 save_any encodings reject the table atomically");

    data = arm64_xdata_fixture();
    put(data, 0x700, 4u | (1u << 22) | (1u << 27), 4);
    put(data, 0x704, 0u, 4);
    put(data, 0x708, 0x00c011e7, 3); // save_preg P1: r=1 is reserved
    loaded = load_fixture(data).value();
    check(!loaded.metadata_complete && loaded.metadata.pe->arm64_exception_functions.empty(),
          "reserved ARM64 save_preg selector rejects the table atomically");

    data = arm64_xdata_fixture();
    data[0x708] = std::byte{0xe3}; // one-byte NOP followed by a four-byte opcode with only 3 bytes left
    data[0x709] = std::byte{0xe0};
    loaded = load_fixture(data).value();
    check(!loaded.metadata_complete && loaded.metadata.pe->arm64_exception_functions.empty(),
          "truncated ARM64 unwind opcodes reject the table atomically");

    data = arm64_exception_fixture();
    put(data, 0x108 + 3 * 8 + 4, 16, 4);
    set_arm64_row(data, 1, 0x1010, 0x2393);
    set_arm64_row(data, 0, 0x1000, 0x239b); // row 0 links to row 1, row 1 links to row 0
    loaded = load_fixture(data).value();
    check(!loaded.metadata_complete && loaded.metadata.pe->arm64_exception_functions.empty(),
          "cyclic ARM64 pdata links reject the table atomically");

    data = arm64_exception_fixture();
    put(data, 0x108 + 3 * 8 + 4, 16, 4);
    set_arm64_row(data, 1, 0x1010, 0x2397); // unaligned/in-row target
    loaded = load_fixture(data).value();
    check(!loaded.metadata_complete && loaded.metadata.pe->arm64_exception_functions.empty(),
          "unaligned ARM64 pdata link targets reject the table atomically");

    data = arm64_exception_fixture();
    put(data, 0x794, 1u | (0x81u << 2), 4); // 516-byte function exceeds initialized .text bytes
    loaded = load_fixture(data).value();
    check(!loaded.metadata_complete && loaded.metadata.pe->arm64_exception_functions.empty(),
          "ARM64 packed code ranges cannot exceed initialized executable bytes");

    data = arm64_exception_fixture();
    put(data, 0x108 + 3 * 8 + 4, 16, 4);
    set_arm64_row(data, 1, 0x1010, 0x3003); // valid alignment, but outside the pdata table
    loaded = load_fixture(data).value();
    check(!loaded.metadata_complete && loaded.metadata.pe->arm64_exception_functions.empty(),
          "dangling ARM64 pdata links reject the table atomically");

    data = arm64_xdata_fixture();
    put(data, 0x70c, 0x1200, 4); // virtual .text end is not initialized
    loaded = load_fixture(data).value();
    check(!loaded.metadata_complete && loaded.metadata.pe->arm64_exception_functions.empty(),
          "ARM64 xdata handlers must target initialized executable bytes");
}

void set_unwind_info(std::vector<std::byte> &data, std::uint8_t version_flags,
                     std::uint8_t prolog_size, std::uint8_t code_slots, std::uint8_t frame,
                     const std::vector<std::uint16_t> &slots, std::uint32_t rva = 0x2300) {
    put(data, 0x700 + (rva - 0x2300), std::uint32_t{version_flags} |
        (std::uint32_t{prolog_size} << 8) | (std::uint32_t{code_slots} << 16) |
        (std::uint32_t{frame} << 24), 4);
    for (std::size_t i = 0; i < slots.size(); ++i)
        put(data, 0x704 + (rva - 0x2300) + i * 2, slots[i], 2);
}

void parsed_exception_entries_seed_functions() {
    auto data = exception_fixture();
    // The first function needs to cover the complete five-byte prolog; the
    // second begins immediately after it.
    put(data, 0x794, 0x1005, 4);
    put(data, 0x79c, 0x1005, 4);
    put(data, 0x7a0, 0x1010, 4);
    // Version 1 unwind header: 5-byte prolog, ALLOC_SMALL 32 bytes at offset
    // 5, then PUSH_NONVOL RBP at offset 1.
    put(data, 0x700, 0x00020501, 4);
    put(data, 0x704, 0x50013205, 4);
    const auto loaded = load_fixture(data).value();
    check(loaded.metadata_complete, "valid AMD64 exception table is recognized as parsed metadata");
    check(loaded.metadata.pe->exception_functions.size() == 2 &&
              loaded.metadata.pe->exception_functions[0].begin_rva == 0x1000 &&
              loaded.metadata.pe->exception_functions[0].end_rva == 0x1005 &&
              loaded.metadata.pe->exception_functions[0].unwind_info_rva == 0x2300 &&
              loaded.metadata.pe->exception_functions[0].source.spans == std::vector<PeSourceSpan>{{{0x790}, 12}},
          "runtime-function rows preserve code bounds, unwind reference, and table provenance");
    const auto &unwind = loaded.metadata.pe->exception_functions.empty()
                             ? std::optional<PeUnwindInfo>{}
                             : loaded.metadata.pe->exception_functions.front().unwind_info;
    check(unwind && unwind->version == 1 && unwind->size_of_prolog == 5 &&
              unwind->operations.size() == 2 &&
              unwind->operations[0].kind == PeUnwindOperationKind::allocate_stack &&
              unwind->operations[0].stack_size == 32 && unwind->operations[0].code_offset == 5 &&
              unwind->operations[1].kind == PeUnwindOperationKind::push_nonvolatile &&
              unwind->operations[1].register_number == 5 && unwind->operations[1].code_offset == 1,
          "AMD64 UNWIND_INFO decodes ordered prolog operations and their stack/register effects");
    auto reloaded = load_fixture(data).value();
    check(loaded.metadata.pe->exception_functions == reloaded.metadata.pe->exception_functions,
          "independently loaded unwind metadata compares structurally for project snapshots");
    auto functions = recover_functions(*loaded.image, loaded.metadata, {}, {}, {}).value();
    std::vector<std::uint64_t> entries;
    for (const auto &function : functions->functions) entries.push_back(function->entry.offset);
    std::sort(entries.begin(), entries.end());
    check(entries == std::vector<std::uint64_t>{0x140001000ULL, 0x140001005ULL, 0x140001010ULL},
          "AMD64 runtime-function entries establish separate analysis function roots");

    FixtureFile file(data);
    auto rebased = load_pe_at_base(FileStorage::open(file.path).value(), 0x180000000ULL, {}).value();
    functions = recover_functions(*rebased.image, rebased.metadata, {}, {}, {}).value();
    entries.clear();
    for (const auto &function : functions->functions) entries.push_back(function->entry.offset);
    std::sort(entries.begin(), entries.end());
    check(entries == std::vector<std::uint64_t>{0x180001000ULL, 0x180001005ULL, 0x180001010ULL},
          "runtime-function RVA seeds are relocated to the loaded PE base");
}

void malformed_exception_table_is_diagnostic_and_atomic() {
    auto data = exception_fixture();
    put(data, 0x108 + 3 * 8 + 4, 23, 4);
    const auto partial = load_fixture(data).value();
    check(!partial.metadata_complete && !partial.diagnostics.empty(),
          "mis-sized AMD64 exception table is reported as incomplete metadata");
    auto functions = recover_functions(*partial.image, partial.metadata, {}, {}, {}).value();
    std::vector<std::uint64_t> entries;
    for (const auto &function : functions->functions) entries.push_back(function->entry.offset);
    std::sort(entries.begin(), entries.end());
    check(entries == std::vector<std::uint64_t>{0x140001000ULL, 0x140001010ULL} &&
              partial.metadata.pe->exception_functions.empty(),
          "malformed exception metadata contributes no partial function roots");

    data = exception_fixture();
    put(data, 0x794, 0x0fff, 4);
    const auto unsorted = load_fixture(data).value();
    check(!unsorted.metadata_complete,
          "out-of-order runtime-function rows are rejected as incomplete metadata");

    data = exception_fixture();
    put(data, 0x790, 0x2000, 4);
    put(data, 0x794, 0x2002, 4);
    const auto non_code = load_fixture(data).value();
    check(!non_code.metadata_complete && non_code.metadata.pe->exception_functions.empty(),
          "runtime-function ranges in non-executable sections are rejected atomically");

    data = exception_fixture();
    put(data, 0x790, 0x1200, 4);
    put(data, 0x794, 0x1202, 4);
    const auto zero_fill = load_fixture(data).value();
    check(!zero_fill.metadata_complete && zero_fill.metadata.pe->exception_functions.empty(),
          "runtime-function ranges cannot claim uninitialized zero-fill as code");

    data = exception_fixture();
    put(data, 0x798, 0x4000, 4);
    const auto invalid_unwind = load_fixture(data).value();
    check(!invalid_unwind.metadata_complete && invalid_unwind.metadata.pe->exception_functions.empty(),
          "out-of-image UNWIND_INFO references are rejected atomically");

    data = exception_fixture();
    set_unwind_info(data, 0x09, 0, 2, 0, {0x0006}, 0x2300); // ALLOC_SMALL with an invalid code offset.
    const auto invalid_code_offset = load_fixture(data).value();
    check(!invalid_code_offset.metadata_complete && invalid_code_offset.metadata.pe->exception_functions.empty(),
          "invalid UNWIND_CODE prolog offsets reject the exception table atomically");

    data = exception_fixture();
    set_unwind_info(data, 0x21, 0, 0, 0, {}, 0x2300); // CHAININFO.
    put(data, 0x704, 0x1000, 4);
    put(data, 0x708, 0x1002, 4);
    put(data, 0x70c, 0x2300, 4); // Self-reference.
    const auto cyclic_chain = load_fixture(data).value();
    check(!cyclic_chain.metadata_complete && cyclic_chain.metadata.pe->exception_functions.empty(),
          "cyclic chained UNWIND_INFO is rejected atomically");
}

void unwind_opcode_families_are_decoded() {
    auto data = exception_fixture();
    // All version-1 forms in a single descending-code-offset prolog.
    set_unwind_info(data, 1, 11, 10, 0x25,
                    {0x1a0b, 0x500a, 0x3209, 0xc408, 0x0002, 0x6807, 0x0003,
                     0x0306, 0x0105, 0x0004});
    set_runtime_function_extent(data, 11);
    auto loaded = load_fixture(data).value();
    check(loaded.metadata_complete && loaded.metadata.pe->exception_functions.front().unwind_info &&
              loaded.metadata.pe->exception_functions.front().unwind_info->operations.size() == 7,
          "version-1 unwind opcodes decode from one complete prolog");
    if (loaded.metadata.pe->exception_functions.empty() ||
        !loaded.metadata.pe->exception_functions.front().unwind_info) return;
    const auto &ops = loaded.metadata.pe->exception_functions.front().unwind_info->operations;
    check(ops[0].kind == PeUnwindOperationKind::push_machine_frame && ops[0].machine_frame_has_error_code &&
              ops[0].stack_size == 48 && ops[1].kind == PeUnwindOperationKind::push_nonvolatile &&
              ops[2].kind == PeUnwindOperationKind::allocate_stack && ops[2].stack_size == 32 &&
              ops[3].kind == PeUnwindOperationKind::save_nonvolatile && ops[3].register_number == 12 &&
              ops[3].stack_offset == 16 && ops[4].kind == PeUnwindOperationKind::save_xmm128 &&
              ops[4].register_number == 6 && ops[4].stack_offset == 48 &&
              ops[5].kind == PeUnwindOperationKind::set_frame_pointer && ops[5].stack_offset == 32 &&
              ops[6].kind == PeUnwindOperationKind::allocate_stack && ops[6].stack_size == 32,
          "unwind operations retain machine frame, saved registers, frame register, and allocation sizes");

    data = exception_fixture();
    set_unwind_info(data, 1, 4, 3, 0, {0x1104, 0x1000, 0x0000});
    set_runtime_function_extent(data, 4);
    loaded = load_fixture(data).value();
    check(loaded.metadata_complete && loaded.metadata.pe->exception_functions.front().unwind_info &&
              loaded.metadata.pe->exception_functions.front().unwind_info->operations.front().stack_size == 0x1000,
          "UWOP_ALLOC_LARGE with an unscaled 32-bit operand is decoded");

    data = exception_fixture();
    set_unwind_info(data, 1, 4, 3, 0, {0xc504, 0x0018, 0x0000});
    set_runtime_function_extent(data, 4);
    loaded = load_fixture(data).value();
    check(loaded.metadata_complete && loaded.metadata.pe->exception_functions.front().unwind_info &&
              loaded.metadata.pe->exception_functions.front().unwind_info->operations.front().stack_offset == 24,
          "UWOP_SAVE_NONVOL_FAR keeps its unscaled byte offset");

    data = exception_fixture();
    set_unwind_info(data, 1, 4, 3, 0, {0x6904, 0x0020, 0x0000});
    set_runtime_function_extent(data, 4);
    loaded = load_fixture(data).value();
    check(loaded.metadata_complete && loaded.metadata.pe->exception_functions.front().unwind_info &&
              loaded.metadata.pe->exception_functions.front().unwind_info->operations.front().stack_offset == 32,
          "UWOP_SAVE_XMM128_FAR keeps its aligned unscaled offset");

    data = exception_fixture();
    set_unwind_info(data, 0x09, 0, 0, 0, {});
    put(data, 0x704, 0x1000, 4);
    loaded = load_fixture(data).value();
    check(loaded.metadata_complete && loaded.metadata.pe->exception_functions.front().unwind_info &&
              loaded.metadata.pe->exception_functions.front().unwind_info->handler_rva == 0x1000,
          "exception-handler unwind flags preserve the validated handler RVA");

    data = exception_fixture();
    set_unwind_info(data, 0x21, 0, 0, 0, {});
    put(data, 0x704, 0x1000, 4);
    put(data, 0x708, 0x1002, 4);
    put(data, 0x70c, 0x2310, 4);
    set_unwind_info(data, 1, 0, 0, 0, {}, 0x2310);
    loaded = load_fixture(data).value();
    check(loaded.metadata_complete && loaded.metadata.pe->exception_functions.front().unwind_info &&
              loaded.metadata.pe->exception_functions.front().unwind_info->chained_function &&
              loaded.metadata.pe->exception_functions.front().unwind_info->chained_function->begin_rva == 0x1000,
          "valid chained RUNTIME_FUNCTION records preserve bounds and nested unwind data");
}
} // namespace

int main() {
    return run([] {
        parsed_exception_entries_seed_functions();
        malformed_exception_table_is_diagnostic_and_atomic();
        unwind_opcode_families_are_decoded();
        arm64_exception_directory_is_supported();
        malformed_arm64_exception_metadata_is_atomic();
    });
}

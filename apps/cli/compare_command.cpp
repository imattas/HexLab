#include "commands.hpp"
#include "argument_text.hpp"
#include "../compare_instruction_features.hpp"

#include "hexlab/compare/compare.hpp"
#include "hexlab/analysis/functions.hpp"
#include "hexlab/processors/instruction.hpp"
#include "hexlab/workspace/document.hpp"
#include "hexlab/image/metadata.hpp"

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <vector>

namespace hexlab::cli {
namespace {
std::string address(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

std::string json_string(std::string_view value) {
    std::ostringstream escaped;
    escaped << '"';
    constexpr char hex[] = "0123456789abcdef";
    for (const unsigned char ch : value) {
        switch (ch) {
        case '"': escaped << "\\\""; break;
        case '\\': escaped << "\\\\"; break;
        case '\b': escaped << "\\b"; break;
        case '\f': escaped << "\\f"; break;
        case '\n': escaped << "\\n"; break;
        case '\r': escaped << "\\r"; break;
        case '\t': escaped << "\\t"; break;
        default:
            if (ch < 0x20) escaped << "\\u00" << hex[ch >> 4] << hex[ch & 0xf];
            else escaped << static_cast<char>(ch);
        }
    }
    escaped << '"';
    return escaped.str();
}

struct InstructionHash {
    std::uint64_t value = UINT64_C(14695981039346656037);
    void add(std::uint64_t part) {
        for (unsigned i = 0; i < 8; ++i) {
            value ^= static_cast<std::uint8_t>(part >> (i * 8));
            value *= UINT64_C(1099511628211);
        }
    }
    void reg(const RegisterOperand &operand) {
        add(static_cast<std::uint64_t>(operand.bank)); add(operand.width); add(operand.high_byte);
    }
    void memory(const MemoryOperand &operand) {
        add(operand.data_width); add(operand.address_width); add(operand.scale);
        add(operand.segment.has_value()); if (operand.segment) reg(*operand.segment);
        add(operand.base.has_value()); if (operand.base) reg(*operand.base);
        add(operand.index.has_value()); if (operand.index) reg(*operand.index);
        add(operand.ip_relative); add(operand.resolved_address.has_value());
        if (!operand.ip_relative && !operand.resolved_address) add(static_cast<std::uint64_t>(operand.displacement));
    }
};

std::optional<std::uint64_t> instruction_fingerprint(const Instruction &instruction) {
    if (instruction.opcode == Opcode::opaque || instruction.opcode == Opcode::x86_opaque) return {};
    InstructionHash hash;
    hash.add(1); hash.add(static_cast<std::uint64_t>(instruction.opcode));
    hash.add(static_cast<std::uint64_t>(instruction.flow));
    hash.add(static_cast<std::uint64_t>(instruction.context.mode));
    hash.add(instruction.condition);
    hash.add(instruction.x86_condition ? static_cast<std::uint64_t>(*instruction.x86_condition) + 1 : 0);
    hash.add(instruction.operands.size());
    for (const auto &operand : instruction.operands) {
        hash.add(operand.index());
        std::visit([&](const auto &value) {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, RegisterOperand>) hash.reg(value);
            else if constexpr (std::is_same_v<T, MemoryOperand>) hash.memory(value);
            else if constexpr (std::is_same_v<T, ImmediateOperand>) {
                hash.add(value.value); hash.add(value.effective_width); hash.add(value.is_signed);
            } else if constexpr (std::is_same_v<T, RelativeOperand>) hash.add(value.effective_width);
            else if constexpr (std::is_same_v<T, FarPointerOperand>) {
                hash.add(value.selector); hash.add(value.offset_width);
            } else if constexpr (std::is_same_v<T, FarMemoryOperand>) {
                hash.memory(value.address); hash.add(value.offset_width);
            } else if constexpr (std::is_same_v<T, ArmShiftedRegisterOperand>) {
                hash.reg(value.source); hash.add(static_cast<std::uint64_t>(value.shift)); hash.add(value.amount);
                hash.add(value.amount_register.has_value()); if (value.amount_register) hash.reg(*value.amount_register);
            } else if constexpr (std::is_same_v<T, ArmMemoryOperand>) {
                hash.reg(value.base); hash.add(value.offset.index()); hash.add(value.add);
                hash.add(value.pre_index); hash.add(value.writeback); hash.add(value.data_width); hash.add(value.sign_extend);
                if (const auto *immediate = std::get_if<std::uint32_t>(&value.offset)) hash.add(*immediate);
                else {
                    const auto &shifted = std::get<ArmShiftedRegisterOperand>(value.offset);
                    hash.reg(shifted.source); hash.add(static_cast<std::uint64_t>(shifted.shift));
                    hash.add(shifted.amount); hash.add(shifted.amount_register.has_value());
                    if (shifted.amount_register) hash.reg(*shifted.amount_register);
                }
            } else if constexpr (std::is_same_v<T, ArmRegisterListOperand>) hash.add(value.mask);
        }, operand);
    }
    hash.add(instruction.access.size());
    for (const auto access : instruction.access) hash.add(static_cast<std::uint64_t>(access));
    hash.add(instruction.memory_read); hash.add(instruction.memory_write); hash.add(instruction.lock_prefix);
    hash.add(instruction.delay_slots);
    if (instruction.arm) {
        hash.add(static_cast<std::uint64_t>(instruction.arm->predicate));
        hash.add(static_cast<std::uint64_t>(instruction.arm->exchange));
        hash.add(instruction.arm->flags_written); hash.add(instruction.arm->flags_known);
        hash.add(instruction.arm->q_flag_may_set);
        hash.add(instruction.arm->writes_pc); hash.add(instruction.arm->writeback);
    } else hash.add(UINT64_MAX);
    return hash.value;
}

std::string stable_function_name(const ImageMetadata &metadata, Address entry) {
    for (const auto &symbol : metadata.exports)
        if (symbol.address == entry && symbol.name && !symbol.name->empty()) return *symbol.name;
    if (metadata.elf) for (const auto &symbol : metadata.elf->symbols)
        if (symbol.address == entry && !symbol.name.empty()) return symbol.name;
    if (metadata.macho) {
        for (const auto &symbol : metadata.macho->symbols)
            if (symbol.address == entry && !symbol.name.empty()) return symbol.name;
        for (const auto &symbol : metadata.macho->dyld_exports)
            if (symbol.is_definition() && symbol.address == entry && !symbol.name.empty()) return symbol.name;
    }
    if (metadata.pe) for (const auto &symbol : metadata.pe->pdb_symbols)
        if (symbol.procedure && symbol.address == entry && !symbol.name.empty()) return symbol.name;
    return {};
}

std::vector<compare::FunctionFeature> function_features(const FunctionSnapshot &snapshot,
                                                         const ImageMetadata &metadata) {
    std::unordered_map<std::uint64_t, const BasicBlock *> blocks;
    for (const auto &block : snapshot.blocks) if (block) blocks.emplace(block->id.value, block.get());
    std::vector<compare::FunctionFeature> features;
    features.reserve(snapshot.functions.size());
    std::map<std::uint64_t, std::size_t> feature_by_id;
    std::uint64_t cfg_instruction_fingerprint_budget = 2'000'000;
    std::uint64_t instruction_address_budget = 1'000'000;
    for (const auto &function : snapshot.functions) {
        if (!function) continue;
        compare::FunctionFeature feature;
        feature.entry = function->entry.offset;
        feature.address_space = function->entry.space.value;
        feature.name = stable_function_name(metadata, function->entry);
        feature.block_count = function->blocks.size();
        feature.opcode_histogram.resize(static_cast<std::size_t>(Opcode::arm_tbh) + 1);
        if (function->blocks.size() <= 100'000) {
            std::unordered_map<std::uint64_t, std::uint32_t> block_indexes;
            for (const auto id : function->blocks) {
                if (blocks.contains(id.value) && feature.cfg_blocks.size() < UINT32_MAX)
                    block_indexes.emplace(id.value, static_cast<std::uint32_t>(block_indexes.size()));
            }
            constexpr std::uint64_t offset_basis = UINT64_C(14695981039346656037);
            const auto mix = [](std::uint64_t hash, std::uint64_t value) {
                for (unsigned byte = 0; byte < 8; ++byte) {
                    hash ^= static_cast<std::uint8_t>(value >> (byte * 8));
                    hash *= UINT64_C(1099511628211);
                }
                return hash;
            };
            feature.cfg_blocks.reserve(block_indexes.size());
            for (const auto id : function->blocks) {
                const auto block = blocks.find(id.value);
                if (block == blocks.end()) continue;
                compare::CfgBlockFeature block_feature;
                std::vector<std::uint32_t> opcodes;
                bool block_fingerprints_complete = true;
                std::uint64_t instruction_position = 0;
                for (const auto &fact : block->second->instructions) {
                    if (!fact) {
                        block_fingerprints_complete = false;
                        ++instruction_position;
                        continue;
                    }
                    opcodes.push_back(static_cast<std::uint32_t>(fact->instruction.opcode));
                    const auto fingerprint = instruction_fingerprint(fact->instruction);
                    if (!fingerprint || cfg_instruction_fingerprint_budget <
                                            (block_feature.instruction_fingerprints.size() + 1) * 2) {
                        block_fingerprints_complete = false;
                    } else {
                        block_feature.instruction_fingerprints.push_back(*fingerprint);
                        block_feature.instruction_fingerprint_positions.push_back(instruction_position);
                        block_feature.instruction_semantics.push_back(::hexlab::app::compare_semantic_feature(fact->instruction, *fingerprint));
                    }
                    ++instruction_position;
                }
                block_feature.instruction_count = instruction_position;
                block_feature.instruction_fingerprints_available = !block_feature.instruction_fingerprints.empty();
                block_feature.instruction_fingerprints_complete = block_fingerprints_complete &&
                    block_feature.instruction_fingerprints.size() == instruction_position;
                cfg_instruction_fingerprint_budget -= block_feature.instruction_fingerprints.size() * 2;
                std::sort(opcodes.begin(), opcodes.end());
                auto hash = mix(offset_basis, opcodes.size());
                for (const auto opcode : opcodes) hash = mix(hash, opcode);
                std::vector<std::uint32_t> edge_kinds;
                for (const auto &edge : block->second->successors)
                    edge_kinds.push_back(static_cast<std::uint32_t>(edge.kind));
                std::sort(edge_kinds.begin(), edge_kinds.end());
                hash = mix(hash, edge_kinds.size());
                for (const auto kind : edge_kinds) hash = mix(hash, kind);
                block_feature.fingerprint = hash;
                for (const auto &edge : block->second->successors) {
                    if (!edge.block) continue;
                    const auto target = block_indexes.find(edge.block->value);
                    if (target != block_indexes.end())
                        block_feature.successors.push_back({target->second, static_cast<std::uint32_t>(edge.kind)});
                }
                feature.cfg_blocks.push_back(std::move(block_feature));
            }
        }
        bool fingerprint_complete = true;
        bool instruction_addresses_complete = true;
        for (const auto block_id : function->blocks) {
            const auto found = blocks.find(block_id.value);
            if (found == blocks.end()) continue;
            for (const auto &fact : found->second->instructions) {
                if (!fact) continue;
                ++feature.instruction_count;
                if (feature.instruction_count == 1)
                    feature.architecture = static_cast<std::uint32_t>(fact->instruction.context.architecture);
                const auto opcode = static_cast<std::size_t>(fact->instruction.opcode);
                if (opcode < feature.opcode_histogram.size()) ++feature.opcode_histogram[opcode];
                if (fingerprint_complete) {
                    if (const auto fingerprint = instruction_fingerprint(fact->instruction)) {
                        feature.instruction_fingerprints.push_back(*fingerprint);
                        if (instruction_addresses_complete && instruction_address_budget) {
                            feature.instruction_addresses.push_back({fact->instruction.address.offset,
                                                                     fact->instruction.address.space.value});
                            --instruction_address_budget;
                        } else {
                            instruction_addresses_complete = false;
                        }
                        feature.instruction_semantics.push_back(::hexlab::app::compare_semantic_feature(fact->instruction, *fingerprint));
                    } else {
                        fingerprint_complete = false;
                        feature.instruction_fingerprints.clear();
                        feature.instruction_addresses.clear();
                        feature.instruction_semantics.clear();
                    }
                }
            }
        }
        if (fingerprint_complete && !instruction_addresses_complete)
            feature.instruction_addresses.clear();
        feature_by_id.emplace(function->id.value, features.size());
        feature.direct_calls_complete = snapshot.complete;
        features.push_back(std::move(feature));
    }
    std::map<std::pair<std::uint32_t, std::uint64_t>, std::size_t> feature_by_address;
    for (std::size_t i = 0; i < features.size(); ++i)
        feature_by_address.emplace(std::pair{features[i].address_space, features[i].entry}, i);
    for (const auto &call : snapshot.calls) {
        const auto owner = feature_by_id.find(call.owner.value);
        if (owner == feature_by_id.end()) continue;
        auto &feature = features[owner->second];
        ++feature.call_count;
        if (call.target && feature_by_address.contains({call.target->space.value, call.target->offset}))
            feature.direct_calls.push_back({call.target->offset, call.target->space.value});
    }
    for (auto &feature : features) {
        auto &calls = feature.direct_calls;
        std::sort(calls.begin(), calls.end(), [](const auto &a, const auto &b) {
            return std::tie(a.address_space, a.entry) < std::tie(b.address_space, b.entry);
        });
        calls.erase(std::unique(calls.begin(), calls.end()), calls.end());
    }
    return features;
}

struct CompareInput {
    std::vector<std::string> keys;
    std::vector<std::uint64_t> addresses;
    std::vector<ByteView> views;
    std::vector<std::vector<compare::RegionView::IgnoredRange>> ignored_ranges;
    compare::ImageView image;
};

Result<CompareInput> make_compare_input(const Image &image, const ImageMetadata &metadata,
                                       std::stop_token stop) {
    CompareInput input;
    std::map<std::string, std::size_t> occurrences;
    std::vector<const Segment *> selected_segments;
    for (const auto &segment : image.layout().segments) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "comparison canceled"};
        const auto storage_size = image.storage()->size();
        if (segment.file_begin.value >= storage_size) continue;
        const auto count = std::min(segment.file_size, storage_size - segment.file_begin.value);
        if (count == 0) continue;
        if (count > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
            return Error{ErrorCode::resource_limit, "comparison segment exceeds addressable memory"};
        auto view = image.storage()->read_at(segment.file_begin, static_cast<std::size_t>(count));
        if (!view) return view.error();
        const auto base = segment.name.empty() ? std::string("segment") : segment.name;
        input.keys.push_back(base + "#" + std::to_string(occurrences[base]++));
        input.addresses.push_back(segment.begin.offset);
        input.views.push_back(std::move(view.value()));
        selected_segments.push_back(&segment);
    }
    input.ignored_ranges.resize(input.views.size());
    constexpr std::size_t relocation_item_budget = 1'000'000;
    std::size_t relocation_items = 0;
    const auto add_file_field = [&](FileOffset place, std::uint64_t size) -> Result<bool> {
        if (!size || size > 64) return true;
        for (std::size_t index = 0; index < selected_segments.size(); ++index) {
            if ((index & 0xffu) == 0 && stop.stop_requested())
                return Error{ErrorCode::canceled, "comparison canceled"};
            const auto &segment = *selected_segments[index];
            const auto region_size = input.views[index].bytes.size();
            if (place.value < segment.file_begin.value) continue;
            const auto offset = place.value - segment.file_begin.value;
            if (offset > region_size || size > region_size - offset) continue;
            if (++relocation_items > relocation_item_budget)
                return Error{ErrorCode::resource_limit, "comparison relocation mask exceeds one million fields"};
            input.ignored_ranges[index].push_back({offset, size});
        }
        return true;
    };
    const auto add_address_field = [&](Address place, std::uint64_t size) -> Result<bool> {
        const auto file_place = image.to_file_offset(place);
        if (!file_place) return true;
        return add_file_field(file_place.value(), size);
    };
    std::size_t visited_relocations = 0;
    const auto check_cancel = [&]() {
        return ((visited_relocations++ & 0xffu) == 0) && stop.stop_requested();
    };
    if (metadata.elf) {
        for (const auto &relocation : metadata.elf->relocations) {
            if (check_cancel()) return Error{ErrorCode::canceled, "comparison canceled"};
            if (!relocation.field_size || relocation.kind == ElfRelocationKind::unknown ||
                relocation.kind == ElfRelocationKind::copy || relocation.kind == ElfRelocationKind::symbol_size ||
                relocation.kind == ElfRelocationKind::tls || relocation.kind == ElfRelocationKind::ifunc)
                continue;
            const auto result = relocation.file_place
                ? add_file_field(*relocation.file_place, *relocation.field_size)
                : (relocation.place ? add_address_field(*relocation.place, *relocation.field_size) : Result<bool>(true));
            if (!result) return result.error();
        }
    }
    if (metadata.macho) {
        for (const auto &relocation : metadata.macho->relocations) {
            if (check_cancel()) return Error{ErrorCode::canceled, "comparison canceled"};
            if (!relocation.field_size || relocation.auxiliary || relocation.kind == MachORelocationKind::pair ||
                relocation.kind == MachORelocationKind::addend || relocation.kind == MachORelocationKind::unknown)
                continue;
            const auto result = relocation.file_place
                ? add_file_field(*relocation.file_place, relocation.field_size)
                : (relocation.place ? add_address_field(*relocation.place, relocation.field_size) : Result<bool>(true));
            if (!result) return result.error();
        }
        for (const auto &fixup : metadata.macho->dyld_fixups) {
            if (check_cancel()) return Error{ErrorCode::canceled, "comparison canceled"};
            if (!fixup.field_size) continue;
            const auto result = fixup.file_place
                ? add_file_field(*fixup.file_place, fixup.field_size)
                : (fixup.place ? add_address_field(*fixup.place, fixup.field_size) : Result<bool>(true));
            if (!result) return result.error();
        }
        for (const auto &pointer : metadata.macho->chained_pointers) {
            if (check_cancel()) return Error{ErrorCode::canceled, "comparison canceled"};
            if (!pointer.field_size) continue;
            const auto result = pointer.file_place
                ? add_file_field(*pointer.file_place, pointer.field_size)
                : (pointer.place ? add_address_field(*pointer.place, pointer.field_size) : Result<bool>(true));
            if (!result) return result.error();
        }
        for (const auto &pointer : metadata.macho->firmware_chained_pointers) {
            if (check_cancel()) return Error{ErrorCode::canceled, "comparison canceled"};
            if (!pointer.field_size) continue;
            const auto result = add_file_field(pointer.file_place, pointer.field_size);
            if (!result) return result.error();
        }
    }
    if (metadata.pe && (image.layout().architecture == Architecture::x86 ||
                        image.layout().architecture == Architecture::x86_64)) {
        for (const auto &relocation : metadata.relocations) {
            if (check_cancel()) return Error{ErrorCode::canceled, "comparison canceled"};
            std::uint64_t width = 0;
            switch (relocation.type) {
            case 1: case 2: case 4: width = 2; break;
            case 3: width = 4; break;
            case 10: width = 8; break;
            default: break;
            }
            if (!width) continue;
            auto result = add_address_field(relocation.address, width);
            if (!result) return result.error();
        }
    }
    for (auto &ranges : input.ignored_ranges) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "comparison canceled"};
        std::sort(ranges.begin(), ranges.end(), [](const auto &a, const auto &b) {
            return std::tie(a.offset, a.size) < std::tie(b.offset, b.size);
        });
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "comparison canceled"};
        std::vector<compare::RegionView::IgnoredRange> merged;
        merged.reserve(ranges.size());
        for (const auto &range : ranges) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "comparison canceled"};
            if (merged.empty() || range.offset > merged.back().offset + merged.back().size) {
                merged.push_back(range);
                continue;
            }
            const auto end = std::max(merged.back().offset + merged.back().size, range.offset + range.size);
            merged.back().size = end - merged.back().offset;
        }
        ranges = std::move(merged);
    }
    input.image.regions.reserve(input.views.size());
    for (std::size_t index = 0; index < input.views.size(); ++index) {
        input.image.regions.push_back({input.keys[index], input.addresses[index], input.views[index].bytes,
                                       input.ignored_ranges[index]});
    }
    return input;
}

std::uint64_t parse_count(std::wstring_view text) {
    if (text.empty()) throw std::invalid_argument("expected an unsigned integer");
    std::size_t start = text.starts_with(L"0x") || text.starts_with(L"0X") ? 2 : 0;
    if (start == text.size()) throw std::invalid_argument("expected an unsigned integer");
    std::uint64_t value = 0;
    for (std::size_t i = start; i < text.size(); ++i) {
        const wchar_t ch = text[i];
        unsigned digit;
        if (ch >= L'0' && ch <= L'9') digit = static_cast<unsigned>(ch - L'0');
        else if (start && ch >= L'a' && ch <= L'f') digit = static_cast<unsigned>(ch - L'a' + 10);
        else if (start && ch >= L'A' && ch <= L'F') digit = static_cast<unsigned>(ch - L'A' + 10);
        else throw std::invalid_argument("expected an unsigned integer");
        const unsigned base = start ? 16u : 10u;
        if (digit >= base || value > (UINT64_MAX - digit) / base)
            throw std::invalid_argument("integer value overflows");
        value = value * base + digit;
    }
    return value;
}
} // namespace

int run_compare_cli(std::span<const std::wstring_view> arguments, std::ostream &out, std::ostream &err) {
    if (arguments.size() == 1 && arguments[0] == L"--help") {
        out << "Usage: hexlab_cli compare <old-image> <new-image> [--window <bytes>] [--anchor <bytes>] [--limit <runs>] [--json]\n"
               "       [--functions] [--function-limit <count>] [--instruction-limit <runs>] [--min-confidence <0..100>] [--ambiguity-margin <0..100>]\n"
               "Compare file-backed regions; optionally recover and match functions with instruction alignment.\n";
        return 0;
    }
    try {
        std::vector<std::filesystem::path> paths;
        compare::CompareOptions options;
        std::uint64_t run_limit = 1000;
        std::uint64_t function_limit = 100;
        std::uint64_t instruction_limit = 1000;
        bool match_functions = false;
        bool json_output = false;
        compare::FunctionMatchOptions function_options;
        for (std::size_t i = 0; i < arguments.size(); ++i) {
            const auto argument = arguments[i];
            if (argument == L"--functions") {
                match_functions = true;
            } else if (argument == L"--json") {
                json_output = true;
            } else if (argument == L"--window" || argument == L"--anchor" || argument == L"--limit" ||
                       argument == L"--function-limit" || argument == L"--min-confidence" ||
                       argument == L"--ambiguity-margin" || argument == L"--instruction-limit") {
                if (++i == arguments.size()) throw std::invalid_argument("option requires a value");
                const auto value = parse_count(arguments[i]);
                if (argument == L"--window") options.resync_window_bytes = value;
                else if (argument == L"--anchor") options.resync_anchor_bytes = value;
                else if (argument == L"--limit") run_limit = value;
                else if (argument == L"--function-limit") function_limit = value;
                else if (argument == L"--instruction-limit") instruction_limit = value;
                else if (argument == L"--min-confidence") {
                    if (value > 100) throw std::invalid_argument("minimum confidence must be between 0 and 100");
                    function_options.minimum_confidence = static_cast<std::uint32_t>(value);
                    match_functions = true;
                } else {
                    if (value > 100) throw std::invalid_argument("ambiguity margin must be between 0 and 100");
                    function_options.ambiguity_margin = static_cast<std::uint32_t>(value);
                    match_functions = true;
                }
            } else if (argument.starts_with(L"--")) {
                throw std::invalid_argument("unknown compare option");
            } else {
                paths.push_back(path_from_wide(argument));
            }
        }
        if (paths.size() != 2) throw std::invalid_argument("compare requires exactly two image paths");
        if (run_limit > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
            throw std::invalid_argument("run limit exceeds addressable memory");
        if (function_limit > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
            throw std::invalid_argument("function limit exceeds addressable memory");
        if (instruction_limit > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
            throw std::invalid_argument("instruction diff limit exceeds addressable memory");
        options.max_change_runs = run_limit;

        OpenRequest old_request;
        old_request.path = paths[0];
        old_request.run_analysis = false;
        OpenRequest new_request;
        new_request.path = paths[1];
        new_request.run_analysis = false;
        auto old_document = load_document(old_request, {{1}, 1}, {});
        if (!old_document) {
            err << "Old image: " << old_document.error().message << '\n';
            return 1;
        }
        auto new_document = load_document(new_request, {{2}, 1}, {});
        if (!new_document) {
            err << "New image: " << new_document.error().message << '\n';
            return 1;
        }
        auto old_input = make_compare_input(*old_document.value()->image, old_document.value()->metadata,
                                            options.stop_token);
        auto new_input = make_compare_input(*new_document.value()->image, new_document.value()->metadata,
                                            options.stop_token);
        if (!old_input || !new_input) {
            err << "Comparison input: " << (!old_input ? old_input.error().message : new_input.error().message) << '\n';
            return 1;
        }
        auto report = compare::compare(old_input.value().image, new_input.value().image, options);
        if (!report) {
            err << "Comparison: " << report.error().message << '\n';
            return 1;
        }
        const auto &summary = report.value().summary;
        if (json_output) {
            std::optional<compare::Result<std::vector<compare::FunctionMatch>>> function_result;
            std::vector<compare::FunctionFeature> old_features, new_features;
            if (match_functions) {
                auto old_functions = recover_functions(*old_document.value()->image,
                    old_document.value()->metadata, {}, {}, {});
                auto new_functions = recover_functions(*new_document.value()->image,
                    new_document.value()->metadata, {}, {}, {});
                if (!old_functions || !new_functions) {
                    err << "Function analysis: "
                        << (!old_functions ? old_functions.error().message : new_functions.error().message) << '\n';
                    return 1;
                }
                old_features = function_features(*old_functions.value(), old_document.value()->metadata);
                new_features = function_features(*new_functions.value(), new_document.value()->metadata);
                function_result.emplace(compare::match_functions_detailed(
                    old_features, new_features, function_options));
                if (!*function_result) {
                    err << "Function comparison: " << function_result->error().message << '\n';
                    return 1;
                }
            }
            const auto shown_runs = std::min<std::size_t>(report.value().runs.size(), static_cast<std::size_t>(run_limit));
            out << "{\"schema\":\"" << (match_functions ? "hexlab.compare.v7" : "hexlab.compare.v2")
                << "\",\"summary\":{\"compared_bytes\":" << summary.compared_bytes
                << ",\"equal_bytes\":" << summary.equal_bytes << ",\"changed_bytes\":" << summary.changed_bytes
                << ",\"added_bytes\":" << summary.added_bytes << ",\"removed_bytes\":" << summary.removed_bytes
                << ",\"ignored_bytes\":" << summary.ignored_bytes << ",\"matched_regions\":" << summary.matched_regions
                << ",\"added_regions\":" << summary.added_regions << ",\"removed_regions\":" << summary.removed_regions
                << "},\"total_regions\":" << report.value().regions.size() << ",\"regions\":[";
            const auto shown_regions = std::min<std::size_t>(report.value().regions.size(), static_cast<std::size_t>(run_limit));
            for (std::size_t i = 0; i < shown_regions; ++i) {
                const auto &region = report.value().regions[i];
                const char *kind = region.kind == compare::RegionChangeKind::matched ? "matched" :
                    region.kind == compare::RegionChangeKind::added ? "added" : "removed";
                if (i) out << ',';
                out << "{\"kind\":" << json_string(kind) << ",\"region\":" << json_string(region.region_key)
                    << ",\"old_address\":";
                if (region.old_address) out << json_string(address(*region.old_address)); else out << "null";
                out << ",\"new_address\":";
                if (region.new_address) out << json_string(address(*region.new_address)); else out << "null";
                out << ",\"old_size\":" << region.old_size << ",\"new_size\":" << region.new_size
                    << ",\"compared\":" << region.compared_bytes << ",\"equal\":" << region.equal_bytes
                    << ",\"changed\":" << region.changed_bytes << ",\"ignored\":" << region.ignored_bytes
                    << ",\"added_bytes\":" << region.added_bytes << ",\"removed_bytes\":" << region.removed_bytes << '}';
            }
            out << "],\"omitted_regions\":" << (report.value().regions.size() - shown_regions)
                << ",\"total_runs\":" << report.value().total_runs << ",\"runs\":[";
            for (std::size_t i = 0; i < shown_runs; ++i) {
                const auto &run = report.value().runs[i];
                const char *kind = run.kind == compare::ChangeKind::changed ? "changed"
                                 : run.kind == compare::ChangeKind::added ? "added" : "removed";
                if (i) out << ',';
                out << "{\"kind\":" << json_string(kind) << ",\"region\":" << json_string(run.region_key)
                    << ",\"size\":" << run.size << ",\"old_address\":";
                if (run.old_address) out << json_string(address(*run.old_address)); else out << "null";
                out << ",\"new_address\":";
                if (run.new_address) out << json_string(address(*run.new_address)); else out << "null";
                out << '}';
            }
            out << "],\"omitted_runs\":" << (report.value().total_runs - shown_runs);
            if (function_result) {
                std::uint64_t matched_count = 0, ambiguous_count = 0, added_count = 0, removed_count = 0;
                for (const auto &match : function_result->value()) {
                    switch (match.kind) {
                    case compare::FunctionMatchKind::matched: ++matched_count; break;
                    case compare::FunctionMatchKind::ambiguous: ++ambiguous_count; break;
                    case compare::FunctionMatchKind::added: ++added_count; break;
                    case compare::FunctionMatchKind::removed: ++removed_count; break;
                    }
                }
                const auto &matches = function_result->value();
                const auto shown_matches = std::min<std::size_t>(matches.size(),
                    static_cast<std::size_t>(function_limit));
                std::uint64_t remaining_instruction_runs = instruction_limit;
                std::uint64_t remaining_block_summaries = 2'000;
                std::uint64_t remaining_partial_evidence = 2'000;
                const auto write_semantic = [&](const compare::InstructionChangeEvidence &evidence) {
                    out << "{\"available\":" << (evidence.available ? "true" : "false")
                        << ",\"opcode\":" << evidence.opcode_changes
                        << ",\"flow\":" << evidence.flow_changes
                        << ",\"operand\":" << evidence.operand_changes
                        << ",\"effect\":" << evidence.effect_changes
                        << ",\"unclassified\":" << evidence.unclassified_changes << '}';
                };
                const auto write_instruction_address = [&](const std::optional<compare::FunctionAddress> &location) {
                    if (!location) { out << "null"; return; }
                    out << "{\"address\":" << json_string(address(location->entry))
                        << ",\"space\":" << location->address_space << '}';
                };
                out << ",\"functions\":{\"matched\":" << matched_count
                    << ",\"ambiguous\":" << ambiguous_count << ",\"added\":" << added_count
                    << ",\"removed\":" << removed_count << ",\"total_matches\":" << matches.size()
                    << ",\"matches\":[";
                for (std::size_t i = 0; i < shown_matches; ++i) {
                    const auto &match = matches[i];
                    const char *kind = match.kind == compare::FunctionMatchKind::matched ? "matched" :
                        match.kind == compare::FunctionMatchKind::ambiguous ? "ambiguous" :
                        match.kind == compare::FunctionMatchKind::added ? "added" : "removed";
                    if (i) out << ',';
                    out << "{\"kind\":" << json_string(kind) << ",\"confidence\":" << match.confidence
                        << ",\"old_address\":";
                    if (match.old_entry) out << json_string(address(*match.old_entry)); else out << "null";
                    out << ",\"old_space\":" << match.old_space << ",\"old_name\":"
                        << json_string(match.old_name) << ",\"new_address\":";
                    if (match.new_entry) out << json_string(address(*match.new_entry)); else out << "null";
                    out << ",\"new_space\":" << match.new_space << ",\"new_name\":"
                        << json_string(match.new_name) << ",\"call_targets\":{\"available\":"
                        << (match.call_targets.available ? "true" : "false")
                        << ",\"unchanged\":" << match.call_targets.unchanged
                        << ",\"added\":" << match.call_targets.added
                        << ",\"removed\":" << match.call_targets.removed
                        << ",\"ambiguous\":" << match.call_targets.ambiguous
                        << "},\"evidence\":{\"base_confidence\":"
                        << match.evidence.base_confidence << ",\"supporting_call_neighbors\":"
                        << match.evidence.supporting_call_neighbors << ",\"call_graph_round\":"
                        << match.evidence.call_graph_round << ",\"score_breakdown\":";
                    const auto &score = match.evidence.score_breakdown;
                    if (!score.available) out << "null";
                    else {
                        out << "{\"shape\":" << score.shape_similarity << ",\"instruction\":";
                        if (score.instruction_available) out << score.instruction_similarity; else out << "null";
                        out << ",\"histogram\":";
                        if (score.histogram_available) out << score.histogram_similarity; else out << "null";
                        out << ",\"cfg\":";
                        if (score.cfg_available) out << score.cfg_similarity; else out << "null";
                        out << ",\"exact_name\":" << (score.exact_name ? "true" : "false")
                            << ",\"name_floor_applied\":" << (score.name_floor_applied ? "true" : "false") << '}';
                    }
                    out << '}';
                    if (match.kind != compare::FunctionMatchKind::matched || !match.old_entry || !match.new_entry) {
                        out << '}';
                        continue;
                    }
                    const auto old_feature = std::find_if(old_features.begin(), old_features.end(), [&](const auto &feature) {
                        return feature.entry == *match.old_entry && feature.address_space == match.old_space;
                    });
                    const auto new_feature = std::find_if(new_features.begin(), new_features.end(), [&](const auto &feature) {
                        return feature.entry == *match.new_entry && feature.address_space == match.new_space;
                    });
                    if (old_feature == old_features.end() || new_feature == new_features.end()) {
                        out << ",\"details_available\":false}";
                        continue;
                    }
                    compare::FunctionBlockMatchOptions block_options;
                    auto block_mapping = compare::correspond_function_blocks(old_feature->cfg_blocks,
                        new_feature->cfg_blocks, block_options);
                    out << ",\"blocks\":";
                    if (!block_mapping) {
                        out << "null";
                    } else {
                        const auto &mapping = block_mapping.value();
                        out << "{\"matched\":" << mapping.matched << ",\"added\":" << mapping.added
                            << ",\"removed\":" << mapping.removed << ",\"ambiguous\":" << mapping.ambiguous
                            << ",\"budget_exhausted\":" << (mapping.budget_exhausted ? "true" : "false")
                            << ",\"instruction_budget_exhausted\":"
                            << (mapping.instruction_diff_budget_exhausted ? "true" : "false")
                            << ",\"partial_instruction_evidence\":[";
                        bool first_partial_evidence = true;
                        std::uint64_t omitted_partial_evidence = 0;
                        for (const auto &block : mapping.blocks) {
                            const auto &evidence = block.instruction_evidence;
                            if (!evidence.available || evidence.complete) continue;
                            if (!remaining_partial_evidence) { ++omitted_partial_evidence; continue; }
                            --remaining_partial_evidence;
                            if (!first_partial_evidence) out << ',';
                            first_partial_evidence = false;
                            out << "{\"old_block\":";
                            if (block.old_block) out << *block.old_block; else out << "null";
                            out << ",\"new_block\":";
                            if (block.new_block) out << *block.new_block; else out << "null";
                            out << ",\"old_coverage_percent\":" << unsigned(evidence.old_coverage_percent)
                                << ",\"new_coverage_percent\":" << unsigned(evidence.new_coverage_percent)
                                << ",\"fingerprint_similarity_percent\":" << evidence.fingerprint_similarity
                                << ",\"adjacency_available\":" << (evidence.adjacency_available ? "true" : "false")
                                << ",\"adjacency_similarity_percent\":" << evidence.adjacency_similarity << '}';
                        }
                        out << "],\"omitted_partial_instruction_evidence\":" << omitted_partial_evidence
                            << ",\"changed_blocks\":[";
                        bool first_block = true;
                        std::uint64_t omitted_blocks = 0;
                        for (const auto &block : mapping.blocks) {
                            const auto &diff = block.instruction_diff;
                            if (!block.instruction_diff_available || (!diff.changed_instructions &&
                                !diff.removed_instructions && !diff.added_instructions)) continue;
                            if (!remaining_block_summaries) { ++omitted_blocks; continue; }
                            --remaining_block_summaries;
                            if (!first_block) out << ',';
                            first_block = false;
                            out << "{\"old_block\":";
                            if (block.old_block) out << *block.old_block; else out << "null";
                            out << ",\"new_block\":";
                            if (block.new_block) out << *block.new_block; else out << "null";
                            out << ",\"equal\":" << diff.equal_instructions
                                << ",\"changed\":" << diff.changed_instructions
                                << ",\"removed\":" << diff.removed_instructions
                                << ",\"added\":" << diff.added_instructions << ",\"semantic\":";
                            write_semantic(diff.semantic);
                            out << '}';
                        }
                        out << "],\"omitted_changed_blocks\":" << omitted_blocks << '}';
                    }
                    out << ",\"instruction_diff\":";
                    if (old_feature->instruction_fingerprints.empty() || new_feature->instruction_fingerprints.empty()) {
                        out << "null";
                    } else {
                        auto body = compare::diff_function_instructions_detailed(old_feature->instruction_fingerprints,
                            new_feature->instruction_fingerprints, old_feature->instruction_semantics,
                            new_feature->instruction_semantics);
                        if (!body) {
                            out << "null";
                        } else {
                            auto &diff = body.value();
                            ::hexlab::app::attach_instruction_addresses(diff, *old_feature, *new_feature);
                            out << "{\"equal\":" << diff.equal_instructions << ",\"changed\":"
                                << diff.changed_instructions << ",\"removed\":" << diff.removed_instructions
                                << ",\"added\":" << diff.added_instructions << ",\"semantic\":";
                            write_semantic(diff.semantic);
                            out << ",\"changes\":[";
                            bool first_change = true;
                            std::uint64_t omitted_changes = 0;
                            for (const auto &run : diff.runs) {
                                if (run.kind == compare::InstructionDiffKind::equal) continue;
                                if (!remaining_instruction_runs) { ++omitted_changes; continue; }
                                --remaining_instruction_runs;
                                if (!first_change) out << ',';
                                first_change = false;
                                const char *run_kind = run.kind == compare::InstructionDiffKind::changed ? "changed" :
                                    run.kind == compare::InstructionDiffKind::removed ? "removed" : "added";
                                out << "{\"kind\":" << json_string(run_kind)
                                    << ",\"old_start\":" << run.old_start << ",\"old_count\":" << run.old_count
                                    << ",\"new_start\":" << run.new_start << ",\"new_count\":" << run.new_count
                                    << ",\"old_address\":";
                                write_instruction_address(run.old_address);
                                out << ",\"new_address\":";
                                write_instruction_address(run.new_address);
                                out << ",\"semantic\":";
                                write_semantic(run.semantic);
                                out << '}';
                            }
                            out << "],\"omitted_changes\":" << omitted_changes << '}';
                        }
                    }
                    out << '}';
                }
                out << "],\"omitted_matches\":" << (matches.size() - shown_matches) << '}';
            }
            out << "}\n";
            return 0;
        }
        out << "Compared bytes: " << summary.compared_bytes << "\nEqual: " << summary.equal_bytes
            << "\nChanged: " << summary.changed_bytes << "\nAdded: " << summary.added_bytes
            << "\nRemoved: " << summary.removed_bytes << "\nIgnored: " << summary.ignored_bytes
            << "\nMatched regions: " << summary.matched_regions
            << "\nAdded regions: " << summary.added_regions << "\nRemoved regions: " << summary.removed_regions
            << "\nChange runs: " << report.value().total_runs << '\n';
        const auto shown_regions = std::min<std::size_t>(report.value().regions.size(), static_cast<std::size_t>(run_limit));
        out << "Region summaries: " << report.value().regions.size() << '\n';
        for (std::size_t i = 0; i < shown_regions; ++i) {
            const auto &region = report.value().regions[i];
            const char *kind = region.kind == compare::RegionChangeKind::matched ? "matched" :
                region.kind == compare::RegionChangeKind::added ? "added" : "removed";
            out << "region " << kind << ' ' << region.region_key << " old-size=" << region.old_size
                << " new-size=" << region.new_size << " compared=" << region.compared_bytes
                << " equal=" << region.equal_bytes << " changed=" << region.changed_bytes
                << " ignored=" << region.ignored_bytes << " added=" << region.added_bytes
                << " removed=" << region.removed_bytes << '\n';
        }
        if (shown_regions < report.value().regions.size())
            out << "... " << (report.value().regions.size() - shown_regions) << " regions omitted (use --limit)\n";
        const auto shown = std::min<std::size_t>(report.value().runs.size(), static_cast<std::size_t>(run_limit));
        for (std::size_t i = 0; i < shown; ++i) {
            const auto &run = report.value().runs[i];
            const char *kind = run.kind == compare::ChangeKind::changed ? "changed"
                             : run.kind == compare::ChangeKind::added ? "added" : "removed";
            out << kind << ' ' << run.region_key << " size=" << run.size;
            if (run.old_address) out << " old=" << address(*run.old_address);
            if (run.new_address) out << " new=" << address(*run.new_address);
            out << '\n';
        }
        if (shown < report.value().total_runs)
            out << "... " << (report.value().total_runs - shown) << " runs omitted (use --limit)\n";
        if (match_functions) {
            auto old_functions = recover_functions(*old_document.value()->image, old_document.value()->metadata, {}, {}, {});
            auto new_functions = recover_functions(*new_document.value()->image, new_document.value()->metadata, {}, {}, {});
            if (!old_functions || !new_functions) {
                err << "Function analysis: " << (!old_functions ? old_functions.error().message : new_functions.error().message) << '\n';
                return 1;
            }
            auto old_features = function_features(*old_functions.value(), old_document.value()->metadata);
            auto new_features = function_features(*new_functions.value(), new_document.value()->metadata);
            auto matches = compare::match_functions_detailed(old_features, new_features, function_options);
            if (!matches) {
                err << "Function comparison: " << matches.error().message << '\n';
                return 1;
            }
            std::uint64_t matched_count = 0, ambiguous_count = 0, added_count = 0, removed_count = 0;
            for (const auto &match : matches.value()) {
                switch (match.kind) {
                case compare::FunctionMatchKind::matched: ++matched_count; break;
                case compare::FunctionMatchKind::ambiguous: ++ambiguous_count; break;
                case compare::FunctionMatchKind::added: ++added_count; break;
                case compare::FunctionMatchKind::removed: ++removed_count; break;
                }
            }
            out << "Function matches: " << matched_count << " matched, " << ambiguous_count << " ambiguous, "
                << added_count << " added, " << removed_count << " removed\n";
            const auto function_rows = std::min<std::size_t>(matches.value().size(), static_cast<std::size_t>(function_limit));
            std::uint64_t remaining_instruction_runs = instruction_limit;
            std::uint64_t remaining_block_instruction_summaries = 2'000;
            for (std::size_t i = 0; i < function_rows; ++i) {
                const auto &match = matches.value()[i];
                const char *kind = match.kind == compare::FunctionMatchKind::matched ? "matched" :
                    match.kind == compare::FunctionMatchKind::ambiguous ? "ambiguous" :
                    match.kind == compare::FunctionMatchKind::added ? "added" : "removed";
                out << "function " << kind << " confidence=" << match.confidence << "%";
                if (match.old_entry) out << " old=" << (match.old_space ? std::to_string(match.old_space) + ":" : "") << address(*match.old_entry);
                if (!match.old_name.empty()) out << " old-name=\"" << match.old_name << '"';
                if (match.new_entry) out << " new=" << (match.new_space ? std::to_string(match.new_space) + ":" : "") << address(*match.new_entry);
                if (!match.new_name.empty()) out << " new-name=\"" << match.new_name << '"';
                out << " call-neighbors=" << match.evidence.supporting_call_neighbors
                    << " graph-round=" << match.evidence.call_graph_round;
                if (match.evidence.score_breakdown.available) {
                    const auto &score = match.evidence.score_breakdown;
                    out << " shape=" << score.shape_similarity;
                    if (score.instruction_available) out << " instruction=" << score.instruction_similarity;
                    if (score.histogram_available) out << " histogram=" << score.histogram_similarity;
                    if (score.cfg_available) out << " cfg=" << score.cfg_similarity;
                    if (score.name_floor_applied) out << " name-floor";
                }
                if (match.call_targets.available)
                    out << " call-targets(unchanged=" << match.call_targets.unchanged
                        << ",added=" << match.call_targets.added << ",removed=" << match.call_targets.removed
                        << ",ambiguous=" << match.call_targets.ambiguous << ')';
                else out << " call-targets=unavailable";
                out << '\n';
                if (match.kind != compare::FunctionMatchKind::matched || !match.old_entry || !match.new_entry) continue;
                const auto old_feature = std::find_if(old_features.begin(), old_features.end(), [&](const auto &feature) {
                    return feature.entry == *match.old_entry && feature.address_space == match.old_space;
                });
                const auto new_feature = std::find_if(new_features.begin(), new_features.end(), [&](const auto &feature) {
                    return feature.entry == *match.new_entry && feature.address_space == match.new_space;
                });
                if (old_feature == old_features.end() || new_feature == new_features.end()) continue;
                compare::FunctionBlockMatchOptions block_options;
                auto block_mapping = compare::correspond_function_blocks(old_feature->cfg_blocks,
                                                                          new_feature->cfg_blocks,
                                                                          block_options);
                if (block_mapping) {
                    out << "  blocks matched=" << block_mapping.value().matched << " added="
                        << block_mapping.value().added << " removed=" << block_mapping.value().removed
                        << " ambiguous=" << block_mapping.value().ambiguous;
                    if (block_mapping.value().budget_exhausted) out << " budget=exhausted";
                    if (block_mapping.value().instruction_diff_budget_exhausted)
                        out << " instruction-budget=exhausted";
                    out << '\n';
                    std::uint64_t shown_partial_evidence = 0;
                    for (const auto &block : block_mapping.value().blocks) {
                        const auto &evidence = block.instruction_evidence;
                        if (!evidence.available || evidence.complete || shown_partial_evidence >= 2000) continue;
                        ++shown_partial_evidence;
                        out << "  block-evidence old=";
                        if (block.old_block) out << *block.old_block; else out << "-";
                        out << " new=";
                        if (block.new_block) out << *block.new_block; else out << "-";
                        out << " coverage=" << unsigned(evidence.old_coverage_percent) << '%'
                            << '/' << unsigned(evidence.new_coverage_percent) << "% similarity="
                            << evidence.fingerprint_similarity << "% adjacency=";
                        if (evidence.adjacency_available) out << evidence.adjacency_similarity << '%';
                        else out << "unavailable";
                        out << '\n';
                    }
                    std::uint64_t omitted_block_summaries = 0;
                    for (const auto &block : block_mapping.value().blocks) {
                        if (!block.instruction_diff_available ||
                            (!block.instruction_diff.changed_instructions &&
                             !block.instruction_diff.removed_instructions &&
                             !block.instruction_diff.added_instructions)) continue;
                        if (!remaining_block_instruction_summaries) {
                            ++omitted_block_summaries;
                            continue;
                        }
                        --remaining_block_instruction_summaries;
                        out << "  block-instructions old=";
                        if (block.old_block) out << *block.old_block; else out << "-";
                        out << " new=";
                        if (block.new_block) out << *block.new_block; else out << "-";
                        out << " equal=" << block.instruction_diff.equal_instructions
                            << " changed=" << block.instruction_diff.changed_instructions
                            << " removed=" << block.instruction_diff.removed_instructions
                            << " added=" << block.instruction_diff.added_instructions;
                        const auto &semantic = block.instruction_diff.semantic;
                        if (semantic.available) out << " semantic(opcode=" << semantic.opcode_changes
                            << ",flow=" << semantic.flow_changes << ",operand=" << semantic.operand_changes
                            << ",effect=" << semantic.effect_changes << ",unclassified=" << semantic.unclassified_changes << ')';
                        out << '\n';
                    }
                    if (omitted_block_summaries)
                        out << "  ... " << omitted_block_summaries
                            << " changed block summaries omitted (global display limit)\n";
                }
                if (old_feature->instruction_fingerprints.empty() || new_feature->instruction_fingerprints.empty()) continue;
                auto body = compare::diff_function_instructions_detailed(old_feature->instruction_fingerprints,
                    new_feature->instruction_fingerprints, old_feature->instruction_semantics,
                    new_feature->instruction_semantics);
                if (!body) continue;
                ::hexlab::app::attach_instruction_addresses(body.value(), *old_feature, *new_feature);
                out << "  instructions equal=" << body.value().equal_instructions << " changed="
                    << body.value().changed_instructions << " removed=" << body.value().removed_instructions
                    << " added=" << body.value().added_instructions << " semantic(opcode=" << body.value().semantic.opcode_changes
                    << ",flow=" << body.value().semantic.flow_changes << ",operand=" << body.value().semantic.operand_changes
                    << ",effect=" << body.value().semantic.effect_changes << ",unclassified=" << body.value().semantic.unclassified_changes << ")\n";
                std::uint64_t omitted_instruction_runs = 0;
                for (const auto &run : body.value().runs) {
                    if (run.kind == compare::InstructionDiffKind::equal) continue;
                    if (!remaining_instruction_runs) { ++omitted_instruction_runs; continue; }
                    const char *run_kind = run.kind == compare::InstructionDiffKind::changed ? "changed" :
                        run.kind == compare::InstructionDiffKind::removed ? "removed" : "added";
                    out << "    " << run_kind << " old-index=" << run.old_start << "+" << run.old_count
                        << " new-index=" << run.new_start << "+" << run.new_count;
                    if (run.old_address) out << " old-va=" << run.old_address->address_space << ':'
                                             << address(run.old_address->entry);
                    if (run.new_address) out << " new-va=" << run.new_address->address_space << ':'
                                             << address(run.new_address->entry);
                    out << '\n';
                    --remaining_instruction_runs;
                }
                if (omitted_instruction_runs)
                    out << "    ... " << omitted_instruction_runs << " instruction runs omitted (use --instruction-limit)\n";
            }
            if (function_rows < matches.value().size())
                out << "... " << (matches.value().size() - function_rows) << " function matches omitted (use --function-limit)\n";
            out << "Function matching uses recovered, bounded features; opaque instructions suppress body alignment.\n";
        }
        return 0;
    } catch (const std::invalid_argument &error) {
        err << "Compare: " << error.what() << '\n';
        return 2;
    } catch (const std::exception &error) {
        err << "Compare: " << error.what() << '\n';
        return 1;
    }
}
} // namespace hexlab::cli

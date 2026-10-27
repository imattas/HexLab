#include "commands.hpp"
#include "argument_text.hpp"
#include "../compare_instruction_features.hpp"

#include "hexlab/compare/compare.hpp"
#include "hexlab/analysis/functions.hpp"
#include "hexlab/processors/instruction.hpp"
#include "hexlab/workspace/document.hpp"

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string_view>
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
                for (const auto &fact : block->second->instructions) if (fact) {
                    opcodes.push_back(static_cast<std::uint32_t>(fact->instruction.opcode));
                    const auto fingerprint = instruction_fingerprint(fact->instruction);
                    if (!fingerprint || block_feature.instruction_fingerprints.size() >=
                                            cfg_instruction_fingerprint_budget) {
                        block_fingerprints_complete = false;
                    } else if (block_fingerprints_complete) {
                        block_feature.instruction_fingerprints.push_back(*fingerprint);
                        block_feature.instruction_semantics.push_back(::hexlab::app::compare_semantic_feature(fact->instruction, *fingerprint));
                    }
                }
                if (block_fingerprints_complete) {
                    block_feature.instruction_fingerprints_available = true;
                    cfg_instruction_fingerprint_budget -= block_feature.instruction_fingerprints.size();
                } else {
                    block_feature.instruction_fingerprints.clear();
                    block_feature.instruction_semantics.clear();
                }
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
                        feature.instruction_semantics.push_back(::hexlab::app::compare_semantic_feature(fact->instruction, *fingerprint));
                    } else { fingerprint_complete = false; feature.instruction_fingerprints.clear(); feature.instruction_semantics.clear(); }
                }
            }
        }
        feature_by_id.emplace(function->id.value, features.size());
        features.push_back(std::move(feature));
    }
    for (const auto &call : snapshot.calls) {
        const auto owner = feature_by_id.find(call.owner.value);
        if (owner == feature_by_id.end()) continue;
        auto &feature = features[owner->second];
        ++feature.call_count;
        if (call.target) feature.direct_calls.push_back({call.target->offset, call.target->space.value});
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
    compare::ImageView image;
};

Result<CompareInput> make_compare_input(const Image &image) {
    CompareInput input;
    std::map<std::string, std::size_t> occurrences;
    for (const auto &segment : image.layout().segments) {
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
    }
    input.image.regions.reserve(input.views.size());
    for (std::size_t index = 0; index < input.views.size(); ++index) {
        input.image.regions.push_back({input.keys[index], input.addresses[index], input.views[index].bytes});
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
        auto old_input = make_compare_input(*old_document.value()->image);
        auto new_input = make_compare_input(*new_document.value()->image);
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
            if (match_functions)
                throw std::invalid_argument("--json currently emits byte and region results; omit --functions");
            const auto shown_runs = std::min<std::size_t>(report.value().runs.size(), static_cast<std::size_t>(run_limit));
            out << "{\"schema\":\"hexlab.compare.v1\",\"summary\":{\"compared_bytes\":" << summary.compared_bytes
                << ",\"equal_bytes\":" << summary.equal_bytes << ",\"changed_bytes\":" << summary.changed_bytes
                << ",\"added_bytes\":" << summary.added_bytes << ",\"removed_bytes\":" << summary.removed_bytes
                << ",\"ignored_bytes\":" << summary.ignored_bytes << ",\"matched_regions\":" << summary.matched_regions
                << ",\"added_regions\":" << summary.added_regions << ",\"removed_regions\":" << summary.removed_regions
                << "},\"total_runs\":" << report.value().runs.size() << ",\"runs\":[";
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
            out << "],\"omitted_runs\":" << (report.value().runs.size() - shown_runs) << "}\n";
            return 0;
        }
        out << "Compared bytes: " << summary.compared_bytes << "\nEqual: " << summary.equal_bytes
            << "\nChanged: " << summary.changed_bytes << "\nAdded: " << summary.added_bytes
            << "\nRemoved: " << summary.removed_bytes << "\nMatched regions: " << summary.matched_regions
            << "\nAdded regions: " << summary.added_regions << "\nRemoved regions: " << summary.removed_regions
            << "\nChange runs: " << report.value().runs.size() << '\n';
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
        if (shown < report.value().runs.size())
            out << "... " << (report.value().runs.size() - shown) << " runs omitted (use --limit)\n";
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
                    << " graph-round=" << match.evidence.call_graph_round << '\n';
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
                        << " new-index=" << run.new_start << "+" << run.new_count << '\n';
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

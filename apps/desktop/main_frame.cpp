#include "main_frame.hpp"
#include "jump_resolver.hpp"
#include "marker_navigation.hpp"
#include "session_controller.hpp"
#include "document_tabs.hpp"
#include "project_actions.hpp"
#include "search_view.hpp"
#include "graph_view.hpp"
#include "reference_view.hpp"
#include "close_coordinator.hpp"
#include "project_view.hpp"
#include "data_views.hpp"
#include "string_view.hpp"
#include "type_symbols_view.hpp"
#include "pseudocode_view.hpp"
#include "debugger_view.hpp"
#include "plugins_view.hpp"
#include "source_view.hpp"
#include "open_dialogs.hpp"
#include "elf_view.hpp"
#include "macho_view.hpp"
#include "macho_objc_view.hpp"
#include "pe_view.hpp"
#include "minidump_view.hpp"
#include "compare_view.hpp"
#include "../compare_instruction_features.hpp"
#include "compare_adapter.hpp"
#include "archive_view.hpp"
#include "history_view.hpp"
#include "analysis_issues_view.hpp"
#include "hexlab/symbols/demangle.hpp"
#include "collaboration_dialog.hpp"
#include "edit_dialogs.hpp"
#ifdef HEXLAB_DESKTOP_PYTHON_CONSOLE
#include "python_console.hpp"
#endif
#include "hexlab/compare/compare.hpp"
#include "hexlab/analysis/functions.hpp"
#include "hexlab/analysis/flirt.hpp"
#include "hexlab/core/sha256.hpp"
#include "hexlab/loaders/ar.hpp"
#include "hexlab/image/file_storage.hpp"
#include "hexlab/loaders/recipe.hpp"
#include "hexlab/workspace/project.hpp"
#include "hexlab/workspace/project_graph.hpp"
#include "hexlab/workspace/commands.hpp"
#include <wx/button.h>
#include <wx/app.h>
#include <wx/config.h>
#include "hexlab/core/version.hpp"
#include <limits>
#include <wx/aboutdlg.h>
#include <wx/display.h>
#include <wx/choice.h>
#include <wx/choicdlg.h>
#include <wx/clipbrd.h>
#include <wx/log.h>
#include <wx/dataobj.h>
#include <wx/filedlg.h>
#include <wx/menu.h>
#include <wx/gauge.h>
#include <wx/menu.h>
#include <wx/msgdlg.h>
#include <wx/notebook.h>
#include <wx/simplebook.h>
#include <wx/sizer.h>
#include <wx/stattext.h>
#include <wx/statusbr.h>
#include <wx/textctrl.h>
#include <wx/timer.h>
#include <wx/dialog.h>
#include <wx/listctrl.h>
#include <wx/valnum.h>
#include <wx/window.h>
#include <algorithm>
#include <map>
#include <array>
#include <atomic>
#include <cstddef>
#include <chrono>
#include <charconv>
#include <condition_variable>
#include <cstring>
#include <functional>
#include <fstream>
#include <mutex>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <type_traits>

namespace hexlab::desktop {
namespace {
constexpr int move_pane_id_base = python_console_id + 1;
// Keep persisted restore work bounded while avoiding the old small ceiling
// that silently dropped most tabs in larger analysis sessions.
constexpr long maximum_restored_documents = 256;
constexpr std::size_t maximum_persisted_path_characters = 32768;
constexpr std::size_t maximum_persisted_recipe_bytes = 65536;
constexpr char recipe_hex_digits[] = "0123456789abcdef";
std::string encode_session_integer(std::uint64_t value) {
    char buffer[16];
    const auto converted = std::to_chars(buffer, buffer + sizeof(buffer), value, 16);
    return converted.ec == std::errc{} ? std::string(buffer, converted.ptr) : std::string{};
}
std::optional<std::uint64_t> decode_session_integer(const wxString &value) {
    const auto encoded = value.utf8_str();
    if (!encoded || encoded.length() == 0 || encoded.length() > 16) return std::nullopt;
    std::uint64_t decoded = 0;
    const char *begin = encoded.data();
    const char *end = begin + encoded.length();
    const auto parsed = std::from_chars(begin, end, decoded, 16);
    if (parsed.ec != std::errc{} || parsed.ptr != end) return std::nullopt;
    return decoded;
}
std::string encode_recipe_hex(std::span<const std::byte> bytes) {
    std::string encoded;
    encoded.reserve(bytes.size() * 2);
    for (const auto byte : bytes) {
        const auto value = std::to_integer<unsigned char>(byte);
        encoded.push_back(recipe_hex_digits[value >> 4]);
        encoded.push_back(recipe_hex_digits[value & 0x0f]);
    }
    return encoded;
}
std::optional<std::vector<std::byte>> decode_recipe_hex(std::string_view encoded) {
    if (encoded.empty() || encoded.size() % 2 || encoded.size() > maximum_persisted_recipe_bytes * 2)
        return std::nullopt;
    const auto nibble = [](char value) -> int {
        if (value >= '0' && value <= '9') return value - '0';
        if (value >= 'a' && value <= 'f') return value - 'a' + 10;
        if (value >= 'A' && value <= 'F') return value - 'A' + 10;
        return -1;
    };
    std::vector<std::byte> bytes;
    bytes.reserve(encoded.size() / 2);
    for (std::size_t index = 0; index < encoded.size(); index += 2) {
        const auto high = nibble(encoded[index]), low = nibble(encoded[index + 1]);
        if (high < 0 || low < 0) return std::nullopt;
        bytes.push_back(std::byte((high << 4) | low));
    }
    return bytes;
}
#ifdef HEXLAB_DESKTOP_PYTHON_CONSOLE
constexpr std::array<const char *, 7> movable_pane_names{
    "workspace", "functions", "symbols", "metadata", "debugger", "output", "python-console"};
constexpr std::array<const char *, 7> movable_pane_labels{
    "Disassembly / Graph / Pseudocode", "Functions", "Symbols", "Binary Metadata", "Debugger", "Output", "Python Console"};
#else
constexpr std::array<const char *, 6> movable_pane_names{
    "workspace", "functions", "symbols", "metadata", "debugger", "output"};
constexpr std::array<const char *, 6> movable_pane_labels{
    "Disassembly / Graph / Pseudocode", "Functions", "Symbols", "Binary Metadata", "Debugger", "Output"};
#endif
constexpr int dock_floating_panes_id = move_pane_id_base + static_cast<int>(movable_pane_names.size());
constexpr int focus_pane_id_base = dock_floating_panes_id + 1;

struct ContextRowKey {
    bool file_offset = false;
    std::uint32_t space = 0;
    std::uint64_t offset = 0;
    bool operator==(const ContextRowKey &) const = default;
};
struct ContextRowKeyHash {
    std::size_t operator()(const ContextRowKey &key) const noexcept {
        auto value = std::hash<std::uint64_t>{}(key.offset);
        const auto domain = (static_cast<std::uint64_t>(key.space) << 1) |
                            static_cast<std::uint64_t>(key.file_offset);
        value ^= std::hash<std::uint64_t>{}(domain) + 0x9e3779b97f4a7c15ull + (value << 6) + (value >> 2);
        return value;
    }
};
using ContextRowMap = std::unordered_map<ContextRowKey, std::size_t, ContextRowKeyHash>;
std::shared_ptr<const Image> active_document_image(const DocumentSnapshot& document) {
    if (document.project && document.project->loaded && document.project->loaded->image)
        return document.project->loaded->image;
    return document.image;
}
bool document_token_matches(const DocumentSnapshot& document, std::uint64_t open_generation,
                            const HexLabDocumentToken& token) {
    if (token.document_id != document.id.value || token.open_generation != open_generation ||
        open_generation == 0) return false;
    const auto *state = document.project && document.project->state ? document.project->state.get() : nullptr;
    return token.edit_revision == (state ? state->revisions.edit : 0) &&
        token.byte_revision == (state ? state->revisions.bytes : 0) &&
        token.decision_revision == (state ? state->revisions.decisions : 0);
}
std::optional<wxRect> fit_frame_rect_to_display(const wxRect &candidate) {
    const auto count = wxDisplay::GetCount();
    if (count == 0) return {};
    std::optional<wxRect> best_bounds;
    std::int64_t best_intersection = -1;
    long double best_distance = std::numeric_limits<long double>::max();
    const auto candidate_center_x = static_cast<long double>(candidate.x) + candidate.width / 2.0L;
    const auto candidate_center_y = static_cast<long double>(candidate.y) + candidate.height / 2.0L;
    for (unsigned i = 0; i < count; ++i) {
        const wxDisplay display(i);
        if (!display.IsOk()) continue;
        const auto bounds = display.GetClientArea();
        if (bounds.width <= 0 || bounds.height <= 0) continue;
        const auto overlap = candidate.Intersect(bounds);
        const auto area = static_cast<std::int64_t>(std::max(0, overlap.width)) *
                          static_cast<std::int64_t>(std::max(0, overlap.height));
        const auto display_center_x = static_cast<long double>(bounds.x) + bounds.width / 2.0L;
        const auto display_center_y = static_cast<long double>(bounds.y) + bounds.height / 2.0L;
        const auto dx = candidate_center_x - display_center_x;
        const auto dy = candidate_center_y - display_center_y;
        const auto distance = dx * dx + dy * dy;
        if (area > best_intersection || (area == best_intersection && distance < best_distance)) {
            best_bounds = bounds;
            best_intersection = area;
            best_distance = distance;
        }
    }
    if (!best_bounds) return {};
    const auto bounds = *best_bounds;
    const int width = std::clamp(candidate.width, std::min(640, bounds.width), bounds.width);
    const int height = std::clamp(candidate.height, std::min(400, bounds.height), bounds.height);
    const int x = std::clamp(candidate.x, bounds.x, bounds.GetRight() - width + 1);
    const int y = std::clamp(candidate.y, bounds.y, bounds.GetBottom() - height + 1);
    return wxRect(x, y, width, height);
}
bool focus_first_keyboard_control(wxWindow *root) {
    if (!root || !root->IsShownOnScreen()) return false;
    if (root->CanAcceptFocusFromKeyboard()) {
        root->SetFocus();
        return true;
    }
    auto &children = root->GetChildren();
    for (auto node = children.GetFirst(); node; node = node->GetNext())
        if (focus_first_keyboard_control(node->GetData())) return true;
    return false;
}
const char *architecture_id(Architecture architecture) {
    switch (architecture) {
    case Architecture::x86: return "x86";
    case Architecture::x86_64: return "x86_64";
    case Architecture::arm: return "arm";
    case Architecture::arm64: return "arm64";
    case Architecture::riscv32: return "riscv32";
    case Architecture::riscv64: return "riscv64";
    case Architecture::mips32: return "mips32";
    case Architecture::mips64: return "mips64";
    case Architecture::powerpc: return "powerpc";
    case Architecture::wasm: return "wasm";
    case Architecture::dex: return "dex";
    case Architecture::jvm: return "jvm";
    case Architecture::mos6502: return "mos6502";
    default: return "unknown";
    }
}
const char *execution_mode_id(ExecutionMode mode) {
    switch (mode) {
    case ExecutionMode::x86_16: return "x86_16";
    case ExecutionMode::x86_32: return "x86_32";
    case ExecutionMode::x86_64: return "x86_64";
    case ExecutionMode::a32: return "a32";
    case ExecutionMode::thumb: return "thumb";
    case ExecutionMode::a64: return "a64";
    case ExecutionMode::rv32: return "rv32";
    case ExecutionMode::rv64: return "rv64";
    case ExecutionMode::rv64c: return "rv64c";
    case ExecutionMode::mips32: return "mips32";
    case ExecutionMode::mips64: return "mips64";
    case ExecutionMode::ppc32: return "ppc32";
    case ExecutionMode::ppc64: return "ppc64";
    case ExecutionMode::m6502: return "m6502";
    case ExecutionMode::jvm: return "jvm";
    default: return "unknown";
    }
}
template<std::size_t N> bool copy_ascii_id(char (&destination)[N], const char *source) {
    const auto length = std::strlen(source);
    if (length >= N) return false;
    std::memcpy(destination, source, length + 1);
    return true;
}
bool parse_active_location(const HexLabProjectLocation& source, Location& location) {
    if (source.struct_size < sizeof(source) || source.reserved != 0) return false;
    if (source.kind == HEXLAB_PROJECT_LOCATION_ADDRESS) {
        location = Address{{source.address_space}, source.offset};
        return true;
    }
    if (source.kind == HEXLAB_PROJECT_LOCATION_FILE && source.address_space == 0) {
        location = FileOffset{source.offset};
        return true;
    }
    return false;
}
struct CandidateBrowserItem {
    std::size_t source_index = 0;
    Address entry{};
    wxString name;
    std::size_t blocks = 0;
    bool complete = true;
    bool recovered_function = false;
};
ContextRowKey context_key(Address address) { return {false, address.space.value, address.offset}; }
ContextRowKey context_key(FileOffset offset) { return {true, 0, offset.value}; }
ContextRowKey context_key(Location location) {
    return std::visit([](auto value) { return context_key(value); }, location);
}
void index_context_row(ContextRowMap &rows, ContextRowKey key, std::size_t row) {
    rows.try_emplace(key, row);
}
wxString string_encoding_name(StringEncoding encoding) {
    switch (encoding) {
    case StringEncoding::ascii: return "ASCII";
    case StringEncoding::utf16le: return "UTF-16LE";
    case StringEncoding::utf8: return "UTF-8";
    case StringEncoding::utf16be: return "UTF-16BE";
    case StringEncoding::utf32le: return "UTF-32LE";
    case StringEncoding::utf32be: return "UTF-32BE";
    case StringEncoding::windows1252: return "Windows-1252";
    case StringEncoding::windows1251: return "Windows-1251";
    case StringEncoding::windows1250: return "Windows-1250";
    case StringEncoding::windows1254: return "Windows-1254";
    case StringEncoding::windows1253: return "Windows-1253";
    case StringEncoding::windows1255: return "Windows-1255";
    case StringEncoding::windows1256: return "Windows-1256";
    case StringEncoding::windows1257: return "Windows-1257";
    case StringEncoding::windows1258: return "Windows-1258";
    case StringEncoding::iso8859_2: return "ISO-8859-2";
    case StringEncoding::iso8859_5: return "ISO-8859-5";
    }
    return "Unknown";
}
struct AddressDialog : wxDialog {
    wxChoice *mode;
    wxTextCtrl *value;
    explicit AddressDialog(wxWindow *parent) : wxDialog(parent, wxID_ANY, "Jump to location") {
        auto *box = new wxBoxSizer(wxVERTICAL);
        wxArrayString choices;
        choices.Add("Virtual address (va:domain:offset)");
        choices.Add("File offset");
        choices.Add("Selector:offset (hex)");
        mode = new wxChoice(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, choices);
        mode->SetSelection(0);
        mode->SetName("location-mode");
        value = new wxTextCtrl(this, wxID_ANY, "0x");
        value->SetName("location-value");
        box->Add(mode, 0, wxEXPAND | wxALL, 10);
        box->Add(new wxStaticText(this, wxID_ANY,
            "Enter an address/file offset, a symbol or bookmark, or section:.text+0x20 / name+0x10."),
                 0, wxLEFT | wxRIGHT | wxBOTTOM, 10);
        box->Add(value, 0, wxEXPAND | wxALL, 10);
        box->Add(CreateButtonSizer(wxOK | wxCANCEL), 0, wxALL, 10);
        SetSizerAndFit(box);
    }
};
struct CompareInput {
    std::vector<std::string> keys;
    std::vector<std::uint64_t> addresses;
    std::vector<ByteView> views;
    compare::ImageView view;
};
Result<std::shared_ptr<CompareInput>> compare_input(const Image &image, std::stop_token stop) {
    auto input = std::make_shared<CompareInput>();
    std::map<std::string, std::size_t> occurrences;
    for (const auto &segment : image.layout().segments) {
        if (stop.stop_requested())
            return Error{ErrorCode::canceled, "comparison canceled"};
        const auto count = std::min<std::uint64_t>(segment.file_size, image.storage()->size() -
            std::min(segment.file_begin.value, image.storage()->size()));
        if (!count)
            continue;
        if (count > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
            return Error{ErrorCode::resource_limit, "comparison region exceeds addressable memory"};
        auto data = image.storage()->read_at(segment.file_begin, static_cast<std::size_t>(count));
        if (!data)
            return data.error();
        const auto base = segment.name.empty() ? std::string("segment") : segment.name;
        auto key = base + "#" + std::to_string(occurrences[base]++);
        input->keys.push_back(std::move(key));
        input->addresses.push_back(segment.begin.offset);
        input->views.push_back(std::move(data.value()));
    }
    input->view.regions.reserve(input->views.size());
    for (std::size_t i = 0; i < input->views.size(); ++i)
        input->view.regions.push_back({input->keys[i], input->addresses[i], input->views[i].bytes});
    return input;
}
std::string stable_function_name(const ImageMetadata &metadata, Address entry) {
    for (const auto &symbol : metadata.exports)
        if (symbol.address == entry && symbol.name && !symbol.name->empty()) return *symbol.name;
    if (metadata.elf)
        for (const auto &symbol : metadata.elf->symbols)
            if (symbol.address == entry && !symbol.name.empty()) return symbol.name;
    if (metadata.macho) {
        for (const auto &symbol : metadata.macho->symbols)
            if (symbol.address == entry && !symbol.name.empty()) return symbol.name;
        for (const auto &symbol : metadata.macho->dyld_exports)
            if (symbol.is_definition() && symbol.address == entry && !symbol.name.empty()) return symbol.name;
    }
    if (metadata.pe)
        for (const auto &symbol : metadata.pe->pdb_symbols)
            if (symbol.procedure && symbol.address == entry && !symbol.name.empty()) return symbol.name;
    return {};
}
std::vector<compare::FunctionFeature> compare_function_features(const FunctionSnapshot &snapshot,
                                                                const ImageMetadata &metadata,
                                                                const ProjectSnapshot *project,
                                                                std::stop_token stop = {}) {
    std::unordered_map<std::uint64_t, const BasicBlock *> blocks;
    for (const auto &block : snapshot.blocks) if (block) blocks.emplace(block->id.value, block.get());
    std::vector<compare::FunctionFeature> result;
    result.reserve(snapshot.functions.size());
    std::uint64_t cfg_node_budget = 1'000'000, cfg_edge_budget = 4'000'000;
    std::uint64_t cfg_instruction_fingerprint_budget = 4'000'000;
    for (const auto &function : snapshot.functions) {
        if (stop.stop_requested()) return {};
        if (!function) continue;
        compare::FunctionFeature feature;
        feature.entry = function->entry.offset;
        feature.address_space = function->entry.space.value;
        feature.name = stable_function_name(metadata, function->entry);
        if (project) {
            if (const auto *annotation = annotation_at(*project, Location{function->entry});
                annotation && !annotation->name.empty()) feature.name = annotation->name;
        }
        feature.block_count = function->blocks.size();
        feature.opcode_histogram.resize(static_cast<std::size_t>(Opcode::arm_tbh) + 1);
        bool cfg_allowed = function->blocks.size() <= cfg_node_budget;
        std::uint64_t function_edge_count = 0;
        if (cfg_allowed) {
            for (const auto block_id : function->blocks) {
                const auto found = blocks.find(block_id.value);
                if (found == blocks.end()) continue;
                const auto count = found->second->successors.size();
                if (count > cfg_edge_budget - std::min(cfg_edge_budget, function_edge_count)) {
                    cfg_allowed = false;
                    break;
                }
                function_edge_count += count;
            }
        }
        if (cfg_allowed) {
            cfg_node_budget -= function->blocks.size();
            cfg_edge_budget -= function_edge_count;
        }
        struct CfgNode {
            const BasicBlock *block = nullptr;
            std::vector<std::pair<std::uint32_t, std::size_t>> outgoing, incoming;
            std::uint64_t color = 0;
            std::uint64_t block_fingerprint = 0;
        };
        std::vector<CfgNode> cfg;
        if (cfg_allowed) cfg.reserve(function->blocks.size());
        std::unordered_map<std::uint64_t, std::size_t> cfg_index;
        if (cfg_allowed) for (const auto block_id : function->blocks) {
            const auto found = blocks.find(block_id.value);
            if (found == blocks.end()) continue;
            cfg_index.emplace(block_id.value, cfg.size());
            cfg.push_back({found->second});
        }
        const auto mix_word = [](std::uint64_t hash, std::uint64_t word) {
            for (unsigned i = 0; i < 8; ++i) {
                hash ^= static_cast<std::uint8_t>(word >> (i * 8));
                hash *= UINT64_C(1099511628211);
            }
            return hash;
        };
        constexpr std::uint64_t fnv_offset = UINT64_C(14695981039346656037);
        if (cfg_allowed) for (std::size_t i = 0; i < cfg.size(); ++i) {
            if (stop.stop_requested()) return {};
            for (const auto &edge : cfg[i].block->successors) {
                const auto kind = static_cast<std::uint32_t>(edge.kind);
                if (!edge.block) {
                    cfg[i].outgoing.emplace_back(kind, cfg.size());
                    continue;
                }
                const auto target = cfg_index.find(edge.block->value);
                if (target == cfg_index.end()) {
                    cfg[i].outgoing.emplace_back(kind, cfg.size());
                    continue;
                }
                cfg[i].outgoing.emplace_back(kind, target->second);
                cfg[target->second].incoming.emplace_back(kind, i);
            }
            auto hash = mix_word(fnv_offset, cfg[i].block->instructions.size());
            std::vector<std::uint32_t> opcodes;
            opcodes.reserve(cfg[i].block->instructions.size());
            for (const auto &fact : cfg[i].block->instructions)
                if (fact) opcodes.push_back(static_cast<std::uint32_t>(fact->instruction.opcode));
            std::sort(opcodes.begin(), opcodes.end());
            for (const auto opcode : opcodes) hash = mix_word(hash, opcode);
            std::vector<std::uint32_t> edge_kinds;
            edge_kinds.reserve(cfg[i].block->successors.size());
            for (const auto &edge : cfg[i].block->successors)
                edge_kinds.push_back(static_cast<std::uint32_t>(edge.kind));
            std::sort(edge_kinds.begin(), edge_kinds.end());
            hash = mix_word(hash, edge_kinds.size());
            for (const auto kind : edge_kinds) hash = mix_word(hash, kind);
            cfg[i].color = hash;
            cfg[i].block_fingerprint = hash;
        }
        // Three bounded neighborhood-refinement rounds capture branch topology
        // while remaining independent of block ordering and virtual addresses.
        if (cfg_allowed) for (unsigned round = 0; round < 3; ++round) {
            if (stop.stop_requested()) return {};
            std::vector<std::uint64_t> colors(cfg.size());
            for (std::size_t i = 0; i < cfg.size(); ++i) {
                auto hash = mix_word(mix_word(fnv_offset, round + 1), cfg[i].color);
                const auto add_neighbors = [&](auto neighbors, std::uint64_t direction) {
                    std::vector<std::pair<std::uint32_t, std::uint64_t>> values;
                    values.reserve(neighbors.size());
                    for (const auto &[kind, node] : neighbors)
                        values.emplace_back(kind, node < cfg.size() ? cfg[node].color : 0);
                    std::sort(values.begin(), values.end());
                    hash = mix_word(hash, direction);
                    hash = mix_word(hash, values.size());
                    for (const auto &[kind, color] : values) {
                        hash = mix_word(hash, kind);
                        hash = mix_word(hash, color);
                    }
                };
                add_neighbors(cfg[i].outgoing, 1);
                add_neighbors(cfg[i].incoming, 2);
                colors[i] = hash;
            }
            for (std::size_t i = 0; i < cfg.size(); ++i) cfg[i].color = colors[i];
            for (const auto &node : cfg) feature.cfg_fingerprints.push_back(node.color);
            // Preserve the directed colored edge relation as its own multiset.
            // Node colors summarize neighborhoods, but two different graphs can
            // still have similar node-color distributions. Edge colors retain
            // source/target context without storing address-dependent IDs.
            for (std::size_t source = 0; source < cfg.size(); ++source) {
                for (const auto &[kind, target] : cfg[source].outgoing) {
                    auto edge_color = mix_word(mix_word(mix_word(fnv_offset, round + 1),
                                                        cfg[source].color), kind);
                    edge_color = mix_word(edge_color, target < cfg.size() ? cfg[target].color : 0);
                    feature.cfg_fingerprints.push_back(edge_color);
                }
            }
        }
        if (cfg_allowed) {
            feature.cfg_blocks.reserve(cfg.size());
            for (const auto &node : cfg) {
                compare::CfgBlockFeature block_feature;
                block_feature.fingerprint = node.block_fingerprint;
                bool block_fingerprints_complete = true;
                for (const auto &fact : node.block->instructions) {
                    if (!fact) continue;
                    const auto fingerprint = compare_instruction_fingerprint(fact->instruction);
                    if (!fingerprint || block_feature.instruction_fingerprints.size() >=
                                            cfg_instruction_fingerprint_budget) {
                        block_fingerprints_complete = false;
                        break;
                    }
                    block_feature.instruction_fingerprints.push_back(*fingerprint);
                    block_feature.instruction_semantics.push_back(::hexlab::app::compare_semantic_feature(fact->instruction, *fingerprint));
                }
                if (block_fingerprints_complete) {
                    block_feature.instruction_fingerprints_available = true;
                    cfg_instruction_fingerprint_budget -= block_feature.instruction_fingerprints.size();
                } else {
                    block_feature.instruction_fingerprints.clear();
                    block_feature.instruction_semantics.clear();
                }
                for (const auto &[kind, target] : node.outgoing)
                    if (target < cfg.size()) block_feature.successors.push_back({static_cast<std::uint32_t>(target), kind});
                feature.cfg_blocks.push_back(std::move(block_feature));
            }
        }
        bool has_architecture = false;
        bool fingerprints_complete = true;
        for (const auto block_id : function->blocks) {
            if (stop.stop_requested()) return {};
            const auto found = blocks.find(block_id.value);
            if (found == blocks.end()) continue;
            for (const auto &fact : found->second->instructions) {
                if (stop.stop_requested()) return {};
                if (!fact) continue;
                ++feature.instruction_count;
                if (!has_architecture) {
                    feature.architecture = static_cast<std::uint32_t>(fact->instruction.context.architecture);
                    has_architecture = true;
                }
                const auto opcode = static_cast<std::size_t>(fact->instruction.opcode);
                if (opcode < feature.opcode_histogram.size()) ++feature.opcode_histogram[opcode];
                if (fingerprints_complete) {
                    const auto fingerprint = compare_instruction_fingerprint(fact->instruction);
                    if (fingerprint) {
                        feature.instruction_fingerprints.push_back(*fingerprint);
                        feature.instruction_semantics.push_back(::hexlab::app::compare_semantic_feature(fact->instruction, *fingerprint));
                    }
                    else {
                        fingerprints_complete = false;
                        feature.instruction_fingerprints.clear();
                        feature.instruction_semantics.clear();
                    }
                }
            }
        }
        feature.call_count = static_cast<std::uint64_t>(std::count_if(snapshot.calls.begin(), snapshot.calls.end(),
            [&](const auto &call) { return call.owner == function->id; }));
        if (!fingerprints_complete) { feature.instruction_fingerprints.clear(); feature.instruction_semantics.clear(); }
        result.push_back(std::move(feature));
    }
    populate_direct_call_neighborhoods(snapshot, result);
    return result;
}
std::vector<compare::FunctionBodyDiff> compare_function_bodies(
    std::span<const compare::FunctionMatch> matches,
    std::span<const compare::FunctionFeature> old_features,
    std::span<const compare::FunctionFeature> new_features,
    std::stop_token stop) {
    using FeatureKey = std::pair<std::uint32_t, std::uint64_t>;
    std::map<FeatureKey, const compare::FunctionFeature *> old_by_address, new_by_address;
    for (const auto &feature : old_features) old_by_address.emplace(FeatureKey{feature.address_space, feature.entry}, &feature);
    for (const auto &feature : new_features) new_by_address.emplace(FeatureKey{feature.address_space, feature.entry}, &feature);

    constexpr std::uint64_t aggregate_cell_budget = 16'000'000;
    constexpr std::uint64_t per_function_cell_budget = 4'000'000;
    std::uint64_t remaining_cells = aggregate_cell_budget;
    std::vector<compare::FunctionBodyDiff> result;
    for (const auto &match : matches) {
        if (stop.stop_requested()) return {};
        if (match.kind != compare::FunctionMatchKind::matched || !match.old_entry || !match.new_entry) continue;
        const auto old_found = old_by_address.find({match.old_space, *match.old_entry});
        const auto new_found = new_by_address.find({match.new_space, *match.new_entry});
        if (old_found == old_by_address.end() || new_found == new_by_address.end()) continue;
        const auto &before = old_found->second->instruction_fingerprints;
        const auto &after = new_found->second->instruction_fingerprints;
        compare::FunctionInstructionDiff instruction_diff;
        if (!before.empty() && !after.empty()) {
            const auto old_size = static_cast<std::uint64_t>(before.size());
            const auto new_size = static_cast<std::uint64_t>(after.size());
            if (old_size != UINT64_MAX && new_size != UINT64_MAX) {
                const auto rows = old_size + 1, columns = new_size + 1;
                if (rows <= UINT64_MAX / columns) {
                    const auto cells = rows * columns;
                    if (cells <= per_function_cell_budget && cells <= remaining_cells) {
                        compare::FunctionInstructionDiffOptions options;
                        options.max_dynamic_cells = std::min(per_function_cell_budget, remaining_cells);
                        options.stop_token = stop;
                        auto diff = compare::diff_function_instructions_detailed(before, after,
                            old_found->second->instruction_semantics, new_found->second->instruction_semantics, options);
                        if (!diff && diff.error().code == compare::ErrorCode::canceled) return {};
                        if (diff) { instruction_diff = std::move(diff.value()); remaining_cells -= cells; }
                    }
                }
            }
        }
        compare::FunctionBlockMatchOptions block_options;
        block_options.stop_token = stop;
        auto block_correspondence = compare::correspond_function_blocks(
            old_found->second->cfg_blocks, new_found->second->cfg_blocks, block_options);
        if (!block_correspondence) {
            if (block_correspondence.error().code == compare::ErrorCode::canceled) return {};
            continue;
        }
        if (instruction_diff.runs.empty() && old_found->second->cfg_blocks.empty() &&
            new_found->second->cfg_blocks.empty()) continue;
        result.push_back({*match.old_entry, *match.new_entry, match.old_space, match.new_space,
                          std::move(instruction_diff), std::move(block_correspondence.value())});
    }
    return result;
}
} // namespace
struct MainFrame::Impl {
    MainFrame &frame;
    bool session_restore_activation_pending = false;
    std::vector<DocumentId> session_restore_documents;
    std::optional<DocumentId> session_restore_active;
    std::optional<Location> session_restore_location;
    wxTimer compare_timer;
    struct CompareWork {
        std::mutex mutex;
        std::optional<compare::Report> report;
        std::optional<std::vector<compare::FunctionMatch>> function_matches;
        std::optional<std::vector<compare::FunctionBodyDiff>> function_body_diffs;
        std::string error;
        std::atomic<std::uint64_t> done{0}, total{0};
        std::atomic<bool> matching_functions{false};
        bool complete = false;
        std::jthread thread;
        wxString old_name, new_name;
        std::optional<DocumentId> source_document;
        std::optional<DocumentId> target_document;
        std::shared_ptr<const ProjectSnapshot> source_project;
        std::shared_ptr<const ProjectSnapshot> target_project;
        std::shared_ptr<const FunctionSnapshot> comparison_old_functions;
        std::shared_ptr<const FunctionSnapshot> comparison_new_functions;
    } compare_work;
    struct FlirtWork {
        std::mutex mutex;
        MainFrame *target = nullptr;
        bool running = false;
        std::jthread thread;
    };
    struct ActiveDocumentBridge {
        std::mutex mutex;
        MainFrame *target = nullptr;
        std::shared_ptr<const DocumentSnapshot> current;
        std::optional<DocumentId> active_id;
        std::optional<DocumentId> generation_document_id;
        std::uint64_t next_open_generation = 1;
        std::uint64_t open_generation = 0;
        bool open_generation_exhausted = false;
    };
    std::shared_ptr<ActiveDocumentBridge> active_document_bridge =
        std::make_shared<ActiveDocumentBridge>();
    std::shared_ptr<FlirtWork> flirt_work = std::make_shared<FlirtWork>();
    std::unique_ptr<SessionController> controller;
    std::shared_ptr<plugins::ModuleProvider> plugin_provider;
    std::unique_ptr<ProjectActions> actions;
    std::unique_ptr<CloseCoordinator> closer;
    std::shared_ptr<const DocumentSnapshot> shown;
    wxSimplebook *center;
    DocumentTabs *tabs;
    SearchView *search;
    GraphView *graph;
    PseudocodeView *pseudocode = nullptr;
    SourceView *source = nullptr;
    wxNotebook *pages = nullptr;
    wxNotebook *metadata_pages = nullptr;
    ReferenceView *references;
    TypeSymbolsView *type_symbols = nullptr;
    DebuggerView *debugger = nullptr;
    PluginsView *plugins = nullptr;
    HistoryView *history_view = nullptr;
    AnalysisIssuesView *analysis_issues = nullptr;
#ifdef HEXLAB_DESKTOP_PYTHON_CONSOLE
    PythonConsolePanel *python_console = nullptr;
#endif
    wxMenu *plugin_menu = nullptr;
    struct PluginMenuInvocation { std::string plugin_id, action_id, label; };
    std::map<int, PluginMenuInvocation> plugin_menu_invocations;
    ListingView *listing;
    BytesView *bytes;
    VirtualTable *candidates, *symbols, *segments, *imports, *exports, *annotations, *bookmarks;
    StringBrowserView *strings;
    wxTextCtrl *function_filter = nullptr;
    wxTextCtrl *symbol_filter = nullptr;
    wxStaticText *symbol_filter_status = nullptr;
    std::vector<std::size_t> visible_symbol_rows;
    std::function<wxString(std::size_t, int)> symbol_source_cell;
    std::function<void(std::size_t)> symbol_source_activate;
    std::size_t symbol_source_count = 0;
    std::vector<CandidateBrowserItem> candidate_items, visible_candidate_items;
    int candidate_sort_column = 0;
    bool candidate_sort_ascending = true;
    wxButton *bookmark_rename = nullptr, *bookmark_remove = nullptr;
    VirtualTable *elf_programs, *elf_sections, *elf_dynamic, *elf_tables;
    VirtualTable *macho_metadata;
    VirtualTable *macho_objc = nullptr;
    wxTextCtrl *macho_objc_filter = nullptr;
    wxStaticText *macho_objc_filter_status = nullptr;
    wxTimer macho_objc_filter_timer;
    wxButton *macho_objc_import_types = nullptr, *macho_objc_pseudocode = nullptr;
    std::shared_ptr<const std::vector<MachOObjCViewRow>> macho_objc_rows;
    std::shared_ptr<const std::vector<std::size_t>> macho_objc_visible_rows;
    std::shared_ptr<const MachOObjCScan> macho_objc_scan;
    std::shared_ptr<const DocumentSnapshot> macho_objc_source;
    PeView *pe_view = nullptr;
    MinidumpView *minidump_view = nullptr;
    wxButton *macho_open_slice;
    wxTextCtrl *macho_details;
    std::optional<std::uint32_t> macho_slice_choice;
    wxTextCtrl *output;
    wxGauge *progress;
    AnalysisOptions options;
    std::map<std::uint64_t, wxString> messages;
    std::map<std::uint64_t, std::optional<AnalysisKey>> reported;
    std::optional<DocumentId> output_document;
    std::optional<std::pair<DocumentId, Location>> annotation_context;
    ContextRowMap candidate_rows, symbol_rows, import_rows, export_rows,
        annotation_rows, bookmark_rows;
    std::string reported_error;
    bool compact = false;
    struct NavigationEntry {
        DocumentId document;
        std::uint64_t document_revision = 0;
        std::optional<database::ProjectUuid> project_uuid;
        database::ProjectRevisions project_revisions{};
        Location location;
        int binary_view = -1;
    };
    std::vector<NavigationEntry> navigation_history;
    std::size_t navigation_position = 0;
    bool restoring_navigation = false;
    explicit Impl(MainFrame &owner, std::shared_ptr<plugins::ModuleProvider> provider)
        : frame(owner), compare_timer(&owner), macho_objc_filter_timer(&owner),
          plugin_provider(provider ? std::move(provider) : plugins::make_native_module_provider()) {
        flirt_work->target = &owner;
        owner.Bind(wxEVT_TIMER, [this](wxTimerEvent &) { poll_compare(); }, compare_timer.GetId());
        owner.Bind(wxEVT_TIMER, [this](wxTimerEvent &) {
            if (macho_objc_source && macho_objc_rows)
                display_macho_objc_rows(macho_objc_source, macho_objc_rows);
        }, macho_objc_filter_timer.GetId());
    }
    ~Impl() {
        stop_compare();
        {
            std::lock_guard lock(flirt_work->mutex);
            flirt_work->target = nullptr;
        }
        if (flirt_work->thread.joinable()) {
            flirt_work->thread.request_stop();
            flirt_work->thread.join();
        }
    }
    void refresh_plugin_menu() {
        if (!plugin_menu || !plugins) return;
        while (plugin_menu->GetMenuItemCount() != 0) {
            auto *item = plugin_menu->FindItemByPosition(0);
            if (!item || !plugin_menu->Destroy(item)) break;
        }
        plugin_menu_invocations.clear();
        std::map<std::string, wxMenu *> menus{{"", plugin_menu}};
        for (const auto &action : plugins->menu_actions()) {
            wxMenu *target = plugin_menu;
            std::size_t start = 0;
            std::string full_path;
            while (start < action.menu_path.size()) {
                const auto end = action.menu_path.find('/', start);
                const auto stop = end == std::string::npos ? action.menu_path.size() : end;
                const auto component = action.menu_path.substr(start, stop - start);
                if (!full_path.empty()) full_path.push_back('/');
                full_path += component;
                auto found = menus.find(full_path);
                if (found == menus.end()) {
                    auto *submenu = new wxMenu;
                    target->AppendSubMenu(submenu, text(component));
                    found = menus.emplace(full_path, submenu).first;
                }
                target = found->second;
                if (end == std::string::npos) break;
                start = end + 1;
            }
            const auto id = wxWindow::NewControlId();
            target->Append(id, text(action.label));
            plugin_menu_invocations.emplace(id,
                PluginMenuInvocation{action.plugin_id, action.id, action.label});
        }
    }
    void stop_compare() {
        compare_timer.Stop();
        if (compare_work.thread.joinable()) {
            compare_work.thread.request_stop();
            compare_work.thread.join();
        }
    }
    void apply_flirt_catalog() {
        auto &documents = controller->documents();
        const auto id = documents.active_document();
        if (!id) {
            wxMessageBox("Open a saved, writable project before applying a FLAIR catalog.",
                         "FLAIR signatures", wxOK | wxICON_INFORMATION, &frame);
            return;
        }
        const auto info = documents.documents();
        const auto document = std::find_if(info.begin(), info.end(), [&](const auto &entry) { return entry.id == *id; });
        if (document == info.end() || !document->path || document->readonly) {
            wxMessageBox("Save the project and open it writable before applying a FLAIR catalog.",
                         "FLAIR signatures", wxOK | wxICON_INFORMATION, &frame);
            return;
        }
        const auto snapshot = documents.project(*id);
        const auto actor = documents.actor(*id);
        if (!snapshot || !snapshot->loaded || !snapshot->loaded->image || !snapshot->effective ||
            !snapshot->functions || !actor) {
            wxMessageBox("Current project analysis is not ready for FLAIR recognition.",
                         "FLAIR signatures", wxOK | wxICON_INFORMATION, &frame);
            return;
        }
        wxFileDialog picker(&frame, "Scan FLAIR signature catalog", {}, {},
                            "FLAIR catalogs (*.pat;*.pat.gz;*.sig)|*.pat;*.pat.gz;*.sig|All files (*.*)|*.*",
                            wxFD_OPEN | wxFD_FILE_MUST_EXIST);
        if (picker.ShowModal() != wxID_OK) return;
        const std::filesystem::path catalog_path(picker.GetPath().ToStdWstring());

        {
            std::lock_guard lock(flirt_work->mutex);
            if (flirt_work->running) {
                frame.SetStatusText("A FLAIR recognition job is already running.", 0);
                return;
            }
        }
        if (flirt_work->thread.joinable()) flirt_work->thread.join();
        {
            std::lock_guard lock(flirt_work->mutex);
            flirt_work->running = true;
        }
        frame.SetStatusText("Reading FLAIR catalog and recognizing functions...", 0);
        const auto work = flirt_work;
        const auto project_id = *id;
        const auto u8name = catalog_path.filename().u8string();
        const std::string provenance = "FLAIR " +
            std::string(reinterpret_cast<const char *>(u8name.data()), u8name.size());
        try {
            flirt_work->thread = std::jthread(
                [work, project_id, snapshot, actor, catalog_path, provenance](std::stop_token stop) {
                    std::string message;
                    std::vector<FunctionFlirtMatch> match_rows;
                    try {
                        std::error_code ec;
                        const auto size = std::filesystem::file_size(catalog_path, ec);
                        FlirtCatalogLimits catalog_limits;
                        if (ec || size > catalog_limits.max_bytes)
                            throw std::runtime_error("Cannot read FLAIR catalog or file exceeds 64 MiB.");
                        std::ifstream input(catalog_path, std::ios::binary);
                        if (!input) throw std::runtime_error("Could not open FLAIR catalog.");
                        std::vector<std::byte> bytes(static_cast<std::size_t>(size));
                        if (size && !input.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(size)))
                            throw std::runtime_error("Could not read FLAIR catalog.");
                        const char *catalog_data = bytes.empty() ? "" : reinterpret_cast<const char *>(bytes.data());
                        if (stop.stop_requested()) throw std::runtime_error("FLAIR recognition canceled.");

                        const auto &image = *snapshot->loaded->image;
                        Result<FlirtCatalog> catalog = Error{ErrorCode::unsupported, "Unsupported FLAIR catalog format."};
                        const bool binary_sig = bytes.size() >= 6 && std::memcmp(bytes.data(), "IDASGN", 6) == 0;
                        const bool gzip_text = bytes.size() >= 2 && bytes[0] == std::byte{0x1f} &&
                                               bytes[1] == std::byte{0x8b};
                        if (binary_sig) {
                            catalog = parse_flirt_sig(bytes, provenance, catalog_limits, stop);
                        } else if (gzip_text) {
                            catalog = parse_flirt_pat_gz(bytes, image.layout().architecture, image.layout().mode,
                                                         provenance, catalog_limits, stop);
                        } else {
                            catalog = parse_flirt_pat(std::string_view(catalog_data, bytes.size()),
                                                      image.layout().architecture, image.layout().mode,
                                                      provenance, catalog_limits, stop);
                        }
                        if (!catalog) throw std::runtime_error(catalog.error().message);
                        auto recognition = recognize_flirt_catalog(image, *snapshot->effective, *snapshot->functions,
                                                                    catalog.value(), {}, stop);
                        if (!recognition) throw std::runtime_error(recognition.error().message);

                        const std::string identity = std::to_string(provenance.size()) + ":" + provenance +
                            std::string(catalog_data, bytes.size());
                        Sha256 hash;
                        const auto identity_bytes = std::as_bytes(std::span(identity.data(), identity.size()));
                        auto updated = hash.update(identity_bytes);
                        if (!updated) throw std::runtime_error(updated.error().message);
                        auto evidence = make_function_recognition_evidence(*snapshot->functions, hash.digest(),
                                                                           recognition.value(), stop);
                        if (!evidence) throw std::runtime_error(evidence.error().message);
                        if (stop.stop_requested()) throw std::runtime_error("FLAIR recognition canceled.");
                        auto submitted = actor->persist_function_recognition(std::move(evidence.value()));
                        if (!submitted) throw std::runtime_error(submitted.error().message);
                        auto operation = std::move(submitted.value());
                        if (stop.stop_requested()) actor->cancel_operation(operation.id);
                        auto persisted = operation.result.get();
                        if (!persisted) throw std::runtime_error(persisted.error().message);
                        std::ostringstream report;
                        report << "Catalog: " << provenance << "\nFormat: "
                               << (binary_sig ? "binary IDASGN" : gzip_text ? "gzip FLAIR text" : "FLAIR text")
                               << "\nPatterns: " << catalog.value().patterns.size()
                               << "\nTarget: " << static_cast<unsigned>(catalog.value().target_architecture)
                               << " / mode " << static_cast<unsigned>(catalog.value().target_mode)
                               << "\nRecovered function matches: " << recognition.value().functions.size()
                               << "\nCandidate checks: " << recognition.value().pattern_candidates
                               << "\nComparisons: " << recognition.value().comparisons
                               << "\nStatus: " << (recognition.value().complete ? "complete" : "partial; work budget reached")
                               << "\nMatches: " << recognition.value().functions.size()
                               << "\n\nMatches and candidate names (evidence only; no names changed):\n";
                        const auto display_count = std::min<std::size_t>(2000, recognition.value().functions.size());
                        for (std::size_t i = 0; i < display_count; ++i) {
                            const auto &function = recognition.value().functions[i];
                            report << "space " << function.entry.space.value << ":0x" << std::hex
                                   << function.entry.offset << std::dec
                                   << (function.ambiguous ? " [AMBIGUOUS] " : " ");
                            for (std::size_t n = 0; n < function.candidates.size(); ++n) {
                                if (n) report << " | ";
                                report << function.candidates[n].name << " {" << function.candidates[n].provenance << "}";
                                if (function.candidates[n].kind == FlirtSymbolKind::local_name)
                                    report << " [local]";
                            }
                            report << '\n';
                        }
                        if (recognition.value().functions.size() > display_count)
                            report << "\nDisplay limit reached; " << (recognition.value().functions.size() - display_count)
                                   << " additional matches remain in persisted project evidence.\n";
                        const auto match_count = recognition.value().functions.size();
                        match_rows = std::move(recognition.value().functions);
                        message = "Stored FLAIR evidence for " + std::to_string(match_count) +
                            " functions" + (recognition.value().complete ? "." : " (partial; work budget reached).") +
                            "\n" + report.str();
                    } catch (const std::exception &error) {
                        message = std::string("FLAIR recognition failed: ") + error.what();
                    } catch (...) {
                        message = "FLAIR recognition failed with an unknown error.";
                    }
                    {
                        std::lock_guard lock(work->mutex);
                        work->running = false;
                    }
                    auto matches = std::make_shared<const std::vector<FunctionFlirtMatch>>(std::move(match_rows));
                    const auto image = snapshot->loaded->image;
                    if (wxTheApp) wxTheApp->CallAfter([work, project_id, message = std::move(message), matches, image] {
                        MainFrame *target = nullptr;
                        {
                            std::lock_guard lock(work->mutex);
                            target = work->target;
                        }
                        if (target && target->projects().active_document() == project_id) {
                            target->impl_->log_to(project_id, text(message));
                            wxDialog dialog(target, wxID_ANY, "FLAIR catalog scan results", wxDefaultPosition, wxSize(920, 680),
                                            wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER);
                            auto *layout = new wxBoxSizer(wxVERTICAL);
                            auto summary_text = message;
                            if (const auto end = summary_text.find("\n\nMatches and candidate names"); end != std::string::npos)
                                summary_text.resize(end);
                            auto *summary = new wxTextCtrl(&dialog, wxID_ANY, text(summary_text), wxDefaultPosition,
                                                           wxSize(-1, 150), wxTE_MULTILINE | wxTE_READONLY | wxTE_RICH2);
                            layout->Add(summary, 0, wxEXPAND | wxALL, 8);
                            auto *results = new wxListCtrl(&dialog, wxID_ANY, wxDefaultPosition, wxDefaultSize,
                                                           wxLC_REPORT | wxLC_SINGLE_SEL | wxLC_HRULES | wxLC_VRULES);
                            results->InsertColumn(0, "Function entry", wxLIST_FORMAT_LEFT, 180);
                            results->InsertColumn(1, "Candidate names and provenance", wxLIST_FORMAT_LEFT, 620);
                            results->InsertColumn(2, "Status", wxLIST_FORMAT_LEFT, 90);
                            const auto row_count = std::min<std::size_t>(2000, matches->size());
                            for (std::size_t i = 0; i < row_count; ++i) {
                                const auto &match = (*matches)[i];
                                const auto row = results->InsertItem(static_cast<long>(i),
                                    text(format_location(Location{match.entry}, image.get())));
                                std::string names;
                                for (const auto &candidate : match.candidates) {
                                    if (!names.empty()) names += " | ";
                                    names += candidate.name + " {" + candidate.provenance + "}";
                                    if (candidate.kind == FlirtSymbolKind::local_name) names += " [local]";
                                    if (names.size() >= 2048) {
                                        names.resize(2048);
                                        names += "...";
                                        break;
                                    }
                                }
                                results->SetItem(row, 1, text(names));
                                results->SetItem(row, 2, match.ambiguous ? "Ambiguous" : "Unambiguous");
                            }
                            results->SetMinSize(wxSize(-1, 300));
                            layout->Add(results, 1, wxEXPAND | wxLEFT | wxRIGHT, 8);
                            if (matches->size() > row_count)
                                layout->Add(new wxStaticText(&dialog, wxID_ANY,
                                    text(std::to_string(matches->size() - row_count) +
                                         " additional matches remain in the stored project evidence.")),
                                    0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 8);
                            auto *buttons = new wxBoxSizer(wxHORIZONTAL);
                            auto *go = new wxButton(&dialog, wxID_OK, "Go to Selected Function");
                            auto *close = new wxButton(&dialog, wxID_CANCEL, "Close");
                            buttons->Add(go, 0, wxRIGHT, 8);
                            buttons->Add(close, 0);
                            layout->Add(buttons, 0, wxALIGN_RIGHT | wxALL, 8);
                            dialog.SetSizerAndFit(layout);
                            dialog.SetSize(920, 680);
                            dialog.CentreOnParent();
                            std::optional<Address> selected_entry;
                            auto navigate_selected = [&] {
                                const auto row = results->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
                                if (row < 0 || static_cast<std::size_t>(row) >= row_count) return;
                                selected_entry = (*matches)[static_cast<std::size_t>(row)].entry;
                                dialog.EndModal(wxID_OK);
                            };
                            go->Bind(wxEVT_BUTTON, [&](wxCommandEvent &) { navigate_selected(); });
                            results->Bind(wxEVT_LIST_ITEM_ACTIVATED, [&](wxListEvent &) { navigate_selected(); });
                            results->Bind(wxEVT_LIST_ITEM_SELECTED, [go](wxListEvent &) { go->Enable(true); });
                            go->Enable(false);
                            if (dialog.ShowModal() == wxID_OK && selected_entry)
                                target->Navigate(*selected_entry);
                        }
                    });
                });
        } catch (const std::exception &error) {
            {
                std::lock_guard lock(flirt_work->mutex);
                flirt_work->running = false;
            }
            frame.SetStatusText("Could not start FLAIR recognition: " + text(error.what()), 0);
        }
    }
    void cancel_flirt() {
        std::lock_guard lock(flirt_work->mutex);
        if (flirt_work->running && flirt_work->thread.joinable())
            flirt_work->thread.request_stop();
    }
    bool move_pane_to_next_display(std::size_t pane_index) {
        if (pane_index >= movable_pane_names.size() || wxDisplay::GetCount() < 2)
            return false;
        auto &pane = frame.docking_.GetPane(movable_pane_names[pane_index]);
        if (!pane.IsOk() || !pane.window)
            return false;
        int current_display = wxDisplay::GetFromWindow(pane.window);
        if (current_display == wxNOT_FOUND)
            current_display = wxDisplay::GetFromWindow(&frame);
        if (current_display == wxNOT_FOUND)
            current_display = 0;
        const auto count = static_cast<int>(wxDisplay::GetCount());
        const auto target_index = static_cast<unsigned>((current_display + 1) % count);
        wxDisplay target(target_index);
        if (!target.IsOk())
            return false;
        const auto bounds = target.GetClientArea();
        if (bounds.width <= 0 || bounds.height <= 0)
            return false;

        const int width = std::min(bounds.width, std::max(480, bounds.width * 4 / 5));
        const int height = std::min(bounds.height, std::max(320, bounds.height * 4 / 5));
        const wxPoint position(bounds.x + (bounds.width - width) / 2,
                               bounds.y + (bounds.height - height) / 2);
        pane.FloatingPosition(position).FloatingSize(wxSize(width, height)).Float().Show();
        frame.docking_.Update();
        return true;
    }
    bool focus_pane(std::size_t pane_index) {
        if (pane_index >= movable_pane_names.size()) return false;
        auto &pane = frame.docking_.GetPane(movable_pane_names[pane_index]);
        if (!pane.IsOk() || !pane.window) return false;
        pane.Show();
        frame.docking_.Update();
        return focus_first_keyboard_control(pane.window);
    }
    void dock_floating_panes() {
        bool changed = false;
        for (const auto *name : movable_pane_names) {
            auto &pane = frame.docking_.GetPane(name);
            if (!pane.IsOk() || !pane.IsFloating())
                continue;
            pane.Dock().Show();
            changed = true;
        }
        if (changed)
            frame.docking_.Update();
    }
    void cancel_compare() {
        if (compare_work.thread.joinable()) {
            compare_work.thread.request_stop();
            frame.SetStatusText("Canceling binary comparison...");
        }
    }
    void index_context_tables(const std::shared_ptr<const DocumentSnapshot> &doc) {
        for (auto *rows : {&candidate_rows, &symbol_rows, &import_rows, &export_rows,
                           &annotation_rows, &bookmark_rows})
            rows->clear();
        if (!doc || !doc->image)
            return;
        for (std::size_t row = 0; row < visible_candidate_items.size(); ++row)
            index_context_row(candidate_rows, context_key(visible_candidate_items[row].entry), row);
        const auto &metadata = doc->metadata_view();
        if (metadata.macho) {
            const auto &rows = metadata.macho->symbols;
            for (std::size_t view_row = 0; view_row < visible_symbol_rows.size(); ++view_row) {
                const auto row = visible_symbol_rows[view_row];
                if (row >= rows.size()) continue;
                if (rows[row].address)
                    index_context_row(symbol_rows, context_key(*rows[row].address), view_row);
                else
                    index_context_row(symbol_rows, context_key(FileOffset{rows[row].record_file_offset}), view_row);
            }
        } else if (metadata.elf) {
            const auto &rows = metadata.elf->symbols;
            for (std::size_t view_row = 0; view_row < visible_symbol_rows.size(); ++view_row) {
                const auto row = visible_symbol_rows[view_row];
                if (row >= rows.size()) continue;
                if (rows[row].address)
                    index_context_row(symbol_rows, context_key(*rows[row].address), view_row);
                else if (doc->project) {
                    const auto record = elf_symbol_record_at(*doc->project, row);
                    if (record) index_context_row(symbol_rows, context_key(*record), view_row);
                }
            }
        } else {
            const auto &rows = metadata.exports;
            for (std::size_t view_row = 0; view_row < visible_symbol_rows.size(); ++view_row) {
                const auto row = visible_symbol_rows[view_row];
                if (row >= rows.size()) continue;
                if (rows[row].address)
                    index_context_row(symbol_rows, context_key(*rows[row].address), view_row);
            }
        }
        for (std::size_t row = 0; row < metadata.imports.size(); ++row)
            index_context_row(import_rows, context_key(metadata.imports[row].iat), row);
        for (std::size_t row = 0; row < metadata.exports.size(); ++row)
            if (metadata.exports[row].address)
                index_context_row(export_rows, context_key(*metadata.exports[row].address), row);
        if (doc->project && doc->project->state) {
            const auto &annotation_records = doc->project->state->user->annotations;
            for (std::size_t row = 0; row < annotation_records.size(); ++row)
                index_context_row(annotation_rows, context_key(annotation_records[row].location), row);
            const auto &bookmark_records = doc->project->state->user->bookmarks;
            for (std::size_t row = 0; row < bookmark_records.size(); ++row)
                index_context_row(bookmark_rows, context_key(bookmark_records[row].location), row);
        }
    }
    void render_symbol_filter(const std::shared_ptr<const DocumentSnapshot> &doc) {
        const wxString query = symbol_filter ? symbol_filter->GetValue().Lower().Trim(true).Trim(false) : wxString{};
        visible_symbol_rows.clear();
        if (query.empty()) {
            for (std::size_t row = 0; row < symbol_source_count; ++row) visible_symbol_rows.push_back(row);
        } else {
            for (std::size_t row = 0; row < symbol_source_count; ++row) {
                bool match = false;
                for (int column = 0; column < 3; ++column) {
                    if (symbol_source_cell(row, column).Lower().Find(query) != wxNOT_FOUND) { match = true; break; }
                }
                if (match) visible_symbol_rows.push_back(row);
            }
        }
        symbols->populate(visible_symbol_rows.size(), [this](std::size_t row, int column) {
            return row < visible_symbol_rows.size() ? symbol_source_cell(visible_symbol_rows[row], column) : wxString{};
        });
        symbols->activate = [this](std::size_t row) {
            if (row < visible_symbol_rows.size() && symbol_source_activate) symbol_source_activate(visible_symbol_rows[row]);
        };
        if (symbol_filter_status)
            symbol_filter_status->SetLabel(wxString::Format("%llu of %llu symbols", static_cast<unsigned long long>(visible_symbol_rows.size()), static_cast<unsigned long long>(symbol_source_count)));
        index_context_tables(doc);
        select_context_rows(state().selection());
    }
    void populate_candidate_model(const std::shared_ptr<const DocumentSnapshot> &doc) {
        candidate_items.clear();
        visible_candidate_items.clear();
        if (doc && doc->project && doc->project->functions) {
            const auto &functions = doc->project->functions->functions;
            candidate_items.reserve(functions.size());
            for (std::size_t index = 0; index < functions.size(); ++index) {
                const auto &function = functions[index];
                if (!function) continue;
                candidate_items.push_back({index, function->entry,
                    text(presentation_name(*doc->project, function->entry)), function->blocks.size(),
                    function->complete, true});
            }
        } else if (doc && doc->analysis) {
            const auto &entries = doc->analysis->candidates;
            candidate_items.reserve(entries.size());
            for (std::size_t index = 0; index < entries.size(); ++index)
                candidate_items.push_back({index, entries[index], "Entry / direct target", 0, true, false});
        }
        render_candidate_rows(doc);
    }
    void render_candidate_rows(const std::shared_ptr<const DocumentSnapshot> &doc) {
        wxString query = function_filter ? function_filter->GetValue() : wxString{};
        query.Trim(true).Trim(false);
        query.MakeLower();
        visible_candidate_items.clear();
        visible_candidate_items.reserve(candidate_items.size());
        for (const auto &item : candidate_items) {
            if (!query.empty()) {
                auto name = item.name;
                name.MakeLower();
                auto address = location_text(item.entry, doc && doc->image ? doc->image.get() : nullptr);
                address.MakeLower();
                if (name.Find(query) == wxNOT_FOUND && address.Find(query) == wxNOT_FOUND)
                    continue;
            }
            visible_candidate_items.push_back(item);
        }
        const auto address_less = [](const CandidateBrowserItem &left, const CandidateBrowserItem &right) {
            if (left.entry.space != right.entry.space) return left.entry.space.value < right.entry.space.value;
            return left.entry.offset < right.entry.offset;
        };
        std::stable_sort(visible_candidate_items.begin(), visible_candidate_items.end(), [&](const auto &left,
                                                                                           const auto &right) {
            int comparison = 0;
            switch (candidate_sort_column) {
            case 1: comparison = left.name.CmpNoCase(right.name); break;
            case 2:
                comparison = left.blocks < right.blocks ? -1 : left.blocks > right.blocks ? 1 : 0;
                break;
            case 3:
                comparison = left.complete == right.complete ? 0 : left.complete ? -1 : 1;
                break;
            default:
                if (left.entry == right.entry) comparison = 0;
                else comparison = address_less(left, right) ? -1 : 1;
                break;
            }
            if (!comparison && left.entry != right.entry)
                comparison = address_less(left, right) ? -1 : 1;
            return candidate_sort_ascending ? comparison < 0 : comparison > 0;
        });
        candidates->populate(visible_candidate_items.size(), [this, doc](std::size_t row, int column) {
            if (row >= visible_candidate_items.size()) return wxString{};
            const auto &item = visible_candidate_items[row];
            switch (column) {
            case 0: return location_text(item.entry, doc && doc->image ? doc->image.get() : nullptr);
            case 1: return item.name;
            case 2: return item.recovered_function ? wxString::Format("%zu", item.blocks) : wxString{};
            default: return item.recovered_function ? (item.complete ? wxString("complete") : wxString("partial"))
                                                      : wxString{};
            }
        });
        candidates->fit_columns({0, 1, 2, 3});
        candidate_rows.clear();
        for (std::size_t row = 0; row < visible_candidate_items.size(); ++row)
            index_context_row(candidate_rows, context_key(visible_candidate_items[row].entry), row);
    }
    void select_context_rows(std::optional<Location> selection) {
        for (auto *table : {candidates, symbols, segments, imports, exports, annotations, bookmarks})
            table->clear_selection();
        strings->clear_selection();
        if (!shown || !selection || !shown->image)
            return;

        const auto &doc = *shown;
        std::optional<Address> address;
        std::optional<FileOffset> file_offset;
        if (const auto *value = std::get_if<Address>(&*selection))
            address = *value;
        else {
            file_offset = std::get<FileOffset>(*selection);
            auto mapped = doc.image->to_address(*file_offset);
            if (mapped)
                address = mapped.value();
        }
        const auto select_indexed = [&](VirtualTable *table, const ContextRowMap &rows) {
            if (address) {
                const auto found = rows.find(context_key(*address));
                if (found != rows.end()) {
                    table->select_row(found->second);
                    return;
                }
            }
            if (file_offset) {
                const auto found = rows.find(context_key(*file_offset));
                if (found != rows.end()) table->select_row(found->second);
            }
        };
        select_indexed(candidates, candidate_rows);

        const auto &segments_in_image = doc.image->layout().segments;
        for (std::size_t row = 0; row < segments_in_image.size(); ++row) {
            const auto &segment = segments_in_image[row];
            const bool contains = address
                ? segment.begin.space == address->space && address->offset >= segment.begin.offset &&
                      address->offset - segment.begin.offset < segment.size
                : file_offset && file_offset->value >= segment.file_begin.value &&
                      file_offset->value - segment.file_begin.value < segment.file_size;
            if (contains) {
                segments->select_row(row);
                break;
            }
        }
        strings->select(*selection);
        select_indexed(imports, import_rows);
        select_indexed(exports, export_rows);
        select_indexed(annotations, annotation_rows);
        select_indexed(bookmarks, bookmark_rows);
        select_indexed(symbols, symbol_rows);
    }
    void poll_compare() {
        if (!compare_work.thread.joinable()) return;
        const auto done = compare_work.done.load(), total = compare_work.total.load();
        frame.SetStatusText(compare_work.matching_functions.load() ? wxString("Matching functions...") : total ? wxString::Format("Comparing images: %llu / %llu bytes",
            static_cast<unsigned long long>(done), static_cast<unsigned long long>(total)) : wxString("Preparing binary comparison..."));
        std::optional<compare::Report> report;
        std::vector<compare::FunctionMatch> function_matches;
        std::vector<compare::FunctionBodyDiff> function_body_diffs;
        std::shared_ptr<const FunctionSnapshot> new_functions_for_navigation;
        std::string error;
        bool complete = false;
        {
            std::lock_guard lock(compare_work.mutex);
            complete = compare_work.complete;
            if (complete) {
                report = std::move(compare_work.report);
                if (compare_work.function_matches) function_matches = std::move(*compare_work.function_matches);
                if (compare_work.function_body_diffs) function_body_diffs = std::move(*compare_work.function_body_diffs);
                new_functions_for_navigation = compare_work.comparison_new_functions;
                error = std::move(compare_work.error);
            }
        }
        if (!complete) return;
        compare_timer.Stop();
        compare_work.thread.join();
        if (!report) {
            frame.SetStatusText(error.empty() ? wxString("Binary comparison canceled") : text(error));
            if (!error.empty()) wxMessageBox(text(error), "Binary comparison", wxOK | wxICON_ERROR, &frame);
            return;
        }
        auto source_id = compare_work.source_document;
        auto source_project = compare_work.source_project;
        auto target_id = compare_work.target_document;
        auto target_project = compare_work.target_project;
        auto new_functions = std::move(new_functions_for_navigation);
        auto old_functions = compare_work.comparison_old_functions;
        auto *view = new CompareView(&frame, std::move(*report), compare_work.old_name, compare_work.new_name,
            std::move(function_matches),
            [this, source_id](const compare::ChangeRun &run) {
                if (!source_id) return;
                auto project = controller->documents().project(*source_id);
                if (!project || !project->loaded || !project->loaded->image) return;
                auto &segments = project->loaded->image->layout().segments;
                std::map<std::string, std::size_t> occurrences;
                for (const auto &segment : segments) {
                    const auto count = std::min<std::uint64_t>(segment.file_size,
                        project->loaded->image->storage()->size() -
                        std::min(segment.file_begin.value, project->loaded->image->storage()->size()));
                    if (!count) continue;
                    const auto name = segment.name.empty() ? std::string("segment") : segment.name;
                    const auto key = name + "#" + std::to_string(occurrences[name]++);
                    if (key == run.region_key && run.old_address) {
                        frame.Navigate(Address{segment.begin.space, *run.old_address});
                        break;
                    }
                }
            },
            [this, old_functions](const compare::FunctionMatch &match) {
                if (!old_functions || !match.old_entry) return;
                for (const auto &function : old_functions->functions)
                    if (function && function->entry.offset == *match.old_entry &&
                        function->entry.space.value == match.old_space) {
                        frame.Navigate(function->entry);
                        break;
                    }
            }, std::move(function_body_diffs),
            [this, target_id, target_project](const compare::ChangeRun &run) {
                if (!target_id || !target_project || !target_project->loaded || !target_project->loaded->image || !run.new_address) return;
                const auto activated = controller->documents().activate(*target_id);
                if (!activated || !activated.value()) return;
                auto &segments = target_project->loaded->image->layout().segments;
                std::map<std::string, std::size_t> occurrences;
                for (const auto &segment : segments) {
                    const auto count = std::min<std::uint64_t>(segment.file_size,
                        target_project->loaded->image->storage()->size() - std::min(segment.file_begin.value, target_project->loaded->image->storage()->size()));
                    if (!count) continue;
                    const auto name = segment.name.empty() ? std::string("segment") : segment.name;
                    const auto key = name + "#" + std::to_string(occurrences[name]++);
                    if (key == run.region_key) { frame.Navigate(Address{segment.begin.space, *run.new_address}); break; }
                }
            },
            [this, target_id, new_functions](const compare::FunctionMatch &match) {
                if (!target_id || !new_functions || !match.new_entry) return;
                const auto activated = controller->documents().activate(*target_id);
                if (!activated || !activated.value()) return;
                for (const auto &function : new_functions->functions)
                    if (function && function->entry.offset == *match.new_entry && function->entry.space.value == match.new_space) { frame.Navigate(function->entry); break; }
            });
        view->Show();
        frame.SetStatusText("Binary comparison complete");
    }
    void compare_current_to_file() {
        if (compare_work.thread.joinable()) {
            wxMessageBox("A binary comparison is already running.", "Binary comparison", wxOK | wxICON_INFORMATION, &frame);
            return;
        }
        auto id = controller->documents().active_document();
        auto project = id ? controller->documents().project(*id) : nullptr;
        if (!id || !project || !project->loaded || !project->loaded->image || !project->effective) {
            wxMessageBox("Open a loaded project before comparing it.", "Binary comparison", wxOK | wxICON_INFORMATION, &frame);
            return;
        }
        wxFileDialog picker(&frame, "Compare current project with a binary", {}, {},
                            "All files (*.*)|*.*", wxFD_OPEN | wxFD_FILE_MUST_EXIST);
        if (picker.ShowModal() != wxID_OK) return;
        const auto path = std::filesystem::path(picker.GetPath().ToStdWstring());
        auto current_image = project->loaded->image;
        compare_work.old_name = "Current project";
        compare_work.new_name = picker.GetFilename();
        compare_work.source_document = id;
        compare_work.target_document.reset(); compare_work.target_project.reset();
        compare_work.done = 0; compare_work.total = 0; compare_work.complete = false;
        compare_work.matching_functions = false;
        compare_work.report.reset(); compare_work.function_matches.reset(); compare_work.function_body_diffs.reset();
        compare_work.error.clear();
        compare_work.comparison_old_functions.reset(); compare_work.comparison_new_functions.reset();
        compare_work.source_project = project;
        compare_work.thread = std::jthread([this, current_image, source_project = project, path](std::stop_token stop) {
            std::optional<compare::Report> report;
            std::optional<std::vector<compare::FunctionMatch>> function_matches;
            std::optional<std::vector<compare::FunctionBodyDiff>> function_body_diffs;
            std::shared_ptr<const FunctionSnapshot> comparison_old_functions;
            std::string error;
            try {
                auto old_input = compare_input(*current_image, stop);
                if (!old_input) throw std::runtime_error(old_input.error().message);
                OpenRequest request; request.path = path; request.format = Format::automatic; request.run_analysis = false;
                auto loaded = load_document(request, {{0}, 0}, stop);
                if (!loaded) throw std::runtime_error(loaded.error().message);
                if (!loaded.value()->image) throw std::runtime_error("Selected file did not produce a mapped image");
                auto new_input = compare_input(*loaded.value()->image, stop);
                if (!new_input) throw std::runtime_error(new_input.error().message);
                compare::CompareOptions options; options.stop_token = stop;
                options.progress_interval = 1024 * 1024;
                options.progress = [this](std::uint64_t done, std::uint64_t total) {
                    compare_work.done = done; compare_work.total = total; return true;
                };
                auto compared = compare::compare(old_input.value()->view, new_input.value()->view, options);
                if (!compared) throw std::runtime_error(compared.error().message);
                compare_work.matching_functions = true;
                auto old_functions = source_project->functions;
                if (!old_functions && source_project->loaded) {
                    const AnalysisDecisions decisions = source_project->state && source_project->state->user
                        ? source_project->state->user->decisions : AnalysisDecisions{};
                    auto recovered = recover_functions(*current_image, source_project->loaded->metadata, decisions,
                                                       source_project->analysis_options, stop);
                    if (recovered) old_functions = std::move(recovered.value());
                }
                comparison_old_functions = old_functions;
                if (old_functions && !stop.stop_requested()) {
                    auto new_functions = recover_functions(*loaded.value()->image, loaded.value()->metadata,
                                                           {}, source_project->analysis_options, stop);
                    if (new_functions) {
                        const auto old_features = compare_function_features(*old_functions,
                            source_project->loaded->metadata, source_project.get(), stop);
                        if (stop.stop_requested()) throw std::runtime_error("Binary comparison canceled");
                        const auto new_features = compare_function_features(*new_functions.value(),
                            loaded.value()->metadata, nullptr, stop);
                        if (stop.stop_requested()) throw std::runtime_error("Binary comparison canceled");
                        compare::FunctionMatchOptions match_options;
                        match_options.stop_token = stop;
                        auto matched = compare::match_functions_detailed(old_features, new_features, match_options);
                        if (!matched) {
                            if (matched.error().code == compare::ErrorCode::canceled)
                                throw std::runtime_error("Binary comparison canceled");
                            throw std::runtime_error(matched.error().message);
                        }
                        function_matches = std::move(matched.value());
                        function_body_diffs = compare_function_bodies(*function_matches, old_features,
                                                                       new_features, stop);
                        if (stop.stop_requested()) throw std::runtime_error("Binary comparison canceled");
                    }
                }
                if (stop.stop_requested()) throw std::runtime_error("Binary comparison canceled");
                report = std::move(compared.value());
            } catch (const std::exception &e) { error = e.what(); }
            {
                std::lock_guard lock(compare_work.mutex);
                compare_work.report = std::move(report);
                compare_work.function_matches = std::move(function_matches);
                compare_work.function_body_diffs = std::move(function_body_diffs);
                compare_work.comparison_old_functions = std::move(comparison_old_functions);
                compare_work.error = std::move(error);
                compare_work.complete = true;
            }
        });
        compare_timer.Start(100);
        frame.SetStatusText("Preparing binary comparison...");
    }
    void compare_open_projects() {
        if (compare_work.thread.joinable()) {
            wxMessageBox("A binary comparison is already running.", "Binary comparison", wxOK | wxICON_INFORMATION, &frame);
            return;
        }
        auto &documents = controller->documents();
        const auto old_id = documents.active_document();
        const auto old_project = old_id ? documents.project(*old_id) : nullptr;
        if (!old_id || !old_project || !old_project->loaded || !old_project->loaded->image) {
            wxMessageBox("Open a loaded project before comparing projects.", "Binary comparison", wxOK | wxICON_INFORMATION, &frame);
            return;
        }
        std::vector<DocumentId> project_ids;
        wxArrayString labels;
        for (const auto &entry : documents.documents()) {
            if (entry.id == *old_id) continue;
            auto project = documents.project(entry.id);
            if (!project || !project->loaded || !project->loaded->image) continue;
            project_ids.push_back(entry.id);
            labels.Add(entry.path ? wxString(entry.path->filename().wstring()) : wxString::Format("Project %llu", static_cast<unsigned long long>(entry.id.value)));
        }
        if (project_ids.empty()) {
            wxMessageBox("Open another loaded project to compare against the active project.", "Binary comparison", wxOK | wxICON_INFORMATION, &frame);
            return;
        }
        wxSingleChoiceDialog chooser(&frame, "Select the new side of the comparison.", "Compare Open Projects", labels);
        if (chooser.ShowModal() != wxID_OK) return;
        const auto selected = static_cast<std::size_t>(chooser.GetSelection());
        if (selected >= project_ids.size()) return;
        const auto new_id = project_ids[selected];
        const auto new_project = documents.project(new_id);
        if (!new_project || !new_project->loaded || !new_project->loaded->image) return;
        const auto entries = documents.documents();
        auto label_for = [&](DocumentId id) {
            for (const auto &entry : entries) if (entry.id == id)
                return entry.path ? wxString(entry.path->filename().wstring()) : wxString::Format("Project %llu", static_cast<unsigned long long>(id.value));
            return wxString("Project");
        };
        compare_work.old_name = label_for(*old_id);
        compare_work.new_name = label_for(new_id);
        compare_work.source_document = old_id;
        compare_work.target_document = new_id; compare_work.target_project = new_project;
        compare_work.done = 0; compare_work.total = 0; compare_work.complete = false;
        compare_work.matching_functions = false;
        compare_work.report.reset(); compare_work.function_matches.reset(); compare_work.function_body_diffs.reset();
        compare_work.error.clear(); compare_work.comparison_old_functions.reset(); compare_work.comparison_new_functions.reset();
        compare_work.source_project = old_project;
        const auto old_image = old_project->loaded->image, new_image = new_project->loaded->image;
        compare_work.thread = std::jthread([this, old_project, new_project, old_image, new_image](std::stop_token stop) {
            std::optional<compare::Report> report;
            std::optional<std::vector<compare::FunctionMatch>> function_matches;
            std::optional<std::vector<compare::FunctionBodyDiff>> function_body_diffs;
            std::shared_ptr<const FunctionSnapshot> old_functions;
            std::shared_ptr<const FunctionSnapshot> new_functions;
            std::string error;
            try {
                auto old_input = compare_input(*old_image, stop);
                if (!old_input) throw std::runtime_error(old_input.error().message);
                auto new_input = compare_input(*new_image, stop);
                if (!new_input) throw std::runtime_error(new_input.error().message);
                compare::CompareOptions options; options.stop_token = stop; options.progress_interval = 1024 * 1024;
                options.progress = [this](std::uint64_t done, std::uint64_t total) { compare_work.done = done; compare_work.total = total; return true; };
                auto compared = compare::compare(old_input.value()->view, new_input.value()->view, options);
                if (!compared) throw std::runtime_error(compared.error().message);
                compare_work.matching_functions = true;
                old_functions = old_project->functions;
                if (!old_functions) {
                    const auto decisions = old_project->state && old_project->state->user ? old_project->state->user->decisions : AnalysisDecisions{};
                    auto recovered = recover_functions(*old_image, old_project->loaded->metadata, decisions, old_project->analysis_options, stop);
                    if (recovered) old_functions = std::move(recovered.value());
                }
                new_functions = new_project->functions;
                if (!new_functions) {
                    const auto decisions = new_project->state && new_project->state->user ? new_project->state->user->decisions : AnalysisDecisions{};
                    auto recovered = recover_functions(*new_image, new_project->loaded->metadata, decisions, new_project->analysis_options, stop);
                    if (recovered) new_functions = std::move(recovered.value());
                }
                if (old_functions && new_functions && !stop.stop_requested()) {
                    const auto old_features = compare_function_features(*old_functions, old_project->loaded->metadata, old_project.get(), stop);
                    const auto new_features = compare_function_features(*new_functions, new_project->loaded->metadata, new_project.get(), stop);
                    compare::FunctionMatchOptions match_options; match_options.stop_token = stop;
                    auto matched = compare::match_functions_detailed(old_features, new_features, match_options);
                    if (!matched) throw std::runtime_error(matched.error().message);
                    function_matches = std::move(matched.value());
                    function_body_diffs = compare_function_bodies(*function_matches, old_features, new_features, stop);
                }
                if (stop.stop_requested()) throw std::runtime_error("Binary comparison canceled");
                report = std::move(compared.value());
            } catch (const std::exception &e) { error = e.what(); }
            {
                std::lock_guard lock(compare_work.mutex);
                compare_work.report = std::move(report); compare_work.function_matches = std::move(function_matches);
                compare_work.function_body_diffs = std::move(function_body_diffs);
                compare_work.comparison_old_functions = std::move(old_functions);
                compare_work.comparison_new_functions = std::move(new_functions);
                compare_work.error = std::move(error); compare_work.complete = true;
            }
        });
        compare_timer.Start(100);
        frame.SetStatusText("Preparing project comparison...");
    }
    Workspace &state() { return controller->state(); }
    std::optional<Location> action_location() {
        auto id = controller->documents().active_document();
        if (annotation_context && id == annotation_context->first) {
            auto project = controller->documents().project(*id);
            if (project) {
                if (annotation_at(*project, annotation_context->second))
                    return annotation_context->second;
                for (auto &bookmark : project->state->user->bookmarks)
                    if (bookmark.location == annotation_context->second)
                        return annotation_context->second;
            }
        }
        annotation_context.reset();
        return state().selection();
    }
    void log_to(DocumentId id, const wxString &message) {
        auto &saved = messages[id.value];
        saved = (saved + message + "\n").Right(131072);
        if (controller->documents().active_document() == id) {
            output->AppendText(message + "\n");
            auto excess = output->GetLastPosition() - 131072;
            if (excess > 0)
                output->Remove(0, excess);
            frame.SetStatusText(message);
        }
    }
    void log(const wxString &message) {
        if (auto id = controller->documents().active_document())
            log_to(*id, message);
        else {
            output->AppendText(message + "\n");
            frame.SetStatusText(message);
        }
    }
    void changed() {
        if (debugger) debugger->document_changed();
        if (closer)
            closer->progress();
        auto &manager = controller->documents();
        tabs->update(manager);
        if (session_restore_activation_pending) {
            const auto entries = manager.documents();
            const bool still_opening = std::any_of(entries.begin(), entries.end(), [this](const DocumentInfo &entry) {
                return std::find(session_restore_documents.begin(), session_restore_documents.end(), entry.id) !=
                           session_restore_documents.end() && entry.save_state == DocumentSaveState::opening;
            });
            if (!still_opening) {
                session_restore_activation_pending = false;
                const bool active_survived = session_restore_active &&
                    std::any_of(entries.begin(), entries.end(), [this](const DocumentInfo &entry) {
                        return session_restore_active && entry.id == *session_restore_active;
                    });
                if (active_survived) {
                    mark_active_document(*session_restore_active);
                    controller->activate(*session_restore_active);
                    if (session_restore_location) {
                        auto moved = controller->documents().navigate(*session_restore_active,
                                                                       *session_restore_location);
                        if (moved) sync();
                        else frame.SetStatusText("The saved cursor location is no longer mapped.");
                    }
                    return;
                }
            }
        }
        tabs->Show(!manager.documents().empty());
        auto active = manager.active_document();
        auto active_snapshot = manager.active_workspace().current();
        auto open_documents = manager.documents();
        references->retain_documents(open_documents);
        if (analysis_issues) analysis_issues->retain_documents(open_documents);
        pseudocode->retain_documents(open_documents);
        if (controller->all_search_scope()) {
            std::vector<SearchDocumentView> search_documents;
            for (const auto &document : open_documents) {
                auto project = manager.project(document.id);
                if (!project)
                    continue;
                auto history = manager.search_history(document.id);
                wxString label = document.path ? wxString(document.path->filename().wstring()) : wxString("Untitled");
                label += wxString::Format(" [%llu]", static_cast<unsigned long long>(document.id.value));
                search_documents.push_back({document.id, std::move(label), history,
                                            controller->search_pending(document.id),
                                            controller->search_reason(document.id),
                                            project && project->loaded ? std::shared_ptr<const Image>(project->loaded->image)
                                                                       : nullptr, project});
            }
            search->update_all(search_documents);
        } else {
            search->update(active, active ? manager.search_history(*active) : nullptr,
                           active && controller->search_pending(*active),
                           active ? controller->search_reason(*active) : wxString{},
                           active_snapshot ? active_snapshot->image : nullptr,
                           active_snapshot ? active_snapshot->project : nullptr);
        }
        if (manager.active_document() != output_document) {
            annotation_context.reset();
            output_document = manager.active_document();
            output->SetValue(output_document ? messages[output_document->value] : wxString{});
            reported_error.clear();
        }
        for (auto it = messages.begin(); it != messages.end();)
            if (!manager.actor({it->first}))
                it = messages.erase(it);
            else
                ++it;
        for (auto it = reported.begin(); it != reported.end();)
            if (!manager.actor({it->first}))
                it = reported.erase(it);
            else
                ++it;
        if (state().opening()) {
            progress->Show();
            progress->Pulse();
        } else
            progress->Hide();
        if (auto error = state().last_error()) {
            if (reported_error != error->message) {
                reported_error = error->message;
                log(text(error->message));
            }
        } else
            reported_error.clear();
        auto document = state().current();
        const auto active_id = controller->documents().active_document();
        {
            std::lock_guard lock(active_document_bridge->mutex);
            if (!document) {
                active_document_bridge->generation_document_id.reset();
                active_document_bridge->open_generation = 0;
            } else if (active_document_bridge->generation_document_id != document->id) {
                active_document_bridge->generation_document_id = document->id;
                if (active_document_bridge->open_generation_exhausted) {
                    active_document_bridge->open_generation = 0;
                } else {
                    active_document_bridge->open_generation = active_document_bridge->next_open_generation;
                }
                if (active_document_bridge->next_open_generation != std::numeric_limits<std::uint64_t>::max()) {
                    ++active_document_bridge->next_open_generation;
                } else {
                    active_document_bridge->open_generation_exhausted = true;
                }
            }
            active_document_bridge->current = document;
            active_document_bridge->active_id = active_id;
        }
        if (document != shown) {
            shown = document;
            listing->set_document(document);
            bytes->set_document(document);
            source->set_document(document);
            populate();
            if (document) {
                auto report = [this](const std::vector<Diagnostic> &diagnostics) {
                    const auto count = std::min<std::size_t>(diagnostics.size(), 200);
                    for (std::size_t i = 0; i < count; ++i) {
                        const auto &diagnostic = diagnostics[i];
                        log((diagnostic.location ? location_text(*diagnostic.location) + ": " : wxString{}) +
                            text(diagnostic.message));
                    }
                    if (count < diagnostics.size())
                        log("Additional diagnostics omitted from Output.");
                };
                if (document->project) {
                    auto &project = *document->project;
                    auto &last = reported[document->id.value];
                    if (project.derived_key && project.derived_key != last) {
                        last = project.derived_key;
                        log("--- Project analysis updated ---");
                        if (project.loaded)
                            report(project.loaded->diagnostics);
                        if (!project.functions && !project.reason.empty())
                            log(text(project.reason));
                        if (project.functions) {
                            std::size_t count = 0;
                            for (auto &function : project.functions->functions)
                                for (auto &stop : function->stops)
                                    if (stop.reason != FunctionStopReason::ret &&
                                        stop.reason != FunctionStopReason::trap && count++ < 200)
                                        log(location_text(stop.address) + ": " + text(stop.detail));
                        }
                        report(document->strings().diagnostics);
                    }
                    if (project.status == DerivedStatus::file_only)
                        log(text(project.reason));
                } else {
                    report(document->diagnostics);
                    if (document->analysis)
                        report(document->analysis->diagnostics);
                    report(document->strings().diagnostics);
                }
            }
        }
        center->SetSelection(document ? 1 : 0);
        if (document) {
            sync();
            const bool partial = document->project ? document->project->status != DerivedStatus::fresh
                                                   : !document->metadata_complete || !document->strings().complete ||
                                                         (document->analysis_requested &&
                                                          (!document->analysis || !document->analysis->complete));
            wxString status = state().opening() ? "Analyzing project..."
                              : partial         ? "Loaded; analysis incomplete (see Output)"
                                                : "Loaded";
            if (!state().selection())
                frame.SetStatusText(status);
        } else {
            graph->update(nullptr, {}, GraphKind::function_cfg, 1, nullptr, false, {});
            references->update({}, nullptr, {});
            pseudocode->update_document({}, nullptr, 0, {});
            history_view->update({}, {}, {});
            frame.SetStatusText(state().opening() ? "Opening project..." : "Ready");
        }
        frame.Layout();
        if (auto error = state().last_error())
            frame.SetStatusText(text(error->message));
    }
    void mark_active_document(DocumentId id) {
        std::lock_guard lock(active_document_bridge->mutex);
        active_document_bridge->active_id = id;
    }
    std::optional<NavigationEntry> current_navigation(Location location) const {
        const auto id = controller->documents().active_document();
        const auto document = controller->documents().active_workspace().current();
        if (!id || !document || document->id != *id)
            return {};
        NavigationEntry entry{*id, document->revision, {}, {}, std::move(location),
                              pages ? pages->GetSelection() : wxNOT_FOUND};
        if (document->project && document->project->state) {
            entry.project_uuid = document->project->state->uuid;
            entry.project_revisions = document->project->state->revisions;
        }
        return entry;
    }
    static bool same_navigation_entry(const NavigationEntry &left, const NavigationEntry &right) {
        return left.document == right.document && left.document_revision == right.document_revision &&
               left.project_uuid == right.project_uuid && left.project_revisions == right.project_revisions &&
               left.location == right.location && left.binary_view == right.binary_view;
    }
    void record_navigation_entry(NavigationEntry entry) {
        if (restoring_navigation) return;
        if (!navigation_history.empty() && navigation_position < navigation_history.size() &&
            same_navigation_entry(navigation_history[navigation_position], entry)) return;
        if (!navigation_history.empty() && navigation_position + 1 < navigation_history.size())
            navigation_history.erase(navigation_history.begin() + static_cast<std::ptrdiff_t>(navigation_position + 1),
                                     navigation_history.end());
        navigation_history.push_back(std::move(entry));
        navigation_position = navigation_history.size() - 1;
        constexpr std::size_t history_limit = 512;
        if (navigation_history.size() > history_limit) {
            navigation_history.erase(navigation_history.begin());
            --navigation_position;
        }
    }
    void record_navigation(Location location) {
        if (restoring_navigation) return;
        if (auto entry = current_navigation(std::move(location)))
            record_navigation_entry(std::move(*entry));
    }
    bool restore_navigation(std::size_t position) {
        if (position >= navigation_history.size()) return false;
        const auto entry = navigation_history[position];
        const auto open = controller->documents().documents();
        if (std::none_of(open.begin(), open.end(), [&](const auto &item) { return item.id == entry.document; }))
            return false;
        restoring_navigation = true;
        controller->activate(entry.document);
        const auto document = controller->documents().active_workspace().current();
        bool valid = document && document->id == entry.document && document->revision == entry.document_revision;
        auto project = controller->documents().project(entry.document);
        if (valid && entry.project_uuid) {
            valid = project && project->state && project->state->uuid == entry.project_uuid &&
                    project->state->revisions == entry.project_revisions;
        }
        if (valid) {
            auto moved = controller->documents().navigate(entry.document, entry.location);
            valid = static_cast<bool>(moved);
        }
        restoring_navigation = false;
        if (!valid) return false;
        navigation_position = position;
        if (entry.binary_view >= 0 && pages && entry.binary_view < static_cast<int>(pages->GetPageCount())) {
            center->SetSelection(1);
            pages->SetSelection(entry.binary_view);
        }
        changed();
        return true;
    }
    bool navigate_history(bool forward) {
        if (navigation_history.empty()) return false;
        auto position = navigation_position;
        while (forward ? position + 1 < navigation_history.size() : position > 0) {
            position = forward ? position + 1 : position - 1;
            if (restore_navigation(position)) return true;
        }
        return false;
    }
    void browse_navigation_history() {
        if (navigation_history.empty()) {
            frame.SetStatusText("Navigation history is empty.");
            return;
        }
        const auto documents = controller->documents().documents();
        wxArrayString choices;
        for (std::size_t i = 0; i < navigation_history.size(); ++i) {
            const auto &entry = navigation_history[i];
            wxString document_label = wxString::Format("Document %llu",
                static_cast<unsigned long long>(entry.document.value));
            for (const auto &document : documents) {
                if (document.id != entry.document) continue;
                if (document.path) document_label = wxString(document.path->filename().wstring());
                else if (auto project = controller->documents().project(document.id);
                         project && project->state && project->state->provenance)
                    document_label = wxString(project->state->provenance->native_path.filename().wstring());
                break;
            }
            auto label = i == navigation_position ? wxString("* ") : wxString("  ");
            label += document_label + "  " + location_text(entry.location);
            if (entry.binary_view >= 0 && pages && entry.binary_view < static_cast<int>(pages->GetPageCount())) {
                label += "  [";
                label += pages->GetPageText(static_cast<std::size_t>(entry.binary_view));
                label += "]";
            }
            choices.Add(label);
        }
        wxSingleChoiceDialog dialog(&frame,
            "Choose a retained address to restore. Entries from closed or changed documents are skipped.",
            "Navigation History", choices);
        if (navigation_position < navigation_history.size())
            dialog.SetSelection(static_cast<int>(navigation_position));
        if (dialog.ShowModal() != wxID_OK) return;
        const auto selected = static_cast<std::size_t>(dialog.GetSelection());
        if (!restore_navigation(selected))
            frame.SetStatusText("That history location is stale or no longer mapped.");
    }
    void sync() {
        if (debugger) debugger->document_changed();
        if (auto selection = state().selection()) {
            listing->select(*selection);
            bytes->select(*selection);
            source->select(*selection);
            auto status = location_text(*selection, shown && shown->image ? shown->image.get() : nullptr);
            if (shown && shown->image) {
                std::optional<Address> address;
                if (const auto *value = std::get_if<Address>(&*selection))
                    address = *value;
                else {
                    auto mapped = shown->image->to_address(std::get<FileOffset>(*selection));
                    if (mapped)
                        address = mapped.value();
                }
                if (address) {
                    auto context = shown->image->context_at(*address);
                    if (context) {
                        auto capability = processor_capabilities(context.value());
                        if (!capability.display_name.empty())
                            status += "; " + text(capability.display_name);
                    }
                }
            }
            if (shown && shown->project && shown->project->status != DerivedStatus::fresh)
                status += "; " + analysis_state_text(*shown->project);
            frame.SetStatusText(status);
        }
        select_context_rows(state().selection());
        auto id = controller->documents().active_document();
        if (history_view) {
            auto project = id ? controller->documents().project(*id) : nullptr;
            auto actor = id ? controller->documents().actor(*id) : nullptr;
            history_view->update(id, std::move(actor), std::move(project));
        }
        if (type_symbols) {
            type_symbols->navigate = [this](DocumentId source_id, std::shared_ptr<const ProjectSnapshot> source,
                                            Location location) {
                const auto source_document = shown;
                if (!source_document || source_document->id != source_id || source_document->project != source) {
                    log("Symbol navigation canceled because its source snapshot changed.");
                    return;
                }
                navigate_from_document(source_document, location);
            };
            type_symbols->diagnostics_changed = [this, id](std::vector<AnalysisIssueDiagnostic> diagnostics) {
                if (!id || !analysis_issues) return;
                analysis_issues->set_type_diagnostics(id, diagnostics);
                const auto project = controller->documents().project(*id);
                const auto actor = controller->documents().actor(*id);
                if (!project || project->mode == database::ProjectMode::read_only || !actor) return;
                std::vector<database::TypeImportDiagnostic> persisted;
                persisted.reserve(diagnostics.size());
                for (const auto &item : diagnostics)
                    persisted.push_back({item.source, item.severity, item.message, item.address, item.function_entry});
                auto submitted = actor->replace_type_import_diagnostics(std::move(persisted));
                if (!submitted) {
                    controller->documents().report_error(*id, submitted.error());
                }
            };
            auto project = id ? controller->documents().project(*id) : nullptr;
            type_symbols->update(id, project, state().selection(), [this, id](ProjectCommand command) {
                if (!id) return;
                auto result = controller->execute(*id, std::move(command));
                if (!result) controller->documents().report_error(*id, result.error());
            });
        }
        references->update(id, shown ? shown->project : nullptr, state().selection());
        if (analysis_issues)
            analysis_issues->update(id, shown ? shown->project : nullptr, state().selection(), shown);
        pseudocode->diagnostics_changed = [this, id](std::vector<AnalysisIssueDiagnostic> diagnostics) {
            if (analysis_issues) analysis_issues->set_decompiler_diagnostics(id, std::move(diagnostics));
        };
        pseudocode->update_document(id, shown ? shown->project : nullptr, shown ? shown->revision : 0,
                           state().selection(),
                           [this, id](ProjectCommand command) {
                               if (!id) return;
                               auto result = controller->execute(*id, std::move(command));
                               if (!result) controller->documents().report_error(*id, result.error());
                           });
        if (id && shown && shown->project) {
            auto kind = controller->graph_kind(*id);
            auto call_depth = controller->graph_call_depth(*id);
            auto queued = controller->request_graph(*id, state().selection(), kind, call_depth);
            (void)queued;
            graph->update(shown->project.get(), state().selection(), kind, call_depth, controller->graph_result(*id),
                          controller->graph_pending(*id), controller->graph_reason(*id));
        } else
            graph->update(nullptr, {}, GraphKind::function_cfg, 1, nullptr, false, {});
    }
    void show_macho_objc_placeholder() {
        if (!macho_objc) return;
        macho_objc_rows.reset();
        macho_objc_visible_rows.reset();
        const bool has_document = static_cast<bool>(shown);
        auto placeholder = std::make_shared<const std::vector<MachOObjCViewRow>>(
            std::vector<MachOObjCViewRow>{{"Scan", "", "Objective-C runtime metadata",
                has_document ? "not scanned" : "unavailable", "on page selection",
                has_document ? "Select this page to scan the displayed immutable Mach-O snapshot."
                             : "No document is currently displayed.", {}}});
        macho_objc->populate(placeholder->size(), [placeholder](std::size_t row, int column) {
            return row < placeholder->size() ? macho_objc_view_cell((*placeholder)[row], column, nullptr) : wxString{};
        });
        if (macho_objc_filter_status) macho_objc_filter_status->SetLabel("No runtime records loaded");
        if (macho_objc_pseudocode) macho_objc_pseudocode->Enable(false);
        macho_objc->activate = {};
    }
    bool navigate_from_document(const std::shared_ptr<const DocumentSnapshot> &source, Location destination) {
        const auto current = controller->state().current();
        const auto current_project = source ? controller->documents().project(source->id) : nullptr;
        if (!source || closer->closing_window() ||
            controller->documents().active_document() != source->id ||
            !current || current->id != source->id || current->revision != source->revision ||
            shown != source || current_project != source->project) {
            log("Navigation canceled because its source document changed.");
            return false;
        }
        frame.Navigate(destination);
        if (state().selection() != std::optional<Location>{destination})
            return false;
        pages->SetSelection(std::holds_alternative<Address>(destination) ? 0 : 1);
        return true;
    }
    void display_macho_objc_rows(const std::shared_ptr<const DocumentSnapshot> &doc,
                                 const std::shared_ptr<const std::vector<MachOObjCViewRow>> &rows) {
        if (!macho_objc || !doc || !rows) return;
        wxString query = macho_objc_filter ? macho_objc_filter->GetValue() : wxString{};
        query.Trim(true).Trim(false);
        query.MakeLower();
        auto visible = std::make_shared<std::vector<std::size_t>>();
        visible->reserve(rows->size());
        for (std::size_t index = 0; index < rows->size(); ++index) {
            const auto &row = (*rows)[index];
            if (query.empty()) {
                visible->push_back(index);
                continue;
            }
            const std::string_view fields[] = {row.kind, row.owner, row.name, row.status, row.provenance, row.details};
            bool matches = false;
            for (const auto field : fields) {
                auto text = wxString::FromUTF8(field.data(), field.size());
                text.MakeLower();
                if (text.Find(query) != wxNOT_FOUND) { matches = true; break; }
            }
            if (!matches) {
                auto address = macho_objc_view_cell(row, 3, doc->image.get());
                address.MakeLower();
                matches = address.Find(query) != wxNOT_FOUND;
            }
            if (matches) visible->push_back(index);
        }
        macho_objc->populate(visible->size(), [doc, rows, visible](std::size_t row, int column) {
            if (row >= visible->size()) return wxString{};
            return macho_objc_view_cell((*rows)[(*visible)[row]], column, doc->image.get());
        });
        macho_objc_visible_rows = visible;
        if (macho_objc_filter_status)
            macho_objc_filter_status->SetLabel(wxString::Format("%zu of %zu rows", visible->size(), rows->size()));
        macho_objc->activate = [this, doc, rows, visible](std::size_t row) {
            if (row < visible->size() && (*rows)[(*visible)[row]].address)
                navigate_from_document(doc, *(*rows)[(*visible)[row]].address);
        };
        if (macho_objc_pseudocode) {
            const auto selected = macho_objc ? macho_objc->selected_row() : std::optional<std::size_t>{};
            const bool enabled = selected && *selected < visible->size() &&
                                 (*rows)[(*visible)[*selected]].code_address.has_value();
            macho_objc_pseudocode->Enable(enabled);
        }
    }
    std::optional<Address> selected_macho_objc_implementation() const {
        if (!macho_objc || !macho_objc_rows || !macho_objc_visible_rows) return {};
        const auto selected = macho_objc->selected_row();
        if (!selected || *selected >= macho_objc_visible_rows->size()) return {};
        const auto original = (*macho_objc_visible_rows)[*selected];
        if (original >= macho_objc_rows->size()) return {};
        return (*macho_objc_rows)[original].code_address;
    }
    void populate_macho_objc() {
        const auto doc = shown;
        if (!doc) {
            show_macho_objc_placeholder();
            return;
        }
        if (macho_objc_source.get() != doc.get()) {
            std::vector<MachOObjCViewRow> rows;
            macho_objc_scan.reset();
            if (doc->image && doc->metadata_view().macho) {
                auto scanned = scan_macho_objc_classes(*doc->image, doc->metadata_view());
                if (scanned) {
                    macho_objc_scan = std::make_shared<const MachOObjCScan>(scanned.value());
                    rows = macho_objc_view_rows(scanned.value());
                } else
                    rows.push_back({"Scan", "", "Objective-C runtime metadata", "unavailable",
                                    "bounded scanner", scanned.error().message, {}});
            } else {
                rows.push_back({"Scan", "", "Objective-C runtime metadata", "unavailable",
                                "image metadata", "No loaded Mach-O image is available.", {}});
            }
            macho_objc_rows = std::make_shared<const std::vector<MachOObjCViewRow>>(std::move(rows));
            macho_objc_source = doc;
        }
        if (macho_objc_import_types)
            macho_objc_import_types->Enable(doc->project && doc->project->state && macho_objc_scan && !macho_objc_scan->classes.empty());
        display_macho_objc_rows(doc, macho_objc_rows);
    }
    void populate() {
        macho_slice_choice.reset();
        macho_open_slice->Enable(false);
        macho_details->ChangeValue({});
        if (bookmark_rename) bookmark_rename->Enable(false);
        if (bookmark_remove) bookmark_remove->Enable(false);
        if (!shown) {
            macho_objc_rows.reset();
            macho_objc_scan.reset();
            macho_objc_source = nullptr;
            candidate_items.clear();
            visible_candidate_items.clear();
            symbol_source_count = 0;
            symbol_source_cell = {};
            symbol_source_activate = {};
            visible_symbol_rows.clear();
            strings->set_document({});
            for (auto *table : {candidates, symbols, segments, imports, exports, annotations, bookmarks,
                                elf_programs, elf_sections, elf_dynamic, elf_tables, macho_metadata, macho_objc}) {
                table->populate(0, {});
                table->activate = {};
            }
            show_macho_objc_placeholder();
            index_context_tables({});
            if (pe_view) pe_view->set_document({});
            if (minidump_view) minidump_view->set_document({});
            return;
        }
        const auto doc = shown;
        if (pe_view) pe_view->set_document(doc);
        if (minidump_view) minidump_view->set_document(doc);
        populate_candidate_model(doc);
        candidates->activate = [this, doc](std::size_t row) {
            if (row < visible_candidate_items.size())
                navigate_from_document(doc, visible_candidate_items[row].entry);
        };
        segments->populate(doc->image->layout().segments.size(), [doc](std::size_t row, int column) {
            const auto &item = doc->image->layout().segments[row];
            switch (column) {
            case 0:
                return location_text(item.begin, doc->image.get());
            case 1:
                return text(item.name);
            case 2:
                return wxString::Format("%llu", static_cast<unsigned long long>(item.size));
            default:
                return wxString(item.readable ? "R" : "-") + (item.writable ? "W" : "-") +
                       (item.executable ? "X" : "-");
            }
        });
        segments->activate = [this, doc](std::size_t row) {
            if (row < doc->image->layout().segments.size())
                navigate_from_document(doc, doc->image->layout().segments[row].begin);
        };
        strings->set_document(doc);
        imports->populate(doc->metadata_view().imports.size(), [doc](std::size_t row, int column) {
            const auto &item = doc->metadata_view().imports[row];
            return column == 0   ? location_text(item.iat, doc->image.get())
                   : column == 1 ? text(item.library)
                   : item.name   ? ([&] {
                         const auto rendered = hexlab::symbols::demangle_cpp_name(*item.name);
                         return text(rendered.status == hexlab::symbols::DemangleStatus::demangled
                                         ? std::string_view(rendered.text) : std::string_view(*item.name));
                     })()
                                 : wxString::Format("ordinal %u", *item.ordinal);
        });
        imports->activate = [this, doc](std::size_t row) {
            if (row < doc->metadata_view().imports.size())
                navigate_from_document(doc, Location{doc->metadata_view().imports[row].iat});
        };
        auto export_cell = [doc](std::size_t row, int column) {
            const auto &item = doc->metadata_view().exports[row];
            return column == 0 ? (item.address ? location_text(*item.address, doc->image.get()) : wxString("forwarded"))
                   : column == 1 ? (item.name ? text(*item.name) : wxString::Format("ordinal %u", item.ordinal))
                                 : (item.forwarder ? text(*item.forwarder) : wxString{});
        };
        exports->populate(doc->metadata_view().exports.size(), export_cell);
        symbol_source_count = doc->metadata_view().exports.size();
        symbol_source_cell = export_cell;
        auto export_jump = [this, doc](std::size_t row) {
            if (row >= doc->metadata_view().exports.size()) return;
            const auto &item = doc->metadata_view().exports[row];
            if (item.address)
                navigate_from_document(doc, Location{*item.address});
            else if (item.forwarder)
                log("Forwarder: " + text(*item.forwarder));
        };
        exports->activate = export_jump;
        symbol_source_activate = export_jump;
        if (doc->metadata_view().elf) {
            symbol_source_count = doc->metadata_view().elf->symbols.size();
            symbol_source_cell = [doc](std::size_t row, int column) {
                const auto &item = doc->metadata_view().elf->symbols[row];
                if (column == 0) {
                    if (item.address)
                        return location_text(*item.address, doc->image.get());
                    if (doc->project) {
                        const auto file = elf_symbol_record_at(*doc->project, row);
                        if (file)
                            return location_text(*file);
                    }
                    return wxString("unmapped");
                }
                if (column == 1)
                    return preview_text(item.name, 256);
                return elf_symbol_state(item.state) + "; table file:" + elf_number(item.table_offset) +
                       wxString::Format("; #%u", item.index);
            };
            symbol_source_activate = [this, doc](std::size_t row) {
                if (row >= doc->metadata_view().elf->symbols.size()) return;
                const auto &item = doc->metadata_view().elf->symbols[row];
                if (item.address)
                    navigate_from_document(doc, Location{*item.address});
                else if (doc->project) {
                    const auto file = elf_symbol_record_at(*doc->project, row);
                    if (file)
                        navigate_from_document(doc, Location{*file});
                }
            };
        }
        if (doc->metadata_view().macho) {
            symbol_source_count = doc->metadata_view().macho->symbols.size();
            symbol_source_cell = [doc](std::size_t row, int column) {
                const auto &item = doc->metadata_view().macho->symbols[row];
                if (column == 0)
                    return item.address ? location_text(*item.address, doc->image.get())
                                        : location_text(FileOffset{item.record_file_offset});
                if (column == 1)
                    return preview_text(item.name, 256);
                return macho_symbol_state(item.state) + wxString::Format("; #%u; ", item.index) +
                       location_text(FileOffset{item.record_file_offset});
            };
            symbol_source_activate = [this, doc](std::size_t row) {
                if (row >= doc->metadata_view().macho->symbols.size()) return;
                const auto &item = doc->metadata_view().macho->symbols[row];
                navigate_from_document(doc, item.address ? Location{*item.address}
                                                         : Location{FileOffset{item.record_file_offset}});
            };
        }
        render_symbol_filter(doc);
        macho_metadata->populate(doc->project ? static_cast<std::size_t>(macho_metadata_row_count(*doc->project)) : 0,
                                 [doc](std::size_t row, int column) {
                                     const auto item = macho_metadata_row_at(*doc->project, row);
                                     return item ? macho_metadata_cell(*doc, *item, column) : wxString{};
                                 });
        macho_metadata->activate = [this, doc](std::size_t row) {
            const auto item = macho_metadata_row_at(*doc->project, row);
            macho_slice_choice.reset();
            if (item && item->kind == MachOMetadataKind::slice && doc->project->state->provenance)
                macho_slice_choice = static_cast<std::uint32_t>(item->index);
            macho_open_slice->Enable(macho_slice_choice.has_value());
            if (item)
                macho_details->ChangeValue(
                    macho_metadata_cell(*doc, *item, 0) + " | " + macho_metadata_cell(*doc, *item, 1) + "\n" +
                    macho_metadata_cell(*doc, *item, 2) + "\n" + macho_metadata_cell(*doc, *item, 3));
            if (item)
                navigate_from_document(doc, item->source);
        };
        if (metadata_pages && metadata_pages->GetCurrentPage() == macho_objc)
            populate_macho_objc();
        else if (macho_objc_source.get() == doc.get() && macho_objc_rows)
            display_macho_objc_rows(doc, macho_objc_rows);
        else
            show_macho_objc_placeholder();
        const auto elf = doc->metadata_view().elf ? &*doc->metadata_view().elf : nullptr;
        elf_tables->populate(elf ? elf->symbol_tables.size() : 0, [doc, elf](std::size_t row, int column) {
            const auto &item = elf->symbol_tables[row];
            switch (column) {
            case 0:
                return location_text(FileOffset{item.source.file_offset});
            case 1:
                return item.count ? wxString::Format("%llu", static_cast<unsigned long long>(*item.count))
                                  : wxString("unavailable");
            case 2:
                return elf_number(item.stride);
            default:
                return elf_symbol_bound(item.count_source) +
                       (item.source.address ? "; " + location_text(*item.source.address, doc->image.get())
                                            : wxString{});
            }
        });
        elf_tables->activate = [this, elf](std::size_t row) {
            frame.Navigate(FileOffset{elf->symbol_tables[row].source.file_offset});
        };
        elf_programs->populate(elf ? elf->programs.size() + 1 : 0, [doc, elf](std::size_t row, int column) {
            if (!row) {
                switch (column) {
                case 0:
                    return wxString(elf->header.is_64 ? "ELF64 " : "ELF32 ") +
                           (elf->header.order == ByteOrder::little ? "little " : "big ") +
                           elf_kind(elf->header.object_type);
                case 1:
                    return wxString("file:0x0");
                case 2:
                    return elf_number(elf->header.entry);
                default:
                    return wxString(doc->metadata_complete ? "complete" : "partial") +
                           (elf->interpreter ? "; " + preview_text(elf->interpreter->path, 256) : wxString{});
                }
            }
            const auto &item = elf->programs[row - 1];
            switch (column) {
            case 0:
                return wxString::Format("#%u type %u", item.index, item.type);
            case 1:
                return location_text(FileOffset{item.offset});
            case 2:
                return elf_number(item.address);
            default:
                return "file " + elf_number(item.file_size) + "; memory " + elf_number(item.memory_size) + "; flags " +
                       elf_number(item.flags);
            }
        });
        elf_programs->activate = [this, doc, elf](std::size_t row) {
            frame.Navigate(FileOffset{row ? elf->programs[row - 1].offset : 0});
        };
        elf_sections->populate(elf ? elf->sections.size() : 0, [doc, elf](std::size_t row, int column) {
            const auto &item = elf->sections[row];
            switch (column) {
            case 0:
                return wxString::Format("#%u ", item.index) + preview_text(item.name, 256);
            case 1:
                return location_text(FileOffset{item.offset});
            case 2:
                return "type " + elf_number(item.type) + "; flags " + elf_number(item.flags);
            default:
                return "size " + elf_number(item.size) + wxString::Format("; link %u; info %u", item.link, item.info);
            }
        });
        elf_sections->activate = [this, doc, elf](std::size_t row) {
            const auto &section = elf->sections[row];
            const Address address{elf->header.object_type == 1 ? AddressSpaceId{section.index} : AddressSpaceId{0},
                                  elf->header.object_type == 1 ? 0 : section.address};
            if ((section.flags & 2) && doc->image->segment_at(address))
                frame.Navigate(address);
            else
                frame.Navigate(FileOffset{section.offset});
        };
        elf_dynamic->populate(doc->project ? static_cast<std::size_t>(elf_dynamic_row_count(*doc->project)) : 0,
                              [doc](std::size_t row, int column) {
                                  auto item = elf_dynamic_row_at(*doc->project, row);
                                  if (!item)
                                      return wxString{};
                                  switch (column) {
                                  case 0:
                                      return "file:" + elf_number(item->table->source.file_offset);
                                  case 1:
                                      return elf_dynamic_tag(item->entry->tag);
                                  case 2:
                                      return item->entry->string_value ? preview_text(*item->entry->string_value, 256)
                                                                       : elf_number(item->entry->value);
                                  default:
                                      return wxString::Format("#%u; ", item->entry->index) +
                                             (doc->metadata_view().elf->dynamic_complete ? "complete" : "partial");
                                  }
                              });
        elf_dynamic->activate = [this, doc](std::size_t row) {
            const auto item = elf_dynamic_row_at(*doc->project, row);
            if (item)
                frame.Navigate(FileOffset{item->table->source.file_offset + item->entry->index * item->table->stride});
        };
        if (elf) {
            symbols->fit_columns({0, 1, 2});
            elf_programs->fit_columns({0, 1, 2, 3});
            elf_sections->fit_columns({0, 1, 2, 3});
            elf_dynamic->fit_columns({0, 1, 2, 3});
            elf_tables->fit_columns({0, 1, 2, 3});
        }
        if (doc->metadata_view().macho) {
            symbols->fit_columns({0, 1, 2});
            macho_metadata->fit_columns({0, 1, 2, 3});
        }
        if (doc->project) {
            auto project = doc->project;
            annotations->populate(project->state->user->annotations.size(), [project](std::size_t row, int column) {
                auto &item = project->state->user->annotations[row];
                switch (column) {
                case 0:
                    return location_text(item.location, project->loaded ? project->loaded->image.get() : nullptr);
                case 1:
                    return text(item.name);
                case 2:
                    return preview_text(item.comment);
                default:
                    return location_mapped(*project, item.location) ? wxString("mapped") : wxString("orphaned");
                }
            });
            annotations->activate = [this, doc, project](std::size_t row) {
                auto location = project->state->user->annotations[row].location;
                if (location_mapped(*project, location))
                    frame.Navigate(location);
                else {
                    annotation_context = std::pair{doc->id, location};
                    log("Orphaned annotation at " + location_text(location));
                    frame.UpdateWindowUI(wxUPDATE_UI_RECURSE);
                }
            };
            bookmarks->populate(project->state->user->bookmarks.size(), [project](std::size_t row, int column) {
                auto &item = project->state->user->bookmarks[row];
                return column == 0
                           ? location_text(item.location, project->loaded ? project->loaded->image.get() : nullptr)
                       : column == 1                              ? text(item.label)
                       : location_mapped(*project, item.location) ? wxString("mapped")
                                                                  : wxString("orphaned");
            });
            bookmarks->activate = [this, doc, project](std::size_t row) {
                auto location = project->state->user->bookmarks[row].location;
                if (location_mapped(*project, location))
                    frame.Navigate(location);
                else {
                    annotation_context = std::pair{doc->id, location};
                    log("Orphaned bookmark at " + location_text(location));
                    frame.UpdateWindowUI(wxUPDATE_UI_RECURSE);
                }
            };
        } else {
            annotations->populate(0, {});
            annotations->activate = {};
            bookmarks->populate(0, {});
            bookmarks->activate = {};
        }
        index_context_tables(doc);
    }
    void open(bool raw) {
        wxFileDialog picker(&frame, "Open binary", {}, {}, "All files (*.*)|*.*", wxFD_OPEN | wxFD_FILE_MUST_EXIST);
        if (picker.ShowModal() != wxID_OK)
            return;
        OpenRequest request;
        request.path = picker.GetPath().ToStdWstring();
        request.analysis_options = options;
        if (raw && !configure_raw_mapping(&frame, request))
            return;
        frame.OpenDocument(std::move(request));
    }
    void open_project() {
        wxFileDialog picker(&frame, "Open project", {}, {}, "HexLab projects (*.hxproj)|*.hxproj|All files (*.*)|*.*",
                            wxFD_OPEN | wxFD_FILE_MUST_EXIST);
        if (picker.ShowModal() == wxID_OK)
            frame.OpenProject(picker.GetPath().ToStdWstring());
    }
    void refresh_plugin_analysis() {
        for (const auto &document : controller->documents().documents()) {
            auto project = controller->documents().project(document.id);
            if (!project || !project->loaded)
                continue;
            auto refreshed = controller->reanalyze(
                document.id, plugins->analysis_options(project->analysis_options));
            if (!refreshed)
                controller->documents().report_error(document.id, refreshed.error());
        }
    }
    void configure() {
        wxDialog dialog(&frame, wxID_ANY, "Analysis options");
        auto *box = new wxBoxSizer(wxVERTICAL);
        box->Add(new wxStaticText(&dialog, wxID_ANY, "Applies to the next binary opened."), 0, wxALL, 10);
        wxTextCtrl *fields[3];
        const char *labels[] = {"Instruction budget", "String record budget", "Minimum string characters"};
        const std::size_t values[] = {options.instruction_budget, options.string_budget, options.min_string_characters};
        for (int i = 0; i < 3; ++i) {
            box->Add(new wxStaticText(&dialog, wxID_ANY, labels[i]), 0, wxLEFT | wxRIGHT, 10);
            fields[i] =
                new wxTextCtrl(&dialog, wxID_ANY, wxString::Format("%llu", static_cast<unsigned long long>(values[i])));
            box->Add(fields[i], 0, wxALL | wxEXPAND, 10);
        }
        auto *error = new wxStaticText(&dialog, wxID_ANY, "");
        box->Add(error, 0, wxALL, 10);
        box->Add(dialog.CreateButtonSizer(wxOK | wxCANCEL), 0, wxALL, 10);
        dialog.SetSizerAndFit(box);
        dialog.Bind(
            wxEVT_BUTTON,
            [&](wxCommandEvent &) {
                std::size_t parsed[3];
                for (int i = 0; i < 3; ++i) {
                    auto number = parse_address(fields[i]->GetValue().ToStdWstring());
                    if (!number || !number.value() || number.value() > SIZE_MAX) {
                        error->SetLabel("Enter positive values that fit this platform.");
                        dialog.Fit();
                        return;
                    }
                    parsed[i] = static_cast<std::size_t>(number.value());
                }
                options.instruction_budget = parsed[0];
                options.string_budget = parsed[1];
                options.min_string_characters = parsed[2];
                dialog.EndModal(wxID_OK);
            },
            wxID_OK);
        dialog.ShowModal();
    }
    void jump() {
        if (!shown)
            return;
        // The address dialog and ambiguity chooser are modal. The user can
        // activate another tab, close this document, or receive a newer
        // analysis snapshot while either dialog is open, so bind every result
        // to the exact document view that produced its candidates.
        const auto source_document = shown;
        const auto source_project = source_document->project;
        const auto navigate_from_source = [&](Location destination) {
            const auto current = controller->state().current();
            const auto current_project = controller->documents().project(source_document->id);
            if (closer->closing_window() ||
                controller->documents().active_document() != source_document->id ||
                !current || current->id != source_document->id ||
                current->revision != source_document->revision ||
                current_project != source_project || shown != source_document) {
                log("Jump canceled because the source document changed while choosing a destination.");
                return false;
            }
            frame.Navigate(destination);
            if (state().selection() != std::optional<Location>{destination})
                return false;
            pages->SetSelection(0); // show the destination in disassembly
            return true;
        };
        AddressDialog dialog(&frame);
        if (dialog.ShowModal() != wxID_OK)
            return;
        if (dialog.mode->GetSelection() == 2) {
            auto address = parse_segment_address(*shown->image, dialog.value->GetValue().ToStdWstring());
            if (address)
                navigate_from_source(address.value());
            else
                log(text(address.error().message));
            return;
        }
        auto space = shown->image->layout().space.id;
        if (auto selection = state().selection())
            if (const auto *address = std::get_if<Address>(&*selection))
                space = address->space;
        const auto input = dialog.value->GetValue().ToStdWstring();
        if (dialog.mode->GetSelection() == 0 && !std::wstring_view(input).starts_with(L"va:")) {
            auto requested = dialog.value->GetValue();
            requested.Trim(true).Trim(false);
            std::vector<std::pair<wxString, Location>> entries = image_symbol_locations(shown->metadata_view());
            std::vector<NamedLocationCandidate> bounded_entries;
            for (const auto &segment : shown->image->layout().segments) {
                if (segment.name.empty())
                    continue;
                const Location start{segment.begin};
                const auto label = wxString::FromUTF8(segment.name.data(), segment.name.size());
                bounded_entries.push_back({"section:" + label, start, segment.size});
                bounded_entries.push_back({"segment:" + label, start, segment.size});
            }
            if (shown->project && shown->project->state && shown->project->state->user) {
                for (const auto &annotation : shown->project->state->user->annotations)
                    entries.emplace_back(text(annotation.name), annotation.location);
                for (const auto &bookmark : shown->project->state->user->bookmarks)
                    entries.emplace_back(text(bookmark.label), bookmark.location);
                if (shown->project->functions)
                    for (const auto &function : shown->project->functions->functions)
                        if (function)
                            entries.emplace_back(text(presentation_name(*shown->project, function->entry)), function->entry);
            }
            const auto match = resolve_named_location_expression(entries, bounded_entries, requested);
            if (match.location) {
                navigate_from_source(*match.location);
                return;
            }
            if (match.ambiguous) {
                wxArrayString labels;
                for (const auto &candidate : match.candidates)
                    labels.Add(candidate.name + " — " + location_text(
                        candidate.location, shown && shown->image ? shown->image.get() : nullptr));
                wxSingleChoiceDialog chooser(&frame,
                    "This name refers to more than one location. Choose the destination:",
                    "Ambiguous name: " + requested, labels);
                if (chooser.ShowModal() == wxID_OK && chooser.GetSelection() >= 0 &&
                    static_cast<std::size_t>(chooser.GetSelection()) < match.candidates.size())
                    navigate_from_source(match.candidates[static_cast<std::size_t>(chooser.GetSelection())].location);
                return;
            }
            const bool address_expression = parse_named_location_expression(requested).has_value() ||
                parse_address(requested.ToStdWstring()).has_value();
            const auto suggestions = address_expression
                ? NamedLocationSearch{} : search_named_locations(entries, bounded_entries, requested);
            if (!suggestions.candidates.empty()) {
                wxArrayString labels;
                for (const auto &candidate : suggestions.candidates)
                    labels.Add(candidate.name + " — " + location_text(
                        candidate.location, shown && shown->image ? shown->image.get() : nullptr));
                const auto prompt = suggestions.truncated
                    ? "Choose a matching name (showing the first 128 distinct destinations):"
                    : "Choose a matching name:";
                wxSingleChoiceDialog chooser(&frame, prompt, "Jump name suggestions: " + requested, labels);
                if (chooser.ShowModal() == wxID_OK && chooser.GetSelection() >= 0 &&
                    static_cast<std::size_t>(chooser.GetSelection()) < suggestions.candidates.size())
                    navigate_from_source(suggestions.candidates[static_cast<std::size_t>(chooser.GetSelection())].location);
                return;
            }
            if (const auto expression = parse_named_location_expression(requested)) {
                auto base = parse_address(expression->base_name.ToStdWstring());
                if (base) {
                    Location destination{Address{space, base.value()}};
                    if (apply_location_displacement(destination, expression->add, expression->displacement)) {
                        navigate_from_source(destination);
                    } else {
                        log("Address expression overflows or underflows the address space.");
                    }
                    return;
                }
            }
        }
        std::wstring_view offset = input;
        if (dialog.mode->GetSelection() == 0 && offset.starts_with(L"va:")) {
            offset.remove_prefix(3);
            const auto separator = offset.find(L':');
            if (separator != std::wstring_view::npos) {
                auto domain = parse_address(offset.substr(0, separator));
                if (!domain || domain.value() > std::numeric_limits<std::uint32_t>::max()) {
                    log(domain ? wxString("Address domain exceeds 32 bits") : text(domain.error().message));
                    return;
                }
                space = AddressSpaceId{static_cast<std::uint32_t>(domain.value())};
                offset.remove_prefix(separator + 1);
            }
        }
        auto number = parse_address(offset);
        if (!number) {
            log(text(number.error().message));
            return;
        }
        navigate_from_source(dialog.mode->GetSelection() == 0 ? Location{Address{space, number.value()}}
                                                              : Location{FileOffset{number.value()}});
    }
    const ListingRow *selected_row() {
        if (auto selection = action_location())
            for (const auto &row : listing->page().rows)
                if (row.location == *selection)
                    return &row;
        return nullptr;
    }
    Location reference_origin(Location location) {
        if (!shown || !shown->image) return location;
        std::optional<Address> address;
        if (const auto *value = std::get_if<Address>(&location)) address = *value;
        else if (const auto mapped = shown->image->to_address(std::get<FileOffset>(location)); mapped)
            address = mapped.value();
        if (address)
            for (const auto &row : listing->page().rows) {
                if (!row.instruction) continue;
                const auto &instruction = *row.instruction;
                if (instruction.address.space == address->space && address->offset >= instruction.address.offset &&
                    address->offset - instruction.address.offset < std::max<std::uint32_t>(1, instruction.byte_length()))
                    return instruction.address;
            }
        return location;
    }
    void browse_references(DocumentId id, Location origin, bool incoming) {
        if (controller->documents().active_document() != id || closer->closing_window()) return;
        const auto project = controller->documents().project(id);
        if (!project || !project->references ||
            (project->status != DerivedStatus::fresh && project->status != DerivedStatus::incomplete)) {
            log("References are unavailable until current project analysis is ready.");
            return;
        }
        references->update(id, project, state().selection());
        references->inspect(origin, incoming);
        if (auto *notebook = dynamic_cast<wxNotebook *>(references->GetParent()))
            notebook->SetSelection(notebook->FindPage(references));
        frame.docking_.GetPane("metadata").Show();
        frame.docking_.Update();
    }
    void browse_references(bool incoming) {
        const auto id = controller->documents().active_document();
        auto location = action_location();
        if (!id || !location) return;
        if (location == state().selection()) location = reference_origin(*location);
        browse_references(*id, *location, incoming);
    }
    std::optional<Address> follow_target() {
        const auto *row = selected_row();
        if (!row || !row->instruction)
            return {};
        if (shown && shown->project) {
            auto target = project_follow_target(*shown->project, row->instruction->address);
            if (!target)
                return {};
            if (target.value())
                return target.value();
        }
        // Manual listing rows are decoded by the current-source worker even
        // when rooted recovery has not produced an instruction/reference fact.
        return row->control_target;
    }
    void follow() {
        auto target = follow_target();
        if (target)
            frame.Navigate(*target);
        else
            log("Selected instruction has no resolved target.");
    }
    std::vector<Location> marker_locations() const {
        std::vector<Location> locations;
        if (!shown || !shown->project)
            return locations;
        for (const auto &annotation : shown->project->state->user->annotations)
            locations.push_back(annotation.location);
        for (const auto &bookmark : shown->project->state->user->bookmarks)
            locations.push_back(bookmark.location);
        return locations;
    }
    void navigate_marker(bool next) {
        auto destination = adjacent_marker(marker_locations(), state().selection(), next);
        if (destination)
            frame.Navigate(*destination);
        else
            log(next ? "No next annotation or bookmark" : "No previous annotation or bookmark");
    }
    void update_navigation(wxUpdateUIEvent &event) {
        bool enabled = false;
        wxString reason = "Open a document first";
        auto id = controller->documents().active_document();
        auto document = state().current();
        auto selection = action_location();
        if (closer->closing_window())
            reason = "The window is closing";
        else if (event.GetId() == wxID_OPEN || event.GetId() == open_raw_id || event.GetId() == open_project_id ||
                 event.GetId() == analysis_options_id)
            enabled = true;
        else if (event.GetId() == cancel_id) {
            enabled = state().opening() || (id && controller->read_pending(*id));
            reason = "No background work is running";
        } else if (event.GetId() == wxID_CLOSE) {
            enabled = id.has_value();
        } else if (event.GetId() == browse_navigation_history_id) {
            enabled = !navigation_history.empty();
            reason = "Navigation history is empty";
        } else if (document) {
            switch (event.GetId()) {
            case jump_id:
                enabled = document->image->storage()->size() > 0;
                reason = "The input contains no bytes";
                break;
            case back_id:
                enabled = !navigation_history.empty() && navigation_position > 0;
                reason = "No previous navigation location";
                break;
            case forward_id:
                enabled = !navigation_history.empty() && navigation_position + 1 < navigation_history.size();
                reason = "No next navigation location";
                break;
            case previous_marker_id:
            case next_marker_id: {
                const bool next = event.GetId() == next_marker_id;
                enabled = adjacent_marker(marker_locations(), state().selection(), next).has_value();
                reason = next ? "No next annotation or bookmark" : "No previous annotation or bookmark";
                break;
            }
            case copy_address_id:
                enabled = selection.has_value();
                reason = "Select a location first";
                break;
            case incoming_references_id:
            case outgoing_references_id: {
                const auto project = id ? controller->documents().project(*id) : nullptr;
                enabled = selection && project && project->references &&
                          (project->status == DerivedStatus::fresh || project->status == DerivedStatus::incomplete);
                reason = "Select a location with current project reference analysis";
                break;
            }
            case copy_bytes_id:
            case copy_text_id:
                enabled = selected_row() != nullptr;
                reason = "Select a row in the current byte mapping";
                break;
            case next_page_id:
                enabled = listing->page().next.has_value();
                reason = "No next listing page";
                break;
            case follow_id: {
                auto target = follow_target();
                enabled = target && document->image->segment_at(*target);
                reason = "Selected instruction has no mapped resolved target";
                break;
            }
            }
        }
        event.Enable(enabled);
        if (auto item = frame.GetMenuBar()->FindItem(event.GetId()))
            item->SetHelp(enabled ? wxString{} : reason);
    }
    void copy(int command) {
        auto selection = action_location();
        if (!shown || !selection)
            return;
        wxString value;
        if (command == copy_address_id)
            value = location_text(*selection, shown->image.get());
        else if (const auto *row = selected_row()) {
            if (command == copy_bytes_id) value = hex_bytes(row->bytes);
            else if (row->instruction && plugins) {
                auto decorated = *row;
                (void)plugins->apply_display_extension(*decorated.instruction);
                value = listing_text(*shown, decorated, true);
            } else value = listing_text(*shown, *row, true);
        }
        bool stored = false;
        {
            wxLogNull quiet;
            for (int attempt = 0; attempt < 20 && !stored; ++attempt) {
                if (wxTheClipboard->Open()) {
                    auto data = std::make_unique<wxTextDataObject>(value);
                    if (wxTheClipboard->SetData(data.get())) {
                        data.release();
                        stored = wxTheClipboard->Flush();
                    }
                    wxTheClipboard->Close();
                }
                if (!stored && attempt != 19)
                    wxMilliSleep(10);
            }
        }
        if (!stored)
            log("Clipboard remained busy; copy failed.");
    }
};
MainFrame::MainFrame(std::shared_ptr<plugins::ModuleProvider> plugin_provider)
    : wxFrame(nullptr, wxID_ANY, "HexLab"), docking_(this),
      impl_(std::make_unique<Impl>(*this, std::move(plugin_provider))) {
    {
        std::lock_guard lock(impl_->active_document_bridge->mutex);
        impl_->active_document_bridge->target = this;
    }
    SetClientSize(FromDIP(wxSize(1280, 800)));
    SetMinClientSize(FromDIP(wxSize(640, 400)));
    auto *menus = new wxMenuBar;
    auto *file = new wxMenu;
    file->Append(wxID_OPEN, "&Open...\tCtrl+O");
    file->Append(open_raw_id, "Open &Raw...");
    file->Append(open_project_id, "Open &Project...\tCtrl+Shift+O");
    file->Append(collaboration_review_id, "Review Collaboration Proposals...");
    file->Append(open_archive_id, "Browse &ar Archive...");
    file->Append(compare_id, "Compare Current Project...\tCtrl+Shift+C");
    file->Append(compare_open_projects_id, "Compare Open Projects...");
    file->Append(open_compare_session_id, "Open Comparison Session...");
    file->Append(compare_cancel_id, "Cancel Binary Comparison");
    file->Append(wxID_CLOSE, "&Close Document\tCtrl+W");
    file->Append(cancel_id, "Cancel Background Work");
    file->AppendSeparator();
    file->Append(wxID_EXIT, "E&xit\tAlt+F4");
    menus->Append(file, "&File");
    auto *nav = new wxMenu;
    nav->Append(jump_id, "&Jump...\tG");
    nav->Append(follow_id, "&Follow Target\tEnter");
    nav->Append(incoming_references_id, "Incoming References\tCtrl+Shift+X");
    nav->Append(outgoing_references_id, "Outgoing References\tCtrl+Alt+X");
    nav->Append(back_id, "&Back\tAlt+Left");
    nav->Append(forward_id, "&Forward\tAlt+Right");
    nav->Append(browse_navigation_history_id, "Browse History...");
    nav->Append(previous_marker_id, "Previous Annotation / Bookmark\tAlt+Up");
    nav->Append(next_marker_id, "Next Annotation / Bookmark\tAlt+Down");
    nav->Append(next_page_id, "Next Listing Page\tCtrl+Down");
    menus->Append(nav, "&Navigate");
    auto *edit = new wxMenu;
    edit->Append(copy_address_id, "Copy Address");
    edit->Append(copy_bytes_id, "Copy Bytes");
    edit->Append(copy_text_id, "Copy Text\tCtrl+C");
    menus->Append(edit, "&Edit");
    ProjectActions::add_menus(*file, *edit);
    edit->AppendSeparator();
    edit->Append(wxID_FIND, "&Find...\tCtrl+F");
    edit->Append(find_next_id, "Find &Next\tF3");
    edit->Append(find_previous_id, "Find &Previous\tShift+F3");
    auto *analysis = new wxMenu;
    analysis->Append(flirt_apply_id, "Scan FLAIR Catalog and Browse Results...");
    menus->Append(analysis, "&Analysis");
    auto *view = new wxMenu;
    view->Append(reset_layout_id, "&Reset Layout\tCtrl+Shift+R");
    auto *focus_menu = new wxMenu;
    for (std::size_t i = 0; i < movable_pane_names.size(); ++i) {
        const auto command_id = focus_pane_id_base + static_cast<int>(i);
        const auto pane_label = wxString::FromUTF8(movable_pane_labels[i]);
        focus_menu->Append(command_id, wxString::Format("Focus %s\tCtrl+Alt+F%u", pane_label,
                                                        static_cast<unsigned>(i + 1)));
        focus_menu->SetHelpString(command_id, "Shows the pane and moves keyboard focus to its first available control.");
    }
    view->AppendSubMenu(focus_menu, "Focus Workspace Pane");
    auto *display_menu = new wxMenu;
    for (std::size_t i = 0; i < movable_pane_names.size(); ++i)
        display_menu->Append(move_pane_id_base + static_cast<int>(i),
                              wxString("Move ") + movable_pane_labels[i] + " to Next Display");
    view->AppendSubMenu(display_menu, "Move Pane to Next Display");
    view->Append(dock_floating_panes_id, "Dock Floating Panes");
    view->AppendSeparator();
    view->Append(analysis_options_id, "Analysis Options...");
    view->Append(reanalyze_id, "Reanalyze Project\tCtrl+F5");
    view->Append(type_symbols_id, "Types & Symbols");
    view->Append(pseudocode_id, "Pseudocode at Selection\tCtrl+D");
    view->Append(plugins_panel_id, "Plugins");
#ifdef HEXLAB_DESKTOP_PYTHON_CONSOLE
    view->Append(python_console_id, "Python Console");
#endif
    menus->Append(view, "&View");
    auto *debug = new wxMenu;
    debug->Append(debugger_panel_id, "&Debugger Panel");
    debug->Append(debugger_toggle_selection_bp_id, "Toggle software breakpoint at listing selection");
    menus->Append(debug, "&Debug");
    auto *help = new wxMenu;
    help->Append(wxID_ABOUT, "&About HexLab");
    menus->Append(help, "&Help");
    auto *plugin_menu = new wxMenu;
    menus->Append(plugin_menu, "E&xtensions");
    impl_->plugin_menu = plugin_menu;
    SetMenuBar(menus);
    CreateStatusBar(2);
    const int widths[] = {-1, 120};
    GetStatusBar()->SetStatusWidths(2, widths);
    auto &ui = *impl_;
    auto *workspace = new wxPanel(this);
    workspace->SetName("Disassembly, graph, and pseudocode workspace");
    auto *stack = new wxBoxSizer(wxVERTICAL);
    ui.tabs = new DocumentTabs(workspace);
    ui.tabs->SetPageSize(FromDIP(wxSize(1, 1)));
    ui.tabs->Hide();
    stack->Add(ui.tabs, 0, wxEXPAND);
    ui.center = new wxSimplebook(workspace);
    stack->Add(ui.center, 1, wxEXPAND);
    workspace->SetSizer(stack);
    auto *welcome = new wxPanel(ui.center);
    auto *layout = new wxBoxSizer(wxVERTICAL);
    layout->Add(new wxStaticText(welcome, wxID_ANY,
                                 "HexLab\n\nOpen a binary or project to begin analysis.\n\nFile > Open    Ctrl+O\nFile "
                                 "> Open Raw    for explicit raw mappings"),
                0, wxALL, FromDIP(28));
    welcome->SetSizer(layout);
    ui.center->AddPage(welcome, "Welcome");
    auto *pages = new wxNotebook(ui.center, wxID_ANY);
    ui.pages = pages;
    ui.listing = new ListingView(pages);
    ui.bytes = new BytesView(pages);
    pages->AddPage(ui.listing, "Disassembly");
    pages->AddPage(ui.bytes, "Bytes");
    ui.graph = new GraphView(pages);
    pages->AddPage(ui.graph, "Graph");
    ui.pseudocode = new PseudocodeView(pages);
    pages->AddPage(ui.pseudocode, "Pseudocode");
    ui.source = new SourceView(pages);
    pages->AddPage(ui.source, "Source");
    ui.pseudocode->navigate_document = [this](const PseudocodeNavigationToken &token, Location location) {
        const auto id = token.document;
        const auto current = impl_->controller->state().current();
        const auto project = impl_->controller->documents().project(id);
        const bool current_project_matches = token.project_uuid
            ? project && project->state && project->state->uuid == *token.project_uuid &&
                  project->state->revisions == token.project_revisions
            : !project || !project->state;
        if (projects().active_document() != id || !current || current->id != id ||
            current->revision != token.document_revision || !current_project_matches ||
            impl_->closer->closing_window()) {
            impl_->log("Pseudocode origin navigation was canceled because its document revision is stale.");
            return;
        }
        Navigate(location);
        if (impl_->graph && impl_->graph->canvas) impl_->graph->canvas->reveal_selection();
    };
    const auto synchronize_graph_source = [this](std::shared_ptr<const ProjectGraph> source_graph, Location location) {
        const auto id = impl_->controller->documents().active_document();
        const auto document = impl_->state().current();
        const auto project = id ? impl_->controller->documents().project(*id) : nullptr;
        const auto current_graph = impl_->graph->canvas->graph();
        if (!id || !document || document->id != *id || !impl_->shown ||
            impl_->shown->id != *id || impl_->shown->revision != document->revision ||
            !project || !project->loaded || !project->loaded->image ||
            document->image != project->loaded->image ||
            !source_graph || source_graph != current_graph ||
            source_graph != impl_->controller->graph_result(*id) ||
            !project_graph_current(*project, *source_graph) || impl_->closer->closing_window()) {
            impl_->log("Graph changed; stale navigation was canceled.");
            return false;
        }
        // Location equality retains the address-space ID. Equal offsets in
        // another image domain must never become a graph source by accident.
        bool graph_location = false;
        for (const auto &node : source_graph->model->nodes) {
            if (node.selection == std::optional<Location>{location}) { graph_location = true; break; }
            if (node.block)
                for (const auto &fact : node.block->instructions)
                    if (fact && Location{fact->instruction.address} == location) { graph_location = true; break; }
            if (graph_location) break;
        }
        if (!graph_location)
            for (const auto &edge : source_graph->model->edges)
                if (edge.selection == std::optional<Location>{location} ||
                    edge.target_location == std::optional<Location>{location}) { graph_location = true; break; }
        if (!graph_location) {
            impl_->log("Selected source is absent from the current graph.");
            return false;
        }
        Navigate(location);
        return impl_->state().selection() == std::optional<Location>{location};
    };
    ui.graph->canvas->synchronize_selection = synchronize_graph_source;
    ui.graph->show_source = [this, synchronize_graph_source](std::shared_ptr<const ProjectGraph> graph,
                                                            Location location, bool pseudocode) {
        if (!synchronize_graph_source(std::move(graph), location)) return;
        auto *view = pseudocode ? static_cast<wxWindow *>(impl_->pseudocode)
                                : static_cast<wxWindow *>(impl_->listing);
        const auto page = impl_->pages->FindPage(view);
        if (page != wxNOT_FOUND) {
            impl_->pages->SetSelection(static_cast<std::size_t>(page));
            view->SetFocus();
        }
    };
    ui.graph->canvas->context_action = [this](Location location, GraphContextAction action) {
        const auto id = impl_->controller->documents().active_document();
        const auto project = id ? impl_->controller->documents().project(*id) : nullptr;
        const auto current_graph = impl_->graph && impl_->graph->canvas ? impl_->graph->canvas->graph() : nullptr;
        if (!project || !current_graph || !project_graph_current(*project, *current_graph)) {
            impl_->log("Graph changed; stale context action was canceled.");
            return;
        }
        Navigate(location);
        if (impl_->state().selection() != std::optional<Location>{location}) return;
        const auto command_id = action == GraphContextAction::rename ? rename_id
                              : action == GraphContextAction::comment ? comment_id
                                                                      : bookmark_id;
        wxCommandEvent command(wxEVT_MENU, command_id);
        GetEventHandler()->ProcessEvent(command);
    };
    ui.graph->canvas->context_action_available = [this](Location location, GraphContextAction action) {
        const auto id = impl_->controller->documents().active_document();
        const auto project = id ? impl_->controller->documents().project(*id) : nullptr;
        if (!project) return false;
        const auto kind = action == GraphContextAction::rename ? ProjectActionKind::rename
                        : action == GraphContextAction::comment ? ProjectActionKind::comment
                                                                : ProjectActionKind::bookmark;
        return action_availability(project.get(), kind, location).enabled;
    };
    ui.graph->canvas->follow_instruction = [this](std::shared_ptr<const ProjectGraph> source_graph, Address source) {
        const auto id = projects().active_document();
        const auto document = impl_->state().current();
        const auto project = id ? projects().project(*id) : nullptr;
        const auto current_graph = impl_->graph->canvas->graph();
        if (!id || !document || document->id != *id || !impl_->shown ||
            impl_->shown->id != *id || impl_->shown->revision != document->revision ||
            !project || !project->loaded || !project->loaded->image ||
            document->image != project->loaded->image ||
            !source_graph || source_graph != current_graph ||
            !project_graph_current(*project, *source_graph) || impl_->closer->closing_window()) {
            impl_->log("Graph changed; stale instruction follow was canceled.");
            return;
        }
        // Resolve from the current graph facts, never the listing's prior row.
        // The reference service checks exact instruction provenance and rejects
        // ambiguous transfer targets. Image mappings own both endpoints.
        const auto &image = *project->loaded->image;
        const auto *source_segment = image.segment_at(source);
        if (!source_segment || !source_segment->executable) {
            impl_->log("Graph instruction is outside executable image mappings.");
            return;
        }
        auto target = project_follow_target(*project, source);
        if (!target) {
            impl_->log(text(target.error().message));
            return;
        }
        if (target.value()) {
            const auto *destination_segment = image.segment_at(*target.value());
            if (!destination_segment || !destination_segment->executable) {
                impl_->log("Graph target is outside executable image mappings.");
                return;
            }
        }
        Navigate(source);
        if (impl_->state().selection() != std::optional<Location>{source}) return;
        if (target.value()) Navigate(*target.value());
        else impl_->log("Selected graph instruction has no resolved target.");
    };
    ui.graph->kind_changed = [this](GraphKind kind, std::size_t call_depth) {
        if (auto id = projects().active_document()) {
            auto result = impl_->controller->request_graph(*id, impl_->state().selection(), kind, call_depth);
            (void)result;
            impl_->sync();
        }
    };
    ui.center->AddPage(pages, "Binary");
    ui.listing->navigate = [this](Location location) { Navigate(location); };
    ui.strings->comment = [this](Location location) {
        const auto id = projects().active_document();
        if (!id) return;
        const auto project = projects().project(*id);
        if (!project || !project->state || project->mode == database::ProjectMode::read_only) {
            impl_->log_to(*id, "String comments require a writable project.");
            return;
        }
        const auto *existing = annotation_at(*project, location);
        auto dialog = edit_dialog(this, "Comment string", "Project comment:",
                                  existing ? text(existing->comment) : wxString{}, true,
                                  [location](const wxString &value) -> Result<ProjectCommand> {
                                      const auto encoded = value.utf8_str();
                                      return ProjectCommand{Comment{
                                          location, std::string(encoded.data(), encoded.length())}};
                                  });
        if (!dialog) return;
        auto result = impl_->controller->execute(*id, std::move(*dialog));
        if (!result) impl_->controller->documents().report_error(*id, result.error());
    };
    ui.bytes->navigate = ui.listing->navigate;
    ui.bytes->submit = [this](ProjectCommand command) {
        const auto id = projects().active_document();
        if (!id) return;
        auto result = impl_->controller->execute(*id, std::move(command));
        if (!result) impl_->controller->documents().report_error(*id, result.error());
    };
    ui.source->navigate = ui.listing->navigate;
    ui.source->toggle_project_breakpoint = [this](std::shared_ptr<const DocumentSnapshot> expected, Address address) {
        if (!expected || impl_->state().current() != expected) return false;
        const auto id = projects().active_document();
        if (!id || *id != expected->id) return false;
        const auto project = projects().project(*id);
        if (!expected->project || !project || project != expected->project || !project->state ||
            project->mode == database::ProjectMode::read_only) return false;
        const auto &breakpoints = project->state->user->breakpoints;
        const auto existing = std::find_if(breakpoints.begin(), breakpoints.end(), [&](const auto &item) {
            return item.address == address && item.kind == database::ProjectBreakpointKind::software;
        });
        ProjectCommand command = existing == breakpoints.end()
            ? ProjectCommand{SetProjectBreakpoint{address}}
            : ProjectCommand{SetProjectBreakpoint{address, database::ProjectBreakpointKind::software,
                                                  existing->size, false, true}};
        auto result = impl_->controller->execute(*id, std::move(command));
        if (!result) {
            impl_->controller->documents().report_error(*id, result.error());
            return false;
        }
        return true;
    };
    docking_.AddPane(workspace, wxAuiPaneInfo().Name("workspace").CenterPane().PaneBorder(false));
    auto *function_panel = new wxPanel(this);
    function_panel->SetName("Functions pane");
    auto *function_layout = new wxBoxSizer(wxVERTICAL);
    ui.function_filter = new wxTextCtrl(function_panel, wxID_ANY, {}, wxDefaultPosition, wxDefaultSize,
                                        wxTE_PROCESS_ENTER);
    ui.function_filter->SetName("function-filter");
    ui.function_filter->SetHint("Filter by function name or address");
    ui.candidates = new VirtualTable(function_panel, "functions", {"Address", "Name", "Blocks", "State"});
    auto *symbol_panel = new wxPanel(this);
    symbol_panel->SetName("Symbols pane");
    auto *symbol_layout = new wxBoxSizer(wxVERTICAL);
    ui.symbol_filter = new wxTextCtrl(symbol_panel, wxID_ANY, {}, wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);
    ui.symbol_filter->SetName("symbol-filter");
    ui.symbol_filter->SetHint("Filter symbols by address, name, or state");
    ui.symbol_filter_status = new wxStaticText(symbol_panel, wxID_ANY, "0 of 0 symbols");
    ui.symbols = new VirtualTable(symbol_panel, "symbols", {"Address / record", "Symbol", "State / forwarder"});
    ui.symbols->SetName("Symbols pane");
    ui.candidates->SetColumnWidth(0, FromDIP(140));
    ui.symbols->SetColumnWidth(0, FromDIP(140));
    symbol_layout->Add(ui.symbol_filter, 0, wxEXPAND | wxALL, FromDIP(4));
    symbol_layout->Add(ui.symbol_filter_status, 0, wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(4));
    symbol_layout->Add(ui.symbols, 1, wxEXPAND);
    symbol_panel->SetSizer(symbol_layout);
    function_layout->Add(ui.function_filter, 0, wxEXPAND | wxALL, FromDIP(4));
    function_layout->Add(ui.candidates, 1, wxEXPAND);
    function_panel->SetSizer(function_layout);
    docking_.AddPane(function_panel, wxAuiPaneInfo()
                                        .Name("functions")
                                        .Caption("Functions")
                                        .Left()
                                        .Position(0)
                                        .BestSize(FromDIP(wxSize(260, 250)))
                                        .MinSize(FromDIP(wxSize(160, 100))));
    docking_.AddPane(symbol_panel, wxAuiPaneInfo()
                                     .Name("symbols")
                                     .Caption("Symbols")
                                     .Left()
                                     .Position(1)
                                     .BestSize(FromDIP(wxSize(260, 200)))
                                     .MinSize(FromDIP(wxSize(160, 100))));
    auto *metadata = new wxNotebook(this, wxID_ANY);
    ui.metadata_pages = metadata;
    metadata->SetName("Binary metadata pane");
    ui.pe_view = new PeView(metadata);
    ui.minidump_view = new MinidumpView(metadata);
    ui.minidump_view->navigate = [this](Location location) { Navigate(location); };
    ui.pe_view->navigate = [this](std::shared_ptr<const DocumentSnapshot> source, Location location) {
        impl_->navigate_from_document(source, location);
    };
    ui.pe_view->open_runtime_view = [this](PeRuntimeArchitecture target) {
        const auto doc = impl_->shown;
        if (!doc || !doc->project || !doc->project->state ||
            !doc->project->state->provenance || doc->project->state->provenance->native_path.empty())
            return;
        OpenRequest request;
        request.path = doc->project->state->provenance->native_path;
        request.format = Format::pe;
        request.pe_runtime_architecture = target;
        request.analysis_options = doc->project->analysis_options;
        OpenDocument(std::move(request));
    };
    ui.segments = new VirtualTable(metadata, "segments", {"Address", "Name", "Size", "Permissions"});
    ui.strings = new StringBrowserView(metadata);
    ui.strings->navigate = [this](Location location) { Navigate(location); };
    ui.imports = new VirtualTable(metadata, "imports", {"IAT", "Library", "Name / ordinal"});
    ui.exports = new VirtualTable(metadata, "exports", {"Address", "Name", "Forwarder"});
    ui.elf_programs = new VirtualTable(metadata, "elf-programs", {"Header / program", "File", "Address", "Details"});
    ui.elf_sections = new VirtualTable(metadata, "elf-sections", {"Section", "File", "Type / flags", "Details"});
    ui.elf_dynamic = new VirtualTable(metadata, "elf-dynamic", {"Table", "Tag", "Value / string", "State"});
    ui.elf_tables = new VirtualTable(metadata, "elf-tables", {"Table file", "Count", "Stride", "Bound"});
    auto *macho_panel = new wxPanel(metadata);
    auto *macho_box = new wxBoxSizer(wxVERTICAL);
    ui.macho_metadata = new VirtualTable(macho_panel, "macho-metadata", {"Record", "Source", "Value", "Details"});
    ui.macho_open_slice = new wxButton(macho_panel, wxID_ANY, "Open original slice in new tab");
    ui.macho_open_slice->SetName("macho-open-slice");
    ui.macho_open_slice->SetToolTip("Select a Slice row. Opens the original source file with that slice; the current "
                                    "project keeps its saved selection and edits.");
    ui.macho_open_slice->Enable(false);
    ui.macho_details = new wxTextCtrl(macho_panel, wxID_ANY, "", wxDefaultPosition, FromDIP(wxSize(-1, 70)),
                                      wxTE_READONLY | wxTE_MULTILINE | wxTE_WORDWRAP);
    ui.macho_details->SetName("macho-record-details");
    ui.macho_open_slice->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        const auto doc = impl_->shown;
        if (!impl_->macho_slice_choice || !doc || !doc->project || !doc->project->state->provenance)
            return;
        OpenRequest request;
        request.path = doc->project->state->provenance->native_path;
        request.format = Format::macho;
        request.macho = MachOOptions{*impl_->macho_slice_choice};
        request.analysis_options = doc->project->analysis_options;
        OpenDocument(std::move(request));
    });
    macho_box->Add(ui.macho_metadata, 1, wxEXPAND);
    macho_box->Add(ui.macho_details, 0, wxEXPAND | wxTOP, FromDIP(4));
    macho_box->Add(ui.macho_open_slice, 0, wxALL, FromDIP(4));
    macho_panel->SetSizer(macho_box);
    ui.macho_objc = new VirtualTable(metadata, "macho-objc",
                                     {"Kind", "Owner", "Name", "Address", "Status", "Provenance", "Details"});
    ui.macho_objc->SetToolTip("Objective-C runtime records from the bounded scan of the displayed Mach-O snapshot. Activate an addressable row to navigate.");
    ui.macho_objc_filter = new wxTextCtrl(metadata, wxID_ANY);
    ui.macho_objc_filter->SetName("macho-objc-filter");
    ui.macho_objc_filter->SetHint("Filter kind, class, selector, status, provenance, or details");
    ui.macho_objc_filter->SetToolTip("Case-insensitive filter over the loaded Objective-C runtime rows. Activating a filtered row still navigates to its original address.");
    ui.macho_objc_filter_status = new wxStaticText(metadata, wxID_ANY, "No runtime records loaded");
    ui.macho_objc_import_types = new wxButton(metadata, wxID_ANY, "Import Objective-C types");
    ui.macho_objc_import_types->SetName("macho-objc-import-types");
    ui.macho_objc_import_types->Enable(false);
    ui.macho_objc_import_types->SetToolTip("Persist class instance layouts and parsed method signatures from validated Objective-C runtime records.");
    ui.macho_objc_pseudocode = new wxButton(metadata, wxID_ANY, "Pseudocode at implementation");
    ui.macho_objc_pseudocode->SetName("macho-objc-pseudocode");
    ui.macho_objc_pseudocode->Enable(false);
    ui.macho_objc_pseudocode->SetToolTip("Open the selected method implementation in the pseudocode view when the runtime record has an exact implementation address.");
    ui.macho_objc_pseudocode->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        const auto doc = impl_->macho_objc_source;
        const auto implementation = impl_->selected_macho_objc_implementation();
        if (!doc || !implementation || !impl_->navigate_from_document(doc, *implementation)) return;
        if (impl_->pages && impl_->pseudocode) {
            impl_->pages->SetSelection(impl_->pages->FindPage(impl_->pseudocode));
            impl_->sync();
        }
    });
    ui.macho_objc_import_types->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        const auto doc = impl_->shown;
        if (!doc || !doc->project || !doc->project->state || !impl_->macho_objc_scan) return;
        if (impl_->macho_objc_source.get() != doc.get()) {
            impl_->populate_macho_objc();
            wxMessageBox("The displayed document changed. Review the refreshed Objective-C metadata before importing.",
                         "Import Objective-C types", wxOK | wxICON_INFORMATION, this);
            return;
        }
        auto plan = macho_objc_type_import_plan(*impl_->macho_objc_scan, doc->project->state->user->types);
        if (plan.definitions.empty()) {
            wxString message = "No new Objective-C types are eligible for import.";
            if (!plan.conflicts.empty()) message += "\nConflicts: " + wxString::FromUTF8(plan.conflicts.front().c_str());
            if (!plan.skipped.empty()) message += "\nSkipped: " + wxString::FromUTF8(plan.skipped.front().c_str());
            wxMessageBox(message, "Import Objective-C types", wxOK | wxICON_INFORMATION, this);
            return;
        }
        const auto count = plan.definitions.size();
        const auto skipped = plan.skipped.size(), conflicts = plan.conflicts.size();
        auto submitted = impl_->frame.ApplyProjectCommand(ImportPortableTypes{std::move(plan.definitions), {}});
        if (!submitted) {
            wxMessageBox(wxString::FromUTF8(submitted.error().message.c_str()),
                         "Import Objective-C types", wxOK | wxICON_ERROR, this);
            return;
        }
        wxString message = wxString::Format("Imported %zu Objective-C type declarations.", count);
        if (skipped || conflicts)
            message += wxString::Format("\nSkipped %zu unsupported records and %zu name conflicts.", skipped, conflicts);
        wxMessageBox(message, "Import Objective-C types", wxOK | wxICON_INFORMATION, this);
    });
    auto *macho_objc_layout = new wxBoxSizer(wxVERTICAL);
    auto *macho_objc_filter_row = new wxBoxSizer(wxHORIZONTAL);
    macho_objc_filter_row->Add(new wxStaticText(metadata, wxID_ANY, "Filter"), 0,
                               wxALL | wxALIGN_CENTER_VERTICAL, FromDIP(3));
    macho_objc_filter_row->Add(ui.macho_objc_filter, 1, wxALL | wxEXPAND, FromDIP(3));
    macho_objc_filter_row->Add(ui.macho_objc_filter_status, 0,
                               wxALL | wxALIGN_CENTER_VERTICAL, FromDIP(3));
    macho_objc_layout->Add(macho_objc_filter_row, 0, wxEXPAND);
    macho_objc_layout->Add(ui.macho_objc_import_types, 0, wxALL, FromDIP(3));
    macho_objc_layout->Add(ui.macho_objc_pseudocode, 0, wxALL, FromDIP(3));
    macho_objc_layout->Add(ui.macho_objc, 1, wxEXPAND);
    auto *macho_objc_panel = new wxPanel(metadata);
    macho_objc_panel->SetSizer(macho_objc_layout);
    ui.macho_objc->Reparent(macho_objc_panel);
    ui.macho_objc_filter->Reparent(macho_objc_panel);
    ui.macho_objc_filter_status->Reparent(macho_objc_panel);
    const auto update_objc_pseudocode_action = [this, button = ui.macho_objc_pseudocode](wxListEvent &) {
        if (button) button->Enable(impl_->selected_macho_objc_implementation().has_value());
    };
    ui.macho_objc->Bind(wxEVT_LIST_ITEM_SELECTED, update_objc_pseudocode_action);
    ui.macho_objc->Bind(wxEVT_LIST_ITEM_DESELECTED, update_objc_pseudocode_action);
    ui.macho_objc_filter->Bind(wxEVT_TEXT, [this](wxCommandEvent &) {
        impl_->macho_objc_filter_timer.Stop();
        if (impl_->macho_objc_filter_status) impl_->macho_objc_filter_status->SetLabel("Filtering...");
        impl_->macho_objc_filter_timer.StartOnce(150);
    });
    ui.annotations = new VirtualTable(metadata, "annotations", {"Address / offset", "Name", "Comment", "State"});
    auto *bookmark_panel = new wxPanel(metadata);
    auto *bookmark_layout = new wxBoxSizer(wxVERTICAL);
    ui.bookmarks = new VirtualTable(bookmark_panel, "bookmarks", {"Address / offset", "Label", "State"});
    ui.bookmarks->SetColumnWidth(0, FromDIP(150));
    ui.bookmarks->SetColumnWidth(1, FromDIP(150));
    ui.bookmark_rename = new wxButton(bookmark_panel, wxID_ANY, "Rename label...");
    ui.bookmark_rename->SetName("bookmark-rename");
    ui.bookmark_remove = new wxButton(bookmark_panel, wxID_ANY, "Remove bookmark");
    ui.bookmark_remove->SetName("bookmark-remove");
    ui.bookmark_rename->Enable(false);
    ui.bookmark_remove->Enable(false);
    ui.bookmarks->Bind(wxEVT_LIST_ITEM_SELECTED, [table = ui.bookmarks, rename = ui.bookmark_rename,
                                                  remove = ui.bookmark_remove](wxListEvent &) {
        const bool selected = table->selected_row().has_value();
        rename->Enable(selected);
        remove->Enable(selected);
    });
    auto *bookmark_actions = new wxBoxSizer(wxHORIZONTAL);
    bookmark_actions->Add(ui.bookmark_rename, 0, wxALL, FromDIP(3));
    bookmark_actions->Add(ui.bookmark_remove, 0, wxALL, FromDIP(3));
    bookmark_layout->Add(ui.bookmarks, 1, wxEXPAND);
    bookmark_layout->Add(bookmark_actions, 0, wxALIGN_RIGHT);
    bookmark_panel->SetSizer(bookmark_layout);
    metadata->AddPage(ui.segments, "Segments");
    metadata->AddPage(ui.strings, "Strings");
    metadata->AddPage(ui.imports, "Imports");
    metadata->AddPage(ui.exports, "Exports");
    metadata->AddPage(ui.pe_view, "PE");
    metadata->AddPage(ui.minidump_view, "Minidump");
    metadata->AddPage(ui.elf_programs, "ELF headers");
    metadata->AddPage(ui.elf_sections, "ELF sections");
    metadata->AddPage(ui.elf_dynamic, "ELF dynamic");
    metadata->AddPage(ui.elf_tables, "ELF tables");
    metadata->AddPage(macho_panel, "Mach-O");
    metadata->AddPage(macho_objc_panel, "Objective-C");
    metadata->AddPage(ui.annotations, "Annotations");
    metadata->AddPage(bookmark_panel, "Bookmarks");
    ui.references = new ReferenceView(metadata);
    metadata->AddPage(ui.references, "References");
    ui.history_view = new HistoryView(metadata);
    ui.history_view->navigate = [this](Location location) { Navigate(location); };
    metadata->AddPage(ui.history_view, "History");
    ui.analysis_issues = new AnalysisIssuesView(metadata);
    ui.analysis_issues->navigate = [this](Location location) { Navigate(location); };
    metadata->AddPage(ui.analysis_issues, "Analysis issues");
    if (auto *table = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("disassembly", ui.listing))) {
        table->Bind(wxEVT_CONTEXT_MENU, [this, table](wxContextMenuEvent &event) {
            const auto document = impl_->shown;
            if (!document || !document->project || !document->project->references ||
                (document->project->status != DerivedStatus::fresh && document->project->status != DerivedStatus::incomplete))
                return;
            auto position = event.GetPosition();
            const bool keyboard = position == wxPoint(-1, -1);
            long row = -1;
            if (keyboard) row = table->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
            else {
                position = table->ScreenToClient(position);
                int flags = 0;
                row = table->HitTest(position, flags);
            }
            const auto &page = impl_->listing->page();
            if (row < 0 || static_cast<std::size_t>(row) >= page.rows.size()) return;
            const auto &item = page.rows[static_cast<std::size_t>(row)];
            const auto origin = item.instruction ? Location{item.instruction->address} : item.location;
            const auto id = document->id;
            wxMenu menu;
            menu.Append(incoming_references_id, "Incoming references to " + location_text(origin, document->image.get()));
            menu.Append(outgoing_references_id, "Outgoing references from " + location_text(origin, document->image.get()));
            menu.Bind(wxEVT_MENU, [this, id, origin](wxCommandEvent &) {
                impl_->browse_references(id, origin, true);
            }, incoming_references_id);
            menu.Bind(wxEVT_MENU, [this, id, origin](wxCommandEvent &) {
                impl_->browse_references(id, origin, false);
            }, outgoing_references_id);
            // Querying a right-clicked row must not add a navigation/history entry.
            if (keyboard) table->PopupMenu(&menu);
            else table->PopupMenu(&menu, position);
        });
        // Native list controls may select on right-button down before emitting
        // their context event. Consume that path and query the hit row directly.
        table->Bind(wxEVT_RIGHT_DOWN, [table](wxMouseEvent &event) {
            wxContextMenuEvent context(wxEVT_CONTEXT_MENU, table->GetId(),
                                       table->ClientToScreen(event.GetPosition()));
            context.SetEventObject(table);
            table->GetEventHandler()->ProcessEvent(context);
        });
        table->Bind(wxEVT_RIGHT_UP, [](wxMouseEvent &) {});
    }
    ui.type_symbols = new TypeSymbolsView(metadata);
    metadata->AddPage(ui.type_symbols, "Types & Symbols");
    ui.plugins = new PluginsView(metadata, impl_->plugin_provider);
    const std::weak_ptr<Impl::ActiveDocumentBridge> document_bridge = impl_->active_document_bridge;
    plugins::ActiveDocumentServices active_document_services;
    active_document_services.query = [document_bridge](HexLabActiveDocumentInfo& output) -> std::int32_t {
        const auto bridge = document_bridge.lock();
        if (!bridge) return HEXLAB_ACTIVE_DOCUMENT_FAILED;
        std::shared_ptr<const DocumentSnapshot> document;
        std::uint64_t open_generation = 0;
        std::optional<DocumentId> active_id;
        { std::lock_guard lock(bridge->mutex); document = bridge->current;
          open_generation = bridge->open_generation; active_id = bridge->active_id; }
        if (!document || active_id != document->id || open_generation == 0)
            return HEXLAB_ACTIVE_DOCUMENT_FAILED;
        const auto image = active_document_image(*document);
        if (!image) return HEXLAB_ACTIVE_DOCUMENT_FAILED;
        output = {};
        output.struct_size = sizeof(output);
        output.address_space = image->layout().space.id.value;
        output.address_width = image->layout().space.width_bits;
        output.byte_order = image->layout().space.order == ByteOrder::big ? 1u : 0u;
        output.token.struct_size = sizeof(output.token);
        output.token.document_id = document->id.value;
        output.token.open_generation = open_generation;
        if (document->project && document->project->state) {
            output.token.edit_revision = document->project->state->revisions.edit;
            output.token.byte_revision = document->project->state->revisions.bytes;
            output.token.decision_revision = document->project->state->revisions.decisions;
        }
        output.image_size = document->metadata_view().image_size;
        output.file_size = document->file_storage().size();
        if (!copy_ascii_id(output.architecture_id, architecture_id(image->layout().architecture)) ||
            !copy_ascii_id(output.mode_id, execution_mode_id(image->layout().mode)))
            return HEXLAB_ACTIVE_DOCUMENT_FAILED;
        return HEXLAB_ACTIVE_DOCUMENT_OK;
    };
    active_document_services.read = [document_bridge](const HexLabDocumentToken& token,
        const HexLabProjectLocation& source, std::uint32_t size, std::uint8_t* output) -> std::int32_t {
        Location location;
        if (!parse_active_location(source, location) || !size ||
            size > HEXLAB_ACTIVE_DOCUMENT_MAX_READ || !output)
            return HEXLAB_ACTIVE_DOCUMENT_INVALID;
        const auto bridge = document_bridge.lock();
        if (!bridge) return HEXLAB_ACTIVE_DOCUMENT_FAILED;
        std::shared_ptr<const DocumentSnapshot> document;
        std::uint64_t open_generation = 0;
        std::optional<DocumentId> active_id;
        { std::lock_guard lock(bridge->mutex); document = bridge->current;
          open_generation = bridge->open_generation; active_id = bridge->active_id; }
        if (!document) return HEXLAB_ACTIVE_DOCUMENT_FAILED;
        if (active_id != document->id || !document_token_matches(*document, open_generation, token))
            return HEXLAB_ACTIVE_DOCUMENT_STALE;
        try {
            std::vector<std::byte> bytes;
            if (const auto *address = std::get_if<Address>(&location)) {
                const auto image = active_document_image(*document);
                if (!image) return HEXLAB_ACTIVE_DOCUMENT_FAILED;
                auto read = image->read(*address, size);
                if (!read || read.value().size() != size) return HEXLAB_ACTIVE_DOCUMENT_FAILED;
                bytes = std::move(read.value());
            } else {
                auto read = document->file_storage().read_at(std::get<FileOffset>(location), size);
                if (!read || read.value().bytes.size() != size) return HEXLAB_ACTIVE_DOCUMENT_FAILED;
                bytes.assign(read.value().bytes.begin(), read.value().bytes.end());
            }
            std::vector<std::uint8_t> result(bytes.size());
            for (std::size_t i = 0; i < bytes.size(); ++i)
                result[i] = std::to_integer<std::uint8_t>(bytes[i]);
            {
                std::lock_guard lock(bridge->mutex);
                if (bridge->current != document || bridge->active_id != document->id ||
                    bridge->open_generation != open_generation ||
                    !document_token_matches(*document, bridge->open_generation, token))
                    return HEXLAB_ACTIVE_DOCUMENT_STALE;
            }
            std::copy(result.begin(), result.end(), output);
            return HEXLAB_ACTIVE_DOCUMENT_OK;
        } catch (...) { return HEXLAB_ACTIVE_DOCUMENT_FAILED; }
    };
    active_document_services.navigate = [document_bridge](const HexLabDocumentToken& token,
        const HexLabProjectLocation& source) -> std::int32_t {
        Location location;
        if (!parse_active_location(source, location)) return HEXLAB_ACTIVE_DOCUMENT_INVALID;
        const auto deadline = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(HEXLAB_ACTIVE_DOCUMENT_NAVIGATION_TIMEOUT_MS);
        const auto perform = [document_bridge, token, location, deadline]() -> std::int32_t {
            if (std::chrono::steady_clock::now() > deadline) return HEXLAB_ACTIVE_DOCUMENT_FAILED;
            const auto bridge = document_bridge.lock();
            if (!bridge) return HEXLAB_ACTIVE_DOCUMENT_FAILED;
            MainFrame *target = nullptr;
            std::shared_ptr<const DocumentSnapshot> document;
            { std::lock_guard lock(bridge->mutex); target = bridge->target; document = bridge->current; }
            if (!target || !document) return HEXLAB_ACTIVE_DOCUMENT_FAILED;
            std::uint64_t open_generation = 0;
            std::optional<DocumentId> active_id;
            { std::lock_guard lock(bridge->mutex); open_generation = bridge->open_generation;
              active_id = bridge->active_id; }
            if (!document_token_matches(*document, open_generation, token) || active_id != document->id ||
                target->projects().active_document() != std::optional<DocumentId>{DocumentId{token.document_id}})
                return HEXLAB_ACTIVE_DOCUMENT_STALE;
            const auto project = target->projects().project(DocumentId{token.document_id});
            if (project && project->state &&
                (project->state->revisions.edit != token.edit_revision ||
                 project->state->revisions.bytes != token.byte_revision ||
                 project->state->revisions.decisions != token.decision_revision))
                return HEXLAB_ACTIVE_DOCUMENT_STALE;
            auto navigated = target->projects().navigate(DocumentId{token.document_id}, location);
            if (!navigated) return HEXLAB_ACTIVE_DOCUMENT_FAILED;
            target->impl_->annotation_context.reset();
            target->impl_->listing->select(navigated.value());
            target->impl_->bytes->select(navigated.value());
            target->impl_->select_context_rows(navigated.value());
            const auto image = active_document_image(*document);
            target->SetStatusText(location_text(navigated.value(), image.get()));
            return HEXLAB_ACTIVE_DOCUMENT_OK;
        };
        if (wxIsMainThread()) return perform();
        if (!wxTheApp) return HEXLAB_ACTIVE_DOCUMENT_FAILED;
        struct Completion { std::mutex mutex; std::condition_variable changed; bool done = false; std::int32_t status = HEXLAB_ACTIVE_DOCUMENT_FAILED; };
        const auto completion = std::make_shared<Completion>();
        wxTheApp->CallAfter([perform, completion] {
            const auto status = perform();
            { std::lock_guard lock(completion->mutex); completion->status = status; completion->done = true; }
            completion->changed.notify_one();
        });
        std::unique_lock lock(completion->mutex);
        if (!completion->changed.wait_until(lock, deadline, [&] { return completion->done; }))
            return HEXLAB_ACTIVE_DOCUMENT_FAILED;
        return completion->status;
    };
    auto active_document_query = active_document_services.query;
    ui.plugins->set_active_document_services(std::move(active_document_services));
    plugins::ActiveProjectBreakpointServices active_breakpoint_services;
    const auto make_active_project_token = [document_bridge](HexLabActiveProjectToken& output) -> std::int32_t {
        const auto bridge = document_bridge.lock();
        if (!bridge) return HEXLAB_ACTIVE_DOCUMENT_FAILED;
        MainFrame* target = nullptr;
        std::shared_ptr<const DocumentSnapshot> document;
        std::uint64_t open_generation = 0;
        std::optional<DocumentId> active_id;
        {
            std::lock_guard lock(bridge->mutex);
            target = bridge->target;
            document = bridge->current;
            open_generation = bridge->open_generation;
            active_id = bridge->active_id;
        }
        if (!target || !document || !document->project || !document->project->state ||
            active_id != document->id || open_generation == 0) return HEXLAB_ACTIVE_DOCUMENT_FAILED;
        const auto binding = target->ActiveSavedProjectBinding();
        if (!binding) return HEXLAB_ACTIVE_DOCUMENT_FAILED;
        output = {};
        output.struct_size = sizeof(output);
        output.document.struct_size = sizeof(output.document);
        output.document.document_id = document->id.value;
        output.document.open_generation = open_generation;
        output.document.edit_revision = document->project->state->revisions.edit;
        output.document.byte_revision = document->project->state->revisions.bytes;
        output.document.decision_revision = document->project->state->revisions.decisions;
        const auto path = binding->first.generic_u8string();
        std::uint64_t identity = 1469598103934665603ull;
        for (const auto ch : path) { identity ^= static_cast<std::uint8_t>(ch); identity *= 1099511628211ull; }
        output.project_identity = identity ? identity : 1;
        output.project_generation = binding->second ? binding->second : 1;
        return HEXLAB_ACTIVE_DOCUMENT_OK;
    };
    const auto same_project_token = [](const HexLabActiveProjectToken& a,
                                       const HexLabActiveProjectToken& b) {
        return a.document.document_id == b.document.document_id &&
            a.document.open_generation == b.document.open_generation &&
            a.document.edit_revision == b.document.edit_revision &&
            a.document.byte_revision == b.document.byte_revision &&
            a.document.decision_revision == b.document.decision_revision &&
            a.project_identity == b.project_identity && a.project_generation == b.project_generation;
    };
    active_breakpoint_services.snapshot = make_active_project_token;
    active_breakpoint_services.query = [document_bridge, make_active_project_token, same_project_token](
        const HexLabActiveProjectToken& token, std::uint64_t start, std::uint32_t capacity,
        HexLabProjectBreakpointRecord* output, std::uint32_t& written) -> std::int32_t {
        written = 0;
        HexLabActiveProjectToken current{};
        current.struct_size = sizeof(current);
        if (make_active_project_token(current) != HEXLAB_ACTIVE_DOCUMENT_OK || !same_project_token(token, current))
            return HEXLAB_ACTIVE_DOCUMENT_STALE;
        const auto bridge = document_bridge.lock();
        if (!bridge) return HEXLAB_ACTIVE_DOCUMENT_FAILED;
        std::shared_ptr<const DocumentSnapshot> document;
        { std::lock_guard lock(bridge->mutex); document = bridge->current; }
        if (!document || document->id.value != token.document.document_id || !document->project ||
            !document->project->state || !document->project->state->user || !document->project->loaded ||
            !document->project->loaded->image)
            return HEXLAB_ACTIVE_DOCUMENT_FAILED;
        const auto& rows = document->project->state->user->breakpoints;
        const auto begin = static_cast<std::size_t>(start);
        if (begin >= rows.size()) return 0;
        const auto count = std::min<std::size_t>(capacity, rows.size() - begin);
        for (std::size_t i = 0; i < count; ++i) {
            const auto& row = rows[begin + i];
            const auto& image = document->project->loaded->image;
            for (std::uint8_t byte = 0; byte < row.size; ++byte) {
                if (row.address.offset > UINT64_MAX - byte ||
                    !image->to_file_offset(Address{row.address.space, row.address.offset + byte}))
                    return HEXLAB_ACTIVE_DOCUMENT_FAILED;
            }
            auto& out = output[i];
            out = {};
            out.struct_size = sizeof(out);
            out.address_space = row.address.space.value;
            out.id = row.id;
            out.address = row.address.offset;
            out.kind = static_cast<std::uint32_t>(row.kind);
            out.enabled = row.enabled ? 1u : 0u;
            out.size = row.size;
        }
        written = static_cast<std::uint32_t>(count);
        return 0;
    };
    active_breakpoint_services.set = [document_bridge, make_active_project_token, same_project_token](
        const HexLabActiveProjectToken& token, std::uint32_t address_space, std::uint64_t address,
        std::uint32_t kind, std::uint8_t size, std::uint8_t enabled, std::uint8_t remove) -> std::int32_t {
        HexLabActiveProjectToken current{};
        current.struct_size = sizeof(current);
        if (make_active_project_token(current) != HEXLAB_ACTIVE_DOCUMENT_OK || !same_project_token(token, current))
            return HEXLAB_ACTIVE_DOCUMENT_STALE;
        const auto bridge = document_bridge.lock();
        if (!bridge) return HEXLAB_ACTIVE_DOCUMENT_FAILED;
        MainFrame* target = nullptr;
        std::shared_ptr<const DocumentSnapshot> document;
        { std::lock_guard lock(bridge->mutex); target = bridge->target; document = bridge->current; }
        if (!target) return HEXLAB_ACTIVE_DOCUMENT_FAILED;
        if (!document || document->id.value != token.document.document_id || !document->project ||
            !document->project->loaded || !document->project->loaded->image)
            return HEXLAB_ACTIVE_DOCUMENT_FAILED;
        const Address location{AddressSpaceId{address_space}, address};
        const auto image = document->project->loaded->image;
        if (!remove) for (std::uint8_t i = 0; i < size; ++i) {
            if (location.offset > UINT64_MAX - i ||
                !image->to_file_offset(Address{location.space, location.offset + i}))
                return HEXLAB_ACTIVE_DOCUMENT_INVALID;
        }
        const auto result = target->ApplyProjectCommandFor(DocumentId{token.document.document_id}, SetProjectBreakpoint{
            location, static_cast<database::ProjectBreakpointKind>(kind), size, enabled != 0, remove != 0});
        return result ? HEXLAB_ACTIVE_DOCUMENT_OK : HEXLAB_ACTIVE_DOCUMENT_FAILED;
    };
    ui.plugins->set_active_project_breakpoint_services(std::move(active_breakpoint_services));
    metadata->AddPage(ui.plugins, "Plugins");
    metadata->Bind(wxEVT_NOTEBOOK_PAGE_CHANGED, [this, metadata](wxBookCtrlEvent &event) {
        if (event.GetSelection() == metadata->FindPage(impl_->macho_objc))
            impl_->populate_macho_objc();
        event.Skip();
    });
    ui.listing->decorate_instruction = [plugins = ui.plugins](Instruction &instruction) {
        (void)plugins->apply_display_extension(instruction);
    };
    ui.plugins->extensions_changing = [this] { impl_->controller->cancel_analyses(); };
    ui.plugins->extensions_quiesce = [this] { impl_->controller->wait_for_analysis_workers(); };
    ui.plugins->extensions_changed = [this, listing = ui.listing] {
        listing->refresh_display();
        impl_->refresh_plugin_menu();
    };
    ui.plugins->extensions_operation_finished = [this](bool) {
        impl_->refresh_plugin_analysis();
    };
    ui.references->navigate = [this](DocumentId id, std::shared_ptr<const ProjectSnapshot> source_project,
                                     Location location) {
        const auto source_document = impl_->shown;
        if (!source_document || source_document->id != id || source_document->project != source_project) {
            impl_->log("Reference navigation canceled because its source snapshot changed.");
            return;
        }
        impl_->navigate_from_document(source_document, location);
    };
    docking_.AddPane(metadata, wxAuiPaneInfo()
                                   .Name("metadata")
                                   .Caption("Binary Metadata")
                                   .Right()
                                   .BestSize(FromDIP(wxSize(380, 400)))
                                   .MinSize(FromDIP(wxSize(180, 120))));
    ui.debugger = new DebuggerView(this, {}, [this] {
        return impl_->controller ? impl_->controller->state().current() : std::shared_ptr<const DocumentSnapshot>{};
    }, [this](DocumentId id, Location location) {
        auto &documents = impl_->controller->documents();
        if (documents.active_document() != id || !documents.project(id)) return;
        auto result = documents.navigate(id, location);
        if (result) impl_->sync();
        else impl_->log(text(result.error().message));
    }, [this]() -> std::optional<std::pair<DocumentId, Location>> {
        const auto id = impl_->controller->documents().active_document();
        const auto location = impl_->state().selection();
        if (!id || !location) return {};
        return std::pair{*id, *location};
    }, [this](ProjectCommand command) {
        auto result=ApplyProjectCommand(std::move(command));
        if(!result)impl_->log(text(result.error().message));
    }, [this](std::vector<database::BreakpointHitCount> counters) {
        const auto id = impl_->controller->documents().active_document();
        if (!id) return false;
        auto &documents = impl_->controller->documents();
        const auto actor = documents.actor(*id);
        if (!actor) return false;
        auto submitted = actor->persist_breakpoint_hit_counts(std::move(counters));
        if (!submitted) { impl_->log(text(submitted.error().message)); return false; }
        auto watched = documents.watch(*id, std::move(submitted));
        if (!watched) { impl_->log(text(watched.error().message)); return false; }
        return true;
    });
    ui.debugger->SetName("Debugger pane");
    ui.plugins->set_active_debugger_services(ui.debugger->active_debugger_services(std::move(active_document_query)));
    Bind(wxEVT_MENU, [this](wxCommandEvent &) {
        impl_->debugger->toggle_selection_breakpoint();
        docking_.GetPane("debugger").Show();
        docking_.Update();
    }, debugger_toggle_selection_bp_id);
    docking_.AddPane(ui.debugger, wxAuiPaneInfo()
                                      .Name("debugger")
                                      .Caption("Debugger")
                                      .Right()
                                      .Position(1)
                                      .BestSize(FromDIP(wxSize(520, 360)))
                                      .MinSize(FromDIP(wxSize(300, 180)))
                                      .Hide());
    for (auto *table : {ui.segments, ui.imports, ui.exports})
        table->SetColumnWidth(0, FromDIP(140));
    ui.imports->SetColumnWidth(1, FromDIP(110));
    ui.imports->SetColumnWidth(2, FromDIP(140));
    ui.output = new wxTextCtrl(this, wxID_ANY, "HexLab workspace ready.\n", wxDefaultPosition, wxDefaultSize,
                               wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    ui.output->SetName("Output log pane");
    docking_.AddPane(ui.output, wxAuiPaneInfo()
                                    .Name("output")
                                    .Caption("Output")
                                    .Bottom()
                                    .BestSize(FromDIP(wxSize(800, 140)))
                                    .MinSize(FromDIP(wxSize(200, 80))));
    ui.search = new SearchView(this);
    docking_.AddPane(ui.search, wxAuiPaneInfo()
                                    .Name("search")
                                    .Caption("Search Results")
                                    .Bottom()
                                    .Position(1)
                                    .BestSize(FromDIP(wxSize(800, 180)))
                                    .MinSize(FromDIP(wxSize(200, 100)))
                                    .Hide());
#ifdef HEXLAB_DESKTOP_PYTHON_CONSOLE
    ui.python_console = new PythonConsolePanel(this, [this] { return ActiveSavedProjectBinding(); });
    ui.python_console->SetName("Python automation console pane");
    docking_.AddPane(ui.python_console, wxAuiPaneInfo()
                                           .Name("python-console")
                                           .Caption("Python Console")
                                           .Bottom()
                                           .Position(1)
                                           .BestSize(FromDIP(wxSize(800, 260)))
                                           .MinSize(FromDIP(wxSize(300, 140)))
                                           .Hide());
#endif
    ui.progress = new wxGauge(GetStatusBar(), wxID_ANY, 100);
    ui.progress->Hide();
    GetStatusBar()->Bind(wxEVT_SIZE, [this](wxSizeEvent &event) {
        wxRect rect;
        GetStatusBar()->GetFieldRect(1, rect);
        impl_->progress->SetSize(rect);
        event.Skip();
    });
    ui.controller = std::make_unique<SessionController>([this] { impl_->changed(); });
    ui.controller->message = [this](DocumentId id, const wxString &message) { impl_->log_to(id, message); };
    ui.controller->recovery_candidates_ready = [this](
        std::filesystem::path failed_path, database::ProjectMode mode, Error open_error,
        Result<std::vector<database::ProjectRecoveryCandidate>> result) {
        if (!impl_ || !impl_->closer || impl_->closer->closing_window())
            return;
        wxString message = "Could not open project:\n" + wxString(failed_path.wstring()) +
                           "\n\n" + text(open_error.message);
        if (!result) {
            message += "\n\nRecovery scan failed: " + text(result.error().message);
            wxMessageBox(message, "Project open failed", wxOK | wxICON_ERROR, this);
            return;
        }
        auto &candidates = result.value();
        if (candidates.empty()) {
            message += "\n\nNo validated recovery copies were found in the same folder.";
            wxMessageBox(message, "Project open failed", wxOK | wxICON_ERROR, this);
            return;
        }
        message += "\n\nChoose a validated recovery copy to open. The selected file will be revalidated; recovery files are not changed automatically.";
        wxArrayString choices;
        choices.Alloc(candidates.size());
        for (const auto &candidate : candidates) {
            const auto kind = candidate.kind == database::RecoveryArtifactKind::interrupted_save
                                  ? wxString("Interrupted Save As")
                                  : wxString("Previous project version");
            choices.Add(kind + ": " + wxString(candidate.path.wstring()));
        }
        wxSingleChoiceDialog dialog(this, message, "Project recovery", choices);
        if (dialog.ShowModal() == wxID_OK) {
            const auto selection = dialog.GetSelection();
            if (selection >= 0 && static_cast<std::size_t>(selection) < candidates.size())
                OpenProject(candidates[static_cast<std::size_t>(selection)].path, mode);
        }
    };
    ui.controller->listing_ready = [this](DocumentId id, Location begin, const ListingPage &page) {
        if (impl_->controller->documents().active_document() == id && impl_->state().selection() == begin)
            impl_->listing->apply_page(begin, page);
    };
    ui.listing->request_page = [this](std::shared_ptr<const DocumentSnapshot> document, Location begin) {
        auto result = impl_->controller->request_listing(std::move(document), begin);
        (void)result;
    };
    ui.search->navigate = [this](DocumentId id, std::size_t index, const SearchMatch &expected) {
        auto &manager = impl_->controller->documents();
        if (manager.active_document() != id) {
            impl_->mark_active_document(id);
            impl_->controller->activate(id);
        }
        auto history = manager.search_history(id);
        if (!history)
            return;
        auto hit = history->select(index);
        if (hit && hit->offset == expected.offset && hit->address == expected.address &&
            hit->instruction_address == expected.instruction_address && hit->operand_index == expected.operand_index)
            Navigate(search_match_location(*hit));
    };
    ui.search->more = [this](DocumentId id) {
        auto result = impl_->controller->more_results(id);
        if (!result)
            impl_->log_to(id, text(result.error().message));
    };
    ui.actions = std::make_unique<ProjectActions>(*this, *ui.controller, [this] { return impl_->action_location(); });
    ui.function_filter->Bind(wxEVT_TEXT, [this](wxCommandEvent &) {
        impl_->render_candidate_rows(impl_->shown);
        impl_->select_context_rows(impl_->state().selection());
    });
    ui.symbol_filter->Bind(wxEVT_TEXT, [this](wxCommandEvent &) {
        impl_->render_symbol_filter(impl_->shown);
    });
    ui.candidates->Bind(wxEVT_LIST_COL_CLICK, [this](wxListEvent &event) {
        const int column = event.GetColumn();
        if (column < 0 || column > 3) return;
        if (impl_->candidate_sort_column == column)
            impl_->candidate_sort_ascending = !impl_->candidate_sort_ascending;
        else {
            impl_->candidate_sort_column = column;
            impl_->candidate_sort_ascending = true;
        }
        impl_->render_candidate_rows(impl_->shown);
        impl_->select_context_rows(impl_->state().selection());
    });
    ui.candidates->Bind(wxEVT_CONTEXT_MENU, [this, table = ui.candidates](wxContextMenuEvent &event) {
        const auto doc = impl_->shown;
        if (!doc || !doc->project || !doc->project->functions)
            return;

        auto position = event.GetPosition();
        long row = -1;
        if (position.x == -1 && position.y == -1) {
            const auto selected = table->selected_row();
            if (selected && *selected <= static_cast<std::size_t>(std::numeric_limits<long>::max()))
                row = static_cast<long>(*selected);
        } else {
            position = table->ScreenToClient(position);
            int flags = 0;
            row = table->HitTest(position, flags);
        }
        if (row < 0 || static_cast<std::size_t>(row) >= impl_->visible_candidate_items.size() ||
            !impl_->visible_candidate_items[static_cast<std::size_t>(row)].recovered_function)
            return;

        const auto source_index = impl_->visible_candidate_items[static_cast<std::size_t>(row)].source_index;
        if (source_index >= doc->project->functions->functions.size() ||
            !doc->project->functions->functions[source_index]) return;
        const auto entry = doc->project->functions->functions[source_index]->entry;
        table->select_row(static_cast<std::size_t>(row));
        Navigate(entry);

        wxMenu menu;
        menu.Append(rename_id, "Rename function...");
        menu.Append(comment_id, "Comment function entry...");
        menu.Append(bookmark_id, "Toggle bookmark");
        menu.AppendSeparator();
        menu.Append(function_id, "Define function here");
        menu.Append(chunks_id, "Function chunks...");
        menu.Append(suppress_id, "Toggle function suppression");
        if (position.x == -1 && position.y == -1)
            table->PopupMenu(&menu);
        else
            table->PopupMenu(&menu, position);
    });
    auto bookmark_command = [this](bool remove) {
        auto id = projects().active_document();
        auto project = id ? projects().project(*id) : nullptr;
        auto row = impl_->bookmarks->selected_row();
        if (!id || !project || !row || *row >= project->state->user->bookmarks.size())
            return;
        const auto bookmark = project->state->user->bookmarks[*row];
        if (remove) {
            auto result = impl_->controller->execute(*id, BookmarkCommand{bookmark.location, {}, true});
            if (!result)
                impl_->log_to(*id, text(result.error().message));
            return;
        }
        auto dialog = edit_dialog(this, "Rename bookmark", "Bookmark label:", text(bookmark.label), false,
                                  [location = bookmark.location](const wxString &value) -> Result<ProjectCommand> {
                                      auto encoded = value.utf8_str();
                                      return ProjectCommand{BookmarkCommand{
                                          location, std::string(encoded.data(), encoded.length()), false}};
                                  });
        if (dialog) {
            auto result = impl_->controller->execute(*id, std::move(*dialog));
            if (!result)
                impl_->log_to(*id, text(result.error().message));
        }
    };
    ui.search->more_all = [this] {
        auto result = impl_->controller->more_results_all();
        if (!result) impl_->log(text(result.error().message));
    };
    ui.bookmark_rename->Bind(wxEVT_BUTTON, [bookmark_command](wxCommandEvent &) { bookmark_command(false); });
    ui.bookmark_remove->Bind(wxEVT_BUTTON, [bookmark_command](wxCommandEvent &) { bookmark_command(true); });
    ui.closer = std::make_unique<CloseCoordinator>(*this, *ui.controller);
    ui.tabs->activate = [this](DocumentId id) {
        impl_->mark_active_document(id);
        impl_->controller->activate(id);
        if (auto selection = impl_->state().selection())
            impl_->record_navigation(*selection);
    };
    ui.tabs->close = [this](DocumentId id) { impl_->closer->request_close(id); };
    ui.tabs->close_many = [this](std::vector<DocumentId> ids) {
        impl_->closer->request_close_many(std::move(ids));
    };
    docking_.Update();
    default_layout_ = docking_.SavePerspective();
    RestoreDesktopState();
    SetStatusText("Ready");
    RestoreWorkspaceSession();
    Bind(wxEVT_SIZE, [this](wxSizeEvent &event) {
        AdaptLayout();
        if (!restoring_desktop_state_ && !IsMaximized() && !IsIconized() && GetSize().x > 0 && GetSize().y > 0)
            normal_frame_rect_ = GetRect();
        event.Skip();
    });
    Bind(wxEVT_MOVE, [this](wxMoveEvent &event) {
        if (!restoring_desktop_state_ && !IsMaximized() && !IsIconized() && GetSize().x > 0 && GetSize().y > 0)
            normal_frame_rect_ = GetRect();
        event.Skip();
    });
    Bind(wxEVT_CLOSE_WINDOW, [this](wxCloseEvent &event) {
        SaveDesktopState();
        event.Skip();
    });
    Bind(wxEVT_AUI_PANE_CLOSE, [](wxAuiManagerEvent &event) {
        auto *pane = event.GetPane();
        if (pane && pane->IsFloating() && pane->window)
            if (auto *sizer = pane->window->GetContainingSizer())
                sizer->Detach(pane->window);
        event.Skip();
    });
    Bind(wxEVT_MENU, [this](wxCommandEvent &) { Close(); }, wxID_EXIT);
    Bind(wxEVT_MENU, [this](wxCommandEvent &) { ResetLayout(); }, reset_layout_id);
    for (std::size_t i = 0; i < movable_pane_names.size(); ++i) {
        const int command_id = move_pane_id_base + static_cast<int>(i);
        Bind(wxEVT_MENU, [this, i](wxCommandEvent &) {
            if (!impl_->move_pane_to_next_display(i))
                SetStatusText("Could not move the pane to another display", 0);
        }, command_id);
        Bind(wxEVT_UPDATE_UI, [](wxUpdateUIEvent &event) {
            event.Enable(wxDisplay::GetCount() > 1);
        }, command_id);
        const int focus_command_id = focus_pane_id_base + static_cast<int>(i);
        Bind(wxEVT_MENU, [this, i](wxCommandEvent &) {
            if (!impl_->focus_pane(i))
                SetStatusText("The selected pane has no keyboard-focusable control.", 0);
        }, focus_command_id);
        Bind(wxEVT_UPDATE_UI, [this, i](wxUpdateUIEvent &event) {
            const auto &pane = docking_.GetPane(movable_pane_names[i]);
            event.Enable(pane.IsOk() && pane.window != nullptr);
        }, focus_command_id);
    }
    Bind(wxEVT_MENU, [this](wxCommandEvent &) { impl_->dock_floating_panes(); }, dock_floating_panes_id);
    Bind(wxEVT_UPDATE_UI, [this](wxUpdateUIEvent &event) {
        bool has_floating = false;
        for (const auto *name : movable_pane_names) {
            auto &pane = docking_.GetPane(name);
            has_floating = has_floating || (pane.IsOk() && pane.IsFloating());
        }
        event.Enable(has_floating);
    }, dock_floating_panes_id);
    Bind(wxEVT_MENU, [this](wxCommandEvent &) {
        auto &pane = docking_.GetPane("debugger");
        pane.Show();
        docking_.Update();
        impl_->debugger->SetFocus();
    }, debugger_panel_id);
#ifdef HEXLAB_DESKTOP_PYTHON_CONSOLE
    Bind(wxEVT_MENU, [this](wxCommandEvent &) {
        auto &pane = docking_.GetPane("python-console");
        if (!pane.IsOk()) return;
        pane.Show(!pane.IsShown());
        docking_.Update();
        if (pane.IsShown()) impl_->python_console->SetFocus();
    }, python_console_id);
#endif
    Bind(wxEVT_MENU, [this](wxCommandEvent &) { impl_->configure(); }, analysis_options_id);
    Bind(wxEVT_MENU, [this](wxCommandEvent &) { impl_->open(false); }, wxID_OPEN);
    Bind(wxEVT_MENU, [this](wxCommandEvent &) { impl_->open(true); }, open_raw_id);
    Bind(wxEVT_MENU, [this](wxCommandEvent &) { impl_->open_project(); }, open_project_id);
    Bind(wxEVT_MENU, [this](wxCommandEvent &) { impl_->apply_flirt_catalog(); }, flirt_apply_id);
    Bind(wxEVT_UPDATE_UI, [this](wxUpdateUIEvent &event) {
        const auto id = projects().active_document();
        const auto project = id ? projects().project(*id) : nullptr;
        const auto info = projects().documents();
        const auto document = id ? std::find_if(info.begin(), info.end(), [&](const auto &entry) {
            return entry.id == *id;
        }) : info.end();
        event.Enable(id && project && project->loaded && project->functions && document != info.end() &&
                     document->path && !document->readonly);
    }, flirt_apply_id);
    Bind(wxEVT_MENU, [this](wxCommandEvent &) {
        const auto id = projects().active_document();
        auto info = projects().documents();
        auto found = id ? std::find_if(info.begin(), info.end(), [&](const auto& row) { return row.id == *id; }) : info.end();
        if (found == info.end() || !found->path || !found->uuid) {
            wxMessageBox("Open a saved project before reviewing collaboration proposals.",
                         "Collaboration", wxOK | wxICON_INFORMATION, this);
            return;
        }
        const auto project_path = *found->path;
        const auto project_uuid = *found->uuid;
        CollaborationDialog dialog(this, project_path, [this, project_path, project_uuid] {
            auto synchronized = projects().synchronize_external(project_path, project_uuid);
            if (!synchronized) {
                wxMessageBox(text(synchronized.error().message), "Project refresh failed",
                             wxOK | wxICON_ERROR, this);
                return false;
            }
            return true;
        }, [this, project_path, project_uuid] {
            auto refreshed = projects().refresh_external(project_path, project_uuid);
            if (!refreshed)
                wxMessageBox(text(refreshed.error().message), "Project refresh failed",
                             wxOK | wxICON_ERROR, this);
        });
        dialog.ShowModal();
    }, collaboration_review_id);
    Bind(wxEVT_MENU, [this](wxCommandEvent &) {
        wxFileDialog picker(this, "Open ar archive", "", "", "ar archives|*.a;*.ar|All files|*.*", wxFD_OPEN | wxFD_FILE_MUST_EXIST);
        if (picker.ShowModal() != wxID_OK) return;
        const std::filesystem::path path(picker.GetPath().ToStdWstring());
        auto storage = FileStorage::open(path);
        if (!storage) { wxMessageBox(text(storage.error().message), "Archive open failed", wxOK | wxICON_ERROR, this); return; }
        auto archive = load_ar_archive(storage.value());
        if (!archive) { wxMessageBox(text(archive.error().message), "Archive parse failed", wxOK | wxICON_ERROR, this); return; }
        ArchiveView dialog(this, archive.value().archive);
        if (dialog.ShowModal() != wxID_OK) return;
        auto index = dialog.selected_member();
        if (!index || *index >= archive.value().archive.members.size()) return;
        const auto& member = archive.value().archive.members[*index];
        auto view = open_ar_member(archive.value().storage, member);
        if (!view) { wxMessageBox(text(view.error().message), "Member open failed", wxOK | wxICON_ERROR, this); return; }
        OpenRequest request;
        request.path = path;
        const auto logical_name = wxString::FromUTF8(member.name.c_str()).ToStdWstring();
        request.source_path = std::filesystem::path(path.wstring() + L"!" + logical_name);
        request.input_storage = std::move(view.value());
        request.format = Format::automatic;
        OpenDocument(std::move(request));
    }, open_archive_id);
    Bind(wxEVT_MENU, [this](wxCommandEvent &) { impl_->compare_current_to_file(); }, compare_id);
    Bind(wxEVT_MENU, [this](wxCommandEvent &) { impl_->compare_open_projects(); }, compare_open_projects_id);
    Bind(wxEVT_MENU, [this](wxCommandEvent &) {
        wxFileDialog picker(this, "Open comparison session", {}, {},
                            "HexLab comparison sessions (*.hxcmp)|*.hxcmp|All files (*.*)|*.*",
                            wxFD_OPEN | wxFD_FILE_MUST_EXIST);
        if (picker.ShowModal() != wxID_OK) return;
        const auto path = std::filesystem::path(picker.GetPath().ToStdWstring());
        auto loaded = load_compare_session(path);
        if (!loaded) {
            wxMessageBox(text(loaded.error().message), "Could not open comparison session", wxOK | wxICON_ERROR, this);
            return;
        }
        auto session = std::move(loaded.value());
        auto *view = new CompareView(this, std::move(session.report), wxString::FromUTF8(session.old_name),
            wxString::FromUTF8(session.new_name), std::move(session.functions), {}, {},
            std::move(session.function_body_diffs));
        view->Show();
    }, open_compare_session_id);
    Bind(wxEVT_MENU, [this](wxCommandEvent &) { impl_->cancel_compare(); }, compare_cancel_id);
    Bind(wxEVT_MENU, [this](wxCommandEvent &) {
        auto &pane = docking_.GetPane("metadata");
        pane.Show();
        if (auto *notebook = dynamic_cast<wxNotebook *>(impl_->type_symbols->GetParent()))
            notebook->SetSelection(notebook->FindPage(impl_->type_symbols));
        docking_.Update();
    }, type_symbols_id);
    Bind(wxEVT_MENU, [this](wxCommandEvent &) {
        auto &pane = docking_.GetPane("metadata");
        pane.Show();
        if (auto *notebook = dynamic_cast<wxNotebook *>(impl_->plugins->GetParent()))
            notebook->SetSelection(notebook->FindPage(impl_->plugins));
        docking_.Update();
    }, plugins_panel_id);
    Bind(wxEVT_MENU, [this](wxCommandEvent &) {
        if (impl_->pages && impl_->pseudocode) {
            impl_->pages->SetSelection(impl_->pages->FindPage(impl_->pseudocode));
            impl_->sync();
        }
    }, pseudocode_id);
    Bind(wxEVT_MENU, [this](wxCommandEvent &) {
        impl_->controller->cancel();
        impl_->cancel_compare();
        impl_->cancel_flirt();
    }, cancel_id);
    const int navigation_ids[] = {
        wxID_OPEN, open_raw_id, open_project_id, analysis_options_id, wxID_CLOSE,    cancel_id,    jump_id,
        follow_id, back_id,     forward_id,      browse_navigation_history_id, previous_marker_id, next_marker_id,
        copy_address_id, copy_bytes_id, copy_text_id, next_page_id, incoming_references_id, outgoing_references_id};
    for (int id : navigation_ids)
        Bind(wxEVT_UPDATE_UI, [this](wxUpdateUIEvent &event) { impl_->update_navigation(event); }, id);
    Bind(wxEVT_MENU, [this](wxCommandEvent &) { impl_->jump(); }, jump_id);
    Bind(wxEVT_MENU, [this](wxCommandEvent &) { impl_->follow(); }, follow_id);
    Bind(wxEVT_MENU, [this](wxCommandEvent &) { impl_->browse_references(true); }, incoming_references_id);
    Bind(wxEVT_MENU, [this](wxCommandEvent &) { impl_->browse_references(false); }, outgoing_references_id);
    Bind(
        wxEVT_MENU,
        [this](wxCommandEvent &) {
            if (!impl_->navigate_history(false))
                SetStatusText("No previous address in navigation history.");
        },
        back_id);
    Bind(
        wxEVT_MENU,
        [this](wxCommandEvent &) {
            if (!impl_->navigate_history(true))
                SetStatusText("No next address in navigation history.");
        },
        forward_id);
    Bind(wxEVT_MENU, [this](wxCommandEvent &) { impl_->browse_navigation_history(); },
         browse_navigation_history_id);
    Bind(wxEVT_MENU, [this](wxCommandEvent &event) {
        impl_->navigate_marker(event.GetId() == next_marker_id);
    }, previous_marker_id);
    Bind(wxEVT_MENU, [this](wxCommandEvent &event) {
        impl_->navigate_marker(event.GetId() == next_marker_id);
    }, next_marker_id);
    Bind(
        wxEVT_MENU,
        [this](wxCommandEvent &) {
            if (auto next = impl_->listing->page().next)
                Navigate(*next);
        },
        next_page_id);
    for (int command : {copy_address_id, copy_bytes_id, copy_text_id})
        Bind(wxEVT_MENU, [this, command](wxCommandEvent &) { impl_->copy(command); }, command);
    Bind(
        wxEVT_MENU,
        [this](wxCommandEvent &) {
            wxAboutDialogInfo info;
            info.SetName("HexLab");
            info.SetVersion(text(build_version()));
            info.SetDescription(wxString("C++ binary analysis workspace\n") + wxVERSION_STRING);
            wxAboutBox(info, this);
        },
        wxID_ABOUT);
    Bind(wxEVT_MENU, [this](wxCommandEvent &event) {
        const auto found = impl_->plugin_menu_invocations.find(event.GetId());
        if (found == impl_->plugin_menu_invocations.end()) {
            event.Skip();
            return;
        }
        const auto invocation = found->second;
        if (impl_->plugins)
            impl_->plugins->invoke_menu_action(invocation.plugin_id, invocation.action_id, invocation.label);
    });
}
MainFrame::~MainFrame() {
    if (impl_ && impl_->active_document_bridge) {
        std::lock_guard lock(impl_->active_document_bridge->mutex);
        impl_->active_document_bridge->target = nullptr;
        impl_->active_document_bridge->current.reset();
    }
    impl_->stop_compare();
    impl_->closer.reset();
    impl_->actions.reset();
    impl_->controller.reset();
    docking_.UnInit();
    DestroyChildren();
    impl_.reset();
}
void MainFrame::AdaptLayout() {
    const bool compact = GetClientSize().x < FromDIP(1050);
    if (compact == impl_->compact)
        return;
    impl_->compact = compact;
    auto &metadata = docking_.GetPane("metadata");
    if (!metadata.IsOk() || metadata.IsFloating())
        return;
    auto &output = docking_.GetPane("output");
    if (compact) {
        const bool macho = impl_->shown && impl_->shown->metadata_view().macho.has_value();
        metadata.Bottom()
            .Row(0)
            .Position(0)
            .BestSize(FromDIP(wxSize(400, macho ? 220 : 120)))
            .MinSize(FromDIP(wxSize(250, macho ? 220 : 100)));
        if (output.IsDocked())
            output.Row(0).Position(1).BestSize(FromDIP(wxSize(300, 120)));
    } else {
        metadata.Right().Row(0).Position(0).BestSize(FromDIP(wxSize(380, 400))).MinSize(FromDIP(wxSize(250, 100)));
        if (output.IsDocked())
            output.Row(0).Position(0).BestSize(FromDIP(wxSize(800, 140)));
    }
    docking_.Update();
}
void MainFrame::ResetLayout() {
    docking_.LoadPerspective(default_layout_, true);
    impl_->compact = false;
    AdaptLayout();
}
void MainFrame::RestoreDesktopState() {
    restoring_desktop_state_ = true;
    normal_frame_rect_ = GetRect();
    auto *config = wxConfigBase::Get();
    if (config) {
        const auto previous_path = config->GetPath();
        config->SetPath("/Desktop");
        long x = 0, y = 0, width = 0, height = 0, maximized = 0;
        const bool have_geometry = config->Read("FrameX", &x) && config->Read("FrameY", &y) &&
            config->Read("FrameWidth", &width) && config->Read("FrameHeight", &height) &&
            width >= 640 && height >= 400 && width <= 16384 && height <= 16384;
        if (have_geometry) {
            const wxRect saved(static_cast<int>(x), static_cast<int>(y),
                               static_cast<int>(width), static_cast<int>(height));
            if (const auto fitted = fit_frame_rect_to_display(saved)) {
                SetSize(*fitted);
                normal_frame_rect_ = *fitted;
            }
        }
        wxString perspective;
        if (config->Read("AuiPerspective", &perspective) && !perspective.empty() && perspective.length() <= 65536) {
            if (!docking_.LoadPerspective(perspective, false))
                docking_.LoadPerspective(default_layout_, false);
        }
        const bool restore_maximized = config->Read("FrameMaximized", &maximized) && maximized != 0;
        config->SetPath(previous_path);
        docking_.Update();
        AdaptLayout();
        if (restore_maximized) Maximize(true);
    }
    restoring_desktop_state_ = false;
    if (!IsMaximized() && !IsIconized() && GetSize().x > 0 && GetSize().y > 0)
        normal_frame_rect_ = GetRect();
}
void MainFrame::RestoreWorkspaceSession() {
    auto *config = wxConfigBase::Get(false);
    if (!config) return;
    const auto previous_path = config->GetPath();
    config->SetPath("/Desktop/Session");
    long count = 0, active = -1;
    if (!config->Read("Count", &count) || count < 0 || count > maximum_restored_documents) count = 0;
    config->Read("Active", &active);
    std::vector<DocumentId> restored_documents;
    restored_documents.reserve(static_cast<std::size_t>(count));
    std::optional<DocumentId> restored_active;
    std::optional<Location> restored_location;
    std::size_t skipped = 0;
    for (long index = 0; index < count; ++index) {
        wxString saved, kind, mode;
        const auto path_key = wxString::Format("Document%ldPath", index);
        const auto kind_key = wxString::Format("Document%ldKind", index);
        const auto mode_key = wxString::Format("Document%ldMode", index);
        if (!config->Read(path_key, &saved) || !config->Read(kind_key, &kind) || saved.empty() ||
            saved.length() > maximum_persisted_path_characters) {
            ++skipped;
            continue;
        }
        const std::filesystem::path path(saved.ToStdWstring());
        std::error_code error;
        if (!std::filesystem::is_regular_file(path, error) || error) {
            ++skipped;
            continue;
        }
        if (kind == "project") {
            // Opening failures are reported by the regular asynchronous open path.
            config->Read(mode_key, &mode);
            const auto project_mode = mode == "readonly" ? database::ProjectMode::read_only
                                      : mode == "collaborative" ? database::ProjectMode::collaborative
                                                                  : database::ProjectMode::read_write;
            OpenProject(path, project_mode);
        } else if (kind == "binary") {
            wxString recipe_text;
            const auto recipe_key = wxString::Format("Document%ldRecipe", index);
            if (!config->Read(recipe_key, &recipe_text) || recipe_text.empty() ||
                recipe_text.length() > maximum_persisted_recipe_bytes * 2) {
                ++skipped;
                continue;
            }
            const auto utf8 = recipe_text.utf8_str();
            auto bytes = decode_recipe_hex(std::string_view(utf8.data(), utf8.length()));
            if (!bytes) {
                ++skipped;
                continue;
            }
            auto recipe = decode_recipe(*bytes);
            if (!recipe || recipe.value().plugin) {
                ++skipped;
                continue;
            }
            OpenRequest request;
            request.path = path;
            request.format = recipe.value().format;
            request.raw = recipe.value().raw;
            request.macho = recipe.value().macho;
            request.pdb_path = recipe.value().pdb_path;
            request.pe_runtime_architecture = recipe.value().pe_runtime_architecture;
            OpenDocument(std::move(request));
        } else {
            ++skipped;
            continue;
        }
        const auto documents = projects().documents();
        if (!documents.empty()) {
            restored_documents.push_back(documents.back().id);
            if (index == active) {
                restored_active = documents.back().id;
                wxString location_kind, space_text, offset_text;
                if (config->Read(wxString::Format("Document%ldLocationKind", index), &location_kind) &&
                    config->Read(wxString::Format("Document%ldLocationSpace", index), &space_text) &&
                    config->Read(wxString::Format("Document%ldLocationOffset", index), &offset_text)) {
                    const auto space = decode_session_integer(space_text);
                    const auto offset = decode_session_integer(offset_text);
                    if (offset && location_kind == "file")
                        restored_location = Location{FileOffset{*offset}};
                    else if (space && *space <= UINT32_MAX && offset && location_kind == "address")
                        restored_location = Location{Address{AddressSpaceId{static_cast<std::uint32_t>(*space)},
                                                             *offset}};
                }
            }
        }
    }
    impl_->session_restore_documents = std::move(restored_documents);
    impl_->session_restore_active = restored_active;
    impl_->session_restore_location = std::move(restored_location);
    impl_->session_restore_activation_pending = !impl_->session_restore_documents.empty();
    config->SetPath(previous_path);
    if (skipped)
        SetStatusText(wxString::Format("Skipped %llu missing, unreadable, or unsupported saved session item(s)",
                                       static_cast<unsigned long long>(skipped)), 0);
}
void MainFrame::SaveWorkspaceSession() {
    auto *config = wxConfigBase::Get(false);
    if (!config) return;
    const auto documents = projects().documents();
    struct SavedEntry {
        std::filesystem::path path;
        wxString kind;
        wxString mode;
        wxString recipe;
        std::optional<Location> location;
    };
    std::vector<SavedEntry> entries;
    entries.reserve(std::min<std::size_t>(documents.size(), maximum_restored_documents));
    long active = -1;
    const auto active_id = projects().active_document();
    for (const auto &document : documents) {
        if (!document.uuid || entries.size() == maximum_restored_documents) continue;
        auto project = projects().project(document.id);
        if (!project || !project->state) continue;
        SavedEntry entry;
        if (document.path && !document.path->empty()) {
            entry.path = *document.path;
            entry.kind = "project";
            entry.mode = project->mode == database::ProjectMode::read_only ? "readonly"
                         : project->mode == database::ProjectMode::collaborative ? "collaborative"
                                                                                : "readwrite";
        } else if (project->state->provenance && !project->state->provenance->native_path.empty()) {
            entry.path = project->state->provenance->native_path;
            entry.kind = "binary";
            entry.mode = "readwrite";
            auto encoded = encode_recipe(project->state->recipe);
            if (!encoded || encoded.value().size() > maximum_persisted_recipe_bytes ||
                project->state->recipe.plugin)
                continue;
            const auto recipe_hex = encode_recipe_hex(encoded.value());
            entry.recipe = wxString::FromUTF8(recipe_hex.data(), recipe_hex.size());
        } else {
            continue;
        }
        if (entry.path.native().size() > maximum_persisted_path_characters) continue;
        if (active_id && document.id == *active_id) active = static_cast<long>(entries.size());
        if (active_id && document.id == *active_id && projects().active_document() == active_id) {
            if (const auto selected = impl_->state().selection()) entry.location = *selected;
        }
        entries.push_back(std::move(entry));
    }
    const auto previous_path = config->GetPath();
    config->SetPath("/Desktop/Session");
    config->Write("Count", static_cast<long>(entries.size()));
    config->Write("Active", active);
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const auto number = static_cast<long>(index);
        config->Write(wxString::Format("Document%ldPath", number), wxString(entries[index].path.wstring()));
        config->Write(wxString::Format("Document%ldKind", number), entries[index].kind);
        config->Write(wxString::Format("Document%ldMode", number), entries[index].mode);
        config->DeleteEntry(wxString::Format("Document%ldLocationKind", number));
        config->DeleteEntry(wxString::Format("Document%ldLocationSpace", number));
        config->DeleteEntry(wxString::Format("Document%ldLocationOffset", number));
        if (!entries[index].recipe.empty())
            config->Write(wxString::Format("Document%ldRecipe", number), entries[index].recipe);
        if (entries[index].location) {
            if (const auto *address = std::get_if<Address>(&*entries[index].location)) {
                config->Write(wxString::Format("Document%ldLocationKind", number), "address");
                config->Write(wxString::Format("Document%ldLocationSpace", number),
                              wxString::FromUTF8(encode_session_integer(address->space.value)));
                config->Write(wxString::Format("Document%ldLocationOffset", number),
                              wxString::FromUTF8(encode_session_integer(address->offset)));
            } else {
                config->Write(wxString::Format("Document%ldLocationKind", number), "file");
                config->Write(wxString::Format("Document%ldLocationSpace", number), "0");
                config->Write(wxString::Format("Document%ldLocationOffset", number),
                              wxString::FromUTF8(encode_session_integer(std::get<FileOffset>(*entries[index].location).value)));
            }
        }
    }
    config->SetPath(previous_path);
    config->Flush();
}
void MainFrame::SaveDesktopState() {
    auto *config = wxConfigBase::Get(false);
    if (!config) return;
    SaveWorkspaceSession();
    auto normal_rect = normal_frame_rect_;
    if (!IsMaximized() && !IsIconized() && GetSize().x > 0 && GetSize().y > 0)
        normal_rect = GetRect();
    if (normal_rect.width < 640 || normal_rect.height < 400) return;
    const auto perspective = docking_.SavePerspective();
    const auto previous_path = config->GetPath();
    config->SetPath("/Desktop");
    config->Write("FrameX", static_cast<long>(normal_rect.x));
    config->Write("FrameY", static_cast<long>(normal_rect.y));
    config->Write("FrameWidth", static_cast<long>(normal_rect.width));
    config->Write("FrameHeight", static_cast<long>(normal_rect.height));
    config->Write("FrameMaximized", IsMaximized());
    if (perspective.length() <= 65536)
        config->Write("AuiPerspective", perspective);
    config->SetPath(previous_path);
    config->Flush();
}
void MainFrame::OpenDocument(OpenRequest request) {
    if (impl_->closer->closing_window())
        return;
    request.analysis_options = impl_->plugins->analysis_options(std::move(request.analysis_options));
    impl_->controller->open(std::move(request));
}
void MainFrame::OpenProject(std::filesystem::path path, database::ProjectMode mode) {
    if (impl_->closer->closing_window())
        return;
    impl_->controller->open_project(std::move(path), mode, impl_->plugins->analysis_options(impl_->options));
}
void MainFrame::ActivateDocument(DocumentId id) {
    impl_->mark_active_document(id);
    impl_->controller->activate(id);
}
void MainFrame::CloseAllDocuments() {
    impl_->closer->cancel_pending();
    impl_->controller->close_all();
}
DocumentManager &MainFrame::projects() { return impl_->controller->documents(); }
Result<ProjectOperationId> MainFrame::ApplyProjectCommand(ProjectCommand command) {
    if (impl_->closer->closing_window())
        return Error{ErrorCode::busy, "The window is closing"};
    if (auto id = projects().active_document())
        return impl_->controller->execute(*id, std::move(command));
    return Error{ErrorCode::invalid_argument, "Open a project first"};
}
Result<ProjectOperationId> MainFrame::ApplyProjectCommandFor(DocumentId id, ProjectCommand command) {
    if (impl_->closer->closing_window())
        return Error{ErrorCode::busy, "The window is closing"};
    if (projects().active_document() != id)
        return Error{ErrorCode::invalid_argument, "The active project changed"};
    return impl_->controller->execute(id, std::move(command));
}
Result<ProjectOperationId> MainFrame::SaveProjectAs(std::filesystem::path path, bool replace) {
    if (impl_->closer->closing_window())
        return Error{ErrorCode::busy, "The window is closing"};
    if (auto id = projects().active_document())
        return impl_->controller->save_as(*id, std::move(path), replace);
    return Error{ErrorCode::invalid_argument, "Open a project first"};
}
Result<ProjectOperationId> MainFrame::ExportBinary(std::filesystem::path path, bool replace) {
    if (impl_->closer->closing_window())
        return Error{ErrorCode::busy, "The window is closing"};
    if (auto id = projects().active_document())
        return impl_->controller->export_binary(*id, std::move(path), replace);
    return Error{ErrorCode::invalid_argument, "Open a project first"};
}
Result<bool> MainFrame::Find(SearchQuery query, const SearchLimits &limits, bool all_documents) {
    if (impl_->closer->closing_window())
        return Error{ErrorCode::busy, "The window is closing"};
    if (auto id = projects().active_document()) {
        impl_->controller->set_all_search_scope(all_documents);
        auto result = all_documents ? impl_->controller->find_all(std::move(query), limits)
                                    : impl_->controller->find(*id, std::move(query), limits);
        if (result) {
            docking_.GetPane("search").Show();
            docking_.Update();
        }
        return result;
    }
    return Error{ErrorCode::invalid_argument, "Open a project first"};
}
bool MainFrame::FindPending() const {
    if (impl_->controller->all_search_scope())
        return impl_->controller->all_search_pending();
    auto id = impl_->controller->documents().active_document();
    return id && impl_->controller->search_pending(*id);
}
void MainFrame::Navigate(Location location) {
    impl_->annotation_context.reset();
    std::optional<Impl::NavigationEntry> previous;
    if (!impl_->restoring_navigation)
        if (auto selected = impl_->state().selection())
            previous = impl_->current_navigation(*selected);
    auto result = impl_->state().navigate(location);
    if (result) {
        if (previous)
            impl_->record_navigation_entry(std::move(*previous));
        impl_->record_navigation(result.value());
        impl_->sync();
    } else
        impl_->log(text(result.error().message));
}
const Workspace &MainFrame::documents() const { return impl_->state(); }
std::optional<std::pair<std::filesystem::path, std::uint64_t>> MainFrame::ActiveSavedProjectBinding() {
    const auto active = projects().active_document();
    if (!active) return {};
    const auto snapshot = projects().project(*active);
    if (!snapshot || !snapshot->state) return {};
    for (const auto &document : projects().documents()) {
        if (document.id != *active || !document.path || document.save_state != DocumentSaveState::saved)
            continue;
        std::uint64_t generation = 1469598103934665603ull;
        const auto mix = [&generation](std::uint64_t value) {
            for (unsigned i = 0; i < 8; ++i) {
                generation ^= static_cast<std::uint8_t>(value >> (i * 8));
                generation *= 1099511628211ull;
            }
        };
        mix(snapshot->state->revisions.edit);
        mix(snapshot->state->revisions.bytes);
        mix(snapshot->state->revisions.decisions);
        if (snapshot->functions) {
            mix(snapshot->functions->functions.size());
            mix(snapshot->functions->blocks.size());
            mix(snapshot->functions->instructions.size());
            if (snapshot->functions->key) {
                for (const auto byte : snapshot->functions->key->input.sha256) {
                    generation ^= std::to_integer<std::uint8_t>(byte);
                    generation *= 1099511628211ull;
                }
                for (const auto byte : snapshot->functions->key->recipe_fingerprint) {
                    generation ^= std::to_integer<std::uint8_t>(byte);
                    generation *= 1099511628211ull;
                }
                for (const auto byte : snapshot->functions->key->engine_fingerprint) {
                    generation ^= std::to_integer<std::uint8_t>(byte);
                    generation *= 1099511628211ull;
                }
            }
        }
        return std::pair{*document.path, generation};
    }
    return {};
}
} // namespace hexlab::desktop

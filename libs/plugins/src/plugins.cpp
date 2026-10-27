#include "hexlab/plugins/plugins.hpp"
#include "scalar_ir.hpp"
#include "hexlab/automation/api.hpp"
#include "hexlab/debugger/debugger.hpp"
#include "hexlab/processors/format.hpp"
#include "hexlab/types/header_import.hpp"
#include "hexlab/types/types.hpp"

#include <algorithm>
#include <atomic>
#include <array>
#include <charconv>
#include <cctype>
#include <fstream>
#include <limits>
#include <cstring>
#include <map>
#include <utility>
#include <filesystem>
#include <string_view>
#include <unordered_set>
#include <unordered_map>
#include <mutex>
#include <shared_mutex>
#include <memory>
#include <atomic>

namespace hexlab::plugins {
namespace {
Error invalid(std::string message) { return {ErrorCode::invalid_argument, std::move(message)}; }
constexpr std::uint32_t max_capabilities = 256;
constexpr std::size_t max_string_length = 1024;
constexpr std::size_t max_actions = 256;
constexpr std::size_t max_extensions = 128;
constexpr std::size_t max_manifest_bytes = 64 * 1024;
constexpr std::size_t max_manifest_capabilities = 256;
constexpr std::array<HexLabCapability, 17> host_capabilities{{
    {sizeof(HexLabCapability), 1, HEXLAB_PLUGIN_ABI_MINOR, 0, "hexlab.host"},
    {sizeof(HexLabCapability), 1, 0, 0, "project.api"},
    {sizeof(HexLabCapability), 1, 2, 0, "project.queries"},
    {sizeof(HexLabCapability), 1, 5, 0, "project.edits"},
    {sizeof(HexLabCapability), 1, 11, 0, "project.read"},
    {sizeof(HexLabCapability), 1, 14, 0, "project.types"},
    {sizeof(HexLabCapability), 1, 8, 0, "debugger.api"},
    {sizeof(HexLabCapability), 1, 19, 0, "debugger.rules"},
    {sizeof(HexLabCapability), 1, 10, 0, "loader.image"},
    {sizeof(HexLabCapability), 1, 7, 0, "processor.semantic.v2"},
    {sizeof(HexLabCapability), 1, 16, 0, "processor.semantic.v3"},
    {sizeof(HexLabCapability), 1, 24, 0, "processor.ir.scalar"},
    {sizeof(HexLabCapability), 1, 9, 0, "analysis.provider"},
    {sizeof(HexLabCapability), 1, 15, 0, "document.active"},
    {sizeof(HexLabCapability), 1, 17, 0, "debugger.active"},
    {sizeof(HexLabCapability), 1, 18, 0, "project.breakpoint.active"},
    {sizeof(HexLabCapability), 1, 21, 0, "project.cfg"},
}};

struct ActiveDocumentServicesState {
    std::mutex mutex;
    ActiveDocumentServices services;
};
struct ActiveDebuggerServicesState {
    std::mutex mutex;
    ActiveDebuggerServices services;
};
struct ActiveProjectBreakpointServicesState {
    std::mutex mutex;
    ActiveProjectBreakpointServices services;
};

struct RegisteredAction {
    std::string id;
    std::string label;
    std::string menu_path;
    void* context = nullptr;
    void (*invoke)(void*) = nullptr;
};
struct HostContext {
    struct DebuggerSession {
        explicit DebuggerSession(std::unique_ptr<debugger::Backend> backend)
            : value(std::make_unique<debugger::DebugSession>(std::move(backend))) {}
        std::unique_ptr<debugger::DebugSession> value;
        std::shared_mutex operations;
        std::atomic_bool closing{false};
    };
    struct Loader {
        std::string id, format_id;
        void* extension_context = nullptr;
        int32_t (*probe)(void*, const uint8_t*, uint32_t, uint64_t, uint32_t*) = nullptr;
        HexLabLoadImage load_image = nullptr;
        std::uint32_t image_api_version = 0;
        bool disabled = false;
        std::string failure_reason;
    };
    struct Processor {
        std::string id, architecture_id, mode_id;
        void* extension_context = nullptr;
        int32_t (*decode)(void*, uint64_t, const uint8_t*, uint32_t, HexLabDecodedInstruction*) = nullptr;
        HexLabProcessorSemanticDecode decode_semantic = nullptr;
        HexLabProcessorSemanticDecodeV2 decode_semantic_v2 = nullptr;
        HexLabProcessorSemanticDecodeV3 decode_semantic_v3 = nullptr;
        HexLabProcessorDecodeIR decode_ir = nullptr;
        bool disabled = false;
        std::string failure_reason;
    };
    struct AnalysisProvider {
        std::string id, name;
        void* context = nullptr;
        int32_t (*analyze)(void*, const HexLabProjectApi*, const char*, char*, uint32_t) = nullptr;
    };
    std::mutex mutex;
    std::string plugin_id;
    bool accepting_extensions = false;
    std::vector<RegisteredAction> actions;
    std::vector<Loader> loaders;
    std::vector<Processor> processors;
    std::vector<AnalysisProvider> analysis_providers;
    std::unordered_set<void*> projects;
    std::unordered_map<void*, std::shared_ptr<DebuggerSession>> debugger_sessions;
    HexLabProjectApi project_api{};
    HexLabDebuggerApi debugger_api{};
    std::shared_ptr<ActiveDocumentServicesState> active_document_services;
    HexLabActiveDocumentApi active_document_api{};
    std::shared_ptr<ActiveDebuggerServicesState> active_debugger_services;
    HexLabActiveDebuggerApi active_debugger_api{};
    std::shared_ptr<ActiveProjectBreakpointServicesState> active_project_breakpoint_services;
    HexLabActiveProjectBreakpointApi active_project_breakpoint_api{};
};

void close_debugger_sessions(HostContext& host) noexcept {
    std::unordered_map<void*, std::shared_ptr<HostContext::DebuggerSession>> sessions;
    {
        std::lock_guard lock(host.mutex);
        for (auto& [handle, entry] : host.debugger_sessions) {
            (void)handle;
            if (entry) entry->closing.store(true, std::memory_order_release);
        }
        sessions.swap(host.debugger_sessions);
    }
    for (auto& [handle, entry] : sessions) {
        (void)handle;
        if (!entry) continue;
        std::unique_lock lock(entry->operations);
        entry->value.reset();
    }
}

bool copy_string(const char* source, std::string& destination) {
    if (!source) return false;
    std::size_t length = 0;
    while (length < max_string_length && source[length] != '\0') ++length;
    if (length == 0 || length == max_string_length) return false;
    destination.assign(source, length);
    return true;
}
bool valid_menu_path(const std::string& path) {
    if (path.empty() || path.size() > 256 || path.front() == '/' || path.back() == '/') return false;
    std::size_t component_start = 0;
    unsigned component_count = 0;
    for (std::size_t i = 0; i <= path.size(); ++i) {
        if (i < path.size() && path[i] != '/') {
            const auto c = static_cast<unsigned char>(path[i]);
            if (c < 0x20 || c == 0x7f) return false;
            continue;
        }
        const auto length = i - component_start;
        if (!length || length > 64 || ++component_count > 8) return false;
        const auto component = std::string_view(path).substr(component_start, length);
        if (component == "." || component == "..") return false;
        component_start = i + 1;
    }
    return true;
}
bool copy_fixed_string(const char* source, std::size_t capacity, std::string& destination) {
    if (!source || capacity == 0) return false;
    std::size_t length = 0;
    while (length < capacity && source[length] != '\0') ++length;
    if (length == 0 || length == capacity) return false;
    destination.assign(source, length);
    return true;
}
bool copy_user_text(const char* source, std::size_t maximum, std::string& destination) {
    if (!source) return false;
    std::size_t length = 0;
    while (length <= maximum && source[length] != '\0') ++length;
    if (length > maximum) return false;
    destination.assign(source, length);
    return true;
}
std::string_view trim_ascii(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t' || text.front() == '\r'))
        text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r'))
        text.remove_suffix(1);
    return text;
}
bool valid_manifest_text(std::string_view text, bool allow_unicode) {
    for (std::size_t i = 0; i < text.size();) {
        const auto first = static_cast<unsigned char>(text[i]);
        if (first < 0x80) {
            if (first < 0x20 || first == 0x7f) return false;
            ++i;
            continue;
        }
        if (!allow_unicode) return false;
        std::size_t count = 0;
        std::uint32_t codepoint = 0;
        if ((first & 0xe0u) == 0xc0u) { count = 2; codepoint = first & 0x1fu; }
        else if ((first & 0xf0u) == 0xe0u) { count = 3; codepoint = first & 0x0fu; }
        else if ((first & 0xf8u) == 0xf0u) { count = 4; codepoint = first & 0x07u; }
        else return false;
        if (i + count > text.size()) return false;
        for (std::size_t j = 1; j < count; ++j) {
            const auto continuation = static_cast<unsigned char>(text[i + j]);
            if ((continuation & 0xc0u) != 0x80u) return false;
            codepoint = (codepoint << 6) | (continuation & 0x3fu);
        }
        if ((count == 2 && codepoint < 0x80u) || (count == 3 && codepoint < 0x800u) ||
            (count == 4 && codepoint < 0x10000u) || codepoint > 0x10ffffu ||
            (codepoint >= 0xd800u && codepoint <= 0xdfffu)) return false;
        i += count;
    }
    return true;
}
bool valid_manifest_id(std::string_view id) {
    return !id.empty() && id.size() <= 128 &&
        std::all_of(id.begin(), id.end(), [](unsigned char ch) {
            return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                   (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-';
        });
}
bool parse_manifest_u32(std::string_view text, std::uint32_t& result) {
    if (text.empty()) return false;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}
Result<PluginCandidate::Manifest> parse_plugin_manifest(std::string_view bytes) {
    PluginCandidate::Manifest manifest;
    bool have_format = false, have_id = false, have_name = false, have_version = false;
    std::unordered_set<std::string> capability_ids;
    std::unordered_set<std::string> required_capability_ids;
    std::size_t line_number = 0;
    while (!bytes.empty()) {
        ++line_number;
        const auto newline = bytes.find('\n');
        auto line = trim_ascii(bytes.substr(0, newline));
        bytes = newline == std::string_view::npos ? std::string_view{} : bytes.substr(newline + 1);
        if (line.empty() || line.front() == '#') continue;
        const auto equals = line.find('=');
        if (equals == std::string_view::npos)
            return invalid("plugin manifest line " + std::to_string(line_number) + " has no '='");
        const auto key = trim_ascii(line.substr(0, equals));
        const auto value = trim_ascii(line.substr(equals + 1));
        if (value.empty() || value.size() > 4096 || !valid_manifest_text(value, key == "name"))
            return invalid("plugin manifest line " + std::to_string(line_number) + " has invalid text");
        if (key == "format") {
            if (have_format || value != "hexlab-plugin-v1") return invalid("plugin manifest format is invalid");
            have_format = true;
        } else if (key == "id") {
            if (have_id || !valid_manifest_id(value)) return invalid("plugin manifest ID is invalid or repeated");
            manifest.id.assign(value); have_id = true;
        } else if (key == "name") {
            if (have_name || value.size() > 256) return invalid("plugin manifest name is invalid or repeated");
            manifest.name.assign(value); have_name = true;
        } else if (key == "version") {
            if (have_version || value.size() > 64 || !valid_manifest_text(value, false))
                return invalid("plugin manifest version is invalid or repeated");
            manifest.version.assign(value); have_version = true;
        } else if (key == "capability") {
            if (manifest.capabilities.size() >= max_manifest_capabilities)
                return Error{ErrorCode::resource_limit, "plugin manifest capability limit exceeded"};
            const auto first = value.find(',');
            const auto second = first == std::string_view::npos ? first : value.find(',', first + 1);
            const auto third = second == std::string_view::npos ? second : value.find(',', second + 1);
            if (first == std::string_view::npos || second == std::string_view::npos || third == std::string_view::npos ||
                value.find(',', third + 1) != std::string_view::npos)
                return invalid("plugin manifest capability must have id,major,minor,flags");
            const auto capability_id = value.substr(0, first);
            PluginInfo::VersionedCapability capability;
            if (!valid_manifest_id(capability_id) || !parse_manifest_u32(value.substr(first + 1, second - first - 1), capability.major_version) ||
                !parse_manifest_u32(value.substr(second + 1, third - second - 1), capability.minor_version) ||
                !parse_manifest_u32(value.substr(third + 1), capability.flags) || capability.major_version == 0 ||
                !capability_ids.emplace(capability_id).second)
                return invalid("plugin manifest capability is invalid or repeated");
            capability.id.assign(capability_id);
            manifest.capabilities.push_back(std::move(capability));
        } else if (key == "requires") {
            if (manifest.required_capabilities.size() >= max_manifest_capabilities)
                return Error{ErrorCode::resource_limit, "plugin manifest requirement limit exceeded"};
            const auto first = value.find(',');
            const auto second = first == std::string_view::npos ? first : value.find(',', first + 1);
            if (first == std::string_view::npos || second == std::string_view::npos ||
                value.find(',', second + 1) != std::string_view::npos)
                return invalid("plugin manifest requirement must have id,major,minor");
            const auto requirement_id = value.substr(0, first);
            PluginInfo::VersionedCapability requirement;
            if (!valid_manifest_id(requirement_id) ||
                !parse_manifest_u32(value.substr(first + 1, second - first - 1), requirement.major_version) ||
                !parse_manifest_u32(value.substr(second + 1), requirement.minor_version) ||
                requirement.major_version == 0 || !required_capability_ids.emplace(requirement_id).second)
                return invalid("plugin manifest requirement is invalid or repeated");
            requirement.id.assign(requirement_id);
            manifest.required_capabilities.push_back(std::move(requirement));
        } else {
            return invalid("plugin manifest contains an unknown key");
        }
    }
    if (!have_format || !have_id || !have_name || !have_version)
        return invalid("plugin manifest is missing a required field");
    return manifest;
}
std::optional<RegisterOperand> semantic_register_v2(DecodeContext context,
                                                     const HexLabSemanticRegisterV2& source) {
    if (source.reserved || source.index > 31 || source.width == 0 || source.width > 128) return {};
    const auto mode_bits = [&] {
        switch (context.mode) {
        case ExecutionMode::x86_16: return 16u;
        case ExecutionMode::x86_32: case ExecutionMode::a32: case ExecutionMode::rv32:
        case ExecutionMode::mips32: case ExecutionMode::ppc32: return 32u;
        case ExecutionMode::x86_64: case ExecutionMode::a64: case ExecutionMode::rv64:
        case ExecutionMode::rv64c: case ExecutionMode::mips64: case ExecutionMode::ppc64: return 64u;
        case ExecutionMode::m6502: return 8u;
        default: return 0u;
        }
    }();
    RegisterBank bank;
    switch (source.bank) {
    case HEXLAB_SEMANTIC_GPR_V2:
        if ((context.architecture != Architecture::x86 && context.architecture != Architecture::x86_64) ||
            source.index > 15 || source.width > mode_bits) return {};
        bank = RegisterBank::gpr; break;
    case HEXLAB_SEMANTIC_IP_V2:
        if ((context.architecture != Architecture::x86 && context.architecture != Architecture::x86_64) ||
            source.index || source.width != mode_bits) return {};
        bank = RegisterBank::ip; break;
    case HEXLAB_SEMANTIC_FLAGS_V2:
        if ((context.architecture != Architecture::x86 && context.architecture != Architecture::x86_64) ||
            source.index || source.width > mode_bits) return {};
        bank = RegisterBank::flags; break;
    case HEXLAB_SEMANTIC_ARM32_GPR_V2:
        if (context.architecture != Architecture::arm || context.mode != ExecutionMode::a32 ||
            source.index > 15 || source.width != 32) return {};
        bank = RegisterBank::arm32_gpr; break;
    case HEXLAB_SEMANTIC_ARM64_GPR_V2:
        if (context.architecture != Architecture::arm64 || context.mode != ExecutionMode::a64 ||
            source.index > 30 || (source.width != 32 && source.width != 64)) return {};
        bank = RegisterBank::arm64_gpr; break;
    case HEXLAB_SEMANTIC_ARM64_SP_V2:
        if (context.architecture != Architecture::arm64 || context.mode != ExecutionMode::a64 ||
            source.index || (source.width != 32 && source.width != 64)) return {};
        bank = RegisterBank::arm64_sp; break;
    case HEXLAB_SEMANTIC_ARM64_ZERO_V2:
        if (context.architecture != Architecture::arm64 || context.mode != ExecutionMode::a64 ||
            source.index || (source.width != 32 && source.width != 64)) return {};
        bank = RegisterBank::arm64_zero; break;
    case HEXLAB_SEMANTIC_ARM_FLAGS_V2:
        if (context.architecture != Architecture::arm || source.index || source.width != 32) return {};
        bank = RegisterBank::arm_flags; break;
    case HEXLAB_SEMANTIC_RISCV_GPR_V2:
        if ((context.architecture != Architecture::riscv32 && context.architecture != Architecture::riscv64) ||
            source.width != mode_bits) return {};
        bank = RegisterBank::riscv_gpr; break;
    case HEXLAB_SEMANTIC_RISCV_FSTATUS_V2:
        if ((context.architecture != Architecture::riscv32 && context.architecture != Architecture::riscv64) ||
            source.index || source.width != 32) return {};
        bank = RegisterBank::riscv_fstatus; break;
    case HEXLAB_SEMANTIC_MIPS_GPR_V2:
        if ((context.architecture != Architecture::mips32 && context.architecture != Architecture::mips64) ||
            source.width != mode_bits) return {};
        bank = RegisterBank::mips_gpr; break;
    case HEXLAB_SEMANTIC_MIPS_FCSR_V2:
        if ((context.architecture != Architecture::mips32 && context.architecture != Architecture::mips64) ||
            source.index || source.width != 32) return {};
        bank = RegisterBank::mips_fcsr; break;
    case HEXLAB_SEMANTIC_MIPS_HILO_V2:
        if ((context.architecture != Architecture::mips32 && context.architecture != Architecture::mips64) ||
            source.index > 1 || source.width != mode_bits) return {};
        bank = RegisterBank::mips_hilo; break;
    case HEXLAB_SEMANTIC_PPC_GPR_V2:
        if (context.architecture != Architecture::powerpc || source.width != mode_bits) return {};
        bank = RegisterBank::ppc_gpr; break;
    case HEXLAB_SEMANTIC_PPC_CR_V2:
        if (context.architecture != Architecture::powerpc || source.index > 7 || source.width != 4) return {};
        bank = RegisterBank::ppc_cr; break;
    case HEXLAB_SEMANTIC_MOS6502_V2:
        if (context.architecture != Architecture::mos6502 || source.index > 4 || source.width != 8) return {};
        bank = RegisterBank::mos6502; break;
    default: return {};
    }
    return RegisterOperand{bank, static_cast<std::uint8_t>(source.index),
                           static_cast<std::uint16_t>(source.width), false};
}
std::optional<Instruction> convert_semantic_v2(const HexLabSemanticInstructionV2& decoded,
                                                DecodeContext context, Address address,
                                                std::span<const std::byte> input) {
    constexpr auto required_size = sizeof(HexLabSemanticInstructionV2);
    if (decoded.struct_size < required_size || decoded.api_version != 2 || decoded.reserved != 0 ||
        decoded.length == 0 || decoded.length > 15 || decoded.length > input.size() ||
        decoded.flow > HEXLAB_INSTRUCTION_FLOW_JUMP || decoded.operand_count > 4 ||
        decoded.register_read_count > 16 || decoded.register_write_count > 16 ||
        decoded.condition > UINT8_MAX || decoded.delay_slots > 4 ||
        (decoded.delay_slots && decoded.flow == HEXLAB_INSTRUCTION_FLOW_NORMAL) ||
        (decoded.delay_slots && decoded.flow > HEXLAB_INSTRUCTION_FLOW_JUMP)) return {};
    std::string mnemonic;
    if (!copy_fixed_string(decoded.mnemonic, sizeof(decoded.mnemonic), mnemonic)) return {};
    Instruction result;
    result.context = context; result.address = address;
    result.length = static_cast<std::uint8_t>(decoded.length); result.opcode = Opcode::opaque;
    result.mnemonic_override = std::move(mnemonic);
    std::copy_n(input.begin(), result.length, result.bytes.begin());
    switch (decoded.flow) {
    case HEXLAB_INSTRUCTION_FLOW_CALL: result.flow = FlowKind::call; break;
    case HEXLAB_INSTRUCTION_FLOW_RETURN: result.flow = FlowKind::ret; break;
    case HEXLAB_INSTRUCTION_FLOW_BRANCH: result.flow = FlowKind::conditional_branch; break;
    case HEXLAB_INSTRUCTION_FLOW_JUMP: result.flow = FlowKind::jump; break;
    default: result.flow = FlowKind::fallthrough; break;
    }
    result.condition = static_cast<std::uint8_t>(decoded.condition);
    result.delay_slots = static_cast<std::uint8_t>(decoded.delay_slots);
    auto add_read = [&](RegisterOperand reg) {
        if (std::find(result.register_reads.begin(), result.register_reads.end(), reg) == result.register_reads.end())
            result.register_reads.push_back(reg);
    };
    auto add_write = [&](RegisterOperand reg) {
        if (std::find(result.register_writes.begin(), result.register_writes.end(), reg) == result.register_writes.end())
            result.register_writes.push_back(reg);
    };
    for (std::uint32_t i = 0; i < decoded.operand_count; ++i) {
        const auto& source = decoded.operands[i];
        if (source.struct_size < sizeof(HexLabSemanticOperandV2) || source.reserved != 0 ||
            source.width == 0 || source.width > 128 ||
            (source.access != HEXLAB_SEMANTIC_READ && source.access != HEXLAB_SEMANTIC_WRITE &&
             source.access != HEXLAB_SEMANTIC_READ_WRITE)) return {};
        const auto access = source.access == HEXLAB_SEMANTIC_READ ? OperandAccess::read :
                            source.access == HEXLAB_SEMANTIC_WRITE ? OperandAccess::write : OperandAccess::read_write;
        if (source.kind == HEXLAB_SEMANTIC_REGISTER_V2) {
            if (source.value || source.address_width || source.base_bank || source.base_index || source.base_width ||
                source.index_bank || source.index_index || source.index_width || source.scale || source.displacement) return {};
            const auto reg = semantic_register_v2(context,
                HexLabSemanticRegisterV2{source.bank, source.index, source.width, 0});
            if (!reg) return {};
            result.operands.emplace_back(*reg);
            if (access != OperandAccess::write) add_read(*reg);
            if (access != OperandAccess::read) add_write(*reg);
        } else if (source.kind == HEXLAB_SEMANTIC_IMMEDIATE_V2 && access == OperandAccess::read && source.width <= 64) {
            if (source.bank || source.index || source.value > (source.width == 64 ? UINT64_MAX :
                ((UINT64_C(1) << source.width) - 1)) || source.address_width || source.base_bank ||
                source.base_index || source.base_width || source.index_bank || source.index_index ||
                source.index_width || source.scale || source.displacement) return {};
            result.operands.emplace_back(ImmediateOperand{source.value, static_cast<std::uint16_t>(source.width),
                                                          static_cast<std::uint16_t>(source.width), false, std::nullopt});
        } else if (source.kind == HEXLAB_SEMANTIC_RELATIVE_V2 && access == OperandAccess::read && source.width <= 64) {
            if (source.bank || source.index || source.address_width || source.base_bank || source.base_index ||
                source.base_width || source.index_bank || source.index_index || source.index_width || source.scale ||
                source.displacement || (result.flow != FlowKind::conditional_branch && result.flow != FlowKind::call &&
                                       result.flow != FlowKind::jump)) return {};
            const auto displacement = source.value <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())
                ? static_cast<std::int64_t>(source.value) : -1 - static_cast<std::int64_t>(~source.value);
            if (source.width < 64) {
                const auto limit = UINT64_C(1) << (source.width - 1);
                if (displacement < -static_cast<std::int64_t>(limit) || displacement >= static_cast<std::int64_t>(limit)) return {};
            }
            result.operands.emplace_back(RelativeOperand{displacement, static_cast<std::uint16_t>(source.width), 0, std::nullopt});
            const auto end = advance(address, decoded.length);
            if (!end) return {};
            std::uint64_t target = end.value().offset;
            if (displacement >= 0) {
                const auto sum = checked_add(target, static_cast<std::uint64_t>(displacement));
                if (!sum) return {};
                target = sum.value();
            } else {
                const auto magnitude = static_cast<std::uint64_t>(-(displacement + 1)) + 1;
                if (target < magnitude) return {};
                target -= magnitude;
            }
            result.direct_target = Address{address.space, target};
        } else if ((source.kind == HEXLAB_SEMANTIC_ABSOLUTE_MEMORY_V2 ||
                    source.kind == HEXLAB_SEMANTIC_BASE_INDEX_MEMORY_V2) && source.width >= 8 &&
                   source.width <= 128 && source.width % 8 == 0) {
            MemoryOperand memory{};
            memory.data_width = static_cast<std::uint16_t>(source.width);
            if (source.kind == HEXLAB_SEMANTIC_ABSOLUTE_MEMORY_V2) {
                const auto address_width = context.mode == ExecutionMode::x86_16 || context.mode == ExecutionMode::m6502 ? 16u :
                    context.mode == ExecutionMode::x86_32 || context.mode == ExecutionMode::a32 ||
                    context.mode == ExecutionMode::rv32 || context.mode == ExecutionMode::mips32 ||
                    context.mode == ExecutionMode::ppc32 ? 32u : 64u;
                if (access == OperandAccess::address || source.bank || source.index ||
                    source.address_width || source.base_bank || source.base_index || source.base_width ||
                    source.index_bank || source.index_index || source.index_width || source.scale ||
                    source.displacement || (address_width < 64 && source.value >= (UINT64_C(1) << address_width))) return {};
                memory.address_width = static_cast<std::uint16_t>(address_width);
                memory.resolved_address = Address{address.space, source.value};
            } else {
                if (access == OperandAccess::address || source.bank || source.index || source.value ||
                    (source.address_width != 16 && source.address_width != 32 && source.address_width != 64)) return {};
                const auto mode_address_width = context.mode == ExecutionMode::x86_16 || context.mode == ExecutionMode::m6502 ? 16u :
                    context.mode == ExecutionMode::x86_32 || context.mode == ExecutionMode::a32 ||
                    context.mode == ExecutionMode::rv32 || context.mode == ExecutionMode::mips32 ||
                    context.mode == ExecutionMode::ppc32 ? 32u : 64u;
                if (source.address_width > mode_address_width) return {};
                memory.address_width = static_cast<std::uint16_t>(source.address_width);
                memory.displacement = source.displacement;
                memory.scale = static_cast<std::uint8_t>(source.scale);
                if (!source.scale || source.scale > 8 || (source.scale & (source.scale - 1))) return {};
                if (source.base_index != UINT32_MAX) {
                    const auto base = semantic_register_v2(context, {source.base_bank, source.base_index, source.base_width, 0});
                    if (!base || base->width != source.address_width) return {};
                    memory.base = *base; add_read(*base);
                } else if (source.base_bank || source.base_width) return {};
                if (source.index_index != UINT32_MAX) {
                    const auto index = semantic_register_v2(context, {source.index_bank, source.index_index, source.index_width, 0});
                    if (!index || index->width != source.address_width) return {};
                    memory.index = *index; add_read(*index);
                } else if (source.index_bank || source.index_width || source.scale != 1) return {};
                if (!memory.base && !memory.index) return {};
            }
            result.operands.emplace_back(std::move(memory));
            result.memory_read = result.memory_read || access == OperandAccess::read || access == OperandAccess::read_write;
            result.memory_write = result.memory_write || access == OperandAccess::write || access == OperandAccess::read_write;
        } else return {};
        result.access.push_back(access);
    }
    for (std::uint32_t i = 0; i < decoded.register_read_count; ++i) {
        const auto reg = semantic_register_v2(context, decoded.register_reads[i]);
        if (!reg) return {};
        add_read(*reg);
    }
    for (std::uint32_t i = 0; i < decoded.register_write_count; ++i) {
        const auto reg = semantic_register_v2(context, decoded.register_writes[i]);
        if (!reg) return {};
        add_write(*reg);
    }
    return result;
}

struct ScalarIRCallbackScope {
    std::uint32_t &depth;
    explicit ScalarIRCallbackScope(std::uint32_t &value):depth(value){++depth;}
    ~ScalarIRCallbackScope(){--depth;}
};
void initialize_scalar_ir(HexLabInstructionIR &record){
    record={};record.struct_size=sizeof(record);record.api_version=HEXLAB_SCALAR_IR_API_VERSION;
    record.semantic.struct_size=sizeof(record.semantic);record.semantic.api_version=3;
    record.semantic.semantic.struct_size=sizeof(record.semantic.semantic);record.semantic.semantic.api_version=2;
}
std::optional<Instruction> convert_semantic_v3(const HexLabSemanticInstructionV3& decoded,
                                                DecodeContext context, Address address,
                                                std::span<const std::byte> input) {
    if (decoded.struct_size < sizeof(HexLabSemanticInstructionV3) || decoded.api_version != 3 ||
        decoded.reserved != 0 || decoded.memory_update_count > 4) return {};
    auto result = convert_semantic_v2(decoded.semantic, context, address, input);
    if (!result) return {};
    std::array<bool, 4> updated_operands{};
    for (std::uint32_t i = 0; i < decoded.memory_update_count; ++i) {
        const auto& update = decoded.memory_updates[i];
        if (update.struct_size < sizeof(HexLabSemanticMemoryUpdateV3) || update.reserved != 0 ||
            update.operand_index >= decoded.semantic.operand_count ||
            updated_operands[update.operand_index]) return {};
        updated_operands[update.operand_index] = true;
        const auto& source = decoded.semantic.operands[update.operand_index];
        if (source.kind != HEXLAB_SEMANTIC_BASE_INDEX_MEMORY_V2 ||
            source.base_index == UINT32_MAX || source.index_index != UINT32_MAX) return {};
        auto* memory = std::get_if<MemoryOperand>(&result->operands[update.operand_index]);
        if (!memory || !memory->base || memory->writeback) return {};
        switch (update.kind) {
        case HEXLAB_SEMANTIC_MEMORY_PRE_INDEX_WRITEBACK_V3:
            // The effective memory address and the updated base must describe
            // the same pre-indexed displacement.
            if (source.displacement != update.writeback_displacement) return {};
            memory->writeback = true;
            memory->post_index = false;
            memory->writeback_displacement = update.writeback_displacement;
            break;
        case HEXLAB_SEMANTIC_MEMORY_POST_INDEX_WRITEBACK_V3:
            // Post-index accesses use the old base; the separate update record
            // describes the value written back after the memory operation.
            if (source.displacement != 0) return {};
            memory->writeback = true;
            memory->post_index = true;
            memory->writeback_displacement = update.writeback_displacement;
            break;
        default: return {};
        }
        if (std::find(result->register_writes.begin(), result->register_writes.end(), *memory->base) ==
            result->register_writes.end()) result->register_writes.push_back(*memory->base);
    }
    return result;
}
bool project_location(const HexLabProjectLocation* source, Location& destination) {
    if (!source || source->struct_size < sizeof(*source) || source->reserved != 0) return false;
    if (source->kind == HEXLAB_PROJECT_LOCATION_ADDRESS) {
        destination = Address{{source->address_space}, source->offset};
        return true;
    }
    if (source->kind == HEXLAB_PROJECT_LOCATION_FILE && source->address_space == 0) {
        destination = FileOffset{source->offset};
        return true;
    }
    return false;
}

int32_t host_register_loader(void* raw_context, const HexLabLoaderExtension* extension) {
    if (!raw_context || !extension) return -1;
    try {
        constexpr auto required = offsetof(HexLabLoaderExtension, probe) + sizeof(extension->probe);
        if (extension->struct_size < required || extension->api_version != HEXLAB_EXTENSION_API_VERSION ||
            !extension->probe) return -1;
        HostContext::Loader loader;
        if (!copy_string(extension->extension_id, loader.id) || !copy_string(extension->format_id, loader.format_id))
            return -1;
        loader.extension_context = extension->extension_context;
        loader.probe = extension->probe;
        if (extension->struct_size >= offsetof(HexLabLoaderExtension, load_image) + sizeof(extension->load_image)) {
            if ((extension->load_image && extension->image_api_version != HEXLAB_IMAGE_PROVIDER_API_VERSION) ||
                (!extension->load_image && extension->image_api_version != 0)) return -1;
            loader.load_image = extension->load_image;
            loader.image_api_version = extension->image_api_version;
        }
        auto& host = *static_cast<HostContext*>(raw_context);
        std::lock_guard lock(host.mutex);
        if (!host.accepting_extensions || host.loaders.size() >= max_extensions ||
            std::any_of(host.loaders.begin(), host.loaders.end(), [&](const auto& value) { return value.id == loader.id; }))
            return -1;
        host.loaders.push_back(std::move(loader));
        return 0;
    } catch (...) { return -1; }
}

int32_t host_register_processor(void* raw_context, const HexLabProcessorExtension* extension) {
    if (!raw_context || !extension) return -1;
    try {
        constexpr auto required = offsetof(HexLabProcessorExtension, decode) + sizeof(extension->decode);
        if (extension->struct_size < required || extension->api_version != HEXLAB_EXTENSION_API_VERSION ||
            !extension->decode) return -1;
        HostContext::Processor processor;
        if (!copy_string(extension->extension_id, processor.id) ||
            !copy_string(extension->architecture_id, processor.architecture_id) ||
            !copy_string(extension->mode_id, processor.mode_id)) return -1;
        processor.extension_context = extension->extension_context;
        processor.decode = extension->decode;
        constexpr auto semantic_end = offsetof(HexLabProcessorExtension, decode_semantic) +
                                      sizeof(extension->decode_semantic);
        if (extension->struct_size >= semantic_end) processor.decode_semantic = extension->decode_semantic;
        constexpr auto semantic_v2_end = offsetof(HexLabProcessorExtension, decode_semantic_v2) +
                                         sizeof(extension->decode_semantic_v2);
        if (extension->struct_size >= semantic_v2_end)
            processor.decode_semantic_v2 = extension->decode_semantic_v2;
        constexpr auto semantic_v3_end = offsetof(HexLabProcessorExtension, decode_semantic_v3) +
                                          sizeof(extension->decode_semantic_v3);
        if (extension->struct_size >= semantic_v3_end)
            processor.decode_semantic_v3 = extension->decode_semantic_v3;
        constexpr auto ir_offset = offsetof(HexLabProcessorExtension, decode_ir);
        constexpr auto ir_end = ir_offset + sizeof(extension->decode_ir);
        if (extension->struct_size > ir_offset && extension->struct_size < ir_end) return -1;
        if (extension->struct_size >= ir_end) processor.decode_ir = extension->decode_ir;
        auto& host = *static_cast<HostContext*>(raw_context);
        std::lock_guard lock(host.mutex);
        if (!host.accepting_extensions || host.processors.size() >= max_extensions ||
            std::any_of(host.processors.begin(), host.processors.end(), [&](const auto& value) { return value.id == processor.id; }))
            return -1;
        host.processors.push_back(std::move(processor));
        return 0;
    } catch (...) { return -1; }
}

int32_t host_register_analysis_provider(void* raw_context, const HexLabAnalysisProvider* extension) {
    if (!raw_context || !extension) return -1;
    try {
        constexpr auto required = offsetof(HexLabAnalysisProvider, analyze) + sizeof(extension->analyze);
        if (extension->struct_size < required || extension->api_version != HEXLAB_ANALYSIS_PROVIDER_API_VERSION ||
            !extension->analyze) return -1;
        HostContext::AnalysisProvider provider;
        if (!copy_string(extension->provider_id, provider.id) ||
            !copy_string(extension->display_name, provider.name)) return -1;
        provider.context = extension->provider_context;
        provider.analyze = extension->analyze;
        auto& host = *static_cast<HostContext*>(raw_context);
        std::lock_guard lock(host.mutex);
        if (!host.accepting_extensions || host.analysis_providers.size() >= max_extensions ||
            std::any_of(host.analysis_providers.begin(), host.analysis_providers.end(),
                        [&](const auto& value) { return value.id == provider.id; })) return -1;
        host.analysis_providers.push_back(std::move(provider));
        return 0;
    } catch (...) { return -1; }
}

bool valid_document_token(const HexLabDocumentToken* token) {
    return token && token->struct_size >= sizeof(*token) && token->reserved == 0 &&
        token->document_id != 0 && token->open_generation != 0;
}
int32_t active_document_query(void* raw_context, HexLabActiveDocumentInfo* output) {
    if (!raw_context || !output || output->struct_size < sizeof(*output))
        return HEXLAB_ACTIVE_DOCUMENT_INVALID;
    auto* state = static_cast<ActiveDocumentServicesState*>(raw_context);
    try {
        std::function<std::int32_t(HexLabActiveDocumentInfo&)> callback;
        { std::lock_guard lock(state->mutex); callback = state->services.query; }
        if (!callback) return HEXLAB_ACTIVE_DOCUMENT_FAILED;
        HexLabActiveDocumentInfo result{};
        result.struct_size = sizeof(result);
        result.token.struct_size = sizeof(result.token);
        const auto status = callback(result);
        if (status != HEXLAB_ACTIVE_DOCUMENT_OK) return status;
        if (result.token.struct_size < sizeof(result.token) || result.token.reserved != 0 ||
            result.token.document_id == 0 || result.token.open_generation == 0 ||
            !std::memchr(result.architecture_id, '\0', sizeof(result.architecture_id)) ||
            !std::memchr(result.mode_id, '\0', sizeof(result.mode_id)))
            return HEXLAB_ACTIVE_DOCUMENT_FAILED;
        *output = result;
        return HEXLAB_ACTIVE_DOCUMENT_OK;
    } catch (...) { return HEXLAB_ACTIVE_DOCUMENT_FAILED; }
}
int32_t active_document_read(void* raw_context, const HexLabDocumentToken* token,
                             const HexLabProjectLocation* location, uint32_t size, uint8_t* output) {
    Location parsed;
    if (!raw_context || !valid_document_token(token) || !project_location(location, parsed) ||
        !size || size > HEXLAB_ACTIVE_DOCUMENT_MAX_READ || !output)
        return HEXLAB_ACTIVE_DOCUMENT_INVALID;
    auto* state = static_cast<ActiveDocumentServicesState*>(raw_context);
    try {
        decltype(ActiveDocumentServices::read) callback;
        { std::lock_guard lock(state->mutex); callback = state->services.read; }
        return callback ? callback(*token, *location, size, output) : HEXLAB_ACTIVE_DOCUMENT_FAILED;
    } catch (...) { return HEXLAB_ACTIVE_DOCUMENT_FAILED; }
}
int32_t active_document_navigate(void* raw_context, const HexLabDocumentToken* token,
                                 const HexLabProjectLocation* location) {
    Location parsed;
    if (!raw_context || !valid_document_token(token) || !project_location(location, parsed))
        return HEXLAB_ACTIVE_DOCUMENT_INVALID;
    auto* state = static_cast<ActiveDocumentServicesState*>(raw_context);
    try {
        decltype(ActiveDocumentServices::navigate) callback;
        { std::lock_guard lock(state->mutex); callback = state->services.navigate; }
        return callback ? callback(*token, *location) : HEXLAB_ACTIVE_DOCUMENT_FAILED;
    } catch (...) { return HEXLAB_ACTIVE_DOCUMENT_FAILED; }
}
bool valid_active_project_token(const HexLabActiveProjectToken* token) {
    return token && token->struct_size >= sizeof(*token) && token->reserved == 0 &&
        valid_document_token(&token->document) && token->project_identity != 0 &&
        token->project_generation != 0;
}
int32_t active_project_breakpoint_snapshot(void* raw, HexLabActiveProjectToken* output) {
    if (!raw || !output || output->struct_size < sizeof(*output)) return HEXLAB_ACTIVE_DOCUMENT_INVALID;
    try {
        auto* state = static_cast<ActiveProjectBreakpointServicesState*>(raw);
        decltype(ActiveProjectBreakpointServices::snapshot) callback;
        { std::lock_guard lock(state->mutex); callback = state->services.snapshot; }
        if (!callback) return HEXLAB_ACTIVE_DOCUMENT_FAILED;
        HexLabActiveProjectToken result{}; result.struct_size = sizeof(result);
        result.document.struct_size = sizeof(result.document);
        const auto status = callback(result);
        if (status != 0) return status;
        if (!valid_active_project_token(&result)) return HEXLAB_ACTIVE_DOCUMENT_FAILED;
        *output = result; return 0;
    } catch (...) { return HEXLAB_ACTIVE_DOCUMENT_FAILED; }
}
int32_t active_project_breakpoints_query(void* raw, const HexLabActiveProjectToken* token,
                                         uint64_t start, uint32_t capacity,
                                         HexLabProjectBreakpointRecord* output, uint32_t* written) {
    if (written) *written = 0;
    if (!raw || !valid_active_project_token(token) || !written || !capacity ||
        capacity > HEXLAB_ACTIVE_PROJECT_BREAKPOINT_MAX_PAGE || !output ||
        start > std::numeric_limits<std::size_t>::max()) return HEXLAB_ACTIVE_DOCUMENT_INVALID;
    try {
        auto* state = static_cast<ActiveProjectBreakpointServicesState*>(raw);
        decltype(ActiveProjectBreakpointServices::query) callback;
        { std::lock_guard lock(state->mutex); callback = state->services.query; }
        if (!callback) return HEXLAB_ACTIVE_DOCUMENT_FAILED;
        const auto status = callback(*token, start, capacity, output, *written);
        if (status != 0) { *written = 0; return status; }
        if (*written > capacity) { *written = 0; return HEXLAB_ACTIVE_DOCUMENT_FAILED; }
        for (std::uint32_t i = 0; i < *written; ++i) {
            const auto& row = output[i];
            if (row.struct_size < sizeof(row) || row.kind > 5 || row.enabled > 1 ||
                !(row.size == 1 || row.size == 2 || row.size == 4 || row.size == 8) ||
                (row.kind <= 2 && row.size != 1) ||
                std::any_of(std::begin(row.reserved), std::end(row.reserved), [](auto b) { return b != 0; })) {
                *written = 0; return HEXLAB_ACTIVE_DOCUMENT_FAILED;
            }
        }
        return 0;
    } catch (...) { if (written) *written = 0; return HEXLAB_ACTIVE_DOCUMENT_FAILED; }
}
int32_t active_project_breakpoint_set(void* raw, const HexLabActiveProjectToken* token,
                                      uint32_t address_space, uint64_t address, uint32_t kind,
                                      uint8_t size, uint8_t enabled, uint8_t remove) {
    if (!raw || !valid_active_project_token(token) || kind > 5 || remove > 1 || enabled > 1 ||
        !(size == 1 || size == 2 || size == 4 || size == 8) ||
        ((kind <= 2) && size != 1)) return HEXLAB_ACTIVE_DOCUMENT_INVALID;
    try {
        auto* state = static_cast<ActiveProjectBreakpointServicesState*>(raw);
        decltype(ActiveProjectBreakpointServices::set) callback;
        { std::lock_guard lock(state->mutex); callback = state->services.set; }
        return callback ? callback(*token, address_space, address, kind, size, enabled, remove)
                        : HEXLAB_ACTIVE_DOCUMENT_FAILED;
    } catch (...) { return HEXLAB_ACTIVE_DOCUMENT_FAILED; }
}
bool valid_active_debugger_token(const HexLabActiveDebuggerToken* t) {
    return t && t->struct_size >= sizeof(*t) && !t->reserved && t->session_id &&
        t->session_generation && t->stop_generation && valid_document_token(&t->document);
}
int32_t active_debugger_query(void* raw, HexLabActiveDebuggerInfo* out) {
    if (!raw || !out || out->struct_size < sizeof(*out)) return HEXLAB_ACTIVE_DEBUGGER_INVALID;
    try { auto* s = static_cast<ActiveDebuggerServicesState*>(raw); decltype(ActiveDebuggerServices::query) cb;
        { std::lock_guard lock(s->mutex); cb = s->services.query; } if (!cb) return HEXLAB_ACTIVE_DEBUGGER_FAILED;
        HexLabActiveDebuggerInfo v{}; v.struct_size = sizeof(v); v.token.struct_size = sizeof(v.token);
        v.token.document.struct_size = sizeof(v.token.document); v.process.struct_size = sizeof(v.process);
        const auto rc = cb(v); if (rc != HEXLAB_ACTIVE_DEBUGGER_OK) return rc;
        if (!valid_active_debugger_token(&v.token) || v.has_process > 1 || v.state > 5) return HEXLAB_ACTIVE_DEBUGGER_FAILED;
        *out = v; return rc;
    } catch (...) { return HEXLAB_ACTIVE_DEBUGGER_FAILED; }
}
int32_t active_debugger_threads(void* raw, const HexLabActiveDebuggerToken* token, uint64_t start,
                                uint32_t cap, HexLabDebugThread* out, uint32_t* written) {
    if (!raw || !valid_active_debugger_token(token) || !written || cap > HEXLAB_ACTIVE_DEBUGGER_MAX_PAGE || (cap && !out)) return HEXLAB_ACTIVE_DEBUGGER_INVALID;
    *written = 0;
    try { auto* s = static_cast<ActiveDebuggerServicesState*>(raw); decltype(ActiveDebuggerServices::threads) cb;
        { std::lock_guard lock(s->mutex); cb = s->services.threads; } if (!cb) return HEXLAB_ACTIVE_DEBUGGER_FAILED;
        uint32_t n=0; auto rc=cb(*token,start,cap,out,&n); if (rc==0 && n<=cap) *written=n; else if(rc==0) rc=HEXLAB_ACTIVE_DEBUGGER_FAILED; return rc;
    } catch (...) { return HEXLAB_ACTIVE_DEBUGGER_FAILED; }
}
int32_t active_debugger_registers(void* raw, const HexLabActiveDebuggerToken* token, uint64_t thread,
                                  uint64_t start, uint32_t cap, HexLabDebugRegister* out, uint32_t* written) {
    if (!raw || !valid_active_debugger_token(token) || !thread || !written || cap > HEXLAB_ACTIVE_DEBUGGER_MAX_PAGE || (cap && !out)) return HEXLAB_ACTIVE_DEBUGGER_INVALID;
    *written = 0;
    try { auto* s = static_cast<ActiveDebuggerServicesState*>(raw); decltype(ActiveDebuggerServices::read_registers) cb;
        { std::lock_guard lock(s->mutex); cb = s->services.read_registers; } if (!cb) return HEXLAB_ACTIVE_DEBUGGER_FAILED;
        uint32_t n=0; auto rc=cb(*token,thread,start,cap,out,&n); if (rc==0 && n<=cap) *written=n; else if(rc==0) rc=HEXLAB_ACTIVE_DEBUGGER_FAILED; return rc;
    } catch (...) { return HEXLAB_ACTIVE_DEBUGGER_FAILED; }
}
int32_t active_debugger_memory(void* raw, const HexLabActiveDebuggerToken* token, uint64_t address, uint32_t size, uint8_t* out) {
    if (!raw || !valid_active_debugger_token(token) || !size || size>HEXLAB_ACTIVE_DEBUGGER_MAX_READ || !out) return HEXLAB_ACTIVE_DEBUGGER_INVALID;
    try { auto* s = static_cast<ActiveDebuggerServicesState*>(raw); decltype(ActiveDebuggerServices::read_memory) cb;
        { std::lock_guard lock(s->mutex); cb = s->services.read_memory; } return cb ? cb(*token,address,size,out) : HEXLAB_ACTIVE_DEBUGGER_FAILED;
    } catch (...) { return HEXLAB_ACTIVE_DEBUGGER_FAILED; }
}
}

struct PluginManager::Impl {
    struct Loaded {
        PluginInfo info;
        ModuleProvider::Module module;
        HexLabPluginStop stop = nullptr;
        void* instance = nullptr;
        std::shared_ptr<HostContext> context = std::make_shared<HostContext>();
        // Plugins may retain the borrowed host table until stop returns. Its
        // address must survive candidate publication and loaded-vector moves.
        std::unique_ptr<HexLabHostApi> host = std::make_unique<HexLabHostApi>();
        std::vector<std::shared_ptr<void>> image_providers;
        void stop_noexcept() noexcept {
            if (!stop) return;
            try { stop(instance); } catch (...) {}
            stop = nullptr;
            instance = nullptr;
        }
        ~Loaded() {
            stop_noexcept();
            if (context) {
                for (void* handle : context->projects) delete static_cast<std::shared_ptr<automation::Project>*>(handle);
                context->projects.clear();
                close_debugger_sessions(*context);
                context->loaders.clear();
                context->processors.clear();
                context->analysis_providers.clear();
            }
            if (module.handle && module.close) module.close(module.handle);
        }
        Loaded() = default;
        Loaded(const Loaded&) = delete;
        Loaded& operator=(const Loaded&) = delete;
        Loaded(Loaded&& other) noexcept
            : info(std::move(other.info)), module(std::exchange(other.module, {})),
              stop(std::exchange(other.stop, nullptr)), instance(std::exchange(other.instance, nullptr)),
              context(std::move(other.context)), host(std::move(other.host)), image_providers(std::move(other.image_providers)) {}
        Loaded& operator=(Loaded&& other) noexcept {
            if (this != &other) {
                stop_noexcept();
                if (context) {
                    for (void* handle : context->projects) delete static_cast<std::shared_ptr<automation::Project>*>(handle);
                    context->projects.clear();
                    close_debugger_sessions(*context);
                    context->loaders.clear();
                    context->processors.clear();
                }
                if (module.handle && module.close) module.close(module.handle);
                info = std::move(other.info);
                image_providers = std::move(other.image_providers);
                module = std::exchange(other.module, {});
                stop = std::exchange(other.stop, nullptr);
                instance = std::exchange(other.instance, nullptr);
                context = std::move(other.context);
                host = std::move(other.host);
            }
            return *this;
        }
    };
    explicit Impl(std::shared_ptr<ModuleProvider> value) : provider(std::move(value)) {
        semantic_identity = make_semantic_identity_locked();
    }
    ~Impl() {
        // A provider must remain resident until every consumer has stopped.
        // Do not depend on a container's element destruction ordering.
        while (!loaded.empty()) loaded.pop_back();
    }
    // Host project services can synchronously reenter loader dispatch from a
    // plugin start/action callback. Loader recursion is bounded at the registry;
    // cross-thread callbacks and unload still serialize on this lock.
    mutable std::recursive_mutex mutex;
    std::uint64_t semantic_generation = 1;
    // Cross-thread calls serialize on mutex. The counter also rejects same-
    // thread lifecycle mutation/recursive decode during a scalar IR callback.
    std::uint32_t scalar_ir_callback_depth = 0;
    std::shared_ptr<const std::vector<std::byte>> semantic_identity =
        std::make_shared<const std::vector<std::byte>>(std::vector<std::byte>{});
    std::shared_ptr<ModuleProvider> provider;
    std::shared_ptr<ActiveDocumentServicesState> active_document_services =
        std::make_shared<ActiveDocumentServicesState>();
    std::shared_ptr<ActiveDebuggerServicesState> active_debugger_services =
        std::make_shared<ActiveDebuggerServicesState>();
    std::shared_ptr<ActiveProjectBreakpointServicesState> active_project_breakpoint_services =
        std::make_shared<ActiveProjectBreakpointServicesState>();
    std::vector<Loaded> loaded;
    std::shared_ptr<const std::vector<std::byte>> make_semantic_identity_locked() const {
        std::vector<std::array<std::string, 5>> rows;
        rows.push_back({"!generation", std::to_string(semantic_generation), "", "", ""});
        for (const auto& plugin : loaded) for (const auto& extension : plugin.context->processors)
            if (!extension.disabled && (extension.decode_semantic || extension.decode_semantic_v2 ||
                                        extension.decode_semantic_v3 || extension.decode_ir))
                rows.push_back({plugin.info.id, plugin.info.version, extension.id,
                                extension.architecture_id, extension.mode_id});
        std::sort(rows.begin(), rows.end());
        auto identity = std::make_shared<std::vector<std::byte>>();
        const auto append = [&](std::string_view value) {
            std::uint64_t length = value.size();
            for (unsigned n = 0; n < 8; ++n) identity->push_back(static_cast<std::byte>((length >> (n * 8)) & 0xff));
            for (unsigned char ch : value) identity->push_back(static_cast<std::byte>(ch));
        };
        for (const auto& row : rows) for (const auto& field : row) append(field);
        return identity;
    }
    void quarantine(HostContext::Loader &extension, std::string_view reason) {
        if (extension.disabled) return;
        extension.disabled = true;
        extension.failure_reason.assign(reason);
    }
    void quarantine(HostContext::Processor &extension, std::string_view reason) {
        if (extension.disabled) return;
        const bool affects_semantics = extension.decode_semantic || extension.decode_semantic_v2 ||
                                       extension.decode_semantic_v3 || extension.decode_ir;
        extension.disabled = true;
        extension.failure_reason.assign(reason);
        if (affects_semantics) {
            ++semantic_generation;
            std::atomic_store(&semantic_identity, make_semantic_identity_locked());
        }
    }
};

namespace {
bool bounded_path(const char* source, std::filesystem::path& path) {
    if (!source) return false;
    std::size_t length = 0;
    while (length < HEXLAB_PROJECT_MAX_PATH && source[length]) ++length;
    if (!length || length == HEXLAB_PROJECT_MAX_PATH) return false;
    try { path = std::filesystem::u8path(std::string(source, length)); return true; }
    catch (...) { return false; }
}
std::shared_ptr<automation::Project>* project_handle(void* context, void* handle) {
    if (!context || !handle) return nullptr;
    auto* host = static_cast<HostContext*>(context);
    if (!host->projects.contains(handle)) return nullptr;
    return static_cast<std::shared_ptr<automation::Project>*>(handle);
}
int32_t project_create(void* context, const char* project_path, const char* input_path,
                       uint32_t format, void** result) {
    if (result) *result = nullptr;
    std::filesystem::path destination, input;
    if (!context || !result || !bounded_path(project_path, destination) || !bounded_path(input_path, input)) return -1;
    std::lock_guard lock(static_cast<HostContext*>(context)->mutex);
    std::optional<Format> selected;
    switch (format) {
    case HEXLAB_PROJECT_FORMAT_AUTO: selected = Format::automatic; break;
    case HEXLAB_PROJECT_FORMAT_PE: selected = Format::pe; break;
    case HEXLAB_PROJECT_FORMAT_ELF: selected = Format::elf; break;
    case HEXLAB_PROJECT_FORMAT_MACHO: selected = Format::macho; break;
    default: return -1;
    }
    try {
        auto created = automation::Project::create(destination, input, LoadRecipe{*selected, {}, {}});
        if (!created) return -2;
        auto* holder = new std::shared_ptr<automation::Project>(std::move(created.value()));
        static_cast<HostContext*>(context)->projects.insert(holder);
        *result = holder;
        return 0;
    } catch (...) { return -2; }
}
int32_t project_open(void* context, const char* project_path, uint8_t read_only, void** result) {
    if (result) *result = nullptr;
    std::filesystem::path path;
    if (!context || !result || !bounded_path(project_path, path)) return -1;
    std::lock_guard lock(static_cast<HostContext*>(context)->mutex);
    try {
        auto opened = automation::Project::open(path, read_only != 0);
        if (!opened) return -2;
        auto* holder = new std::shared_ptr<automation::Project>(std::move(opened.value()));
        static_cast<HostContext*>(context)->projects.insert(holder);
        *result = holder;
        return 0;
    } catch (...) { return -2; }
}
void project_close(void* context, void* handle) {
    if (!context) return;
    std::lock_guard lock(static_cast<HostContext*>(context)->mutex);
    auto* project = project_handle(context, handle);
    if (!project) return;
    static_cast<HostContext*>(context)->projects.erase(handle);
    delete project;
}
int32_t project_analyze(void* context, void* handle) {
    if (!context) return -1;
    std::lock_guard lock(static_cast<HostContext*>(context)->mutex);
    auto* project = project_handle(context, handle);
    if (!project) return -1;
    try { return (*project)->analyze() ? 0 : -2; } catch (...) { return -2; }
}
int32_t project_summary(void* context, void* handle, HexLabProjectSummary* output) {
    if (!context) return -1;
    std::lock_guard lock(static_cast<HostContext*>(context)->mutex);
    auto* project = project_handle(context, handle);
    if (!project || !output || output->struct_size < sizeof(*output)) return -1;
    try {
        auto snapshot = (*project)->snapshot();
        if (!snapshot) return -2;
        output->derived_status = static_cast<uint32_t>(snapshot.value()->status);
        output->function_count = snapshot.value()->functions ? snapshot.value()->functions->functions.size() : 0;
        output->instruction_count = snapshot.value()->functions ? snapshot.value()->functions->instructions.size() : 0;
        output->input_size = snapshot.value()->effective ? snapshot.value()->effective->size() : 0;
        return 0;
    } catch (...) { return -2; }
}
int32_t project_functions(void* context, void* handle, uint64_t start, uint32_t capacity,
                          HexLabFunction* output, uint32_t* written) {
    if (written) *written = 0;
    if (!context) return -1;
    std::lock_guard lock(static_cast<HostContext*>(context)->mutex);
    auto* project = project_handle(context, handle);
    if (!project || !written || !capacity || capacity > HEXLAB_PROJECT_MAX_PAGE || !output ||
        start > std::numeric_limits<std::size_t>::max()) return -1;
    try {
        auto rows = (*project)->functions(static_cast<std::size_t>(start), capacity);
        if (!rows) return -2;
        for (std::size_t i = 0; i < rows.value().size(); ++i)
            if (output[i].struct_size < sizeof(HexLabFunction)) return -1;
        for (const auto& row : rows.value()) {
            auto& target = output[*written];
            target.address_space = row.entry.space.value;
            target.entry = row.entry.offset;
            target.chunk_count = row.chunks.size();
            target.complete = row.complete ? 1u : 0u;
            ++*written;
        }
        return 0;
    } catch (...) { return -2; }
}
template<std::size_t N> bool copy_field(char (&output)[N], const std::string& value) {
    if (value.size() >= N) return false;
    std::copy(value.begin(), value.end(), output);
    output[value.size()] = '\0';
    return true;
}
int32_t project_instructions(void* context, void* handle, uint64_t start, uint32_t capacity,
                             HexLabInstruction* output, uint32_t* written) {
    if (written) *written = 0;
    if (!context) return -1;
    std::lock_guard lock(static_cast<HostContext*>(context)->mutex);
    auto* project = project_handle(context, handle);
    if (!project || !written || !capacity || capacity > HEXLAB_PROJECT_MAX_PAGE || !output ||
        start > std::numeric_limits<std::size_t>::max()) return -1;
    try {
        auto rows = (*project)->instructions(static_cast<std::size_t>(start), capacity);
        if (!rows) return -2;
        for (std::size_t i = 0; i < rows.value().size(); ++i)
            if (output[i].struct_size < sizeof(HexLabInstruction)) return -1;
        for (const auto& row : rows.value()) {
            auto& target = output[*written];
            const auto text = format_instruction(row);
            if (text.size() >= sizeof(target.text)) return -2;
            target.address_space = row.address.space.value;
            target.address = row.address.offset;
            target.length = row.length;
            for (std::size_t i = 0; i < row.length; ++i) target.bytes[i] = std::to_integer<std::uint8_t>(row.bytes[i]);
            copy_field(target.text, text);
            ++*written;
        }
        return 0;
    } catch (...) { return -2; }
}
int32_t project_references(void* context, void* handle, uint32_t source_space, uint64_t source,
                           uint64_t start, uint32_t capacity, HexLabReference* output, uint32_t* written) {
    if (written) *written = 0;
    if (!context) return -1;
    std::lock_guard lock(static_cast<HostContext*>(context)->mutex);
    auto* project = project_handle(context, handle);
    if (!project || !written || !capacity || capacity > HEXLAB_PROJECT_MAX_PAGE || !output ||
        start > std::numeric_limits<std::size_t>::max()) return -1;
    try {
        const Location location = Address{{source_space}, source};
        auto rows = (*project)->references(location, static_cast<std::size_t>(start), capacity);
        if (!rows) return -2;
        for (std::size_t i = 0; i < rows.value().size(); ++i)
            if (output[i].struct_size < sizeof(HexLabReference)) return -1;
        for (const auto& row : rows.value()) {
            auto& target = output[*written];
            if (const auto* address = std::get_if<Address>(&row.source)) {
                target.source_space = address->space.value;
                target.source = address->offset;
            } else {
                target.source_is_file = 1;
                target.source = std::get<FileOffset>(row.source).value;
            }
            target.kind = static_cast<uint32_t>(row.kind);
            if (const auto* address = std::get_if<Location>(&row.target)) {
                target.target_kind = HEXLAB_REFERENCE_TARGET_LOCATION;
                if (const auto* mapped = std::get_if<Address>(address)) {
                    target.target_space = mapped->space.value;
                    target.target = mapped->offset;
                } else {
                    target.target_is_file = 1;
                    target.target = std::get<FileOffset>(*address).value;
                }
            } else if (const auto* external = std::get_if<ExternalIdentity>(&row.target)) {
                target.target_kind = HEXLAB_REFERENCE_TARGET_EXTERNAL;
                if (!copy_field(target.external_library, external->library) ||
                    (external->name && !copy_field(target.external_name, *external->name))) return -2;
            } else if (std::holds_alternative<UnresolvedTarget>(row.target)) {
                target.target_kind = HEXLAB_REFERENCE_TARGET_UNRESOLVED;
            } else target.target_kind = HEXLAB_REFERENCE_TARGET_NONE;
            ++*written;
        }
        return 0;
    } catch (...) { return -2; }
}
int32_t project_strings(void* context, void* handle, uint64_t start, uint32_t capacity,
                        HexLabString* output, uint32_t* written) {
    if (written) *written = 0;
    if (!context) return -1;
    std::lock_guard lock(static_cast<HostContext*>(context)->mutex);
    auto* project = project_handle(context, handle);
    if (!project || !written || !capacity || capacity > HEXLAB_PROJECT_MAX_PAGE || !output ||
        start > std::numeric_limits<std::size_t>::max()) return -1;
    try {
        auto rows = (*project)->strings(static_cast<std::size_t>(start), capacity);
        if (!rows) return -2;
        for (std::size_t i = 0; i < rows.value().size(); ++i)
            if (output[i].struct_size < sizeof(HexLabString)) return -1;
        for (const auto& row : rows.value()) {
            auto& target = output[*written];
            if (!copy_field(target.preview, row.preview)) return -2;
            target.encoding = static_cast<uint32_t>(row.encoding);
            target.file_offset = row.file_offset.value;
            target.characters = row.characters;
            target.byte_length = row.byte_length;
            target.has_address = row.address ? 1u : 0u;
            if (row.address) {
                target.address_space = row.address->space.value;
                target.address = row.address->offset;
            }
            target.terminated = row.terminated ? 1u : 0u;
            ++*written;
        }
        return 0;
    } catch (...) { return -2; }
}
int32_t project_rename(void* context, void* handle, uint32_t address_space,
                       uint64_t address, const char* name) {
    std::string copied;
    if (!context || !copy_user_text(name, 512, copied)) return -1;
    std::lock_guard lock(static_cast<HostContext*>(context)->mutex);
    auto* project = project_handle(context, handle);
    if (!project) return -1;
    try { return (*project)->execute(Rename{Address{{address_space}, address}, std::move(copied)}) ? 0 : -2; }
    catch (...) { return -2; }
}
int32_t project_comment(void* context, void* handle, const HexLabProjectLocation* input,
                        const char* text) {
    Location location;
    std::string copied;
    if (!context || !project_location(input, location) || !copy_user_text(text, 1024 * 1024, copied)) return -1;
    std::lock_guard lock(static_cast<HostContext*>(context)->mutex);
    auto* project = project_handle(context, handle);
    if (!project) return -1;
    try { return (*project)->execute(Comment{location, std::move(copied)}) ? 0 : -2; }
    catch (...) { return -2; }
}
int32_t project_bookmark(void* context, void* handle, const HexLabProjectLocation* input,
                         const char* label, uint8_t remove) {
    Location location;
    std::string copied;
    if (!context || remove > 1 || !project_location(input, location) ||
        !copy_user_text(label, 512, copied)) return -1;
    std::lock_guard lock(static_cast<HostContext*>(context)->mutex);
    auto* project = project_handle(context, handle);
    if (!project) return -1;
    try { return (*project)->execute(BookmarkCommand{location, std::move(copied), remove != 0}) ? 0 : -2; }
    catch (...) { return -2; }
}
int32_t project_read(void* context, void* handle, const HexLabProjectLocation* input,
                     uint32_t size, uint8_t* output) {
    Location location;
    if (!context || !project_location(input, location) || !size || size > HEXLAB_PROJECT_MAX_READ || !output) return -1;
    std::lock_guard lock(static_cast<HostContext*>(context)->mutex);
    auto* project = project_handle(context, handle);
    if (!project) return -1;
    try {
        auto bytes = (*project)->read(location, size);
        if (!bytes || bytes.value().size() != size) return -2;
        for (std::size_t i = 0; i < bytes.value().size(); ++i)
            output[i] = std::to_integer<std::uint8_t>(bytes.value()[i]);
        return 0;
    } catch (...) { return -2; }
}
int32_t project_import_header(void* context, void* handle, const char* source,
                              const HexLabHeaderImportOptions* input_options,
                              HexLabHeaderImportSummary* output) {
    std::string copied;
    if (!context || !output || output->struct_size < sizeof(*output) ||
        !copy_user_text(source, HEXLAB_PROJECT_MAX_HEADER_BYTES, copied)) return -1;
    types::HeaderImportOptions options;
    if (input_options) {
        if (input_options->struct_size < sizeof(*input_options)) return -1;
        const std::uint8_t sizes[] = {input_options->pointer_bytes, input_options->char_bytes,
            input_options->short_bytes, input_options->int_bytes, input_options->long_bytes,
            input_options->long_long_bytes, input_options->float_bytes, input_options->double_bytes};
        if (std::any_of(std::begin(sizes), std::end(sizes), [](auto size) { return size == 0 || size > 16; })) return -1;
        options.pointer_bytes = input_options->pointer_bytes;
        options.char_bytes = input_options->char_bytes;
        options.short_bytes = input_options->short_bytes;
        options.int_bytes = input_options->int_bytes;
        options.long_bytes = input_options->long_bytes;
        options.long_long_bytes = input_options->long_long_bytes;
        options.float_bytes = input_options->float_bytes;
        options.double_bytes = input_options->double_bytes;
    }
    std::lock_guard lock(static_cast<HostContext*>(context)->mutex);
    auto* project = project_handle(context, handle);
    if (!project) return -1;
    try {
        auto snapshot = (*project)->snapshot();
        if (!snapshot || !snapshot.value()->state || !snapshot.value()->state->user) return -2;
        if (!input_options) {
            if (!snapshot.value()->loaded || !snapshot.value()->loaded->image) return -2;
            const auto bits = snapshot.value()->loaded->image->layout().space.width_bits;
            if (bits != 32 && bits != 64) return -2;
            options.pointer_bytes = static_cast<std::uint8_t>(bits / 8);
            options.long_bytes = bits == 32 || snapshot.value()->state->recipe.format == Format::pe ? 4 : 8;
        }
        auto parsed = types::import_c_header(copied, options);
        if (!parsed) return -2;
        std::vector<PortableTypeDefinition> definitions;
        definitions.reserve(parsed.value().symbols.size());
        std::uint32_t typedefs = 0, tags = 0;
        for (const auto& [name, symbol] : parsed.value().symbols) {
            const auto& rows = snapshot.value()->state->user->types;
            auto found = std::find_if(rows.begin(), rows.end(), [&](const auto& row) { return row.name == name; });
            const auto kind = symbol.kind == types::HeaderSymbolKind::function ? database::DeclarationKind::function :
                symbol.kind == types::HeaderSymbolKind::object ? database::DeclarationKind::object : database::DeclarationKind::type;
            if (found == rows.end() || found->type->id() != symbol.type->id() || found->origin || found->declaration_kind != kind)
                definitions.push_back(PortableTypeDefinition{name, symbol.type,
                    found == rows.end() ? std::optional<std::uint64_t>{} : std::optional<std::uint64_t>{found->id}, {}, kind,
                    found == rows.end() ? std::optional<database::TypeDefinition>{} : std::optional<database::TypeDefinition>{*found}});
            if (symbol.kind == types::HeaderSymbolKind::tag) ++tags;
            else if (symbol.kind == types::HeaderSymbolKind::typedef_name) ++typedefs;
        }
        if (!definitions.empty()) {
            auto imported = (*project)->execute(ImportPortableTypes{std::move(definitions), {}});
            if (!imported) return -2;
        }
        output->imported_types = typedefs + tags;
        output->typedefs = typedefs;
        output->tags = tags;
        output->enum_constants = static_cast<std::uint32_t>(std::min<std::size_t>(parsed.value().enum_constants.size(), UINT32_MAX));
        return 0;
    } catch (...) { return -2; }
}
int32_t project_types(void* context, void* handle, uint64_t start, uint32_t capacity,
                      HexLabTypeRecord* output, uint32_t* written) {
    if (written) *written = 0;
    if (!context) return -1;
    std::lock_guard lock(static_cast<HostContext*>(context)->mutex);
    auto* project = project_handle(context, handle);
    if (!project || !written || !capacity || capacity > HEXLAB_PROJECT_MAX_PAGE || !output ||
        start > std::numeric_limits<std::size_t>::max()) return -1;
    try {
        auto snapshot = (*project)->snapshot();
        if (!snapshot || !snapshot.value()->state || !snapshot.value()->state->user) return -2;
        const auto& rows = snapshot.value()->state->user->types;
        // ABI 1.13 pages only named types. Object and function declarations
        // added in 1.14 are visible through declarations(), without changing
        // the legacy page's logical indices or row set.
        std::vector<const database::TypeDefinition*> page;
        page.reserve(std::min<std::size_t>(capacity, rows.size()));
        std::size_t type_index = 0;
        for (const auto& row : rows) {
            if (row.declaration_kind != database::DeclarationKind::type) continue;
            if (type_index++ < static_cast<std::size_t>(start)) continue;
            if (page.size() == capacity) break;
            page.push_back(&row);
        }
        for (std::size_t i = 0; i < page.size(); ++i)
            if (output[i].struct_size < sizeof(HexLabTypeRecord)) return -1;
        for (const auto* row : page) {
            auto& target = output[*written];
            target.id = row->id;
            if (!copy_field(target.name, row->name) || !copy_field(target.formatted, types::format(*row->type))) return -2;
            ++*written;
        }
        return 0;
    } catch (...) { return -2; }
}
int32_t project_assign_type(void* context, void* handle, uint32_t address_space,
                            uint64_t address, uint64_t type_id, uint8_t remove) {
    if (!context || remove > 1 || (!remove && type_id == 0)) return -1;
    std::lock_guard lock(static_cast<HostContext*>(context)->mutex);
    auto* project = project_handle(context, handle);
    if (!project) return -1;
    try { return (*project)->execute(AssignType{Address{{address_space}, address}, type_id, remove != 0}) ? 0 : -2; }
    catch (...) { return -2; }
}
class DeclarationEnumResolver {
public:
    explicit DeclarationEnumResolver(const std::vector<database::TypeDefinition>& rows) {
        for (const auto& row : rows) by_name_.emplace(row.name, row.type.get());
    }
    const types::Type* resolve(const database::TypeDefinition& definition) {
        const types::Type* type = definition.type.get();
        const types::Type* result = nullptr;
        std::vector<const types::Type*> path;
        path.reserve(64);
        bool determined = false;
        unsigned suffix_distance = 0;
        for (unsigned depth = 0; type && depth < 64; ++depth) {
            if (const auto cached = resolved_.find(type); cached != resolved_.end()) {
                if (cached->second.type && depth + cached->second.distance >= 64) return nullptr;
                result = cached->second.type;
                suffix_distance = cached->second.distance + 1;
                determined = true; break;
            }
            if (std::find(path.begin(), path.end(), type) != path.end()) { determined = true; break; }
            path.push_back(type);
            if (type->kind() == types::Kind::enumeration) { result = type; determined = true; break; }
            if (type->kind() == types::Kind::qualified) { type = type->element().get(); continue; }
            if (type->kind() != types::Kind::named_reference) { determined = true; break; }
            const auto found = by_name_.find(type->name());
            if (found == by_name_.end()) { determined = true; break; }
            type = found->second;
        }
        // Do not cache a depth-limit failure: another row may start closer to
        // the same enum and fit within the independent 64-edge query budget.
        if (determined || !type)
            for (auto visited = path.rbegin(); visited != path.rend(); ++visited) {
                resolved_.emplace(*visited, ResolvedEnum{result, result ? suffix_distance : 0});
                ++suffix_distance;
            }
        return result;
    }
private:
    std::map<std::string_view, const types::Type*, std::less<>> by_name_;
    struct ResolvedEnum { const types::Type* type; unsigned distance; };
    std::map<const types::Type*, ResolvedEnum, std::less<>> resolved_;
};
int32_t project_declarations(void* context, void* handle, uint64_t start, uint32_t capacity,
                             HexLabDeclarationRecord* output, uint32_t* written) {
    if (written) *written = 0;
    if (!context || !written || !capacity || capacity > HEXLAB_PROJECT_MAX_PAGE || !output ||
        start > std::numeric_limits<std::size_t>::max()) return -1;
    std::lock_guard lock(static_cast<HostContext*>(context)->mutex);
    auto* project = project_handle(context, handle);
    if (!project) return -1;
    try {
        auto snapshot = (*project)->snapshot();
        if (!snapshot || !snapshot.value()->state || !snapshot.value()->state->user) return -2;
        const auto& rows = snapshot.value()->state->user->types;
        DeclarationEnumResolver resolver(rows);
        const auto begin = std::min<std::size_t>(static_cast<std::size_t>(start), rows.size());
        const auto end = begin + std::min<std::size_t>(capacity, rows.size() - begin);
        for (std::size_t i = begin; i < end; ++i)
            if (output[i - begin].struct_size < sizeof(HexLabDeclarationRecord)) return -1;
        for (std::size_t i = begin; i < end; ++i) {
            auto& target = output[*written];
            target.id = rows[i].id;
            target.kind = static_cast<std::uint32_t>(rows[i].declaration_kind);
            const auto* enumeration = resolver.resolve(rows[i]);
            target.enum_constant_count = enumeration ? static_cast<std::uint32_t>(enumeration->enumerator_values().size()) : 0;
            if (!copy_field(target.name, rows[i].name) || !copy_field(target.formatted, types::format(*rows[i].type))) return -2;
            ++*written;
        }
        return 0;
    } catch (...) { return -2; }
}
int32_t project_enum_values(void* context, void* handle, uint64_t type_id, uint64_t start,
                            uint32_t capacity, HexLabEnumConstantRecord* output, uint32_t* written) {
    if (written) *written = 0;
    if (!context || !written || !type_id || !capacity || capacity > HEXLAB_PROJECT_MAX_PAGE || !output ||
        start > std::numeric_limits<std::size_t>::max()) return -1;
    std::lock_guard lock(static_cast<HostContext*>(context)->mutex);
    auto* project = project_handle(context, handle);
    if (!project) return -1;
    try {
        auto snapshot = (*project)->snapshot();
        if (!snapshot || !snapshot.value()->state || !snapshot.value()->state->user) return -2;
        const auto& rows = snapshot.value()->state->user->types;
        const auto found = std::find_if(rows.begin(), rows.end(), [&](const auto& row) { return row.id == type_id; });
        if (found == rows.end()) return -1;
        DeclarationEnumResolver resolver(rows);
        const auto* enumeration = resolver.resolve(*found);
        if (!enumeration) return -1;
        const auto& values = enumeration->enumerator_values();
        const auto begin = std::min<std::size_t>(static_cast<std::size_t>(start), values.size());
        const auto end = begin + std::min<std::size_t>(capacity, values.size() - begin);
        for (std::size_t i = begin; i < end; ++i)
            if (output[i - begin].struct_size < sizeof(HexLabEnumConstantRecord)) return -1;
        for (std::size_t i = begin; i < end; ++i) {
            auto& target = output[*written];
            target.value = values[i].value;
            target.is_signed = enumeration->element()->is_signed() ? 1u : 0u;
            std::fill(std::begin(target.reserved), std::end(target.reserved), std::uint8_t{0});
            if (!copy_field(target.name, values[i].name)) return -2;
            ++*written;
        }
        return 0;
    } catch (...) { return -2; }
}
int32_t project_function_blocks(void* context, void* handle, uint32_t address_space,
                                uint64_t function_entry, uint64_t start, uint32_t capacity,
                                HexLabBasicBlock* output, uint32_t* written) {
    if (written) *written = 0;
    if (!context || !written || !capacity || capacity > HEXLAB_PROJECT_MAX_PAGE || !output ||
        start > std::numeric_limits<std::size_t>::max()) return -1;
    std::lock_guard lock(static_cast<HostContext*>(context)->mutex);
    auto* project = project_handle(context, handle);
    if (!project) return -1;
    try {
        auto rows = (*project)->function_blocks(Address{{address_space}, function_entry},
                                                static_cast<std::size_t>(start), capacity);
        if (!rows) return -2;
        for (std::size_t i = 0; i < rows.value().size(); ++i)
            if (output[i].struct_size < sizeof(HexLabBasicBlock)) return -1;
        for (const auto& row : rows.value()) {
            auto& target = output[*written];
            target.struct_size = sizeof(target);
            target.address_space = row.begin.space.value;
            target.id = row.id.value;
            target.address = row.begin.offset;
            target.instruction_count = row.instruction_count;
            target.successor_count = row.successor_count;
            target.has_stop = row.stop ? 1u : 0u;
            std::fill(std::begin(target.reserved), std::end(target.reserved), std::uint8_t{0});
            ++*written;
        }
        return 0;
    } catch (...) { return -2; }
}
int32_t project_block_instructions(void* context, void* handle, uint64_t block_id,
                                   uint64_t start, uint32_t capacity,
                                   HexLabInstruction* output, uint32_t* written) {
    if (written) *written = 0;
    if (!context || !block_id || !written || !capacity || capacity > HEXLAB_PROJECT_MAX_PAGE || !output ||
        start > std::numeric_limits<std::size_t>::max()) return -1;
    std::lock_guard lock(static_cast<HostContext*>(context)->mutex);
    auto* project = project_handle(context, handle);
    if (!project) return -1;
    try {
        auto rows = (*project)->block_instructions(BlockId{block_id}, static_cast<std::size_t>(start), capacity);
        if (!rows) return -2;
        for (std::size_t i = 0; i < rows.value().size(); ++i)
            if (output[i].struct_size < sizeof(HexLabInstruction)) return -1;
        for (const auto& row : rows.value()) {
            auto& target = output[*written];
            const auto text = format_instruction(row);
            if (text.size() >= sizeof(target.text)) return -2;
            target.struct_size = sizeof(target);
            target.address_space = row.address.space.value;
            target.address = row.address.offset;
            target.length = row.length;
            for (std::size_t i = 0; i < row.length; ++i)
                target.bytes[i] = std::to_integer<std::uint8_t>(row.bytes[i]);
            copy_field(target.text, text);
            ++*written;
        }
        return 0;
    } catch (...) { return -2; }
}
int32_t project_block_successors(void* context, void* handle, uint64_t block_id,
                                 uint64_t start, uint32_t capacity,
                                 HexLabBlockSuccessor* output, uint32_t* written) {
    if (written) *written = 0;
    if (!context || !block_id || !written || !capacity || capacity > HEXLAB_PROJECT_MAX_PAGE || !output ||
        start > std::numeric_limits<std::size_t>::max()) return -1;
    std::lock_guard lock(static_cast<HostContext*>(context)->mutex);
    auto* project = project_handle(context, handle);
    if (!project) return -1;
    try {
        auto rows = (*project)->block_successors(BlockId{block_id}, static_cast<std::size_t>(start), capacity);
        if (!rows) return -2;
        for (std::size_t i = 0; i < rows.value().size(); ++i)
            if (output[i].struct_size < sizeof(HexLabBlockSuccessor)) return -1;
        for (const auto& row : rows.value()) {
            auto& target = output[*written];
            target.struct_size = sizeof(target);
            switch (row.kind) {
            case BlockEdgeKind::fallthrough: target.kind = HEXLAB_BLOCK_EDGE_FALLTHROUGH; break;
            case BlockEdgeKind::conditional_true: target.kind = HEXLAB_BLOCK_EDGE_CONDITIONAL_TRUE; break;
            case BlockEdgeKind::conditional_false: target.kind = HEXLAB_BLOCK_EDGE_CONDITIONAL_FALSE; break;
            case BlockEdgeKind::jump: target.kind = HEXLAB_BLOCK_EDGE_JUMP; break;
            case BlockEdgeKind::call_continuation: target.kind = HEXLAB_BLOCK_EDGE_CALL_CONTINUATION; break;
            case BlockEdgeKind::unresolved: target.kind = HEXLAB_BLOCK_EDGE_UNRESOLVED; break;
            case BlockEdgeKind::delay_slot: target.kind = HEXLAB_BLOCK_EDGE_DELAY_SLOT; break;
            case BlockEdgeKind::exception: target.kind = HEXLAB_BLOCK_EDGE_EXCEPTION; break;
            default: return -2;
            }
            target.source_space = row.source.space.value;
            target.source = row.source.offset;
            target.target_space = 0;
            target.target = 0;
            target.target_block_id = 0;
            target.has_target = row.target ? 1u : 0u;
            if (row.target) {
                target.target_space = row.target->space.value;
                target.target = row.target->offset;
            }
            target.has_block = row.block ? 1u : 0u;
            if (row.block) target.target_block_id = row.block->value;
            std::fill(std::begin(target.reserved), std::end(target.reserved), std::uint8_t{0});
            ++*written;
        }
        return 0;
    } catch (...) { return -2; }
}
std::shared_ptr<HostContext::DebuggerSession> debugger_handle(void* context, void* handle) {
    if (!context || !handle) return nullptr;
    auto* host = static_cast<HostContext*>(context);
    std::lock_guard lock(host->mutex);
    const auto found = host->debugger_sessions.find(handle);
    return found == host->debugger_sessions.end() ? nullptr : found->second;
}
bool debugger_page_args(std::uint64_t start, std::uint32_t capacity, const void* output,
                        const std::uint32_t* written) {
    return written && output && capacity && capacity <= HEXLAB_DEBUGGER_MAX_PAGE &&
           start <= std::numeric_limits<std::size_t>::max();
}
bool debugger_process_out(const debugger::ProcessInfo& source, HexLabDebugProcess& output) {
    if (output.struct_size < sizeof(output)) return false;
    output.struct_size = sizeof(output);
    output.architecture = static_cast<std::uint32_t>(source.architecture);
    output.id = source.id;
    return copy_field(output.name, source.name);
}
bool debugger_thread_out(const debugger::ThreadInfo& source, HexLabDebugThread& output) {
    if (output.struct_size < sizeof(output)) return false;
    output.struct_size = sizeof(output);
    output.state = static_cast<std::uint32_t>(source.state);
    output.id = source.id;
    return copy_field(output.name, source.name);
}
bool debugger_module_out(const debugger::ModuleInfo& source, HexLabDebugModule& output) {
    if (output.struct_size < sizeof(output)) return false;
    output.struct_size = sizeof(output);
    output.reserved = 0;
    output.base = source.base;
    output.size = source.size;
    return copy_field(output.name, source.name) && copy_field(output.path, source.path);
}
bool debugger_region_out(const debugger::MemoryRegion& source, HexLabDebugMemoryRegion& output) {
    if (output.struct_size < sizeof(output)) return false;
    output.struct_size = sizeof(output);
    output.readable = source.readable ? 1u : 0u;
    output.writable = source.writable ? 1u : 0u;
    output.executable = source.executable ? 1u : 0u;
    output.reserved = 0;
    output.start = source.start;
    output.length = source.length;
    return copy_field(output.type, source.type);
}
bool debugger_register_out(const debugger::RegisterValue& source, HexLabDebugRegister& output) {
    if (output.struct_size < sizeof(output) || source.bytes.empty() ||
        source.bytes.size() > sizeof(output.bytes) ||
        (source.byte_order && *source.byte_order != ByteOrder::little && *source.byte_order != ByteOrder::big))
        return false;
    output.struct_size = sizeof(output);
    output.byte_count = static_cast<std::uint32_t>(source.bytes.size());
    output.number = source.number;
    output.byte_order = !source.byte_order ? HEXLAB_DEBUGGER_BYTE_ORDER_UNKNOWN :
        *source.byte_order == ByteOrder::little ? HEXLAB_DEBUGGER_BYTE_ORDER_LITTLE : HEXLAB_DEBUGGER_BYTE_ORDER_BIG;
    output.reserved = 0;
    if (!copy_field(output.name, source.name) || !copy_field(output.group, source.group)) return false;
    for (std::size_t i = 0; i < source.bytes.size(); ++i)
        output.bytes[i] = std::to_integer<std::uint8_t>(source.bytes[i]);
    return true;
}
bool debugger_breakpoint_out(const debugger::Breakpoint& source, HexLabDebugBreakpoint& output) {
    if (output.struct_size < sizeof(output)) return false;
    output.struct_size = sizeof(output);
    output.kind = static_cast<std::uint32_t>(source.kind);
    output.id = source.id;
    output.address = source.address;
    output.enabled = source.enabled ? 1u : 0u;
    output.size = source.size;
    std::fill(std::begin(output.reserved), std::end(output.reserved), 0);
    return true;
}
int32_t debugger_create(void* context, std::uint32_t kind, void** result) {
    if (result) *result = nullptr;
    if (!context || !result) return -1;
    try {
        std::unique_ptr<debugger::Backend> backend;
        if (kind == HEXLAB_DEBUGGER_BACKEND_NATIVE)
            backend = debugger::make_backend_router(debugger::make_native_backend());
        else if (kind == HEXLAB_DEBUGGER_BACKEND_GDB_REMOTE)
            backend = debugger::make_remote_backend();
        else return -1;
        if (!backend) return -2;
        auto entry = std::make_shared<HostContext::DebuggerSession>(std::move(backend));
        auto* host = static_cast<HostContext*>(context);
        std::lock_guard lock(host->mutex);
        auto* token = entry.get();
        host->debugger_sessions.emplace(token, std::move(entry));
        *result = token;
        return 0;
    } catch (...) { return -2; }
}
void debugger_close(void* context, void* handle) {
    if (!context || !handle) return;
    auto* host = static_cast<HostContext*>(context);
    std::shared_ptr<HostContext::DebuggerSession> entry;
    {
        std::lock_guard lock(host->mutex);
        const auto found = host->debugger_sessions.find(handle);
        if (found == host->debugger_sessions.end()) return;
        entry = std::move(found->second);
        entry->closing.store(true, std::memory_order_release);
        host->debugger_sessions.erase(found);
    }
    std::unique_lock lock(entry->operations);
    entry->value.reset();
}
int32_t debugger_processes(void* context, void* handle, std::uint64_t start, std::uint32_t capacity,
                           HexLabDebugProcess* output, std::uint32_t* written) {
    if (written) *written = 0;
    if (!context || !debugger_page_args(start, capacity, output, written)) return -1;
    auto entry = debugger_handle(context, handle);
    if (!entry) return -1;
    std::unique_lock lock(entry->operations);
    if (entry->closing.load(std::memory_order_acquire) || !entry->value) return -1;
    auto* session = entry->value.get();
    try {
        auto rows = session->processes();
        if (!rows) return -2;
        if (start >= rows.value().size()) return 0;
        const auto count = std::min<std::size_t>(capacity, rows.value().size() - static_cast<std::size_t>(start));
        for (std::size_t i = 0; i < count; ++i)
            if (output[i].struct_size < sizeof(HexLabDebugProcess)) return -1;
        for (std::size_t i = 0; i < count; ++i) {
            if (!debugger_process_out(rows.value()[static_cast<std::size_t>(start) + i], output[i])) return -2;
            ++*written;
        }
        return 0;
    } catch (...) { return -2; }
}
int32_t debugger_launch(void* context, void* handle, const HexLabDebuggerTarget* input,
                        HexLabDebugProcess* output) {
    if (!context || !input || input->struct_size < sizeof(*input) || !input->executable ||
        !output || output->struct_size < sizeof(*output) || input->argument_count > HEXLAB_DEBUGGER_MAX_ARGUMENTS ||
        (input->argument_count && !input->arguments)) return -1;
    debugger::Target target;
    if (!copy_user_text(input->executable, HEXLAB_PROJECT_MAX_PATH - 1, target.executable) || target.executable.empty()) return -1;
    if (input->working_directory && !copy_user_text(input->working_directory, HEXLAB_PROJECT_MAX_PATH - 1, target.working_directory)) return -1;
    for (std::uint32_t i = 0; i < input->argument_count; ++i) {
        std::string argument;
        if (!copy_user_text(input->arguments[i], HEXLAB_PROJECT_MAX_PATH - 1, argument)) return -1;
        target.arguments.push_back(std::move(argument));
    }
    auto entry = debugger_handle(context, handle);
    if (!entry) return -1;
    std::unique_lock lock(entry->operations);
    if (entry->closing.load(std::memory_order_acquire) || !entry->value) return -1;
    auto* session = entry->value.get();
    try { auto result = session->launch(target); return result && debugger_process_out(result.value(), *output) ? 0 : -2; }
    catch (...) { return -2; }
}
int32_t debugger_attach(void* context, void* handle, std::uint64_t process_id, HexLabDebugProcess* output) {
    if (!context || !process_id || !output || output->struct_size < sizeof(*output)) return -1;
    auto entry = debugger_handle(context, handle);
    if (!entry) return -1;
    std::unique_lock lock(entry->operations);
    if (entry->closing.load(std::memory_order_acquire) || !entry->value) return -1;
    auto* session = entry->value.get();
    try { auto result = session->attach(process_id); return result && debugger_process_out(result.value(), *output) ? 0 : -2; }
    catch (...) { return -2; }
}
int32_t debugger_connect_remote(void* context, void* handle, const char* host_name,
                                std::uint16_t port, HexLabDebugProcess* output) {
    std::string host_text;
    if (!context || !port || !output || output->struct_size < sizeof(*output) ||
        !copy_user_text(host_name, 1024, host_text) || host_text.empty()) return -1;
    auto entry = debugger_handle(context, handle);
    if (!entry) return -1;
    std::unique_lock lock(entry->operations);
    if (entry->closing.load(std::memory_order_acquire) || !entry->value) return -1;
    auto* session = entry->value.get();
    try { auto result = session->connect_remote(host_text, port); return result && debugger_process_out(result.value(), *output) ? 0 : -2; }
    catch (...) { return -2; }
}
int32_t debugger_state(void* context, void* handle, std::uint32_t* state,
                       std::uint8_t* has_process, HexLabDebugProcess* output) {
    if (!context || !state || !has_process) return -1;
    auto entry = debugger_handle(context, handle);
    if (!entry) return -1;
    std::unique_lock lock(entry->operations);
    if (entry->closing.load(std::memory_order_acquire) || !entry->value) return -1;
    auto* session = entry->value.get();
    *state = static_cast<std::uint32_t>(session->state());
    const auto& process = session->process();
    *has_process = process ? 1u : 0u;
    if (process && (!output || output->struct_size < sizeof(*output))) return -1;
    if (process && !debugger_process_out(*process, *output)) return -2;
    return 0;
}
int32_t debugger_detach(void* context, void* handle) {
    if (!context) return -1;
    auto entry = debugger_handle(context, handle); if (!entry) return -1;
    std::unique_lock lock(entry->operations); if (entry->closing.load(std::memory_order_acquire) || !entry->value) return -1; auto* session = entry->value.get();
    try { return session->detach() ? 0 : -2; } catch (...) { return -2; }
}
int32_t debugger_interrupt(void* context, void* handle) {
    if (!context) return -1;
    auto entry = debugger_handle(context, handle); if (!entry) return -1;
    std::unique_lock lock(entry->operations);
    if (entry->closing.load(std::memory_order_acquire) || !entry->value) return -1;
    auto* session = entry->value.get();
    try { return session->request_interrupt() ? 0 : -2; } catch (...) { return -2; }
}
int32_t debugger_wait_event(void* context, void* handle, std::uint32_t timeout_ms, HexLabDebugEvent* output) {
    if (!context || timeout_ms > HEXLAB_DEBUGGER_MAX_WAIT_MS || !output || output->struct_size < sizeof(*output)) return -1;
    auto entry = debugger_handle(context, handle); if (!entry) return -1;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    do {
        const auto now = std::chrono::steady_clock::now();
        const auto remaining = now < deadline
            ? std::max(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now),
                       std::chrono::milliseconds(1))
            : std::chrono::milliseconds::zero();
        const auto slice = std::min(remaining, std::chrono::milliseconds(50));
        std::unique_lock lock(entry->operations);
        if (entry->closing.load(std::memory_order_acquire) || !entry->value) return -1;
        try {
            auto event = entry->value->wait_event(slice);
            if (event) {
                output->struct_size = sizeof(*output); output->kind = static_cast<std::uint32_t>(event.value().kind);
                output->sequence = event.value().sequence; output->process = event.value().process;
                output->thread = event.value().thread; output->address = event.value().address;
                output->code = event.value().code;
                output->first_chance_present = event.value().first_chance ? 1u : 0u;
                output->first_chance = event.value().first_chance.value_or(false) ? 1u : 0u;
                std::fill(std::begin(output->reserved), std::end(output->reserved), 0);
                // The stable plugin ABI keeps a 256-byte event message field,
                // while the core may aggregate up to 4096 bytes. Preserve the
                // event and report a visibly bounded prefix to older clients.
                constexpr std::string_view marker = "...[truncated]";
                constexpr auto capacity = sizeof(output->message) - 1;
                const auto& message = event.value().message;
                auto count = std::min(message.size(), capacity);
                if (message.size() > capacity) {
                    const auto content_limit = capacity - marker.size();
                    count = std::min(count, content_limit);
                    while (count && count < message.size() &&
                           (static_cast<unsigned char>(message[count]) & 0xc0u) == 0x80u)
                        --count;
                    std::memcpy(output->message, message.data(), count);
                    std::memcpy(output->message + count, marker.data(), marker.size());
                    output->message[count + marker.size()] = '\0';
                    return 0;
                }
                std::memcpy(output->message, message.data(), count);
                output->message[count] = '\0';
                return 0;
            }
            if (event.error().code != ErrorCode::busy ||
                event.error().message.find("timed out") == std::string::npos) return -2;
        } catch (...) { return -2; }
        lock.unlock();
    } while (std::chrono::steady_clock::now() < deadline);
    return -2;
}
int32_t debugger_continue(void* context, void* handle, std::uint64_t sequence, std::uint32_t status) {
    if (!context || status > HEXLAB_DEBUGGER_CONTINUE_NOT_HANDLED) return -1;
    auto entry = debugger_handle(context, handle); if (!entry) return -1;
    std::unique_lock lock(entry->operations); if (entry->closing.load(std::memory_order_acquire) || !entry->value) return -1; auto* session = entry->value.get();
    try { return session->continue_execution(sequence, static_cast<debugger::ContinueStatus>(status)) ? 0 : -2; }
    catch (...) { return -2; }
}
int32_t debugger_single_step(void* context, void* handle, std::uint64_t sequence, std::uint32_t status) {
    if (!context || status > HEXLAB_DEBUGGER_CONTINUE_NOT_HANDLED) return -1;
    auto entry = debugger_handle(context, handle); if (!entry) return -1;
    std::unique_lock lock(entry->operations); if (entry->closing.load(std::memory_order_acquire) || !entry->value) return -1; auto* session = entry->value.get();
    try { return session->single_step_execution(sequence, static_cast<debugger::ContinueStatus>(status)) ? 0 : -2; }
    catch (...) { return -2; }
}
template<class Source, class Output, class Query>
int32_t debugger_page(void* context, void* handle, std::uint64_t start, std::uint32_t capacity,
                      Output* output, std::uint32_t* written, Query&& query, bool ( *convert)(const Source&, Output&)) {
    if (written) *written = 0;
    if (!context || !debugger_page_args(start, capacity, output, written)) return -1;
    auto entry = debugger_handle(context, handle); if (!entry) return -1;
    std::unique_lock lock(entry->operations); if (entry->closing.load(std::memory_order_acquire) || !entry->value) return -1; auto* session = entry->value.get();
    try {
        auto rows = query(*session); if (!rows) return -2;
        if (start >= rows.value().size()) return 0;
        const auto count = std::min<std::size_t>(capacity, rows.value().size() - static_cast<std::size_t>(start));
        for (std::size_t i=0;i<count;++i) if(output[i].struct_size<sizeof(Output)) return -1;
        for(std::size_t i=0;i<count;++i){if(!convert(rows.value()[static_cast<std::size_t>(start)+i],output[i]))return -2;++*written;}
        return 0;
    } catch (...) { return -2; }
}
int32_t debugger_threads(void* c, void* h, std::uint64_t s, std::uint32_t n, HexLabDebugThread* o, std::uint32_t* w) {
    return debugger_page<debugger::ThreadInfo>(c,h,s,n,o,w,[](debugger::DebugSession& x){return x.threads();},debugger_thread_out);
}
int32_t debugger_modules(void* c, void* h, std::uint64_t s, std::uint32_t n, HexLabDebugModule* o, std::uint32_t* w) {
    return debugger_page<debugger::ModuleInfo>(c,h,s,n,o,w,[](debugger::DebugSession& x){return x.modules();},debugger_module_out);
}
int32_t debugger_regions(void* c, void* h, std::uint64_t s, std::uint32_t n, HexLabDebugMemoryRegion* o, std::uint32_t* w) {
    return debugger_page<debugger::MemoryRegion>(c,h,s,n,o,w,[](debugger::DebugSession& x){return x.memory_regions();},debugger_region_out);
}
int32_t debugger_read_memory(void* context, void* handle, std::uint64_t address, std::uint32_t size, std::uint8_t* output) {
    if (!context || size > HEXLAB_DEBUGGER_MAX_IO || (size && !output) || address > UINT64_MAX - size) return -1;
    auto entry = debugger_handle(context, handle); if (!entry) return -1;
    std::unique_lock lock(entry->operations); if (entry->closing.load(std::memory_order_acquire) || !entry->value) return -1; auto* session = entry->value.get();
    try { auto bytes=session->read_memory(address,size); if(!bytes || bytes.value().size()!=size)return -2;
        for(std::size_t i=0;i<size;++i)output[i]=std::to_integer<std::uint8_t>(bytes.value()[i]); return 0; }
    catch (...) { return -2; }
}
int32_t debugger_write_memory(void* context, void* handle, std::uint64_t address, std::uint32_t size, const std::uint8_t* input) {
    if (!context || size > HEXLAB_DEBUGGER_MAX_IO || (size && !input) || address > UINT64_MAX - size) return -1;
    std::vector<std::byte> bytes(size); for(std::size_t i=0;i<size;++i)bytes[i]=static_cast<std::byte>(input[i]);
    auto entry = debugger_handle(context, handle); if (!entry) return -1;
    std::unique_lock lock(entry->operations); if (entry->closing.load(std::memory_order_acquire) || !entry->value) return -1; auto* session = entry->value.get();
    try { return session->write_memory(address, bytes) ? 0 : -2; } catch (...) { return -2; }
}
int32_t debugger_read_registers(void* context, void* handle, std::uint64_t thread, std::uint64_t start,
                                std::uint32_t capacity, HexLabDebugRegister* output, std::uint32_t* written) {
    if (written) *written=0;
    if (!context || !thread || !debugger_page_args(start,capacity,output,written)) return -1;
    auto entry=debugger_handle(context,handle); if(!entry)return -1;
    std::unique_lock lock(entry->operations); if(entry->closing.load(std::memory_order_acquire)||!entry->value)return -1; auto* session=entry->value.get();
    try { auto rows=session->read_registers(thread); if(!rows)return -2;
        if(start>=rows.value().size())return 0;
        const auto count=std::min<std::size_t>(capacity,rows.value().size()-static_cast<std::size_t>(start));
        for(std::size_t i=0;i<count;++i)if(output[i].struct_size<sizeof(HexLabDebugRegister))return -1;
        for(std::size_t i=0;i<count;++i){if(!debugger_register_out(rows.value()[static_cast<std::size_t>(start)+i],output[i]))return -2;++*written;}return 0;
    } catch(...) { return -2; }
}
int32_t debugger_write_registers(void* context, void* handle, std::uint64_t thread,
                                 std::uint32_t count, const HexLabDebugRegister* input) {
    if(!context||!thread||!count||count>HEXLAB_DEBUGGER_MAX_PAGE||!input)return -1;
    std::vector<debugger::RegisterValue> registers; registers.reserve(count);
    for(std::uint32_t i=0;i<count;++i){const auto& row=input[i];std::string name,group;
        if(row.struct_size<sizeof(row)||row.reserved||!row.byte_count||row.byte_count>sizeof(row.bytes)||
           row.byte_order>HEXLAB_DEBUGGER_BYTE_ORDER_BIG||!copy_fixed_string(row.name,sizeof(row.name),name)||!copy_fixed_string(row.group,sizeof(row.group),group))return -1;
        debugger::RegisterValue value;value.name=std::move(name);value.group=std::move(group);value.number=row.number;
        if(row.byte_order!=HEXLAB_DEBUGGER_BYTE_ORDER_UNKNOWN)value.byte_order=row.byte_order==HEXLAB_DEBUGGER_BYTE_ORDER_LITTLE?ByteOrder::little:ByteOrder::big;
        value.bytes.reserve(row.byte_count);for(std::uint32_t b=0;b<row.byte_count;++b)value.bytes.push_back(static_cast<std::byte>(row.bytes[b]));registers.push_back(std::move(value));
    }
    auto entry=debugger_handle(context,handle);if(!entry)return -1;std::unique_lock lock(entry->operations);if(entry->closing.load(std::memory_order_acquire)||!entry->value)return -1;auto* session=entry->value.get();
    try{return session->write_registers(thread,registers)?0:-2;}catch(...){return -2;}
}
int32_t debugger_add_breakpoint(void* context, void* handle, std::uint64_t address,
                                std::uint32_t kind, std::uint8_t size, HexLabDebugBreakpoint* output) {
    if(!context||kind>HEXLAB_DEBUGGER_BREAKPOINT_ACCESS||!output||output->struct_size<sizeof(*output))return -1;
    auto entry=debugger_handle(context,handle);if(!entry)return -1;std::unique_lock lock(entry->operations);if(entry->closing.load(std::memory_order_acquire)||!entry->value)return -1;auto* session=entry->value.get();
    try{auto result=session->add_breakpoint(address,static_cast<debugger::BreakpointKind>(kind),size);return result&&debugger_breakpoint_out(result.value(),*output)?0:-2;}catch(...){return -2;}
}
int32_t debugger_remove_breakpoint(void* context, void* handle, std::uint64_t id) {
    if(!context||!id)return -1;auto entry=debugger_handle(context,handle);if(!entry)return -1;std::unique_lock lock(entry->operations);if(entry->closing.load(std::memory_order_acquire)||!entry->value)return -1;auto* session=entry->value.get();
    try{return session->remove_breakpoint(id)?0:-2;}catch(...){return -2;}
}
int32_t debugger_enable_breakpoint(void* context, void* handle, std::uint64_t id, std::uint8_t enabled) {
    if(!context||!id||enabled>1)return -1;auto entry=debugger_handle(context,handle);if(!entry)return -1;std::unique_lock lock(entry->operations);if(entry->closing.load(std::memory_order_acquire)||!entry->value)return -1;auto* session=entry->value.get();
    try{return session->set_breakpoint_enabled(id,enabled!=0)?0:-2;}catch(...){return -2;}
}
int32_t debugger_breakpoints(void* context, void* handle, std::uint64_t start, std::uint32_t capacity,
                             HexLabDebugBreakpoint* output, std::uint32_t* written) {
    if(written)*written=0;if(!context||!debugger_page_args(start,capacity,output,written))return -1;
    auto entry=debugger_handle(context,handle);if(!entry)return -1;std::unique_lock lock(entry->operations);if(entry->closing.load(std::memory_order_acquire)||!entry->value)return -1;auto* session=entry->value.get();
    try{auto rows=session->breakpoints();if(start>=rows.size())return 0;const auto count=std::min<std::size_t>(capacity,rows.size()-static_cast<std::size_t>(start));
        for(std::size_t i=0;i<count;++i)if(output[i].struct_size<sizeof(HexLabDebugBreakpoint))return -1;
        for(std::size_t i=0;i<count;++i){if(!debugger_breakpoint_out(rows[static_cast<std::size_t>(start)+i],output[i]))return -2;++*written;}return 0;
    }catch(...){return -2;}
}
int32_t debugger_set_breakpoint_ignore_count(void* context, void* handle, std::uint64_t id,
                                            std::uint64_t ignore_count) {
    if (!context || !id) return -1;
    auto entry = debugger_handle(context, handle); if (!entry) return -1;
    std::unique_lock lock(entry->operations);
    if (entry->closing.load(std::memory_order_acquire) || !entry->value) return -1;
    try { return entry->value->set_breakpoint_ignore_count(id, ignore_count) ? 0 : -2; }
    catch (...) { return -2; }
}
int32_t debugger_set_breakpoint_condition(void* context, void* handle, std::uint64_t id,
                                          const char* expression) {
    std::string value;
    if (!context || !id || !copy_user_text(expression, 256, value)) return -1;
    auto entry = debugger_handle(context, handle); if (!entry) return -1;
    std::unique_lock lock(entry->operations);
    if (entry->closing.load(std::memory_order_acquire) || !entry->value) return -1;
    try { return entry->value->set_breakpoint_condition(id, std::move(value)) ? 0 : -2; }
    catch (...) { return -2; }
}
int32_t debugger_set_breakpoint_logpoint(void* context, void* handle, std::uint64_t id,
                                         std::uint8_t enabled, const char* message) {
    std::string value;
    if (!context || !id || enabled > 1 || !copy_user_text(message, 1024, value)) return -1;
    auto entry = debugger_handle(context, handle); if (!entry) return -1;
    std::unique_lock lock(entry->operations);
    if (entry->closing.load(std::memory_order_acquire) || !entry->value) return -1;
    try { return entry->value->set_breakpoint_logpoint(id, enabled != 0, std::move(value)) ? 0 : -2; }
    catch (...) { return -2; }
}
int32_t debugger_breakpoint_rule(void* context, void* handle, std::uint64_t id,
                                 HexLabDebugBreakpointRule* output) {
    if (!context || !id || !output || output->struct_size < sizeof(*output)) return -1;
    auto entry = debugger_handle(context, handle); if (!entry) return -1;
    std::unique_lock lock(entry->operations);
    if (entry->closing.load(std::memory_order_acquire) || !entry->value) return -1;
    try {
        const auto rows = entry->value->breakpoints();
        const auto found = std::find_if(rows.begin(), rows.end(), [id](const auto& row) { return row.id == id; });
        if (found == rows.end()) return -2;
        output->struct_size = sizeof(*output);
        output->reserved = 0;
        output->id = found->id;
        output->hit_count = found->hit_count;
        output->ignore_count = found->ignore_count;
        output->logpoint = found->logpoint ? 1u : 0u;
        std::fill(std::begin(output->reserved_flags), std::end(output->reserved_flags), 0);
        if (!copy_field(output->condition, found->condition) ||
            !copy_field(output->log_message, found->log_message)) return -2;
        return 0;
    } catch (...) { return -2; }
}
void host_log(void*, std::uint32_t, const char*) {}
int32_t host_register_action_impl(void* context, const char* menu_path, const char* id, const char* label,
                                  void* action_context, void (*invoke)(void*)) {
    if (!context || !id || !label || !invoke) return -1;
    auto* actions = &static_cast<HostContext*>(context)->actions;
    RegisteredAction action;
    if (!copy_string(id, action.id) || !copy_string(label, action.label) || actions->size() >= max_actions)
        return -1;
    if (menu_path && (!copy_string(menu_path, action.menu_path) || !valid_menu_path(action.menu_path))) return -1;
    if (std::any_of(actions->begin(), actions->end(), [&](const auto& item) { return item.id == action.id; }))
        return -1;
    action.context = action_context;
    action.invoke = invoke;
    actions->push_back(std::move(action));
    return 0;
}
int32_t host_register_action(void* context, const char* id, const char* label,
                             void* action_context, void (*invoke)(void*)) {
    return host_register_action_impl(context, nullptr, id, label, action_context, invoke);
}
int32_t host_register_menu_action(void* context, const char* menu_path, const char* id, const char* label,
                                  void* action_context, void (*invoke)(void*)) {
    return host_register_action_impl(context, menu_path, id, label, action_context, invoke);
}
}

PluginManager::PluginManager(std::shared_ptr<ModuleProvider> provider)
    : impl_(std::make_shared<Impl>(std::move(provider))) {}
PluginManager::~PluginManager() = default;
PluginManager::PluginManager(PluginManager&&) noexcept = default;
PluginManager& PluginManager::operator=(PluginManager&&) noexcept = default;

Result<PluginCandidate::Manifest> read_manifest(const std::string& path) {
    if (path.empty()) return invalid("plugin manifest path is empty");
    try {
        const auto manifest_path = std::filesystem::u8path(path);
        std::error_code ec;
        const auto status = std::filesystem::symlink_status(manifest_path, ec);
        if (ec) return Error{ErrorCode::io, "cannot inspect plugin manifest: " + ec.message()};
        if (std::filesystem::is_symlink(status) || !std::filesystem::is_regular_file(status))
            return invalid("plugin manifest must be a regular, non-symlink file");
        const auto size = std::filesystem::file_size(manifest_path, ec);
        if (ec) return Error{ErrorCode::io, "cannot size plugin manifest: " + ec.message()};
        if (size == 0 || size > max_manifest_bytes)
            return Error{ErrorCode::resource_limit, "plugin manifest size is outside the supported range"};
        std::ifstream input(manifest_path, std::ios::binary);
        if (!input) return Error{ErrorCode::io, "cannot open plugin manifest"};
        std::string bytes(static_cast<std::size_t>(size), '\0');
        input.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        if (!input || input.peek() != std::char_traits<char>::eof())
            return Error{ErrorCode::io, "plugin manifest changed or could not be read completely"};
        if (bytes.find('\0') != std::string::npos)
            return invalid("plugin manifest contains a NUL byte");
        return parse_plugin_manifest(bytes);
    } catch (const std::filesystem::filesystem_error& error) {
        return Error{ErrorCode::io, std::string("plugin manifest read failed: ") + error.what()};
    } catch (...) {
        return Error{ErrorCode::io, "plugin manifest read failed"};
    }
}

bool manifest_matches(const PluginCandidate::Manifest& manifest, const PluginInfo& loaded) {
    if (manifest.id != loaded.id || manifest.name != loaded.name || manifest.version != loaded.version ||
        manifest.capabilities.size() != loaded.declared_capabilities.size() ||
        manifest.required_capabilities.size() != loaded.required_capabilities.size()) return false;
    for (const auto& expected : manifest.capabilities) {
        const auto found = std::find_if(loaded.declared_capabilities.begin(), loaded.declared_capabilities.end(),
            [&](const auto& actual) {
                return actual.id == expected.id && actual.major_version == expected.major_version &&
                       actual.minor_version == expected.minor_version && actual.flags == expected.flags;
            });
        if (found == loaded.declared_capabilities.end()) return false;
    }
    for (const auto& expected : manifest.required_capabilities) {
        const auto found = std::find_if(loaded.required_capabilities.begin(), loaded.required_capabilities.end(),
            [&](const auto& actual) {
                return actual.id == expected.id && actual.major_version == expected.major_version &&
                       actual.minor_version == expected.minor_version && actual.flags == expected.flags;
            });
        if (found == loaded.required_capabilities.end()) return false;
    }
    return true;
}

void PluginManager::set_active_document_services(ActiveDocumentServices services) {
    if (!impl_ || !impl_->active_document_services) return;
    std::lock_guard lock(impl_->active_document_services->mutex);
    impl_->active_document_services->services = std::move(services);
}
void PluginManager::set_active_debugger_services(ActiveDebuggerServices services) {
    if (!impl_ || !impl_->active_debugger_services) return;
    std::lock_guard lock(impl_->active_debugger_services->mutex);
    impl_->active_debugger_services->services = std::move(services);
}
void PluginManager::set_active_project_breakpoint_services(ActiveProjectBreakpointServices services) {
    if (!impl_ || !impl_->active_project_breakpoint_services) return;
    std::lock_guard lock(impl_->active_project_breakpoint_services->mutex);
    impl_->active_project_breakpoint_services->services = std::move(services);
}

Result<PluginInfo> PluginManager::load(const std::string& path) {
    if (!impl_ || !impl_->provider || path.empty() || path.size() > 32768 || path.find('\0') != std::string::npos)
        return invalid("plugin path or module provider is missing or invalid");
    std::lock_guard manager_lock(impl_->mutex);
    return load_locked(path);
}

Result<PluginInfo> PluginManager::load_locked(
    const std::string& path, const PluginCandidate::Manifest* expected) {
    if(impl_->scalar_ir_callback_depth)return Error{ErrorCode::busy,"Cannot load plugins during a scalar IR callback"};
    auto opened = impl_->provider->open(path);
    if (!opened) return opened.error();
    Impl::Loaded candidate;
    candidate.module = opened.value();
    if (!candidate.module.handle || !candidate.module.lookup || !candidate.module.close)
        return Error{ErrorCode::malformed, "module provider returned an incomplete module"};
    auto* query_raw = candidate.module.lookup(candidate.module.handle, HEXLAB_PLUGIN_QUERY_SYMBOL);
    if (!query_raw) return Error{ErrorCode::malformed, "plugin query entry point is missing"};
    const auto query = reinterpret_cast<HexLabPluginQuery>(query_raw);
    HexLabPluginApi api{};
    api.struct_size = sizeof(api);
    candidate.host->struct_size = sizeof(HexLabHostApi);
    candidate.host->abi_major = HEXLAB_PLUGIN_ABI_MAJOR;
    candidate.host->abi_minor = HEXLAB_PLUGIN_ABI_MINOR;
    candidate.host->declared_capabilities = host_capabilities.data();
    candidate.host->declared_capability_count = static_cast<std::uint32_t>(host_capabilities.size());
    candidate.host->host_context = candidate.context.get();
    candidate.host->log = host_log;
    candidate.host->register_action = host_register_action;
    candidate.host->register_menu_action = host_register_menu_action;
    candidate.host->register_loader_extension = host_register_loader;
    candidate.host->register_processor_extension = host_register_processor;
    candidate.host->register_analysis_provider = host_register_analysis_provider;
    candidate.context->active_document_services = impl_->active_document_services;
    candidate.context->active_document_api = HexLabActiveDocumentApi{
        sizeof(HexLabActiveDocumentApi), HEXLAB_ACTIVE_DOCUMENT_API_VERSION,
        candidate.context->active_document_services.get(), active_document_query,
        active_document_read, active_document_navigate};
    candidate.host->active_document_api = &candidate.context->active_document_api;
    candidate.context->active_debugger_services = impl_->active_debugger_services;
    candidate.context->active_debugger_api = HexLabActiveDebuggerApi{
        sizeof(HexLabActiveDebuggerApi), HEXLAB_ACTIVE_DEBUGGER_API_VERSION,
        candidate.context->active_debugger_services.get(), active_debugger_query,
        active_debugger_threads, active_debugger_registers, active_debugger_memory};
    candidate.host->active_debugger_api = &candidate.context->active_debugger_api;
    candidate.context->active_project_breakpoint_services = impl_->active_project_breakpoint_services;
    candidate.context->active_project_breakpoint_api = HexLabActiveProjectBreakpointApi{
        sizeof(HexLabActiveProjectBreakpointApi), HEXLAB_ACTIVE_PROJECT_BREAKPOINT_API_VERSION,
        candidate.context->active_project_breakpoint_services.get(), active_project_breakpoint_snapshot,
        active_project_breakpoints_query,
        active_project_breakpoint_set};
    candidate.host->active_project_breakpoint_api = &candidate.context->active_project_breakpoint_api;
    candidate.context->project_api = HexLabProjectApi{sizeof(HexLabProjectApi), HEXLAB_PROJECT_API_VERSION,
        candidate.context.get(), project_create, project_open, project_close, project_analyze,
        project_summary, project_functions, project_instructions, project_references, project_strings,
        project_rename, project_comment, project_bookmark, project_read,
        project_import_header, project_types, project_assign_type, project_declarations, project_enum_values,
        project_function_blocks, project_block_instructions, project_block_successors};
    candidate.host->project_api = &candidate.context->project_api;
    candidate.context->debugger_api = HexLabDebuggerApi{sizeof(HexLabDebuggerApi), HEXLAB_DEBUGGER_API_VERSION,
        candidate.context.get(), debugger_create, debugger_close, debugger_processes, debugger_launch,
        debugger_attach, debugger_connect_remote, debugger_state, debugger_detach, debugger_interrupt,
        debugger_wait_event, debugger_continue, debugger_single_step, debugger_threads, debugger_modules,
        debugger_regions, debugger_read_memory, debugger_write_memory, debugger_read_registers,
        debugger_write_registers, debugger_add_breakpoint, debugger_remove_breakpoint,
        debugger_enable_breakpoint, debugger_breakpoints, debugger_set_breakpoint_ignore_count,
        debugger_set_breakpoint_condition, debugger_set_breakpoint_logpoint,
        debugger_breakpoint_rule};
    candidate.host->debugger_api = &candidate.context->debugger_api;
    int32_t query_status = -1;
    try { query_status = query(HEXLAB_PLUGIN_ABI_MAJOR, candidate.host.get(), &api); }
    catch (...) { return Error{ErrorCode::io, "plugin query entry point raised an exception"}; }
    if (query_status != 0)
        return Error{ErrorCode::unsupported, "plugin rejected the host ABI"};
    constexpr std::size_t required_size = offsetof(HexLabPluginApi, stop) + sizeof(api.stop);
    if (api.struct_size < required_size || api.abi_major != HEXLAB_PLUGIN_ABI_MAJOR ||
        !api.start || !api.stop || api.capability_count > max_capabilities ||
        (api.capability_count != 0 && !api.capabilities))
        return Error{ErrorCode::unsupported, "plugin API layout or ABI is incompatible"};
    if (!copy_string(api.plugin_id, candidate.info.id) || !copy_string(api.name, candidate.info.name) ||
        !copy_string(api.version, candidate.info.version))
        return Error{ErrorCode::malformed, "plugin metadata is missing or exceeds limits"};
    for (std::uint32_t i = 0; i < api.capability_count; ++i) {
        std::string capability;
        if (!copy_string(api.capabilities[i], capability))
            return Error{ErrorCode::malformed, "plugin capability is missing or exceeds limits"};
        if (std::find(candidate.info.capabilities.begin(), candidate.info.capabilities.end(), capability) != candidate.info.capabilities.end())
            return Error{ErrorCode::malformed, "plugin declares a duplicate capability"};
        candidate.info.capabilities.push_back(std::move(capability));
    }
    constexpr std::size_t versioned_capabilities_offset = offsetof(HexLabPluginApi, declared_capabilities);
    constexpr std::size_t versioned_capabilities_end =
        offsetof(HexLabPluginApi, declared_capability_count) + sizeof(api.declared_capability_count);
    if (api.struct_size > versioned_capabilities_offset && api.struct_size < versioned_capabilities_end)
        return Error{ErrorCode::malformed, "plugin versioned capability table is truncated"};
    if (api.struct_size >= versioned_capabilities_end) {
        if (api.declared_capability_count > max_capabilities ||
            (api.declared_capability_count != 0 && !api.declared_capabilities))
            return Error{ErrorCode::malformed, "plugin versioned capability table is invalid"};
        std::unordered_set<std::string> declared_ids;
        for (std::uint32_t i = 0; i < api.declared_capability_count; ++i) {
            const auto& declaration = api.declared_capabilities[i];
            constexpr auto required_capability_size = offsetof(HexLabCapability, capability_id) +
                                                       sizeof(declaration.capability_id);
            PluginInfo::VersionedCapability copied;
            if (declaration.struct_size < required_capability_size || declaration.major_version == 0 ||
                !copy_string(declaration.capability_id, copied.id) ||
                !declared_ids.insert(copied.id).second)
                return Error{ErrorCode::malformed, "plugin versioned capability declaration is invalid"};
            copied.major_version = declaration.major_version;
            copied.minor_version = declaration.minor_version;
            copied.flags = declaration.flags;
            candidate.info.declared_capabilities.push_back(std::move(copied));
        }
    }
    constexpr std::size_t required_capabilities_offset = offsetof(HexLabPluginApi, required_capabilities);
    constexpr std::size_t required_capabilities_end =
        offsetof(HexLabPluginApi, required_capability_count) + sizeof(api.required_capability_count);
    if (api.struct_size > required_capabilities_offset && api.struct_size < required_capabilities_end)
        return Error{ErrorCode::malformed, "plugin required-capability table is truncated"};
    if (api.struct_size >= required_capabilities_end) {
        if (api.required_capability_count > max_capabilities ||
            (api.required_capability_count != 0 && !api.required_capabilities))
            return Error{ErrorCode::malformed, "plugin required-capability table is invalid"};
        std::unordered_set<std::string> required_ids;
        for (std::uint32_t i = 0; i < api.required_capability_count; ++i) {
            const auto& requirement = api.required_capabilities[i];
            constexpr auto required_record_size = offsetof(HexLabCapability, capability_id) +
                                                   sizeof(requirement.capability_id);
            PluginInfo::VersionedCapability copied;
            if (requirement.struct_size < required_record_size || requirement.major_version == 0 ||
                requirement.flags != 0 || !copy_string(requirement.capability_id, copied.id) ||
                !required_ids.insert(copied.id).second)
                return Error{ErrorCode::malformed, "plugin required-capability entry is invalid"};
            copied.major_version = requirement.major_version;
            copied.minor_version = requirement.minor_version;
            copied.flags = 0;
            const auto available = std::find_if(host_capabilities.begin(), host_capabilities.end(),
                [&](const auto& capability) {
                    return copied.id == capability.capability_id &&
                           copied.major_version == capability.major_version &&
                           capability.minor_version >= copied.minor_version;
                });
            if (available == host_capabilities.end()) {
                const PluginManager::Impl::Loaded* provider = nullptr;
                for (const auto& loaded : impl_->loaded) {
                    const auto declared = std::find_if(loaded.info.declared_capabilities.begin(),
                        loaded.info.declared_capabilities.end(), [&](const auto& capability) {
                            return copied.id == capability.id &&
                                   copied.major_version == capability.major_version &&
                                   capability.minor_version >= copied.minor_version;
                        });
                    if (declared == loaded.info.declared_capabilities.end()) continue;
                    if (provider)
                        return Error{ErrorCode::conflict, "plugin capability " + copied.id + " v" +
                            std::to_string(copied.major_version) + "." + std::to_string(copied.minor_version) +
                            " has multiple loaded providers"};
                    provider = &loaded;
                }
                if (!provider)
                    return Error{ErrorCode::unsupported, "plugin requires unavailable capability " + copied.id +
                        " v" + std::to_string(copied.major_version) + "." + std::to_string(copied.minor_version)};
                if (std::find(candidate.info.resolved_dependencies.begin(),
                              candidate.info.resolved_dependencies.end(), provider->info.id) ==
                    candidate.info.resolved_dependencies.end())
                    candidate.info.resolved_dependencies.push_back(provider->info.id);
            }
            candidate.info.required_capabilities.push_back(std::move(copied));
        }
    }
    if (std::any_of(impl_->loaded.begin(), impl_->loaded.end(), [&](const auto& item) { return item.info.id == candidate.info.id; }))
        return Error{ErrorCode::conflict, "plugin ID is already loaded"};
    if (expected && !manifest_matches(*expected, candidate.info))
        return Error{ErrorCode::integrity, "plugin metadata does not match activation manifest for " + expected->id};
    candidate.context->plugin_id = candidate.info.id;
    candidate.context->accepting_extensions = true;
    candidate.stop = api.stop;
    int32_t start_status = -1;
    bool start_threw = false;
    try { start_status = api.start(candidate.host.get(), &candidate.instance); }
    catch (...) { start_threw = true; }
    {
        std::lock_guard context_lock(candidate.context->mutex);
        candidate.context->accepting_extensions = false;
    }
    if (start_threw)
        return Error{ErrorCode::io, "plugin initialization raised an exception"};
    if (start_status != 0) {
        return Error{ErrorCode::io, "plugin initialization failed with status " + std::to_string(start_status)};
    }
    auto info = candidate.info;
    for (const auto& extension : candidate.context->loaders) {
        if (!extension.load_image) continue;
        PluginImageIdentity identity{info.id, info.version, extension.id, extension.format_id, extension.image_api_version};
        std::weak_ptr<Impl> owner = impl_;
        auto registered = register_plugin_image_provider(identity,
            [owner, identity](std::shared_ptr<const ByteStorage> storage, std::stop_token stop) -> Result<LoadedImage> {
                auto active = owner.lock();
                if (!active) return Error{ErrorCode::unsupported, "Plugin image provider owner has expired"};
                return PluginManager(std::move(active)).load_plugin_image(std::move(storage), identity, stop);
            },
            [owner, identity](std::span<const std::byte> prefix, std::uint64_t total,
                              std::stop_token stop) -> Result<std::optional<std::uint32_t>> {
                auto active = owner.lock();
                if (!active) return Error{ErrorCode::unsupported, "Plugin image probe owner has expired"};
                std::unique_lock lock(active->mutex, std::try_to_lock);
                if (!lock.owns_lock()) return Error{ErrorCode::busy, "Plugin image probe manager is busy"};
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Plugin image probe canceled"};
                for (const auto& plugin : active->loaded) {
                    if (plugin.info.id != identity.plugin_id || plugin.info.version != identity.plugin_version) continue;
                    for (auto& extension : plugin.context->loaders) {
                        if (extension.id != identity.extension_id || extension.format_id != identity.format_id ||
                            extension.image_api_version != identity.api_version || !extension.load_image ||
                            extension.disabled) continue;
                        std::uint32_t confidence = 0;
                        int32_t status = -1;
                        try {
                            status = extension.probe(extension.extension_context,
                                reinterpret_cast<const uint8_t*>(prefix.data()),
                                static_cast<std::uint32_t>(prefix.size()), total, &confidence);
                        } catch (...) { status = -1; }
                        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Plugin image probe canceled"};
                        if (status == 0) return std::optional<std::uint32_t>{};
                        if (status < 0 || (status != 0 && (status != 1 || confidence > 1000))) {
                            active->quarantine(extension, "loader probe callback failed or returned an invalid result");
                            return std::optional<std::uint32_t>{};
                        }
                        return std::optional<std::uint32_t>{confidence};
                    }
                }
                return Error{ErrorCode::unsupported, "Exact plugin image probe is unavailable"};
            });
        if (!registered) return registered.error();
        candidate.image_providers.push_back(std::move(registered.value()));
    }
    impl_->loaded.push_back(std::move(candidate));
    ++impl_->semantic_generation;
    std::atomic_store(&impl_->semantic_identity, impl_->make_semantic_identity_locked());
    return info;
}

Result<std::vector<PluginCandidate>> PluginManager::plan_activation(
    std::span<const PluginCandidate> candidates, const std::string& root_path) const {
    if (!impl_) return invalid("plugin manager is unavailable");
    std::lock_guard lock(impl_->mutex);
    return plan_activation_locked(candidates, root_path);
}

Result<std::vector<PluginCandidate>> PluginManager::plan_activation_locked(
    std::span<const PluginCandidate> candidates, const std::string& root_path) const {
    constexpr std::size_t max_candidates = 4096, max_activation = 256;
    if (root_path.empty() || candidates.empty()) return invalid("activation requires a selected candidate");
    if (candidates.size() > max_candidates)
        return Error{ErrorCode::resource_limit, "plugin activation candidate limit exceeded"};

    using CapabilityKey = std::pair<std::string, std::uint32_t>;
    std::map<CapabilityKey, std::vector<std::size_t>> providers;
    std::map<std::string, std::size_t> identity_counts;
    std::unordered_set<std::string> paths, loaded_ids;
    for (const auto& plugin : impl_->loaded) loaded_ids.insert(plugin.info.id);
    std::size_t root = candidates.size();
    for (std::size_t index = 0; index < candidates.size(); ++index) {
        const auto& candidate = candidates[index];
        if (candidate.path.empty() || candidate.path.size() > 32768 || candidate.path.find('\0') != std::string::npos ||
            !paths.insert(candidate.path).second)
            return invalid("activation candidates contain an empty, repeated or oversized path");
        if (candidate.path == root_path) root = index;
        if (!candidate.manifest) continue;
        const auto& manifest = *candidate.manifest;
        if (!valid_manifest_id(manifest.id) || manifest.name.empty() || manifest.name.size() > 256 ||
            manifest.version.empty() || manifest.version.size() > 64 ||
            !valid_manifest_text(manifest.name, true) || !valid_manifest_text(manifest.version, false))
            return invalid("activation candidate has invalid manifest identity");
        if (manifest.capabilities.size() > max_manifest_capabilities ||
            manifest.required_capabilities.size() > max_manifest_capabilities)
            return Error{ErrorCode::resource_limit, "activation manifest capability limit exceeded"};
        ++identity_counts[manifest.id];
        for (const auto* table : {&manifest.capabilities, &manifest.required_capabilities}) {
            std::unordered_set<std::string> ids;
            for (const auto& capability : *table) {
                if (!valid_manifest_id(capability.id) || !capability.major_version ||
                    !ids.insert(capability.id).second ||
                    (table == &manifest.required_capabilities && capability.flags != 0))
                    return invalid("activation candidate has invalid capability declarations");
            }
        }
        if (loaded_ids.contains(manifest.id)) continue;
        for (const auto& capability : manifest.capabilities)
            providers[{capability.id, capability.major_version}].push_back(index);
    }
    if (root == candidates.size()) return invalid("selected plugin path is absent from activation candidates");
    if (!candidates[root].manifest) return invalid("dependency activation requires a valid sidecar manifest");
    if (loaded_ids.contains(candidates[root].manifest->id))
        return Error{ErrorCode::conflict, "selected plugin ID is already loaded"};

    const auto supports = [](const auto& declarations, const PluginInfo::VersionedCapability& requirement) {
        return std::any_of(declarations.begin(), declarations.end(), [&](const auto& capability) {
            return capability.id == requirement.id && capability.major_version == requirement.major_version &&
                   capability.minor_version >= requirement.minor_version;
        });
    };
    const auto host_supports = [](const PluginInfo::VersionedCapability& requirement) {
        return std::any_of(host_capabilities.begin(), host_capabilities.end(), [&](const auto& capability) {
            return requirement.id == capability.capability_id && requirement.major_version == capability.major_version &&
                   capability.minor_version >= requirement.minor_version;
        });
    };
    std::vector<std::uint8_t> state(candidates.size(), 0);
    std::vector<std::size_t> order;
    std::size_t selected_count = 0;
    std::function<Status(std::size_t)> visit = [&](std::size_t index) -> Status {
        const auto& manifest = *candidates[index].manifest;
        if (state[index] == 2) return std::monostate{};
        if (state[index] == 1)
            return Error{ErrorCode::conflict, "plugin dependency cycle reaches " + manifest.id};
        if (identity_counts[manifest.id] != 1)
            return Error{ErrorCode::conflict, "multiple candidate modules declare plugin ID " + manifest.id};
        if (++selected_count > max_activation)
            return Error{ErrorCode::resource_limit, "plugin activation dependency limit exceeded"};
        state[index] = 1;
        for (const auto& requirement : manifest.required_capabilities) {
            if (host_supports(requirement)) continue;
            std::size_t loaded_count = 0;
            for (const auto& plugin : impl_->loaded)
                if (supports(plugin.info.declared_capabilities, requirement)) ++loaded_count;
            if (loaded_count > 1)
                return Error{ErrorCode::conflict, "multiple loaded providers for capability " + requirement.id};
            if (loaded_count == 1) continue;
            const auto found = providers.find({requirement.id, requirement.major_version});
            std::size_t provider = candidates.size();
            if (found != providers.end()) {
                for (const auto possible : found->second) {
                    if (!supports(candidates[possible].manifest->capabilities, requirement)) continue;
                    if (provider != candidates.size())
                        return Error{ErrorCode::conflict, "multiple candidate providers for capability " + requirement.id};
                    provider = possible;
                }
            }
            if (provider == candidates.size())
                return Error{ErrorCode::unsupported, manifest.id + " requires unavailable capability " +
                    requirement.id + " v" + std::to_string(requirement.major_version) + "." +
                    std::to_string(requirement.minor_version)};
            auto visited = visit(provider);
            if (!visited) return visited.error();
        }
        state[index] = 2;
        order.push_back(index);
        return std::monostate{};
    };
    auto visited = visit(root);
    if (!visited) return visited.error();
    // A transitive provider can also declare a capability already supplied by
    // another dependency. Reject that ambiguity before opening any module.
    for (const auto index : order) {
        for (const auto& requirement : candidates[index].manifest->required_capabilities) {
            if (host_supports(requirement)) continue;
            std::size_t count = 0;
            for (const auto& plugin : impl_->loaded)
                if (supports(plugin.info.declared_capabilities, requirement)) ++count;
            for (const auto provider : order)
                if (supports(candidates[provider].manifest->capabilities, requirement)) ++count;
            if (count != 1)
                return Error{ErrorCode::conflict, "activation introduces ambiguous capability " + requirement.id};
        }
    }
    std::vector<PluginCandidate> result;
    result.reserve(order.size());
    for (const auto index : order) result.push_back(candidates[index]);
    return result;
}

Result<std::vector<PluginInfo>> PluginManager::load_with_dependencies(
    std::span<const PluginCandidate> candidates, const std::string& root_path) {
    if (!impl_ || !impl_->provider) return invalid("plugin manager or module provider is unavailable");
    std::lock_guard lock(impl_->mutex);
    auto plan = plan_activation_locked(candidates, root_path);
    if (!plan) return plan.error();
    // Reserve before starting anything, so tracking a successful activation
    // cannot allocate after a plugin has already entered the loaded inventory.
    std::vector<PluginInfo> activated;
    activated.reserve(plan.value().size());
    const auto original_count = impl_->loaded.size();
    const auto rollback = [&] {
        // Every newly loaded consumer appears after its providers. No other
        // lifecycle operation can interleave while this lock is held.
        while (impl_->loaded.size() > original_count) impl_->loaded.pop_back();
        ++impl_->semantic_generation;
        std::atomic_store(&impl_->semantic_identity, impl_->make_semantic_identity_locked());
    };
    try {
        for (const auto& candidate : plan.value()) {
            auto loaded = load_locked(candidate.path, &*candidate.manifest);
            if (!loaded) {
                auto error = loaded.error();
                error.message = "Activation failed for " + candidate.manifest->id + ": " + error.message +
                                ". Newly activated dependencies were unloaded.";
                rollback();
                return error;
            }
            activated.push_back(std::move(loaded.value()));
        }
    } catch (...) {
        rollback();
        return Error{ErrorCode::io, "plugin dependency activation raised an exception; new dependencies were unloaded"};
    }
    return activated;
}

Status PluginManager::refresh_requirement_preflight(std::span<PluginCandidate> candidates) const {
    if (!impl_) return invalid("plugin manager is unavailable");
    if (candidates.size() > 16384)
        return Error{ErrorCode::resource_limit, "plugin preflight candidate limit exceeded"};
    std::lock_guard lock(impl_->mutex);
    using CapabilityKey = std::pair<std::string, std::uint32_t>;
    struct Provider {
        const std::string* plugin_id;
        std::uint32_t minor_version;
    };
    using Providers = std::map<CapabilityKey, std::vector<Provider>>;
    Providers loaded_providers, candidate_providers;
    std::unordered_set<std::string> loaded_ids;
    const auto collect = [](Providers& providers, const auto& declarations, const std::string& plugin_id) {
        for (const auto& capability : declarations)
            providers[{capability.id, capability.major_version}].push_back({&plugin_id, capability.minor_version});
    };
    for (const auto& plugin : impl_->loaded) {
        loaded_ids.insert(plugin.info.id);
        collect(loaded_providers, plugin.info.declared_capabilities, plugin.info.id);
    }
    for (const auto& candidate : candidates) {
        if (!candidate.manifest) continue;
        const auto& manifest = *candidate.manifest;
        if (!valid_manifest_id(manifest.id)) return invalid("plugin preflight manifest identity is invalid");
        if (manifest.capabilities.size() > max_manifest_capabilities ||
            manifest.required_capabilities.size() > max_manifest_capabilities)
            return Error{ErrorCode::resource_limit, "plugin preflight capability limit exceeded"};
        for (const auto* table : {&manifest.capabilities, &manifest.required_capabilities}) {
            std::unordered_set<std::string> ids;
            for (const auto& capability : *table)
                if (!valid_manifest_id(capability.id) || !capability.major_version ||
                    !ids.insert(capability.id).second ||
                    (table == &manifest.required_capabilities && capability.flags != 0))
                    return invalid("plugin preflight capability declaration is invalid");
        }
        if (!loaded_ids.contains(manifest.id))
            collect(candidate_providers, manifest.capabilities, manifest.id);
    }
    // Build all output before replacing any caller-owned status table.
    std::vector<std::vector<PluginRequirementPreflight>> statuses(candidates.size());
    for (std::size_t index = 0; index < candidates.size(); ++index) {
        const auto& candidate = candidates[index];
        if (!candidate.manifest) continue;
        auto& result = statuses[index];
        result.reserve(candidate.manifest->required_capabilities.size());
        for (const auto& requirement : candidate.manifest->required_capabilities) {
            PluginRequirementPreflight status;
            status.capability = requirement;
            const auto host_provider = std::find_if(host_capabilities.begin(), host_capabilities.end(),
                [&](const auto& capability) {
                    return requirement.id == capability.capability_id &&
                           requirement.major_version == capability.major_version &&
                           capability.minor_version >= requirement.minor_version;
                });
            const auto resolve = [&](const Providers& providers, PluginRequirementResolution resolution) {
                const auto found = providers.find({requirement.id, requirement.major_version});
                if (found == providers.end()) return false;
                const Provider* selected = nullptr;
                for (const auto& provider : found->second) {
                    if (provider.minor_version < requirement.minor_version) continue;
                    if (selected) {
                        status.resolution = PluginRequirementResolution::ambiguous;
                        return true;
                    }
                    selected = &provider;
                }
                if (!selected) return false;
                status.resolution = resolution;
                status.provider_plugin_id = *selected->plugin_id;
                return true;
            };
            if (host_provider != host_capabilities.end()) status.resolution = PluginRequirementResolution::host;
            else if (!resolve(loaded_providers, PluginRequirementResolution::loaded_plugin))
                (void)resolve(candidate_providers, PluginRequirementResolution::candidate_plugin);
            result.push_back(std::move(status));
        }
    }
    for (std::size_t index = 0; index < candidates.size(); ++index)
        candidates[index].requirement_preflight = std::move(statuses[index]);
    return std::monostate{};
}

Result<std::vector<PluginCandidate>> PluginManager::scan_directory(
    const std::string& directory, std::size_t max_entries) const {
    constexpr std::size_t hard_entry_limit = 16384;
    if (!impl_) return invalid("plugin manager is unavailable");
    if (directory.empty()) return invalid("plugin directory is empty");
    if (max_entries == 0 || max_entries > hard_entry_limit)
        return invalid("plugin directory scan limit is outside the supported range");

    try {
        const auto root = std::filesystem::u8path(directory);
        std::error_code ec;
        const auto root_status = std::filesystem::symlink_status(root, ec);
        if (ec) return Error{ErrorCode::io, "cannot inspect plugin directory: " + ec.message()};
        if (std::filesystem::is_symlink(root_status) || !std::filesystem::is_directory(root_status))
            return invalid("plugin scan path must be a real directory, not a symlink");

        std::vector<PluginCandidate> candidates;
        std::size_t entries = 0;
        std::filesystem::directory_iterator current(root, std::filesystem::directory_options::none, ec);
        const std::filesystem::directory_iterator end;
        if (ec) return Error{ErrorCode::io, "cannot enumerate plugin directory: " + ec.message()};
        while (current != end) {
            if (++entries > max_entries)
                return Error{ErrorCode::resource_limit, "plugin directory entry count exceeds scan limit"};

            const auto entry_path = current->path();
            const auto entry_status = current->symlink_status(ec);
            if (ec) return Error{ErrorCode::io, "cannot inspect plugin directory entry: " + ec.message()};
            const bool regular = std::filesystem::is_regular_file(entry_status);
            const bool directory_bundle = std::filesystem::is_directory(entry_status);
            if (!std::filesystem::is_symlink(entry_status)) {
                const auto filename = entry_path.filename().u8string();
                std::string ascii_name;
                ascii_name.reserve(filename.size());
                for (const auto ch : filename)
                    ascii_name.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));

                bool supported = false;
#if defined(_WIN32)
                supported = regular && ascii_name.size() > 4 && ascii_name.ends_with(".dll");
#elif defined(__APPLE__)
                supported = (regular && (ascii_name.ends_with(".dylib") || ascii_name.ends_with(".so"))) ||
                            (directory_bundle && ascii_name.ends_with(".bundle"));
#else
                supported = regular && ascii_name.ends_with(".so");
                if (regular && !supported) {
                    const auto version = ascii_name.rfind(".so.");
                    if (version != std::string::npos && version + 4 < ascii_name.size()) {
                        bool has_digit = false;
                        bool valid_version = true;
                        for (std::size_t i = version + 4; i < ascii_name.size(); ++i) {
                            const char ch = ascii_name[i];
                            if (ch >= '0' && ch <= '9') has_digit = true;
                            else if (ch != '.') valid_version = false;
                        }
                        supported = valid_version && has_digit;
                    }
                }
#endif
                if (supported) {
                    auto absolute = std::filesystem::absolute(entry_path, ec);
                    if (ec) return Error{ErrorCode::io, "cannot resolve plugin candidate path: " + ec.message()};
                    absolute = absolute.lexically_normal();
                    const auto utf8 = absolute.u8string();
                    PluginCandidate candidate;
                    candidate.path.assign(reinterpret_cast<const char*>(utf8.data()), utf8.size());
                    auto manifest_path = absolute;
                    manifest_path += ".hexlab-plugin";
                    std::error_code manifest_ec;
                    const auto manifest_status = std::filesystem::symlink_status(manifest_path, manifest_ec);
                    if (!manifest_ec) {
                        if (std::filesystem::exists(manifest_status)) {
                            const auto manifest_utf8 = manifest_path.u8string();
                            const std::string manifest_name(reinterpret_cast<const char*>(manifest_utf8.data()),
                                                            manifest_utf8.size());
                            auto parsed = read_manifest(manifest_name);
                            if (parsed) {
                                candidate.manifest = std::move(parsed.value());
                            }
                            else candidate.manifest_error = parsed.error().message;
                        }
                    } else if (manifest_ec != std::errc::no_such_file_or_directory) {
                        candidate.manifest_error = "cannot inspect plugin manifest: " + manifest_ec.message();
                    }
                    candidates.push_back(std::move(candidate));
                }
            }

            current.increment(ec);
            if (ec) return Error{ErrorCode::io, "plugin directory enumeration failed: " + ec.message()};
        }
        std::sort(candidates.begin(), candidates.end(), [](const auto& left, const auto& right) {
            return left.path < right.path;
        });
        auto preflight = refresh_requirement_preflight(candidates);
        if (!preflight) return preflight.error();
        return candidates;
    } catch (const std::filesystem::filesystem_error& error) {
        return Error{ErrorCode::io, std::string("plugin directory scan failed: ") + error.what()};
    } catch (...) {
        return Error{ErrorCode::io, "plugin directory scan failed"};
    }
}

Status PluginManager::unload(const std::string& plugin_id) {
    if (!impl_) return invalid("plugin manager is unavailable");
    std::lock_guard manager_lock(impl_->mutex);
    return unload_locked(plugin_id);
}

Status PluginManager::unload_locked(const std::string& plugin_id) {
    if(impl_->scalar_ir_callback_depth)return Error{ErrorCode::busy,"Cannot unload plugins during a scalar IR callback"};
    const auto it = std::find_if(impl_->loaded.begin(), impl_->loaded.end(),
        [&](const auto& item) { return item.info.id == plugin_id; });
    if (it == impl_->loaded.end()) return Error{ErrorCode::out_of_bounds, "plugin is not loaded"};
    for (const auto& dependent : impl_->loaded) {
        if (dependent.info.id == plugin_id) continue;
        if (std::find(dependent.info.resolved_dependencies.begin(),
                      dependent.info.resolved_dependencies.end(), plugin_id) !=
            dependent.info.resolved_dependencies.end())
            return Error{ErrorCode::conflict, "cannot unload plugin " + plugin_id +
                " while dependent plugin " + dependent.info.id + " is loaded"};
    }
    impl_->loaded.erase(it);
    ++impl_->semantic_generation;
    std::atomic_store(&impl_->semantic_identity, impl_->make_semantic_identity_locked());
    return std::monostate{};
}

Result<std::vector<std::string>> PluginManager::unload_with_dependents(const std::string& plugin_id) {
    if (!impl_) return invalid("plugin manager is unavailable");
    std::lock_guard lock(impl_->mutex);
    const auto root = std::find_if(impl_->loaded.begin(), impl_->loaded.end(),
        [&](const auto& item) { return item.info.id == plugin_id; });
    if (root == impl_->loaded.end()) return Error{ErrorCode::out_of_bounds, "plugin is not loaded"};
    std::unordered_set<std::string> selected{plugin_id};
    std::vector<std::string> order;
    // Activation only permits dependencies on earlier loaded modules, so one
    // forward pass finds the complete transitive consumer closure.
    for (auto current = root; current != impl_->loaded.end(); ++current) {
        if (current->info.id != plugin_id &&
            !std::any_of(current->info.resolved_dependencies.begin(), current->info.resolved_dependencies.end(),
                [&](const auto& dependency) { return selected.contains(dependency); })) continue;
        selected.insert(current->info.id);
        order.push_back(current->info.id);
    }
    std::reverse(order.begin(), order.end());
    for (const auto& id : order) {
        auto removed = unload_locked(id);
        if (!removed) return removed.error();
    }
    return order;
}

Status PluginManager::unload_all() {
    if (!impl_) return invalid("plugin manager is unavailable");
    std::lock_guard lock(impl_->mutex);
    if(impl_->scalar_ir_callback_depth)return Error{ErrorCode::busy,"Cannot unload plugins during a scalar IR callback"};
    if (impl_->loaded.empty()) return std::monostate{};
    while (!impl_->loaded.empty()) impl_->loaded.pop_back();
    ++impl_->semantic_generation;
    std::atomic_store(&impl_->semantic_identity, impl_->make_semantic_identity_locked());
    return std::monostate{};
}

std::vector<PluginInfo> PluginManager::plugins() const {
    std::vector<PluginInfo> result;
    if (!impl_) return result;
    std::lock_guard manager_lock(impl_->mutex);
    result.reserve(impl_->loaded.size());
    for (const auto& item : impl_->loaded) result.push_back(item.info);
    return result;
}

bool PluginManager::supports_capability(const std::string& plugin_id, const std::string& capability_id,
                                       std::uint32_t major_version,
                                       std::uint32_t minimum_minor_version) const {
    if (!impl_ || plugin_id.empty() || capability_id.empty() || major_version == 0) return false;
    std::lock_guard manager_lock(impl_->mutex);
    const auto plugin = std::find_if(impl_->loaded.begin(), impl_->loaded.end(),
        [&](const auto& item) { return item.info.id == plugin_id; });
    if (plugin == impl_->loaded.end()) return false;
    return std::any_of(plugin->info.declared_capabilities.begin(), plugin->info.declared_capabilities.end(),
        [&](const auto& capability) {
            return capability.id == capability_id && capability.major_version == major_version &&
                   capability.minor_version >= minimum_minor_version;
        });
}

std::vector<PluginActionInfo> PluginManager::actions() const {
    std::vector<PluginActionInfo> result;
    if (!impl_) return result;
    std::lock_guard manager_lock(impl_->mutex);
    for (const auto& plugin : impl_->loaded)
        for (const auto& action : plugin.context->actions)
            result.push_back({plugin.info.id, action.id, action.label});
    return result;
}

std::vector<PluginMenuActionInfo> PluginManager::menu_actions() const {
    std::vector<PluginMenuActionInfo> result;
    if (!impl_) return result;
    std::lock_guard manager_lock(impl_->mutex);
    for (const auto& plugin : impl_->loaded)
        for (const auto& action : plugin.context->actions)
            if (!action.menu_path.empty())
                result.push_back({plugin.info.id, action.menu_path, action.id, action.label});
    return result;
}

Status PluginManager::invoke_action(const std::string& plugin_id, const std::string& action_id) {
    if (!impl_) return invalid("plugin manager is unavailable");
    std::lock_guard manager_lock(impl_->mutex);
    const auto plugin = std::find_if(impl_->loaded.begin(), impl_->loaded.end(),
        [&](const auto& item) { return item.info.id == plugin_id; });
    if (plugin == impl_->loaded.end())
        return Error{ErrorCode::out_of_bounds, "plugin is not loaded"};
    const auto action = std::find_if(plugin->context->actions.begin(), plugin->context->actions.end(),
        [&](const auto& item) { return item.id == action_id; });
    if (action == plugin->context->actions.end())
        return Error{ErrorCode::out_of_bounds, "plugin action is not registered"};
    try {
        action->invoke(action->context);
    } catch (...) {
        return Error{ErrorCode::io, "plugin action raised an exception"};
    }
    return std::monostate{};
}

std::vector<LoaderExtensionInfo> PluginManager::loader_extensions() const {
    std::vector<LoaderExtensionInfo> result;
    if (!impl_) return result;
    std::lock_guard manager_lock(impl_->mutex);
    for (const auto& plugin : impl_->loaded)
        for (const auto& extension : plugin.context->loaders)
            result.push_back({plugin.info.id, extension.id, extension.format_id});
    return result;
}

std::vector<ProcessorExtensionInfo> PluginManager::processor_extensions() const {
    std::vector<ProcessorExtensionInfo> result;
    if (!impl_) return result;
    std::lock_guard manager_lock(impl_->mutex);
    for (const auto& plugin : impl_->loaded)
        for (const auto& extension : plugin.context->processors)
            result.push_back({plugin.info.id, extension.id, extension.architecture_id, extension.mode_id});
    return result;
}

std::vector<PluginExtensionFailure> PluginManager::extension_failures() const {
    std::vector<PluginExtensionFailure> result;
    if (!impl_) return result;
    std::lock_guard manager_lock(impl_->mutex);
    for (const auto &plugin : impl_->loaded) {
        for (const auto &extension : plugin.context->loaders)
            if (extension.disabled)
                result.push_back({plugin.info.id, extension.id, "loader", extension.failure_reason});
        for (const auto &extension : plugin.context->processors)
            if (extension.disabled)
                result.push_back({plugin.info.id, extension.id, "processor", extension.failure_reason});
    }
    return result;
}

std::vector<AnalysisProviderInfo> PluginManager::analysis_providers() const {
    std::vector<AnalysisProviderInfo> result;
    if (!impl_) return result;
    std::lock_guard manager_lock(impl_->mutex);
    for (const auto& plugin : impl_->loaded)
        for (const auto& provider : plugin.context->analysis_providers)
            result.push_back({plugin.info.id, provider.id, provider.name});
    return result;
}

Result<std::string> PluginManager::run_analysis_provider(const std::string& plugin_id,
                                                        const std::string& provider_id,
                                                        const std::string& project_path) const {
    if (!impl_ || plugin_id.empty() || provider_id.empty() || project_path.empty() ||
        project_path.size() >= HEXLAB_PROJECT_MAX_PATH)
        return invalid("analysis provider, plugin, or project path is invalid");
    std::error_code path_error;
    const auto path = std::filesystem::u8path(project_path);
    if (!std::filesystem::is_regular_file(path, path_error) || path_error)
        return invalid("analysis provider requires an existing project file");
    std::lock_guard manager_lock(impl_->mutex);
    const auto plugin = std::find_if(impl_->loaded.begin(), impl_->loaded.end(),
        [&](const auto& item) { return item.info.id == plugin_id; });
    if (plugin == impl_->loaded.end()) return Error{ErrorCode::out_of_bounds, "plugin is not loaded"};
    const auto provider = std::find_if(plugin->context->analysis_providers.begin(),
        plugin->context->analysis_providers.end(),
        [&](const auto& item) { return item.id == provider_id; });
    if (provider == plugin->context->analysis_providers.end())
        return Error{ErrorCode::out_of_bounds, "analysis provider is not registered"};
    std::array<char, HEXLAB_ANALYSIS_PROVIDER_MAX_OUTPUT> output{};
    int32_t status = -1;
    try {
        status = provider->analyze(provider->context, &plugin->context->project_api,
                                   project_path.c_str(), output.data(),
                                   static_cast<uint32_t>(output.size()));
    } catch (...) { return Error{ErrorCode::io, "analysis provider raised an exception"}; }
    if (status != 0) return Error{ErrorCode::io, "analysis provider failed with status " + std::to_string(status)};
    const auto end = std::find(output.begin(), output.end(), '\0');
    if (end == output.end()) return Error{ErrorCode::malformed, "analysis provider output exceeded its limit"};
    return std::string(output.begin(), end);
}

Result<std::optional<LoaderProbeResult>> PluginManager::probe_loaders(
    std::span<const std::uint8_t> input, const std::string& requested_format, std::uint64_t total_size) const {
    if (!impl_) return invalid("plugin manager is unavailable");
    if (input.empty()) return invalid("loader probe input is empty");
    if (!total_size) total_size = static_cast<std::uint64_t>(input.size());
    if (total_size < input.size()) return invalid("loader probe prefix exceeds total input size");
    std::lock_guard manager_lock(impl_->mutex);
    std::optional<LoaderProbeResult> best;
    const auto prefix_size = static_cast<std::uint32_t>(std::min<std::size_t>(input.size(), HEXLAB_PLUGIN_MAX_LOADER_PROBE_BYTES));
    for (auto &plugin : impl_->loaded) for (auto &extension : plugin.context->loaders) {
        if (extension.disabled || (!requested_format.empty() && requested_format != extension.format_id)) continue;
        std::uint32_t confidence = 0;
        int32_t status = -1;
        try {
            status = extension.probe(extension.extension_context, input.data(), prefix_size,
                                     total_size, &confidence);
        } catch (...) { status = -1; }
        if (status < 0) { impl_->quarantine(extension, "loader probe callback failed"); continue; }
        if (status == 0) continue;
        if (status != 1 || confidence > 1000) {
            impl_->quarantine(extension, "loader probe returned an invalid status or confidence");
            continue;
        }
        if (!best || confidence > best->confidence)
            best = LoaderProbeResult{plugin.info.id, extension.id, extension.format_id, confidence};
    }
    if (best) return best;
    return std::optional<LoaderProbeResult>{};
}

Result<LoadRecipe> PluginManager::image_recipe(const std::string& plugin_id,
                                             const std::string& extension_id) const {
    if (!impl_) return invalid("plugin manager is unavailable");
    std::lock_guard lock(impl_->mutex);
    for (const auto& plugin : impl_->loaded) {
        if (plugin.info.id != plugin_id) continue;
        for (const auto& extension : plugin.context->loaders) {
            if (extension.id != extension_id || extension.disabled || !extension.load_image) continue;
            LoadRecipe recipe{Format::plugin, {}};
            recipe.plugin = PluginImageIdentity{plugin.info.id, plugin.info.version, extension.id,
                                                extension.format_id, extension.image_api_version};
            return recipe;
        }
    }
    return Error{ErrorCode::unsupported, "Plugin extension has no image provider"};
}

namespace {
struct ImageInputContext {
    const ByteStorage& storage;
    std::stop_token stop;
    std::mutex mutex;
    std::uint64_t bytes_read = 0;
    std::uint32_t calls = 0;
    bool failed = false;
};
int32_t image_input_read(void* opaque, uint64_t offset, uint8_t* output, uint32_t size) noexcept {
    if (!opaque) return -1;
    auto& input = *static_cast<ImageInputContext*>(opaque);
    std::lock_guard lock(input.mutex);
    try {
        if (input.failed || input.stop.stop_requested() || !output || !size ||
            size > HEXLAB_IMAGE_MAX_READ || ++input.calls > 4096 ||
            size > UINT64_C(64) * 1024 * 1024 - input.bytes_read ||
            offset > input.storage.size() || size > input.storage.size() - offset) {
            input.failed = true;
            return -1;
        }
        input.bytes_read += size;
        auto read = input.storage.read_at({offset}, size);
        if (!read || read.value().bytes.size() != size) {
            input.failed = true;
            return -1;
        }
        std::transform(read.value().bytes.begin(), read.value().bytes.end(), output,
                       [](std::byte value) { return std::to_integer<uint8_t>(value); });
        return 0;
    } catch (...) { input.failed = true; return -1; }
}
int32_t image_input_canceled(void* opaque) noexcept {
    return !opaque || static_cast<ImageInputContext*>(opaque)->stop.stop_requested() ? 1 : 0;
}
struct FlatImageMode {
    const char* architecture;
    const char* mode;
    Architecture architecture_value;
    ExecutionMode mode_value;
    std::uint32_t width, alignment;
    bool big_endian;
};
constexpr FlatImageMode flat_image_modes[] = {
    {"x86", "x86_32", Architecture::x86, ExecutionMode::x86_32, 32, 1, false},
    {"x86_64", "x86_64", Architecture::x86_64, ExecutionMode::x86_64, 64, 1, false},
    {"arm64", "a64", Architecture::arm64, ExecutionMode::a64, 64, 4, false},
    {"riscv32", "rv32", Architecture::riscv32, ExecutionMode::rv32, 32, 4, false},
    {"riscv64", "rv64", Architecture::riscv64, ExecutionMode::rv64, 64, 4, false},
    {"riscv64", "rv64c", Architecture::riscv64, ExecutionMode::rv64c, 64, 2, false},
    {"mips32", "mips32", Architecture::mips32, ExecutionMode::mips32, 32, 4, true},
    {"mips64", "mips64", Architecture::mips64, ExecutionMode::mips64, 64, 4, true},
    {"powerpc", "ppc32", Architecture::powerpc, ExecutionMode::ppc32, 32, 4, true},
    {"powerpc", "ppc64", Architecture::powerpc, ExecutionMode::ppc64, 64, 4, true},
    {"mos6502", "m6502", Architecture::mos6502, ExecutionMode::m6502, 16, 1, false}
};
}

Result<LoadedImage> PluginManager::load_plugin_image(std::shared_ptr<const ByteStorage> storage,
    const PluginImageIdentity& identity, std::stop_token stop) const {
    if (!impl_ || !storage) return invalid("plugin image loading requires a manager and input storage");
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Plugin image loading canceled"};
    // Avoid lock inversion when native callbacks on independent managers use
    // synchronous host project services that resolve each other's providers.
    std::unique_lock manager_lock(impl_->mutex, std::try_to_lock);
    if (!manager_lock.owns_lock()) return Error{ErrorCode::busy, "Plugin image provider manager is busy"};
    const HostContext::Loader* selected = nullptr;
    for (const auto& plugin : impl_->loaded) {
        if (plugin.info.id != identity.plugin_id || plugin.info.version != identity.plugin_version) continue;
        for (const auto& extension : plugin.context->loaders)
            if (!extension.disabled && extension.id == identity.extension_id && extension.format_id == identity.format_id &&
                extension.image_api_version == identity.api_version && extension.load_image)
                selected = &extension;
    }
    if (!selected) return Error{ErrorCode::unsupported, "Exact plugin image provider is unavailable"};
    try {
        ImageInputContext context{*storage, stop};
        HexLabImageInput input{sizeof(HexLabImageInput), HEXLAB_IMAGE_PROVIDER_API_VERSION,
            storage->size(), &context, image_input_read, image_input_canceled};
        auto mapping = std::make_unique<HexLabImageMapping>();
        mapping->struct_size = sizeof(*mapping);
        mapping->api_version = HEXLAB_IMAGE_PROVIDER_API_VERSION;
        int32_t status = -1;
        try { status = selected->load_image(selected->extension_context, &input, mapping.get()); }
        catch (...) { status = -1; }
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Plugin image loading canceled"};
        if (status != 0 || context.failed)
            return Error{ErrorCode::io, "Plugin image callback or bounded input read failed"};
        const auto& source = *mapping;
        if (source.struct_size != sizeof(source) || source.api_version != HEXLAB_IMAGE_PROVIDER_API_VERSION ||
            source.reserved || !source.segment_count || source.segment_count > HEXLAB_IMAGE_MAX_SEGMENTS ||
            source.entry_count > HEXLAB_IMAGE_MAX_ENTRIES || source.byte_order > 1)
            return Error{ErrorCode::malformed, "Invalid plugin image mapping header"};
        std::string architecture, mode;
        if (!copy_fixed_string(source.architecture_id, sizeof(source.architecture_id), architecture) ||
            !copy_fixed_string(source.mode_id, sizeof(source.mode_id), mode))
            return Error{ErrorCode::malformed, "Invalid plugin image architecture or mode ID"};
        const auto found = std::find_if(std::begin(flat_image_modes), std::end(flat_image_modes), [&](const auto& row) {
            return architecture == row.architecture && mode == row.mode;
        });
        if (found == std::end(flat_image_modes) || source.address_width != found->width ||
            (source.byte_order && !found->big_endian))
            return Error{ErrorCode::unsupported, "Plugin image mode, width or byte order cannot be represented safely"};
        ImageLayout layout{{{source.address_space}, static_cast<std::uint8_t>(source.address_width), 1,
                            source.byte_order ? ByteOrder::big : ByteOrder::little},
                           found->architecture_value, found->mode_value, {}, {}};
        std::uint64_t mapped_bytes = 0;
        for (std::uint32_t n = 0; n < source.segment_count; ++n) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Plugin image validation canceled"};
            const auto& segment = source.segments[n];
            std::string name;
            if (segment.struct_size != sizeof(segment) || segment.reserved || segment.permissions > 7 ||
                !segment.memory_size || !copy_fixed_string(segment.name, sizeof(segment.name), name) ||
                ((segment.permissions & 4) && segment.address % found->alignment))
                return Error{ErrorCode::malformed, "Invalid plugin image segment record"};
            // Image::create checks address overflow, domain width, backing
            // extents and virtual overlap using the same rules as built-ins.
            auto total = checked_add(mapped_bytes, segment.memory_size);
            if (!total) return total.error();
            mapped_bytes = total.value();
            layout.segments.push_back({std::move(name), {{source.address_space}, segment.address},
                segment.memory_size, {segment.file_offset}, segment.file_size,
                bool(segment.permissions & 1), bool(segment.permissions & 2), bool(segment.permissions & 4)});
        }
        for (std::uint32_t n = 0; n < source.entry_count; ++n) {
            const auto entry = source.entries[n];
            if (entry % found->alignment ||
                std::find(source.entries, source.entries + n, entry) != source.entries + n)
                return Error{ErrorCode::malformed, "Misaligned or duplicate plugin image entry"};
            layout.entries.push_back({{source.address_space}, entry});
        }
        auto image = Image::create(storage, std::move(layout));
        if (!image) return image.error();
        for (auto entry : image.value()->layout().entries) {
            const auto* segment = image.value()->segment_at(entry);
            if (!segment || !segment->executable)
                return Error{ErrorCode::malformed, "Plugin image entry is not executable"};
        }
        LoadedImage loaded;
        loaded.image = std::move(image.value());
        loaded.metadata.format = identity.format_id;
        loaded.metadata.image_size = mapped_bytes;
        loaded.metadata.preferred_base = loaded.image->layout().segments.front().begin.offset;
        // All original bytes are parser dependencies, including reads the
        // plugin may have declined to make after a conditional parse branch.
        auto dependency = loaded.metadata_reads.include({0}, storage->size());
        if (!dependency) return dependency.error();
        loaded.metadata_reads_complete = true;
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Plugin image loading canceled"};
        loaded.diagnostics.push_back({DiagnosticSeverity::info,
            "Plugin image provider supplies mappings only; format metadata is incomplete", {}});
        return loaded;
    } catch (const std::bad_alloc&) {
        return Error{ErrorCode::resource_limit, "Cannot allocate plugin image mapping"};
    } catch (...) { return Error{ErrorCode::io, "Plugin image construction failed"}; }
}

Result<std::optional<ProcessorDecodeResult>> PluginManager::decode_processor(
    const std::string& architecture_id, const std::string& mode_id, std::uint64_t address,
    std::span<const std::uint8_t> input) const {
    if (!impl_) return invalid("plugin manager is unavailable");
    if (architecture_id.empty() || mode_id.empty() || input.empty())
        return invalid("processor decode request is missing architecture, mode, or bytes");
    std::lock_guard manager_lock(impl_->mutex);
    const auto input_size = static_cast<std::uint32_t>(std::min<std::size_t>(input.size(), HEXLAB_PLUGIN_MAX_EXTENSION_INPUT));
    for (auto &plugin : impl_->loaded) for (auto &extension : plugin.context->processors) {
        if (extension.disabled || extension.architecture_id != architecture_id || extension.mode_id != mode_id) continue;
        HexLabDecodedInstruction decoded{};
        decoded.struct_size = sizeof(decoded);
        int32_t status = -1;
        try { status = extension.decode(extension.extension_context, address, input.data(), input_size, &decoded); }
        catch (...) { status = -1; }
        if (status < 0) { impl_->quarantine(extension, "processor decode callback failed"); continue; }
        if (status == 0) continue;
        if (status != 1 || decoded.struct_size < sizeof(decoded) || decoded.length == 0 ||
            decoded.length > input_size || decoded.flow > HEXLAB_INSTRUCTION_FLOW_RETURN ||
            decoded.reserved != 0) {
            impl_->quarantine(extension, "processor decode callback returned an invalid instruction record");
            continue;
        }
        std::string mnemonic, operands;
        if (!copy_fixed_string(decoded.mnemonic, sizeof(decoded.mnemonic), mnemonic)) {
            impl_->quarantine(extension, "processor decode callback returned an invalid mnemonic");
            continue;
        }
        if (decoded.operands[0] != '\0' &&
            !copy_fixed_string(decoded.operands, sizeof(decoded.operands), operands)) {
            impl_->quarantine(extension, "processor decode callback returned invalid operand text");
            continue;
        }
        return std::optional<ProcessorDecodeResult>{ProcessorDecodeResult{
            plugin.info.id, extension.id, extension.architecture_id, extension.mode_id,
            decoded.length, static_cast<HexLabInstructionFlow>(decoded.flow), std::move(mnemonic), std::move(operands)}};
    }
    return std::optional<ProcessorDecodeResult>{};
}

Result<std::optional<Instruction>> PluginManager::decode_processor_semantic(
    DecodeContext decode_context, Address address, std::span<const std::byte> input) const {
    if (!impl_) return invalid("plugin manager is unavailable");
    if (input.empty()) return invalid("semantic decode request has no bytes");
    const auto architecture_id = [&] {
        switch (decode_context.architecture) {
        case Architecture::x86: return std::string("x86"); case Architecture::x86_64: return std::string("x86_64");
        case Architecture::arm: return std::string("arm"); case Architecture::arm64: return std::string("arm64");
        case Architecture::riscv32: return std::string("riscv32"); case Architecture::riscv64: return std::string("riscv64");
        case Architecture::mips32: return std::string("mips32"); case Architecture::mips64: return std::string("mips64");
        case Architecture::powerpc: return std::string("powerpc"); case Architecture::mos6502: return std::string("mos6502");
        case Architecture::wasm: return std::string("wasm"); case Architecture::dex: return std::string("dex"); case Architecture::jvm: return std::string("jvm");
        default: return std::string{};
        }
    }();
    const auto mode_id = [&] {
        switch (decode_context.mode) {
        case ExecutionMode::x86_16: return std::string("x86_16"); case ExecutionMode::x86_32: return std::string("x86_32");
        case ExecutionMode::x86_64: return std::string("x86_64"); case ExecutionMode::a32: return std::string("a32");
        case ExecutionMode::thumb: return std::string("thumb"); case ExecutionMode::a64: return std::string("a64");
        case ExecutionMode::rv32: return std::string("rv32"); case ExecutionMode::rv64: return std::string("rv64");
        case ExecutionMode::rv64c: return std::string("rv64c"); case ExecutionMode::mips32: return std::string("mips32");
        case ExecutionMode::mips64: return std::string("mips64"); case ExecutionMode::ppc32: return std::string("ppc32");
        case ExecutionMode::ppc64: return std::string("ppc64"); case ExecutionMode::m6502: return std::string("m6502");
        case ExecutionMode::wasm32: return std::string("wasm32"); case ExecutionMode::dex: return std::string("dex"); case ExecutionMode::jvm: return std::string("jvm");
        default: return std::string{};
        }
    }();
    if (architecture_id.empty() || mode_id.empty()) return std::optional<Instruction>{};
    std::lock_guard manager_lock(impl_->mutex);
    if(impl_->scalar_ir_callback_depth)return Error{ErrorCode::busy,"Recursive scalar IR decode is unsupported"};
    const auto input_size = static_cast<std::uint32_t>(std::min<std::size_t>(input.size(), HEXLAB_PLUGIN_MAX_EXTENSION_INPUT));
    const auto* raw = reinterpret_cast<const std::uint8_t*>(input.data());
    std::size_t ir_attempts=0;
    for(auto &plugin:impl_->loaded)for(auto &extension:plugin.context->processors){
        if(extension.disabled||!extension.decode_ir||extension.architecture_id!=architecture_id||extension.mode_id!=mode_id)continue;
        if(++ir_attempts>256)return Error{ErrorCode::resource_limit,"Scalar IR provider-attempt limit exceeded"};
        const auto generation=impl_->semantic_generation;
        HexLabInstructionIR decoded{};initialize_scalar_ir(decoded);
        int32_t status=-1;
        {ScalarIRCallbackScope scope(impl_->scalar_ir_callback_depth);
         try{status=extension.decode_ir(extension.extension_context,address.offset,raw,input_size,&decoded);}catch(...){status=-1;}}
        if(impl_->semantic_generation!=generation)return Error{ErrorCode::conflict,"Plugin semantic generation changed inside a scalar IR callback"};
        if(status==0)continue;
        if(status!=1){impl_->quarantine(extension,"scalar IR callback failed or returned an invalid status");
            return Error{status<0?ErrorCode::io:ErrorCode::malformed,"Plugin scalar IR callback failed: "+extension.id};}
        auto semantic=convert_semantic_v3(decoded.semantic,decode_context,address,input.first(input_size));
        if(!semantic||!detail::convert_scalar_ir(decoded,*semantic,semantic_register_v2)){
            impl_->quarantine(extension,"scalar IR callback returned an invalid or unsupported program");
            return Error{ErrorCode::malformed,"Plugin scalar IR record failed validation: "+extension.id};}
        return std::optional<Instruction>{std::move(*semantic)};
    }
    for (auto &plugin : impl_->loaded) for (auto &extension : plugin.context->processors) {
        if (extension.disabled || !extension.decode_semantic_v3 || extension.architecture_id != architecture_id ||
            extension.mode_id != mode_id) continue;
        HexLabSemanticInstructionV3 decoded{};
        decoded.struct_size = sizeof(decoded);
        decoded.api_version = 3;
        decoded.semantic.struct_size = sizeof(decoded.semantic);
        decoded.semantic.api_version = 2;
        int32_t status = -1;
        try { status = extension.decode_semantic_v3(extension.extension_context, address.offset,
                                                     raw, input_size, &decoded); }
        catch (...) { status = -1; }
        if (status < 0) { impl_->quarantine(extension, "semantic V3 callback failed"); continue; }
        if (status == 0) continue;
        if (status != 1) { impl_->quarantine(extension, "semantic V3 callback returned an invalid status"); continue; }
        auto semantic = convert_semantic_v3(decoded, decode_context, address, input.first(input_size));
        if (!semantic) { impl_->quarantine(extension, "semantic V3 callback returned an invalid instruction record"); continue; }
        return std::optional<Instruction>{std::move(*semantic)};
    }
    for (auto &plugin : impl_->loaded) for (auto &extension : plugin.context->processors) {
        if (extension.disabled || !extension.decode_semantic_v2 || extension.architecture_id != architecture_id ||
            extension.mode_id != mode_id) continue;
        HexLabSemanticInstructionV2 decoded{};
        decoded.struct_size = sizeof(decoded);
        decoded.api_version = 2;
        int32_t status = -1;
        try { status = extension.decode_semantic_v2(extension.extension_context, address.offset,
                                                     raw, input_size, &decoded); }
        catch (...) { status = -1; }
        if (status < 0) { impl_->quarantine(extension, "semantic V2 callback failed"); continue; }
        if (status == 0) continue;
        if (status != 1) { impl_->quarantine(extension, "semantic V2 callback returned an invalid status"); continue; }
        auto semantic = convert_semantic_v2(decoded, decode_context, address, input.first(input_size));
        if (!semantic) { impl_->quarantine(extension, "semantic V2 callback returned an invalid instruction record"); continue; }
        return std::optional<Instruction>{std::move(*semantic)};
    }
    for (auto &plugin : impl_->loaded) for (auto &extension : plugin.context->processors) {
        if (extension.disabled || !extension.decode_semantic || extension.architecture_id != architecture_id || extension.mode_id != mode_id) continue;
        HexLabSemanticInstruction decoded{}; decoded.struct_size = sizeof(decoded);
        int32_t status = -1;
        try { status = extension.decode_semantic(extension.extension_context, address.offset, raw, input_size, &decoded); }
        catch (...) { status = -1; }
        if (status < 0) { impl_->quarantine(extension, "semantic V1 callback failed"); continue; }
        if (status == 0) continue;
        if (status != 1 || decoded.struct_size < sizeof(decoded) || decoded.length == 0 || decoded.length > 15 ||
            decoded.length > input_size || decoded.flow > HEXLAB_INSTRUCTION_FLOW_RETURN ||
            decoded.reserved != 0 || decoded.operand_count > 4) {
            impl_->quarantine(extension, "semantic V1 callback returned an invalid instruction header");
            continue;
        }
        std::string mnemonic;
        if (!copy_fixed_string(decoded.mnemonic, sizeof(decoded.mnemonic), mnemonic)) {
            impl_->quarantine(extension, "semantic V1 callback returned an invalid mnemonic");
            continue;
        }
        Instruction result; result.context = decode_context; result.address = address;
        result.length = static_cast<std::uint8_t>(decoded.length); result.opcode = Opcode::opaque;
        result.mnemonic_override = std::move(mnemonic);
        std::copy_n(input.begin(), result.length, result.bytes.begin());
        result.flow = decoded.flow == HEXLAB_INSTRUCTION_FLOW_CALL ? FlowKind::call :
                      decoded.flow == HEXLAB_INSTRUCTION_FLOW_RETURN ? FlowKind::ret :
                      decoded.flow == HEXLAB_INSTRUCTION_FLOW_BRANCH ? FlowKind::conditional_branch : FlowKind::fallthrough;
        bool valid = true;
        for (std::uint32_t i = 0; i < decoded.operand_count; ++i) {
            const auto& source = decoded.operands[i];
            if (source.reserved != 0 || source.width == 0 || source.width > 128 ||
                (source.access != HEXLAB_SEMANTIC_READ && source.access != HEXLAB_SEMANTIC_WRITE &&
                 source.access != HEXLAB_SEMANTIC_READ_WRITE)) { valid = false; break; }
            const auto access = source.access == HEXLAB_SEMANTIC_READ ? OperandAccess::read :
                                source.access == HEXLAB_SEMANTIC_WRITE ? OperandAccess::write : OperandAccess::read_write;
            if (source.kind == HEXLAB_SEMANTIC_REGISTER) {
                if (source.value != 0) { valid = false; break; }
                if (source.index > 31) { valid = false; break; }
                RegisterBank bank;
                switch (source.bank) {
                case HEXLAB_SEMANTIC_GPR:
                    if (decode_context.architecture != Architecture::x86 && decode_context.architecture != Architecture::x86_64) { valid = false; continue; }
                    if (source.index > 15) { valid = false; continue; }
                    bank = RegisterBank::gpr; break;
                case HEXLAB_SEMANTIC_IP:
                    if (decode_context.architecture != Architecture::x86 && decode_context.architecture != Architecture::x86_64) { valid = false; continue; }
                    if (source.index != 0) { valid = false; continue; }
                    bank = RegisterBank::ip; break;
                case HEXLAB_SEMANTIC_FLAGS:
                    if (decode_context.architecture != Architecture::x86 && decode_context.architecture != Architecture::x86_64) { valid = false; continue; }
                    if (source.index != 0) { valid = false; continue; }
                    bank = RegisterBank::flags; break;
                case HEXLAB_SEMANTIC_ARM32_GPR:
                    if (decode_context.architecture != Architecture::arm) { valid = false; continue; }
                    bank = RegisterBank::arm32_gpr; break;
                case HEXLAB_SEMANTIC_ARM64_GPR:
                    if (decode_context.architecture != Architecture::arm64) { valid = false; continue; }
                    bank = RegisterBank::arm64_gpr; break;
                case HEXLAB_SEMANTIC_RISCV_GPR:
                    if (decode_context.architecture != Architecture::riscv32 && decode_context.architecture != Architecture::riscv64) { valid = false; continue; }
                    bank = RegisterBank::riscv_gpr; break;
                case HEXLAB_SEMANTIC_MIPS_GPR:
                    if (decode_context.architecture != Architecture::mips32 && decode_context.architecture != Architecture::mips64) { valid = false; continue; }
                    bank = RegisterBank::mips_gpr; break;
                case HEXLAB_SEMANTIC_PPC_GPR:
                    if (decode_context.architecture != Architecture::powerpc) { valid = false; continue; }
                    bank = RegisterBank::ppc_gpr; break;
                default: valid = false; continue;
                }
                RegisterOperand reg{bank, static_cast<std::uint8_t>(source.index), static_cast<std::uint16_t>(source.width), false};
                result.operands.emplace_back(reg);
                if (access == OperandAccess::read || access == OperandAccess::read_write) result.register_reads.push_back(reg);
                if (access == OperandAccess::write || access == OperandAccess::read_write) result.register_writes.push_back(reg);
            } else if (source.kind == HEXLAB_SEMANTIC_IMMEDIATE && source.access == HEXLAB_SEMANTIC_READ && source.width <= 64) {
                if (source.bank != 0 || source.index != 0 ||
                    (source.width < 64 && (source.value >> source.width) != 0)) { valid = false; break; }
                result.operands.emplace_back(ImmediateOperand{source.value, static_cast<std::uint16_t>(source.width),
                                                              static_cast<std::uint16_t>(source.width), false, std::nullopt});
            } else if (source.kind == HEXLAB_SEMANTIC_RELATIVE && source.access == HEXLAB_SEMANTIC_READ && source.width <= 64) {
                if (source.bank != 0 || source.index != 0) { valid = false; break; }
                if (result.flow != FlowKind::conditional_branch && result.flow != FlowKind::call && result.flow != FlowKind::jump) {
                    valid = false; break;
                }
                const auto displacement = source.value <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())
                    ? static_cast<std::int64_t>(source.value)
                    : -1 - static_cast<std::int64_t>(~source.value);
                if (source.width < 64) {
                    const auto limit = std::uint64_t{1} << (source.width - 1);
                    if (displacement < -static_cast<std::int64_t>(limit) || displacement >= static_cast<std::int64_t>(limit)) {
                        valid = false; break;
                    }
                }
                result.operands.emplace_back(RelativeOperand{displacement,
                                                             static_cast<std::uint16_t>(source.width), 0, std::nullopt});
                const auto end = advance(address, decoded.length);
                if (!end) { valid = false; break; }
                std::uint64_t target = end.value().offset;
                if (displacement >= 0) {
                    const auto sum = checked_add(target, static_cast<std::uint64_t>(displacement));
                    if (!sum) { valid = false; break; }
                    target = sum.value();
                } else {
                    const auto magnitude = static_cast<std::uint64_t>(-(displacement + 1)) + 1;
                    if (target < magnitude) { valid = false; break; }
                    target -= magnitude;
                }
                result.direct_target = Address{address.space, target};
            } else if (source.kind == HEXLAB_SEMANTIC_ABSOLUTE_MEMORY && source.width >= 8 &&
                       source.width <= 128 && source.width % 8 == 0 && source.bank == 0 && source.index == 0) {
                std::uint16_t address_width = 64;
                switch (decode_context.mode) {
                case ExecutionMode::x86_16: case ExecutionMode::m6502: address_width = 16; break;
                case ExecutionMode::x86_32: case ExecutionMode::a32: case ExecutionMode::rv32:
                case ExecutionMode::mips32: case ExecutionMode::ppc32: address_width = 32; break;
                default: break;
                }
                if (address_width < 64 && source.value >= (std::uint64_t{1} << address_width)) { valid = false; break; }
                MemoryOperand memory{};
                memory.data_width = static_cast<std::uint16_t>(source.width);
                memory.address_width = address_width;
                memory.resolved_address = Address{address.space, source.value};
                result.operands.emplace_back(std::move(memory));
                result.memory_read = access == OperandAccess::read || access == OperandAccess::read_write;
                result.memory_write = access == OperandAccess::write || access == OperandAccess::read_write;
            } else { valid = false; break; }
            result.access.push_back(access);
        }
        if (!valid) { impl_->quarantine(extension, "semantic V1 callback returned invalid operands"); continue; }
        return std::optional<Instruction>{std::move(result)};
    }
    return std::optional<Instruction>{};
}

Result<std::optional<decompiler::Intrinsic>> PluginManager::instruction_ir(
    const Instruction &instruction,std::span<const std::byte> expected_identity) const {
    if(!impl_)return invalid("plugin manager is unavailable");
    std::lock_guard lock(impl_->mutex);
    const auto identity=std::atomic_load(&impl_->semantic_identity);
    if(expected_identity.empty()||!identity||!std::equal(expected_identity.begin(),expected_identity.end(),identity->begin(),identity->end()))
        return Error{ErrorCode::conflict,"Plugin scalar IR request has a stale semantic identity"};
    if(impl_->scalar_ir_callback_depth)return Error{ErrorCode::busy,"Recursive scalar IR lifting is unsupported"};
    if(instruction.opcode!=Opcode::opaque)return std::optional<decompiler::Intrinsic>{};
    const auto bytes=instruction.encoded_bytes();
    if(bytes.empty()||bytes.size()>15)return Error{ErrorCode::unsupported,"Plugin scalar IR requires a native instruction of at most 15 bytes"};
    // Reuse the same native architecture/mode identifiers as semantic dispatch.
    const auto context=instruction.context;
    const auto matches=[&](const HostContext::Processor &extension){
        const auto &architecture=extension.architecture_id;const auto &mode=extension.mode_id;
        switch(context.architecture){
        case Architecture::x86: return architecture=="x86"&&(context.mode==ExecutionMode::x86_16?mode=="x86_16":context.mode==ExecutionMode::x86_32&&mode=="x86_32");
        case Architecture::x86_64:return architecture=="x86_64"&&mode=="x86_64"&&context.mode==ExecutionMode::x86_64;
        case Architecture::arm:return architecture=="arm"&&mode=="a32"&&context.mode==ExecutionMode::a32;
        case Architecture::arm64:return architecture=="arm64"&&mode=="a64"&&context.mode==ExecutionMode::a64;
        case Architecture::riscv32:return architecture=="riscv32"&&mode=="rv32"&&context.mode==ExecutionMode::rv32;
        case Architecture::riscv64:return architecture=="riscv64"&&(context.mode==ExecutionMode::rv64?mode=="rv64":context.mode==ExecutionMode::rv64c&&mode=="rv64c");
        case Architecture::mips32:return architecture=="mips32"&&mode=="mips32"&&context.mode==ExecutionMode::mips32;
        case Architecture::mips64:return architecture=="mips64"&&mode=="mips64"&&context.mode==ExecutionMode::mips64;
        case Architecture::powerpc:return architecture=="powerpc"&&(context.mode==ExecutionMode::ppc32?mode=="ppc32":context.mode==ExecutionMode::ppc64&&mode=="ppc64");
        case Architecture::mos6502:return architecture=="mos6502"&&mode=="m6502"&&context.mode==ExecutionMode::m6502;
        default:return false;
        }
    };
    std::size_t attempts=0;
    for(auto &plugin:impl_->loaded)for(auto &extension:plugin.context->processors){
        if(extension.disabled||!extension.decode_ir||!matches(extension))continue;
        if(++attempts>256)return Error{ErrorCode::resource_limit,"Scalar IR provider-attempt limit exceeded"};
        const auto generation=impl_->semantic_generation;
        HexLabInstructionIR decoded{};initialize_scalar_ir(decoded);int32_t status=-1;
        {ScalarIRCallbackScope scope(impl_->scalar_ir_callback_depth);
         try{status=extension.decode_ir(extension.extension_context,instruction.address.offset,
             reinterpret_cast<const std::uint8_t*>(bytes.data()),static_cast<std::uint32_t>(bytes.size()),&decoded);}catch(...){status=-1;}}
        if(impl_->semantic_generation!=generation)return Error{ErrorCode::conflict,"Plugin semantic generation changed inside a scalar IR callback"};
        if(status==0)continue;
        if(status!=1){impl_->quarantine(extension,"scalar IR callback failed during lifting");
            return Error{status<0?ErrorCode::io:ErrorCode::malformed,"Plugin scalar IR callback failed during lifting: "+extension.id};}
        auto semantic=convert_semantic_v3(decoded.semantic,context,instruction.address,bytes);
        auto effect=semantic?detail::convert_scalar_ir(decoded,*semantic,semantic_register_v2):std::optional<decompiler::Intrinsic>{};
        if(!semantic||!effect){impl_->quarantine(extension,"scalar IR callback returned an invalid program during lifting");
            return Error{ErrorCode::malformed,"Plugin scalar IR record failed validation during lifting: "+extension.id};}
        if(!detail::same_scalar_instruction(instruction,*semantic))
            return Error{ErrorCode::conflict,"Plugin scalar IR decode no longer matches the analyzed instruction"};
        return std::optional<decompiler::Intrinsic>{std::move(*effect)};
    }
    return std::optional<decompiler::Intrinsic>{};
}

AnalysisOptions PluginManager::analysis_options(AnalysisOptions options) const {
    if (!impl_) return options;
    const auto state = impl_;
    options.semantic_decoder = [state](DecodeContext context, Address address, std::span<const std::byte> bytes)
        -> Result<std::optional<Instruction>> {
        PluginManager manager(state);
        return manager.decode_processor_semantic(context, address, bytes);
    };
    options.semantic_decoder_identity = [state] {
        auto identity = std::atomic_load(&state->semantic_identity);
        return identity ? *identity : std::vector<std::byte>{};
    };
    return options;
}
} // namespace hexlab::plugins

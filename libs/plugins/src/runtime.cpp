#include "hexlab/plugins/runtime.hpp"

#include "hexlab/loaders/recipe.hpp"

#include <algorithm>
#include <array>

namespace hexlab::plugins {
namespace {
std::string_view architecture_id(Architecture value) {
    switch (value) {
    case Architecture::x86: return "x86";
    case Architecture::x86_64: return "x86_64";
    case Architecture::arm: return "arm";
    case Architecture::arm64: return "arm64";
    case Architecture::riscv64: return "riscv64";
    case Architecture::riscv32: return "riscv32";
    case Architecture::mips32: return "mips32";
    case Architecture::mips64: return "mips64";
    case Architecture::powerpc: return "powerpc";
    case Architecture::mos6502: return "mos6502";
    case Architecture::wasm: return "wasm";
    case Architecture::dex: return "dex";
    case Architecture::jvm: return "jvm";
    default: return {};
    }
}
std::string_view mode_id(ExecutionMode value) {
    switch (value) {
    case ExecutionMode::x86_16: return "x86_16";
    case ExecutionMode::x86_32: return "x86_32";
    case ExecutionMode::x86_64: return "x86_64";
    case ExecutionMode::a32: return "a32";
    case ExecutionMode::thumb: return "thumb";
    case ExecutionMode::a64: return "a64";
    case ExecutionMode::rv64: return "rv64";
    case ExecutionMode::rv64c: return "rv64c";
    case ExecutionMode::rv32: return "rv32";
    case ExecutionMode::mips32: return "mips32";
    case ExecutionMode::mips64: return "mips64";
    case ExecutionMode::ppc32: return "ppc32";
    case ExecutionMode::ppc64: return "ppc64";
    case ExecutionMode::wasm32: return "wasm32";
    case ExecutionMode::dex: return "dex";
    case ExecutionMode::jvm: return "jvm";
    case ExecutionMode::m6502: return "m6502";
    default: return {};
    }
}
}

Result<DecodeDispatchResult> decode_with_extensions(const PluginManager& manager, DecodeContext context,
                                                     std::span<const std::byte> bytes, Address at) {
    const auto architecture = architecture_id(context.architecture);
    const auto mode = mode_id(context.mode);
    if (!architecture.empty() && !mode.empty() && !bytes.empty()) {
        auto semantic = manager.decode_processor_semantic(context, at, bytes);
        if (!semantic) return semantic.error();
        if (semantic.value()) return DecodeDispatchResult{std::move(*semantic.value())};
        const auto raw = std::span(reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size());
        auto extension = manager.decode_processor(std::string(architecture), std::string(mode), at.offset, raw);
        if (!extension) return extension.error();
        if (extension.value()) return DecodeDispatchResult{std::move(*extension.value())};
    }
    return DecodeDispatchResult{decode_instruction(context, bytes, at)};
}

Status apply_display_extension(const PluginManager& manager, Instruction& instruction) {
    const auto architecture = architecture_id(instruction.context.architecture);
    const auto mode = mode_id(instruction.context.mode);
    if (architecture.empty() || mode.empty() || instruction.length == 0) return std::monostate{};
    // Processor extension ABI's byte buffer is capped at the native 15-byte ISA maximum.
    if (!instruction.extended_bytes.empty()) return std::monostate{};
    const auto encoded = instruction.encoded_bytes();
    const auto raw = std::span(reinterpret_cast<const std::uint8_t*>(encoded.data()), encoded.size());
    if (instruction.opcode == Opcode::opaque) {
        auto semantic = manager.decode_processor_semantic(instruction.context, instruction.address,
                                                           encoded);
        if (!semantic) return semantic.error();
        if (semantic.value() && semantic.value()->length == instruction.length) {
            instruction = std::move(*semantic.value());
            return std::monostate{};
        }
    }
    auto extension = manager.decode_processor(std::string(architecture), std::string(mode),
                                              instruction.address.offset, raw);
    if (!extension) return extension.error();
    if (!extension.value()) return std::monostate{};
    const auto& decoded = *extension.value();
    if (instruction.opcode != Opcode::nop || instruction.flow != FlowKind::fallthrough ||
        decoded.length != instruction.length || decoded.flow != HEXLAB_INSTRUCTION_FLOW_NORMAL)
        return std::monostate{};
    instruction.opcode = Opcode::opaque;
    instruction.mnemonic_override = decoded.mnemonic;
    return std::monostate{};
}

Result<decompiler::LiftedFunction> lift_function_with_extensions(
    const PluginManager &manager,const FunctionRecord &function,const FunctionSnapshot &snapshot,
    const AnalysisOptions &requested_options,std::stop_token stop) {
    if(stop.stop_requested())return Error{ErrorCode::canceled,"Plugin IR lifting canceled"};
    auto options=manager.analysis_options(requested_options);
    if(!options.semantic_decoder_identity)return Error{ErrorCode::conflict,"Plugin semantic identity is unavailable"};
    const auto identity=options.semantic_decoder_identity();
    if(identity.empty())return Error{ErrorCode::conflict,"Plugin semantic identity is empty"};
    options.semantic_decoder_identity=[identity]{return identity;};
    if(!snapshot.key||snapshot.key->engine_fingerprint!=function_engine_fingerprint(options))
        return Error{ErrorCode::conflict,"Function snapshot does not match the active plugin semantic generation and analysis options"};
    std::size_t requests=0;
    auto result=decompiler::lift_function(function,snapshot,nullptr,nullptr,
        [&](const Instruction &instruction)->Result<std::optional<decompiler::Intrinsic>>{
            if(stop.stop_requested())return Error{ErrorCode::canceled,"Plugin IR lifting canceled"};
            if(++requests>4096)return Error{ErrorCode::resource_limit,"Function exceeds the 4096 plugin-IR instruction limit"};
            return manager.instruction_ir(instruction,identity);
        });
    if(!result)return result.error();
    if(stop.stop_requested())return Error{ErrorCode::canceled,"Plugin IR lifting canceled"};
    const auto current=manager.analysis_options().semantic_decoder_identity;
    if(!current||current()!=identity)return Error{ErrorCode::conflict,"Plugin semantic generation changed during lifting"};
    return result;
}

Result<LoaderDispatchResult> detect_with_extensions(const PluginManager& manager, const ByteStorage& storage,
                                                     std::span<const std::uint8_t> probe_prefix,
                                                     const std::string& requested_format) {
    if (storage.size() == 0) return Error{ErrorCode::invalid_argument, "loader input is empty"};
    if (!probe_prefix.empty()) {
        auto extension = manager.probe_loaders(probe_prefix, requested_format, storage.size());
        if (!extension) return extension.error();
        if (extension.value()) return LoaderDispatchResult{std::move(*extension.value())};
    }
    auto builtin = detect_format(storage);
    if (!builtin) return builtin.error();
    return LoaderDispatchResult{builtin.value()};
}

} // namespace hexlab::plugins

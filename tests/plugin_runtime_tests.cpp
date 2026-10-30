#include "hexlab/plugins/runtime.hpp"
#include "hexlab/workspace/project_analysis.hpp"
#include "hexlab/database/project_state.hpp"
#include "hexlab/image/byte_storage.hpp"

#include <algorithm>
#include <cstring>
#include <cstdio>
#include <cstdlib>

using namespace hexlab;
using namespace hexlab::plugins;

namespace {
int failures = 0;
void check(bool value, const char* message) { if (!value) { std::fprintf(stderr, "%s\n", message); ++failures; } }
int32_t decode(void*, uint64_t, const uint8_t* data, uint32_t size, HexLabDecodedInstruction* out) {
    if (size < 2 || data[0] != 0xFE || (data[1] != 0xED && data[1] != 0xEE)) return 0;
    out->length = 2;
    if (data[1] == 0xEE) {
        out->flow = HEXLAB_INSTRUCTION_FLOW_BRANCH;
        std::memcpy(out->mnemonic, "plugin-branch", sizeof("plugin-branch"));
        std::memcpy(out->operands, "0x1234", sizeof("0x1234"));
    } else {
        out->flow = HEXLAB_INSTRUCTION_FLOW_NORMAL;
        std::memcpy(out->mnemonic, "plugin-op", sizeof("plugin-op"));
    }
    return 1;
}
int32_t malformed_decode(void*, uint64_t, const uint8_t* data, uint32_t size, HexLabDecodedInstruction* out) {
    if (!size || data[0] < 1 || data[0] > 4) return 0;
    out->length = 1;
    std::memcpy(out->mnemonic, "bad", sizeof("bad"));
    switch (data[0]) {
    case 1: out->length = size + 1; break;
    case 2: out->reserved = 1; break;
    case 3: out->flow = 99; break;
    case 4: std::memset(out->mnemonic, 'x', sizeof(out->mnemonic)); break;
    }
    return 1;
}
int32_t semantic_decode(void*, uint64_t, const uint8_t* data, uint32_t size, HexLabSemanticInstruction* out) {
    if (!size || data[0] < 0xA0 || data[0] > 0xA6) return 0;
    out->length = 1; out->flow = HEXLAB_INSTRUCTION_FLOW_NORMAL;
    std::memcpy(out->mnemonic, "plugin-add", sizeof("plugin-add"));
    out->operand_count = 2;
    out->operands[0] = {HEXLAB_SEMANTIC_REGISTER, HEXLAB_SEMANTIC_GPR, 1, 32,
                        HEXLAB_SEMANTIC_WRITE, 0, 0};
    out->operands[1] = {HEXLAB_SEMANTIC_IMMEDIATE, 0, 0, 32,
                        HEXLAB_SEMANTIC_READ, 0, 7};
    if (data[0] == 0xA1) out->operand_count = 5;
    if (data[0] == 0xA2) out->operands[0].width = 999;
    if (data[0] == 0xA3) out->operands[1].access = 99;
    if (data[0] == 0xA4) out->reserved = 1;
    if (data[0] == 0xA5) {
        out->flow = HEXLAB_INSTRUCTION_FLOW_BRANCH;
        out->operand_count = 1;
        out->operands[0] = {HEXLAB_SEMANTIC_RELATIVE, 0, 0, 32,
                            HEXLAB_SEMANTIC_READ, 0, UINT64_C(0xfffffffffffffffc)};
    }
    if (data[0] == 0xA6) out->operands[1].bank = 99;
    return 1;
}
int32_t a64_call_decode(void*, uint64_t, const uint8_t* data, uint32_t size, HexLabSemanticInstruction* out) {
    if (size < 4 || data[0] != 0xff || data[1] != 0xff || data[2] != 0xff || data[3] != 0xff) return 0;
    out->length = 4; out->flow = HEXLAB_INSTRUCTION_FLOW_CALL;
    std::memcpy(out->mnemonic, "plugin-call", sizeof("plugin-call"));
    out->operand_count = 1;
    out->operands[0] = {HEXLAB_SEMANTIC_RELATIVE, 0, 0, 32,
                        HEXLAB_SEMANTIC_READ, 0, 12};
    return 1;
}
int32_t a64_display_decode(void*, uint64_t, const uint8_t*, uint32_t, HexLabDecodedInstruction*) { return 0; }
int32_t probe(void*, const uint8_t* data, uint32_t size, uint64_t, uint32_t* confidence) {
    if (size < 2 || data[0] != 0xFA || data[1] != 0xCE) return 0;
    *confidence = 900; return 1;
}
int32_t start(const HexLabHostApi* host, void**) {
    HexLabProcessorExtension cpu{}; cpu.struct_size = sizeof(cpu); cpu.api_version = HEXLAB_EXTENSION_API_VERSION;
    cpu.extension_id = "cpu.test"; cpu.architecture_id = "x86_64"; cpu.mode_id = "x86_64"; cpu.decode = decode;
    cpu.struct_size = offsetof(HexLabProcessorExtension, decode_semantic);
    HexLabProcessorExtension malformed{}; malformed.struct_size = sizeof(malformed);
    malformed.api_version = HEXLAB_EXTENSION_API_VERSION; malformed.extension_id = "cpu.malformed";
    malformed.architecture_id = "test"; malformed.mode_id = "test"; malformed.decode = malformed_decode;
    HexLabProcessorExtension semantic{}; semantic.struct_size = sizeof(semantic);
    semantic.api_version = HEXLAB_EXTENSION_API_VERSION; semantic.extension_id = "cpu.semantic";
    semantic.architecture_id = "x86_64"; semantic.mode_id = "x86_64";
    semantic.decode = decode; semantic.decode_semantic = semantic_decode;
    HexLabProcessorExtension a64{}; a64.struct_size = sizeof(a64);
    a64.api_version = HEXLAB_EXTENSION_API_VERSION; a64.extension_id = "cpu.semantic.a64";
    a64.architecture_id = "arm64"; a64.mode_id = "a64"; a64.decode = a64_display_decode;
    a64.decode_semantic = a64_call_decode;
    HexLabLoaderExtension loader{}; loader.struct_size = sizeof(loader); loader.api_version = HEXLAB_EXTENSION_API_VERSION;
    loader.extension_id = "loader.test"; loader.format_id = "testfmt"; loader.probe = probe;
    return host->register_processor_extension(host->host_context, &cpu) == 0 &&
                   host->register_processor_extension(host->host_context, &malformed) == 0 &&
                   host->register_processor_extension(host->host_context, &semantic) == 0 &&
                   host->register_processor_extension(host->host_context, &a64) == 0 &&
                   host->register_loader_extension(host->host_context, &loader) == 0 ? 0 : -1;
}
void stop(void*) {}
int32_t query(uint32_t abi, const HexLabHostApi*, HexLabPluginApi* api) {
    api->struct_size = sizeof(*api); api->abi_major = abi; api->abi_minor = HEXLAB_PLUGIN_ABI_MINOR;
    api->plugin_id = "runtime.test"; api->name = "Runtime Test"; api->version = "1"; api->start = start; api->stop = stop;
    return 0;
}
class Provider final : public ModuleProvider {
public:
    Result<Module> open(const std::string&) override {
        return Module{this, [](void*, const char* symbol)->void* {
            return std::strcmp(symbol, HEXLAB_PLUGIN_QUERY_SYMBOL) == 0 ? reinterpret_cast<void*>(&query) : nullptr;
        }, [](void*){}};
    }
};
class Memory final : public ByteStorage {
public:
    explicit Memory(std::vector<std::byte> bytes) : bytes_(std::move(bytes)) {}
    uint64_t size() const noexcept override { return bytes_.size(); }
    Result<ByteView> read_at(FileOffset at, size_t size) const override {
        if (at.value > bytes_.size() || size > bytes_.size() - at.value)
            return Error{ErrorCode::out_of_bounds, "read outside test bytes"};
        return ByteView{std::shared_ptr<const void>{}, std::span(bytes_).subspan(at.value, size)};
    }
private: std::vector<std::byte> bytes_;
};
template<class T> T take(Result<T> result) {
    if (!result) throw std::runtime_error(result.error().message);
    return std::move(result.value());
}
void project_semantic_roundtrip(PluginManager& manager) {
    auto path = std::filesystem::temp_directory_path() /
                ("hexlab-plugin-semantic-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".hxproj");
    const auto cleanup = [&] {
        std::error_code ignored;
        for (auto suffix : {L"", L"-wal", L"-shm"}) { auto item = path; item += suffix; std::filesystem::remove(item, ignored); }
    };
    try {
        std::vector<std::byte> image(20);
        image[0]=std::byte{0xff}; image[1]=std::byte{0xff}; image[2]=std::byte{0xff}; image[3]=std::byte{0xff};
        image[4]=std::byte{0xc0}; image[5]=std::byte{0x03}; image[6]=std::byte{0x5f}; image[7]=std::byte{0xd6};
        image[16]=std::byte{0xc0}; image[17]=std::byte{0x03}; image[18]=std::byte{0x5f}; image[19]=std::byte{0xd6};
        auto source = Memory(std::move(image));
        auto store = take(database::ProjectStore::create(path, {}));
        RawOptions raw{Architecture::arm64, ExecutionMode::a64, {{0}, 0x1000}, true, false, true, {}};
        take(store->import_input(source, {Format::raw, raw}, {}, {}));
        auto options = manager.analysis_options();
        // This test extension is intentionally pure over the callback bytes,
        // so it can certify that it consults no external inputs.
        options.semantic_decoder_read_set = [] {
            return std::vector<AnalysisOptions::SemanticDecoderInput>{};
        };
        auto session = take(ProjectSession::attach(store, options, {}));
        auto snapshot = session->snapshot();
        auto key = take(project_analysis_key(*snapshot, options));
        ProjectAnalysisRequest request; request.snapshot = snapshot; request.options = options;
        request.key = key; request.force_full = true; request.encode_cache = true;
        auto analysis = take(compute_project_analysis(request, {}));
        bool has_call_reference = false;
        if (analysis.derived.references) {
            const auto outgoing = analysis.derived.references->outgoing_view(Address{{0}, 0x1000});
            has_call_reference = std::any_of(outgoing.begin(), outgoing.end(), [](const auto& ref) {
                const auto* location = std::get_if<Location>(&ref.target);
                const auto* address = location ? std::get_if<Address>(location) : nullptr;
                return address && *address == Address{{0}, 0x1010};
            });
        }
        check(analysis.derived.functions && analysis.derived.functions->functions.size() == 2 &&
                  analysis.derived.functions->calls.size() == 1 &&
                  analysis.derived.functions->calls[0].target == Address{{0}, 0x1010} &&
                  has_call_reference,
              "plugin-decoded A64 call changes rooted project functions and references");
        check(bool(analysis.encoded_cache), "plugin-derived project analysis serializes to the persistent cache");
        if (analysis.encoded_cache) take(store->write_derived_cache(key, *analysis.encoded_cache, {}));
        session.reset(); store.reset();
        auto reopened_store = take(database::ProjectStore::open(path, database::ProjectMode::read_only, {}));
        auto reopened = take(ProjectSession::attach(reopened_store, options, {}))->snapshot();
        auto cached = take(reopened_store->load_derived_cache(key, *reopened->loaded->image,
                                                               reopened->loaded->metadata, options, {}));
        check(cached.status == database::CacheStatus::hit && cached.proposal &&
                  cached.proposal->functions->calls.size() == 1 &&
                  cached.proposal->functions->calls[0].target == Address{{0}, 0x1010},
              "reopened project validates and restores plugin-derived call/reference facts");
        take(manager.unload("runtime.test"));
        auto unloaded_options = manager.analysis_options();
        auto unloaded_key = take(project_analysis_key(*reopened, unloaded_options));
        auto invalidated = take(reopened_store->load_derived_cache(unloaded_key, *reopened->loaded->image,
                                                                    reopened->loaded->metadata, unloaded_options, {}));
        check(unloaded_key != key && invalidated.status != database::CacheStatus::hit,
              "unloading semantic extension invalidates its persisted analysis cache identity");
        take(manager.load("fake"));
    } catch (...) { cleanup(); throw; }
    cleanup();
}
}

int main() {
    PluginManager manager(std::make_shared<Provider>());
    auto loaded = manager.load("fake");
    if (!loaded) std::fprintf(stderr, "plugin load failed: %s\n", loaded.error().message.c_str());
    check(bool(loaded), "test extension should load");
    project_semantic_roundtrip(manager);
    auto analysis_options = manager.analysis_options();
    const auto loaded_identity = analysis_options.semantic_decoder_identity();
    const std::array<std::byte, 2> custom{std::byte{0xFE}, std::byte{0xED}};
    auto ext_decode = decode_with_extensions(manager, {Architecture::x86_64, ExecutionMode::x86_64}, custom, {{0}, 0x1234});
    check(ext_decode && std::holds_alternative<ProcessorDecodeResult>(ext_decode.value()), "matching extension decoder takes precedence");
    if (ext_decode && std::holds_alternative<ProcessorDecodeResult>(ext_decode.value())) {
        const auto& decoded = std::get<ProcessorDecodeResult>(ext_decode.value());
    check(decoded.mnemonic == "plugin-op" && decoded.length == 2, "extension result remains opaque and intact");
    }
    const std::array<std::byte, 2> custom_branch{std::byte{0xFE}, std::byte{0xEE}};
    const auto branch_decode = decode_with_extensions(
        manager, {Architecture::x86_64, ExecutionMode::x86_64}, custom_branch, {{0}, 0x1234});
    check(branch_decode && std::holds_alternative<ProcessorDecodeResult>(branch_decode.value()) &&
              std::get<ProcessorDecodeResult>(branch_decode.value()).flow == HEXLAB_INSTRUCTION_FLOW_BRANCH &&
              std::get<ProcessorDecodeResult>(branch_decode.value()).operands == "0x1234",
          "validated processor flow and operand text reach the runtime dispatch result");
    for (std::uint8_t marker = 1; marker <= 4; ++marker) {
        const std::array<std::uint8_t, 1> malformed{marker};
        PluginManager malformed_manager(std::make_shared<Provider>());
        const auto loaded_malformed = malformed_manager.load("fake");
        if (!loaded_malformed) {
            check(false, "malformed processor test extension loads");
            continue;
        }
        const auto rejected = malformed_manager.decode_processor("test", "test", 0, malformed);
        check(rejected && !rejected.value(),
              "invalid processor callback output is quarantined without a decode result");
    }
    const std::array<std::byte, 1> semantic_bytes{std::byte{0xA0}};
    auto semantic = manager.decode_processor_semantic({Architecture::x86_64, ExecutionMode::x86_64},
                                                       {{0}, 0x2000}, semantic_bytes);
    check(semantic && semantic.value() && semantic.value()->operands.size() == 2 &&
              semantic.value()->opcode == Opcode::opaque &&
              semantic.value()->mnemonic_override == "plugin-add" &&
              semantic.value()->access.size() == 2 &&
              semantic.value()->register_writes.size() == 1 &&
              std::get<ImmediateOperand>(semantic.value()->operands[1]).value == 7,
          "validated plugin semantic operands and effects convert to core instruction IR");
    auto dispatched_semantic = decode_with_extensions(manager, {Architecture::x86_64, ExecutionMode::x86_64},
                                                       semantic_bytes, {{0}, 0x2000});
    check(dispatched_semantic && std::holds_alternative<Instruction>(dispatched_semantic.value()) &&
              std::get<Instruction>(dispatched_semantic.value()).register_writes.size() == 1,
          "extension-aware decode exposes validated semantic instructions to IR consumers");
    Instruction undecoded{};
    undecoded.context = {Architecture::x86_64, ExecutionMode::x86_64};
    undecoded.address = {{0}, 0x2000}; undecoded.length = 1; undecoded.opcode = Opcode::opaque;
    undecoded.bytes[0] = std::byte{0xA0};
    auto decorated_semantic = apply_display_extension(manager, undecoded);
    check(decorated_semantic && undecoded.mnemonic_override == "plugin-add" &&
              undecoded.register_writes.size() == 1 && undecoded.operands.size() == 2,
          "CLI and desktop opaque rows can consume typed extension semantics at render time");
    const std::array<std::byte, 1> relative_bytes{std::byte{0xA5}};
    auto relative_semantic = manager.decode_processor_semantic({Architecture::x86_64, ExecutionMode::x86_64},
                                                                {{0}, 0x2000}, relative_bytes);
    check(relative_semantic && relative_semantic.value() && relative_semantic.value()->direct_target == Address{{0}, 0x1ffd} &&
              relative_semantic.value()->flow == FlowKind::conditional_branch,
          "relative semantic effects use checked address arithmetic and become typed branch facts");
    for (std::uint8_t marker = 0xA1; marker <= 0xA4; ++marker) {
        const std::array<std::byte, 1> bad_semantic{static_cast<std::byte>(marker)};
        PluginManager malformed_manager(std::make_shared<Provider>());
        const auto loaded_malformed = malformed_manager.load("fake");
        if (!loaded_malformed) {
            check(false, "malformed semantic test extension loads");
            continue;
        }
        const auto rejected = malformed_manager.decode_processor_semantic(
            {Architecture::x86_64, ExecutionMode::x86_64}, {{0}, 0x2000}, bad_semantic);
        check(rejected && !rejected.value(),
              "invalid semantic plugin record is quarantined without an instruction result");
    }
    const std::array<std::byte, 1> invalid_enum{std::byte{0xA6}};
    PluginManager invalid_enum_manager(std::make_shared<Provider>());
    const auto invalid_enum_loaded = invalid_enum_manager.load("fake");
    const auto invalid_enum_result = invalid_enum_loaded
        ? invalid_enum_manager.decode_processor_semantic(
              {Architecture::x86_64, ExecutionMode::x86_64}, {{0}, 0x2000}, invalid_enum)
        : Result<std::optional<Instruction>>{Error{ErrorCode::io, "malformed semantic test extension did not load"}};
    check(invalid_enum_loaded && invalid_enum_result && !invalid_enum_result.value(),
          "invalid operand enums quarantine the extension without an instruction result");
    Instruction display_only{};
    display_only.context = {Architecture::x86_64, ExecutionMode::x86_64};
    display_only.length = 2;
    display_only.bytes[0] = std::byte{0xFE};
    display_only.bytes[1] = std::byte{0xED};
    display_only.flow = FlowKind::fallthrough;
    auto applied = apply_display_extension(manager, display_only);
    check(applied && display_only.opcode == Opcode::opaque && display_only.mnemonic_override == "plugin-op" &&
              display_only.operands.empty() && display_only.flow == FlowKind::fallthrough,
          "processor extension contributes display text for a semantically empty normal-flow NOP");
    Instruction semantic_instruction = display_only;
    semantic_instruction.opcode = Opcode::mov;
    semantic_instruction.mnemonic_override.clear();
    semantic_instruction.operands.emplace_back(ImmediateOperand{7, 8, 8, false, std::nullopt});
    auto preserved = apply_display_extension(manager, semantic_instruction);
    check(preserved && semantic_instruction.opcode == Opcode::mov &&
              semantic_instruction.mnemonic_override.empty() && semantic_instruction.operands.size() == 1,
          "processor extension cannot replace an instruction with existing semantic facts");
    const std::array<std::byte, 1> nop{std::byte{0x90}};
    auto builtin = decode_with_extensions(manager, {Architecture::x86_64, ExecutionMode::x86_64}, nop, {{0}, 0});
    check(builtin && std::holds_alternative<DecodeResult>(builtin.value()) &&
              std::get<DecodeResult>(builtin.value()).instruction.has_value(), "declining extension falls back to built-in decoder");
    const std::array<uint8_t, 2> custom_header{0xFA, 0xCE};
    Memory custom_file({std::byte{0xFA}, std::byte{0xCE}});
    auto ext_loader = detect_with_extensions(manager, custom_file, custom_header);
    check(ext_loader && std::holds_alternative<LoaderProbeResult>(ext_loader.value()) &&
              std::get<LoaderProbeResult>(ext_loader.value()).format_id == "testfmt", "matching loader extension claims input");
    Memory unknown_file({std::byte{0}, std::byte{0}});
    auto builtin_loader = detect_with_extensions(manager, unknown_file, {});
    check(builtin_loader && std::holds_alternative<DetectedFormat>(builtin_loader.value()) &&
              std::get<DetectedFormat>(builtin_loader.value()) == DetectedFormat::unknown, "no plugin claim falls back to built-in format detection");
    check(bool(manager.unload("runtime.test")), "plugin unload completes after semantic dispatch");
    const auto unloaded_identity = analysis_options.semantic_decoder_identity();
    check(loaded_identity != unloaded_identity,
          "semantic analysis identity changes on unload so persisted plugin-derived facts cannot be reused");
    auto after_unload = manager.decode_processor_semantic({Architecture::x86_64, ExecutionMode::x86_64},
                                                           {{0}, 0x2000}, semantic_bytes);
    check(after_unload && !after_unload.value(), "semantic callbacks are unregistered before module unload");
    auto reloaded = manager.load("fake");
    check(bool(reloaded) && analysis_options.semantic_decoder_identity() != loaded_identity &&
              analysis_options.semantic_decoder_identity() != unloaded_identity,
          "semantic analysis identity is generation-stamped across unload and reload of identical plugin metadata");
    return failures ? 1 : 0;
}

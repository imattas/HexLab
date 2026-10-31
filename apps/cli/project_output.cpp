#include "project_arguments.hpp"
#include "signature_catalog_inputs.hpp"
#include "argument_text.hpp"
#include "argument_text.hpp"
#include "profile_output.hpp"
#include "elf_output.hpp"
#include "macho_output.hpp"
#include "pe_output.hpp"
#include "jvm_output.hpp"
#include "wasm_output.hpp"
#include "dex_output.hpp"
#include "hexlab/workspace/project_graph.hpp"
#include "hexlab/analysis/switches.hpp"
#include "hexlab/analysis/stack.hpp"
#include "hexlab/analysis/signatures.hpp"
#include "hexlab/analysis/flirt.hpp"
#include "hexlab/decompiler/decompiler.hpp"
#include "hexlab/decompiler/type_recovery.hpp"
#include "hexlab/processors/format.hpp"
#include "hexlab/loaders/cil.hpp"
#include "hexlab/loaders/pe.hpp"
#include "hexlab/image/file_storage.hpp"
#include <algorithm>
#include <iomanip>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <tuple>
namespace hexlab::cli::project_detail {
namespace {
std::string search_json_string(std::string_view value) {
    std::ostringstream out;
    out << '"';
    for (const unsigned char c : value) {
        switch (c) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 0x20) out << "\\u00" << std::hex << std::setw(2) << std::setfill('0')
                              << static_cast<unsigned>(c) << std::dec;
            else out << static_cast<char>(c);
        }
    }
    out << '"';
    return out.str();
}
Sha256Digest catalog_digest(std::string_view text){Sha256 hash;auto bytes=std::span(reinterpret_cast<const std::byte*>(text.data()),text.size());auto updated=hash.update(bytes);if(!updated)throw Failure{updated.error()};return hash.digest();}
const char *status(DerivedStatus value) {
    switch (value) {
    case DerivedStatus::fresh:
        return "fresh";
    case DerivedStatus::pending:
        return "pending";
    case DerivedStatus::stale:
        return "stale";
    case DerivedStatus::incomplete:
        return "incomplete";
    case DerivedStatus::file_only:
        return "file-only";
    }
    return "unknown";
}
const char *reference_kind(ReferenceKind kind) {
    switch (kind) {
    case ReferenceKind::call:
        return "call";
    case ReferenceKind::jump:
        return "jump";
    case ReferenceKind::conditional_jump:
        return "conditional-jump";
    case ReferenceKind::memory_read:
        return "read";
    case ReferenceKind::memory_write:
        return "write";
    case ReferenceKind::memory_read_write:
        return "read-write";
    case ReferenceKind::memory_address:
        return "address";
    case ReferenceKind::imported_call:
        return "imported-call";
    case ReferenceKind::imported_jump:
        return "imported-jump";
    case ReferenceKind::user_code:
        return "user-code";
    case ReferenceKind::user_data:
        return "user-data";
    case ReferenceKind::relocation:
        return "relocation";
    case ReferenceKind::dyld_fixup:
        return "dyld-fixup";
    }
    return "unknown";
}
const char *elf_resolution(ElfResolutionReason value) {
    switch (value) {
    case ElfResolutionReason::none:
        return "none";
    case ElfResolutionReason::resolved:
        return "resolved";
    case ElfResolutionReason::ambiguous:
        return "ambiguous";
    case ElfResolutionReason::field_mismatch:
        return "field-mismatch";
    case ElfResolutionReason::unsupported:
        return "unsupported";
    case ElfResolutionReason::unavailable_symbol:
        return "unavailable-symbol";
    case ElfResolutionReason::undefined_symbol:
        return "undefined-symbol";
    case ElfResolutionReason::symbol_not_address:
        return "symbol-not-address";
    case ElfResolutionReason::preemptible_symbol:
        return "preemptible-symbol";
    case ElfResolutionReason::unavailable_addend:
        return "unavailable-addend";
    case ElfResolutionReason::overflow:
        return "overflow";
    }
    return "unknown";
}
std::string managed_type_text(const ManagedTypeSignature &type, unsigned depth = 0) {
    if (depth > 16) return "<depth-limit>";
    const auto child = [&](std::size_t index) {
        return index < type.children.size() ? managed_type_text(type.children[index], depth + 1) : std::string("<missing>");
    };
    switch (type.element_type) {
    case 0x02: return "bool";
    case 0x03: return "char";
    case 0x04: return "int8";
    case 0x05: return "uint8";
    case 0x06: return "int16";
    case 0x07: return "uint16";
    case 0x08: return "int32";
    case 0x09: return "uint32";
    case 0x0a: return "int64";
    case 0x0b: return "uint64";
    case 0x0c: return "float32";
    case 0x0d: return "float64";
    case 0x0e: return "string";
    case 0x0f: return child(0) + "*";
    case 0x10: return child(0) + "&";
    case 0x11: case 0x12: {
        if (type.type_spec_signature)
            return "typespec(" + managed_type_text(*type.type_spec_signature, depth + 1) + ")";
        auto name = type.metadata_type_name.empty() ? std::string("<unresolved-type>") : type.metadata_type_name;
        if (type.metadata_type_external_unresolved) name += " [unresolved:" + type.metadata_type_scope + "]";
        return name;
    }
    case 0x13: return "!" + std::to_string(type.generic_index);
    case 0x14: {
        std::string result = child(0) + "[";
        if (type.array_rank > 0) result.append(type.array_rank - 1, ',');
        return result + "]";
    }
    case 0x15: {
        auto name = type.metadata_type_name.empty() ? std::string("<unresolved-generic-type>") : type.metadata_type_name;
        if (type.type_spec_signature)
            name = "typespec(" + managed_type_text(*type.type_spec_signature, depth + 1) + ")";
        if (type.metadata_type_external_unresolved) name += " [unresolved:" + type.metadata_type_scope + "]";
        name += '<';
        for (std::size_t i = 0; i < type.children.size(); ++i) {
            if (i) name += ',';
            name += managed_type_text(type.children[i], depth + 1);
        }
        return name + '>';
    }
    case 0x16: return "typedref";
    case 0x18: return "native-int";
    case 0x19: return "native-uint";
    case 0x1c: return "object";
    case 0x1d: return child(0) + "[]";
    case 0x1e: return "!!" + std::to_string(type.generic_index);
    default:
        if (type.type_spec_signature)
            return "typespec(" + managed_type_text(*type.type_spec_signature, depth + 1) + ")";
        return "element-type-0x" + [&] { std::ostringstream value; value << std::hex << unsigned(type.element_type); return value.str(); }();
    }
}
const char *managed_marshal_status(ManagedMarshalDescriptorStatus status) {
    switch (status) {
    case ManagedMarshalDescriptorStatus::decoded_scalar: return "scalar";
    case ManagedMarshalDescriptorStatus::decoded_array: return "array";
    case ManagedMarshalDescriptorStatus::decoded_custom_marshaler: return "custom-marshaler";
    case ManagedMarshalDescriptorStatus::opaque_unknown: return "opaque-unknown";
    }
    return "unknown";
}
void managed_marshal_owner_summary(std::ostream &out, const ManagedMarshalDescriptor &descriptor) {
    out << " marshal-token=0x" << std::hex << descriptor.token << std::dec
        << " marshal-decode=" << managed_marshal_status(descriptor.decode_status);
    if (!descriptor.native_type_name.empty()) out << " marshal-type=" << escape(descriptor.native_type_name);
    out << " marshal-bytes=" << descriptor.native_type.size();
}
void print_generic_parameter(std::ostream &out, const ManagedGenericParameter &parameter) {
    const auto variance = parameter.flags & 0x3u;
    out << "  Generic parameter: number=" << parameter.number
        << " token=0x" << std::hex << parameter.token << std::dec
        << " metadata-offset=0x" << std::hex << parameter.metadata_offset << std::dec
        << " name=" << escape(parameter.name)
        << " variance=" << (variance == 1 ? "covariant" : variance == 2 ? "contravariant" : "none")
        << " reference-type=" << ((parameter.flags & 0x4u) ? "true" : "false")
        << " value-type=" << ((parameter.flags & 0x8u) ? "true" : "false")
        << " default-constructor=" << ((parameter.flags & 0x10u) ? "true" : "false") << '\n';
    for (std::size_t index = 0; index < parameter.constraint_tokens.size(); ++index) {
        out << "    Constraint token: 0x" << std::hex << parameter.constraint_tokens[index] << std::dec;
        if (index < parameter.constraint_metadata_offsets.size())
            out << " metadata-offset=0x" << std::hex << parameter.constraint_metadata_offsets[index] << std::dec;
        out << '\n';
    }
}
struct ParsedFlirtInputs {
    std::vector<FlirtCatalog> catalogs;
    std::string identity;
};
ParsedFlirtInputs load_flirt_inputs(const Arguments &args, const Image &image) {
    struct Input { std::filesystem::path path; std::string provenance; };
    std::vector<Input> inputs;
    if (args.flirt_definitions_list.empty()) {
        inputs.push_back({args.flirt_definitions, args.flirt_provenance});
    } else {
        std::error_code error;
        const auto size = std::filesystem::file_size(args.flirt_definitions_list, error);
        if (error || size > 1024 * 1024)
            throw Failure{{ErrorCode::invalid_argument, "Cannot read FLAIR catalog list or list exceeds 1 MiB"}};
        std::ifstream stream(args.flirt_definitions_list, std::ios::binary);
        if (!stream) throw Failure{{ErrorCode::io, "Cannot open FLAIR catalog list"}};
        std::string contents(static_cast<std::size_t>(size), '\0');
        if (size && !stream.read(contents.data(), static_cast<std::streamsize>(size)))
            throw Failure{{ErrorCode::io, "Cannot read FLAIR catalog list"}};
        if (contents.starts_with("\xef\xbb\xbf")) contents.erase(0, 3);
        std::istringstream lines(contents);
        std::string line;
        while (std::getline(lines, line)) {
            const auto first = line.find_first_not_of(" \t\r");
            if (first == std::string::npos || line[first] == '#') continue;
            const auto last = line.find_last_not_of(" \t\r");
            const auto item = line.substr(first, last - first + 1);
            auto path = path_from_wide(utf8_to_wide(item));
            if (path.is_relative()) path = args.flirt_definitions_list.parent_path() / path;
            auto provenance = args.flirt_provenance + " [" + item + "]";
            if (provenance.size() > 256)
                throw Failure{{ErrorCode::invalid_argument, "FLAIR per-catalog provenance exceeds 256 bytes"}};
            inputs.push_back({std::move(path), std::move(provenance)});
            if (inputs.size() > args.flirt_limits.max_catalogs)
                throw Failure{{ErrorCode::resource_limit, "FLAIR catalog list exceeds the catalog-count budget"}};
        }
        if (inputs.empty())
            throw Failure{{ErrorCode::invalid_argument, "FLAIR catalog list contains no paths"}};
    }

    ParsedFlirtInputs result;
    result.catalogs.reserve(inputs.size());
    std::uint64_t input_bytes = 0, inflated_bytes = 0, pattern_count = 0;
    for (const auto &item : inputs) {
        if (pattern_count >= args.flirt_limits.max_patterns)
            throw Failure{{ErrorCode::resource_limit, "FLAIR catalog set exceeds its aggregate pattern budget"}};
        std::error_code error;
        const auto size = std::filesystem::file_size(item.path, error);
        if (error || size > args.flirt_catalog_limits.max_bytes - input_bytes)
            throw Failure{{ErrorCode::invalid_argument, "Cannot read FLAIR catalog set or aggregate input exceeds its byte budget"}};
        std::ifstream stream(item.path, std::ios::binary);
        if (!stream) throw Failure{{ErrorCode::io, "Cannot open FLAIR catalog"}};
        std::string text(static_cast<std::size_t>(size), '\0');
        if (size && !stream.read(text.data(), static_cast<std::streamsize>(size)))
            throw Failure{{ErrorCode::io, "Cannot read FLAIR catalog"}};
        input_bytes += size;

        auto limits = args.flirt_catalog_limits;
        limits.max_bytes = static_cast<std::size_t>(args.flirt_catalog_limits.max_bytes - input_bytes + size);
        limits.max_inflated_bytes = static_cast<std::size_t>(std::max<std::uint64_t>(1,
            args.flirt_catalog_limits.max_inflated_bytes - inflated_bytes));
        limits.max_patterns = static_cast<std::size_t>(std::min<std::uint64_t>(limits.max_patterns,
            args.flirt_limits.max_patterns - pattern_count));
        const auto bytes = std::span<const std::byte>(reinterpret_cast<const std::byte *>(text.data()), text.size());
        Result<FlirtCatalog> parsed = text.size() >= 6 && text.compare(0, 6, "IDASGN") == 0
            ? parse_flirt_sig(bytes, item.provenance, limits)
            : text.size() >= 2 && static_cast<unsigned char>(text[0]) == 0x1f &&
                static_cast<unsigned char>(text[1]) == 0x8b
            ? parse_flirt_pat_gz(bytes, image.layout().architecture, image.layout().mode, item.provenance, limits)
            : parse_flirt_pat(text, image.layout().architecture, image.layout().mode, item.provenance, limits);
        auto catalog = take(std::move(parsed));
        if (catalog.inflated_body_bytes > args.flirt_catalog_limits.max_inflated_bytes - inflated_bytes)
            throw Failure{{ErrorCode::resource_limit, "FLAIR catalog set exceeds its aggregate inflated-byte budget"}};
        if (catalog.patterns.size() > args.flirt_limits.max_patterns - pattern_count)
            throw Failure{{ErrorCode::resource_limit, "FLAIR catalog set exceeds its aggregate pattern budget"}};
        inflated_bytes += catalog.inflated_body_bytes;
        pattern_count += catalog.patterns.size();
        if (args.flirt_definitions_list.empty()) {
            result.identity = std::to_string(args.flirt_provenance.size()) + ":" + args.flirt_provenance + text;
        } else {
            result.identity += std::to_string(item.provenance.size()) + ":" + item.provenance +
                std::to_string(text.size()) + ":" + text;
        }
        result.catalogs.push_back(std::move(catalog));
    }
    return result;
}
} // namespace
void print_inspection(std::ostream &out, const ProjectSnapshot &snapshot) {
    auto &state = *snapshot.state;
    out << "Project UUID: ";
    for (auto b : state.uuid)
        out << std::hex << std::setw(2) << std::setfill('0') << std::to_integer<unsigned>(b);
    out << std::dec << "\nInput bytes: " << state.input.size << "\nInput SHA256: " << digest_hex(state.input.sha256)
        << "\nEdit revision: " << state.revisions.edit << "\nByte revision: " << state.revisions.bytes
        << "\nDecision revision: " << state.revisions.decisions
        << "\nMode: " << (snapshot.mode == database::ProjectMode::read_write ? "editable" : "read-only")
        << "\nAnalysis: " << status(snapshot.status) << '\n';
    if (!snapshot.reason.empty())
        out << "Reason: " << escape(snapshot.reason) << '\n';
    if (snapshot.loaded) {
        if (const auto &firmware = snapshot.loaded->metadata.firmware) {
            out << "Format: " << snapshot.loaded->metadata.format
                << "\nData bytes: " << snapshot.loaded->metadata.image_size
                << "\nRecords: " << firmware->records.size() << '\n';
            if (firmware->has_start_address)
                out << "Start address: " << hex(firmware->start_address) << '\n';
        }
        profile_description(out, *snapshot.loaded->image);
        elf_description(out, snapshot.loaded->metadata, snapshot.loaded->image.get());
        macho_description(out, snapshot.loaded->metadata, snapshot.loaded->image.get());
        pe_description(out, snapshot.loaded->metadata, snapshot.loaded->image.get());
        jvm_description(out, snapshot.loaded->metadata);
        wasm_description(out, snapshot.loaded->metadata);
        dex_description(out, snapshot.loaded->metadata);
    }
    for (auto &annotation : state.user->annotations) {
        out << "Annotation: " << location(annotation.location) << " name=" << escape(annotation.name)
            << " comment=" << escape(annotation.comment);
        if (snapshot.loaded)
            profile_coordinate(out, *snapshot.loaded->image, annotation.location);
        out << '\n';
    }
    for (auto &bookmark : state.user->bookmarks) {
        out << "Bookmark: " << location(bookmark.location) << " label=" << escape(bookmark.label);
        if (snapshot.loaded)
            profile_coordinate(out, *snapshot.loaded->image, bookmark.location);
        out << '\n';
    }
    for (auto &patch : state.user->patches)
        out << "Patch: " << location(patch.begin) << " size=" << patch.replacement.size() << '\n';
}
int print_derived(std::ostream &out, const Arguments &args, const ProjectSnapshot &snapshot,ProjectActor& actor) {
    if (args.action == L"decompile") {
        require(snapshot.loaded && snapshot.loaded->image && snapshot.functions && args.at &&
                    std::holds_alternative<Address>(*args.at),
                "Project decompilation requires current function analysis and a virtual function entry");
        require(snapshot.status == DerivedStatus::fresh || snapshot.status == DerivedStatus::incomplete,
                "Project decompilation requires current analysis; refresh the project and retry");
        const auto entry = std::get<Address>(*args.at);
        const auto found = std::find_if(snapshot.functions->functions.begin(), snapshot.functions->functions.end(),
            [&](const auto &function) { return function && function->entry == entry; });
        require(found != snapshot.functions->functions.end(), "No recovered function begins at the requested address");
        const auto &function = **found;
        require(function.blocks.size() <= 100000 && snapshot.functions->blocks.size() <= 1000000,
                "Project decompilation exceeds the block budget");
        std::map<BlockId, const BasicBlock *> blocks;
        for (const auto &block : snapshot.functions->blocks)
            if (block) blocks.emplace(block->id, block.get());
        std::map<std::uint64_t, const InstructionFact *> instruction_facts;
        std::uint64_t instruction_count = 0;
        for (const auto id : function.blocks) {
            const auto block = blocks.find(id);
            require(block != blocks.end(), "Recovered function references a missing basic block");
            instruction_count += block->second->instructions.size();
            require(instruction_count <= 1000000, "Project decompilation exceeds the instruction budget");
            for (const auto &fact : block->second->instructions)
                if (fact) instruction_facts.emplace(fact->id, fact.get());
        }
        const auto &image = *snapshot.loaded->image;
        const auto &metadata = snapshot.loaded->metadata;
        decompiler::AbiDescription abi;
        switch (image.layout().architecture) {
        case Architecture::x86:
            if (image.layout().mode == ExecutionMode::x86_32) abi = decompiler::x86_32_cdecl_abi();
            break;
        case Architecture::x86_64:
            abi = metadata.pe ? decompiler::x86_64_windows_abi() : decompiler::x86_64_system_v_abi();
            break;
        case Architecture::arm: abi = decompiler::arm32_aapcs_abi(); break;
        case Architecture::arm64: abi = decompiler::aarch64_abi(); break;
        case Architecture::riscv32: abi = decompiler::riscv32_ilp32_abi(); break;
        case Architecture::riscv64: abi = decompiler::riscv64_lp64_abi(); break;
        case Architecture::mips32: abi = decompiler::mips32_o32_abi(); break;
        case Architecture::mips64:
            abi = image.layout().space.width_bits == 32 ? decompiler::mips_n32_abi() : decompiler::mips64_n64_abi();
            break;
        case Architecture::powerpc:
            if (image.layout().mode == ExecutionMode::ppc64 && metadata.elf &&
                metadata.elf->header.is_64 && metadata.elf->header.machine == 21 &&
                metadata.elf->header.order == ByteOrder::little && (metadata.elf->header.flags & 3u) == 2u)
                abi = decompiler::ppc64le_elfv2_abi();
            break;
        default: break;
        }
        auto lifted = take(decompiler::lift_function(function, *snapshot.functions,
            metadata.jvm ? &*metadata.jvm : nullptr, metadata.wasm ? &*metadata.wasm : nullptr,
            metadata.dex ? &*metadata.dex : nullptr));
        auto call_effects = take(decompiler::prepare_call_effects(lifted, abi));
        auto call_arguments = abi.integer_argument_registers;
        call_arguments.insert(call_arguments.end(), abi.floating_argument_registers.begin(),
                              abi.floating_argument_registers.end());
        call_arguments.insert(call_arguments.end(), abi.vector_argument_registers.begin(),
                              abi.vector_argument_registers.end());
        auto ssa = take(decompiler::to_ssa(call_effects, call_arguments));
        auto constants = take(decompiler::simplify_constants(ssa));
        auto identities = take(decompiler::simplify_identities(constants));
        auto dead = take(decompiler::eliminate_dead_code(identities));
        auto pseudocode = decompiler::format_pseudocode_with_types(dead, abi, types::TypePtr{});
        std::optional<decompiler::StructuredPseudocode> structured;
        if (!pseudocode)
            structured = decompiler::format_structured_pseudocode(dead);
        const bool typed_output = bool(pseudocode);
        const std::string pseudocode_text = typed_output ? pseudocode.value() : structured->text;
        const std::string typed_error = typed_output ? std::string{} : pseudocode.error().message;
        std::string fallback_reason;
        if (!typed_output) {
            fallback_reason = typed_error;
            if (structured->used_fallback) {
                if (!fallback_reason.empty()) fallback_reason += "; ";
                fallback_reason += structured->fallback_reason;
            }
        }
        const bool complete = function.complete && snapshot.functions->complete &&
                              snapshot.status == DerivedStatus::fresh;
        if (args.decompile_json) {
            constexpr std::size_t max_origin_rows = 100000;
            std::uint64_t total_origins = 0;
            for (const auto &block : dead.blocks) total_origins += block.instructions.size();
            const auto emitted_origins = static_cast<std::size_t>(std::min<std::uint64_t>(
                total_origins, max_origin_rows));
            out << "{\"schema\":\"hexlab.project-decompile.v1\",\"schema_version\":1,\"entry\":"
                << search_json_string(location(entry)) << ",\"analysis_status\":"
                << search_json_string(complete ? "complete" : "partial") << ",\"partial\":"
                << (complete ? "false" : "true") << ",\"pseudocode_format\":"
                << search_json_string(typed_output ? "typed" : "structured_fallback")
                << ",\"fallback\":" << (typed_output ? "false" : "true")
                << ",\"structured_fallback_used\":"
                << (structured && structured->used_fallback ? "true" : "false")
                << ",\"fallback_reason\":";
            if (typed_output) out << "null";
            else out << search_json_string(fallback_reason);
            out << ",\"pseudocode\":" << search_json_string(pseudocode_text)
                << ",\"instruction_count\":" << instruction_count
                << ",\"lifted_instruction_count\":" << total_origins
                << ",\"origin_rows\":[";
            std::size_t emitted = 0;
            for (const auto &block : dead.blocks) {
                for (const auto &instruction : block.instructions) {
                    if (emitted == emitted_origins) break;
                    if (emitted++) out << ',';
                    const auto fact = instruction_facts.find(instruction.origin.instruction_id);
                    require(fact != instruction_facts.end(),
                            "Decompiled instruction has no matching source origin");
                    out << "{\"address\":" << search_json_string(location(instruction.origin.address))
                        << ",\"instruction_id\":" << instruction.origin.instruction_id
                        << ",\"instruction\":" << search_json_string(format_instruction(fact->second->instruction))
                        << '}';
                }
                if (emitted == emitted_origins) break;
            }
            out << "],\"omitted_origin_rows\":" << (total_origins - emitted_origins)
                << ",\"origin_rows_complete\":" << (total_origins == emitted_origins ? "true" : "false")
                << "}\n";
            return complete ? 0 : 3;
        }
        out << "Function at " << location(entry) << ":\n";
        if (typed_output) out << pseudocode_text;
        else {
            out << "Typed formatting unavailable: " << escape(typed_error)
                << "; using structured fallback.\n";
            out << pseudocode_text;
        }
        out << "Analysis: " << (complete ? "complete" : "partial") << '\n';
        return complete ? 0 : 3;
    }
    if (args.action == L"marshaling") {
        if (!snapshot.loaded)
            throw Failure{{ErrorCode::unsupported, "Managed marshal query requires a loaded PE image"}};
        const auto descriptors = take(inspect_managed_marshal_descriptors(*snapshot.loaded));
        const auto limit = std::min<std::size_t>(descriptors.size(), 256);
        for (std::size_t i = 0; i < limit; ++i) {
            const auto &descriptor = descriptors[i];
            const auto parent_kind = (descriptor.parent_token >> 24) == 4 ? "field" : "param";
            out << "Marshal: token=0x" << std::hex << descriptor.token << " parent-token=0x"
                << descriptor.parent_token << std::dec << " parent-kind=" << parent_kind
                << " metadata-offset=0x" << std::hex << descriptor.metadata_offset
                << " blob-index=0x" << descriptor.blob_index << " blob-data-offset=0x"
                << descriptor.blob_data_offset << std::dec << " decode=";
            switch (descriptor.decode_status) {
            case ManagedMarshalDescriptorStatus::decoded_scalar: out << "scalar"; break;
            case ManagedMarshalDescriptorStatus::decoded_array: out << "array"; break;
            case ManagedMarshalDescriptorStatus::decoded_custom_marshaler: out << "custom-marshaler"; break;
            case ManagedMarshalDescriptorStatus::opaque_unknown: out << "opaque-unknown"; break;
            }
            if (!descriptor.native_type_name.empty()) out << " type=" << descriptor.native_type_name;
            if (descriptor.array_element_type) out << " element-type=0x" << std::hex << unsigned(*descriptor.array_element_type) << std::dec;
            if (descriptor.array_parameter_index) out << " param-index=" << *descriptor.array_parameter_index;
            if (descriptor.array_element_count) out << " element-count=" << *descriptor.array_element_count;
            out << " native-type=";
            const auto byte_limit = std::min<std::size_t>(descriptor.native_type.size(), 128);
            for (std::size_t n = 0; n < byte_limit; ++n)
                out << std::hex << std::setw(2) << std::setfill('0')
                    << std::to_integer<unsigned>(descriptor.native_type[n]);
            out << std::dec << std::setfill(' ') << " bytes=" << descriptor.native_type.size();
            if (byte_limit < descriptor.native_type.size()) out << " bytes-omitted=" << descriptor.native_type.size() - byte_limit;
            for (std::size_t field = 0; field < descriptor.custom_marshaler_strings.size(); ++field) {
                const auto &value = descriptor.custom_marshaler_strings[field];
                if (!value) {
                    out << " custom-string" << field << "=null";
                    continue;
                }
                out << " custom-string" << field << "-hex=";
                const auto text_limit = std::min<std::size_t>(value->size(), 64);
                for (std::size_t n = 0; n < text_limit; ++n)
                    out << std::hex << std::setw(2) << std::setfill('0')
                        << static_cast<unsigned>(static_cast<unsigned char>((*value)[n]));
                out << std::dec << std::setfill(' ');
                if (text_limit < value->size()) out << " custom-string" << field << "-bytes-omitted=" << value->size() - text_limit;
            }
            out << '\n';
        }
        if (descriptors.size() > limit) out << "Marshal descriptors omitted: " << descriptors.size() - limit << '\n';
        out << "Marshal descriptors: " << descriptors.size() << "\nAnalysis: complete\n";
        return 0;
    }
    if (args.action == L"user-strings") {
        if (!snapshot.loaded)
            throw Failure{{ErrorCode::unsupported, "Managed user-string query requires a loaded PE image"}};
        const auto strings = take(inspect_managed_user_strings(*snapshot.loaded));
        for (const auto &[token, text] : strings) {
            out << "UserString: token=0x" << std::hex << token << std::dec << " utf16=";
            for (std::size_t i = 0; i < text.size(); ++i) {
                if (i) out << ',';
                out << "0x" << std::hex << std::setw(4) << std::setfill('0')
                    << static_cast<std::uint16_t>(text[i]) << std::dec << std::setfill(' ');
            }
            out << '\n';
        }
        out << "User strings: " << strings.size() << "\nAnalysis: complete\n";
        return 0;
    }
    if (args.action == L"fields") {
        if (!snapshot.loaded)
            throw Failure{{ErrorCode::unsupported, "Managed field query requires a loaded PE image"}};
        const auto fields = take(inspect_managed_fields(*snapshot.loaded));
        bool complete = true;
        for (const auto &field : fields) {
            out << "Field: token=0x" << std::hex << field.token << " signature-index=0x" << field.signature_index << std::dec
                << " owner=" << escape(field.declaring_type) << " name=" << escape(field.name)
                << " flags=0x" << std::hex << field.flags << std::dec;
            if (field.rva)
                out << " rva=0x" << std::hex << *field.rva << std::dec;
            if (field.rva_metadata_offset)
                out << " rva-metadata-offset=0x" << std::hex << *field.rva_metadata_offset << std::dec;
            if (field.explicit_layout_offset)
                out << " explicit-layout-offset=0x" << std::hex << *field.explicit_layout_offset
                    << " layout-metadata-offset=0x" << field.layout_metadata_offset.value_or(0) << std::dec;
            out << " type=";
            if (field.type_signature) out << escape(managed_type_text(*field.type_signature));
            else {
                out << "unsupported";
                if (!field.signature_diagnostic.empty()) out << " detail=" << escape(field.signature_diagnostic);
                complete = false;
            }
            if (field.marshal_descriptor) managed_marshal_owner_summary(out, *field.marshal_descriptor);
            out << '\n';
        }
        out << "Fields: " << fields.size() << "\nAnalysis: " << (complete ? "complete" : "partial") << '\n';
        return complete ? 0 : 3;
    }
    if (args.action == L"properties") {
        if (!snapshot.loaded)
            throw Failure{{ErrorCode::unsupported, "Managed property query requires a loaded PE image"}};
        const auto properties = take(inspect_managed_properties(*snapshot.loaded));
        constexpr std::size_t limit = 128;
        bool complete = true;
        for (std::size_t index = 0; index < properties.size(); ++index) {
            const auto &property = properties[index];
            if (!property.signature) complete = false;
            for (const auto &accessor : property.accessors)
                if ((accessor.semantics == 1 || accessor.semantics == 2) &&
                    accessor.validation != ManagedPropertyAccessorValidation::valid)
                    complete = false;
            if (index >= limit) continue;
            out << "Property: token=0x" << std::hex << property.token << " owner-token=0x" << property.declaring_type_token
                << " flags=0x" << property.flags << " signature-index=0x" << property.signature_index
                << " metadata-offset=0x" << property.metadata_offset << std::dec << " row-bytes=" << property.row_size
                << " owner=" << escape(property.declaring_type) << " name=" << escape(property.name);
            if (property.signature) {
                const auto &signature = *property.signature;
                out << " has-this=" << signature.has_this << " type=" << escape(managed_type_text(signature.property_type))
                    << " index-parameters=" << signature.index_parameter_types.size();
                for (std::size_t n = 0; n < std::min<std::size_t>(signature.index_parameter_types.size(), 16); ++n)
                    out << " index-type[" << n << "]=" << escape(managed_type_text(signature.index_parameter_types[n]));
                if (signature.index_parameter_types.size() > 16) out << " index-types-omitted=" << signature.index_parameter_types.size() - 16;
            } else out << " type=unsupported detail=" << escape(property.signature_diagnostic);
            out << " signature-metadata-offset=0x" << std::hex << property.signature_metadata_offset
                << std::dec << " signature-bytes=" << property.signature_size << '\n';
            for (std::size_t n = 0; n < std::min<std::size_t>(property.accessors.size(), 16); ++n) {
                const auto &accessor = property.accessors[n];
                const char *validation = "not-applicable";
                switch (accessor.validation) {
                case ManagedPropertyAccessorValidation::not_applicable: validation = "not-applicable"; break;
                case ManagedPropertyAccessorValidation::valid: validation = "valid"; break;
                case ManagedPropertyAccessorValidation::invalid: validation = "invalid"; break;
                case ManagedPropertyAccessorValidation::unsupported: validation = "unsupported"; break;
                }
                out << "  Accessor: role=" << (accessor.semantics == 1 ? "setter" : accessor.semantics == 2 ? "getter" : "other")
                    << " method-token=0x" << std::hex << accessor.method_token << " semantics-token=0x" << accessor.semantics_token
                    << " metadata-offset=0x" << accessor.metadata_offset << " signature-index=0x" << accessor.signature_index
                    << " signature-metadata-offset=0x" << accessor.signature_metadata_offset << std::dec
                    << " signature-bytes=" << accessor.signature_size << " validation=" << validation;
                if (!accessor.validation_diagnostic.empty())
                    out << " validation-detail=" << escape(accessor.validation_diagnostic);
                out << '\n';
            }
            if (property.accessors.size() > 16) out << "  Accessors omitted: " << property.accessors.size() - 16 << '\n';
            if (property.default_value) {
                const auto &value = *property.default_value;
                out << "  Default: token=0x" << std::hex << value.token << " element-type=0x" << unsigned(value.element_type);
                if (value.element_type == 0x0e) {
                    out << " utf16=";
                    for (std::size_t n = 0; n < std::min<std::size_t>(value.string_value.size(), 64); ++n) {
                        if (n) out << ',';
                        out << "0x" << static_cast<std::uint16_t>(value.string_value[n]);
                    }
                    if (value.string_value.size() > 64) out << " omitted-units=" << std::dec << value.string_value.size() - 64;
                } else out << " scalar-bits=0x" << value.scalar_bits;
                out << std::dec << '\n';
            }
        }
        if (properties.size() > limit) out << "Properties omitted: " << properties.size() - limit << '\n';
        out << "Properties: " << properties.size() << "\nSignature decoding: " << (complete ? "complete" : "partial") << '\n';
        return complete ? 0 : 3;
    }
    if (args.action == L"events") {
        if (!snapshot.loaded)
            throw Failure{{ErrorCode::unsupported, "Managed event query requires a loaded PE image"}};
        const auto events = take(inspect_managed_events(*snapshot.loaded));
        constexpr std::size_t limit = 128;
        for (std::size_t index = 0; index < events.size(); ++index) {
            const auto &event = events[index];
            if (index >= limit) continue;
            out << "Event: token=0x" << std::hex << event.token << " owner-token=0x" << event.declaring_type_token
                << " flags=0x" << event.flags << " type-token=0x" << event.event_type_token
                << " type-coded-index=0x" << event.event_type_coded_index << " metadata-offset=0x"
                << event.metadata_offset << std::dec << " row-bytes=" << event.row_size
                << " owner=" << escape(event.declaring_type) << " name=" << escape(event.name) << '\n';
            for (std::size_t n = 0; n < std::min<std::size_t>(event.accessors.size(), 16); ++n) {
                const auto &accessor = event.accessors[n];
                const char *role = accessor.semantics == 8 ? "add" : accessor.semantics == 16 ? "remove" :
                                   accessor.semantics == 32 ? "fire" : "other";
                out << "  Accessor: role=" << role << " method-token=0x" << std::hex << accessor.method_token
                    << " semantics-token=0x" << accessor.semantics_token << " metadata-offset=0x"
                    << accessor.metadata_offset << std::dec << '\n';
            }
            if (event.accessors.size() > 16) out << "  Accessors omitted: " << event.accessors.size() - 16 << '\n';
        }
        if (events.size() > limit) out << "Events omitted: " << events.size() - limit << '\n';
        out << "Events: " << events.size() << "\nAnalysis: complete\n";
        return 0;
    }
    if (args.action == L"managed-types") {
        if (!snapshot.loaded)
            throw Failure{{ErrorCode::unsupported, "Managed type query requires a loaded PE image"}};
        const auto types = take(inspect_managed_types(*snapshot.loaded));
        for (const auto &type : types) {
            out << "Type: token=0x" << std::hex << type.token << std::dec
                << " name=" << escape(type.full_name)
                << " generic-arity=" << type.generic_parameters.size() << '\n';
            if (type.layout_metadata_offset.has_value())
                out << "  ClassLayout: packing=" << type.packing_size.value_or(0)
                    << " declared-size=" << type.declared_class_size.value_or(0)
                    << " metadata-offset=0x" << std::hex << type.layout_metadata_offset.value_or(0) << std::dec << '\n';
            for (const auto &parameter : type.generic_parameters)
                print_generic_parameter(out, parameter);
        }
        out << "Types: " << types.size() << "\nAnalysis: complete\n";
        return 0;
    }
    if (args.action == L"managed-resources") {
        if (!snapshot.loaded)
            throw Failure{{ErrorCode::unsupported, "Managed resource query requires a loaded PE image"}};
        std::vector<std::filesystem::path> input_paths;
        if (!args.managed_resource_inputs_list.empty()) {
            std::error_code error;
            const auto size=std::filesystem::file_size(args.managed_resource_inputs_list,error);
            if(error||size>1024u*1024u)throw Failure{{ErrorCode::invalid_argument,"Cannot read CLR resource input list or list exceeds 1 MiB"}};
            std::ifstream list(args.managed_resource_inputs_list,std::ios::binary);
            if(!list)throw Failure{{ErrorCode::io,"Cannot open CLR resource input list"}};
            std::string contents(static_cast<std::size_t>(size),'\0');
            if(size&&!list.read(contents.data(),static_cast<std::streamsize>(size)))throw Failure{{ErrorCode::io,"Cannot read CLR resource input list"}};
            if(contents.starts_with("\xef\xbb\xbf"))contents.erase(0,3);
            std::istringstream lines(contents);std::string line;
            while(std::getline(lines,line)){
                const auto first=line.find_first_not_of(" \t\r");if(first==std::string::npos||line[first]=='#')continue;
                const auto last=line.find_last_not_of(" \t\r");const auto value=line.substr(first,last-first+1);
                if(value.size()>4096)throw Failure{{ErrorCode::resource_limit,"CLR resource input path exceeds 4096 bytes"}};
                auto path=path_from_wide(utf8_to_wide(value));
                if(path.is_relative())path=args.managed_resource_inputs_list.parent_path()/path;
                input_paths.push_back(std::move(path));
                if(input_paths.size()>256)throw Failure{{ErrorCode::resource_limit,"CLR resource input list exceeds 256 files"}};
            }
        }
        std::vector<std::shared_ptr<const FileStorage>> input_storage;input_storage.reserve(input_paths.size());
        std::vector<std::optional<LoadedImage>> input_images;input_images.reserve(input_paths.size());
        std::uint64_t total_input_bytes=0;
        for(const auto& path:input_paths){
            auto storage=take(FileStorage::open(path));
            if(storage->size()>512u*1024u*1024u-total_input_bytes)
                throw Failure{{ErrorCode::resource_limit,"CLR resource inputs exceed 512 MiB cumulative size"}};
            total_input_bytes+=storage->size();
            auto loaded=load_pe(storage,{});
            input_storage.push_back(std::move(storage));
            if(loaded)input_images.emplace_back(std::move(loaded.value()));else input_images.emplace_back(std::nullopt);
        }
        std::vector<ManagedResourceInput> supplied;supplied.reserve(input_paths.size());
        for(std::size_t i=0;i<input_paths.size();++i){
            ManagedResourceInput input;
            input.file_name=utf8(input_paths[i].filename().wstring());
            input.storage=input_storage[i];
            input.loaded_image=input_images[i]?&*input_images[i]:nullptr;
            supplied.push_back(std::move(input));
        }
        auto resources_result=supplied.empty()?inspect_managed_resources(*snapshot.loaded):
            inspect_managed_resources(*snapshot.loaded,supplied);
        const auto resources=take(std::move(resources_result));
        const auto limit = std::min<std::size_t>(resources.size(), 256);
        const auto resolution_name=[](ManagedResourceResolutionState state){
            switch(state){
            case ManagedResourceResolutionState::embedded:return "embedded";
            case ManagedResourceResolutionState::unresolved:return "unresolved";
            case ManagedResourceResolutionState::resolved_file:return "resolved-file";
            case ManagedResourceResolutionState::resolved_assembly:return "resolved-assembly";
            case ManagedResourceResolutionState::ambiguous:return "ambiguous";
            case ManagedResourceResolutionState::hash_mismatch:return "hash-mismatch";
            case ManagedResourceResolutionState::unsupported_hash:return "unsupported-hash";
            }
            return "unknown";
        };
        const auto value_kind_name=[](ManagedResourceValueKind kind){
            switch(kind){
            case ManagedResourceValueKind::null_value:return "null";
            case ManagedResourceValueKind::string_value:return "string";
            case ManagedResourceValueKind::boolean:return "boolean";
            case ManagedResourceValueKind::character:return "character";
            case ManagedResourceValueKind::signed_integer:return "signed-integer";
            case ManagedResourceValueKind::unsigned_integer:return "unsigned-integer";
            case ManagedResourceValueKind::single:return "single";
            case ManagedResourceValueKind::double_value:return "double";
            case ManagedResourceValueKind::decimal:return "decimal";
            case ManagedResourceValueKind::date_time:return "date-time";
            case ManagedResourceValueKind::time_span:return "time-span";
            case ManagedResourceValueKind::byte_array:return "byte-array";
            case ManagedResourceValueKind::stream:return "stream";
            case ManagedResourceValueKind::user_type:return "user-type";
            case ManagedResourceValueKind::unsupported:return "unsupported";
            }
            return "unknown";
        };
        bool complete=true;
        std::size_t remaining_record_details=4096;
        if(args.managed_resources_json)out<<"{\"resources\":[";
        for (std::size_t i = 0; i < limit; ++i) {
            const auto &resource = resources[i];
            const char *kind = resource.implementation == ManagedResourceImplementationKind::embedded ? "embedded"
                             : resource.implementation == ManagedResourceImplementationKind::file ? "file"
                             : resource.implementation == ManagedResourceImplementationKind::assembly_ref ? "assembly-ref"
                             : "exported-type";
            if(resource.resolution!=ManagedResourceResolutionState::embedded&&
               resource.resolution!=ManagedResourceResolutionState::resolved_file&&
               resource.resolution!=ManagedResourceResolutionState::resolved_assembly)complete=false;
            const auto record_detail_count=std::min(resource.records.size(),remaining_record_details);
            const auto record_details_omitted=resource.records.size()-record_detail_count;
            remaining_record_details-=record_detail_count;
            if(record_details_omitted)complete=false;
            if(args.managed_resources_json){
                if(i)out<<',';
                std::ostringstream token;token<<"0x"<<std::hex<<resource.token;
                const auto& detail=resource.resolution_diagnostic.empty()?resource.payload_diagnostic:resource.resolution_diagnostic;
                out<<"{\"token\":"<<search_json_string(token.str())
                   <<",\"name\":"<<search_json_string(resource.name)
                   <<",\"implementation\":"<<search_json_string(kind)
                   <<",\"identity\":"<<search_json_string(resource.implementation_name)
                   <<",\"resolution\":"<<search_json_string(resolution_name(resource.resolution))
                   <<",\"payload_bytes\":"<<resource.payload.size()
                   <<",\"records\":"<<resource.records.size();
                if(resource.resolution_input_index)out<<",\"resolved_input_index\":"<<*resource.resolution_input_index;
                if(!resource.implementation_hash.empty()){
                    constexpr std::size_t hash_prefix_bytes=32;
                    const auto hash_prefix=std::min(resource.implementation_hash.size(),hash_prefix_bytes);
                    std::ostringstream hash_hex;hash_hex<<std::hex<<std::setfill('0');
                    for(std::size_t hash_index=0;hash_index<hash_prefix;++hash_index)
                        hash_hex<<std::setw(2)<<std::to_integer<unsigned>(resource.implementation_hash[hash_index]);
                    out<<",\"implementation_hash_algorithm\":"<<resource.implementation_hash_algorithm
                       <<",\"implementation_hash_bytes\":"<<resource.implementation_hash.size()
                       <<",\"implementation_hash_prefix_hex\":"<<search_json_string(hash_hex.str())
                       <<",\"implementation_hash_truncated\":"<<(hash_prefix<resource.implementation_hash.size()?"true":"false");
                }
                out<<",\"record_details\":[";
                for(std::size_t record_index=0;record_index<record_detail_count;++record_index){
                    if(record_index)out<<',';
                    const auto& record=resource.records[record_index];
                    out<<"{\"name\":"<<search_json_string(record.name)
                       <<",\"type_code\":"<<record.type_code
                       <<",\"kind\":"<<search_json_string(value_kind_name(record.kind))
                       <<",\"type_name\":"<<search_json_string(record.type_name)
                       <<",\"supported\":"<<(record.supported?"true":"false")
                       <<",\"data_offset\":"<<record.data_offset
                       <<",\"data_size\":"<<record.data_size;
                    if(record.kind==ManagedResourceValueKind::string_value)
                        out<<",\"string_value\":"<<search_json_string(record.string_value);
                    if(record.supported&&record.kind!=ManagedResourceValueKind::null_value&&
                       record.kind!=ManagedResourceValueKind::string_value&&
                       record.kind!=ManagedResourceValueKind::byte_array&&
                       record.kind!=ManagedResourceValueKind::stream){
                        std::ostringstream bits;bits<<"0x"<<std::hex<<std::uppercase<<record.scalar_bits;
                        out<<",\"scalar_bits\":"<<search_json_string(bits.str());
                    }
                    out<<'}';
                }
                out<<"],\"records_omitted\":"<<record_details_omitted
                   <<",\"detail\":"<<search_json_string(detail)<<'}';
                continue;
            }
            out << "Resource: token=0x" << std::hex << resource.token << std::dec
                << " name=" << escape(resource.name) << " implementation=" << kind
                << " implementation-token=0x" << std::hex << resource.implementation_token << std::dec;
            if (!resource.implementation_name.empty()) {
                out << " identity=" << escape(resource.implementation_name);
                if (resource.implementation == ManagedResourceImplementationKind::assembly_ref) {
                    out << " version=" << resource.implementation_major << '.' << resource.implementation_minor
                        << '.' << resource.implementation_build << '.' << resource.implementation_revision
                        << " culture=" << (resource.implementation_culture.empty() ? "neutral"
                            : escape(resource.implementation_culture));
                } else {
                    out << " contains-metadata=" << (resource.implementation_file_contains_metadata ? "yes" : "no");
                }
            }
            if(!resource.implementation_hash.empty()){
                constexpr std::size_t hash_prefix_bytes=32;
                const auto hash_prefix=std::min(resource.implementation_hash.size(),hash_prefix_bytes);
                out<<" implementation-hash-algorithm=0x"<<std::hex<<resource.implementation_hash_algorithm<<std::dec
                   <<" implementation-hash-bytes="<<resource.implementation_hash.size()<<" implementation-hash-prefix=";
                for(std::size_t hash_index=0;hash_index<hash_prefix;++hash_index)
                    out<<std::hex<<std::setw(2)<<std::setfill('0')<<std::to_integer<unsigned>(resource.implementation_hash[hash_index]);
                out<<std::dec<<std::setfill(' ');
                if(hash_prefix<resource.implementation_hash.size())out<<"...";
            }
            out << " resolution=" << resolution_name(resource.resolution);
            if(resource.resolution_input_index)out<<" resolved-input-index="<<*resource.resolution_input_index;
            if (resource.payload.size()||resource.data_size)
                out << " payload-bytes=" << resource.payload.size() << " records=" << resource.records.size();
            out << '\n';
            const auto& detail=resource.resolution_diagnostic.empty()?resource.payload_diagnostic:resource.resolution_diagnostic;
            if (!detail.empty()) out << "  Detail: " << escape(detail) << '\n';
            for(std::size_t record_index=0;record_index<record_detail_count;++record_index){
                const auto& record=resource.records[record_index];
                out<<"  Record: name="<<escape(record.name)<<" kind="<<value_kind_name(record.kind)
                   <<" type-code="<<record.type_code;
                if(!record.type_name.empty())out<<" type-name="<<escape(record.type_name);
                out<<" supported="<<(record.supported?"yes":"no")<<" data-offset=0x"
                   <<std::hex<<record.data_offset<<" data-size=0x"<<record.data_size<<std::dec;
                if(record.kind==ManagedResourceValueKind::string_value)
                    out<<" string="<<escape(record.string_value);
                else if(record.supported&&record.kind!=ManagedResourceValueKind::null_value&&
                        record.kind!=ManagedResourceValueKind::byte_array&&
                        record.kind!=ManagedResourceValueKind::stream)
                    out<<" scalar-bits=0x"<<std::hex<<record.scalar_bits<<std::dec;
                out<<'\n';
            }
            if(record_details_omitted)
                out<<"  Resource records omitted: "<<record_details_omitted<<" (CLI detail limit 4096)\n";
        }
        if(args.managed_resources_json){
            out<<"],\"total\":"<<resources.size()<<",\"complete\":"<<((complete&&resources.size()<=limit)?"true":"false")<<"}\n";
            return 0;
        }
        if (resources.size() > limit) out << "Resources omitted: " << resources.size() - limit << '\n';
        out << "Resources: " << resources.size() << "\nAnalysis: "<<(complete&&resources.size()<=limit?"complete":"partial")<<'\n';
        return 0;
    }
    if (args.action == L"methods") {
        if (!snapshot.loaded)
            throw Failure{{ErrorCode::unsupported, "Managed method query requires a loaded PE image"}};
        auto methods = take(inspect_managed_methods(*snapshot.loaded, {}));
        bool complete = true;
        for (const auto &method : methods) {
            const char *state = method.status == ManagedMethodStatus::decoded ? "decoded"
                              : method.status == ManagedMethodStatus::no_body ? "no-body"
                              : method.status == ManagedMethodStatus::unsupported ? "unsupported" : "malformed";
            out << "Method: token=0x" << std::hex << method.method.token << " rva=0x" << method.method.rva << std::dec
                << " name=" << escape(method.method.name) << " status=" << state << " instructions="
                << method.instructions.size() << " type-generic-arity=" << method.method.declaring_type_generic_parameters.size()
                << " method-generic-arity=" << method.method.generic_parameters.size() << '\n';
            if (method.method.import_map) {
                out << "  Native import: module=" << escape(method.method.import_map->module_name)
                    << " entry=" << escape(method.method.import_map->import_name) << " flags=0x"
                    << std::hex << method.method.import_map->flags << std::dec
                    << " module-token=0x" << std::hex << method.method.import_map->module_token << std::dec << '\n';
            }
            for (const auto &parameter : method.method.parameters) {
                if (!parameter.marshal_descriptor) continue;
                out << "  Parameter marshal: sequence=" << parameter.sequence
                    << " token=0x" << std::hex << parameter.token << std::dec;
                if (!parameter.name.empty()) out << " name=" << escape(parameter.name);
                managed_marshal_owner_summary(out, *parameter.marshal_descriptor);
                out << '\n';
            }
            for (const auto &parameter : method.method.declaring_type_generic_parameters)
                print_generic_parameter(out, parameter);
            for (const auto &parameter : method.method.generic_parameters)
                print_generic_parameter(out, parameter);
            if (!method.diagnostic.empty())
                out << "  Detail: " << escape(method.diagnostic) << '\n';
            for (const auto &instruction : method.instructions) {
                out << "  IL+0x" << std::hex << instruction.offset << std::dec << " " << instruction.mnemonic;
                if (instruction.opcode == 0x29) {
                    if (const auto *operand = std::get_if<CilTokenOperand>(&instruction.operand)) {
                        out << " signature=0x" << std::hex << operand->token << std::dec;
                        if (const auto signature = method.resolved_call_signatures.find(operand->token);
                            signature != method.resolved_call_signatures.end())
                            out << " parameters=" << signature->second.parameter_count
                                << " has-this=" << (signature->second.has_this ? "yes" : "no")
                                << " returns=" << (signature->second.returns_value ? "value" : "void");
                        else
                            out << " signature=unresolved";
                    }
                } else if (instruction.opcode == 0xa3 || instruction.opcode == 0xa4) {
                    if (const auto *operand = std::get_if<CilTokenOperand>(&instruction.operand))
                        out << " type-token=0x" << std::hex << operand->token << std::dec;
                }
                out << '\n';
            }
            if (method.status == ManagedMethodStatus::unsupported || method.status == ManagedMethodStatus::malformed)
                complete = false;
        }
        out << "Methods: " << methods.size() << "\nAnalysis: " << (complete ? "complete" : "partial") << '\n';
        return complete ? 0 : 3;
    }
    if (args.action == L"search") {
        auto limits = args.search_limits;
        if (args.search_start && !args.cursor) {
            const auto start = take(resolve_location(snapshot, *args.search_start));
            if (const auto *file = std::get_if<FileOffset>(&start)) {
                limits.start_offset = file->value;
            } else {
                const auto address = std::get<Address>(start);
                require(snapshot.loaded && snapshot.loaded->image,
                        "Address-based search start requires a mapped project image");
                auto mapped_file = snapshot.loaded->image->to_file_offset(address);
                require(bool(mapped_file), "Search start address is not backed by a unique file offset");
                limits.start_offset = mapped_file.value().value;
                limits.start_address = address;
            }
        }
        auto result = search(snapshot, *args.query, args.cursor, limits, {});
        if (!result && result.error().code == ErrorCode::conflict)
            throw Failure{{ErrorCode::invalid_argument,
                           "Continuation or immediate facts do not match current project: " + result.error().message}};
        auto page = take(std::move(result));
        if (args.search_json) {
            out << "{\"schema\":\"hexlab.project-search.v1\",\"complete\":"
                << (page.complete ? "true" : "false") << ",\"source_complete\":"
                << (page.source_complete ? "true" : "false") << ",\"examined_candidates\":"
                << page.examined_candidates << ",\"comparisons\":" << page.comparisons << ",\"matches\":[";
            for (std::size_t i = 0; i < page.matches.size(); ++i) {
                if (i) out << ',';
                const auto &match = page.matches[i];
                out << "{\"file_offset\":" << search_json_string(hex(match.offset.value))
                    << ",\"size\":" << match.size << ",\"address\":";
                if (match.address) out << search_json_string(location(*match.address));
                else out << "null";
                out << ",\"instruction_address\":";
                if (match.instruction_address) out << search_json_string(location(*match.instruction_address));
                else out << "null";
                out << ",\"operand_index\":";
                if (match.operand_index) out << *match.operand_index;
                else out << "null";
                out << ",\"file_ranges\":[";
                for (std::size_t j = 0; j < match.file_ranges.size(); ++j) {
                    if (j) out << ',';
                    out << "{\"file_offset\":" << search_json_string(hex(match.file_ranges[j].begin.value))
                        << ",\"size\":" << match.file_ranges[j].size << '}';
                }
                out << "]}";
            }
            out << "],\"next\":";
            if (page.next) out << search_json_string(cursor_text(*page.next));
            else out << "null";
            out << ",\"reason\":";
            if (!page.reason.empty()) out << search_json_string(page.reason);
            else out << "null";
            out << "}\n";
            return page.complete && page.source_complete ? 0 : 3;
        }
        for (auto &match : page.matches) {
            out << "Match: " << location(match.offset) << " size=" << match.size;
            const auto selected = search_match_location(match);
            if (const auto *address = std::get_if<Address>(&selected))
                out << " " << location(*address);
            if (snapshot.loaded)
                profile_coordinate(out, *snapshot.loaded->image, selected);
            if (match.operand_index)
                out << " operand=" << *match.operand_index;
            if (match.file_ranges.size() > 1) {
                out << " file-ranges=";
                for (auto &range : match.file_ranges)
                    out << location(range.begin) << "+" << range.size << ' ';
            }
            out << '\n';
        }
        out << "Matches: " << page.matches.size() << "\nSearch: " << (page.complete ? "complete" : "incomplete")
            << "\nSource: " << (page.source_complete ? "complete" : "partial") << '\n';
        if (page.next)
            out << "Continuation: " << cursor_text(*page.next) << '\n';
        if (!page.reason.empty())
            out << "Reason: " << escape(page.reason) << '\n';
        return page.complete && page.source_complete ? 0 : 3;
    }
    if (args.action == L"fingerprint-create") {
        require(snapshot.loaded && snapshot.functions,
                "Function fingerprint extraction requires a loaded image and recovered function facts");
        if (args.fingerprint_all_functions) {
            if (snapshot.functions->functions.size() > 4096)
                throw Failure{{ErrorCode::resource_limit,
                    "Fingerprint catalog extraction exceeds the 4096-function selection limit"}};
            std::vector<FunctionId> selected;
            selected.reserve(snapshot.functions->functions.size());
            for (const auto &function : snapshot.functions->functions) {
                if (!function) throw Failure{{ErrorCode::conflict, "Recovered function snapshot contains an empty record"}};
                selected.push_back(function->id);
            }
            const auto catalog = take(create_function_fingerprint_catalog(*snapshot.loaded->image,
                *snapshot.effective, *snapshot.functions, selected, args.signature_provenance,
                args.fingerprint_options));
            out << take(serialize_function_fingerprint_catalog(catalog));
            return 0;
        }
        require(args.at && std::holds_alternative<Address>(*args.at),
                "Single-function fingerprint extraction requires a virtual entry address");
        const auto entry = std::get<Address>(*args.at);
        const auto found = std::find_if(snapshot.functions->functions.begin(), snapshot.functions->functions.end(),
                                        [&](const auto &function) { return function->entry == entry; });
        require(found != snapshot.functions->functions.end(), "No recovered function begins at the requested address");
        const auto definition = take(create_function_fingerprint(*snapshot.loaded->image, *snapshot.effective, **found,
            *snapshot.functions, args.signature_name, args.signature_provenance, args.fingerprint_options));
        out << take(serialize_function_fingerprint_catalog(FunctionFingerprintCatalog{1,
            snapshot.loaded->image->layout().architecture, snapshot.loaded->image->layout().mode, {definition}}));
        return 0;
    }
    if (args.action == L"fingerprints") {
        require(snapshot.loaded && snapshot.functions,
                "Function fingerprint recognition requires a loaded image and recovered function facts");
        std::vector<std::filesystem::path> paths;
        if (args.fingerprint_definitions_list.empty()) paths.push_back(args.fingerprint_definitions);
        else {
            std::error_code ec;
            const auto list_size = std::filesystem::file_size(args.fingerprint_definitions_list, ec);
            if (ec || list_size > 1024 * 1024)
                throw Failure{{ErrorCode::invalid_argument, "Cannot read fingerprint catalog list or list exceeds 1 MiB"}};
            std::ifstream list(args.fingerprint_definitions_list, std::ios::binary);
            if (!list) throw Failure{{ErrorCode::io, "Cannot open fingerprint catalog list"}};
            std::string contents(static_cast<std::size_t>(list_size), '\0');
            if (list_size && !list.read(contents.data(), static_cast<std::streamsize>(list_size)))
                throw Failure{{ErrorCode::io, "Cannot read fingerprint catalog list"}};
            if (contents.starts_with("\xef\xbb\xbf")) contents.erase(0, 3);
            std::istringstream lines(contents);
            std::string line;
            while (std::getline(lines, line)) {
                const auto first = line.find_first_not_of(" \t\r");
                if (first == std::string::npos || line[first] == '#') continue;
                const auto last = line.find_last_not_of(" \t\r");
                const auto item = line.substr(first, last - first + 1);
                auto path = path_from_wide(utf8_to_wide(item));
                if (path.is_relative()) path = args.fingerprint_definitions_list.parent_path() / path;
                paths.push_back(std::move(path));
                if (paths.size() > 256)
                    throw Failure{{ErrorCode::resource_limit, "Fingerprint catalog list exceeds 256 catalogs"}};
            }
            if (paths.empty()) throw Failure{{ErrorCode::invalid_argument, "Fingerprint catalog list contains no paths"}};
        }
        FunctionFingerprintCatalogSet catalog_set;
        catalog_set.catalogs.reserve(paths.size());
        std::string canonical_set = "HexLab ordered fingerprint catalog set v1\n";
        std::uint64_t total_bytes = 0;
        for (const auto &path : paths) {
            std::error_code ec;
            const auto size = std::filesystem::file_size(path, ec);
            if (ec || size > 1024 * 1024 || size > 64ull * 1024 * 1024 - total_bytes)
                throw Failure{{ErrorCode::invalid_argument, "Cannot read fingerprint catalog set or aggregate input exceeds its byte budget"}};
            std::ifstream input(path, std::ios::binary);
            if (!input) throw Failure{{ErrorCode::io, "Cannot open fingerprint catalog"}};
            std::string text(static_cast<std::size_t>(size), '\0');
            if (size && !input.read(text.data(), static_cast<std::streamsize>(size)))
                throw Failure{{ErrorCode::io, "Cannot read fingerprint catalog"}};
            total_bytes += size;
            auto catalog = take(parse_function_fingerprint_catalog(text));
            auto canonical = take(serialize_function_fingerprint_catalog(catalog));
            if (canonical.size() > 64ull * 1024 * 1024 - canonical_set.size())
                throw Failure{{ErrorCode::resource_limit, "Canonical fingerprint catalog set exceeds 64 MiB"}};
            canonical_set += std::to_string(canonical.size()) + ":" + canonical;
            catalog_set.catalogs.push_back(std::move(catalog));
        }
        const auto recognized = take(recognize_function_fingerprints(*snapshot.loaded->image, *snapshot.effective,
            *snapshot.functions, catalog_set, args.fingerprint_limits));
        auto evidence=take(make_function_recognition_evidence(*snapshot.functions,catalog_digest(canonical_set),recognized));
        auto stored=take(actor.persist_function_recognition(std::move(evidence)));take(stored.result.get());
        for (const auto &function : recognized.functions) {
            out << "Function fingerprint: " << location(function.entry)
                << " ambiguous=" << (function.ambiguous ? "true" : "false")
                << " candidates=" << function.candidates.size() << '\n';
            for (const auto &candidate : function.candidates)
                out << "  Candidate: " << escape(candidate.name) << " provenance=" << escape(candidate.provenance)
                    << " instructions=" << candidate.instruction_count << " sha256=" << digest_hex(candidate.digest)
                    << (catalog_set.catalogs.size() > 1 ? " catalog-index=" + std::to_string(candidate.catalog_index) : "") << '\n';
        }
        out << "Fingerprint matches: " << recognized.functions.size()
            << " functions-scanned=" << recognized.functions_scanned
            << " instructions-scanned=" << recognized.instructions_scanned
            << " token-bytes=" << recognized.token_bytes
            << " definition-checks=" << recognized.definition_checks
            << "\nRecognition: " << (recognized.complete ? "complete" : "incomplete")
            << "\nEvidence: persisted for current source\n";
        return recognized.complete ? 0 : 3;
    }
    if (args.action == L"signature-create") {
        require(snapshot.loaded && snapshot.functions && args.at && std::holds_alternative<Address>(*args.at),
                "Function signature extraction requires a loaded function and virtual entry address");
        const auto entry = std::get<Address>(*args.at);
        const auto found = std::find_if(snapshot.functions->functions.begin(), snapshot.functions->functions.end(),
                                        [&](const auto &function) { return function->entry == entry; });
        require(found != snapshot.functions->functions.end(), "No recovered function begins at the requested address");
        const auto definition = take(create_function_signature(*snapshot.loaded->image, *snapshot.effective, **found,
            *snapshot.functions, args.signature_name, args.signature_provenance, args.function_signature_options));
        out << take(serialize_signature_catalog(SignatureCatalog{2, {definition},
            snapshot.loaded->image->layout().architecture, snapshot.loaded->image->layout().mode}));
        return 0;
    }
    if (args.action == L"signatures") {
        if (!snapshot.loaded)
            throw Failure{{ErrorCode::unsupported, "Signature scanning requires a loaded mapped image"}};
        const auto loaded_catalogs = load_signature_inputs(args);
        const auto &catalogs = loaded_catalogs.catalogs;
        if (args.signature_function_entries) {
            require(bool(snapshot.functions), "Function recognition requires recovered function facts");
            const auto recognized = take(recognize_function_signatures(*snapshot.loaded->image, *snapshot.effective,
                *snapshot.functions, catalogs, args.signature_limits));
            auto evidence=take(make_function_recognition_evidence(*snapshot.functions,
                catalog_digest(loaded_catalogs.identity),recognized));
            auto stored=take(actor.persist_function_recognition(std::move(evidence)));take(stored.result.get());
            for (const auto &function : recognized.functions) {
                out << "Function signature: " << location(function.entry)
                    << " ambiguous=" << (function.ambiguous ? "true" : "false")
                    << " candidates=" << function.candidates.size() << '\n';
                for (const auto &match : function.candidates)
                    out << "  Candidate: " << escape(match.name) << " provenance=" << escape(match.provenance)
                        << (catalogs.catalogs.size() > 1 ? " catalog-index=" + std::to_string(match.catalog_index) : "")
                        << '\n';
            }
            out << "Recognized functions: " << recognized.functions.size()
                << "\nScan: " << (recognized.complete ? "complete" : "incomplete")
                << "\nEvidence: persisted for current source\n";
            return recognized.complete ? 0 : 3;
        }
        auto scan = take(scan_executable_signatures(*snapshot.loaded->image, *snapshot.effective, catalogs,
                                                    args.signature_limits, {}));
        for (const auto &match : scan.matches) {
            out << "Signature: " << escape(match.name) << " provenance=" << escape(match.provenance)
                << (catalogs.catalogs.size() > 1 ? " catalog-index=" + std::to_string(match.catalog_index) : "")
                << " " << location(match.address) << " file=" << location(match.offset) << '\n';
        }
        out << "Signatures: " << scan.matches.size() << " candidates=" << scan.candidates
            << " comparisons=" << scan.comparisons << "\nScan: " << (scan.complete ? "complete" : "incomplete") << '\n';
        if (!scan.reason.empty()) out << "Reason: " << escape(scan.reason) << '\n';
        return scan.complete ? 0 : 3;
    }
    if (args.action == L"flirt" || args.action == L"flirt-apply") {
        require(bool(snapshot.loaded) && bool(snapshot.functions),
                "FLAIR recognition requires a loaded image and recovered function facts");
        const auto &image = *snapshot.loaded->image;
        auto catalog_set = load_flirt_inputs(args, image);
        const auto recognized = take(catalog_set.catalogs.size() == 1
            ? recognize_flirt_catalog(image, *snapshot.effective, *snapshot.functions,
                                      catalog_set.catalogs.front(), args.flirt_limits)
            : recognize_flirt_catalogs(image, *snapshot.effective, *snapshot.functions,
                                       catalog_set.catalogs, args.flirt_limits));
        for (const auto &catalog : catalog_set.catalogs) {
            if (catalog.source_format_version == 0) continue;
            out << "FLAIR catalog: version=" << static_cast<unsigned>(catalog.source_format_version)
                << " library-bytes=\"" << escape(catalog.library_name_bytes) << "\""
                << " alternate-compiler-type-crc16=" << catalog.alternate_compiler_type_crc16
                << " provenance=" << escape(catalog.provenance) << '\n';
        }
        if (args.action == L"flirt-apply") {
            auto evidence = take(make_function_recognition_evidence(*snapshot.functions,
                catalog_digest(catalog_set.identity), recognized));
            auto stored = take(actor.persist_function_recognition(std::move(evidence)));
            take(stored.result.get());
        }
        std::size_t renamed = 0, name_ambiguous = 0, local_only = 0, already_named = 0, name_collisions = 0;
        if (args.flirt_rename_unique && recognized.complete) {
            std::map<std::pair<std::uint32_t, std::string>, std::size_t> name_counts;
            for (const auto &function : recognized.functions)
                if (!function.ambiguous && function.candidates.size() == 1 &&
                    function.candidates.front().kind == FlirtSymbolKind::public_name)
                    ++name_counts[{function.entry.space.value, function.candidates.front().name}];
            std::set<std::tuple<std::uint32_t, std::string, std::uint64_t>> existing_names;
            for (const auto &annotation : snapshot.state->user->annotations)
                if (const auto address = std::get_if<Address>(&annotation.location); address && !annotation.name.empty())
                    existing_names.emplace(address->space.value, annotation.name, address->offset);
            for (const auto &symbol : importable_symbols(snapshot))
                if (!symbol.name.empty())
                    existing_names.emplace(symbol.address.space.value, symbol.name, symbol.address.offset);
            std::vector<ProjectCommand> edits;
            for (const auto &function : recognized.functions) {
                if (function.ambiguous || function.candidates.size() != 1) { ++name_ambiguous; continue; }
                const auto &candidate = function.candidates.front();
                if (candidate.kind != FlirtSymbolKind::public_name) { ++local_only; continue; }
                const auto key = std::pair{function.entry.space.value, candidate.name};
                const auto annotation = std::find_if(snapshot.state->user->annotations.begin(),
                    snapshot.state->user->annotations.end(), [&](const auto &row) { return row.location == Location{function.entry}; });
                if (annotation != snapshot.state->user->annotations.end() && !annotation->name.empty()) {
                    ++already_named;
                    continue;
                }
                const bool occupied_elsewhere = std::any_of(existing_names.begin(), existing_names.end(), [&](const auto &row) {
                    return std::get<0>(row) == key.first && std::get<1>(row) == key.second &&
                           std::get<2>(row) != function.entry.offset;
                });
                if (name_counts[key] > 1 || occupied_elsewhere) { ++name_collisions; continue; }
                const std::string marker = "FLAIR provenance: " + candidate.provenance + " (" + candidate.name + ")";
                const std::string prior = annotation == snapshot.state->user->annotations.end() ? std::string{} : annotation->comment;
                if (prior.find(marker) == std::string::npos)
                    edits.emplace_back(Comment{Location{function.entry}, prior.empty() ? marker : prior + "\n" + marker});
                edits.emplace_back(Rename{Location{function.entry}, candidate.name});
                existing_names.emplace(function.entry.space.value, candidate.name, function.entry.offset);
                ++renamed;
            }
            if (!edits.empty()) {
                auto committed = take(actor.execute_batch(std::move(edits)));
                take(committed.result.get());
            }
        }
        for (const auto &function : recognized.functions) {
            out << "FLAIR function: " << location(function.entry)
                << " ambiguous=" << (function.ambiguous ? "true" : "false")
                << " candidates=" << function.candidates.size() << '\n';
            for (const auto &candidate : function.candidates) {
                const auto kind = candidate.kind == FlirtSymbolKind::local_name ? "local" : "public";
                out << "  Candidate: " << escape(candidate.name) << " kind=" << kind
                    << " provenance=" << escape(candidate.provenance)
                    << " patterns=" << candidate.matching_patterns << '\n';
            }
        }
        out << "FLAIR matches: " << recognized.functions.size()
            << " pattern-candidates=" << recognized.pattern_candidates
            << " comparisons=" << recognized.comparisons
            << "\nRecognition: " << (recognized.complete ? "complete" : "incomplete")
            << "\nEvidence: " << (args.action == L"flirt-apply" ? "persisted" : "not persisted")
            << "\nEdits: ";
        if (!args.flirt_rename_unique)
            out << "none\n";
        else if (!recognized.complete)
            out << "none (recognition incomplete; unique names not applied)\n";
        else
            out << renamed << " unique public names applied, " << name_ambiguous << " ambiguous, " << local_only
                << " local-only, " << name_collisions << " name collisions, " << already_named << " already named\n";
        return recognized.complete ? 0 : 3;
    }
    if (!snapshot.functions || !snapshot.references)
        throw Failure{{ErrorCode::unsupported,
                       snapshot.reason.empty() ? "No decoded function/reference facts available" : snapshot.reason}};
    if (args.action == L"functions") {
        if (args.functions_json) {
            out << "{\"schema\":\"hexlab.project-functions.v1\",\"analysis_status\":"
                << search_json_string(status(snapshot.status))
                << ",\"complete\":"
                << (snapshot.status == DerivedStatus::fresh && snapshot.functions->complete ? "true" : "false")
                << ",\"source_complete\":" << (snapshot.functions->complete ? "true" : "false")
                << ",\"function_count\":" << snapshot.functions->functions.size()
                << ",\"omitted_functions\":" << snapshot.functions->omitted_functions
                << ",\"functions\":[";
            for (std::size_t index = 0; index < snapshot.functions->functions.size(); ++index) {
                if (index) out << ',';
                const auto &function = *snapshot.functions->functions[index];
                const auto name = presentation_at(snapshot, function.entry).name;
                out << "{\"id\":" << function.id.value
                    << ",\"entry\":" << search_json_string(location(function.entry))
                    << ",\"name\":" << search_json_string(name)
                    << ",\"complete\":" << (function.complete ? "true" : "false")
                    << ",\"thunk\":" << (function.thunk ? "true" : "false")
                    << ",\"block_count\":" << function.blocks.size() << ",\"chunks\":[";
                for (std::size_t chunk_index = 0; chunk_index < function.chunks.size(); ++chunk_index) {
                    if (chunk_index) out << ',';
                    const auto &chunk = function.chunks[chunk_index];
                    out << "{\"begin\":" << search_json_string(location(chunk.begin))
                        << ",\"size\":" << chunk.size << ",\"block_count\":" << chunk.blocks.size() << '}';
                }
                out << "]}";
            }
            out << "]}\n";
            return snapshot.status == DerivedStatus::fresh && snapshot.functions->complete ? 0 : 3;
        }
        for (auto &function : snapshot.functions->functions) {
            auto text = presentation_at(snapshot, function->entry);
            out << "Function: " << location(function->entry) << " name=" << escape(text.name)
                << " blocks=" << function->blocks.size() << " chunks=" << function->chunks.size()
                << " complete=" << (function->complete ? "true" : "false");
            if (snapshot.loaded)
                profile_coordinate(out, *snapshot.loaded->image, function->entry);
            out << '\n';
        }
        out << "Analysis: " << status(snapshot.status) << '\n';
        return snapshot.status == DerivedStatus::fresh ? 0 : 3;
    }
    if (args.action == L"switches") {
        if (!snapshot.loaded || !args.at)
            throw Failure{{ErrorCode::unsupported, "Switch query requires a loaded image and function entry"}};
        const auto entry = std::get<Address>(*args.at);
        const auto found = std::find_if(snapshot.functions->functions.begin(), snapshot.functions->functions.end(),
                                        [&](const auto &function) { return function->entry == entry; });
        if (found == snapshot.functions->functions.end())
            throw Failure{{ErrorCode::invalid_argument, "No recovered function starts at the selected address"}};
        const auto analysis = take(analyze_switch_tables(*snapshot.loaded->image, snapshot.loaded->metadata,
                                                          **found, *snapshot.functions, {}));
        out << "{\"complete\":" << (analysis.complete ? "true" : "false") << ",\"switches\":[";
        for (std::size_t site_index = 0; site_index < analysis.sites.size(); ++site_index) {
            if (site_index)
                out << ',';
            const auto &site = analysis.sites[site_index];
            out << "{\"dispatch\":\"" << location(site.dispatch) << "\",\"table\":\"" << location(site.table)
                << "\",\"selector\":\"" << (site.selector.bank == RegisterBank::dex_vreg ? "v" : "r")
                << unsigned(site.selector.index) << "\",\"scale\":"
                << unsigned(site.scale) << ",\"selector_width\":" << unsigned(site.selector.width)
                << ",\"entry_encoding\":\""
                << (site.entry_encoding == SwitchEntryEncoding::absolute_pointer ? "absolute_pointer"
                    : site.entry_encoding == SwitchEntryEncoding::decoded_metadata ? "decoded_metadata"
                    : site.entry_encoding == SwitchEntryEncoding::signed_halfword_offset_from_table ? "signed_halfword_offset_from_table"
                    : site.entry_encoding == SwitchEntryEncoding::signed_offset_from_table ? "signed_offset_from_table"
                    : site.entry_encoding == SwitchEntryEncoding::thumb_scaled_pc_relative ? "thumb_scaled_pc_relative"
                    : site.entry_encoding == SwitchEntryEncoding::a32_branch_instruction ? "a32_branch_instruction"
                    : site.entry_encoding == SwitchEntryEncoding::unsigned_byte_offset_scaled_from_target_base
                        ? "unsigned_byte_offset_scaled_from_target_base"
                    : site.entry_encoding == SwitchEntryEncoding::unsigned_dword_offset_from_target_base
                        ? "unsigned_dword_offset_from_target_base"
                    : site.entry_encoding == SwitchEntryEncoding::signed_halfword_offset_from_target_base
                        ? "signed_halfword_offset_from_target_base"
                    : "signed_offset_from_target_base")
                << "\",\"target_base\":";
            if (site.target_base)
                out << '"' << location(*site.target_base) << '"';
            else
                out << "null";
            out << ",\"base_definition\":";
            if (site.base_definition)
                out << '"' << location(*site.base_definition) << '"';
            else
                out << "null";
            out << ",\"selector_use\":";
            if (site.selector_use)
                out << '"' << location(*site.selector_use) << '"';
            else
                out << "null";
            out << ",\"table_base_source\":\""
                << (site.table_base_source == SwitchSite::TableBaseSource::elf_relocation_pair ? "elf_relocation_pair"
                    : site.table_base_source == SwitchSite::TableBaseSource::operand_relocation ? "operand_relocation"
                    : "encoded_bytes")
                << "\",\"table_base_relocation_rows\":[";
            for (std::size_t row_index = 0; row_index < site.table_base_relocation_rows.size(); ++row_index) {
                if (row_index)
                    out << ',';
                out << site.table_base_relocation_rows[row_index];
            }
            out << ']';
            out << ",\"complete\":" << (site.complete ? "true" : "false")
                << ",\"incomplete_reason\":";
            if (site.incomplete_reason)
                out << '"' << *site.incomplete_reason << '"';
            else
                out << "null";
            out << ",\"case_count\":";
            if (site.case_count)
                out << *site.case_count;
            else
                out << "null";
            out << ",\"default_target\":";
            if (site.default_target)
                out << '"' << location(*site.default_target) << '"';
            else
                out << "null";
            out << ",\"cases\":[";
            for (std::size_t case_index = 0; case_index < site.cases.size(); ++case_index) {
                if (case_index)
                    out << ',';
                const auto &item = site.cases[case_index];
                const char *source = "encoded_bytes";
                switch (item.source) {
                case SwitchCase::TargetSource::encoded_bytes: source = "encoded_bytes"; break;
                case SwitchCase::TargetSource::elf_relocation: source = "elf_relocation"; break;
                case SwitchCase::TargetSource::macho_relocation: source = "macho_relocation"; break;
                case SwitchCase::TargetSource::macho_dyld_rebase: source = "macho_dyld_rebase"; break;
                }
                out << "{\"index\":" << item.index << ",\"target\":\"" << location(item.target)
                    << "\",\"source\":\"" << source << "\"";
                const auto output_rows = [&](const char *name, const std::vector<std::uint64_t> &rows) {
                    out << ",\"" << name << "\":[";
                    for (std::size_t row_index = 0; row_index < rows.size(); ++row_index) {
                        if (row_index)
                            out << ',';
                        out << rows[row_index];
                    }
                    out << ']';
                };
                output_rows("relocation_rows", item.relocation_rows);
                output_rows("dyld_classic_rows", item.dyld_classic_rows);
                output_rows("dyld_chained_rows", item.dyld_chained_rows);
                out << '}';
            }
            out << "]}";
        }
        out << "]}\n";
        return analysis.complete ? 0 : 3;
    }
    if (args.action == L"stack") {
        if (!snapshot.loaded || !args.at || !std::holds_alternative<Address>(*args.at))
            throw Failure{{ErrorCode::unsupported, "Stack query requires a loaded image and function entry"}};
        const auto entry = std::get<Address>(*args.at);
        const auto found = std::find_if(snapshot.functions->functions.begin(), snapshot.functions->functions.end(),
                                        [&](const auto &function) { return function->entry == entry; });
        if (found == snapshot.functions->functions.end())
            throw Failure{{ErrorCode::invalid_argument, "No recovered function starts at the selected address"}};
        const auto frame = std::find_if(snapshot.stack_frames.begin(), snapshot.stack_frames.end(),
                                        [&](const auto &record) { return record.function == (*found)->id; });
        if (frame == snapshot.stack_frames.end())
            throw Failure{{ErrorCode::unsupported, "Stack frame derivation is unavailable for this function"}};
        const auto &analysis = frame->frame;
        out << "Stack frame: " << location(entry) << " complete=" << (analysis.complete ? "true" : "false") << '\n';
        for (const auto &slot : analysis.slots) {
            out << "Slot: offset=" << slot.offset_from_entry_sp << " width=" << slot.width
                << " read=" << (slot.read ? "true" : "false") << " written=" << (slot.written ? "true" : "false")
                << " address_taken=" << (slot.address_taken ? "true" : "false")
                << " incoming_argument=" << (slot.incoming_argument ? "true" : "false")
                << " incoming_argument_abi=";
            if (slot.incoming_argument_abi) {
                switch (*slot.incoming_argument_abi) {
                case StackArgumentAbi::x86_32_near_call: out << "x86-32-near-call"; break;
                case StackArgumentAbi::sysv_x86_64: out << "sysv-x86-64"; break;
                case StackArgumentAbi::windows_x64: out << "windows-x64"; break;
                case StackArgumentAbi::aapcs64: out << "aapcs64"; break;
                case StackArgumentAbi::riscv32: out << "riscv32"; break;
                case StackArgumentAbi::riscv64: out << "riscv64"; break;
                case StackArgumentAbi::aapcs32: out << "aapcs32"; break;
                case StackArgumentAbi::mips_o32: out << "mips_o32"; break;
                case StackArgumentAbi::ppc64le_elfv2: out << "ppc64le-elfv2"; break;
                case StackArgumentAbi::x86_32_callee_cleanup: out << "x86-32-callee-cleanup"; break;
                case StackArgumentAbi::mips_n64: out << "mips-n64"; break;
                }
            } else out << "none";
            out << " accesses=";
            for (std::size_t i = 0; i < slot.accesses.size(); ++i) {
                if (i) out << ',';
                out << location(slot.accesses[i]);
            }
            if (!slot.outgoing_call_arguments.empty()) {
                out << " outgoing_call_arguments=";
                for (std::size_t i = 0; i < slot.outgoing_call_arguments.size(); ++i) {
                    if (i) out << ',';
                    const auto &argument = slot.outgoing_call_arguments[i];
                    const auto source_kind = argument.source_kind == StackCallArgumentSourceKind::x86_push ? "push@" :
                        argument.source_kind == StackCallArgumentSourceKind::windows_x64_shadow_store ? "win64-shadow@" :
                        argument.source_kind == StackCallArgumentSourceKind::riscv_store ? "riscv-store@" :
                        argument.source_kind == StackCallArgumentSourceKind::powerpc_store ? "ppc-store@" :
                        argument.source_kind == StackCallArgumentSourceKind::mips_store ? "mips-store@" :
                        argument.source_kind == StackCallArgumentSourceKind::aapcs32_store ? "aapcs32-store@" : "store@";
                    out << source_kind
                        << location(argument.source_instruction)
                        << "->call@" << location(argument.call_instruction);
                }
            }
            out << '\n';
        }
        return analysis.complete ? 0 : 3;
    }
    if (args.action == L"references") {
        Result<ReferencePage> query = Error{ErrorCode::invalid_argument, "Invalid reference query"};
        if (args.reference_range_size && args.reference_mapped_range) {
            if (!snapshot.loaded || !std::holds_alternative<FileOffset>(*args.at))
                throw Failure{{ErrorCode::invalid_argument,
                               "Mapped file-range query requires a loaded image and file location"}};
            query = args.incoming
                        ? snapshot.references->incoming_mapped_file_range(
                              *snapshot.loaded->image, std::get<FileOffset>(*args.at), *args.reference_range_size,
                              args.page)
                        : snapshot.references->outgoing_mapped_file_range(
                              *snapshot.loaded->image, std::get<FileOffset>(*args.at), *args.reference_range_size,
                              args.page);
        } else if (args.reference_range_size) {
            if (!std::holds_alternative<Address>(*args.at))
                throw Failure{{ErrorCode::invalid_argument, "Reference range query requires a VA location"}};
            query = args.incoming
                        ? snapshot.references->incoming_range(std::get<Address>(*args.at), *args.reference_range_size,
                                                              args.page)
                        : snapshot.references->outgoing_range(std::get<Address>(*args.at), *args.reference_range_size,
                                                              args.page);
        } else {
            query = args.incoming ? snapshot.references->incoming(*args.at, args.page)
                                  : snapshot.references->outgoing(*args.at, args.page);
        }
        auto page = take(std::move(query));
        for (auto &reference : page.rows) {
            out << "Reference: " << location(reference.source) << " -> ";
            if (auto target = std::get_if<Location>(&reference.target))
                out << location(*target);
            else if (auto external = std::get_if<ExternalIdentity>(&reference.target)) {
                if (external->wasm_function_index) {
                    out << "wasm-import:" << escape(external->library) << '!'
                        << escape(external->name.value_or(std::string{})) << " [function-index="
                        << *external->wasm_function_index;
                    if (external->host_binding) out << ", host-binding=" << escape(*external->host_binding);
                    out << ']';
                } else
                    out << "external:" << escape(external->library) << '!'
                        << (external->name ? escape(*external->name)
                                            : "#" + std::to_string(external->ordinal.value_or(0)));
            }
            else
                out << "unresolved";
            const auto *external_target = std::get_if<ExternalIdentity>(&reference.target);
            const bool wasm_import = external_target && external_target->wasm_function_index.has_value();
            out << " kind=" << reference_kind(reference.kind) << " provenance="
                << (wasm_import                                                        ? "wasm-import"
                    : reference.provenance.kind == ReferenceProvenanceKind::user               ? "user"
                    : reference.provenance.kind == ReferenceProvenanceKind::import_slot      ? "import-slot"
                    : reference.provenance.kind == ReferenceProvenanceKind::elf_relocation   ? "elf-relocation"
                    : reference.provenance.kind == ReferenceProvenanceKind::macho_dyld       ? "macho-dyld"
                    : reference.provenance.kind == ReferenceProvenanceKind::macho_relocation ? "macho-relocation"
                    : reference.provenance.kind == ReferenceProvenanceKind::dataflow         ? "dataflow"
                                                                                             : "decoded");
            if (reference.provenance.elf) {
                const auto &provenance = *reference.provenance.elf;
                out << " elf-resolution=" << elf_resolution(provenance.resolution);
                if (provenance.origins.size() == 1) {
                    const auto &origin = provenance.origins[0];
                    const auto &relocation = origin.relocation;
                    out << " elf-record=" << location(FileOffset{relocation.record_file_offset})
                        << " elf-type=" << relocation.type;
                    if (relocation.symbol_table)
                        out << " symbol-table=" << location(FileOffset{relocation.symbol_table->file_offset})
                            << " symbol-index=" << relocation.symbol_index;
                    if (origin.symbol && !origin.symbol->name.empty())
                        out << " symbol=" << escape(origin.symbol->name);
                    if (relocation.addend)
                        out << " addend=" << *relocation.addend;
                } else
                    out << " elf-origins=" << provenance.origins.size();
            }
            if (reference.provenance.dyld) {
                const auto &provenance = *reference.provenance.dyld;
                out << " dyld-origins=" << provenance.origins.size();
                if (provenance.resolution.binding) {
                    const auto &binding = *provenance.resolution.binding;
                    out << " symbol=" << escape(binding.name) << " addend=" << binding.addend;
                    if (binding.library_ordinal)
                        out << " library-ordinal=" << *binding.library_ordinal;
                }
            }
            if (snapshot.loaded) {
                profile_coordinate(out, *snapshot.loaded->image, reference.source, "logical-source", false);
                if (const auto *target = std::get_if<Location>(&reference.target))
                    profile_coordinate(out, *snapshot.loaded->image, *target, "logical-target", false);
            }
            out << '\n';
        }
        out << "References: " << page.total << "\nAnalysis: " << status(snapshot.status) << '\n';
        if (page.next_offset)
            out << "Next offset: " << *page.next_offset << '\n';
        return page.next_offset || snapshot.status != DerivedStatus::fresh ? 3 : 0;
    }
    std::optional<FunctionId> selected;
    if (args.graph_kind == GraphKind::function_cfg) {
        require(args.at && std::holds_alternative<Address>(*args.at), "CFG requires a virtual function entry location");
        for (auto &function : snapshot.functions->functions)
            if (function->entry == std::get<Address>(*args.at)) {
                selected = function->id;
                break;
            }
        require(selected.has_value(), "No function begins at the requested location");
    } else if (args.graph_kind == GraphKind::function_calls) {
        require(args.at && std::holds_alternative<Address>(*args.at),
                "Function-call graph requires a virtual address inside a recovered function");
    }
    auto graph = take(make_project_graph(snapshot, args.graph_kind, args.at, args.graph_options, {}));
    auto model = graph.model;
    std::string text;
    if (args.dot)
        text = take(export_graph_dot(*model, {}));
    else {
        text = take(export_graph_json(*model, *graph.layout, {}));
    }
    out << text << '\n';
    return model->complete && snapshot.status == DerivedStatus::fresh ? 0 : 3;
}
} // namespace hexlab::cli::project_detail

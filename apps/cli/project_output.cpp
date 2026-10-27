#include "project_arguments.hpp"
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
#include "hexlab/loaders/cil.hpp"
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
void print_generic_parameter(std::ostream &out, const ManagedGenericParameter &parameter) {
    const auto variance = parameter.flags & 0x3u;
    out << "  Generic parameter: number=" << parameter.number
        << " token=0x" << std::hex << parameter.token << std::dec
        << " name=" << escape(parameter.name)
        << " variance=" << (variance == 1 ? "covariant" : variance == 2 ? "contravariant" : "none")
        << " reference-type=" << ((parameter.flags & 0x4u) ? "true" : "false")
        << " value-type=" << ((parameter.flags & 0x8u) ? "true" : "false")
        << " default-constructor=" << ((parameter.flags & 0x10u) ? "true" : "false") << '\n';
    for (const auto token : parameter.constraint_tokens)
        out << "    Constraint token: 0x" << std::hex << token << std::dec << '\n';
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
        pe_description(out, snapshot.loaded->metadata);
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
                << " flags=0x" << std::hex << field.flags << std::dec << " type=";
            if (field.type_signature) out << escape(managed_type_text(*field.type_signature));
            else {
                out << "unsupported";
                if (!field.signature_diagnostic.empty()) out << " detail=" << escape(field.signature_diagnostic);
                complete = false;
            }
            out << '\n';
        }
        out << "Fields: " << fields.size() << "\nAnalysis: " << (complete ? "complete" : "partial") << '\n';
        return complete ? 0 : 3;
    }
    if (args.action == L"managed-types") {
        if (!snapshot.loaded)
            throw Failure{{ErrorCode::unsupported, "Managed type query requires a loaded PE image"}};
        const auto types = take(inspect_managed_types(*snapshot.loaded));
        for (const auto &type : types) {
            out << "Type: token=0x" << std::hex << type.token << std::dec
                << " name=" << escape(type.full_name)
                << " generic-arity=" << type.generic_parameters.size() << '\n';
            for (const auto &parameter : type.generic_parameters)
                print_generic_parameter(out, parameter);
        }
        out << "Types: " << types.size() << "\nAnalysis: complete\n";
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
        auto result = search(snapshot, *args.query, args.cursor, args.search_limits, {});
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
        require(snapshot.loaded && snapshot.functions && args.at && std::holds_alternative<Address>(*args.at),
                "Function fingerprint extraction requires a loaded function and virtual entry address");
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
        std::error_code ec;
        const auto size = std::filesystem::file_size(args.fingerprint_definitions, ec);
        if (ec || size > 1024 * 1024)
            throw Failure{{ErrorCode::invalid_argument, "Cannot read fingerprint catalog or file exceeds 1 MiB"}};
        std::ifstream input(args.fingerprint_definitions, std::ios::binary);
        if (!input) throw Failure{{ErrorCode::io, "Cannot open fingerprint catalog"}};
        std::string text(static_cast<std::size_t>(size), '\0');
        if (size && !input.read(text.data(), static_cast<std::streamsize>(size)))
            throw Failure{{ErrorCode::io, "Cannot read fingerprint catalog"}};
        const auto catalog = take(parse_function_fingerprint_catalog(text));
        const auto recognized = take(recognize_function_fingerprints(*snapshot.loaded->image, *snapshot.effective,
            *snapshot.functions, catalog, args.fingerprint_limits));
        auto canonical=take(serialize_function_fingerprint_catalog(catalog));
        auto evidence=take(make_function_recognition_evidence(*snapshot.functions,catalog_digest(canonical),recognized));
        auto stored=take(actor.persist_function_recognition(std::move(evidence)));take(stored.result.get());
        for (const auto &function : recognized.functions) {
            out << "Function fingerprint: " << location(function.entry)
                << " ambiguous=" << (function.ambiguous ? "true" : "false")
                << " candidates=" << function.candidates.size() << '\n';
            for (const auto &candidate : function.candidates)
                out << "  Candidate: " << escape(candidate.name) << " provenance=" << escape(candidate.provenance)
                    << " instructions=" << candidate.instruction_count << " sha256=" << digest_hex(candidate.digest) << '\n';
        }
        out << "Fingerprint matches: " << recognized.functions.size()
            << " functions-scanned=" << recognized.functions_scanned
            << " instructions-scanned=" << recognized.instructions_scanned
            << " token-bytes=" << recognized.token_bytes
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
        std::error_code ec;
        const auto size = std::filesystem::file_size(args.signature_definitions, ec);
        if (ec || size > 1024 * 1024)
            throw Failure{{ErrorCode::invalid_argument, "Cannot read signature definitions or file exceeds 1 MiB"}};
        std::ifstream input(args.signature_definitions, std::ios::binary);
        if (!input)
            throw Failure{{ErrorCode::io, "Cannot open signature definitions"}};
        std::string text(static_cast<std::size_t>(size), '\0');
        if (size && !input.read(text.data(), static_cast<std::streamsize>(size)))
            throw Failure{{ErrorCode::io, "Cannot read signature definitions"}};
        auto catalog = take(parse_signature_catalog(text));
        if (args.signature_function_entries) {
            require(bool(snapshot.functions), "Function recognition requires recovered function facts");
            const auto recognized = take(recognize_function_signatures(*snapshot.loaded->image, *snapshot.effective,
                *snapshot.functions, catalog, args.signature_limits));
            auto canonical=take(serialize_signature_catalog(catalog));
            auto evidence=take(make_function_recognition_evidence(*snapshot.functions,catalog_digest(canonical),recognized));
            auto stored=take(actor.persist_function_recognition(std::move(evidence)));take(stored.result.get());
            for (const auto &function : recognized.functions) {
                out << "Function signature: " << location(function.entry)
                    << " ambiguous=" << (function.ambiguous ? "true" : "false")
                    << " candidates=" << function.candidates.size() << '\n';
                for (const auto &match : function.candidates)
                    out << "  Candidate: " << escape(match.name) << " provenance=" << escape(match.provenance) << '\n';
            }
            out << "Recognized functions: " << recognized.functions.size()
                << "\nScan: " << (recognized.complete ? "complete" : "incomplete")
                << "\nEvidence: persisted for current source\n";
            return recognized.complete ? 0 : 3;
        }
        auto scan = take(scan_executable_signatures(*snapshot.loaded->image, *snapshot.effective, catalog,
                                                    args.signature_limits, {}));
        for (const auto &match : scan.matches) {
            out << "Signature: " << escape(match.name) << " provenance=" << escape(match.provenance)
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
                << "\",\"selector\":\"r" << unsigned(site.selector.index) << "\",\"scale\":"
                << unsigned(site.scale) << ",\"entry_encoding\":\""
                << (site.entry_encoding == SwitchEntryEncoding::absolute_pointer ? "absolute_pointer"
                    : site.entry_encoding == SwitchEntryEncoding::signed_offset_from_table ? "signed_offset_from_table"
                    : site.entry_encoding == SwitchEntryEncoding::thumb_scaled_pc_relative ? "thumb_scaled_pc_relative"
                    : site.entry_encoding == SwitchEntryEncoding::a32_branch_instruction ? "a32_branch_instruction"
                    : "signed_offset_from_target_base")
                << "\",\"target_base\":";
            if (site.target_base)
                out << '"' << location(*site.target_base) << '"';
            else
                out << "null";
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
                << " accesses=";
            for (std::size_t i = 0; i < slot.accesses.size(); ++i) {
                if (i) out << ',';
                out << location(slot.accesses[i]);
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
            else if (auto external = std::get_if<ExternalIdentity>(&reference.target))
                out << "external:" << escape(external->library) << '!'
                    << (external->name ? escape(*external->name) : "#" + std::to_string(external->ordinal.value_or(0)));
            else
                out << "unresolved";
            out << " kind=" << reference_kind(reference.kind) << " provenance="
                << (reference.provenance.kind == ReferenceProvenanceKind::user               ? "user"
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

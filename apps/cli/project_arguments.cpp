#include "project_arguments.hpp"
#include "argument_text.hpp"
#include "hexlab/workspace/navigation.hpp"
#include <sstream>
#include <set>
#include <iomanip>
namespace hexlab::cli::project_detail {
std::string utf8(std::wstring_view value) {
    try { return wide_to_utf8(value); }
    catch (const std::exception &error) { throw Failure{{ErrorCode::invalid_argument, error.what()}}; }
}
std::string hex(uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}
std::string escape(std::string_view text) {
    std::ostringstream out;
    for (unsigned char c : text) {
        if (c >= 32 && c < 127 && c != '\\')
            out << char(c);
        else if (c == '\\')
            out << "\\\\";
        else
            out << "\\x" << std::hex << std::setw(2) << std::setfill('0') << unsigned(c);
    }
    return out.str();
}
std::string location(Location value) {
    if (auto address = std::get_if<Address>(&value))
        return "va:" + (address->space.value ? std::to_string(address->space.value) + ":" : "") + hex(address->offset);
    return "file:" + hex(std::get<FileOffset>(value).value);
}
namespace {
uint64_t number(std::wstring_view value) { return take(parse_address(value)); }
LocationExpression typed_location(std::wstring_view value) {
    if (value.starts_with(L"seg:"))
        return take(parse_x86_logical_address(value.substr(4)));
    if (value.starts_with(L"file:"))
        return Location{FileOffset{number(value.substr(5))}};
    require(value.starts_with(L"va:"), "Location must use va:<address>, seg:<selector>:<offset>, or file:<offset>");
    value.remove_prefix(3);
    auto separator = value.find(L':');
    uint32_t space = 0;
    if (separator != value.npos) {
        auto parsed = number(value.substr(0, separator));
        require(parsed <= UINT32_MAX, "Location address-space ID exceeds 32 bits");
        space = uint32_t(parsed);
        value.remove_prefix(separator + 1);
    }
    return Location{Address{{space}, number(value)}};
}
LocationExpression address(LocationExpression value) {
    if (const auto *location = std::get_if<Location>(&value))
        require(std::holds_alternative<Address>(*location), "This command requires a virtual address location");
    return value;
}
template <class Builder> CommandFactory location_command(LocationExpression at, Builder builder) {
    return [at, builder](const ProjectSnapshot &project) -> Result<ProjectCommand> {
        auto resolved = resolve_location(project, at);
        if (!resolved)
            return resolved.error();
        return builder(resolved.value());
    };
}
struct Options {
    std::map<std::wstring, std::wstring> values;
    bool contains(std::wstring_view name) const { return values.contains(std::wstring(name)); }
    std::wstring pop(std::wstring_view name, std::wstring fallback = {}) {
        auto found = values.find(std::wstring(name));
        if (found == values.end())
            return fallback;
        auto result = std::move(found->second);
        values.erase(found);
        return result;
    }
    std::wstring needed(std::wstring_view name) {
        require(contains(name), "Missing required option " + utf8(name));
        return pop(name);
    }
    bool flag(std::wstring_view name) {
        bool present = contains(name);
        pop(name);
        return present;
    }
    uint64_t count(std::wstring_view name, uint64_t fallback) { return contains(name) ? number(pop(name)) : fallback; }
};
std::vector<std::byte> patch_bytes(std::wstring_view text) {
    auto narrow = utf8(text);
    take(search_query_fingerprint(BytePattern{narrow}));
    std::istringstream input(narrow);
    std::string octet;
    std::vector<std::byte> result;
    while (input >> octet) {
        require(octet != "??", "Patch bytes cannot contain wildcards");
        unsigned value = 0;
        for (char c : octet)
            value = value * 16 + unsigned(c <= '9' ? c - '0' : (c >= 'a' ? c - 'a' : c - 'A') + 10);
        result.push_back(std::byte(value));
    }
    return result;
}
Sha256Digest digest(std::wstring_view text) {
    require(text.size() == 64, "Invalid continuation digest");
    Sha256Digest result{};
    for (std::size_t n = 0; n < 32; ++n) {
        unsigned value = 0;
        for (auto c : text.substr(n * 2, 2)) {
            require((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'), "Invalid continuation digest");
            value = value * 16 + unsigned(c <= L'9' ? c - L'0' : c - L'a' + 10);
        }
        result[n] = std::byte(value);
    }
    return result;
}
} // namespace
Result<Location> resolve_location(const ProjectSnapshot &project, const LocationExpression &expression) {
    if (const auto *location = std::get_if<Location>(&expression))
        return *location;
    if (!project.loaded || !project.loaded->image->layout().x86_profile)
        return Error{ErrorCode::invalid_argument, "Selector locations require a segmented project mapping"};
    auto address = project.loaded->image->from_logical(std::get<X86LogicalAddress>(expression));
    if (!address)
        return Error{ErrorCode::invalid_argument, address.error().message};
    return Location{address.value()};
}
std::string cursor_text(const SearchCursor &c) {
    return "1:" + std::to_string(c.source_key.input.size) + ":" + digest_hex(c.source_key.input.sha256) + ":" +
           std::to_string(c.source_key.byte_revision) + ":" + std::to_string(c.source_key.decision_revision) + ":" +
           digest_hex(c.source_key.recipe_fingerprint) + ":" + digest_hex(c.source_key.engine_fingerprint) + ":" +
           digest_hex(c.query_fingerprint) + ":" + std::to_string(c.next_offset) + ":" +
           std::to_string(c.next_instruction) + ":" + std::to_string(c.next_operand);
}
SearchCursor parse_cursor(std::wstring_view text) {
    require(text.size() <= 1024, "Continuation is too long");
    std::vector<std::wstring_view> fields;
    for (;;) {
        auto separator = text.find(L':');
        fields.push_back(text.substr(0, separator));
        if (separator == text.npos)
            break;
        text.remove_prefix(separator + 1);
    }
    require(fields.size() == 11 && fields[0] == L"1", "Unknown continuation format");
    SearchCursor c;
    c.source_key.input = {number(fields[1]), digest(fields[2])};
    c.source_key.byte_revision = number(fields[3]);
    c.source_key.decision_revision = number(fields[4]);
    c.source_key.recipe_fingerprint = digest(fields[5]);
    c.source_key.engine_fingerprint = digest(fields[6]);
    c.query_fingerprint = digest(fields[7]);
    c.next_offset = number(fields[8]);
    c.next_instruction = number(fields[9]);
    auto operand = number(fields[10]);
    require(operand <= UINT32_MAX, "Invalid continuation operand");
    c.next_operand = uint32_t(operand);
    return c;
}
Arguments parse(std::span<const std::wstring_view> args) {
    require(args.size() >= 2, "Project command requires an action and project path");
    Arguments result;
    std::size_t option_start = 2;
    if (args[0] == L"history") {
        require(args.size() >= 3 && (args[1] == L"audit" || args[1] == L"preview" || args[1] == L"save"), "History requires audit, preview, or save and a project path");
        result.action = args[1] == L"audit" ? L"history-audit" : args[1] == L"preview" ? L"history-preview" : L"history-save";
        result.path = path_from_wide(args[2]);
        option_start = 3;
    } else if (args[0] == L"recovery") {
        require(args.size() >= 3 && (args[1] == L"list" || args[1] == L"restore"),
                "Recovery requires list or restore and a directory/artifact path");
        result.action = args[1] == L"list" ? L"recovery-list" : L"recovery-restore";
        result.path = path_from_wide(args[2]);
        option_start = 3;
    } else if (args[0] == L"backup") {
        if (args.size() >= 3 && args[1] == L"restore") {
            result.action = L"backup-restore";
            result.path = path_from_wide(args[2]);
            option_start = 3;
        } else {
            require(args.size() >= 2, "Backup requires a project path");
            result.action = L"backup";
            result.path = path_from_wide(args[1]);
            option_start = 2;
        }
    } else if (args[0] == L"exchange") {
        require(args.size() >= 3 && (args[1] == L"export" || args[1] == L"import"), "Exchange requires export or import and a project path");
        result.action = args[1] == L"export" ? L"exchange-export" : L"exchange-import";
        result.path = path_from_wide(args[2]);
        option_start = 3;
    } else if (args[0] == L"types") {
        require(args.size() >= 3 && (args[1] == L"export" || args[1] == L"import"), "Types requires export or import and a project path");
        result.action = args[1] == L"export" ? L"types-export" : L"types-import";
        result.path = path_from_wide(args[2]);
        option_start = 3;
    } else {
        result.action = args[0];
        result.path = path_from_wide(args[1]);
    }
    require(!result.path.empty(), "Empty project path");
    Options options;
    const std::set<std::wstring_view> flags{L"--readonly", L"--replace", L"--remove", L"--signed", L"--unsigned", L"--function-entries", L"--json", L"--verify-replay", L"--dry-run", L"--skip-assignments-on-mismatch", L"--replace-assignments"};
    for (std::size_t n = option_start; n < args.size(); ++n) {
        auto name = args[n];
        require(name.starts_with(L"--"), "Expected a named option");
        std::wstring value;
        if (!flags.contains(name)) {
            require(n + 1 < args.size() && !args[n + 1].starts_with(L"--"), "Option requires a value");
            value = args[++n];
        }
        require(options.values.emplace(name, std::move(value)).second, "Duplicate option " + utf8(name));
    }
    result.readonly = options.flag(L"--readonly");
    result.analysis.instruction_budget =
        std::size_t(options.count(L"--instruction-budget", result.analysis.instruction_budget));
    result.analysis.string_budget = std::size_t(options.count(L"--string-budget", result.analysis.string_budget));
    if (result.action == L"history-audit") {
        result.history_json = options.flag(L"--json");
        result.history_verify_replay = options.flag(L"--verify-replay");
        if (options.contains(L"--expected-edit"))
            result.history_expected_edit = number(options.pop(L"--expected-edit"));
        result.history_after_step = options.count(L"--after-step", 0);
        require(result.history_after_step == 0 || result.history_expected_edit.has_value(),
                "Resuming history audit requires --expected-edit from the prior page");
        require(!result.history_verify_replay || result.history_after_step == 0,
                "History replay verification must start at step zero");
        const auto steps = options.count(L"--page-steps", result.history_audit_limits.max_steps);
        require(steps > 0 && steps <= 4096, "History audit page steps must be 1..4096");
        result.history_audit_limits.max_steps = static_cast<std::size_t>(steps);
        const auto page_bytes = options.count(L"--page-bytes", result.history_audit_limits.max_delta_bytes);
        require(page_bytes > 0 && page_bytes <= 128ull * 1024 * 1024,
                "History audit page-byte budget must be 1..134217728");
        result.history_audit_limits.max_delta_bytes = static_cast<std::size_t>(page_bytes);
        const auto max_pages = options.count(L"--max-pages", result.history_max_pages);
        require(max_pages > 0 && max_pages <= 4096, "History audit max pages must be 1..4096");
        result.history_max_pages = static_cast<std::size_t>(max_pages);
        const auto total_bytes = options.count(L"--total-bytes", result.history_total_delta_bytes);
        require(total_bytes > 0 && total_bytes <= 4ull * 1024 * 1024 * 1024,
                "History audit total-byte budget must be 1..4294967296");
        result.history_total_delta_bytes = static_cast<std::size_t>(total_bytes);
    } else if (result.action == L"history-preview" || result.action == L"history-save") {
        result.history_target_step = number(options.needed(L"--step"));
        result.history_json = options.flag(L"--json");
        const auto steps = options.count(L"--max-steps", result.history_preview_limits.max_steps);
        require(steps <= 4096, "History replay max steps must be 0..4096");
        result.history_preview_limits.max_steps = static_cast<std::size_t>(steps);
        const auto bytes = options.count(L"--max-bytes", result.history_preview_limits.max_delta_bytes);
        require(bytes <= 64ull * 1024 * 1024, "History replay max bytes must be 0..67108864");
        result.history_preview_limits.max_delta_bytes = static_cast<std::size_t>(bytes);
        if (result.action == L"history-save") {
            result.output = path_from_wide(options.needed(L"--output"));
            result.replace = options.flag(L"--replace");
            if (options.contains(L"--expected-edit"))
                result.history_expected_edit = number(options.pop(L"--expected-edit"));
        }
    } else if (result.action == L"recovery-list") {
        result.recovery_json = options.flag(L"--json");
    } else if (result.action == L"recovery-restore") {
        result.output = path_from_wide(options.needed(L"--output"));
        result.replace = options.flag(L"--replace");
    } else if (result.action == L"backup") {
        result.output = path_from_wide(options.needed(L"--output"));
        result.replace = options.flag(L"--replace");
    } else if (result.action == L"backup-restore") {
        result.output = path_from_wide(options.needed(L"--output"));
        result.replace = options.flag(L"--replace");
    } else if (result.action == L"exchange-export") {
        result.output = path_from_wide(options.needed(L"--output"));
        result.replace = options.flag(L"--replace");
    } else if (result.action == L"exchange-import") {
        result.exchange_dry_run = options.flag(L"--dry-run");
        result.exchange_json = options.flag(L"--json");
        require(!result.readonly || result.exchange_dry_run, "Cannot import into a read-only project");
        result.exchange_input = path_from_wide(options.needed(L"--input"));
        auto policy = options.pop(L"--conflict", L"fail");
        require(policy == L"fail" || policy == L"skip" || policy == L"replace", "Unknown exchange conflict policy");
        result.exchange_conflicts = policy == L"skip" ? ExchangeConflictPolicy::skip
                                    : policy == L"replace" ? ExchangeConflictPolicy::replace
                                                            : ExchangeConflictPolicy::fail;
    } else if (result.action == L"types-export") {
        result.output = path_from_wide(options.needed(L"--output"));
        result.replace = options.flag(L"--replace");
    } else if (result.action == L"types-import") {
        require(!result.readonly, "Cannot import types into a read-only project");
        result.type_library_input = path_from_wide(options.needed(L"--input"));
        result.type_skip_assignments_on_mismatch = options.flag(L"--skip-assignments-on-mismatch");
        result.type_replace_assignments = options.flag(L"--replace-assignments");
    } else if (result.action == L"create") {
        require(!result.readonly, "Cannot create a read-only project");
        result.replace = options.flag(L"--replace");
        result.input.path = path_from_wide(options.needed(L"--input"));
        if (options.contains(L"--pdb")) result.input.pdb_path = path_from_wide(options.pop(L"--pdb"));
        if (options.contains(L"--pdb-search")) result.input.pdb_search_paths.emplace_back(path_from_wide(options.pop(L"--pdb-search")));
        if (options.contains(L"--dwarf-supplementary-package"))
            result.input.dwarf_supplementary_package_path = path_from_wide(options.pop(L"--dwarf-supplementary-package"));
        auto format = options.pop(L"--format", L"auto");
        require(format == L"auto" || format == L"pe" || format == L"elf" || format == L"raw" || format == L"macho" || format == L"wasm" || format == L"dex" || format == L"jvm" ||
                    format == L"ihex" || format == L"srec",
                "Unknown input format");
        result.input.format = format == L"raw"     ? Format::raw
                              : format == L"pe"    ? Format::pe
                              : format == L"elf"   ? Format::elf
                              : format == L"macho" ? Format::macho
                              : format == L"wasm"  ? Format::wasm
                              : format == L"dex"   ? Format::dex
                              : format == L"jvm"   ? Format::jvm
                              : format == L"ihex"  ? Format::intel_hex
                              : format == L"srec"  ? Format::s_record
                                                   : Format::automatic;
        if (options.contains(L"--slice")) {
            const auto index = number(options.pop(L"--slice"));
            require(index <= UINT32_MAX &&
                        (result.input.format == Format::automatic || result.input.format == Format::macho),
                    "Slice requires auto or macho format and a 32-bit unsigned index");
            result.input.macho = MachOOptions{static_cast<std::uint32_t>(index)};
        }
        if (result.input.format == Format::raw) {
            if (options.contains(L"--profile") || options.contains(L"--arm-profile")) {
                require(!options.contains(L"--arch") && !options.contains(L"--base") && !options.contains(L"--entry"),
                        "A raw profile replaces architecture/base/entry options");
                require(!(options.contains(L"--profile") && options.contains(L"--arm-profile")),
                        "Choose one raw profile format");
                if (options.contains(L"--arm-profile"))
                    result.input.arm_profile_path = path_from_wide(options.pop(L"--arm-profile"));
                else
                    result.input.x86_profile_path = path_from_wide(options.pop(L"--profile"));
            } else {
                auto arch = options.needed(L"--arch");
                require(arch == L"x86-32" || arch == L"x86-64" || arch == L"a64" || arch == L"6502" ||
                            arch == L"rv32" || arch == L"rv64" || arch == L"mips64" || arch == L"ppc32le" ||
                            arch == L"ppc32be" || arch == L"ppc64le" || arch == L"ppc64be",
                        "Raw architecture must include ppc32le/be or ppc64le/be for PowerPC");
                const bool ppc = arch.starts_with(L"ppc");
                RawOptions raw{arch == L"a64"      ? Architecture::arm64
                               : arch == L"x86-32" ? Architecture::x86
                               : arch == L"6502"   ? Architecture::mos6502
                               : arch == L"rv32"   ? Architecture::riscv32
                               : arch == L"rv64"   ? Architecture::riscv64
                               : arch == L"mips64" ? Architecture::mips64
                               : ppc               ? Architecture::powerpc
                                                   : Architecture::x86_64,
                               arch == L"a64"      ? ExecutionMode::a64
                               : arch == L"x86-32" ? ExecutionMode::x86_32
                               : arch == L"6502"   ? ExecutionMode::m6502
                               : arch == L"rv32"   ? ExecutionMode::rv32
                               : arch == L"rv64"   ? ExecutionMode::rv64
                               : arch == L"mips64" ? ExecutionMode::mips64
                               : ppc && arch.starts_with(L"ppc32") ? ExecutionMode::ppc32
                               : ppc ? ExecutionMode::ppc64
                                                   : ExecutionMode::x86_64,
                               {{0}, number(options.needed(L"--base"))},
                               true,
                               false,
                               true,
                               {}};
                if (ppc) raw.order = arch.ends_with(L"be") ? ByteOrder::big : ByteOrder::little;
                if (options.contains(L"--entry"))
                    raw.entry = Address{{0}, number(options.pop(L"--entry"))};
                auto valid = validate_raw_coordinates(raw);
                require(bool(valid), valid ? "" : valid.error().message);
                result.input.raw = raw;
            }
        }
        result.input.run_analysis = false;
        result.input.analysis_options = result.analysis;
    } else if (result.action == L"rename" || result.action == L"comment" || result.action == L"bookmark" ||
               result.action == L"patch" || result.action == L"define" || result.action == L"undefine" ||
               result.action == L"reference") {
        auto at = typed_location(options.needed(L"--at"));
        if (result.action == L"rename")
            result.command = location_command(
                at, [name = utf8(options.needed(L"--name"))](Location at) { return ProjectCommand{Rename{at, name}}; });
        else if (result.action == L"comment")
            result.command = location_command(at, [text = utf8(options.needed(L"--text"))](Location at) {
                return ProjectCommand{Comment{at, text}};
            });
        else if (result.action == L"bookmark") {
            bool remove = options.flag(L"--remove");
            auto label = utf8(remove ? options.pop(L"--label") : options.needed(L"--label"));
            result.command = location_command(
                at, [remove, label](Location at) { return ProjectCommand{BookmarkCommand{at, label, remove}}; });
        } else if (result.action == L"patch")
            result.command = location_command(at, [replacement = patch_bytes(options.needed(L"--bytes"))](Location at) {
                return ProjectCommand{PatchBytes{at, replacement}};
            });
        else if (result.action == L"undefine") {
            const auto kind = options.needed(L"--kind");
            require(kind == L"function", "Undefine supports only --kind function");
            const auto begin = address(at);
            result.command = location_command(begin, [](Location at) {
                return ProjectCommand{ResetFunctionOverride{std::get<Address>(at)}};
            });
        } else if (result.action == L"define") {
            auto begin = address(at);
            auto kind = options.needed(L"--kind");
            if (kind == L"code" || kind == L"data") {
                auto size = number(options.needed(L"--size"));
                auto region = kind == L"code" ? RegionKind::code : RegionKind::data;
                result.command = location_command(begin, [size, region](Location at) {
                    return ProjectCommand{DefineRegion{std::get<Address>(at), size, region}};
                });
            } else if (kind == L"function")
                result.command = location_command(
                    begin, [](Location at) { return ProjectCommand{DefineFunction{std::get<Address>(at)}}; });
            else if (kind == L"suppress" || kind == L"unsuppress")
                result.command = location_command(begin, [suppressed = kind == L"suppress"](Location at) {
                    return ProjectCommand{SuppressFunction{std::get<Address>(at), suppressed}};
                });
            else if (kind == L"chunks") {
                auto raw = options.needed(L"--chunks");
                std::wstring_view remaining = raw;
                std::vector<std::pair<LocationExpression, std::uint64_t>> chunks;
                while (!remaining.empty()) {
                    auto comma = remaining.find(L',');
                    auto chunk = remaining.substr(0, comma);
                    auto plus = chunk.find(L'+');
                    require(plus != chunk.npos, "Chunk requires an address+size pair");
                    chunks.emplace_back(address(typed_location(chunk.substr(0, plus))), number(chunk.substr(plus + 1)));
                    if (comma == remaining.npos)
                        break;
                    remaining.remove_prefix(comma + 1);
                }
                result.command = [begin, chunks](const ProjectSnapshot &project) -> Result<ProjectCommand> {
                    auto entry = resolve_location(project, begin);
                    if (!entry)
                        return entry.error();
                    std::vector<DecisionRange> resolved;
                    for (const auto &[expression, size] : chunks) {
                        auto at = resolve_location(project, expression);
                        if (!at)
                            return at.error();
                        resolved.push_back({std::get<Address>(at.value()), size});
                    }
                    return ProjectCommand{SetFunctionChunks{std::get<Address>(entry.value()), std::move(resolved)}};
                };
            } else
                require(false, "Unknown definition kind");
        } else {
            auto target = typed_location(options.needed(L"--to"));
            auto kind = options.needed(L"--kind");
            const std::map<std::wstring, UserReferenceKind> kinds{
                {L"code", UserReferenceKind::code},      {L"data", UserReferenceKind::data},
                {L"call", UserReferenceKind::call},      {L"jump", UserReferenceKind::jump},
                {L"read", UserReferenceKind::read},      {L"write", UserReferenceKind::write},
                {L"address", UserReferenceKind::address}};
            require(kinds.contains(kind), "Unknown reference kind");
            auto type = kinds.at(kind);
            bool remove = options.flag(L"--remove");
            result.command = [at, target, type, remove](const ProjectSnapshot &project) -> Result<ProjectCommand> {
                auto source = resolve_location(project, at);
                if (!source)
                    return source.error();
                auto destination = resolve_location(project, target);
                if (!destination)
                    return destination.error();
                return ProjectCommand{SetReference{source.value(), destination.value(), type, remove}};
            };
        }
    } else if (result.action == L"export" || result.action == L"save-as") {
        result.output = path_from_wide(options.needed(L"--output"));
        result.replace = options.flag(L"--replace");
    } else if (result.action == L"switches") {
        result.at_expression = address(typed_location(options.needed(L"--at")));
    } else if (result.action == L"stack") {
        result.at_expression = address(typed_location(options.needed(L"--at")));
    } else if (result.action == L"references") {
        result.at_expression = typed_location(options.needed(L"--at"));
        auto direction = options.pop(L"--direction", L"outgoing");
        require(direction == L"incoming" || direction == L"outgoing", "Unknown reference direction");
        result.incoming = direction == L"incoming";
        result.reference_mapped_range = options.flag(L"--mapped");
        if (options.contains(L"--size")) {
            result.reference_range_size = options.count(L"--size", 0);
            require(*result.reference_range_size > 0, "Reference range size must be greater than zero");
        }
        require(!result.reference_mapped_range ||
                    (result.reference_range_size && std::holds_alternative<Location>(*result.at_expression) &&
                     std::holds_alternative<FileOffset>(std::get<Location>(*result.at_expression))),
                "--mapped requires --size and a file:<offset> location");
        result.page.offset = options.count(L"--offset", 0);
        result.page.limit = std::size_t(options.count(L"--limit", 256));
        require(result.page.limit > 0 && result.page.limit <= 4096, "Reference limit must be 1..4096");
    } else if (result.action == L"graph") {
        auto kind = options.pop(L"--kind", L"cfg");
        require(kind == L"cfg" || kind == L"call" || kind == L"function-calls", "Unknown graph kind");
        result.graph_kind = kind == L"cfg" ? GraphKind::function_cfg
                            : kind == L"call" ? GraphKind::image_calls
                                               : GraphKind::function_calls;
        if (kind == L"cfg" || kind == L"function-calls")
            result.at_expression = address(typed_location(options.needed(L"--at")));
        if (kind == L"function-calls") {
            const auto depth = options.count(L"--depth", 1);
            require(depth >= 1 && depth <= 4, "Function-call graph depth must be 1..4");
            result.graph_options.call_depth = static_cast<std::size_t>(depth);
        }
        auto format = options.pop(L"--format", L"json");
        require(format == L"json" || format == L"dot", "Unknown graph format");
        result.dot = format == L"dot";
        const auto node_budget = options.count(L"--node-budget", 1000);
        const auto edge_budget = options.count(L"--edge-budget", 10000);
        require(node_budget <= 1000000, "Graph node budget must be at most 1000000");
        require(edge_budget <= 4000000, "Graph edge budget must be at most 4000000");
        result.graph_options.node_budget = static_cast<std::size_t>(node_budget);
        result.graph_options.edge_budget = static_cast<std::size_t>(edge_budget);
    } else if (result.action == L"search") {
        auto kind = options.needed(L"--kind");
        if (kind == L"bytes")
            result.query = BytePattern{utf8(options.needed(L"--pattern"))};
        else if (kind == L"text") {
            auto encoding = options.needed(L"--encoding");
            require(encoding == L"ascii" || encoding == L"utf8" || encoding == L"utf16le" || encoding == L"utf16be" ||
                        encoding == L"utf32le" || encoding == L"utf32be", "Unknown text encoding");
            const auto text_encoding = encoding == L"ascii"   ? TextEncoding::ascii
                                       : encoding == L"utf8"    ? TextEncoding::utf8
                                       : encoding == L"utf16le" ? TextEncoding::utf16le
                                       : encoding == L"utf16be" ? TextEncoding::utf16be
                                       : encoding == L"utf32le" ? TextEncoding::utf32le : TextEncoding::utf32be;
            result.query = TextQuery{utf8(options.needed(L"--text")), text_encoding};
        } else if (kind == L"immediate") {
            auto width = number(options.needed(L"--width"));
            require(width <= 64, "Immediate width exceeds 64");
            bool signed_value = options.flag(L"--signed"), unsigned_value = options.flag(L"--unsigned");
            require(!(signed_value && unsigned_value), "Choose signed or unsigned immediate interpretation");
            result.query = ImmediateQuery{utf8(options.needed(L"--value")), uint16_t(width),
                                          signed_value ? ImmediateInterpretation::signed_value
                                                       : ImmediateInterpretation::unsigned_value};
        } else
            require(false, "Unknown search kind");
        auto fingerprint = take(search_query_fingerprint(*result.query));
        result.search_limits.max_results = std::size_t(options.count(L"--limit", 256));
        result.search_limits.max_candidates = options.count(L"--candidate-budget", 1048576);
        if (options.contains(L"--cursor")) {
            result.cursor = parse_cursor(options.pop(L"--cursor"));
            require(result.cursor->query_fingerprint == fingerprint, "Continuation belongs to another query");
        }
    } else if (result.action == L"signatures" || result.action == L"signature-apply") {
        result.signature_function_entries = options.flag(L"--function-entries");
        require(result.action != L"signature-apply" || !result.signature_function_entries,
                "signature-apply always targets recovered function entries");
        result.signature_definitions = path_from_wide(options.needed(L"--definitions"));
        result.signature_limits.max_results = std::size_t(options.count(L"--limit", 4096));
        result.signature_limits.max_candidates = options.count(L"--candidate-budget", 16777216);
        result.signature_limits.max_comparisons = options.count(L"--comparison-budget", 67108864);
    } else if (result.action == L"signature-create") {
        result.at_expression = address(typed_location(options.needed(L"--at")));
        result.signature_name = utf8(options.needed(L"--name"));
        result.signature_provenance = utf8(options.needed(L"--provenance"));
        result.function_signature_options.max_bytes = std::size_t(options.count(L"--max-bytes", 128));
        result.function_signature_options.min_exact_bytes = std::size_t(options.count(L"--min-exact-bytes", 8));
    } else if (result.action == L"flirt" || result.action == L"flirt-apply") {
        require(result.action != L"flirt-apply" || !result.readonly,
                "flirt-apply cannot be used with --readonly");
        result.flirt_rename_unique = options.flag(L"--rename-unique");
        require(!result.flirt_rename_unique || result.action == L"flirt-apply",
                "--rename-unique requires flirt-apply");
        const bool has_definitions = options.contains(L"--definitions");
        const bool has_list = options.contains(L"--definitions-list");
        require(has_definitions != has_list,
                "Specify exactly one of --definitions or --definitions-list");
        if (has_list)
            result.flirt_definitions_list = path_from_wide(options.needed(L"--definitions-list"));
        else
            result.flirt_definitions = path_from_wide(options.needed(L"--definitions"));
        result.flirt_provenance = utf8(options.needed(L"--provenance"));
        const auto catalog_byte_budget = options.count(L"--catalog-byte-budget", 64ull * 1024 * 1024);
        const auto pattern_budget = options.count(L"--pattern-budget", 65536);
        require(catalog_byte_budget > 0 && catalog_byte_budget <= 64ull * 1024 * 1024,
                "FLAIR catalog byte budget must be 1..67108864");
        require(pattern_budget > 0 && pattern_budget <= 65536,
                "FLAIR pattern budget must be 1..65536");
        result.flirt_catalog_limits.max_bytes = static_cast<std::size_t>(catalog_byte_budget);
        result.flirt_catalog_limits.max_patterns = static_cast<std::size_t>(pattern_budget);
        const auto function_budget = options.count(L"--function-budget", 100000);
        const auto result_budget = options.count(L"--result-budget", 100000);
        require(function_budget > 0 && function_budget <= 1000000,
                "FLAIR function budget must be 1..1000000");
        require(result_budget > 0 && result_budget <= 1000000,
                "FLAIR result budget must be 1..1000000");
        result.flirt_limits.max_functions = static_cast<std::size_t>(function_budget);
        result.flirt_limits.max_patterns = static_cast<std::size_t>(pattern_budget);
        const auto candidate_budget = options.count(L"--candidate-budget", 16777216);
        const auto comparison_budget = options.count(L"--comparison-budget", 67108864);
        const auto reference_budget = options.count(L"--reference-budget", 16777216);
        require(candidate_budget > 0 && candidate_budget <= 67108864,
                "FLAIR candidate budget must be 1..67108864");
        require(comparison_budget > 0 && comparison_budget <= 268435456,
                "FLAIR comparison budget must be 1..268435456");
        require(reference_budget > 0 && reference_budget <= 67108864,
                "FLAIR reference budget must be 1..67108864");
        result.flirt_limits.max_pattern_candidates = candidate_budget;
        result.flirt_limits.max_comparisons = comparison_budget;
        result.flirt_limits.max_reference_checks = reference_budget;
        result.flirt_limits.max_results = static_cast<std::size_t>(result_budget);
    } else if (result.action == L"fingerprints") {
        result.fingerprint_definitions = path_from_wide(options.needed(L"--definitions"));
        result.fingerprint_limits.max_functions = std::size_t(options.count(L"--function-budget", 100000));
        result.fingerprint_limits.max_instructions = options.count(L"--instruction-budget", 4000000);
        result.fingerprint_limits.max_token_bytes = options.count(L"--token-budget", 256ull * 1024 * 1024);
        result.fingerprint_limits.per_function.max_instructions =
            std::size_t(options.count(L"--max-instructions", 512));
        result.fingerprint_limits.per_function.max_blocks = std::size_t(options.count(L"--max-blocks", 1024));
        result.fingerprint_limits.per_function.max_token_bytes =
            std::size_t(options.count(L"--per-function-token-budget", 1024 * 1024));
    } else if (result.action == L"fingerprint-create") {
        result.at_expression = address(typed_location(options.needed(L"--at")));
        result.signature_name = utf8(options.needed(L"--name"));
        result.signature_provenance = utf8(options.needed(L"--provenance"));
        result.fingerprint_options.max_instructions = std::size_t(options.count(L"--max-instructions", 512));
        result.fingerprint_options.max_blocks = std::size_t(options.count(L"--max-blocks", 1024));
        result.fingerprint_options.max_token_bytes = std::size_t(options.count(L"--token-budget", 1024 * 1024));
    } else if (result.action == L"recognition-evidence") {
        const auto kind = options.needed(L"--kind");
        require(kind == L"signatures" || kind == L"fingerprints" || kind == L"flirt",
                "Recognition evidence kind must be signatures, fingerprints, or flirt");
        result.recognition_kind = kind == L"signatures" ? FunctionRecognitionKind::byte_signatures
                                : kind == L"fingerprints" ? FunctionRecognitionKind::normalized_fingerprints
                                                           : FunctionRecognitionKind::flirt_patterns;
    } else
        require(result.action == L"history-audit" || result.action == L"history-preview" || result.action == L"recovery-list" || result.action == L"recovery-restore" || result.action == L"backup" || result.action == L"backup-restore" || result.action == L"exchange-export" || result.action == L"exchange-import" || result.action == L"inspect" || result.action == L"functions" || result.action == L"methods" || result.action == L"managed-types" || result.action == L"fields" || result.action == L"stack" || result.action == L"undo" ||
                    result.action == L"redo" || result.action == L"save",
                "Unknown project action");
    require(options.values.empty(),
            options.values.empty() ? "" : "Unknown or inapplicable option " + utf8(options.values.begin()->first));
    return result;
}
} // namespace hexlab::cli::project_detail

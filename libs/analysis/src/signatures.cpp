#include "hexlab/analysis/signatures.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <map>
#include <set>
#include <sstream>
#include <type_traits>

namespace hexlab {
namespace {
struct Failure { Error error; };
void require(bool ok, std::string message, ErrorCode code = ErrorCode::invalid_argument) {
    if (!ok) throw Failure{{code, std::move(message)}};
}
void canceled(std::stop_token stop) { require(!stop.stop_requested(), "Signature scan canceled", ErrorCode::canceled); }
std::string_view architecture_name(Architecture value) {
    switch (value) {
    case Architecture::x86: return "x86"; case Architecture::x86_64: return "x86_64";
    case Architecture::arm: return "arm"; case Architecture::arm64: return "arm64";
    case Architecture::riscv64: return "riscv64"; case Architecture::riscv32: return "riscv32";
    case Architecture::mips32: return "mips32"; case Architecture::mips64: return "mips64";
    case Architecture::mos6502: return "mos6502"; case Architecture::powerpc: return "powerpc";
    case Architecture::wasm: return "wasm"; case Architecture::dex: return "dex"; case Architecture::jvm: return "jvm";
    default: return "unknown";
    }
}
std::string_view mode_name(ExecutionMode value) {
    switch (value) {
    case ExecutionMode::x86_16: return "x86_16"; case ExecutionMode::x86_32: return "x86_32";
    case ExecutionMode::x86_64: return "x86_64"; case ExecutionMode::a32: return "a32";
    case ExecutionMode::thumb: return "thumb"; case ExecutionMode::a64: return "a64";
    case ExecutionMode::rv64: return "rv64"; case ExecutionMode::rv64c: return "rv64c";
    case ExecutionMode::rv32: return "rv32"; case ExecutionMode::mips32: return "mips32";
    case ExecutionMode::mips64: return "mips64"; case ExecutionMode::m6502: return "m6502";
    case ExecutionMode::ppc32: return "ppc32"; case ExecutionMode::ppc64: return "ppc64";
    default: return "unknown";
    }
}
Architecture parse_architecture(std::string_view value) {
    for (const auto candidate : {Architecture::x86, Architecture::x86_64, Architecture::arm,
             Architecture::arm64, Architecture::riscv64, Architecture::riscv32, Architecture::mips32,
             Architecture::mips64, Architecture::mos6502, Architecture::powerpc, Architecture::wasm, Architecture::dex, Architecture::jvm})
        if (architecture_name(candidate) == value) return candidate;
    return Architecture::unknown;
}
ExecutionMode parse_mode(std::string_view value) {
    for (const auto candidate : {ExecutionMode::x86_16, ExecutionMode::x86_32, ExecutionMode::x86_64,
             ExecutionMode::a32, ExecutionMode::thumb, ExecutionMode::a64, ExecutionMode::rv64,
             ExecutionMode::rv64c, ExecutionMode::rv32, ExecutionMode::mips32, ExecutionMode::mips64,
             ExecutionMode::m6502, ExecutionMode::ppc32, ExecutionMode::ppc64})
        if (mode_name(candidate) == value) return candidate;
    return ExecutionMode::unknown;
}
template<class F> auto guarded(F f) -> decltype(f()) {
    try { return f(); }
    catch (const Failure &e) { return e.error; }
    catch (const std::bad_alloc &) { return Error{ErrorCode::resource_limit, "Signature allocation limit"}; }
    catch (const std::length_error &) { return Error{ErrorCode::resource_limit, "Signature allocation limit"}; }
}
int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
std::vector<SignatureByte> parse_pattern(std::string_view text) {
    std::istringstream input{std::string(text)};
    std::string token;
    std::vector<SignatureByte> result;
    bool anchored = false;
    while (input >> token) {
        require(token.size() == 2, "Signature pattern tokens must be two characters");
        unsigned value = 0, mask = 0;
        for (std::size_t i = 0; i < 2; ++i) {
            const auto shift = unsigned((1 - i) * 4);
            if (token[i] == '?') continue;
            const auto digit = nibble(token[i]);
            require(digit >= 0, "Signature pattern contains a non-hex digit");
            value |= unsigned(digit) << shift;
            mask |= 0x0f << shift;
        }
        anchored |= mask == 0xff;
        result.push_back({std::byte(value), std::byte(mask)});
        require(result.size() <= 256, "Signature pattern exceeds 256 bytes", ErrorCode::resource_limit);
    }
    require(!result.empty(), "Signature pattern is empty");
    require(anchored, "Signature pattern requires at least one exact byte");
    return result;
}
struct Reader {
    const ByteStorage &source;
    std::uint64_t start = UINT64_MAX;
    ByteView view;
    std::byte at(std::uint64_t offset) {
        if (!view.owner || offset < start || offset - start >= view.bytes.size()) {
            start = (offset / 65536) * 65536;
            const auto count = std::size_t(std::min<std::uint64_t>(65536, source.size() - start));
            auto loaded = source.read_at({start}, count);
            require(bool(loaded), loaded ? "" : loaded.error().message, ErrorCode::io);
            require(loaded.value().bytes.size() == count, "Short read inside executable range", ErrorCode::io);
            view = std::move(loaded.value());
        }
        return view.bytes[std::size_t(offset - start)];
    }
};
bool matches(Reader &reader, std::uint64_t offset, const std::vector<SignatureByte> &pattern,
             std::uint64_t &comparisons, const SignatureLimits &limits, std::stop_token stop) {
    for (std::size_t n = 0; n < pattern.size(); ++n) {
        if ((n & 63u) == 0) canceled(stop);
        require(comparisons < limits.max_comparisons, "Signature comparison budget reached", ErrorCode::resource_limit);
        ++comparisons;
        if ((std::to_integer<unsigned>(reader.at(offset + n)) & std::to_integer<unsigned>(pattern[n].mask)) !=
            (std::to_integer<unsigned>(pattern[n].value) & std::to_integer<unsigned>(pattern[n].mask))) return false;
    }
    return true;
}
struct FlattenedSignatureCatalogs {
    std::vector<SignatureDefinition> definitions;
    std::vector<std::size_t> catalog_indices;
};
Result<FlattenedSignatureCatalogs> flatten_catalogs(const Image &image, const SignatureCatalogSet &set) {
    return guarded([&]() -> Result<FlattenedSignatureCatalogs> {
        require(!set.catalogs.empty() && set.catalogs.size() <= 256,
                "Signature catalog set must contain 1..256 catalogs", ErrorCode::resource_limit);
        FlattenedSignatureCatalogs flattened;
        std::size_t total = 0;
        for (std::size_t catalog_index = 0; catalog_index < set.catalogs.size(); ++catalog_index) {
            const auto &catalog = set.catalogs[catalog_index];
            require(catalog.format_version == 1 || catalog.format_version == 2,
                    "Unsupported signature catalog version");
            if (catalog.format_version == 1)
                require(catalog.target_architecture == Architecture::unknown &&
                            catalog.target_mode == ExecutionMode::unknown,
                        "Version 1 signature catalogs cannot carry target metadata");
            else {
                require(catalog.target_architecture != Architecture::unknown &&
                            catalog.target_mode != ExecutionMode::unknown,
                        "Version 2 signature catalogs require a known architecture and mode");
                require(catalog.target_architecture == image.layout().architecture &&
                            catalog.target_mode == image.layout().mode,
                        "Signature catalog target does not match image architecture and mode");
            }
            require(catalog.definitions.size() <= 4096 - total,
                    "Composed signature catalogs exceed 4096 definitions", ErrorCode::resource_limit);
            for (const auto &definition : catalog.definitions) {
                require(definition.name.size() <= 128 && definition.provenance.size() <= 256 &&
                            definition.pattern.size() <= 256 && definition.exclusions.size() <= 16,
                        "Composed signature definition exceeds its metadata limits", ErrorCode::resource_limit);
                for (const auto &exclusion : definition.exclusions)
                    require(exclusion.size() <= 256, "Composed signature exclusion exceeds its size limit",
                            ErrorCode::resource_limit);
            }
            total += catalog.definitions.size();
        }
        require(total != 0, "Signature catalog set contains no definitions");
        flattened.definitions.reserve(total);
        flattened.catalog_indices.reserve(total);
        for (std::size_t catalog_index = 0; catalog_index < set.catalogs.size(); ++catalog_index) {
            const auto &definitions = set.catalogs[catalog_index].definitions;
            flattened.definitions.insert(flattened.definitions.end(), definitions.begin(), definitions.end());
            flattened.catalog_indices.insert(flattened.catalog_indices.end(), definitions.size(), catalog_index);
        }
        return flattened;
    });
}
}

Result<std::vector<SignatureDefinition>> parse_signature_definitions(std::string_view text) {
    return guarded([&]() -> Result<std::vector<SignatureDefinition>> {
        require(text.size() <= 1024 * 1024, "Signature definitions exceed 1 MiB", ErrorCode::resource_limit);
        std::vector<SignatureDefinition> result;
        std::set<std::string> names;
        std::size_t line_number = 0;
        while (!text.empty()) {
            ++line_number;
            auto end = text.find('\n');
            auto line = text.substr(0, end);
            if (end == text.npos) text = {}; else text.remove_prefix(end + 1);
            if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
            while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.remove_prefix(1);
            if (line.empty() || line.front() == '#') continue;
            auto error_prefix = "Signature line " + std::to_string(line_number) + ": ";
            std::array<std::string_view, 4> fields{};
            for (std::size_t i = 0; i < 3; ++i) {
                auto sep = line.find('|');
                require(sep != line.npos, error_prefix + "expected four pipe-separated fields");
                fields[i] = line.substr(0, sep);
                line.remove_prefix(sep + 1);
            }
            require(line.find('|') == line.npos, error_prefix + "too many fields");
            fields[3] = line;
            require(!fields[0].empty() && fields[0].size() <= 128, error_prefix + "name must be 1..128 bytes");
            require(!fields[1].empty() && fields[1].size() <= 256, error_prefix + "provenance must be 1..256 bytes");
            require(fields[0].find_first_of("\r\n") == fields[0].npos && fields[1].find_first_of("\r\n") == fields[1].npos,
                    error_prefix + "invalid metadata");
            SignatureDefinition definition{std::string(fields[0]), std::string(fields[1]), parse_pattern(fields[2]), {}};
            require(names.insert(definition.name).second, error_prefix + "duplicate signature name");
            if (!fields[3].empty()) {
                auto negatives = fields[3];
                for (;;) {
                    auto sep = negatives.find(';');
                    auto pattern = negatives.substr(0, sep);
                    require(!pattern.empty(), error_prefix + "empty exclusion pattern");
                    definition.exclusions.push_back(parse_pattern(pattern));
                    require(definition.exclusions.size() <= 16, error_prefix + "more than 16 exclusions", ErrorCode::resource_limit);
                    if (sep == negatives.npos) break;
                    negatives.remove_prefix(sep + 1);
                }
            }
            result.push_back(std::move(definition));
            require(result.size() <= 4096, "More than 4096 signature definitions", ErrorCode::resource_limit);
        }
        require(!result.empty(), "No signature definitions found");
        return result;
    });
}

Result<SignatureCatalog> parse_signature_catalog(std::string_view text) {
    return guarded([&]() -> Result<SignatureCatalog> {
        constexpr std::string_view header_v1 = "# HexLab signature catalog v1";
        constexpr std::string_view header_v2 = "# HexLab signature catalog v2";
        require(text.size() <= 1024 * 1024, "Signature catalog exceeds 1 MiB", ErrorCode::resource_limit);
        auto first = text;
        while (!first.empty() && (first.front() == '\r' || first.front() == '\n' || first.front() == ' ' || first.front() == '\t'))
            first.remove_prefix(1);
        const auto end = first.find('\n');
        auto line = first.substr(0, end == first.npos ? first.size() : end);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        std::string_view body = text;
        std::uint32_t version = 1;
        Architecture target_architecture = Architecture::unknown;
        ExecutionMode target_mode = ExecutionMode::unknown;
        if (line.starts_with("# HexLab signature catalog v")) {
            require(line == header_v1 || line == header_v2, "Unsupported signature catalog version");
            version = line == header_v2 ? 2u : 1u;
            body = end == first.npos ? std::string_view{} : first.substr(end + 1);
            if (version == 2) {
                const auto metadata_end = body.find('\n');
                auto metadata = body.substr(0, metadata_end == body.npos ? body.size() : metadata_end);
                if (!metadata.empty() && metadata.back() == '\r') metadata.remove_suffix(1);
                constexpr std::string_view prefix = "# target: ";
                require(metadata.starts_with(prefix), "Version 2 signature catalog requires target metadata");
                metadata.remove_prefix(prefix.size());
                const auto slash = metadata.find('/');
                require(slash != metadata.npos && metadata.find('/', slash + 1) == metadata.npos,
                        "Malformed signature target metadata");
                target_architecture = parse_architecture(metadata.substr(0, slash));
                target_mode = parse_mode(metadata.substr(slash + 1));
                require(target_architecture != Architecture::unknown && target_mode != ExecutionMode::unknown,
                        "Unknown signature target architecture or mode");
                body = metadata_end == body.npos ? std::string_view{} : body.substr(metadata_end + 1);
            }
        }
        auto definitions = parse_signature_definitions(body);
        require(bool(definitions), definitions ? "" : definitions.error().message);
        return SignatureCatalog{version, std::move(definitions.value()), target_architecture, target_mode};
    });
}

Result<std::string> serialize_signature_catalog(const SignatureCatalog &catalog) {
    return guarded([&]() -> Result<std::string> {
        require(catalog.format_version == 1 || catalog.format_version == 2, "Unsupported signature catalog version");
        if (catalog.format_version == 1)
            require(catalog.target_architecture == Architecture::unknown && catalog.target_mode == ExecutionMode::unknown,
                    "Version 1 signature catalogs cannot carry target metadata");
        else
            require(architecture_name(catalog.target_architecture) != "unknown" &&
                        mode_name(catalog.target_mode) != "unknown",
                    "Version 2 signature catalogs require a known architecture and mode");
        auto definitions = serialize_signature_definitions(catalog.definitions);
        require(bool(definitions), definitions ? "" : definitions.error().message);
        std::string output = catalog.format_version == 1 ? "# HexLab signature catalog v1\n"
                                                         : "# HexLab signature catalog v2\n# target: ";
        if (catalog.format_version == 2)
            output += std::string(architecture_name(catalog.target_architecture)) + "/" +
                      std::string(mode_name(catalog.target_mode)) + "\n";
        output += definitions.value();
        require(output.size() <= 1024 * 1024, "Signature catalog exceeds 1 MiB", ErrorCode::resource_limit);
        return output;
    });
}

Result<SignatureScan> scan_executable_signatures(const Image &image, const ByteStorage &bytes,
                                                  std::span<const SignatureDefinition> definitions,
                                                  const SignatureLimits &limits, std::stop_token stop) {
    return guarded([&]() -> Result<SignatureScan> {
        canceled(stop);
        require(bytes.size() == image.storage()->size(), "Signature source extent does not match image");
        require(!definitions.empty() && definitions.size() <= 4096, "Signature definition count is outside 1..4096",
                ErrorCode::resource_limit);
        std::vector<std::pair<std::uint32_t, std::uint32_t>> specificity;
        specificity.reserve(definitions.size());
        for (const auto &definition : definitions) {
            require(!definition.name.empty() && definition.name.size() <= 128 && !definition.provenance.empty() &&
                        definition.provenance.size() <= 256 && !definition.pattern.empty() &&
                        definition.pattern.size() <= 256 && definition.exclusions.size() <= 16,
                    "Invalid signature definition", ErrorCode::invalid_argument);
            const auto anchored = std::any_of(definition.pattern.begin(), definition.pattern.end(),
                                              [](const auto &b) { return b.mask == std::byte{0xff}; });
            require(anchored, "Signature pattern requires at least one exact byte");
            for (const auto &negative : definition.exclusions)
                require(!negative.empty() && negative.size() <= 256, "Invalid signature exclusion");
            std::uint32_t constrained_bits = 0;
            for (const auto &byte : definition.pattern)
                constrained_bits += std::popcount(std::to_integer<unsigned>(byte.mask));
            specificity.emplace_back(constrained_bits, static_cast<std::uint32_t>(definition.pattern.size()));
        }
        require(limits.max_results && limits.max_results <= 100000 && limits.max_candidates &&
                    limits.max_candidates <= 16777216 && limits.max_comparisons && limits.max_comparisons <= 67108864 &&
                    limits.max_scanned_bytes && limits.max_scanned_bytes <= 268435456,
                "Signature scan limits exceed supported bounds", ErrorCode::resource_limit);
        SignatureScan scan;
        std::uint64_t scanned_bytes = 0;
        Reader reader{bytes};
        const auto &segments = image.layout().segments;
        require(segments.size() <= 1000000, "Too many image segments", ErrorCode::resource_limit);
        struct Anchor {
            std::size_t definition = 0;
            std::size_t pattern_offset = 0;
            std::size_t length = 0;
        };
        for (const auto &segment : segments) {
            canceled(stop);
            if (!segment.executable || segment.file_size == 0) continue;
            require(segment.file_begin.value <= bytes.size() && segment.file_size <= bytes.size() - segment.file_begin.value,
                    "Executable segment exceeds source extent", ErrorCode::integrity);
            std::map<unsigned, std::vector<Anchor>> anchors;
            for (std::size_t d = 0; d < definitions.size(); ++d) {
                const auto &pattern = definitions[d].pattern;
                if (pattern.size() > segment.file_size) continue;
                std::size_t best_start = 0, best_length = 0;
                for (std::size_t i = 0; i < pattern.size();) {
                    if (pattern[i].mask != std::byte{0xff}) { ++i; continue; }
                    const auto start = i;
                    while (i < pattern.size() && pattern[i].mask == std::byte{0xff}) ++i;
                    if (i - start > best_length) { best_start = start; best_length = i - start; }
                }
                require(best_length != 0, "Signature pattern requires at least one exact byte");
                anchors[std::to_integer<unsigned>(pattern[best_start].value)].push_back({d, best_start, best_length});
            }

            // First index signatures by the leading byte of their longest exact run. Only
            // positions passing that anchor enter full-pattern verification.
            std::vector<std::vector<std::uint64_t>> candidates(definitions.size());
            for (std::uint64_t delta = 0; delta < segment.file_size; ++delta) {
                canceled(stop);
                require(scanned_bytes < limits.max_scanned_bytes, "Signature indexed-byte budget reached", ErrorCode::resource_limit);
                ++scanned_bytes;
                const auto found = anchors.find(std::to_integer<unsigned>(reader.at(segment.file_begin.value + delta)));
                if (found == anchors.end()) continue;
                for (const auto &anchor : found->second) {
                    if (anchor.pattern_offset > delta || anchor.length > segment.file_size - delta) continue;
                    const auto start = delta - anchor.pattern_offset;
                    const auto width = definitions[anchor.definition].pattern.size();
                    if (width > segment.file_size - start) continue;
                    bool anchor_matches = true;
                    for (std::size_t n = 0; n < anchor.length; ++n) {
                        canceled(stop);
                        require(scan.comparisons < limits.max_comparisons,
                                "Signature comparison budget reached", ErrorCode::resource_limit);
                        ++scan.comparisons;
                        if (reader.at(segment.file_begin.value + delta + n) !=
                            definitions[anchor.definition].pattern[anchor.pattern_offset + n].value) {
                            anchor_matches = false;
                            break;
                        }
                    }
                    if (!anchor_matches) continue;
                    require(scan.candidates < limits.max_candidates, "Signature candidate budget reached", ErrorCode::resource_limit);
                    ++scan.candidates;
                    candidates[anchor.definition].push_back(start);
                }
            }

            for (std::size_t d = 0; d < definitions.size(); ++d) {
                const auto &definition = definitions[d];
                for (const auto delta : candidates[d]) {
                    canceled(stop);
                    const auto file = segment.file_begin.value + delta;
                    if (!matches(reader, file, definition.pattern, scan.comparisons, limits, stop)) continue;
                    bool excluded = false;
                    for (const auto &negative : definition.exclusions) {
                        if (negative.size() <= segment.file_size - delta &&
                            matches(reader, file, negative, scan.comparisons, limits, stop)) {
                            excluded = true;
                            break;
                        }
                    }
                    if (excluded) continue;
                    require(scan.matches.size() < limits.max_results, "Signature result limit reached", ErrorCode::resource_limit);
                    require(delta <= UINT64_MAX - segment.begin.offset, "Executable address overflows", ErrorCode::integrity);
                    scan.matches.push_back({definition.name, definition.provenance, {file},
                                            {segment.begin.space, segment.begin.offset + delta}, d,
                                            specificity[d].first, specificity[d].second});
                }
            }
        }
        return scan;
    });
}

Result<SignatureScan> scan_executable_signatures(const Image &image, const ByteStorage &bytes,
        const SignatureCatalog &catalog, const SignatureLimits &limits, std::stop_token stop) {
    if (catalog.format_version != 1 && catalog.format_version != 2)
        return Error{ErrorCode::invalid_argument, "Unsupported signature catalog version"};
    if (catalog.format_version == 2 &&
        (catalog.target_architecture != image.layout().architecture || catalog.target_mode != image.layout().mode))
        return Error{ErrorCode::invalid_argument, "Signature catalog target does not match image architecture and mode"};
    return scan_executable_signatures(image, bytes, catalog.definitions, limits, stop);
}

Result<SignatureScan> scan_executable_signatures(const Image &image, const ByteStorage &bytes,
        const SignatureCatalogSet &catalogs, const SignatureLimits &limits, std::stop_token stop) {
    auto flattened = flatten_catalogs(image, catalogs);
    if (!flattened) return flattened.error();
    auto scanned = scan_executable_signatures(image, bytes, flattened.value().definitions, limits, stop);
    if (!scanned) return scanned.error();
    for (auto &match : scanned.value().matches) {
        if (match.definition_index >= flattened.value().catalog_indices.size())
            return Error{ErrorCode::integrity, "Signature scan returned an invalid definition index"};
        match.catalog_index = flattened.value().catalog_indices[match.definition_index];
    }
    return scanned;
}

Result<std::string> serialize_signature_definitions(std::span<const SignatureDefinition> definitions) {
    return guarded([&]() -> Result<std::string> {
        require(!definitions.empty() && definitions.size() <= 4096, "Invalid signature definition count");
        std::string output;
        const auto pattern = [&](const std::vector<SignatureByte> &bytes) {
            require(!bytes.empty() && bytes.size() <= 256, "Invalid signature pattern extent");
            constexpr char digits[] = "0123456789ABCDEF";
            bool first = true;
            for (const auto &byte : bytes) {
                if (!first) output += ' ';
                first = false;
                const auto mask = std::to_integer<unsigned>(byte.mask);
                const auto value = std::to_integer<unsigned>(byte.value);
                require((mask == 0 || mask == 15 || mask == 240 || mask == 255) && (value & ~mask) == 0,
                        "Signature text requires canonical nibble masks");
                output += mask & 240 ? digits[value >> 4] : '?';
                output += mask & 15 ? digits[value & 15] : '?';
            }
        };
        for (const auto &definition : definitions) {
            require(definition.name.find_first_of("|\r\n") == std::string::npos &&
                        definition.provenance.find_first_of("|\r\n") == std::string::npos &&
                        !definition.name.empty() && definition.name.front() != '#' &&
                        definition.name.front() != ' ' && definition.name.front() != '\t' &&
                        definition.exclusions.size() <= 16,
                    "Signature metadata cannot be represented in definition text");
            output += definition.name + '|' + definition.provenance + '|';
            pattern(definition.pattern);
            output += '|';
            for (std::size_t n = 0; n < definition.exclusions.size(); ++n) {
                if (n) output += ';';
                pattern(definition.exclusions[n]);
            }
            output += '\n';
            require(output.size() <= 1024 * 1024, "Signature definitions exceed 1 MiB", ErrorCode::resource_limit);
        }
        auto parsed = parse_signature_definitions(output);
        require(bool(parsed), parsed ? "" : parsed.error().message);
        return output;
    });
}

Result<SignatureDefinition> create_function_signature(const Image &image, const ByteStorage &bytes,
        const FunctionRecord &function, const FunctionSnapshot &snapshot, std::string name,
        std::string provenance, const FunctionSignatureOptions &options, std::stop_token stop) {
    return guarded([&]() -> Result<SignatureDefinition> {
        canceled(stop);
        require(bytes.size() == image.storage()->size(), "Signature source extent does not match image");
        require(options.max_bytes && options.max_bytes <= 256 && options.min_exact_bytes &&
                    options.min_exact_bytes <= options.max_bytes, "Invalid function signature limits");
        require(function.blocks.size() <= 1000000 && snapshot.blocks.size() <= 1000000,
                "Function signature block budget exceeded", ErrorCode::resource_limit);
        std::shared_ptr<const BasicBlock> entry;
        for (const auto &block : snapshot.blocks) {
            canceled(stop);
            if (block && block->begin == function.entry &&
                std::find(function.blocks.begin(), function.blocks.end(), block->id) != function.blocks.end()) {
                require(!entry, "Ambiguous function entry block");
                entry = block;
            }
        }
        require(bool(entry), "Function entry block is unavailable");
        // Calls terminate recovered basic blocks. Retain their contiguous,
        // explicitly recovered continuation so normal prologue/call sequences
        // produce useful reusable prefixes rather than a wildcarded CALL alone.
        std::vector<std::shared_ptr<const InstructionFact>> prefix;
        std::set<std::uint64_t> visited;
        auto current = entry;
        while (current && prefix.size() < options.max_bytes) {
            canceled(stop);
            require(visited.insert(current->id.value).second, "Cyclic signature continuation");
            for (const auto &fact : current->instructions) {
                if (prefix.size() == options.max_bytes) break;
                prefix.push_back(fact);
            }
            if (current->instructions.empty() || !current->instructions.back()) break;
            const auto &last = current->instructions.back()->instruction;
            if ((last.flow != FlowKind::call && last.flow != FlowKind::fallthrough) ||
                last.length > UINT64_MAX - last.address.offset) break;
            const Address next{last.address.space, last.address.offset + last.length};
            bool continuation = false;
            for (const auto &edge : current->successors)
                if (edge.source == last.address && edge.target == next &&
                    (edge.kind == BlockEdgeKind::call_continuation || edge.kind == BlockEdgeKind::fallthrough))
                    continuation = true;
            if (!continuation) break;
            current.reset();
            for (const auto &block : snapshot.blocks) {
                canceled(stop);
                if (block && block->begin == next &&
                    std::find(function.blocks.begin(), function.blocks.end(), block->id) != function.blocks.end()) {
                    require(!current, "Ambiguous function continuation block");
                    current = block;
                }
            }
        }
        SignatureDefinition definition{std::move(name), std::move(provenance), {}, {}};
        Address expected = function.entry;
        std::optional<DecodeContext> context;
        for (const auto &fact : prefix) {
            canceled(stop);
            if (definition.pattern.size() == options.max_bytes) break;
            require(bool(fact), "Missing instruction fact in function signature");
            const auto &instruction = fact->instruction;
            require(instruction.address == expected && instruction.length &&
                        instruction.length == instruction.encoded_bytes().size(),
                    "Noncontiguous or invalid function instruction facts");
            require(instruction.context.architecture != Architecture::unknown &&
                        instruction.context.mode != ExecutionMode::unknown &&
                        !instruction.context.segmented_memory,
                    "Function signature extraction requires a known, nonsegmented decode context",
                    ErrorCode::unsupported);
            require(instruction.opcode != Opcode::x86_opaque && instruction.opcode != Opcode::opaque,
                    "Opaque instruction cannot establish a reusable signature", ErrorCode::unsupported);
            require(!context || *context == instruction.context, "Function signature changes decoding context");
            context = instruction.context;
            if (instruction.length > options.max_bytes - definition.pattern.size()) break;
            const auto *segment = image.segment_at(expected);
            require(segment && segment->executable && expected.offset >= segment->begin.offset &&
                        expected.offset - segment->begin.offset <= segment->file_size &&
                        instruction.length <= segment->file_size - (expected.offset - segment->begin.offset),
                    "Function signature instruction is not executable file-backed data");
            auto file = image.to_file_offset(expected);
            require(bool(file), "Function instruction has no file mapping");
            auto raw = bytes.read_at(file.value(), instruction.length);
            require(raw && raw.value().bytes.size() == instruction.length, "Cannot read function signature bytes", ErrorCode::io);
            require(std::equal(raw.value().bytes.begin(), raw.value().bytes.end(), instruction.encoded_bytes().begin()),
                    "Function instruction facts do not match effective bytes", ErrorCode::integrity);
            const auto decoded = decode_instruction(instruction.context, raw.value().bytes, instruction.address);
            require(decoded.status == DecodeStatus::decoded && decoded.instruction &&
                        decoded.instruction->length == instruction.length && decoded.instruction->opcode == instruction.opcode &&
                        decoded.instruction->flow == instruction.flow,
                    "Function instruction facts do not match decoding", ErrorCode::integrity);
            const auto base = definition.pattern.size();
            for (const auto byte : raw.value().bytes) definition.pattern.push_back({byte, std::byte{255}});
            const auto mask = [&](std::optional<EncodedField> field) {
                // Some decoders describe control-flow values but cannot yet
                // report the byte span of packed/scattered fields (for example
                // Thumb or AArch64 ADRP). Keep those bytes exact. The resulting
                // pattern is less relocatable, but it does not invent a mask.
                if (!field) return;
                require(field->size && field->offset < instruction.length &&
                            field->size <= instruction.length - field->offset,
                        "Address operand has invalid encoding metadata");
                if (field->offset == 0 && field->size == instruction.length)
                    return; // The byte span also contains the opcode; keep it exact.
                for (unsigned n = 0; n < field->size; ++n) definition.pattern[base + field->offset + n] = {};
            };
            for (const auto &operand : decoded.instruction->operands) {
                if (const auto *relative = std::get_if<RelativeOperand>(&operand)) mask(relative->encoding);
                if (const auto *memory = std::get_if<MemoryOperand>(&operand)) {
                    require(!memory->segment, "Segmented address operand is unsupported", ErrorCode::unsupported);
                    if (memory->ip_relative || memory->resolved_address || (!memory->base && memory->displacement))
                        mask(memory->displacement_encoding);
                }
                require(!std::holds_alternative<FarPointerOperand>(operand) &&
                            !std::holds_alternative<FarMemoryOperand>(operand),
                        "Far address operand is unsupported", ErrorCode::unsupported);
            }
            require(instruction.length <= UINT64_MAX - expected.offset, "Function signature address overflows");
            expected.offset += instruction.length;
            if (instruction.flow != FlowKind::fallthrough && instruction.flow != FlowKind::call) break;
        }
        const auto exact = std::count_if(definition.pattern.begin(), definition.pattern.end(),
                                         [](const auto &byte) { return byte.mask == std::byte{255}; });
        require(static_cast<std::size_t>(exact) >= options.min_exact_bytes,
                "Function signature has insufficient exact-byte evidence");
        const std::array<SignatureDefinition, 1> validation{definition};
        auto text = serialize_signature_definitions(validation);
        require(bool(text), text ? "" : text.error().message);
        return definition;
    });
}

Result<FunctionSignatureRecognition> recognize_function_signatures(const Image &image, const ByteStorage &bytes,
        const FunctionSnapshot &snapshot, std::span<const SignatureDefinition> definitions,
        const SignatureLimits &limits, std::stop_token stop) {
    return guarded([&]() -> Result<FunctionSignatureRecognition> {
        canceled(stop);
        require(snapshot.functions.size() <= 1000000, "Function recognition budget exceeded", ErrorCode::resource_limit);
        auto scanned = scan_executable_signatures(image, bytes, definitions, limits, stop);
        if (!scanned) return scanned.error();
        const auto key = [](Address address) { return std::pair{address.space.value, address.offset}; };
        std::map<std::pair<std::uint32_t, std::uint64_t>, std::vector<SignatureMatch>> entries;
        for (const auto &function : snapshot.functions) {
            canceled(stop);
            require(bool(function), "Missing function record");
            require(entries.emplace(key(function->entry), std::vector<SignatureMatch>{}).second,
                    "Ambiguous recovered function entry");
        }
        for (auto &match : scanned.value().matches) {
            canceled(stop);
            auto found = entries.find(key(match.address));
            if (found != entries.end()) found->second.push_back(std::move(match));
        }
        FunctionSignatureRecognition result;
        result.source_key=snapshot.key;
        result.complete = snapshot.complete && scanned.value().complete;
        result.candidates = scanned.value().candidates;
        result.comparisons = scanned.value().comparisons;
        for (const auto &function : snapshot.functions) {
            canceled(stop);
            result.complete = result.complete && function->complete;
            auto &matches = entries.at(key(function->entry));
            if (matches.empty()) continue;
            const bool ambiguous = matches.size() > 1;
            result.functions.push_back({function->id, function->entry, std::move(matches), ambiguous});
        }
        return result;
    });
}

Result<FunctionSignatureRecognition> recognize_function_signatures(const Image &image, const ByteStorage &bytes,
        const FunctionSnapshot &snapshot, const SignatureCatalog &catalog,
        const SignatureLimits &limits, std::stop_token stop) {
    if (catalog.format_version != 1 && catalog.format_version != 2)
        return Error{ErrorCode::invalid_argument, "Unsupported signature catalog version"};
    if (catalog.format_version == 2 &&
        (catalog.target_architecture != image.layout().architecture || catalog.target_mode != image.layout().mode))
        return Error{ErrorCode::invalid_argument, "Signature catalog target does not match image architecture and mode"};
    return recognize_function_signatures(image, bytes, snapshot, catalog.definitions, limits, stop);
}

Result<FunctionSignatureRecognition> recognize_function_signatures(const Image &image, const ByteStorage &bytes,
        const FunctionSnapshot &snapshot, const SignatureCatalogSet &catalogs,
        const SignatureLimits &limits, std::stop_token stop) {
    auto flattened = flatten_catalogs(image, catalogs);
    if (!flattened) return flattened.error();
    auto recognized = recognize_function_signatures(image, bytes, snapshot, flattened.value().definitions, limits, stop);
    if (!recognized) return recognized.error();
    for (auto &function : recognized.value().functions)
        for (auto &candidate : function.candidates) {
            if (candidate.definition_index >= flattened.value().catalog_indices.size())
                return Error{ErrorCode::integrity, "Function recognition returned an invalid definition index"};
            candidate.catalog_index = flattened.value().catalog_indices[candidate.definition_index];
        }
    return recognized;
}

namespace {
using AddressKey = std::pair<std::uint32_t, std::uint64_t>;
AddressKey address_key(Address address) { return {address.space.value, address.offset}; }

class TokenWriter {
  public:
    explicit TokenWriter(std::size_t limit) : limit_(limit) {}
    void u8(std::uint8_t value) { room(1); data_.push_back(std::byte(value)); }
    void u16(std::uint16_t value) { integer(value); }
    void u32(std::uint32_t value) { integer(value); }
    void u64(std::uint64_t value) { integer(value); }
    void text(std::string_view value) {
        require(value.size() <= UINT32_MAX, "Fingerprint token string is too long", ErrorCode::resource_limit);
        u32(static_cast<std::uint32_t>(value.size())); room(value.size());
        for (const unsigned char byte : value) data_.push_back(std::byte(byte));
    }
    const std::vector<std::byte> &data() const { return data_; }
  private:
    template<class T> void integer(T value) {
        using U = std::make_unsigned_t<T>;
        U bits = static_cast<U>(value);
        room(sizeof(T));
        for (std::size_t i = 0; i < sizeof(T); ++i) {
            data_.push_back(std::byte(bits & 0xffu));
            bits >>= 8;
        }
    }
    void room(std::size_t count) {
        require(count <= limit_ && data_.size() <= limit_ - count,
                "Function fingerprint token budget reached", ErrorCode::resource_limit);
    }
    std::size_t limit_;
    std::vector<std::byte> data_;
};

void token_register(TokenWriter &out, const RegisterOperand &reg) {
    out.u8(static_cast<std::uint8_t>(reg.bank)); out.u8(reg.index); out.u16(reg.width); out.u8(reg.high_byte);
}
void token_address(TokenWriter &out, Address address) {
    out.u32(address.space.value); out.u64(address.offset);
}
bool normalizable_field(const std::optional<EncodedField> &field, std::uint32_t instruction_length) {
    return field && field->size && field->offset > 0 && field->offset < instruction_length &&
           field->size <= instruction_length - field->offset;
}

struct FingerprintBlock {
    std::shared_ptr<const BasicBlock> block;
    std::uint32_t ordinal = 0;
};
struct FingerprintInstruction {
    std::shared_ptr<const InstructionFact> fact;
    std::uint32_t block_ordinal = 0;
    std::uint32_t instruction_ordinal = 0;
};

Result<std::pair<std::vector<std::byte>, std::uint32_t>> fingerprint_tokens(
        const Image &image, const ByteStorage &bytes, const FunctionRecord &function,
        const FunctionSnapshot &snapshot, const FunctionFingerprintOptions &options, std::stop_token stop) {
    return guarded([&]() -> Result<std::pair<std::vector<std::byte>, std::uint32_t>> {
        canceled(stop);
        require(options.max_instructions && options.max_instructions <= 2048 &&
                    options.max_blocks && options.max_blocks <= 4096 &&
                    options.max_token_bytes && options.max_token_bytes <= 4 * 1024 * 1024,
                "Function fingerprint limits exceed supported bounds", ErrorCode::resource_limit);
        require(bytes.size() == image.storage()->size(), "Fingerprint byte source does not match image");
        require(!function.blocks.empty() && function.blocks.size() <= options.max_blocks,
                "Function fingerprint block count is outside the selected bound", ErrorCode::resource_limit);
        std::map<BlockId, std::shared_ptr<const BasicBlock>> available_blocks;
        for (const auto &block : snapshot.blocks) {
            canceled(stop);
            if (block) available_blocks.emplace(block->id, block);
        }
        std::vector<FingerprintBlock> blocks;
        std::map<BlockId, std::uint32_t> block_ordinals;
        for (const auto id : function.blocks) {
            canceled(stop);
            const auto found = available_blocks.find(id);
            require(found != available_blocks.end(), "Function fingerprint block is unavailable");
            const auto ordinal = static_cast<std::uint32_t>(blocks.size());
            require(block_ordinals.emplace(id, ordinal).second, "Function fingerprint repeats a block");
            blocks.push_back({found->second, ordinal});
        }
        std::map<AddressKey, FingerprintInstruction> instructions;
        std::uint32_t instruction_count = 0;
        for (const auto &row : blocks) {
            canceled(stop);
            require(row.block->instructions.size() <= options.max_instructions - instruction_count,
                    "Function fingerprint instruction count exceeds its bound", ErrorCode::resource_limit);
            for (std::size_t index = 0; index < row.block->instructions.size(); ++index) {
                canceled(stop);
                const auto &fact = row.block->instructions[index];
                require(bool(fact), "Function fingerprint contains a missing instruction fact");
                const auto ordinal = static_cast<std::uint32_t>(index);
                require(instructions.emplace(address_key(fact->instruction.address),
                    FingerprintInstruction{fact, row.ordinal, ordinal}).second,
                    "Function fingerprint contains duplicate instruction addresses");
                ++instruction_count;
            }
        }
        require(instruction_count != 0, "Function fingerprint has no instructions");

        TokenWriter out(options.max_token_bytes);
        std::set<AddressKey> normalized_branch_sources;
        out.text("HexLab normalized function fingerprint v1");
        out.u8(static_cast<std::uint8_t>(image.layout().architecture));
        out.u8(static_cast<std::uint8_t>(image.layout().mode));
        out.u32(static_cast<std::uint32_t>(blocks.size()));
        out.u32(instruction_count);
        for (const auto &row : blocks) {
            canceled(stop);
            out.u8(0xb1); // Basic-block boundary.
            out.u32(row.ordinal);
            out.u32(static_cast<std::uint32_t>(row.block->instructions.size()));
            for (const auto &fact : row.block->instructions) {
                canceled(stop);
                const auto &instruction = fact->instruction;
                require(instruction.context.architecture != Architecture::unknown &&
                            instruction.context.mode != ExecutionMode::unknown && !instruction.context.segmented_memory,
                        "Fingerprint requires a known, nonsegmented instruction context", ErrorCode::unsupported);
                require(instruction.opcode != Opcode::opaque && instruction.opcode != Opcode::x86_opaque,
                        "Opaque instruction cannot establish a normalized fingerprint", ErrorCode::unsupported);
                require(instruction.length && instruction.length == instruction.encoded_bytes().size(),
                        "Fingerprint instruction has an invalid length", ErrorCode::integrity);
                const auto *segment = image.segment_at(instruction.address);
                require(segment && segment->executable && instruction.address.offset >= segment->begin.offset &&
                            instruction.address.offset - segment->begin.offset <= segment->file_size &&
                            instruction.length <= segment->file_size - (instruction.address.offset - segment->begin.offset),
                        "Fingerprint instruction is not executable file-backed data", ErrorCode::integrity);
                auto file = image.to_file_offset(instruction.address);
                require(bool(file), "Fingerprint instruction has no file mapping", ErrorCode::integrity);
                auto raw = bytes.read_at(file.value(), instruction.length);
                require(raw && raw.value().bytes.size() == instruction.length &&
                            std::equal(raw.value().bytes.begin(), raw.value().bytes.end(), instruction.encoded_bytes().begin()),
                        "Fingerprint instruction facts do not match effective bytes", ErrorCode::integrity);
                const auto decoded = decode_instruction(instruction.context, raw.value().bytes, instruction.address);
                require(decoded.status == DecodeStatus::decoded && decoded.instruction &&
                            decoded.instruction->length == instruction.length &&
                            decoded.instruction->opcode == instruction.opcode &&
                            decoded.instruction->flow == instruction.flow,
                        "Fingerprint instruction facts do not match decoding", ErrorCode::integrity);
                const auto &canonical = *decoded.instruction;

                out.u8(0x49); // Instruction token.
                out.u8(static_cast<std::uint8_t>(instruction.context.architecture));
                out.u8(static_cast<std::uint8_t>(instruction.context.mode));
                out.u8(static_cast<std::uint8_t>(instruction.context.order));
                out.u8(instruction.context.stack_address_width);
                out.u8(instruction.context.segmented_memory);
                out.u32(static_cast<std::uint32_t>(canonical.opcode));
                out.u8(static_cast<std::uint8_t>(canonical.flow));
                out.u8(canonical.condition);
                out.u8(canonical.x86_condition.has_value());
                if (canonical.x86_condition) out.u8(static_cast<std::uint8_t>(*canonical.x86_condition));
                out.u8(static_cast<std::uint8_t>(canonical.x86_repeat));
                out.u8(canonical.lock_prefix); out.u8(canonical.memory_read); out.u8(canonical.memory_write);
                out.u16(canonical.stack_value_width); out.u8(canonical.stack_slot_count);
                out.u8(static_cast<std::uint8_t>(canonical.x87_stack_delta)); out.u8(canonical.delay_slots);
                out.u8(canonical.atomic_aq); out.u8(canonical.atomic_rl);
                out.u8(canonical.csr_read); out.u8(canonical.csr_write);
                out.u8(canonical.rounding_mode.has_value());
                if (canonical.rounding_mode) out.u8(*canonical.rounding_mode);
                out.u8(canonical.writes_fflags);

                const auto &operands = canonical.operands;
                require(operands.size() <= 16, "Fingerprint instruction has too many operands", ErrorCode::resource_limit);
                if (canonical.direct_target && std::any_of(operands.begin(), operands.end(), [&](const Operand &operand) {
                        const auto *relative = std::get_if<RelativeOperand>(&operand);
                        return relative && normalizable_field(relative->encoding, canonical.length);
                    }))
                    normalized_branch_sources.insert(address_key(canonical.address));
                out.u8(static_cast<std::uint8_t>(operands.size()));
                for (const auto &operand : operands) {
                    canceled(stop);
                    out.u8(static_cast<std::uint8_t>(operand.index()));
                    std::visit([&](const auto &value) {
                        using T = std::decay_t<decltype(value)>;
                        if constexpr (std::is_same_v<T, RegisterOperand>) {
                            token_register(out, value);
                        } else if constexpr (std::is_same_v<T, ImmediateOperand>) {
                            out.u64(value.value); out.u16(value.encoded_width); out.u16(value.effective_width);
                            out.u8(value.is_signed);
                        } else if constexpr (std::is_same_v<T, RelativeOperand>) {
                            out.u16(value.effective_width);
                            if (normalizable_field(value.encoding, canonical.length) && canonical.direct_target.has_value()) {
                                out.u8(1); // Decoder proved a non-opcode relative field.
                                const auto target = canonical.direct_target;
                                if (target) {
                                    const auto destination = instructions.find(address_key(*target));
                                    if (destination != instructions.end()) {
                                        out.u8(1); out.u32(destination->second.block_ordinal);
                                        out.u32(destination->second.instruction_ordinal);
                                    } else out.u8(2); // Relocated external target; preserve only its role.
                                } else out.u8(0);
                            } else {
                                out.u8(0); out.u64(static_cast<std::uint64_t>(value.displacement));
                                out.u16(value.encoded_width);
                            }
                        } else if constexpr (std::is_same_v<T, MemoryOperand>) {
                            out.u16(value.data_width); out.u16(value.address_width);
                            out.u8(value.segment.has_value()); if (value.segment) token_register(out, *value.segment);
                            out.u8(value.base.has_value()); if (value.base) token_register(out, *value.base);
                            out.u8(value.index.has_value()); if (value.index) token_register(out, *value.index);
                            out.u8(value.scale); out.u8(value.ip_relative);
                            out.text(value.index_extend); out.u8(value.index_shift_amount);
                            const bool normalize = normalizable_field(value.displacement_encoding, canonical.length) &&
                                (value.ip_relative || value.resolved_address || (!value.base && value.displacement));
                            out.u8(normalize);
                            if (!normalize) out.u64(static_cast<std::uint64_t>(value.displacement));
                            out.u8(value.resolved_address.has_value());
                            if (value.resolved_address && !normalize) token_address(out, *value.resolved_address);
                        } else if constexpr (std::is_same_v<T, FarPointerOperand>) {
                            out.u16(value.selector); out.u32(value.offset); out.u16(value.offset_width);
                        } else if constexpr (std::is_same_v<T, FarMemoryOperand>) {
                            out.u16(value.offset_width); out.u16(value.address.data_width);
                            out.u16(value.address.address_width); out.u64(static_cast<std::uint64_t>(value.address.displacement));
                            out.u8(value.address.scale); out.u8(value.address.ip_relative);
                            out.u8(value.address.segment.has_value()); if (value.address.segment) token_register(out, *value.address.segment);
                            out.u8(value.address.base.has_value()); if (value.address.base) token_register(out, *value.address.base);
                            out.u8(value.address.index.has_value()); if (value.address.index) token_register(out, *value.address.index);
                            out.text(value.address.index_extend); out.u8(value.address.index_shift_amount);
                            out.u8(value.address.resolved_address.has_value());
                            if (value.address.resolved_address) token_address(out, *value.address.resolved_address);
                        } else if constexpr (std::is_same_v<T, ArmShiftedRegisterOperand>) {
                            token_register(out, value.source); out.u8(static_cast<std::uint8_t>(value.shift));
                            out.u8(value.amount); out.u8(value.amount_register.has_value());
                            if (value.amount_register) token_register(out, *value.amount_register);
                        } else if constexpr (std::is_same_v<T, ArmMemoryOperand>) {
                            token_register(out, value.base); out.u8(value.offset.index());
                            if (const auto *immediate = std::get_if<std::uint32_t>(&value.offset)) out.u32(*immediate);
                            else {
                                const auto &shifted = std::get<ArmShiftedRegisterOperand>(value.offset);
                                token_register(out, shifted.source); out.u8(static_cast<std::uint8_t>(shifted.shift));
                                out.u8(shifted.amount); out.u8(shifted.amount_register.has_value());
                                if (shifted.amount_register) token_register(out, *shifted.amount_register);
                            }
                            out.u8(value.add); out.u8(value.pre_index); out.u8(value.writeback);
                            out.u16(value.data_width); out.u8(value.sign_extend);
                            out.u8(value.resolved_address.has_value()); if (value.resolved_address) token_address(out, *value.resolved_address);
                        } else if constexpr (std::is_same_v<T, ArmRegisterListOperand>) {
                            out.u16(value.mask);
                        } else if constexpr (std::is_same_v<T, ThumbRelativeOperand>) {
                            out.u64(static_cast<std::uint64_t>(value.displacement)); out.u16(value.encoded_width);
                        }
                    }, operand);
                }
                require(canonical.access.size() <= 16,
                        "Fingerprint instruction access limit exceeded", ErrorCode::resource_limit);
                out.u8(static_cast<std::uint8_t>(canonical.access.size()));
                for (const auto access : canonical.access) out.u8(static_cast<std::uint8_t>(access));
                const auto registers = [&](const std::vector<RegisterOperand> &values) {
                    require(values.size() <= 64, "Fingerprint instruction register effect limit exceeded", ErrorCode::resource_limit);
                    out.u8(static_cast<std::uint8_t>(values.size()));
                    for (const auto &reg : values) token_register(out, reg);
                };
                registers(canonical.register_reads); registers(canonical.register_writes);
                out.u8(canonical.arm.has_value());
                if (canonical.arm) {
                    const auto &arm = *canonical.arm;
                    out.u8(static_cast<std::uint8_t>(arm.predicate)); out.u8(static_cast<std::uint8_t>(arm.exchange));
                    out.u8(arm.flags_written); out.u8(arm.flags_known); out.u8(arm.writes_pc); out.u8(arm.writeback);
                    out.u8(static_cast<std::uint8_t>(arm.multiple_mode));
                    out.u8(arm.it_before.known); out.u8(arm.it_before.bits);
                    out.u8(arm.it_after.known); out.u8(arm.it_after.bits);
                    out.u8(arm.target_mode.has_value()); if (arm.target_mode) out.u8(static_cast<std::uint8_t>(*arm.target_mode));
                    out.u8(arm.return_mode.has_value()); if (arm.return_mode) out.u8(static_cast<std::uint8_t>(*arm.return_mode));
                }
            }
            require(row.block->successors.size() <= 64, "Function fingerprint block edge limit exceeded", ErrorCode::resource_limit);
            out.u8(0xe1); out.u8(static_cast<std::uint8_t>(row.block->successors.size()));
            for (const auto &edge : row.block->successors) {
                out.u8(static_cast<std::uint8_t>(edge.kind));
                if (!edge.target) { out.u8(0); continue; }
                const bool address_normalized = normalized_branch_sources.contains(address_key(edge.source));
                const auto destination = instructions.find(address_key(*edge.target));
                if (address_normalized && destination != instructions.end()) {
                    out.u8(1); out.u32(destination->second.block_ordinal); out.u32(destination->second.instruction_ordinal);
                } else if (address_normalized) {
                    out.u8(2); // External address has a proven relocatable field.
                } else {
                    out.u8(3); token_address(out, *edge.target);
                }
            }
        }
        return std::pair{out.data(), instruction_count};
    });
}

Result<FunctionFingerprintDefinition> fingerprint_definition(const Image &image, const ByteStorage &bytes,
        const FunctionRecord &function, const FunctionSnapshot &snapshot, std::string name,
        std::string provenance, const FunctionFingerprintOptions &options, std::stop_token stop) {
    return guarded([&]() -> Result<FunctionFingerprintDefinition> {
        require(!name.empty() && name.size() <= 128 && name.find_first_of("|\r\n") == std::string::npos &&
                    !provenance.empty() && provenance.size() <= 256 && provenance.find_first_of("|\r\n") == std::string::npos,
                "Invalid fingerprint metadata");
        auto tokens = fingerprint_tokens(image, bytes, function, snapshot, options, stop);
        require(bool(tokens), tokens ? "" : tokens.error().message);
        Sha256 hash;
        auto updated = hash.update(tokens.value().first);
        require(bool(updated), updated ? "" : updated.error().message, ErrorCode::resource_limit);
        return FunctionFingerprintDefinition{std::move(name), std::move(provenance),
            image.layout().architecture, image.layout().mode, tokens.value().second, hash.digest()};
    });
}

std::string digest_text(const Sha256Digest &digest) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result; result.reserve(64);
    for (const auto byte : digest) {
        const auto value = std::to_integer<unsigned>(byte);
        result.push_back(digits[value >> 4]); result.push_back(digits[value & 15]);
    }
    return result;
}
Sha256Digest parse_digest(std::string_view text) {
    require(text.size() == 64, "Fingerprint digest must contain 64 hex digits");
    Sha256Digest digest{};
    for (std::size_t i = 0; i < digest.size(); ++i) {
        const auto high = nibble(text[i * 2]), low = nibble(text[i * 2 + 1]);
        require(high >= 0 && low >= 0, "Fingerprint digest is not hexadecimal");
        digest[i] = std::byte((high << 4) | low);
    }
    return digest;
}
}

Result<FunctionFingerprintDefinition> create_function_fingerprint(const Image &image, const ByteStorage &bytes,
        const FunctionRecord &function, const FunctionSnapshot &snapshot, std::string name,
        std::string provenance, const FunctionFingerprintOptions &options, std::stop_token stop) {
    return fingerprint_definition(image, bytes, function, snapshot, std::move(name), std::move(provenance), options, stop);
}

Result<std::string> serialize_function_fingerprint_catalog(const FunctionFingerprintCatalog &catalog) {
    return guarded([&]() -> Result<std::string> {
        require(catalog.format_version == 1 && architecture_name(catalog.target_architecture) != "unknown" &&
                    mode_name(catalog.target_mode) != "unknown" && !catalog.definitions.empty() &&
                    catalog.definitions.size() <= 4096,
                "Invalid fingerprint catalog header or definition count");
        std::set<std::string> names;
        std::string output = "# HexLab normalized fingerprint catalog v1\n# target: ";
        output += std::string(architecture_name(catalog.target_architecture)) + "/" +
                  std::string(mode_name(catalog.target_mode)) + "\n";
        for (const auto &definition : catalog.definitions) {
            require(!definition.name.empty() && definition.name.size() <= 128 &&
                        definition.name.find_first_of("|\r\n") == std::string::npos &&
                        definition.name.front() != '#' && definition.name.front() != ' ' && definition.name.front() != '\t' &&
                        !definition.provenance.empty() && definition.provenance.size() <= 256 &&
                        definition.provenance.find_first_of("|\r\n") == std::string::npos &&
                        definition.target_architecture == catalog.target_architecture &&
                        definition.target_mode == catalog.target_mode && definition.instruction_count > 0 &&
                        definition.instruction_count <= 2048 && names.insert(definition.name).second,
                    "Invalid or duplicate function fingerprint definition");
            output += definition.name + '|' + definition.provenance + '|' +
                      std::to_string(definition.instruction_count) + '|' + digest_text(definition.digest) + '\n';
            require(output.size() <= 1024 * 1024, "Fingerprint catalog exceeds 1 MiB", ErrorCode::resource_limit);
        }
        return output;
    });
}

Result<FunctionFingerprintCatalog> parse_function_fingerprint_catalog(std::string_view text) {
    return guarded([&]() -> Result<FunctionFingerprintCatalog> {
        require(text.size() <= 1024 * 1024, "Fingerprint catalog exceeds 1 MiB", ErrorCode::resource_limit);
        constexpr std::string_view header = "# HexLab normalized fingerprint catalog v1";
        const auto line_end = text.find('\n');
        auto first = text.substr(0, line_end == text.npos ? text.size() : line_end);
        if (!first.empty() && first.back() == '\r') first.remove_suffix(1);
        require(first == header, "Unsupported function fingerprint catalog header");
        require(line_end != text.npos, "Fingerprint catalog is missing target metadata");
        text.remove_prefix(line_end + 1);
        const auto target_end = text.find('\n');
        auto target = text.substr(0, target_end == text.npos ? text.size() : target_end);
        if (!target.empty() && target.back() == '\r') target.remove_suffix(1);
        constexpr std::string_view prefix = "# target: ";
        require(target.starts_with(prefix), "Fingerprint catalog is missing target metadata");
        target.remove_prefix(prefix.size());
        const auto slash = target.find('/');
        require(slash != target.npos && target.find('/', slash + 1) == target.npos, "Malformed fingerprint target");
        const auto architecture = parse_architecture(target.substr(0, slash));
        const auto mode = parse_mode(target.substr(slash + 1));
        require(architecture != Architecture::unknown && mode != ExecutionMode::unknown,
                "Unknown function fingerprint target");
        text = target_end == text.npos ? std::string_view{} : text.substr(target_end + 1);
        FunctionFingerprintCatalog catalog{1, architecture, mode, {}};
        std::set<std::string> names;
        while (!text.empty()) {
            const auto end = text.find('\n');
            auto line = text.substr(0, end == text.npos ? text.size() : end);
            if (end == text.npos) text = {}; else text.remove_prefix(end + 1);
            if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
            if (line.empty() || line.front() == '#') continue;
            std::array<std::string_view, 4> fields{};
            for (std::size_t i = 0; i < 3; ++i) {
                const auto separator = line.find('|');
                require(separator != line.npos, "Fingerprint definition requires four pipe-separated fields");
                fields[i] = line.substr(0, separator); line.remove_prefix(separator + 1);
            }
            fields[3] = line;
            require(line.find('|') == line.npos && !fields[0].empty() && fields[0].size() <= 128 &&
                        !fields[1].empty() && fields[1].size() <= 256 &&
                        fields[0].front() != '#' && fields[0].front() != ' ' && fields[0].front() != '\t' &&
                        fields[0].find_first_of("\r\n") == fields[0].npos &&
                        fields[1].find_first_of("\r\n") == fields[1].npos,
                    "Invalid fingerprint definition metadata");
            require(fields[3].size() == 64, "Fingerprint digest must contain exactly 64 hex digits");
            std::uint32_t count = 0;
            for (const char ch : fields[2]) {
                require(ch >= '0' && ch <= '9' && count <= 2048, "Invalid fingerprint instruction count");
                count = count * 10 + std::uint32_t(ch - '0');
            }
            require(count > 0 && count <= 2048 && names.insert(std::string(fields[0])).second,
                    "Fingerprint count is out of range or name is duplicated");
            catalog.definitions.push_back({std::string(fields[0]), std::string(fields[1]), architecture, mode,
                                           count, parse_digest(fields[3])});
            require(catalog.definitions.size() <= 4096, "Fingerprint catalog exceeds 4096 definitions", ErrorCode::resource_limit);
        }
        require(!catalog.definitions.empty(), "Fingerprint catalog has no definitions");
        return catalog;
    });
}

Result<FunctionFingerprintRecognition> recognize_function_fingerprints(const Image &image, const ByteStorage &bytes,
        const FunctionSnapshot &snapshot, const FunctionFingerprintCatalog &catalog,
        const FunctionFingerprintLimits &limits, std::stop_token stop) {
    return guarded([&]() -> Result<FunctionFingerprintRecognition> {
        canceled(stop);
        require(catalog.format_version == 1 && catalog.target_architecture == image.layout().architecture &&
                    catalog.target_mode == image.layout().mode,
                "Fingerprint catalog target does not match image architecture and mode");
        require(!catalog.definitions.empty() && catalog.definitions.size() <= 4096 &&
                    limits.max_functions && limits.max_functions <= 100000 &&
                    limits.max_instructions && limits.max_instructions <= 4000000 &&
                    limits.max_token_bytes && limits.max_token_bytes <= 256ull * 1024 * 1024 &&
                    limits.per_function.max_instructions && limits.per_function.max_instructions <= 2048 &&
                    limits.per_function.max_blocks && limits.per_function.max_blocks <= 4096 &&
                    limits.per_function.max_token_bytes && limits.per_function.max_token_bytes <= 4 * 1024 * 1024,
                "Fingerprint recognition limits exceed supported bounds", ErrorCode::resource_limit);
        FunctionFingerprintRecognition result;
        result.source_key=snapshot.key;
        result.complete = snapshot.complete;
        std::map<AddressKey, std::vector<FunctionFingerprintCandidate>> matches;
        std::set<AddressKey> entries;
        for (const auto &definition : catalog.definitions) {
            require(definition.target_architecture == catalog.target_architecture &&
                        definition.target_mode == catalog.target_mode && definition.instruction_count > 0 &&
                        definition.instruction_count <= limits.per_function.max_instructions,
                    "Fingerprint definition target/count is inconsistent with its catalog");
        }
        for (const auto &function : snapshot.functions) {
            canceled(stop);
            require(result.functions_scanned < limits.max_functions, "Fingerprint function budget reached", ErrorCode::resource_limit);
            require(bool(function), "Missing recovered function record");
            require(entries.insert(address_key(function->entry)).second, "Duplicate recovered function entry");
            auto tokens = fingerprint_tokens(image, bytes, *function, snapshot, limits.per_function, stop);
            require(bool(tokens), tokens ? "" : tokens.error().message);
            result.instructions_scanned += tokens.value().second;
            result.token_bytes += tokens.value().first.size();
            require(result.instructions_scanned <= limits.max_instructions && result.token_bytes <= limits.max_token_bytes,
                    "Fingerprint aggregate work budget reached", ErrorCode::resource_limit);
            ++result.functions_scanned;
            result.complete = result.complete && function->complete;
            Sha256 hash; auto updated = hash.update(tokens.value().first);
            require(bool(updated), updated ? "" : updated.error().message, ErrorCode::resource_limit);
            const auto digest = hash.digest();
            for (const auto &definition : catalog.definitions) {
                canceled(stop);
                if (definition.instruction_count == tokens.value().second && definition.digest == digest)
                    matches[address_key(function->entry)].push_back({definition.name, definition.provenance,
                        definition.instruction_count, definition.digest});
            }
        }
        for (auto &[key, candidates] : matches) {
            if (candidates.empty()) continue;
            const auto function = std::find_if(snapshot.functions.begin(), snapshot.functions.end(),
                [&](const auto &value) { return address_key(value->entry) == key; });
            require(function != snapshot.functions.end(), "Fingerprint match lost its recovered function");
            const bool ambiguous = candidates.size() > 1;
            result.functions.push_back({(*function)->id, (*function)->entry, std::move(candidates), ambiguous});
        }
        std::sort(result.functions.begin(), result.functions.end(), [](const auto &a, const auto &b) {
            return address_key(a.entry) < address_key(b.entry);
        });
        return result;
    });
}

namespace {
void evidence_u8(std::vector<std::byte>& out,std::uint8_t value){out.push_back(std::byte(value));}
void evidence_u16(std::vector<std::byte>& out,std::uint16_t value){for(unsigned i=0;i<2;++i)out.push_back(std::byte(value>>(i*8)));}
void evidence_u32(std::vector<std::byte>& out,std::uint32_t value){for(unsigned i=0;i<4;++i)out.push_back(std::byte(value>>(i*8)));}
void evidence_u64(std::vector<std::byte>& out,std::uint64_t value){for(unsigned i=0;i<8;++i)out.push_back(std::byte(value>>(i*8)));}
void evidence_key(std::vector<std::byte>& out,const AnalysisKey& key){
    evidence_u64(out,key.input.size);out.insert(out.end(),key.input.sha256.begin(),key.input.sha256.end());
    evidence_u64(out,key.byte_revision);evidence_u64(out,key.decision_revision);
    out.insert(out.end(),key.recipe_fingerprint.begin(),key.recipe_fingerprint.end());
    out.insert(out.end(),key.engine_fingerprint.begin(),key.engine_fingerprint.end());
}
struct EvidenceReader {
    std::span<const std::byte> bytes;std::size_t at=0;
    std::uint8_t u8(){require(at<bytes.size(),"Truncated function recognition evidence");return std::to_integer<std::uint8_t>(bytes[at++]);}
    std::uint16_t u16(){std::uint16_t v=0;for(unsigned i=0;i<2;++i)v|=std::uint16_t(u8())<<(i*8);return v;}
    std::uint32_t u32(){std::uint32_t v=0;for(unsigned i=0;i<4;++i)v|=std::uint32_t(u8())<<(i*8);return v;}
    std::uint64_t u64(){std::uint64_t v=0;for(unsigned i=0;i<8;++i)v|=std::uint64_t(u8())<<(i*8);return v;}
    std::string string(std::size_t maximum){const auto size=u16();require(size>0&&size<=maximum&&size<=bytes.size()-at,"Invalid recognition evidence string extent");std::string value;value.reserve(size);for(std::size_t i=0;i<size;++i)value.push_back(static_cast<char>(u8()));return value;}
    Sha256Digest digest(){require(bytes.size()-at>=32,"Truncated recognition evidence digest");Sha256Digest value{};std::copy_n(bytes.begin()+static_cast<std::ptrdiff_t>(at),32,value.begin());at+=32;return value;}
    AnalysisKey key(){AnalysisKey value;value.input.size=u64();value.input.sha256=digest();value.byte_revision=u64();value.decision_revision=u64();value.recipe_fingerprint=digest();value.engine_fingerprint=digest();return value;}
};
void validate_evidence(const FunctionRecognitionEvidence& evidence){
    const bool legacy_kind=evidence.kind==FunctionRecognitionKind::byte_signatures||evidence.kind==FunctionRecognitionKind::normalized_fingerprints;
    const bool valid_legacy=evidence.format_version==1&&legacy_kind;
    const bool valid_flirt=evidence.format_version==2&&evidence.kind==FunctionRecognitionKind::flirt_patterns;
    require(valid_legacy||valid_flirt,"Unsupported function recognition evidence version or kind",ErrorCode::unsupported);
    require(evidence.functions.size()<=100000,"Function recognition evidence function limit exceeded",ErrorCode::resource_limit);
    std::set<std::uint64_t> ids;std::set<AddressKey> entries;std::uint64_t candidates=0;
    for(const auto& function:evidence.functions){
        require(function.function.value&&ids.insert(function.function.value).second&&entries.insert(address_key(function.entry)).second,"Duplicate or invalid recognized function identity");
        require(!function.candidates.empty()&&function.candidates.size()<=4096&&function.ambiguous==(function.candidates.size()>1),"Recognition evidence ambiguity is inconsistent");
        candidates+=function.candidates.size();require(candidates<=65536,"Function recognition evidence candidate limit exceeded",ErrorCode::resource_limit);
        for(const auto& candidate:function.candidates){
            require(!candidate.name.empty()&&candidate.name.size()<=256&&!candidate.provenance.empty()&&candidate.provenance.size()<=256,"Invalid recognition candidate metadata");
            if(evidence.kind==FunctionRecognitionKind::normalized_fingerprints)
                require(candidate.instruction_count>0,"Fingerprint evidence has no instruction count");
            if(evidence.kind==FunctionRecognitionKind::flirt_patterns)
                require(candidate.symbol_kind<=1&&candidate.matching_patterns>0,"Invalid FLAIR candidate metadata");
        }
    }
}
}

Result<FunctionRecognitionEvidence> make_function_recognition_evidence(const FunctionSnapshot& snapshot,
        const Sha256Digest& catalog_digest,const FunctionSignatureRecognition& recognition,std::stop_token stop){
    return guarded([&]()->Result<FunctionRecognitionEvidence>{
        canceled(stop);require(snapshot.key&&recognition.source_key&&*snapshot.key==*recognition.source_key,
            "Signature recognition is not bound to the current source identity",ErrorCode::conflict);
        FunctionRecognitionEvidence evidence;evidence.kind=FunctionRecognitionKind::byte_signatures;
        evidence.source_key=*snapshot.key;evidence.catalog_digest=catalog_digest;evidence.complete=recognition.complete;
        evidence.functions.reserve(recognition.functions.size());
        for(const auto& function:recognition.functions){canceled(stop);FunctionRecognitionRecord record;record.function=function.function;record.entry=function.entry;record.ambiguous=function.ambiguous;
            for(const auto& candidate:function.candidates)record.candidates.push_back({candidate.name,candidate.provenance,candidate.constrained_bits,candidate.pattern_bytes,0,{}});
            evidence.functions.push_back(std::move(record));}
        validate_evidence(evidence);return evidence;
    });
}
Result<FunctionRecognitionEvidence> make_function_recognition_evidence(const FunctionSnapshot& snapshot,
        const Sha256Digest& catalog_digest,const FunctionFingerprintRecognition& recognition,std::stop_token stop){
    return guarded([&]()->Result<FunctionRecognitionEvidence>{
        canceled(stop);require(snapshot.key&&recognition.source_key&&*snapshot.key==*recognition.source_key,
            "Fingerprint recognition is not bound to the current source identity",ErrorCode::conflict);
        FunctionRecognitionEvidence evidence;evidence.kind=FunctionRecognitionKind::normalized_fingerprints;
        evidence.source_key=*snapshot.key;evidence.catalog_digest=catalog_digest;evidence.complete=recognition.complete;
        evidence.functions.reserve(recognition.functions.size());
        for(const auto& function:recognition.functions){canceled(stop);FunctionRecognitionRecord record;record.function=function.function;record.entry=function.entry;record.ambiguous=function.ambiguous;
            for(const auto& candidate:function.candidates)record.candidates.push_back({candidate.name,candidate.provenance,0,0,candidate.instruction_count,candidate.digest});
            evidence.functions.push_back(std::move(record));}
        validate_evidence(evidence);return evidence;
    });
}
Result<bool> validate_function_recognition_evidence(const FunctionRecognitionEvidence& evidence,const AnalysisKey& key,
        const FunctionSnapshot& snapshot,std::stop_token stop){
    return guarded([&]()->Result<bool>{
        canceled(stop);validate_evidence(evidence);require(evidence.source_key==key&&snapshot.key&&*snapshot.key==key,
            "Recognition evidence belongs to a stale source revision",ErrorCode::conflict);
        std::map<std::uint64_t,Address> functions;for(const auto& function:snapshot.functions){canceled(stop);require(bool(function),"Function snapshot contains a null record");functions.emplace(function->id.value,function->entry);}
        for(const auto& function:evidence.functions){canceled(stop);auto found=functions.find(function.function.value);require(found!=functions.end()&&found->second==function.entry,
            "Recognition evidence refers to a stale function fact",ErrorCode::conflict);}
        return true;
    });
}
Result<std::vector<std::byte>> encode_function_recognition_evidence(const FunctionRecognitionEvidence& evidence,std::stop_token stop){
    return guarded([&]()->Result<std::vector<std::byte>>{
        canceled(stop);validate_evidence(evidence);std::vector<std::byte> out{std::byte{'H'},std::byte{'X'},std::byte{'R'},std::byte{'E'}};
        evidence_u16(out,static_cast<std::uint16_t>(evidence.format_version));evidence_u8(out,static_cast<std::uint8_t>(evidence.kind));evidence_u8(out,evidence.complete?1:0);
        evidence_key(out,evidence.source_key);out.insert(out.end(),evidence.catalog_digest.begin(),evidence.catalog_digest.end());
        evidence_u32(out,static_cast<std::uint32_t>(evidence.functions.size()));
        for(const auto& function:evidence.functions){canceled(stop);evidence_u64(out,function.function.value);evidence_u32(out,function.entry.space.value);evidence_u64(out,function.entry.offset);
            evidence_u8(out,function.ambiguous?1:0);evidence_u16(out,static_cast<std::uint16_t>(function.candidates.size()));
            for(const auto& candidate:function.candidates){evidence_u16(out,static_cast<std::uint16_t>(candidate.name.size()));for(auto ch:candidate.name)evidence_u8(out,static_cast<std::uint8_t>(ch));
                evidence_u16(out,static_cast<std::uint16_t>(candidate.provenance.size()));for(auto ch:candidate.provenance)evidence_u8(out,static_cast<std::uint8_t>(ch));
                evidence_u32(out,candidate.constrained_bits);evidence_u32(out,candidate.pattern_bytes);evidence_u32(out,candidate.instruction_count);out.insert(out.end(),candidate.digest.begin(),candidate.digest.end());
                if(evidence.format_version>=2){evidence_u8(out,candidate.symbol_kind);evidence_u32(out,candidate.matching_patterns);}}
            require(out.size()<=16*1024*1024,"Recognition evidence payload exceeds 16 MiB",ErrorCode::resource_limit);
        }
        return out;
    });
}
Result<FunctionRecognitionEvidence> decode_function_recognition_evidence(std::span<const std::byte> bytes,
        const AnalysisKey& expected,FunctionRecognitionKind expected_kind,std::stop_token stop){
    return guarded([&]()->Result<FunctionRecognitionEvidence>{
        canceled(stop);require(bytes.size()>=164&&bytes.size()<=16*1024*1024,"Recognition evidence payload extent is invalid",ErrorCode::integrity);
        EvidenceReader reader{bytes};require(reader.u8()=='H'&&reader.u8()=='X'&&reader.u8()=='R'&&reader.u8()=='E',"Invalid recognition evidence magic",ErrorCode::integrity);
        FunctionRecognitionEvidence evidence;evidence.format_version=reader.u16();require(evidence.format_version==1||evidence.format_version==2,"Unsupported recognition evidence format",ErrorCode::unsupported);evidence.kind=static_cast<FunctionRecognitionKind>(reader.u8());const auto complete=reader.u8();require(complete<=1,"Invalid recognition evidence completion flag",ErrorCode::integrity);evidence.complete=complete!=0;
        evidence.source_key=reader.key();evidence.catalog_digest=reader.digest();const auto count=reader.u32();require(count<=100000,"Recognition evidence function count exceeds limit",ErrorCode::resource_limit);evidence.functions.reserve(count);
        for(std::uint32_t i=0;i<count;++i){canceled(stop);FunctionRecognitionRecord function;function.function={reader.u64()};function.entry={{reader.u32()},reader.u64()};const auto ambiguous=reader.u8();require(ambiguous<=1,"Invalid recognition evidence ambiguity flag",ErrorCode::integrity);function.ambiguous=ambiguous!=0;
            const auto candidates=reader.u16();require(candidates>0&&candidates<=4096,"Recognition evidence candidate count exceeds limit",ErrorCode::resource_limit);function.candidates.reserve(candidates);
            for(std::uint16_t n=0;n<candidates;++n){FunctionRecognitionCandidateEvidence candidate;candidate.name=reader.string(256);candidate.provenance=reader.string(256);candidate.constrained_bits=reader.u32();candidate.pattern_bytes=reader.u32();candidate.instruction_count=reader.u32();candidate.digest=reader.digest();if(evidence.format_version>=2){candidate.symbol_kind=reader.u8();candidate.matching_patterns=reader.u32();}function.candidates.push_back(std::move(candidate));}
            evidence.functions.push_back(std::move(function));}
        require(reader.at==bytes.size(),"Trailing bytes in recognition evidence",ErrorCode::integrity);validate_evidence(evidence);
        require(evidence.source_key==expected&&evidence.kind==expected_kind,"Recognition evidence source or kind mismatch",ErrorCode::conflict);return evidence;
    });
}

}

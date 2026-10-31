#include "hexlab/analysis/module_dependencies.hpp"
#include <algorithm>
#include <cstddef>
#include <cwctype>
#include <fstream>
#include <limits>
#include <set>
#include <span>
#include <string_view>

namespace hexlab {
namespace {
bool contained(const std::filesystem::path &path, const std::filesystem::path &root) {
    auto part = path.begin();
    for (const auto &root_part : root) {
        if (part == path.end()) return false;
#ifdef _WIN32
        auto left = part->wstring(), right = root_part.wstring();
        std::transform(left.begin(), left.end(), left.begin(), ::towlower);
        std::transform(right.begin(), right.end(), right.begin(), ::towlower);
        if (left != right) return false;
#else
        if (*part != root_part) return false;
#endif
        ++part;
    }
    return true;
}
std::filesystem::path utf8_path(std::string_view text) {
    return std::filesystem::path(std::u8string(text.begin(), text.end()));
}
std::string identity(const std::filesystem::path &path) {
    auto value = path.generic_u8string();
    std::string result(value.begin(), value.end());
#ifdef _WIN32
    auto wide = path.generic_wstring();
    std::transform(wide.begin(), wide.end(), wide.begin(), ::towlower);
    value = std::filesystem::path(wide).generic_u8string();
    result.assign(value.begin(), value.end());
#endif
    return result;
}
std::uint64_t cache_integer(std::span<const std::byte> bytes, std::size_t offset,
                            std::size_t width, bool little_endian) {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < width; ++i) {
        const auto byte = std::to_integer<std::uint8_t>(bytes[offset + i]);
        const auto shift = little_endian ? i * 8 : (width - 1 - i) * 8;
        value |= std::uint64_t{byte} << shift;
    }
    return value;
}
enum class CacheAbiMatch { compatible, incompatible, unsupported };
CacheAbiMatch cache_abi_match(std::uint32_t flags, const ElfHeader &header) {
    constexpr std::uint32_t type_mask = 0x00ff, required_mask = 0xff00;
    if ((flags & type_mask) != 3 || (flags & ~(type_mask | required_mask)) != 0)
        return CacheAbiMatch::unsupported;
    const auto required = flags & required_mask;
    if (required == 0) {
        switch (header.machine) {
        case 3: case 20: case 22: case 2:
            return header.is_64 ? CacheAbiMatch::incompatible : CacheAbiMatch::compatible;
        case 8: {
            constexpr std::uint32_t mips_abi2 = 0x20, mips_abi_mask = 0xf000, mips_nan2008 = 0x400;
            const auto abi = header.flags & mips_abi_mask;
            return !header.is_64 && !(header.flags & (mips_abi2 | mips_nan2008)) &&
                           (abi == 0 || abi == 0x1000)
                       ? CacheAbiMatch::compatible : CacheAbiMatch::unsupported;
        }
        case 40:
            if (header.is_64 || (header.flags & 0x600) == 0x600) return CacheAbiMatch::unsupported;
            return CacheAbiMatch::compatible;
        default: return CacheAbiMatch::unsupported;
        }
    }
    switch (header.machine) {
    case 62: // EM_X86_64: x86-64 or x32 cache ABI.
        if (required == 0x0300) return header.is_64 ? CacheAbiMatch::compatible : CacheAbiMatch::incompatible;
        if (required == 0x0800) return !header.is_64 ? CacheAbiMatch::compatible : CacheAbiMatch::incompatible;
        break;
    case 3: // EM_386.
        if (required == 0x0300 || required == 0x0800) return CacheAbiMatch::incompatible;
        break;
    case 43: // EM_SPARCV9.
        if (required == 0x0100) return header.is_64 ? CacheAbiMatch::compatible : CacheAbiMatch::incompatible;
        break;
    case 22: // EM_S390.
        if (required == 0x0400) return header.is_64 ? CacheAbiMatch::compatible : CacheAbiMatch::incompatible;
        break;
    case 21: // EM_PPC64.
        if (required == 0x0500) return header.is_64 ? CacheAbiMatch::compatible : CacheAbiMatch::incompatible;
        break;
    case 8: // EM_MIPS: N32/N64 and nan2008 require more e_flags detail than this inventory exposes.
        if (required == 0x0600)
            return !header.is_64 && (header.flags & 0x20) ? CacheAbiMatch::compatible : CacheAbiMatch::incompatible;
        if (required == 0x0700)
            return header.is_64 && !(header.flags & 0x20) ? CacheAbiMatch::compatible : CacheAbiMatch::incompatible;
        if (required == 0x0c00)
            return !header.is_64 && !(header.flags & 0x20) && (header.flags & 0x400)
                ? CacheAbiMatch::compatible : CacheAbiMatch::incompatible;
        if (required == 0x0d00)
            return !header.is_64 && (header.flags & 0x20) && (header.flags & 0x400)
                ? CacheAbiMatch::compatible : CacheAbiMatch::incompatible;
        if (required == 0x0e00)
            return header.is_64 && !(header.flags & 0x20) && (header.flags & 0x400)
                ? CacheAbiMatch::compatible : CacheAbiMatch::incompatible;
        break;
    case 40: // EM_ARM.
        if (required == 0x0900) {
            if (header.is_64 || (header.flags & 0x600) == 0) return CacheAbiMatch::unsupported;
            return (header.flags & 0x600) == 0x400 ? CacheAbiMatch::compatible : CacheAbiMatch::incompatible;
        }
        if (required == 0x0b00) {
            if (header.is_64 || (header.flags & 0x600) == 0) return CacheAbiMatch::unsupported;
            return (header.flags & 0x600) == 0x200 ? CacheAbiMatch::compatible : CacheAbiMatch::incompatible;
        }
        break;
    case 183: // EM_AARCH64.
        if (required == 0x0a00) return header.is_64 ? CacheAbiMatch::compatible : CacheAbiMatch::incompatible;
        break;
    case 243: // EM_RISCV: cache flags distinguish soft and double-float ABIs.
        if (required == 0x0f00) return header.is_64 && (header.flags & 0x6) == 0 ? CacheAbiMatch::compatible : CacheAbiMatch::incompatible;
        if (required == 0x1000) return header.is_64 && (header.flags & 0x6) == 4 ? CacheAbiMatch::compatible : CacheAbiMatch::incompatible;
        break;
    case 258: // EM_LOONGARCH.
        if (required == 0x1100) return header.is_64 && (header.flags & 0x3) == 1 ? CacheAbiMatch::compatible : CacheAbiMatch::incompatible;
        if (required == 0x1200) return header.is_64 && (header.flags & 0x3) == 3 ? CacheAbiMatch::compatible : CacheAbiMatch::incompatible;
        break;
    default: break;
    }
    return CacheAbiMatch::unsupported;
}
ElfGlibcCacheSnapshot load_glibc_cache(const std::filesystem::path &root,
                                      std::size_t byte_limit, std::size_t entry_limit,
                                      std::size_t string_byte_limit,
                                      std::stop_token stop) {
    ElfGlibcCacheSnapshot result;
    result.sysroot = root;
    std::error_code ec;
    const auto cache_path = std::filesystem::canonical(root / "etc" / "ld.so.cache", ec);
    if (ec) { result.filesystem_errors = 1; return result; }
    if (!contained(cache_path, root) || !std::filesystem::is_regular_file(cache_path, ec) || ec) {
        result.filesystem_errors = 1;
        return result;
    }
    const auto file_size = std::filesystem::file_size(cache_path, ec);
    if (ec || file_size > byte_limit || file_size > std::numeric_limits<std::size_t>::max() ||
        file_size > static_cast<std::uintmax_t>((std::numeric_limits<std::streamsize>::max)())) {
        result.unsupported_formats = 1;
        return result;
    }
    result.bytes = static_cast<std::size_t>(file_size);
    std::vector<std::byte> bytes(result.bytes);
    std::ifstream input(cache_path, std::ios::binary);
    if (!input || (result.bytes && !input.read(reinterpret_cast<char *>(bytes.data()),
                                               static_cast<std::streamsize>(result.bytes)))) {
        result.filesystem_errors = 1;
        return result;
    }
    constexpr std::string_view magic = "glibc-ld.so.cache1.1";
    if (bytes.size() < 48 || bytes.size() < magic.size() ||
        !std::equal(magic.begin(), magic.end(), bytes.begin(), [](char left, std::byte right) {
            return static_cast<unsigned char>(left) == std::to_integer<unsigned char>(right);
        })) {
        result.unsupported_formats = 1;
        return result;
    }
    const auto format_flags = std::to_integer<std::uint8_t>(bytes[28]);
    const auto endian_tag = format_flags & 3;
    if (endian_tag == 1 || endian_tag == 0 || endian_tag > 3) {
        result.unsupported_formats = 1;
        return result;
    }
    const bool little = endian_tag == 2;
    result.order = little ? ByteOrder::little : ByteOrder::big;
    const auto count = static_cast<std::size_t>(cache_integer(bytes, 20, 4, little));
    const auto string_size = static_cast<std::size_t>(cache_integer(bytes, 24, 4, little));
    const auto extension_offset = static_cast<std::size_t>(cache_integer(bytes, 32, 4, little));
    constexpr std::size_t header_size = 48, entry_size = 24;
    if (count > entry_limit || count > (bytes.size() - header_size) / entry_size) {
        result.unsupported_formats = 1;
        return result;
    }
    const auto string_base = header_size + count * entry_size;
    if (string_size > bytes.size() - string_base ||
        (extension_offset && (extension_offset % 4 || extension_offset >= bytes.size() ||
                             extension_offset < string_base + string_size))) {
        result.unsupported_formats = 1;
        return result;
    }
    struct RawEntry {
        std::uint32_t flags = 0, key = 0, value = 0, os_version = 0;
        std::uint64_t hwcap = 0;
    };
    std::vector<RawEntry> raw_entries;
    raw_entries.reserve(count);
    std::set<std::uint32_t> requested_strings;
    for (std::size_t i = 0; i < count; ++i) {
        if ((i & 255u) == 0 && stop.stop_requested()) return result;
        const auto at = header_size + i * entry_size;
        RawEntry entry;
        entry.flags = static_cast<std::uint32_t>(cache_integer(bytes, at, 4, little));
        entry.key = static_cast<std::uint32_t>(cache_integer(bytes, at + 4, 4, little));
        entry.value = static_cast<std::uint32_t>(cache_integer(bytes, at + 8, 4, little));
        entry.os_version = static_cast<std::uint32_t>(cache_integer(bytes, at + 12, 4, little));
        entry.hwcap = cache_integer(bytes, at + 16, 8, little);
        requested_strings.insert(entry.key);
        requested_strings.insert(entry.value);
        raw_entries.push_back(entry);
    }
    std::map<std::uint32_t, std::string> decoded_strings;
    const auto string_end = string_base + string_size;
    for (std::size_t position = string_base; position < string_end;) {
        if (((position - string_base) & 4095u) == 0 && stop.stop_requested()) return result;
        auto end = position;
        while (end < string_end && bytes[end] != std::byte{}) ++end;
        if (end == string_end) break;
        if (requested_strings.contains(static_cast<std::uint32_t>(position))) {
            if (end - position <= 32768) {
                std::string value;
                value.reserve(end - position);
                for (auto i = position; i < end; ++i)
                    value.push_back(static_cast<char>(std::to_integer<unsigned char>(bytes[i])));
                decoded_strings.emplace(static_cast<std::uint32_t>(position), std::move(value));
            }
        }
        position = end + 1;
    }
    for (std::size_t i = 0; i < raw_entries.size(); ++i) {
        if ((i & 255u) == 0 && stop.stop_requested()) return result;
        const auto &entry = raw_entries[i];
        const auto name_it = decoded_strings.find(entry.key);
        const auto path_it = decoded_strings.find(entry.value);
        if (name_it == decoded_strings.end() || path_it == decoded_strings.end()) {
            ++result.unsupported_entries;
            continue;
        }
        const auto &name = name_it->second;
        const auto &path = path_it->second;
        if (name.empty() || path.empty() || path.front() != '/' || result.string_bytes > string_byte_limit ||
            name.size() > string_byte_limit - result.string_bytes ||
            path.size() > string_byte_limit - result.string_bytes - name.size()) {
            ++result.unsupported_entries;
            continue;
        }
        result.string_bytes += name.size() + path.size();
        const auto index = result.entries.size();
        result.entries.push_back({name, utf8_path(path), entry.flags, entry.os_version, entry.hwcap});
        result.entry_indices_by_name[name].push_back(index);
    }
    return result;
}
std::vector<std::string> standard_default_dirs(const ElfHeader &header) {
    std::vector<std::string> dirs{"/lib", "/usr/lib"};
    const auto add = [&](std::string_view base, std::string_view triplet) {
        dirs.push_back(std::string(base) + "/" + std::string(triplet));
        dirs.push_back(std::string(base == "/lib" ? "/usr/lib" : base) + "/" + std::string(triplet));
    };
    if (header.is_64)
        dirs.insert(dirs.begin(), {"/lib64", "/usr/lib64"});
    if (header.machine == 62 && header.is_64) {
        add("/lib", "x86_64-linux-gnu");
    } else if (header.machine == 62 && !header.is_64) {
        dirs.insert(dirs.begin(), {"/libx32", "/usr/libx32"});
    } else if (header.machine == 3 && !header.is_64) add("/lib", "i386-linux-gnu");
    else if (header.machine == 183 && header.is_64) add("/lib", "aarch64-linux-gnu");
    else if (header.machine == 40 && !header.is_64)
        add("/lib", (header.flags & 0x400) ? "arm-linux-gnueabihf" : "arm-linux-gnueabi");
    else if (header.machine == 243 && header.is_64) add("/lib", "riscv64-linux-gnu");
    else if (header.machine == 258 && header.is_64) add("/lib", "loongarch64-linux-gnu");
    else if (header.machine == 22 && header.is_64) add("/lib", "s390x-linux-gnu");
    else if (header.machine == 22 && !header.is_64) add("/lib", "s390-linux-gnu");
    else if (header.machine == 21 && header.is_64)
        add("/lib", header.order == ByteOrder::little ? "powerpc64le-linux-gnu" : "powerpc64-linux-gnu");
    else if (header.machine == 20 && !header.is_64)
        add("/lib", header.order == ByteOrder::little ? "powerpcle-linux-gnu" : "powerpc-linux-gnu");
    return dirs;
}
}
Result<std::shared_ptr<const ElfGlibcCacheSnapshot>> read_elf_glibc_cache(
    const std::filesystem::path &sysroot, const ElfDependencyDiscoveryLimits &limits, std::stop_token stop) {
    try {
        if (!limits.glibc_cache_bytes || !limits.glibc_cache_entries || !limits.glibc_cache_string_bytes)
            return Error{ErrorCode::invalid_argument, "ELF glibc cache limits must be positive"};
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "ELF glibc cache read canceled"};
        std::error_code ec;
        const auto root = std::filesystem::canonical(sysroot, ec);
        if (ec || !std::filesystem::is_directory(root, ec))
            return Error{ErrorCode::invalid_argument, "ELF cache sysroot must be an existing directory"};
        auto snapshot = load_glibc_cache(root, limits.glibc_cache_bytes, limits.glibc_cache_entries,
                                         limits.glibc_cache_string_bytes, stop);
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "ELF glibc cache read canceled"};
        return std::make_shared<const ElfGlibcCacheSnapshot>(std::move(snapshot));
    } catch (const std::filesystem::filesystem_error &error) {
        return Error{ErrorCode::io, std::string("ELF glibc cache filesystem error: ") + error.what()};
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate bounded ELF glibc cache snapshot"};
    }
}
Result<ElfDependencyFileReport> discover_elf_dependency_files(
    const ElfMetadata &metadata, const std::filesystem::path &importer,
    const std::filesystem::path &sysroot, std::span<const std::filesystem::path> explicit_directories,
    const ElfDependencyDiscoveryLimits &limits, std::stop_token stop,
    const ElfDependencyPathContext &context) {
    try {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "ELF dependency discovery canceled"};
        if ((context.use_glibc_ld_so_cache && (!limits.glibc_cache_bytes || !limits.glibc_cache_entries ||
                                               !limits.glibc_cache_string_bytes)) ||
            (context.use_standard_default_directories && !limits.search_directories))
            return Error{ErrorCode::invalid_argument, "ELF system dependency limits must be positive"};
        if (explicit_directories.size() > limits.search_directories)
            return Error{ErrorCode::resource_limit, "ELF dependency search-directory limit exceeded"};
        if (context.environment_directories.size() > limits.search_directories ||
            explicit_directories.size() > limits.search_directories - context.environment_directories.size())
            return Error{ErrorCode::resource_limit, "ELF environment and explicit search-directory limit exceeded"};
        std::error_code ec;
        const auto root = std::filesystem::canonical(sysroot, ec);
        if (ec || !std::filesystem::is_directory(root, ec))
            return Error{ErrorCode::invalid_argument, "Dependency sysroot must be an existing directory"};
        const auto source = std::filesystem::canonical(importer, ec);
        if (ec || !contained(source, root) || !std::filesystem::is_regular_file(source, ec))
            return Error{ErrorCode::invalid_argument, "Dependency importer must be a regular file inside sysroot"};
        std::optional<std::filesystem::path> target_working_directory;
        if (context.target_working_directory) {
            const auto directory = std::filesystem::canonical(*context.target_working_directory, ec);
            if (ec || !contained(directory, root) || !std::filesystem::is_directory(directory, ec))
                return Error{ErrorCode::invalid_argument,
                             "Target working directory must be an existing directory inside sysroot"};
            target_working_directory = directory;
        }
        const auto valid_token_value = [](std::string_view value) {
            return !value.empty() && value.size() <= 128 &&
                std::all_of(value.begin(), value.end(), [](unsigned char c) {
                    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                           (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == '+';
                });
        };
        if ((!context.lib_token.empty() && !valid_token_value(context.lib_token)) ||
            (!context.platform_token.empty() && !valid_token_value(context.platform_token)))
            return Error{ErrorCode::invalid_argument,
                         "ELF $LIB and $PLATFORM substitutions must be bounded path-token values"};
        struct SearchPath {
            std::filesystem::path path;
            ElfDependencyPathSource source;
            std::optional<std::uint64_t> offset;
        };
        ElfDependencyFileReport report;
        std::vector<SearchPath> rpath, runpath, search;
        bool has_runpath = false;
        std::size_t unsupported_rpath = 0, unsupported_runpath = 0;
        const auto offset_of = [](const ElfDynamicTable &table, const ElfDynamicEntry &entry)
            -> std::optional<std::uint64_t> {
            if (!table.stride || table.size > UINT64_MAX - table.source.file_offset ||
                entry.index >= table.size / table.stride ||
                entry.index > (UINT64_MAX - table.source.file_offset) / table.stride) return {};
            return table.source.file_offset + entry.index * table.stride;
        };
        const auto account_name = [&](const std::string &text) {
            if (text.size() > 32768 || text.size() > limits.name_bytes - report.name_bytes) return false;
            report.name_bytes += text.size();
            return true;
        };
        const auto metadata_path = [&](std::string text, bool empty_means_cwd = false)
            -> std::optional<std::filesystem::path> {
            if (text.find('\0') != std::string::npos || text.find('\\') != std::string::npos ||
                text.find(':') != std::string::npos) return {};
            if (text.empty()) return empty_means_cwd ? target_working_directory : std::nullopt;
            // Validate token syntax before substitution. A canonical importer
            // path may itself contain '$'; those bytes are path data and must
            // not be mistaken for another unexpanded dynamic-string token.
            const auto supported_tokens_only = [](std::string_view value) {
                for (std::size_t position = 0; position < value.size();) {
                    if (value[position] != '$') { ++position; continue; }
                    constexpr std::string_view tokens[] = {
                        "$ORIGIN", "${ORIGIN}", "$LIB", "${LIB}", "$PLATFORM", "${PLATFORM}"
                    };
                    bool matched = false;
                    for (const auto token : tokens) {
                        if (value.substr(position).starts_with(token)) {
                            position += token.size();
                            matched = true;
                            break;
                        }
                    }
                    if (!matched) return false;
                }
                return true;
            };
            if (!supported_tokens_only(text)) return {};
            bool uses_origin = false;
            const auto replace_token = [&](std::string_view short_form, std::string_view long_form,
                                           std::string_view value) -> bool {
                for (const auto form : {short_form, long_form}) {
                    std::size_t position = 0;
                    while ((position = text.find(form, position)) != std::string::npos) {
                        if (value.empty()) return false;
                        text.replace(position, form.size(), value);
                        position += value.size();
                    }
                }
                return true;
            };
            const auto origin_path = source.parent_path().generic_u8string();
            const std::string origin(reinterpret_cast<const char *>(origin_path.data()), origin_path.size());
            uses_origin = text.find("$ORIGIN") != std::string::npos || text.find("${ORIGIN}") != std::string::npos;
            if (!replace_token("$LIB", "${LIB}", context.lib_token) ||
                !replace_token("$PLATFORM", "${PLATFORM}", context.platform_token) ||
                !replace_token("$ORIGIN", "${ORIGIN}", origin)) return {};
            const auto expanded = utf8_path(text);
            if (expanded.is_absolute()) {
                if (uses_origin) return expanded;
                return root / expanded.relative_path();
            }
            if (target_working_directory) return *target_working_directory / expanded;
            return {};
        };
        for (const auto &table : metadata.dynamic_tables) {
            for (const auto &entry : table.entries) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "ELF dependency discovery canceled"};
                if (report.metadata_entries++ >= limits.metadata_entries)
                    return Error{ErrorCode::resource_limit, "ELF dependency metadata-entry limit exceeded"};
                constexpr std::uint64_t dt_auxiliary = 0x7ffffffd;
                constexpr std::uint64_t dt_filter = 0x7fffffff;
                if (entry.tag != 1 && entry.tag != 15 && entry.tag != 29 &&
                    entry.tag != dt_auxiliary && entry.tag != dt_filter) continue;
                if (!entry.string_value)
                    return Error{ErrorCode::malformed, "ELF dependency metadata is missing its string"};
                if (!account_name(*entry.string_value))
                    return Error{ErrorCode::resource_limit, "ELF dependency string exceeds its byte limit"};
                const auto offset = offset_of(table, entry);
                if (!offset) return Error{ErrorCode::malformed, "ELF dependency entry provenance overflows"};
                const auto &text = *entry.string_value;
                if (entry.tag == 1 || entry.tag == dt_auxiliary || entry.tag == dt_filter) {
                    if (report.raw_dependency_rows++ >= limits.dependency_rows)
                        return Error{ErrorCode::resource_limit, "ELF dependency row limit exceeded"};
                    // Preserve every declaration and its own source offset.
                    // Repeated names may be significant evidence in malformed
                    // or hand-authored dynamic tables.
                    ElfDependencyFileRow row;
                    row.kind = entry.tag == dt_auxiliary ? ElfDependencyFileRow::Kind::auxiliary
                              : entry.tag == dt_filter ? ElfDependencyFileRow::Kind::filter
                                                       : ElfDependencyFileRow::Kind::needed;
                    row.name = text;
                    row.dynamic_entry_file_offset = *offset;
                    if (row.kind == ElfDependencyFileRow::Kind::needed)
                        row.needed_entry_file_offset = *offset;
                    report.rows.push_back(std::move(row));
                } else {
                    if (entry.tag == 29) has_runpath = true;
                    auto &paths = entry.tag == 29 ? runpath : rpath;
                    for (std::size_t begin = 0;;) {
                        const auto end = text.find(':', begin);
                        const auto part = text.substr(begin, end == std::string::npos ? end : end - begin);
                        if (paths.size() >= limits.search_directories)
                            return Error{ErrorCode::resource_limit, "ELF dynamic search-directory limit exceeded"};
                        if (auto path = metadata_path(part, true))
                            paths.push_back({*path, entry.tag == 29 ? ElfDependencyPathSource::runpath
                                                                  : ElfDependencyPathSource::rpath, offset});
                        else ++(entry.tag == 29 ? unsupported_runpath : unsupported_rpath);
                        if (end == std::string::npos) break;
                        begin = end + 1;
                    }
                }
            }
        }
        if (!has_runpath) {
            report.inherited_rpath.reserve(rpath.size());
            for (const auto &directory : rpath)
                report.inherited_rpath.push_back({directory.path, ElfDependencyPathSource::rpath, directory.offset});
        }
        const auto applicable_unsupported = has_runpath ? unsupported_runpath : unsupported_rpath;
        const auto inherited_local_unsupported = has_runpath ? std::size_t{} : unsupported_rpath;
        const auto max_count = (std::numeric_limits<std::size_t>::max)();
        if (context.inherited_unsupported_rpath > max_count - applicable_unsupported ||
            context.inherited_unsupported_rpath > max_count - inherited_local_unsupported)
            return Error{ErrorCode::resource_limit, "ELF inherited unsupported-path count overflow"};
        report.inherited_unsupported_rpath = context.inherited_unsupported_rpath + inherited_local_unsupported;
        // glibc searches an object's RPATH (when RUNPATH is absent), inherited
        // ancestor RPATH, LD_LIBRARY_PATH, and then the object's RUNPATH.
        // This inventory retains every compatible candidate; this order is
        // provenance only and does not select a runtime link map.
        if (!has_runpath) search = std::move(rpath);
        for (const auto &directory : context.inherited_rpath) {
            if (search.size() >= limits.search_directories)
                return Error{ErrorCode::resource_limit, "ELF combined search-directory limit exceeded"};
            if (!directory.path.is_absolute() || !contained(directory.path.lexically_normal(), root))
                return Error{ErrorCode::invalid_argument,
                             "Inherited DT_RPATH directories must remain inside the sysroot"};
            search.push_back({directory.path, ElfDependencyPathSource::inherited_rpath,
                              directory.search_entry_file_offset});
        }
        for (const auto &directory : context.environment_directories) {
            if (search.size() >= limits.search_directories)
                return Error{ErrorCode::resource_limit, "ELF combined search-directory limit exceeded"};
            auto canonical = std::filesystem::canonical(directory, ec);
            if (ec || !contained(canonical, root) || !std::filesystem::is_directory(canonical, ec))
                return Error{ErrorCode::invalid_argument,
                             "LD_LIBRARY_PATH directories must exist inside the explicit sysroot"};
            search.push_back({canonical, ElfDependencyPathSource::environment_directory, {}});
        }
        if (has_runpath) {
            for (const auto &directory : runpath) {
                if (search.size() >= limits.search_directories)
                    return Error{ErrorCode::resource_limit, "ELF combined search-directory limit exceeded"};
                search.push_back(directory);
            }
        }
        for (const auto &directory : explicit_directories) {
            if (search.size() >= limits.search_directories)
                return Error{ErrorCode::resource_limit, "ELF combined search-directory limit exceeded"};
            auto canonical = std::filesystem::canonical(directory, ec);
            if (ec || !contained(canonical, root) || !std::filesystem::is_directory(canonical, ec))
                return Error{ErrorCode::invalid_argument, "Explicit dependency search directory is outside sysroot or missing"};
            search.push_back({canonical, ElfDependencyPathSource::explicit_directory, {}});
        }
        std::shared_ptr<const ElfGlibcCacheSnapshot> glibc_cache;
        if (context.use_glibc_ld_so_cache) {
            glibc_cache = context.glibc_cache;
            if (glibc_cache && glibc_cache->sysroot != root)
                return Error{ErrorCode::invalid_argument, "ELF cache snapshot belongs to another sysroot"};
            if (glibc_cache && (glibc_cache->bytes > limits.glibc_cache_bytes ||
                                glibc_cache->entries.size() > limits.glibc_cache_entries ||
                                glibc_cache->string_bytes > limits.glibc_cache_string_bytes))
                return Error{ErrorCode::resource_limit, "ELF cache snapshot exceeds configured limits"};
            if (glibc_cache && glibc_cache->entry_indices_by_name.size() > limits.glibc_cache_entries)
                return Error{ErrorCode::resource_limit, "ELF cache name index exceeds configured limits"};
            if (!glibc_cache) {
                auto loaded_cache = read_elf_glibc_cache(root, limits, stop);
                if (!loaded_cache) return loaded_cache.error();
                glibc_cache = std::move(loaded_cache.value());
            }
            report.glibc_cache_bytes = glibc_cache->bytes;
            report.glibc_cache_entries = glibc_cache->entries.size();
            report.unsupported_cache_formats = glibc_cache->unsupported_formats;
            report.unsupported_cache_entries = glibc_cache->unsupported_entries;
            report.cache_filesystem_errors = glibc_cache->filesystem_errors;
            if (!report.unsupported_cache_formats && glibc_cache->order != metadata.header.order)
                ++report.unsupported_cache_formats;
        }
        std::vector<SearchPath> default_search;
        if (context.use_standard_default_directories) {
            auto defaults = standard_default_dirs(metadata.header);
            if (defaults.size() > limits.search_directories)
                return Error{ErrorCode::resource_limit, "ELF default-directory limit exceeded"};
            default_search.reserve(defaults.size());
            for (auto &path : defaults)
                default_search.push_back({root / utf8_path(path).relative_path(),
                                          ElfDependencyPathSource::default_directory, {}});
            if (search.size() + default_search.size() > limits.search_directories)
                return Error{ErrorCode::resource_limit, "ELF combined default-directory limit exceeded"};
        }
        for (auto &row : report.rows) {
            const bool uses_search_path = !row.name.empty() &&
                row.name.find('/') == std::string::npos && row.name.find('$') == std::string::npos;
            row.unsupported_paths = uses_search_path
                ? applicable_unsupported + context.inherited_unsupported_rpath : 0;
            std::vector<SearchPath> paths;
            if (row.name.find('/') != std::string::npos || row.name.find('$') != std::string::npos) {
                const auto source = row.kind == ElfDependencyFileRow::Kind::auxiliary
                    ? ElfDependencyPathSource::auxiliary_path
                    : row.kind == ElfDependencyFileRow::Kind::filter ? ElfDependencyPathSource::filter_path
                                                                      : ElfDependencyPathSource::needed_path;
                if (auto path = metadata_path(row.name)) paths.push_back({*path, source, {}});
                else ++row.unsupported_paths;
            } else if (row.name.empty() || row.name.find('\\') != std::string::npos ||
                       row.name.find(':') != std::string::npos || row.name.find('\0') != std::string::npos) {
                ++row.unsupported_paths;
            } else {
                for (const auto &directory : search) {
                    auto candidate = directory;
                    candidate.path /= utf8_path(row.name);
                    paths.push_back(std::move(candidate));
                }
                if (context.use_glibc_ld_so_cache) {
                    if (report.unsupported_cache_formats) ++row.unsupported_paths;
                    const auto cached = report.unsupported_cache_formats
                        ? glibc_cache->entry_indices_by_name.end()
                        : glibc_cache->entry_indices_by_name.find(row.name);
                    if (cached != glibc_cache->entry_indices_by_name.end() &&
                        cached->second.size() > limits.glibc_cache_entries)
                        return Error{ErrorCode::resource_limit, "ELF cache name index row exceeds configured limits"};
                    if (cached != glibc_cache->entry_indices_by_name.end()) for (const auto index : cached->second) {
                        if (report.probes++ >= limits.probes)
                            return Error{ErrorCode::resource_limit, "ELF dependency path-probe limit exceeded"};
                        if ((index & 255u) == 0 && stop.stop_requested())
                            return Error{ErrorCode::canceled, "ELF dependency discovery canceled"};
                        if (index >= glibc_cache->entries.size()) {
                            ++row.unsupported_paths;
                            ++report.unsupported_cache_entries;
                            continue;
                        }
                        const auto &entry = glibc_cache->entries[index];
                        if (entry.name != row.name) {
                            ++row.unsupported_paths;
                            ++report.unsupported_cache_entries;
                            continue;
                        }
                        const auto entry_path = entry.path.generic_u8string();
                        if (entry.name.empty() || entry.name.size() > 32768 || entry_path.size() > 32768) {
                            ++row.unsupported_paths;
                            ++report.unsupported_cache_entries;
                            continue;
                        }
                        const auto abi = cache_abi_match(entry.flags, metadata.header);
                        if (abi == CacheAbiMatch::incompatible) continue;
                        if (abi == CacheAbiMatch::unsupported || entry.os_version != 0 || entry.hwcap != 0) {
                            ++row.unsupported_paths;
                            ++report.unsupported_cache_entries;
                            continue;
                        }
                        paths.push_back({root / entry.path.relative_path(), ElfDependencyPathSource::glibc_cache,
                                         {}});
                    }
                }
                paths.insert(paths.end(), default_search.begin(), default_search.end());
                for (std::size_t i = paths.size() - default_search.size(); i < paths.size(); ++i) {
                    if (!default_search.empty()) paths[i].path /= utf8_path(row.name);
                }
            }
            std::set<std::string> seen;
            for (const auto &candidate : paths) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "ELF dependency discovery canceled"};
                if (report.probes++ >= limits.probes)
                    return Error{ErrorCode::resource_limit, "ELF dependency path-probe limit exceeded"};
                const auto canonical = std::filesystem::canonical(candidate.path, ec);
                if (ec) {
                    if (ec != std::errc::no_such_file_or_directory && ec != std::errc::not_a_directory)
                        ++row.filesystem_errors;
                    ec.clear(); continue;
                }
                if (!contained(canonical, root)) { ++row.escaped_paths; continue; }
                if (!std::filesystem::is_regular_file(canonical, ec)) {
                    if (ec) ++row.filesystem_errors;
                    ec.clear(); continue;
                }
                const auto key = identity(canonical);
                if (!seen.insert(key).second) continue;
                if (report.candidates >= limits.candidates || key.size() > limits.path_bytes - report.path_bytes)
                    return Error{ErrorCode::resource_limit, "ELF dependency candidate/path-byte limit exceeded"};
                ++report.candidates;
                report.path_bytes += key.size();
                row.candidates.push_back({canonical, candidate.source, candidate.offset});
            }
        }
        return report;
    } catch (const std::filesystem::filesystem_error &error) {
        return Error{ErrorCode::io, std::string("ELF dependency filesystem error: ") + error.what()};
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate ELF dependency discovery report"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "ELF dependency discovery exceeds host limits"};
    }
}

Result<MachODependencyFileReport> discover_macho_dependency_files(
    const MachOMetadata &metadata, const std::filesystem::path &importer,
    const std::filesystem::path &sysroot, const MachODependencyPathContext &context,
    const MachODependencyDiscoveryLimits &limits, std::stop_token stop) {
    try {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Mach-O dependency discovery canceled"};
        std::error_code ec;
        const auto root = std::filesystem::canonical(sysroot, ec);
        if (ec || !std::filesystem::is_directory(root, ec))
            return Error{ErrorCode::invalid_argument, "Dependency sysroot must be an existing directory"};
        const auto source = std::filesystem::canonical(importer, ec);
        if (ec || !contained(source, root) || !std::filesystem::is_regular_file(source, ec))
            return Error{ErrorCode::invalid_argument, "Mach-O importer must be a regular file inside sysroot"};
        std::optional<std::filesystem::path> executable;
        if (context.executable_path) {
            executable = std::filesystem::canonical(*context.executable_path, ec);
            if (ec || !contained(*executable, root) || !std::filesystem::is_regular_file(*executable, ec))
                return Error{ErrorCode::invalid_argument, "Mach-O executable must be a regular file inside sysroot"};
        }
        if (context.inherited_rpaths.size() > limits.rpaths)
            return Error{ErrorCode::resource_limit, "Mach-O inherited LC_RPATH limit exceeded"};
        if (context.inherited_unsupported_rpaths > limits.rpaths - context.inherited_rpaths.size())
            return Error{ErrorCode::resource_limit, "Mach-O inherited LC_RPATH limit exceeded"};
        for (const auto &rpath : context.inherited_rpaths)
            if (!rpath.path.is_absolute() || !contained(rpath.path.lexically_normal(), root))
                return Error{ErrorCode::invalid_argument, "Inherited Mach-O LC_RPATH escapes the sysroot"};

        constexpr std::uint32_t lc_load_dylib = 0x0000000c;
        constexpr std::uint32_t lc_load_weak_dylib = 0x80000018;
        constexpr std::uint32_t lc_reexport_dylib = 0x8000001f;
        constexpr std::uint32_t lc_load_upward_dylib = 0x80000023;
        constexpr std::uint32_t lc_rpath = 0x8000001c;
        MachODependencyFileReport report;
        report.inherited_rpaths = context.inherited_rpaths;
        report.inherited_unsupported_rpaths = context.inherited_unsupported_rpaths;
        std::size_t own_unsupported_rpaths = 0;
        const auto append_checked = [&](std::string_view text, std::size_t &counter, std::size_t cap) {
            if (text.size() > 32768 || text.size() > cap - counter) return false;
            counter += text.size();
            return true;
        };
        struct ExpandedPath { std::filesystem::path path; MachODependencyPathSource source; };
        const auto expand_path = [&](std::string_view text, bool allow_rpath,
                                     MachODependencyPathSource &path_source)
            -> std::optional<std::filesystem::path> {
            if (text.empty() || text.size() > 32768 || text.find('\0') != std::string_view::npos ||
                text.find('\\') != std::string_view::npos) return {};
            const auto replace_prefix = [&](std::string_view token, const std::filesystem::path &base,
                                            MachODependencyPathSource source_kind)
                -> std::optional<std::filesystem::path> {
                if (text != token && !(text.size() > token.size() && text.starts_with(token) &&
                                       text[token.size()] == '/')) return {};
                if (!base.is_absolute()) return {};
                auto suffix = text.size() == token.size() ? std::filesystem::path{} : utf8_path(text.substr(token.size() + 1));
                if (suffix.is_absolute()) return {};
                path_source = source_kind;
                return (base / suffix).lexically_normal();
            };
            if (text.starts_with("@loader_path"))
                return replace_prefix("@loader_path", source.parent_path(), MachODependencyPathSource::loader_path);
            if (text.starts_with("@executable_path")) {
                if (!executable) return {};
                return replace_prefix("@executable_path", executable->parent_path(), MachODependencyPathSource::executable_path);
            }
            if (text.starts_with("@rpath/")) {
                if (!allow_rpath) return {};
                return {};
            }
            if (text.front() == '@') return {};
            if (text.front() == '/') {
                path_source = MachODependencyPathSource::install_name;
                return (root / utf8_path(text).relative_path()).lexically_normal();
            }
            // Plain relative LC_RPATH values have process-CWD semantics which
            // are not guessed. Ordinary non-token install names are rooted in
            // the explicit sysroot as an offline image path.
            if (allow_rpath) return {};
            path_source = MachODependencyPathSource::install_name;
            return (root / utf8_path(text)).lexically_normal();
        };

        std::vector<MachORPathDirectory> own_rpaths;
        for (const auto &path : metadata.paths) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Mach-O dependency discovery canceled"};
            if (report.metadata_entries++ >= limits.metadata_entries)
                return Error{ErrorCode::resource_limit, "Mach-O dependency metadata-entry limit exceeded"};
            if (path.command != lc_rpath) continue;
            if (!append_checked(path.name, report.name_bytes, limits.name_bytes))
                return Error{ErrorCode::resource_limit, "Mach-O dependency-name byte limit exceeded"};
            if (own_rpaths.size() + context.inherited_rpaths.size() >= limits.rpaths)
                return Error{ErrorCode::resource_limit, "Mach-O LC_RPATH limit exceeded"};
            MachODependencyPathSource kind = MachODependencyPathSource::install_name;
            auto expanded = expand_path(path.name, false, kind);
            if (!expanded) { ++own_unsupported_rpaths; continue; }
            if (!expanded->is_absolute() || !contained(expanded->lexically_normal(), root)) {
                ++own_unsupported_rpaths;
                continue;
            }
            own_rpaths.push_back({*expanded, path.record_file_offset});
        }
        const auto max_count = (std::numeric_limits<std::size_t>::max)();
        if (report.inherited_unsupported_rpaths > max_count - own_unsupported_rpaths)
            return Error{ErrorCode::resource_limit, "Mach-O inherited unsupported-path count overflow"};
        report.inherited_unsupported_rpaths += own_unsupported_rpaths;
        report.inherited_rpaths.insert(report.inherited_rpaths.end(), own_rpaths.begin(), own_rpaths.end());

        for (const auto &library : metadata.libraries) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Mach-O dependency discovery canceled"};
            if (report.metadata_entries++ >= limits.metadata_entries)
                return Error{ErrorCode::resource_limit, "Mach-O dependency metadata-entry limit exceeded"};
            if (library.command != lc_load_dylib && library.command != lc_load_weak_dylib &&
                library.command != lc_reexport_dylib && library.command != lc_load_upward_dylib) continue;
            if (report.rows.size() >= limits.dependency_rows)
                return Error{ErrorCode::resource_limit, "Mach-O dependency row limit exceeded"};
            if (!append_checked(library.name, report.name_bytes, limits.name_bytes))
                return Error{ErrorCode::resource_limit, "Mach-O dependency-name byte limit exceeded"};
            MachODependencyFileRow row{library.name, library.command, library.command_index,
                                       library.record_file_offset};
            const auto name = std::string_view(library.name);
            if (name.starts_with("@rpath/")) {
                const auto suffix = utf8_path(name.substr(7));
                if (suffix.empty() || suffix.is_absolute() || report.inherited_rpaths.empty()) {
                    row.unsupported_paths += report.inherited_unsupported_rpaths + 1;
                } else {
                    row.unsupported_paths += report.inherited_unsupported_rpaths;
                    for (const auto &rpath : report.inherited_rpaths) {
                        if (row.candidates.size() >= limits.rpaths)
                            return Error{ErrorCode::resource_limit, "Mach-O per-import LC_RPATH probe limit exceeded"};
                        row.candidates.push_back({(rpath.path / suffix).lexically_normal(),
                            MachODependencyPathSource::rpath, library.command_index,
                            library.record_file_offset, rpath.command_file_offset});
                    }
                }
            } else {
                MachODependencyPathSource kind = MachODependencyPathSource::install_name;
                auto expanded = expand_path(name, false, kind);
                if (!expanded) ++row.unsupported_paths;
                else row.candidates.push_back({*expanded, kind, library.command_index,
                                               library.record_file_offset, {}});
            }
            // Canonicalize each exact candidate, retaining only regular files
            // inside the explicit root. No directory scan or host fallback is used.
            std::vector<MachODependencyFileCandidate> retained;
            std::set<std::string> seen;
            for (auto candidate : row.candidates) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Mach-O dependency discovery canceled"};
                if (!contained(candidate.path.lexically_normal(), root)) {
                    ++row.escaped_paths;
                    continue;
                }
                if (report.probes++ >= limits.probes)
                    return Error{ErrorCode::resource_limit, "Mach-O dependency path-probe limit exceeded"};
                const auto canonical = std::filesystem::canonical(candidate.path, ec);
                if (ec) {
                    if (ec != std::errc::no_such_file_or_directory && ec != std::errc::not_a_directory)
                        ++row.filesystem_errors;
                    ec.clear();
                    continue;
                }
                if (!contained(canonical, root)) { ++row.escaped_paths; continue; }
                if (!std::filesystem::is_regular_file(canonical, ec)) {
                    if (ec) ++row.filesystem_errors;
                    ec.clear();
                    continue;
                }
                const auto key = identity(canonical);
                if (!seen.insert(key).second) continue;
                if (report.candidates >= limits.candidates || key.size() > limits.path_bytes - report.path_bytes)
                    return Error{ErrorCode::resource_limit, "Mach-O dependency candidate/path-byte limit exceeded"};
                ++report.candidates;
                report.path_bytes += key.size();
                candidate.path = canonical;
                retained.push_back(std::move(candidate));
            }
            row.candidates = std::move(retained);
            report.rows.push_back(std::move(row));
        }
        return report;
    } catch (const std::filesystem::filesystem_error &error) {
        return Error{ErrorCode::io, std::string("Mach-O dependency filesystem error: ") + error.what()};
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate Mach-O dependency discovery report"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "Mach-O dependency discovery exceeds host limits"};
    }
}
}

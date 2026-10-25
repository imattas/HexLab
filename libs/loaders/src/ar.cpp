#include "hexlab/loaders/ar.hpp"
#include <algorithm>
#include <charconv>
#include <limits>
#include <map>
#include <optional>
#include <unordered_map>
#include <unordered_set>

namespace hexlab {
namespace {
struct Failure { Error error; };
void require(bool condition, const char *message, ErrorCode code = ErrorCode::malformed) {
    if (!condition) throw Failure{{code, message}};
}
void canceled(std::stop_token stop) { require(!stop.stop_requested(), "ar operation canceled", ErrorCode::canceled); }
std::uint64_t add(std::uint64_t a, std::uint64_t b) {
    require(b <= UINT64_MAX - a, "ar extent overflow", ErrorCode::overflow);
    return a + b;
}
class Reader {
  public:
    Reader(const ByteStorage &source, std::stop_token stop) : source(source), stop(stop) {}
    std::vector<std::byte> read(std::uint64_t offset, std::uint64_t count) const {
        canceled(stop);
        require(offset <= source.size() && count <= source.size() - offset, "ar range exceeds input");
        require(count <= std::numeric_limits<std::size_t>::max(), "ar read exceeds host address space", ErrorCode::resource_limit);
        auto view = source.read_at({offset}, static_cast<std::size_t>(count));
        if (!view) throw Failure{view.error()};
        require(view.value().bytes.size() == count, "incomplete ar storage view", ErrorCode::io);
        canceled(stop);
        return {view.value().bytes.begin(), view.value().bytes.end()};
    }
    const ByteStorage &source;
    std::stop_token stop;
};
std::string field(std::span<const std::byte> bytes) {
    std::string value;
    value.reserve(bytes.size());
    for (const auto b : bytes) value.push_back(static_cast<char>(std::to_integer<unsigned char>(b)));
    return value;
}
std::uint64_t number(std::span<const std::byte> bytes, unsigned base, const char *message) {
    auto text = field(bytes);
    const auto first = text.find_first_not_of(' ');
    if (first == std::string::npos) return 0;
    const auto last = text.find_last_not_of(' ');
    text = text.substr(first, last - first + 1);
    std::uint64_t value = 0;
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value, base);
    require(result.ec == std::errc{} && result.ptr == text.data() + text.size(), message);
    return value;
}
std::uint32_t be32(std::span<const std::byte> bytes, std::size_t at) {
    require(at <= bytes.size() && bytes.size() - at >= 4, "truncated GNU ar symbol index");
    return (std::to_integer<std::uint32_t>(bytes[at]) << 24) |
           (std::to_integer<std::uint32_t>(bytes[at + 1]) << 16) |
           (std::to_integer<std::uint32_t>(bytes[at + 2]) << 8) |
           std::to_integer<std::uint32_t>(bytes[at + 3]);
}
std::uint64_t be64(std::span<const std::byte> bytes, std::size_t at) {
    require(at <= bytes.size() && bytes.size() - at >= 8, "truncated GNU ar 64-bit symbol index");
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8; ++i)
        value = (value << 8) | std::to_integer<std::uint64_t>(bytes[at + i]);
    return value;
}
struct PendingSymbol { std::string name; std::uint64_t header = 0; };
std::uint64_t bsd_word(std::span<const std::byte> bytes, std::size_t at, std::size_t width, bool little_endian) {
    require(width == 4 || width == 8, "invalid BSD ranlib word width");
    require(at <= bytes.size() && bytes.size() - at >= width, "truncated BSD ranlib index");
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < width; ++i) {
        const auto index = little_endian ? width - i - 1 : i;
        value = (value << 8) | std::to_integer<std::uint64_t>(bytes[at + index]);
    }
    return value;
}
std::optional<std::vector<PendingSymbol>> decode_bsd_index(std::span<const std::byte> bytes,
                                                           std::size_t width, bool little_endian,
                                                           std::size_t max_symbols, std::size_t max_name_bytes,
                                                           std::stop_token stop) {
    try {
        if (bytes.size() < width * 2) return {};
        const auto ranlib_bytes = bsd_word(bytes, 0, width, little_endian);
        if (ranlib_bytes % (2 * width) != 0 || ranlib_bytes > bytes.size() - width * 2) return {};
        const auto count = ranlib_bytes / (2 * width);
        if (count > max_symbols) return {};
        const auto string_size_at = width + static_cast<std::size_t>(ranlib_bytes);
        const auto string_size = bsd_word(bytes, string_size_at, width, little_endian);
        if (string_size != bytes.size() - string_size_at - width) return {};
        const auto strings_at = string_size_at + width;
        std::vector<PendingSymbol> result;
        result.reserve(static_cast<std::size_t>(count));
        for (std::size_t i = 0; i < count; ++i) {
            canceled(stop);
            const auto entry = width + i * 2 * width;
            const auto name_offset = bsd_word(bytes, entry, width, little_endian);
            const auto member_offset = bsd_word(bytes, entry + width, width, little_endian);
            if (name_offset >= string_size) return {};
            const auto start = strings_at + static_cast<std::size_t>(name_offset);
            auto end = start;
            while (end < bytes.size() && bytes[end] != std::byte{0}) ++end;
            if (end == bytes.size() || end - start == 0 || end - start > max_name_bytes) return {};
            result.push_back({field(bytes.subspan(start, end - start)), member_offset});
        }
        return result;
    } catch (const Failure &failure) {
        if (failure.error.code == ErrorCode::canceled) throw;
        return {};
    }
}
std::string trim_ar_name(std::string name) {
    while (!name.empty() && name.back() == ' ') name.pop_back();
    if (!name.empty() && name.back() == '/') name.pop_back();
    return name;
}
class MemberStorage final : public ByteStorage {
  public:
    MemberStorage(std::shared_ptr<const ByteStorage> source, ArMember member)
        : source_(std::move(source)), member_(std::move(member)) {}
    std::uint64_t size() const noexcept override { return member_.size; }
    Result<ByteView> read_at(FileOffset offset, std::size_t count) const override {
        if (offset.value > member_.size || count > member_.size - offset.value)
            return Error{ErrorCode::out_of_bounds, "ar member read exceeds bounded view"};
        return source_->read_at({member_.data_offset.value + offset.value}, count);
    }
  private:
    std::shared_ptr<const ByteStorage> source_;
    ArMember member_;
};
}

Result<ArArchive> read_ar_archive(const ByteStorage &storage, std::stop_token stop, ArLimits limits) {
    try {
        canceled(stop);
        require(limits.max_members != 0 && limits.max_name_bytes != 0 && limits.max_symbols != 0,
                "ar limits must be positive", ErrorCode::invalid_argument);
        Reader reader(storage, stop);
        constexpr std::string_view magic = "!<arch>\n";
        const auto signature = reader.read(0, magic.size());
        require(field(signature) != "!<thin>\n", "thin ar archives are not supported", ErrorCode::unsupported);
        require(field(signature) == magic, "invalid ar archive signature");
        ArArchive archive;
        std::vector<std::byte> long_names;
        std::vector<PendingSymbol> pending_symbols;
        std::map<std::uint64_t, std::size_t> member_by_header;
        std::uint64_t cursor = magic.size();
        while (cursor < storage.size()) {
            canceled(stop);
            require(archive.members.size() < limits.max_members, "ar member count limit exceeded", ErrorCode::resource_limit);
            require(storage.size() - cursor >= 60, "truncated ar member header");
            const auto header = reader.read(cursor, 60);
            require(header[58] == std::byte{'`'} && header[59] == std::byte{'\n'}, "invalid ar member trailer");
            std::string raw_name = field(std::span(header).subspan(0, 16));
            while (!raw_name.empty() && raw_name.back() == ' ') raw_name.pop_back();
            const auto raw_size = number(std::span(header).subspan(48, 10), 10, "invalid ar member size");
            const auto data_start = add(cursor, 60);
            require(raw_size <= storage.size() - data_start, "ar member data exceeds input");
            std::string name;
            ArMemberKind kind = ArMemberKind::regular;
            std::uint64_t payload_offset = data_start, payload_size = raw_size;
            if (raw_name == "//") { name = "//"; kind = ArMemberKind::long_name_table; }
            else if (raw_name == "/" || raw_name == "/SYM64/") { name = raw_name; kind = ArMemberKind::symbol_index; }
            else if (raw_name.starts_with("__.SYMDEF")) {
                name = raw_name;
                kind = ArMemberKind::symbol_index;
            } else if (raw_name.starts_with("#1/")) {
                const auto inline_name_size = number(std::as_bytes(std::span(raw_name.data() + 3, raw_name.size() - 3)), 10,
                                                    "invalid BSD ar extended name length");
                require(inline_name_size <= raw_size && inline_name_size <= limits.max_name_bytes,
                        "BSD ar extended name exceeds limits", ErrorCode::resource_limit);
                const auto inline_name = reader.read(data_start, inline_name_size);
                name = field(inline_name);
                while (!name.empty() && name.back() == '\0') name.pop_back();
                payload_offset = add(payload_offset, inline_name_size);
                payload_size -= inline_name_size;
            } else if (raw_name.size() > 1 && raw_name[0] == '/' && raw_name[1] >= '0' && raw_name[1] <= '9') {
                const auto offset = number(std::as_bytes(std::span(raw_name.data() + 1, raw_name.size() - 1)), 10,
                                           "invalid GNU ar long-name offset");
                require(offset < long_names.size(), "GNU ar long-name offset out of range");
                require(offset == 0 || long_names[static_cast<std::size_t>(offset - 1)] == std::byte{'\n'},
                        "GNU ar long-name offset does not point to an entry boundary");
                auto end = offset;
                while (end < long_names.size() && long_names[end] != std::byte{'\n'} &&
                       !(long_names[end] == std::byte{'/'} && end + 1 < long_names.size() &&
                         long_names[end + 1] == std::byte{'\n'}))
                    ++end;
                require(end < long_names.size() && end > offset && end - offset <= limits.max_name_bytes,
                        "unterminated or oversized GNU ar long name");
                name = field(std::span(long_names).subspan(static_cast<std::size_t>(offset), static_cast<std::size_t>(end - offset)));
            } else name = trim_ar_name(raw_name);
            require(!name.empty() || kind != ArMemberKind::regular, "empty ar member name");
            const std::size_t index = archive.members.size();
            archive.members.push_back({std::move(name), {cursor}, {payload_offset}, payload_size, kind});
            member_by_header.emplace(cursor, index);

            if (kind == ArMemberKind::long_name_table) {
                require(raw_size <= 64ULL * 1024 * 1024, "GNU ar long-name table exceeds metadata budget", ErrorCode::resource_limit);
                long_names = reader.read(data_start, raw_size);
            } else if (kind == ArMemberKind::symbol_index && raw_name == "/") {
                archive.has_symbol_index = true;
                require(raw_size <= 256ULL * 1024 * 1024, "GNU ar symbol index exceeds metadata budget", ErrorCode::resource_limit);
                const auto bytes = reader.read(data_start, raw_size);
                const auto count = be32(bytes, 0);
                require(count <= limits.max_symbols, "GNU ar symbol count limit exceeded", ErrorCode::resource_limit);
                require(count <= (bytes.size() - 4) / 4, "truncated GNU ar member-offset array");
                std::size_t names_at = 4 + static_cast<std::size_t>(count) * 4;
                for (std::uint32_t i = 0; i < count; ++i) {
                    canceled(stop);
                    const auto offset = be32(bytes, 4 + static_cast<std::size_t>(i) * 4);
                    const auto terminator = std::find(bytes.begin() + static_cast<std::ptrdiff_t>(names_at), bytes.end(), std::byte{0});
                    require(terminator != bytes.end(), "unterminated GNU ar symbol name");
                    const auto length = static_cast<std::size_t>(terminator - (bytes.begin() + static_cast<std::ptrdiff_t>(names_at)));
                    require(length > 0 && length <= limits.max_name_bytes, "invalid GNU ar symbol name length", ErrorCode::resource_limit);
                    pending_symbols.push_back({field(std::span(bytes).subspan(names_at, length)), offset});
                    names_at += length + 1;
                }
                require(names_at == bytes.size(), "unexpected trailing bytes in GNU ar symbol index");
            } else if (kind == ArMemberKind::symbol_index && raw_name == "/SYM64/") {
                archive.has_symbol_index = true;
                require(raw_size <= 256ULL * 1024 * 1024, "GNU ar symbol index exceeds metadata budget", ErrorCode::resource_limit);
                const auto bytes = reader.read(data_start, raw_size);
                const auto count = be64(bytes, 0);
                require(count <= limits.max_symbols, "GNU ar symbol count limit exceeded", ErrorCode::resource_limit);
                require(count <= (bytes.size() - 8) / 8, "truncated GNU ar 64-bit member-offset array");
                std::size_t names_at = 8 + static_cast<std::size_t>(count) * 8;
                for (std::uint64_t i = 0; i < count; ++i) {
                    canceled(stop);
                    const auto offset = be64(bytes, 8 + static_cast<std::size_t>(i) * 8);
                    const auto terminator = std::find(bytes.begin() + static_cast<std::ptrdiff_t>(names_at), bytes.end(), std::byte{0});
                    require(terminator != bytes.end(), "unterminated GNU ar symbol name");
                    const auto length = static_cast<std::size_t>(terminator - (bytes.begin() + static_cast<std::ptrdiff_t>(names_at)));
                    require(length > 0 && length <= limits.max_name_bytes, "invalid GNU ar symbol name length", ErrorCode::resource_limit);
                    pending_symbols.push_back({field(std::span(bytes).subspan(names_at, length)), offset});
                    names_at += length + 1;
                }
                require(names_at == bytes.size(), "unexpected trailing bytes in GNU ar symbol index");
            } else if (kind == ArMemberKind::symbol_index && raw_name.starts_with("__.SYMDEF")) {
                archive.has_symbol_index = true;
                require(raw_size <= 256ULL * 1024 * 1024, "BSD ranlib index exceeds metadata budget", ErrorCode::resource_limit);
                const auto bytes = reader.read(data_start, raw_size);
                const std::size_t width = raw_name.find("_64") != std::string::npos ? 8 : 4;
                auto decoded = decode_bsd_index(bytes, width, true, limits.max_symbols, limits.max_name_bytes, stop);
                if (!decoded) decoded = decode_bsd_index(bytes, width, false, limits.max_symbols, limits.max_name_bytes, stop);
                if (decoded) {
                    pending_symbols.insert(pending_symbols.end(),
                                           std::make_move_iterator(decoded->begin()),
                                           std::make_move_iterator(decoded->end()));
                } else {
                    archive.symbol_index_complete = false;
                    archive.diagnostics.emplace_back("BSD ranlib symbol index has an unsupported or malformed layout; member listing and extraction remain available");
                }
            }

            cursor = add(data_start, raw_size);
            if (raw_size & 1) {
                require(cursor < storage.size(), "missing ar member alignment byte");
                require(reader.read(cursor, 1)[0] == std::byte{'\n'}, "invalid ar member alignment byte");
                ++cursor;
            }
        }
        require(cursor == storage.size(), "ar archive has trailing partial member");
        for (auto &symbol : pending_symbols) {
            canceled(stop);
            const auto found = member_by_header.find(symbol.header);
            require(found != member_by_header.end() && archive.members[found->second].kind == ArMemberKind::regular,
                    "ar symbol index references unknown or special member");
            archive.symbols.push_back({std::move(symbol.name), found->second});
        }
        return archive;
    } catch (const Failure &failure) { return failure.error; }
}

Result<ArSymbolSelection> select_ar_members(const ArArchive &archive,
                                            std::span<const std::string_view> unresolved_symbols) {
    std::unordered_map<std::string_view, std::size_t> first_definition;
    first_definition.reserve(archive.symbols.size());
    for (const auto &symbol : archive.symbols) {
        if (symbol.name.empty())
            return Error{ErrorCode::malformed, "ar symbol index contains an empty symbol name"};
        if (symbol.member_index >= archive.members.size())
            return Error{ErrorCode::malformed, "ar symbol references an invalid member index"};
        if (archive.members[symbol.member_index].kind != ArMemberKind::regular)
            return Error{ErrorCode::malformed, "ar symbol references a non-regular member"};
        if (!symbol.name.empty()) first_definition.try_emplace(symbol.name, symbol.member_index);
    }

    ArSymbolSelection selection;
    selection.archive_index_complete = archive.symbol_index_complete;
    std::unordered_set<std::size_t> selected;
    std::unordered_set<std::string_view> visited;
    for (const auto name : unresolved_symbols) {
        if (name.empty() || !visited.insert(name).second) continue;
        const auto found = first_definition.find(name);
        if (found == first_definition.end()) {
            selection.unresolved_symbols.emplace_back(name);
            continue;
        }
        if (selected.insert(found->second).second) selection.member_indices.push_back(found->second);
    }
    return selection;
}

Result<ArSymbolLookup> lookup_ar_member_by_symbol(const ArArchive &archive, std::string_view requested) {
    if (requested.empty())
        return Error{ErrorCode::invalid_argument, "ar symbol lookup requires a nonempty name"};
    ArSymbolLookup result{std::nullopt, archive.has_symbol_index, archive.symbol_index_complete};
    for (const auto &symbol : archive.symbols) {
        if (symbol.name.empty())
            return Error{ErrorCode::malformed, "ar symbol index contains an empty symbol name"};
        if (symbol.member_index >= archive.members.size())
            return Error{ErrorCode::malformed, "ar symbol references an invalid member index"};
        if (archive.members[symbol.member_index].kind != ArMemberKind::regular)
            return Error{ErrorCode::malformed, "ar symbol references a non-regular member"};
        if (!result.member_index && symbol.name == requested)
            result.member_index = symbol.member_index;
    }
    return result;
}

Result<ArLinkSelection> select_ar_members_fixed_point(
    const ArArchive &archive, std::span<const ArMemberSymbols> summaries,
    std::span<const std::string_view> unresolved_symbols,
    std::span<const std::string_view> already_defined, std::stop_token stop, ArLinkLimits limits) {
    try {
        canceled(stop);
        require(limits.max_selected_members != 0 && limits.max_symbol_work != 0,
                "ar link limits must be positive", ErrorCode::invalid_argument);
        std::vector<const ArMemberSymbols *> by_member(archive.members.size(), nullptr);
        std::size_t work = 0;
        for (const auto &summary : summaries) {
            canceled(stop);
            require(summary.member_index < archive.members.size(), "ar object summary references invalid member", ErrorCode::malformed);
            require(archive.members[summary.member_index].kind == ArMemberKind::regular,
                    "ar object summary references non-regular member", ErrorCode::malformed);
            require(by_member[summary.member_index] == nullptr, "duplicate ar object summary", ErrorCode::malformed);
            require(summary.definitions.size() <= limits.max_symbol_work - work,
                    "ar link symbol work limit exceeded", ErrorCode::resource_limit);
            work += summary.definitions.size();
            require(summary.undefined.size() <= limits.max_symbol_work - work,
                    "ar link symbol work limit exceeded", ErrorCode::resource_limit);
            work += summary.undefined.size();
            by_member[summary.member_index] = &summary;
        }
        std::unordered_set<std::string> resolved;
        for (const auto name : already_defined) if (!name.empty()) resolved.emplace(name);
        std::vector<std::string> pending;
        std::unordered_set<std::string> pending_set;
        auto enqueue = [&](std::string_view name) {
            if (name.empty() || resolved.contains(std::string(name))) return;
            if (pending_set.emplace(name).second) pending.emplace_back(name);
        };
        for (const auto name : unresolved_symbols) enqueue(name);

        ArLinkSelection result;
        std::vector<bool> selected(archive.members.size(), false);
        bool progress = true;
        while (progress) {
            canceled(stop);
            progress = false;
            for (std::size_t index = 0; index < archive.members.size(); ++index) {
                canceled(stop);
                if (selected[index] || by_member[index] == nullptr) continue;
                const auto &summary = *by_member[index];
                ArSelectedMember chosen;
                chosen.member_index = index;
                std::unordered_set<std::string_view> triggers;
                for (const auto &definition : summary.definitions) {
                    require(++work <= limits.max_symbol_work, "ar link symbol work limit exceeded", ErrorCode::resource_limit);
                    if (definition.empty() || resolved.contains(definition)) continue;
                    if (pending_set.contains(definition) && triggers.emplace(definition).second)
                        chosen.selected_for.push_back(definition);
                }
                if (chosen.selected_for.empty()) continue;
                require(result.members.size() < limits.max_selected_members,
                        "ar selected member limit exceeded", ErrorCode::resource_limit);
                selected[index] = true;
                for (const auto &definition : summary.definitions) {
                    require(++work <= limits.max_symbol_work, "ar link symbol work limit exceeded", ErrorCode::resource_limit);
                    if (definition.empty()) continue;
                    resolved.emplace(definition);
                    pending_set.erase(definition);
                }
                for (const auto &undefined : summary.undefined) {
                    require(++work <= limits.max_symbol_work, "ar link symbol work limit exceeded", ErrorCode::resource_limit);
                    enqueue(undefined);
                }
                result.members.push_back(std::move(chosen));
                progress = true;
            }
        }
        for (const auto &name : pending) if (pending_set.contains(name)) result.unresolved_symbols.push_back(name);
        return result;
    } catch (const Failure &failure) { return failure.error; }
      catch (const std::bad_alloc &) { return Error{ErrorCode::resource_limit, "Cannot allocate ar link selection state"}; }
}

Result<LoadedArchive> load_ar_archive(std::shared_ptr<const ByteStorage> storage, std::stop_token stop, ArLimits limits) {
    if (!storage)
        return Error{ErrorCode::invalid_argument, "Archive loading requires byte storage"};
    auto archive = read_ar_archive(*storage, stop, limits);
    if (!archive)
        return archive.error();
    return LoadedArchive{std::move(storage), std::move(archive.value())};
}

Result<std::shared_ptr<const ByteStorage>> open_ar_member(std::shared_ptr<const ByteStorage> storage,
                                                          const ArMember &member) {
    if (!storage)
        return Error{ErrorCode::invalid_argument, "ar member view requires source storage"};
    if (member.kind != ArMemberKind::regular)
        return Error{ErrorCode::invalid_argument, "cannot open an ar special member as object storage"};
    if (member.data_offset.value > storage->size() || member.size > storage->size() - member.data_offset.value)
        return Error{ErrorCode::malformed, "ar member extent exceeds source storage"};
    try {
        return std::shared_ptr<const ByteStorage>(std::make_shared<MemberStorage>(std::move(storage), member));
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate ar member storage view"};
    }
}

Result<std::vector<std::byte>> extract_ar_member(const ByteStorage &storage, const ArMember &member,
                                                 std::stop_token stop, ArLimits limits) {
    try {
        canceled(stop);
        require(member.kind == ArMemberKind::regular, "cannot extract ar special member", ErrorCode::invalid_argument);
        require(member.size <= limits.max_extracted_bytes, "ar member exceeds extraction limit", ErrorCode::resource_limit);
        require(member.data_offset.value <= storage.size() && member.size <= storage.size() - member.data_offset.value,
                "ar member extent exceeds input");
        std::vector<std::byte> result;
        result.reserve(static_cast<std::size_t>(member.size));
        constexpr std::size_t chunk_size = 1024 * 1024;
        std::uint64_t offset = 0;
        while (offset < member.size) {
            canceled(stop);
            const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(chunk_size, member.size - offset));
            auto view = storage.read_at({member.data_offset.value + offset}, count);
            if (!view) throw Failure{view.error()};
            require(view.value().bytes.size() == count, "incomplete ar member read", ErrorCode::io);
            result.insert(result.end(), view.value().bytes.begin(), view.value().bytes.end());
            offset += count;
        }
        canceled(stop);
        return result;
    } catch (const Failure &failure) { return failure.error; }
}
} // namespace hexlab

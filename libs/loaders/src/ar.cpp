#include "hexlab/loaders/ar.hpp"
#include <algorithm>
#include <charconv>
#include <limits>
#include <map>
#include <mutex>
#include <new>
#include <optional>
#include <stdexcept>
#include <filesystem>
#include <memory>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

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
std::optional<std::vector<PendingSymbol>> decode_gnu_index(std::span<const std::byte> bytes,
                                                           std::size_t width,
                                                           std::size_t max_symbols,
                                                           std::size_t max_name_bytes,
                                                           std::stop_token stop) {
    try {
        require(width == 4 || width == 8, "invalid GNU ar symbol-index word width");
        require(bytes.size() >= width, "truncated GNU ar symbol index");
        const auto count = width == 4 ? static_cast<std::uint64_t>(be32(bytes, 0)) : be64(bytes, 0);
        require(count <= max_symbols, "GNU ar symbol count limit exceeded", ErrorCode::resource_limit);
        require(count <= (bytes.size() - width) / width, "truncated GNU ar member-offset array");
        std::size_t names_at = width + static_cast<std::size_t>(count) * width;
        std::vector<PendingSymbol> result;
        result.reserve(static_cast<std::size_t>(count));
        for (std::uint64_t i = 0; i < count; ++i) {
            canceled(stop);
            const auto offset_at = width + static_cast<std::size_t>(i) * width;
            const auto offset = width == 4 ? static_cast<std::uint64_t>(be32(bytes, offset_at)) : be64(bytes, offset_at);
            const auto names_begin = bytes.begin() + static_cast<std::ptrdiff_t>(names_at);
            const auto terminator = std::find(names_begin, bytes.end(), std::byte{0});
            require(terminator != bytes.end(), "unterminated GNU ar symbol name");
            const auto length = static_cast<std::size_t>(terminator - names_begin);
            require(length > 0 && length <= max_name_bytes, "invalid GNU ar symbol name length", ErrorCode::resource_limit);
            result.push_back({field(bytes.subspan(names_at, length)), offset});
            names_at += length + 1;
        }
        require(names_at == bytes.size(), "unexpected trailing bytes in GNU ar symbol index");
        return result;
    } catch (const Failure &failure) {
        if (failure.error.code == ErrorCode::malformed || failure.error.code == ErrorCode::resource_limit)
            return {};
        throw;
    }
}
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
std::optional<std::vector<PendingSymbol>> decode_aix_index(std::span<const std::byte> bytes,
                                                           std::size_t max_symbols,
                                                           std::size_t max_name_bytes,
                                                           std::stop_token stop) {
    try {
        require(bytes.size() >= 8, "truncated AIX big ar symbol index");
        const auto count = be64(bytes, 0);
        require(count <= max_symbols, "AIX big ar symbol count limit exceeded", ErrorCode::resource_limit);
        require(count <= (bytes.size() - 8) / 8, "truncated AIX big ar symbol offsets");
        std::size_t names_at = 8 + static_cast<std::size_t>(count) * 8;
        std::vector<PendingSymbol> result;
        result.reserve(static_cast<std::size_t>(count));
        for (std::uint64_t index = 0; index < count; ++index) {
            canceled(stop);
            const auto member_offset = be64(bytes, 8 + static_cast<std::size_t>(index) * 8);
            const auto terminator = std::find(bytes.begin() + static_cast<std::ptrdiff_t>(names_at), bytes.end(),
                                              std::byte{0});
            require(terminator != bytes.end(), "unterminated AIX big ar symbol name");
            const auto length = static_cast<std::size_t>(terminator - (bytes.begin() + static_cast<std::ptrdiff_t>(names_at)));
            require(length != 0 && length <= max_name_bytes, "invalid AIX big ar symbol name length",
                    ErrorCode::resource_limit);
            result.push_back({field(bytes.subspan(names_at, length)), member_offset});
            names_at += length + 1;
        }
        require(names_at == bytes.size(), "unexpected trailing bytes in AIX big ar symbol index");
        return result;
    } catch (const Failure &failure) {
        if (failure.error.code == ErrorCode::malformed || failure.error.code == ErrorCode::resource_limit)
            return {};
        throw;
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

class ThinSnapshot final : public ByteStorage, public std::enable_shared_from_this<ThinSnapshot> {
  public:
    explicit ThinSnapshot(std::vector<std::byte> bytes) : bytes_(std::move(bytes)) {}
    std::uint64_t size() const noexcept override { return bytes_.size(); }
    Result<ByteView> read_at(FileOffset offset, std::size_t count) const override {
        if (offset.value > bytes_.size() || count > bytes_.size() - static_cast<std::size_t>(offset.value))
            return Error{ErrorCode::out_of_bounds, "thin ar snapshot read exceeds its bounded view"};
        return ByteView{shared_from_this(), std::span<const std::byte>(bytes_).subspan(
            static_cast<std::size_t>(offset.value), count)};
    }
  private:
    std::vector<std::byte> bytes_;
};

bool valid_utf8(std::string_view value) {
    std::size_t at = 0;
    while (at < value.size()) {
        const auto first = static_cast<unsigned char>(value[at++]);
        if (first < 0x80) continue;
        unsigned continuation = 0;
        std::uint32_t scalar = 0;
        if (first >= 0xc2 && first <= 0xdf) { continuation = 1; scalar = first & 0x1f; }
        else if (first >= 0xe0 && first <= 0xef) { continuation = 2; scalar = first & 0x0f; }
        else if (first >= 0xf0 && first <= 0xf4) { continuation = 3; scalar = first & 0x07; }
        else return false;
        if (continuation > value.size() - at) return false;
        for (unsigned i = 0; i < continuation; ++i) {
            const auto next = static_cast<unsigned char>(value[at++]);
            if ((next & 0xc0) != 0x80) return false;
            scalar = (scalar << 6) | (next & 0x3f);
        }
        if ((continuation == 2 && scalar < 0x800) || (continuation == 3 && scalar < 0x10000) ||
            (scalar >= 0xd800 && scalar <= 0xdfff) || scalar > 0x10ffff) return false;
    }
    return true;
}

Result<std::filesystem::path> thin_relative_path(std::string_view name, const ArThinResolverLimits &limits) {
    if (name.empty() || name.size() > limits.max_path_bytes || name.find('\0') != std::string_view::npos ||
        name.find(':') != std::string_view::npos || !valid_utf8(name))
        return Error{ErrorCode::invalid_argument, "thin ar member path is empty, oversized, or invalid UTF-8"};
    std::string portable(name);
    std::replace(portable.begin(), portable.end(), '\\', '/');
    if (portable.front() == '/' || portable.back() == '/')
        return Error{ErrorCode::invalid_argument, "thin ar member path must be a relative file path"};
    std::size_t begin = 0;
    while (begin < portable.size()) {
        const auto end = portable.find('/', begin);
        const auto length = (end == std::string::npos ? portable.size() : end) - begin;
        const std::string_view component(portable.data() + begin, length);
        if (component.empty() || component == "." || component == "..")
            return Error{ErrorCode::invalid_argument, "thin ar member path contains an ambiguous or traversing component"};
        begin += length + 1;
    }
    try {
        auto path = std::filesystem::u8path(portable);
        if (path.empty() || path.is_absolute() || path.has_root_name() || path.has_root_directory())
            return Error{ErrorCode::invalid_argument, "thin ar member path is rooted"};
        return path;
    } catch (...) {
        return Error{ErrorCode::invalid_argument, "thin ar member path cannot be decoded"};
    }
}

Result<std::vector<std::byte>> read_thin_file_under_root(const std::filesystem::path &root,
                                                          const std::filesystem::path &relative,
                                                          std::uint64_t max_bytes) {
#ifdef _WIN32
    struct Handle { HANDLE value=INVALID_HANDLE_VALUE; ~Handle(){if(value!=INVALID_HANDLE_VALUE)CloseHandle(value);} };
    Handle directory{CreateFileW(root.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr)};
    if(directory.value==INVALID_HANDLE_VALUE)return Error{ErrorCode::io,"cannot open explicit thin ar member root"};
    const auto final_path=[](HANDLE handle)->Result<std::wstring>{
        const auto count=GetFinalPathNameByHandleW(handle,nullptr,0,FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
        if(!count||count>32768)return Error{ErrorCode::io,"cannot resolve thin ar handle path"};
        std::wstring path(count,L'\0');
        const auto written=GetFinalPathNameByHandleW(handle,path.data(),count,FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
        if(!written||written>=count)return Error{ErrorCode::io,"cannot resolve thin ar handle path"};
        path.resize(written);return path;
    };
    auto root_final=final_path(directory.value);if(!root_final)return root_final.error();
    Handle file{CreateFileW((std::filesystem::path(root_final.value())/relative).c_str(),GENERIC_READ,
        FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr)};
    if(file.value==INVALID_HANDLE_VALUE)return Error{ErrorCode::io,"cannot open thin ar member below explicit root"};
    auto file_final=final_path(file.value);if(!file_final)return file_final.error();
    auto prefix=root_final.value();if(prefix.empty()||(prefix.back()!=L'\\'&&prefix.back()!=L'/'))prefix.push_back(L'\\');
    if(file_final.value().size()<=prefix.size()||
       CompareStringOrdinal(prefix.data(),static_cast<int>(prefix.size()),file_final.value().data(),
                            static_cast<int>(prefix.size()),TRUE)!=CSTR_EQUAL)
        return Error{ErrorCode::invalid_argument,"thin ar member resolves outside explicit root"};
    BY_HANDLE_FILE_INFORMATION info{};LARGE_INTEGER length{};
    if(GetFileType(file.value)!=FILE_TYPE_DISK||!GetFileInformationByHandle(file.value,&info)||
       (info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)||!GetFileSizeEx(file.value,&length)||length.QuadPart<0)
        return Error{ErrorCode::io,"thin ar member is not a regular disk file"};
    const auto size=static_cast<std::uint64_t>(length.QuadPart);
#else
    struct Descriptor { int value=-1; ~Descriptor(){if(value>=0)::close(value);} };
    Descriptor directory{::open(root.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC)};
    if(directory.value<0)return Error{ErrorCode::io,"cannot open explicit thin ar member root"};
    Descriptor file;
    for(auto component=relative.begin();component!=relative.end();++component){
        auto next=component;++next;const bool last=next==relative.end();
        const int opened=::openat(directory.value,component->c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|
                                 (last?O_NONBLOCK:O_DIRECTORY));
        if(opened<0)return Error{ErrorCode::io,"cannot open thin ar member without following symlinks"};
        if(last)file.value=opened;else{::close(directory.value);directory.value=opened;}
    }
    struct stat info{};
    if(file.value<0||::fstat(file.value,&info)!=0||!S_ISREG(info.st_mode)||info.st_size<0)
        return Error{ErrorCode::io,"thin ar member is not a regular file"};
    const auto size=static_cast<std::uint64_t>(info.st_size);
#endif
    if(size>max_bytes||size>std::numeric_limits<std::size_t>::max())
        return Error{ErrorCode::resource_limit,"thin ar member exceeds resolver byte limit"};
    try {
        std::vector<std::byte> bytes(static_cast<std::size_t>(size));
        std::size_t offset=0;
        while(offset<bytes.size()){
            const auto chunk=std::min<std::size_t>(bytes.size()-offset,1024*1024);
#ifdef _WIN32
            DWORD read=0;
            if(!ReadFile(file.value,bytes.data()+offset,static_cast<DWORD>(chunk),&read,nullptr)||!read)
                return Error{ErrorCode::io,"cannot read complete thin ar member"};
#else
            const auto read=::read(file.value,bytes.data()+offset,chunk);
            if(read<0&&errno==EINTR)continue;
            if(read<=0)return Error{ErrorCode::io,"cannot read complete thin ar member"};
#endif
            offset+=static_cast<std::size_t>(read);
        }
        return bytes;
    }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"cannot allocate thin ar member snapshot"};}
}

struct ThinResolverState {
    std::filesystem::path root;
    ArThinResolverLimits limits;
    std::mutex mutex;
    std::uint64_t remaining=0;
    std::map<std::string,std::shared_ptr<const ByteStorage>,std::less<>> cache;
    Result<std::shared_ptr<const ByteStorage>> resolve(std::string_view name) {
        std::lock_guard lock(mutex);
        if(const auto found=cache.find(name);found!=cache.end())return found->second;
        if(cache.size()>=limits.max_unique_paths)
            return Error{ErrorCode::resource_limit,"thin ar unique path limit exceeded"};
        auto relative=thin_relative_path(name,limits);if(!relative)return relative.error();
        auto bytes=read_thin_file_under_root(root,relative.value(),remaining);if(!bytes)return bytes.error();
        const auto size = bytes.value().size();
        try {
            std::shared_ptr<const ByteStorage> snapshot=std::make_shared<const ThinSnapshot>(std::move(bytes.value()));
            cache.emplace(std::string(name),snapshot);
            remaining-=size;
            return snapshot;
        }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"cannot allocate thin ar resolver cache entry"};}
    }
};

struct AixBigMemberHeader {
    ArMember member;
    std::uint64_t next = 0;
    std::uint64_t previous = 0;
};

AixBigMemberHeader read_aix_big_member(const Reader &reader, std::uint64_t offset,
                                      ArMemberKind kind, std::uint64_t source_size,
                                      std::size_t max_name_bytes) {
    require(offset >= 128 && offset < source_size && (offset & 1) == 0,
            "AIX big ar member header offset is invalid or not even-aligned");
    const auto fixed = reader.read(offset, 112);
    const auto get = [&](std::size_t at, std::size_t size, unsigned base, const char *message) {
        return number(std::span(fixed).subspan(at, size), base, message);
    };
    const auto size = get(0, 20, 10, "invalid AIX big ar member size");
    const auto next = get(20, 20, 10, "invalid AIX big ar next-member offset");
    const auto previous = get(40, 20, 10, "invalid AIX big ar previous-member offset");
    require(next == 0 || (next >= 128 && next < source_size && (next & 1) == 0),
            "AIX big ar next-member link is invalid");
    require(previous == 0 || (previous >= 128 && previous < source_size && (previous & 1) == 0),
            "AIX big ar previous-member link is invalid");
    const auto timestamp = get(60, 12, 10, "invalid AIX big ar member timestamp");
    const auto uid = get(72, 12, 10, "invalid AIX big ar member uid");
    const auto gid = get(84, 12, 10, "invalid AIX big ar member gid");
    const auto mode = get(96, 12, 8, "invalid AIX big ar member mode");
    const auto name_size = get(108, 4, 10, "invalid AIX big ar member name length");
    require(name_size <= 255 && name_size <= max_name_bytes,
            "AIX big ar member name exceeds limits", ErrorCode::resource_limit);
    require(uid <= UINT32_MAX && gid <= UINT32_MAX && mode <= UINT32_MAX,
            "AIX big ar member metadata exceeds supported range", ErrorCode::overflow);
    const auto name_offset = add(offset, 112);
    const auto name_bytes = reader.read(name_offset, name_size);
    require(std::find(name_bytes.begin(), name_bytes.end(), std::byte{0}) == name_bytes.end(),
            "AIX big ar member name contains NUL");
    const auto pad_size = name_size & 1;
    const auto trailer_offset = add(name_offset, name_size + pad_size);
    if (pad_size)
        require(reader.read(add(name_offset, name_size), 1)[0] == std::byte{0},
                "invalid AIX big ar member name padding");
    // AIX describes the two-byte AIAFMAG marker as cosmetic. Consume its
    // bounded extent without using it as a structural validity check.
    (void)reader.read(trailer_offset, 2);
    const auto data_offset = add(trailer_offset, 2);
    require(data_offset <= source_size && size <= source_size - data_offset,
            "AIX big ar member data exceeds input");
    std::string name;
    name.reserve(name_bytes.size());
    for (const auto byte : name_bytes)
        name.push_back(static_cast<char>(std::to_integer<unsigned char>(byte)));
    return {{std::move(name), {offset}, {data_offset}, size, kind, timestamp,
             static_cast<std::uint32_t>(uid), static_cast<std::uint32_t>(gid),
             static_cast<std::uint32_t>(mode)}, next, previous};
}

ArArchive read_aix_big_archive(const ByteStorage &storage, const Reader &reader,
                               std::stop_token stop, ArLimits limits) {
    constexpr std::string_view magic = "<bigaf>\n";
    require(storage.size() >= 128, "truncated AIX big ar fixed header");
    const auto header = reader.read(0, 128);
    require(field(std::span(header).first(8)) == magic, "invalid AIX big ar signature");
    const auto offset = [&](std::size_t at, const char *message) {
        return number(std::span(header).subspan(at, 20), 10, message);
    };
    const auto member_table_offset = offset(8, "invalid AIX big ar member-table offset");
    const auto symbols32_offset = offset(28, "invalid AIX big ar 32-bit symbol-table offset");
    const auto symbols64_offset = offset(48, "invalid AIX big ar 64-bit symbol-table offset");
    const auto first_member_offset = offset(68, "invalid AIX big ar first-member offset");
    const auto last_member_offset = offset(88, "invalid AIX big ar last-member offset");
    const auto free_member_offset = offset(108, "invalid AIX big ar free-list offset");
    require(member_table_offset == 0 || symbols32_offset == 0 || member_table_offset != symbols32_offset,
            "AIX big ar member and symbol tables alias the same member");
    require(member_table_offset == 0 || symbols64_offset == 0 || member_table_offset != symbols64_offset,
            "AIX big ar member and symbol tables alias the same member");
    require(symbols32_offset == 0 || symbols64_offset == 0 || symbols32_offset != symbols64_offset,
            "AIX big ar 32-/64-bit symbol tables alias the same member");
    for (const auto special : {member_table_offset, symbols32_offset, symbols64_offset,
                               first_member_offset, last_member_offset, free_member_offset})
        require(special == 0 || (special >= 128 && special < storage.size() && (special & 1) == 0),
                "AIX big ar header contains an invalid member offset");

    ArArchive archive;
    archive.aix_big = true;
    archive.has_symbol_index = symbols32_offset != 0 || symbols64_offset != 0;
    archive.symbol_index_complete = true;

    std::map<std::uint64_t, std::size_t> parsed;
    const auto kind_for = [&](std::uint64_t member_offset) {
        if (member_offset == member_table_offset) return ArMemberKind::member_table;
        if (member_offset == symbols32_offset || member_offset == symbols64_offset)
            return ArMemberKind::symbol_index;
        return ArMemberKind::regular;
    };
    auto append_member = [&](std::uint64_t member_offset, std::optional<std::uint64_t> expected_previous) {
        canceled(stop);
        require(archive.members.size() < limits.max_members,
                "AIX big ar member count limit exceeded", ErrorCode::resource_limit);
        auto decoded = read_aix_big_member(reader, member_offset, kind_for(member_offset),
                                           storage.size(), limits.max_name_bytes);
        if (expected_previous)
            require(decoded.previous == *expected_previous,
                    "AIX big ar previous-member link is inconsistent");
        if (decoded.member.kind == ArMemberKind::symbol_index)
            require(decoded.member.name.empty(), "AIX big ar symbol table must have an empty member name");
        if (decoded.member.kind == ArMemberKind::member_table)
            require(decoded.member.name.empty(), "AIX big ar member table must have an empty member name");
        if (decoded.member.kind == ArMemberKind::regular)
            require(!decoded.member.name.empty(), "AIX big ar regular member has an empty name");
        const auto index = archive.members.size();
        archive.members.push_back(std::move(decoded.member));
        parsed.emplace(member_offset, index);
        return decoded;
    };

    std::uint64_t current = first_member_offset;
    std::uint64_t previous = 0;
    while (current != 0) {
        canceled(stop);
        require(!parsed.contains(current), "AIX big ar member chain contains a cycle");
        const auto decoded = append_member(current, previous);
        previous = current;
        current = decoded.next;
    }
    require(previous == last_member_offset,
            "AIX big ar last-member offset disagrees with linked member chain");

    // Indexed metadata members are sometimes omitted from the file-member
    // chain. Retain them by the offsets in the fixed header as special rows.
    for (const auto special : {member_table_offset, symbols32_offset, symbols64_offset}) {
        if (special == 0 || parsed.contains(special)) continue;
        (void)append_member(special, std::nullopt);
    }
    require(free_member_offset == 0 || !parsed.contains(free_member_offset),
            "AIX big ar free-list member overlaps a live or indexed member");

    constexpr std::uint64_t max_symbol_index_bytes = 256ULL * 1024 * 1024;
    std::uint64_t symbol_index_bytes = 0;
    std::vector<PendingSymbol> pending_symbols;
    for (const auto [table_offset, table_name] : {
             std::pair{symbols32_offset, "AIX big ar 32-bit"},
             std::pair{symbols64_offset, "AIX big ar 64-bit"}}) {
        if (!table_offset) continue;
        const auto indexed = parsed.find(table_offset);
        require(indexed != parsed.end(), "AIX big ar symbol table member was not retained");
        const auto &member = archive.members[indexed->second];
        if (member.size > max_symbol_index_bytes - symbol_index_bytes ||
            pending_symbols.size() > limits.max_symbols) {
            archive.symbol_index_complete = false;
            archive.diagnostics.emplace_back(std::string(table_name) +
                " symbol table exceeds the cumulative metadata budget; member listing and extraction remain available");
            continue;
        }
        symbol_index_bytes += member.size;
        const auto bytes = reader.read(member.data_offset.value, member.size);
        auto decoded = decode_aix_index(bytes, limits.max_symbols - pending_symbols.size(),
                                        limits.max_name_bytes, stop);
        if (!decoded) {
            archive.symbol_index_complete = false;
            archive.diagnostics.emplace_back(std::string(table_name) +
                " symbol table has a malformed or over-budget layout; member listing and extraction remain available");
            continue;
        }
        pending_symbols.insert(pending_symbols.end(), std::make_move_iterator(decoded->begin()),
                               std::make_move_iterator(decoded->end()));
    }
    bool invalid_symbol_reference_reported = false;
    for (auto &symbol : pending_symbols) {
        canceled(stop);
        const auto found = parsed.find(symbol.header);
        if (found == parsed.end() || archive.members[found->second].kind != ArMemberKind::regular) {
            archive.symbol_index_complete = false;
            if (!invalid_symbol_reference_reported) {
                archive.diagnostics.emplace_back("AIX big ar symbol index references an unknown or special member; member listing and extraction remain available");
                invalid_symbol_reference_reported = true;
            }
            continue;
        }
        archive.symbols.push_back({std::move(symbol.name), found->second});
    }
    return archive;
}
}

Result<ArArchive> read_ar_archive(const ByteStorage &storage, std::stop_token stop, ArLimits limits) {
    try {
        canceled(stop);
        require(limits.max_members != 0 && limits.max_name_bytes != 0 && limits.max_symbols != 0,
                "ar limits must be positive", ErrorCode::invalid_argument);
        Reader reader(storage, stop);
        constexpr std::string_view aix_big_magic = "<bigaf>\n";
        if (storage.size() >= aix_big_magic.size() &&
            field(reader.read(0, aix_big_magic.size())) == aix_big_magic)
            return read_aix_big_archive(storage, reader, stop, limits);
        constexpr std::string_view magic = "!<arch>\n";
        constexpr std::string_view thin_magic = "!<thin>\n";
        const auto signature = reader.read(0, magic.size());
        const auto signature_text = field(signature);
        require(signature_text == magic || signature_text == thin_magic, "invalid ar archive signature");
        ArArchive archive;
        archive.thin = signature_text == thin_magic;
        std::vector<std::byte> long_names;
        std::vector<PendingSymbol> pending_symbols;
        std::uint64_t symbol_index_bytes = 0;
        std::map<std::uint64_t, std::size_t> member_by_header;
        constexpr std::uint64_t max_symbol_index_bytes = 256ULL * 1024 * 1024;
        std::uint64_t cursor = magic.size();
        while (cursor < storage.size()) {
            canceled(stop);
            require(archive.members.size() < limits.max_members, "ar member count limit exceeded", ErrorCode::resource_limit);
            require(storage.size() - cursor >= 60, "truncated ar member header");
            const auto header = reader.read(cursor, 60);
            require(header[58] == std::byte{'`'} && header[59] == std::byte{'\n'}, "invalid ar member trailer");
            std::string raw_name = field(std::span(header).subspan(0, 16));
            while (!raw_name.empty() && raw_name.back() == ' ') raw_name.pop_back();
            const auto timestamp = number(std::span(header).subspan(16, 12), 10, "invalid ar member timestamp");
            const auto uid = number(std::span(header).subspan(28, 6), 10, "invalid ar member uid");
            const auto gid = number(std::span(header).subspan(34, 6), 10, "invalid ar member gid");
            const auto mode = number(std::span(header).subspan(40, 8), 8, "invalid ar member mode");
            require(uid <= UINT32_MAX && gid <= UINT32_MAX && mode <= UINT32_MAX,
                    "ar member header metadata exceeds supported range", ErrorCode::overflow);
            const auto raw_size = number(std::span(header).subspan(48, 10), 10, "invalid ar member size");
            const auto data_start = add(cursor, 60);
            std::string name;
            ArMemberKind kind = ArMemberKind::regular;
            std::uint64_t payload_offset = data_start, payload_size = raw_size;
            if (raw_name == "//") { name = "//"; kind = ArMemberKind::long_name_table; }
            else if (raw_name == "/" || raw_name == "/SYM64/") { name = raw_name; kind = ArMemberKind::symbol_index; }
            else if (raw_name.starts_with("__.SYMDEF")) {
                name = raw_name;
                kind = ArMemberKind::symbol_index;
            } else if (raw_name.starts_with("#1/")) {
                require(!archive.thin, "BSD inline names are unsupported in GNU thin archives", ErrorCode::unsupported);
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
            const bool external = archive.thin && kind == ArMemberKind::regular;
            if (external) kind = ArMemberKind::thin_external;
            const auto stored_size = external ? std::uint64_t{0} : raw_size;
            require(stored_size <= storage.size() - data_start, "ar member data exceeds input");
            const std::size_t index = archive.members.size();
            archive.members.push_back({std::move(name), {cursor}, {payload_offset}, payload_size, kind,
                                       timestamp, static_cast<std::uint32_t>(uid),
                                       static_cast<std::uint32_t>(gid), static_cast<std::uint32_t>(mode)});
            member_by_header.emplace(cursor, index);

            if (kind == ArMemberKind::long_name_table) {
                require(raw_size <= 64ULL * 1024 * 1024, "GNU ar long-name table exceeds metadata budget", ErrorCode::resource_limit);
                long_names = reader.read(data_start, raw_size);
            } else if (kind == ArMemberKind::symbol_index && raw_name == "/") {
                archive.has_symbol_index = true;
                if (raw_size > max_symbol_index_bytes - symbol_index_bytes) {
                    archive.symbol_index_complete = false;
                    archive.diagnostics.emplace_back("GNU ar symbol index exceeds the cumulative metadata budget; member listing and extraction remain available");
                } else {
                    symbol_index_bytes += raw_size;
                    const auto bytes = reader.read(data_start, raw_size);
                    auto decoded = decode_gnu_index(bytes, 4, limits.max_symbols - pending_symbols.size(), limits.max_name_bytes, stop);
                    if (decoded) {
                        pending_symbols.insert(pending_symbols.end(),
                                               std::make_move_iterator(decoded->begin()),
                                               std::make_move_iterator(decoded->end()));
                    } else {
                        archive.symbol_index_complete = false;
                        archive.diagnostics.emplace_back("GNU ar symbol index has a malformed or unsupported layout; member listing and extraction remain available");
                    }
                }
            } else if (kind == ArMemberKind::symbol_index && raw_name == "/SYM64/") {
                archive.has_symbol_index = true;
                if (raw_size > max_symbol_index_bytes - symbol_index_bytes) {
                    archive.symbol_index_complete = false;
                    archive.diagnostics.emplace_back("GNU ar 64-bit symbol index exceeds the cumulative metadata budget; member listing and extraction remain available");
                } else {
                    symbol_index_bytes += raw_size;
                    const auto bytes = reader.read(data_start, raw_size);
                    auto decoded = decode_gnu_index(bytes, 8, limits.max_symbols - pending_symbols.size(), limits.max_name_bytes, stop);
                    if (decoded) {
                        pending_symbols.insert(pending_symbols.end(),
                                               std::make_move_iterator(decoded->begin()),
                                               std::make_move_iterator(decoded->end()));
                    } else {
                        archive.symbol_index_complete = false;
                        archive.diagnostics.emplace_back("GNU ar 64-bit symbol index has a malformed or unsupported layout; member listing and extraction remain available");
                    }
                }
            } else if (kind == ArMemberKind::symbol_index && raw_name.starts_with("__.SYMDEF")) {
                archive.has_symbol_index = true;
                if (raw_size > max_symbol_index_bytes - symbol_index_bytes) {
                    archive.symbol_index_complete = false;
                    archive.diagnostics.emplace_back("BSD ranlib index exceeds the cumulative metadata budget; member listing and extraction remain available");
                } else {
                    symbol_index_bytes += raw_size;
                    const auto bytes = reader.read(data_start, raw_size);
                    const std::size_t width = raw_name.find("_64") != std::string::npos ? 8 : 4;
                    const auto remaining_symbols = limits.max_symbols - pending_symbols.size();
                    auto decoded = decode_bsd_index(bytes, width, true, remaining_symbols, limits.max_name_bytes, stop);
                    if (!decoded) decoded = decode_bsd_index(bytes, width, false, remaining_symbols, limits.max_name_bytes, stop);
                    if (decoded) {
                        pending_symbols.insert(pending_symbols.end(),
                                               std::make_move_iterator(decoded->begin()),
                                               std::make_move_iterator(decoded->end()));
                    } else {
                        archive.symbol_index_complete = false;
                        archive.diagnostics.emplace_back("BSD ranlib symbol index has an unsupported, malformed, or over-budget layout; member listing and extraction remain available");
                    }
                }
            }

            cursor = add(data_start, stored_size);
            if (stored_size & 1) {
                require(cursor < storage.size(), "missing ar member alignment byte");
                require(reader.read(cursor, 1)[0] == std::byte{'\n'}, "invalid ar member alignment byte");
                ++cursor;
            }
        }
        require(cursor == storage.size(), "ar archive has trailing partial member");
        bool invalid_symbol_reference_reported = false;
        for (auto &symbol : pending_symbols) {
            canceled(stop);
            const auto found = member_by_header.find(symbol.header);
            if (found == member_by_header.end() ||
                (archive.members[found->second].kind != ArMemberKind::regular &&
                 archive.members[found->second].kind != ArMemberKind::thin_external)) {
                archive.symbol_index_complete = false;
                if (!invalid_symbol_reference_reported) {
                    archive.diagnostics.emplace_back("ar symbol index references an unknown or special member; member listing and extraction remain available");
                    invalid_symbol_reference_reported = true;
                }
                continue;
            }
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
        if (archive.members[symbol.member_index].kind != ArMemberKind::regular &&
            archive.members[symbol.member_index].kind != ArMemberKind::thin_external)
            return Error{ErrorCode::malformed, "ar symbol references a non-regular member"};
        if (!symbol.name.empty()) {
            const auto [it, inserted] = first_definition.try_emplace(symbol.name, symbol.member_index);
            if (!inserted && symbol.member_index < it->second) it->second = symbol.member_index;
        }
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
    ArSymbolLookup result{std::nullopt, {}, archive.has_symbol_index, archive.symbol_index_complete};
    for (const auto &symbol : archive.symbols) {
        if (symbol.name.empty())
            return Error{ErrorCode::malformed, "ar symbol index contains an empty symbol name"};
        if (symbol.member_index >= archive.members.size())
            return Error{ErrorCode::malformed, "ar symbol references an invalid member index"};
        if (archive.members[symbol.member_index].kind != ArMemberKind::regular &&
            archive.members[symbol.member_index].kind != ArMemberKind::thin_external)
            return Error{ErrorCode::malformed, "ar symbol references a non-regular member"};
        if (symbol.name == requested) result.candidate_member_indices.push_back(symbol.member_index);
    }
    std::sort(result.candidate_member_indices.begin(), result.candidate_member_indices.end());
    result.candidate_member_indices.erase(
        std::unique(result.candidate_member_indices.begin(), result.candidate_member_indices.end()),
        result.candidate_member_indices.end());
    if (!result.candidate_member_indices.empty())
        result.member_index = result.candidate_member_indices.front();
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
            const auto kind = archive.members[summary.member_index].kind;
            require(kind == ArMemberKind::regular || kind == ArMemberKind::thin_external,
                    "ar object summary references a special member", ErrorCode::malformed);
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

Result<ArThinMemberResolver> make_ar_thin_member_resolver(std::filesystem::path root,
                                                           ArThinResolverLimits limits) {
    if (root.empty() || limits.max_total_bytes == 0 || limits.max_unique_paths == 0 ||
        limits.max_path_bytes == 0 || limits.max_path_bytes > 64 * 1024)
        return Error{ErrorCode::invalid_argument, "thin ar resolver root and limits must be nonempty and positive"};
    std::error_code error;
    if (!std::filesystem::is_directory(root, error) || error)
        return Error{ErrorCode::invalid_argument, "thin ar resolver root must be an existing directory"};
    try {
        auto state = std::make_shared<ThinResolverState>();
        state->root = std::move(root);
        state->limits = limits;
        state->remaining = limits.max_total_bytes;
        ArThinMemberResolver resolver = [state = std::move(state)](std::string_view name) {
            return state->resolve(name);
        };
        return resolver;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "cannot allocate thin ar resolver state"};
    } catch (const std::filesystem::filesystem_error &) {
        return Error{ErrorCode::invalid_argument, "thin ar resolver root cannot be inspected"};
    }
}

Result<std::shared_ptr<const ByteStorage>> open_ar_member(std::shared_ptr<const ByteStorage> storage,
                                                          const ArMember &member) {
    if (!storage)
        return Error{ErrorCode::invalid_argument, "ar member view requires source storage"};
    if (member.kind != ArMemberKind::regular)
        return Error{member.kind == ArMemberKind::thin_external ? ErrorCode::unsupported : ErrorCode::invalid_argument,
                     member.kind == ArMemberKind::thin_external
                         ? "thin ar member contents are external and are not resolved by this API"
                         : "cannot open an ar special member as object storage"};
    if (member.data_offset.value > storage->size() || member.size > storage->size() - member.data_offset.value)
        return Error{ErrorCode::malformed, "ar member extent exceeds source storage"};
    try {
        return std::shared_ptr<const ByteStorage>(std::make_shared<MemberStorage>(std::move(storage), member));
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate ar member storage view"};
    }
}

Result<std::shared_ptr<const ByteStorage>> open_ar_member(
    std::shared_ptr<const ByteStorage> storage, const ArMember &member,
    const ArThinMemberResolver &resolver) {
    if (member.kind != ArMemberKind::thin_external)
        return open_ar_member(std::move(storage), member);
    if (!resolver)
        return Error{ErrorCode::invalid_argument, "Thin ar member resolution requires a caller resolver"};
    Result<std::shared_ptr<const ByteStorage>> resolved = Error{ErrorCode::invalid_argument, "Thin ar resolver did not run"};
    try {
        resolved = resolver(member.name);
    } catch (...) {
        return Error{ErrorCode::invalid_argument, "Thin ar member resolver threw an exception"};
    }
    if (!resolved) return resolved.error();
    if (!resolved.value())
        return Error{ErrorCode::malformed, "Thin ar resolver returned no member storage"};
    if (resolved.value()->size() != member.size)
        return Error{ErrorCode::malformed, "Thin ar resolved member size does not match archive declaration"};
    return std::move(resolved.value());
}

Result<std::vector<std::byte>> extract_ar_member(const ByteStorage &storage, const ArMember &member,
                                                 std::stop_token stop, ArLimits limits) {
    try {
        canceled(stop);
        require(member.kind == ArMemberKind::regular,
                member.kind == ArMemberKind::thin_external
                    ? "thin ar member contents are external and are not resolved by this API"
                    : "cannot extract ar special member",
                member.kind == ArMemberKind::thin_external ? ErrorCode::unsupported : ErrorCode::invalid_argument);
        require(member.size <= limits.max_extracted_bytes, "ar member exceeds extraction limit", ErrorCode::resource_limit);
        require(member.data_offset.value <= storage.size() && member.size <= storage.size() - member.data_offset.value,
                "ar member extent exceeds input");
        std::vector<std::byte> result;
        require(member.size <= std::numeric_limits<std::size_t>::max() &&
                    member.size <= result.max_size(),
                "ar member exceeds host vector capacity", ErrorCode::resource_limit);
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
      catch (const std::bad_alloc &) { return Error{ErrorCode::resource_limit, "Cannot allocate ar member extraction buffer"}; }
      catch (const std::length_error &) { return Error{ErrorCode::resource_limit, "ar member exceeds host vector capacity"}; }
}

Result<std::vector<std::byte>> extract_ar_member(
    std::shared_ptr<const ByteStorage> storage, const ArMember &member,
    const ArThinMemberResolver &resolver, std::stop_token stop, ArLimits limits) {
    if (member.kind != ArMemberKind::thin_external) {
        if (!storage) return Error{ErrorCode::invalid_argument, "ar member extraction requires source storage"};
        return extract_ar_member(*storage, member, stop, limits);
    }
    if (member.size > limits.max_extracted_bytes)
        return Error{ErrorCode::resource_limit, "ar member exceeds extraction limit"};
    auto resolved = open_ar_member(std::move(storage), member, resolver);
    if (!resolved) return resolved.error();
    ArMember bounded = member;
    bounded.kind = ArMemberKind::regular;
    bounded.data_offset = {0};
    return extract_ar_member(*resolved.value(), bounded, stop, limits);
}
} // namespace hexlab

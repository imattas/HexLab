#include "hexlab/firmware/firmware.hpp"
#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <map>
#include <string>

namespace hexlab::firmware {
namespace {
Error fail(ErrorCode code, std::size_t line, std::string message) {
    return {code, "line " + std::to_string(line) + ": " + std::move(message)};
}
int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
Result<std::vector<std::uint8_t>> hex_bytes(std::string_view line, std::size_t line_number) {
    if (line.size() % 2 != 0) return fail(ErrorCode::malformed, line_number, "hex payload has an odd number of digits");
    std::vector<std::uint8_t> out;
    out.reserve(line.size() / 2);
    for (std::size_t i = 0; i < line.size(); i += 2) {
        const int hi = nibble(line[i]), lo = nibble(line[i + 1]);
        if (hi < 0 || lo < 0) return fail(ErrorCode::malformed, line_number, "non-hexadecimal digit");
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}
bool canceled(std::stop_token stop) { return stop.stop_requested(); }

struct Builder {
    FirmwareImage image;
    ParseOptions options;
    std::map<std::uint64_t, std::uint64_t> intervals;
    Result<bool> add(std::uint64_t address, std::span<const std::uint8_t> bytes,
              std::size_t line, std::size_t record_index) {
        if (bytes.empty()) return true;
        if (address > options.max_address || bytes.size() - 1 > options.max_address - address)
            return fail(ErrorCode::out_of_bounds, line, "data address exceeds configured address bound");
        if (bytes.size() > std::numeric_limits<std::uint64_t>::max() - address)
            return fail(ErrorCode::overflow, line, "data end address overflows the address type");
        if (bytes.size() > options.max_data_bytes - std::min(options.max_data_bytes, image.total_data_bytes))
            return fail(ErrorCode::resource_limit, line, "configured firmware data-byte limit exceeded");
        const std::uint64_t end = address + bytes.size(); // address bound is at most UINT32_MAX by default
        auto next = intervals.lower_bound(address);
        if (next != intervals.end() && next->first < end)
            return fail(ErrorCode::conflict, line, "data overlaps a prior record");
        if (next != intervals.begin() && std::prev(next)->second > address)
            return fail(ErrorCode::conflict, line, "data overlaps a prior record");
        DataSegment segment;
        segment.address = address;
        segment.provenance = {line, record_index};
        segment.bytes.reserve(bytes.size());
        for (auto byte : bytes) segment.bytes.push_back(static_cast<std::byte>(byte));
        intervals.emplace(address, end);
        image.total_data_bytes += bytes.size();
        ++image.data_record_count;
        image.segments.push_back(std::move(segment));
        return true;
    }
    void sort() {
        std::sort(image.segments.begin(), image.segments.end(), [](const auto &a, const auto &b) { return a.address < b.address; });
    }
};
struct Lines {
    std::string_view text;
    std::size_t at = 0, number = 0;
    bool next(std::string_view &line) {
        if (at >= text.size()) return false;
        const auto e = text.find('\n', at);
        line = text.substr(at, e == std::string_view::npos ? text.size() - at : e - at);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        at = e == std::string_view::npos ? text.size() : e + 1;
        ++number;
        return true;
    }
};
}

Result<FirmwareImage> parse_intel_hex(std::string_view text, ParseOptions options, std::stop_token stop) {
    if (options.max_data_bytes == 0 || options.max_records == 0)
        return Error{ErrorCode::invalid_argument, "firmware parser limits must be nonzero"};
    Builder builder; builder.options = options; builder.image.format = Format::intel_hex;
    Lines lines{text}; std::string_view line; std::uint64_t base = 0;
    std::size_t records = 0; bool eof = false;
    while (lines.next(line)) {
        if (canceled(stop)) return Error{ErrorCode::canceled, "firmware parsing canceled"};
        if (line.empty()) continue;
        if (eof) return fail(ErrorCode::malformed, lines.number, "record appears after Intel HEX EOF");
        if (line.front() != ':') return fail(ErrorCode::malformed, lines.number, "Intel HEX record must begin with ':'");
        if (line.size() > 521) return fail(ErrorCode::resource_limit, lines.number, "Intel HEX record exceeds the format byte-count maximum");
        auto parsed = hex_bytes(line.substr(1), lines.number); if (!parsed) return parsed.error();
        const auto &b = parsed.value();
        if (b.size() < 5 || b.size() != static_cast<std::size_t>(b[0]) + 5)
            return fail(ErrorCode::malformed, lines.number, "record length does not match byte count");
        ++records;
        if (records > options.max_records) return fail(ErrorCode::resource_limit, lines.number, "configured record-count limit exceeded");
        unsigned sum = 0; for (auto v : b) sum += v;
        if ((sum & 0xffu) != 0) return fail(ErrorCode::integrity, lines.number, "Intel HEX checksum mismatch");
        const std::uint16_t offset = static_cast<std::uint16_t>((b[1] << 8) | b[2]);
        const std::uint8_t type = b[3];
        const std::span<const std::uint8_t> data(b.data() + 4, b[0]);
        if (type == 0) {
            if (!data.empty() && base > std::numeric_limits<std::uint64_t>::max() - offset)
                return fail(ErrorCode::overflow, lines.number, "address arithmetic overflow");
            auto added = builder.add(base + offset, data, lines.number, records); if (!added) return added.error();
        } else if (type == 1) {
            if (b[0] != 0 || offset != 0) return fail(ErrorCode::malformed, lines.number, "EOF record must have zero length and address");
            eof = true; builder.image.termination = Termination::eof;
        } else if (type == 2 || type == 4) {
            if (b[0] != 2 || offset != 0) return fail(ErrorCode::malformed, lines.number, "extended-address record must contain two bytes at address zero");
            const std::uint64_t value = (static_cast<std::uint64_t>(data[0]) << 8) | data[1];
            base = type == 2 ? value << 4 : value << 16;
        } else if (type == 3 || type == 5) {
            if (b[0] != 4 || offset != 0) return fail(ErrorCode::malformed, lines.number, "start-address record must contain four bytes at address zero");
            if (builder.image.has_start_address)
                return fail(ErrorCode::malformed, lines.number, "multiple Intel HEX start-address records");
            std::uint64_t entry = 0; for (auto v : data) entry = (entry << 8) | v;
            if (type == 3) entry = ((entry >> 16) << 4) + (entry & 0xffff);
            builder.image.start_address = entry; builder.image.has_start_address = true;
        } else return fail(ErrorCode::unsupported, lines.number, "unsupported Intel HEX record type");
    }
    if (canceled(stop)) return Error{ErrorCode::canceled, "firmware parsing canceled"};
    if (!eof) return Error{ErrorCode::malformed, "Intel HEX input is missing its EOF record"};
    builder.sort(); return std::move(builder.image);
}

Result<FirmwareImage> parse_s_record(std::string_view text, ParseOptions options, std::stop_token stop) {
    if (options.max_data_bytes == 0 || options.max_records == 0)
        return Error{ErrorCode::invalid_argument, "firmware parser limits must be nonzero"};
    Builder builder; builder.options = options; builder.image.format = Format::motorola_s_record;
    Lines lines{text}; std::string_view line; std::size_t records = 0, data_records = 0;
    bool terminated = false; int last_data_type = 0; bool count_seen = false;
    while (lines.next(line)) {
        if (canceled(stop)) return Error{ErrorCode::canceled, "firmware parsing canceled"};
        if (line.empty()) continue;
        if (terminated) return fail(ErrorCode::malformed, lines.number, "record appears after S-record termination");
        if (line.size() < 4 || line[0] != 'S' || line[1] < '0' || line[1] > '9')
            return fail(ErrorCode::malformed, lines.number, "invalid S-record prefix");
        if (line.size() > 514) return fail(ErrorCode::resource_limit, lines.number, "S-record exceeds the format byte-count maximum");
        const int type = line[1] - '0';
        auto parsed = hex_bytes(line.substr(2), lines.number); if (!parsed) return parsed.error();
        const auto &b = parsed.value();
        if (b.empty() || b.size() != static_cast<std::size_t>(b[0]) + 1)
            return fail(ErrorCode::malformed, lines.number, "S-record count does not match payload length");
        ++records;
        if (records > options.max_records) return fail(ErrorCode::resource_limit, lines.number, "configured record-count limit exceeded");
        unsigned sum = 0; for (auto v : b) sum += v;
        if ((sum & 0xffu) != 0xffu) return fail(ErrorCode::integrity, lines.number, "S-record checksum mismatch");
        const unsigned address_bytes = (type == 0 || type == 1 || type == 5 || type == 9) ? 2u :
            (type == 2 || type == 6 || type == 8) ? 3u : (type == 3 || type == 7) ? 4u : 0u;
        if (address_bytes == 0) return fail(ErrorCode::unsupported, lines.number, "unsupported S-record type");
        if (b[0] < address_bytes + 1) return fail(ErrorCode::malformed, lines.number, "S-record is too short for its address and checksum");
        std::uint64_t address = 0; for (unsigned i = 0; i < address_bytes; ++i) address = (address << 8) | b[1 + i];
        const std::size_t data_size = b[0] - address_bytes - 1;
        const std::span<const std::uint8_t> data(b.data() + 1 + address_bytes, data_size);
        if (type >= 1 && type <= 3) {
            if (count_seen)
                return fail(ErrorCode::malformed, lines.number, "data record appears after S-record count");
            auto added = builder.add(address, data, lines.number, records); if (!added) return added.error();
            ++data_records; last_data_type = type;
        } else if (type == 5 || type == 6) {
            if (data_size != 0 || count_seen) return fail(ErrorCode::malformed, lines.number, "invalid or duplicate S-record count record");
            if (address != data_records) return fail(ErrorCode::integrity, lines.number, "S-record count does not match preceding data records");
            count_seen = true;
        } else if (type == 7 || type == 8 || type == 9) {
            if (data_size != 0) return fail(ErrorCode::malformed, lines.number, "termination record must not contain data");
            const int expected = last_data_type == 3 ? 7 : last_data_type == 2 ? 8 : 9;
            if (data_records && type != expected) return fail(ErrorCode::malformed, lines.number, "termination record does not match data-record address width");
            builder.image.start_address = address; builder.image.has_start_address = true;
            builder.image.termination = Termination::start_record; terminated = true;
        } else if (type == 0) {
            // S0 is optional metadata and must lead the data sequence. Preserve
            // its raw bytes and source identity, but never map it as data.
            if (builder.image.has_s_record_header || data_records || count_seen)
                return fail(ErrorCode::malformed, lines.number, "S0 header must be unique and precede data/count records");
            builder.image.has_s_record_header = true;
            builder.image.s_record_header_provenance = {lines.number, records};
            builder.image.s_record_header.reserve(data.size());
            for (const auto byte : data)
                builder.image.s_record_header.push_back(static_cast<std::byte>(byte));
        }
    }
    if (canceled(stop)) return Error{ErrorCode::canceled, "firmware parsing canceled"};
    if (!terminated) return Error{ErrorCode::malformed, "S-record input is missing its termination record"};
    builder.sort(); return std::move(builder.image);
}
} // namespace hexlab::firmware

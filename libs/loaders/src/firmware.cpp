#include "hexlab/loaders/firmware.hpp"
#include "hexlab/image/image.hpp"
#include <algorithm>
#include <limits>
#include <new>

namespace hexlab {
namespace {
class FirmwareStorage final : public ByteStorage {
  public:
    explicit FirmwareStorage(std::vector<std::byte> bytes) : bytes_(std::move(bytes)) {}
    std::uint64_t size() const noexcept override { return bytes_.size(); }
    Result<ByteView> read_at(FileOffset offset, std::size_t count) const override {
        if (offset.value > bytes_.size() || count > bytes_.size() - static_cast<std::size_t>(offset.value))
            return Error{ErrorCode::io, "Firmware backing read is out of range"};
        return ByteView{std::shared_ptr<const void>(shared_from_this(), this),
                        std::span<const std::byte>(bytes_).subspan(static_cast<std::size_t>(offset.value), count)};
    }
  private:
    struct EnableShared : std::enable_shared_from_this<FirmwareStorage> {};
    std::vector<std::byte> bytes_;
    std::shared_ptr<const FirmwareStorage> shared_from_this() const {
        return owner_.lock();
    }
  public:
    void bind(const std::shared_ptr<const FirmwareStorage> &self) { owner_ = self; }
  private:
    std::weak_ptr<const FirmwareStorage> owner_;
};
} // namespace

Result<LoadedImage> load_firmware(std::string_view text, const FirmwareLoadOptions &options, std::stop_token stop) {
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Firmware loading canceled"};
    auto parsed = options.format == firmware::Format::intel_hex
        ? firmware::parse_intel_hex(text, options.parse_options, stop)
        : firmware::parse_s_record(text, options.parse_options, stop);
    if (!parsed) return parsed.error();
    try {
        std::vector<std::byte> packed;
        packed.reserve(static_cast<std::size_t>(parsed.value().total_data_bytes));
        ImageLayout layout{{{0}, 64, 1, ByteOrder::little}, options.architecture, options.mode, {}, {}};
        FirmwareMetadata metadata;
        metadata.intel_hex = parsed.value().format == firmware::Format::intel_hex;
        metadata.has_start_address = parsed.value().has_start_address;
        metadata.start_address = parsed.value().start_address;
        metadata.records.reserve(parsed.value().segments.size());
        for (const auto &record : parsed.value().segments) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Firmware loading canceled"};
            if (record.bytes.empty()) continue;
            if (packed.size() > UINT64_MAX - record.bytes.size())
                return Error{ErrorCode::overflow, "Firmware backing extent overflow"};
            const auto file_offset = packed.size();
            packed.insert(packed.end(), record.bytes.begin(), record.bytes.end());
            layout.segments.push_back({"record-line-" + std::to_string(record.provenance.line),
                {{0}, record.address}, record.bytes.size(), {file_offset}, record.bytes.size(), true, false,
                options.executable});
            metadata.records.push_back({{{0}, record.address}, record.bytes.size(), record.provenance.line,
                record.provenance.record_index, {file_offset}});
        }
        auto storage = std::make_shared<FirmwareStorage>(std::move(packed));
        storage->bind(storage);
        if (metadata.has_start_address) {
            const Address entry{{0}, metadata.start_address};
            const auto mapped = std::any_of(layout.segments.begin(), layout.segments.end(), [&](const Segment &s) {
                return entry.offset >= s.begin.offset && entry.offset - s.begin.offset < s.file_size;
            });
            if (mapped) layout.entries.push_back(entry);
        }
        auto image = Image::create(storage, std::move(layout));
        if (!image) return image.error();
        LoadedImage result;
        result.image = std::move(image.value());
        result.metadata.format = metadata.intel_hex ? "Intel HEX" : "Motorola S-record";
        result.metadata.preferred_base = metadata.records.empty() ? 0 : metadata.records.front().address.offset;
        result.metadata.image_size = parsed.value().total_data_bytes;
        result.metadata.firmware = std::move(metadata);
        result.metadata_complete = true;
        if (result.metadata.firmware->has_start_address && result.image->layout().entries.empty())
            result.diagnostics.push_back({DiagnosticSeverity::warning,
                "Firmware start address is not covered by a data record; retained in firmware metadata", {}});
        return result;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate firmware image"};
    }
}
} // namespace hexlab

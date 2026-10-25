#include "pe_internal.hpp"
#include <bit>
#include <map>
#include <set>
#include <span>

namespace hexlab::pe_detail {
namespace {
constexpr std::uint64_t scan_limit = 32 * 1024 * 1024;
constexpr std::size_t locator_limit = 4096, type_limit = 16384, base_limit = 65536;
constexpr std::size_t slots_per_table = 256, slot_limit = 65536, name_limit = 4096;
constexpr std::uint64_t string_budget = 1024 * 1024;
constexpr std::uint64_t parse_byte_limit = 8 * 1024 * 1024;

std::uint64_t fixed(std::span<const std::byte> data, std::size_t at, unsigned width) {
    std::uint64_t value = 0;
    for (unsigned i = 0; i < width; ++i) value |= std::uint64_t(std::to_integer<unsigned>(data[at + i])) << (8 * i);
    return value;
}
struct ScanRegion { std::uint32_t rva = 0; std::vector<std::byte> bytes; bool complete_extent = true; };

class RttiReader {
public:
    RttiReader(const Image &image, const ImageMetadata &metadata, std::stop_token stop)
        : image_(image), metadata_(metadata), reader_(image, metadata, stop), stop_(stop) {}

    PeMsvcRttiMetadata read() {
        require(metadata_.pe->exception_functions.size() <= record_limit, "RTTI runtime-function lookup exceeds record budget", ErrorCode::resource_limit);
        runtime_starts_.reserve(metadata_.pe->exception_functions.size());
        for (const auto &function : metadata_.pe->exception_functions) {
            canceled(stop_); runtime_starts_.push_back(function.begin_rva);
        }
        std::sort(runtime_starts_.begin(), runtime_starts_.end());
        runtime_starts_.erase(std::unique(runtime_starts_.begin(), runtime_starts_.end()), runtime_starts_.end());
        std::vector<ScanRegion> regions;
        for (const auto &segment : image_.layout().segments) {
            canceled(stop_);
            if (segment.name == "headers" || !segment.readable || segment.writable || segment.executable || !segment.file_size) continue;
            if (output_.scanned_bytes == scan_limit) { incomplete("Read-only-data scan reached its 32 MiB limit"); break; }
            require(segment.begin.offset >= metadata_.preferred_base, "RTTI scan section precedes image base");
            const auto rva = segment.begin.offset - metadata_.preferred_base;
            require(rva < metadata_.image_size, "RTTI scan section exceeds image");
            const auto available = std::min(segment.file_size, metadata_.image_size - rva);
            const auto amount = std::min(available, scan_limit - output_.scanned_bytes);
            regions.push_back({static_cast<std::uint32_t>(rva), reader_.bytes(rva, static_cast<std::size_t>(amount)), amount == available});
            output_.scanned_bytes += amount;
            if (amount != available) { incomplete("Read-only-data scan reached its 32 MiB limit"); break; }
        }
        // COL signature 1 includes a self RVA, which must identify this exact
        // record. It is a much stronger anchor than a mangled-name scan alone.
        for (const auto &region : regions) {
            const auto first = (4 - (region.rva & 3u)) & 3u;
            for (std::size_t at = first; at <= region.bytes.size() && region.bytes.size() - at >= 24; at += 4) {
                canceled(stop_);
                const auto rva = static_cast<std::uint32_t>(std::uint64_t{region.rva} + at);
                if (fixed(region.bytes, at, 4) != 1 || fixed(region.bytes, at + 20, 4) != rva) continue;
                if (output_.locators.size() >= locator_limit) { incomplete("RTTI locator discovery reached 4096 candidates"); break; }
                PeRttiCompleteObjectLocator locator;
                locator.rva = rva; locator.signature = 1;
                locator.object_offset = static_cast<std::uint32_t>(fixed(region.bytes, at + 4, 4));
                locator.constructor_displacement = static_cast<std::uint32_t>(fixed(region.bytes, at + 8, 4));
                locator.type_descriptor_rva = static_cast<std::uint32_t>(fixed(region.bytes, at + 12, 4));
                locator.hierarchy_rva = static_cast<std::uint32_t>(fixed(region.bytes, at + 16, 4));
                locator.self_rva = rva;
                locator.source = source(rva, 24, static_cast<std::uint32_t>(output_.locators.size()));
                try {
                    type(locator.type_descriptor_rva);
                    const auto hierarchy_index = hierarchy(locator.hierarchy_rva);
                    const auto &hierarchy = output_.hierarchies[hierarchy_index];
                    require(hierarchy.bases.front().type_descriptor_rva == locator.type_descriptor_rva,
                        "RTTI locator and hierarchy self type disagree");
                    locator.state = hierarchy.state;
                    locator.diagnostic = locator.state == PeRttiRecordState::ambiguous
                        ? "Hierarchy retains ABI ambiguity attributes; no unique base conversion is inferred"
                        : "Validated signature-1 locator and class hierarchy";
                    accepted_locators_.insert(rva);
                } catch (const Failure &failure) {
                    if (failure.error.code == ErrorCode::canceled) throw;
                    locator.state = failure.error.code == ErrorCode::unsupported ? PeRttiRecordState::unsupported
                        : failure.error.code == ErrorCode::resource_limit ? PeRttiRecordState::unresolved : PeRttiRecordState::malformed;
                    locator.diagnostic = failure.error.message;
                    if (failure.error.code == ErrorCode::resource_limit) incomplete(failure.error.message);
                }
                output_.locators.push_back(std::move(locator));
            }
            if (output_.locators.size() >= locator_limit) break;
        }
        discover_tables(regions);
        return std::move(output_);
    }
private:
    void incomplete(std::string message) {
        output_.discovery_complete = false;
        if (output_.diagnostic.empty()) output_.diagnostic = std::move(message);
    }
    PeRecordSource source(std::uint64_t rva, std::uint64_t size, std::uint32_t index = 0) const {
        return {index, reader_.sources(rva, size)};
    }
    void charge(std::uint64_t size) {
        require(size <= parse_byte_limit - parse_bytes_, "RTTI descriptor inspection reached 8 MiB", ErrorCode::resource_limit);
        parse_bytes_ += size;
    }
    void data(std::uint32_t rva, std::size_t size, unsigned alignment = 4) {
        charge(size);
        require(rva != 0 && rva % alignment == 0, "RTTI data RVA is null or misaligned");
        require(rva < metadata_.image_size && size <= metadata_.image_size - rva, "RTTI data extent exceeds image");
        for (std::uint64_t at = rva, remaining = size; remaining;) {
            const auto *segment = image_.segment_at(reader_.address(at));
            require(segment && segment->readable && !segment->executable, "RTTI data is not mapped readable non-executable data");
            const auto amount = std::min(remaining, reader_.initialized_extent(at));
            at += amount; remaining -= amount;
        }
    }
    std::optional<std::uint32_t> pointer_rva(std::uint64_t va) const {
        if (va < metadata_.preferred_base || va - metadata_.preferred_base >= metadata_.image_size) return {};
        return static_cast<std::uint32_t>(va - metadata_.preferred_base);
    }
    std::size_t type(std::uint32_t rva) {
        if (const auto found = types_.find(rva); found != types_.end()) return found->second;
        require(output_.types.size() < type_limit, "RTTI type descriptor limit reached", ErrorCode::resource_limit);
        data(rva, 17, 8);
        const auto extent = reader_.initialized_extent(std::uint64_t{rva} + 16);
        charge(std::min<std::uint64_t>(extent, name_limit));
        const auto end = std::uint64_t{rva} + 16 + std::min<std::uint64_t>(extent, name_limit);
        auto name = reader_.sourced_string(std::uint64_t{rva} + 16, end);
        require(name.first.starts_with(".?AV") || name.first.starts_with(".?AU"),
            "RTTI type name is outside the supported MSVC class/struct form", ErrorCode::unsupported);
        require(name.first.size() >= 7 && name.first.ends_with("@@") &&
            std::all_of(name.first.begin(), name.first.end(), [](unsigned char ch) { return ch >= 0x21 && ch <= 0x7e; }),
            "RTTI decorated type name has invalid characters or suffix");
        require(name.first.size() + 1 <= string_budget - string_bytes_, "RTTI type names exceed 1 MiB", ErrorCode::resource_limit);
        PeRttiTypeDescriptor descriptor;
        descriptor.rva = rva;
        descriptor.type_info_vftable_va = reader_.integer<std::uint64_t>(rva);
        descriptor.spare = reader_.integer<std::uint64_t>(std::uint64_t{rva} + 8);
        descriptor.type_info_vftable_rva = pointer_rva(descriptor.type_info_vftable_va);
        descriptor.decorated_name = std::move(name.first);
        descriptor.header_source = source(rva, 16);
        descriptor.name_source.spans = std::move(name.second);
        string_bytes_ += descriptor.decorated_name.size() + 1;
        const auto index = output_.types.size();
        output_.types.push_back(std::move(descriptor)); types_.emplace(rva, index);
        return index;
    }
    std::size_t hierarchy(std::uint32_t rva) {
        if (const auto found = hierarchies_.find(rva); found != hierarchies_.end()) return found->second;
        data(rva, 16);
        PeRttiClassHierarchy result;
        result.rva = rva; result.signature = reader_.integer<std::uint32_t>(rva);
        result.attributes = reader_.integer<std::uint32_t>(std::uint64_t{rva} + 4);
        const auto count = reader_.integer<std::uint32_t>(std::uint64_t{rva} + 8);
        result.base_array_rva = reader_.integer<std::uint32_t>(std::uint64_t{rva} + 12);
        require(result.signature == 0 && !(result.attributes & ~7u), "Unsupported RTTI hierarchy signature/attributes", ErrorCode::unsupported);
        require(count != 0, "RTTI hierarchy base count is zero");
        require(count <= 4096, "RTTI hierarchy base count exceeds 4096", ErrorCode::resource_limit);
        require(count <= base_limit - base_count_, "RTTI aggregate base descriptor limit reached", ErrorCode::resource_limit);
        base_count_ += count; // Failed candidates still consume the work budget.
        data(result.base_array_rva, std::size_t{count} * 4);
        result.source = source(rva, 16);
        result.base_array_source = source(result.base_array_rva, std::uint64_t{count} * 4);
        std::vector<std::pair<std::uint32_t, std::uint32_t>> parents; // index, inclusive subtree end
        bool ambiguous = (result.attributes & 4u) != 0;
        for (std::uint32_t i = 0; i < count; ++i) {
            canceled(stop_);
            const auto entry = std::uint64_t{result.base_array_rva} + std::uint64_t{i} * 4;
            PeRttiBaseClass base;
            base.descriptor_rva = reader_.integer<std::uint32_t>(entry);
            data(base.descriptor_rva, 24);
            const auto at = std::uint64_t{base.descriptor_rva};
            base.type_descriptor_rva = reader_.integer<std::uint32_t>(at);
            type(base.type_descriptor_rva);
            base.contained_bases = reader_.integer<std::uint32_t>(at + 4);
            base.member_displacement = std::bit_cast<std::int32_t>(reader_.integer<std::uint32_t>(at + 8));
            base.vbptr_displacement = std::bit_cast<std::int32_t>(reader_.integer<std::uint32_t>(at + 12));
            base.vbtable_displacement = std::bit_cast<std::int32_t>(reader_.integer<std::uint32_t>(at + 16));
            base.attributes = reader_.integer<std::uint32_t>(at + 20);
            require(!(base.attributes & ~0x7fu), "Unsupported RTTI base-class attribute bits", ErrorCode::unsupported);
            require(base.contained_bases <= count - i - 1, "RTTI base subtree exceeds class hierarchy");
            if (i == 0) require(base.contained_bases == count - 1, "RTTI hierarchy self descriptor does not cover its base array");
            while (!parents.empty() && i > parents.back().second) parents.pop_back();
            if (i != 0) {
                require(!parents.empty() && i + base.contained_bases <= parents.back().second, "RTTI base subtrees overlap inconsistently");
                base.parent_index = parents.back().first;
            }
            parents.push_back({i, i + base.contained_bases});
            const auto descriptor_size = (base.attributes & 0x40u) ? 28u : 24u;
            if (descriptor_size == 28) {
                data(base.descriptor_rva, descriptor_size);
                const auto linked = reader_.integer<std::uint32_t>(at + 24);
                data(linked, 16); base.hierarchy_rva = linked;
            }
            base.array_entry_source = source(entry, 4, i);
            base.descriptor_source = source(at, descriptor_size, i);
            ambiguous = ambiguous || (base.attributes & 2u) != 0;
            result.bases.push_back(std::move(base));
        }
        result.state = ambiguous ? PeRttiRecordState::ambiguous : PeRttiRecordState::decoded;
        const auto index = output_.hierarchies.size();
        output_.hierarchies.push_back(std::move(result)); hierarchies_.emplace(rva, index);
        return index;
    }
    void discover_tables(const std::vector<ScanRegion> &regions) {
        for (const auto &region : regions) {
            const auto first = (8 - (region.rva & 7u)) & 7u;
            for (std::size_t at = first; at <= region.bytes.size() && region.bytes.size() - at >= 16; at += 8) {
                canceled(stop_);
                const auto locator = pointer_rva(fixed(region.bytes, at, 8));
                if (!locator || !accepted_locators_.contains(*locator)) continue;
                if (output_.vftables.size() >= locator_limit || slot_count_ >= slot_limit) {
                    incomplete("RTTI vftable/slot discovery budget reached"); return;
                }
                PeRttiVftable table;
                table.prefix_rva = static_cast<std::uint32_t>(std::uint64_t{region.rva} + at);
                table.address_point_rva = table.prefix_rva + 8; table.locator_rva = *locator;
                table.prefix_source = source(table.prefix_rva, 8);
                table.state = PeRttiRecordState::unresolved;
                table.diagnostic = "Structural vftable candidate; function run does not prove the table's complete extent or runtime dispatch";
                table.end = region.complete_extent ? PeRttiTableEnd::section_end : PeRttiTableEnd::scan_limit;
                for (std::size_t cursor = at + 8; cursor <= region.bytes.size() && region.bytes.size() - cursor >= 8; cursor += 8) {
                    canceled(stop_);
                    const auto va = fixed(region.bytes, cursor, 8);
                    const auto target = pointer_rva(va);
                    if (target && accepted_locators_.contains(*target)) { table.end = PeRttiTableEnd::next_locator_prefix; break; }
                    if (table.slots.size() >= slots_per_table || slot_count_ >= slot_limit) {
                        table.end = PeRttiTableEnd::slot_limit; incomplete("RTTI vftable slot-run limit reached"); break;
                    }
                    PeRttiVftableSlot slot;
                    slot.index = static_cast<std::uint32_t>(table.slots.size());
                    slot.rva = static_cast<std::uint32_t>(std::uint64_t{region.rva} + cursor);
                    slot.encoded_va = va; slot.target_rva = target;
                    slot.source = source(slot.rva, 8, slot.index);
                    if (!va) slot.state = PeRttiSlotState::null_pointer;
                    else if (target) {
                        const auto *segment = image_.segment_at(reader_.address(*target));
                        const auto address = reader_.address(*target);
                        if (!segment || address.offset - segment->begin.offset >= segment->file_size)
                            slot.state = PeRttiSlotState::unmapped_or_uninitialized;
                        else slot.state = segment->executable ? PeRttiSlotState::executable : PeRttiSlotState::in_image_nonexecutable;
                        if (slot.state == PeRttiSlotState::executable)
                            slot.matches_runtime_function_begin = std::binary_search(runtime_starts_.begin(), runtime_starts_.end(), *target);
                    }
                    const auto state = slot.state;
                    slot.boundary_probe = state != PeRttiSlotState::executable;
                    table.slots.push_back(std::move(slot)); ++slot_count_;
                    if (state != PeRttiSlotState::executable) {
                        table.end = state == PeRttiSlotState::null_pointer ? PeRttiTableEnd::null_pointer : PeRttiTableEnd::nonexecutable_pointer;
                        break;
                    }
                }
                output_.vftables.push_back(std::move(table));
            }
        }
    }
    const Image &image_;
    const ImageMetadata &metadata_;
    ImageReader reader_;
    std::stop_token stop_;
    PeMsvcRttiMetadata output_;
    std::map<std::uint32_t, std::size_t> types_, hierarchies_;
    std::set<std::uint32_t> accepted_locators_;
    std::vector<std::uint32_t> runtime_starts_;
    std::size_t base_count_ = 0, slot_count_ = 0;
    std::uint64_t string_bytes_ = 0, parse_bytes_ = 0;
};
} // namespace

Result<std::size_t> read_msvc_rtti(const Image &image, ImageMetadata &metadata, std::stop_token stop) {
    return guarded([&]() -> std::size_t {
        if (metadata.machine != 0x8664 || image.layout().space.width_bits != 64) return 0;
        require(metadata.pe.has_value(), "MSVC RTTI discovery requires PE metadata", ErrorCode::invalid_argument);
        auto result = RttiReader(image, metadata, stop).read();
        const auto count = result.locators.size();
        metadata.pe->msvc_rtti = std::move(result);
        return count;
    });
}
} // namespace hexlab::pe_detail

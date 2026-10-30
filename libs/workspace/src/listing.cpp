#include "hexlab/workspace/listing.hpp"
#include "hexlab/workspace/project.hpp"
#include "hexlab/analysis/relocations.hpp"
#include <algorithm>

namespace hexlab {
namespace {
bool address_less(Address a, Address b) noexcept {
    return a.space.value < b.space.value || (a.space == b.space && a.offset < b.offset);
}
bool valid(const DocumentSnapshot &document, const Location &location) {
    if (const auto *address = std::get_if<Address>(&location))
        return document.image->segment_at(*address) != nullptr;
    return std::get<FileOffset>(location).value < document.file_storage().size();
}
std::optional<Location> step(Location location, std::size_t size) {
    if (auto *address = std::get_if<Address>(&location)) {
        auto next = advance(*address, size);
        if (next)
            return Location{next.value()};
    } else {
        auto next = checked_add(std::get<FileOffset>(location).value, size);
        if (next)
            return Location{FileOffset{next.value()}};
    }
    return {};
}
Result<ByteCell> read_byte(const DocumentSnapshot &document, const Location &location) {
    const auto &image = *document.image;
    const bool shared_coordinates = image.storage().get() == &document.file_storage();
    if (const auto *address = std::get_if<Address>(&location)) {
        auto value = image.read(*address, 1);
        if (!value)
            return value.error();
        if (value.value().size() != 1)
            return Error{ErrorCode::io, "Image returned a short preview read"};
        const auto offset = image.to_file_offset(*address);
        return ByteCell{value.value()[0], *address,
                        shared_coordinates && offset ? std::optional<FileOffset>(offset.value()) : std::nullopt,
                        offset.has_value()};
    }
    const auto offset = std::get<FileOffset>(location);
    auto value = document.file_storage().read_at(offset, 1);
    if (!value)
        return value.error();
    if (value.value().bytes.size() != 1)
        return Error{ErrorCode::io, "Byte source returned a short preview read"};
    auto address = image.to_address(offset);
    return ByteCell{value.value().bytes[0],
                    shared_coordinates && address ? std::optional<Address>(address.value()) : std::nullopt, offset,
                    true};
}
const Instruction *known(const DocumentSnapshot &document, Address address) {
    if (document.project) {
        auto &project = *document.project;
        if (!project.loaded || !project.functions || !project.functions->key ||
            project.functions->key->byte_revision != project.state->revisions.bytes ||
            project.functions->key->decision_revision != project.state->revisions.decisions)
            return nullptr;
        auto &instructions = project.functions->instructions;
        auto found = std::lower_bound(instructions.begin(), instructions.end(), address, [](auto &fact, Address at) {
            return address_less(fact->instruction.address, at);
        });
        return found != instructions.end() && (*found)->instruction.address == address ? &(*found)->instruction
                                                                                       : nullptr;
    }
    if (!document.analysis)
        return nullptr;
    const auto &instructions = document.analysis->instructions;
    auto found = std::lower_bound(instructions.begin(), instructions.end(), address,
                                  [](const auto &i, Address at) { return address_less(i.address, at); });
    return found != instructions.end() && found->address == address ? &*found : nullptr;
}
struct Regions {
    std::vector<const RegionDecision *> rows;
    static bool less(Address a, Address b) { return address_less(a, b); }
    explicit Regions(const DocumentSnapshot &document) {
        if (document.project) {
            for (auto &row : document.project->state->user->decisions.regions)
                rows.push_back(&row);
            std::sort(rows.begin(), rows.end(), [](auto a, auto b) { return less(a->begin, b->begin); });
        }
    }
    auto next(Address at) const {
        return std::upper_bound(rows.begin(), rows.end(), at,
                                [](auto address, auto region) { return less(address, region->begin); });
    }
    const RegionDecision *at(Address address) const {
        auto found = next(address);
        if (found == rows.begin())
            return nullptr;
        auto region = *std::prev(found);
        return region->begin.space == address.space && address.offset >= region->begin.offset &&
                       address.offset - region->begin.offset < region->size
                   ? region
                   : nullptr;
    }
};
Result<DecodeResult> manual_decode(const DocumentSnapshot &document, Address address, const Regions &regions) {
    if (!document.project)
        return decode_at(*document.image, address);
    auto &image = *document.image;
    auto context = image.context_at(address);
    if (!context)
        return context.error();
    if (!processor_capabilities(context.value()).can_decode)
        return Error{ErrorCode::unsupported, "This processor mode has no manual decoder"};
    const std::size_t decode_window = context.value().architecture == Architecture::wasm &&
            context.value().mode == ExecutionMode::wasm32
        ? 32u : 15u;
    std::array<std::byte, 32> input{};
    std::size_t count = 0;
    auto cursor = address;
    while (count < decode_window) {
        auto segment = image.segment_at(cursor);
        if (!segment)
            break;
        auto region = regions.at(cursor);
        if (region && region->kind == RegionKind::data)
            break;
        if (!segment->executable && (!region || region->kind != RegionKind::code))
            break;
        auto relative = cursor.offset - segment->begin.offset;
        if (relative >= segment->file_size)
            break;
        auto amount =
            std::min<uint64_t>(image.code_window(cursor, decode_window - count), segment->file_size - relative);
        if (!amount)
            break;
        if (region)
            amount = std::min(amount, region->size - (cursor.offset - region->begin.offset));
        else {
            auto next = regions.next(cursor);
            if (next != regions.rows.end() && (*next)->begin.space == cursor.space)
                amount = std::min(amount, (*next)->begin.offset - cursor.offset);
        }
        auto bytes = image.storage()->read_at({segment->file_begin.value + relative}, std::size_t(amount));
        if (!bytes)
            return bytes.error();
        if (bytes.value().bytes.size() != amount)
            return Error{ErrorCode::io, "Manual decode source returned a short read"};
        std::copy(bytes.value().bytes.begin(), bytes.value().bytes.end(), input.begin() + std::ptrdiff_t(count));
        count += std::size_t(amount);
        auto next = advance(cursor, amount);
        if (!next)
            break;
        cursor = next.value();
    }
    return decode_instruction(context.value(), std::span(input).first(count), address);
}
} // namespace
Result<BytesPage> make_bytes_page(const DocumentSnapshot &document, Location location, std::size_t limit) {
    if (!document.image || !limit || limit > 4096)
        return Error{ErrorCode::invalid_argument, "Invalid bytes page request"};
    BytesPage page{location, {}, {}};
    if (document.file_storage().size() == 0 && location == Location{FileOffset{0}})
        return page;
    if (!valid(document, location))
        return Error{ErrorCode::out_of_bounds, "Initial byte location is not mapped"};
    try {
        for (std::size_t n = 0; n < limit; ++n) {
            auto cell = read_byte(document, location);
            if (!cell)
                return cell.error();
            page.cells.push_back(cell.value());
            auto next = step(location, 1);
            if (!next || !valid(document, *next))
                return page;
            location = *next;
        }
        page.next = location;
        return page;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate bytes page"};
    }
}
Result<ListingPage> make_listing_page(const DocumentSnapshot &document, Location location, std::size_t limit) {
    return make_listing_page(document, location, limit, ListingOptions{});
}
Result<ListingPage> make_listing_page(const DocumentSnapshot &document, Location location, std::size_t limit,
                                      ListingOptions options) {
    if (options.stop.stop_requested())
        return Error{ErrorCode::canceled, "Listing canceled"};
    if (!document.image || !limit || limit > 4096)
        return Error{ErrorCode::invalid_argument, "Invalid listing page request"};
    ListingPage page;
    if (document.file_storage().size() == 0 && location == Location{FileOffset{0}})
        return page;
    if (!valid(document, location))
        return Error{ErrorCode::out_of_bounds, "Initial listing location is not mapped"};
    bool manual = options.manual_decode && std::holds_alternative<Address>(location) &&
                  !known(document, std::get<Address>(location));
    try {
        Regions regions(document);
        std::optional<RelocationResolver> relocations;
        if (options.manual_decode) {
            auto created = RelocationResolver::create(*document.image, document.metadata_view(), options.stop);
            if (!created)
                return created.error();
            relocations = std::move(created.value());
        }
        for (std::size_t n = 0; n < limit; ++n) {
            if (options.stop.stop_requested())
                return Error{ErrorCode::canceled, "Listing canceled"};
            ListingRow row{location, {}, {}, false, "data"};
            if (const auto *address = std::get_if<Address>(&location)) {
                if (!document.image->code_window(*address, 1)) {
                    manual = false;
                    row.status = "declared data/encrypted bytes";
                } else if (auto region = regions.at(*address); region && region->kind == RegionKind::data) {
                    manual = false;
                    row.status = "manual data";
                } else if (const auto *instruction = known(document, *address)) {
                    if (document.image->code_window(*address, instruction->length) == instruction->length) {
                        row.instruction = *instruction;
                        row.reachable = true;
                        row.status = "reachable";
                    } else {
                        manual = false;
                        row.status = "instruction crosses declared data/encrypted bytes";
                    }
                } else if (manual) {
                    auto decoded = manual_decode(document, *address, regions);
                    if (!decoded && decoded.error().code == ErrorCode::io)
                        return decoded.error();
                    if (decoded && decoded.value().instruction) {
                        row.instruction = std::move(decoded.value().instruction);
                        row.status = "manual decode";
                    } else {
                        manual = false;
                        row.status = decoded ? decoded.value().reason : decoded.error().message;
                    }
                }
            }
            std::size_t length = 1;
            if (row.instruction) {
                if (relocations) {
                    auto target = relocations->control_target(*document.image, *row.instruction, options.stop);
                    if (!target)
                        return target.error();
                    if (target.value() && document.image->code_window(*target.value(), 1))
                        row.control_target = target.value();
                }
                length = row.instruction->length;
                row.bytes.assign(row.instruction->bytes.begin(), row.instruction->bytes.begin() + length);
                const auto flow = row.instruction->flow;
                if (flow == FlowKind::ret || flow == FlowKind::trap || flow == FlowKind::jump)
                    manual = false;
            } else {
                auto cell = read_byte(document, location);
                if (!cell)
                    return cell.error();
                row.bytes.push_back(cell.value().value);
                if (!cell.value().initialized)
                    row.status = "zero-filled data";
                if (const auto *address = std::get_if<Address>(&location); address && document.analysis) {
                    const auto &stops = document.analysis->stops;
                    auto at = std::lower_bound(stops.begin(), stops.end(), *address, [](const auto &stop, Address at) {
                        return address_less(stop.address, at);
                    });
                    if (at != stops.end() && at->address == *address)
                        row.status = at->detail;
                }
            }
            page.rows.push_back(std::move(row));
            auto next = step(location, length);
            if (!next || !valid(document, *next))
                return page;
            location = *next;
        }
        page.next = location;
        return page;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate listing page"};
    }
}
} // namespace hexlab

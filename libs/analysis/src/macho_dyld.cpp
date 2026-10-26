#include "hexlab/analysis/macho_dyld.hpp"
#include "hexlab/image/macho_mapping.hpp"
#include <algorithm>
#include <atomic>
#include <map>
#include <tuple>
namespace hexlab {
namespace {
struct Failure {
    Error error;
};
void require(bool ok, const char *text, ErrorCode code = ErrorCode::malformed) {
    if (!ok)
        throw Failure{{code, text}};
}
void canceled(std::stop_token stop) {
    require(!stop.stop_requested(), "Mach-O dyld resolution canceled", ErrorCode::canceled);
}
template <class F> auto guarded(F operation) -> decltype(operation()) {
    try {
        return operation();
    } catch (const Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate Mach-O dyld index"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "Mach-O dyld allocation limit"};
    }
}
bool plus(std::int64_t a, std::int64_t b, std::int64_t &out) {
    if ((b > 0 && a > INT64_MAX - b) || (b < 0 && a < INT64_MIN - b))
        return false;
    out = a + b;
    return true;
}
} // namespace
struct MachODyldResolver::State {
    struct Interval {
        std::uint64_t begin, end, maximum;
        MachODyldIdentity identity;
    };
    const Image *image = nullptr;
    const MachOMetadata *metadata = nullptr;
    std::optional<Address> header_anchor;
    std::map<std::uint32_t, std::vector<Interval>> domains;
    mutable std::atomic<std::uint64_t> work_left{0};
    std::uint32_t max_matches = 4096;
    void charge() const {
        auto left = work_left.load(std::memory_order_relaxed);
        for (;;) {
            require(left != 0, "Mach-O dyld lookup budget exhausted", ErrorCode::resource_limit);
            if (work_left.compare_exchange_weak(left, left - 1, std::memory_order_relaxed))
                return;
        }
    }
    static void build(std::vector<Interval> &rows, std::stop_token stop) {
        std::sort(rows.begin(), rows.end(), [stop](const auto &a, const auto &b) {
            canceled(stop);
            return std::tie(a.begin, a.identity) < std::tie(b.begin, b.identity);
        });
        const auto mark = [&](auto &&self, std::size_t first, std::size_t last) -> std::uint64_t {
            if (first == last)
                return 0;
            canceled(stop);
            const auto middle = first + (last - first) / 2;
            return rows[middle].maximum =
                       std::max({rows[middle].end, self(self, first, middle), self(self, middle + 1, last)});
        };
        (void)mark(mark, 0, rows.size());
    }
    void query(Address at, std::uint8_t width, std::vector<MachODyldIdentity> &matches, std::stop_token stop) const {
        require(width && width <= 8, "Invalid dyld field query width", ErrorCode::invalid_argument);
        require(width <= UINT64_MAX - at.offset, "Dyld query interval overflow", ErrorCode::overflow);
        const auto found = domains.find(at.space.value);
        if (found == domains.end())
            return;
        const auto end = at.offset + width;
        const auto &rows = found->second;
        const auto visit = [&](auto &&self, std::size_t first, std::size_t last) -> void {
            if (first == last)
                return;
            canceled(stop);
            charge();
            const auto middle = first + (last - first) / 2;
            const auto &row = rows[middle];
            if (row.maximum <= at.offset || rows[first].begin >= end)
                return;
            self(self, first, middle);
            if (row.begin < end && row.end > at.offset) {
                require(matches.size() < max_matches, "Mach-O dyld match limit", ErrorCode::resource_limit);
                matches.push_back(row.identity);
            }
            if (row.begin < end)
                self(self, middle + 1, last);
        };
        visit(visit, 0, rows.size());
        std::sort(matches.begin(), matches.end());
    }
    std::pair<std::optional<Address>, std::uint8_t> location(MachODyldIdentity id) const {
        require(metadata != nullptr, "No Mach-O dyld metadata", ErrorCode::invalid_argument);
        if (id.source == MachODyldSource::classic) {
            require(id.row < metadata->dyld_fixups.size(), "Classic dyld row outside namespace",
                    ErrorCode::invalid_argument);
            const auto &row = metadata->dyld_fixups[static_cast<std::size_t>(id.row)];
            return {row.place, row.field_size};
        }
        require(id.source == MachODyldSource::chained && id.row < metadata->chained_pointers.size(),
                "Chained dyld row outside namespace", ErrorCode::invalid_argument);
        const auto &row = metadata->chained_pointers[static_cast<std::size_t>(id.row)];
        return {row.place, row.field_size};
    }
    MachODyldResolution solve(MachODyldResolution out, Address at, std::uint8_t width) const {
        using R = MachODyldResolutionReason;
        const auto fail = [&](R reason) {
            out.reason = reason;
            return std::move(out);
        };
        if (out.origins.empty())
            return out;
        if (out.origins.size() != 1)
            return fail(R::ambiguous);
        const auto id = out.origins.front();
        const auto [place, size] = location(id);
        if (!place || !size)
            return fail(R::unavailable_field);
        if (*place != at || size != width)
            return fail(R::field_mismatch);
        if (image->plaintext_window(at, width) != width)
            return fail(R::unsupported);
        const auto &slice = metadata->container.slices[metadata->selected_slice];
        if (slice.header.file_type == 1)
            return fail(R::unsupported);
        std::uint64_t target = 0;
        if (id.source == MachODyldSource::classic) {
            const auto &row = metadata->dyld_fixups[static_cast<std::size_t>(id.row)];
            if (row.type != 1 || size != (slice.header.is_64 ? 8 : 4))
                return fail(R::unsupported);
            if (metadata->dyld_streams[row.stream].kind != MachODyldStreamKind::rebase) {
                out.binding =
                    MachODyldBinding{row.library_ordinal, row.symbol, row.addend, bool(row.symbol_flags & 1), {}};
                return fail(R::runtime_binding);
            }
            if (!row.encoded_value)
                return fail(R::unavailable_field);
            target = *row.encoded_value;
        } else {
            const auto &row = metadata->chained_pointers[static_cast<std::size_t>(id.row)];
            const auto &starts = metadata->chained_starts[row.starts];
            const auto &header = metadata->chained_headers[row.header];
            const auto format = starts.pointer_format;
            const bool generic = format == 2 || format == 3 || format == 6;
            const bool arm64e = format == 1 || format == 7 || format == 9 || format == 10 || format == 12;
            if (!row.complete || !starts.complete || header.version || (!generic && !arm64e) ||
                slice.header.order != ByteOrder::little || size != (slice.header.is_64 ? 8 : 4) ||
                (format == 3) == slice.header.is_64)
                return fail(R::unsupported);
            if (row.authenticated)
                return fail(R::authenticated);
            if (row.non_pointer) {
                if (row.scalar_value)
                    out.constant = *row.scalar_value;
                return fail(R::non_pointer);
            }
            if (row.bind) {
                if (!row.import_row)
                    return fail(R::unsupported);
                const auto &import = metadata->chained_imports[static_cast<std::size_t>(*row.import_row)];
                if (!import.complete || !import.name)
                    return fail(R::unsupported);
                std::int64_t addend = 0;
                if (!plus(import.addend, row.addend, addend))
                    return fail(R::overflow);
                out.binding =
                    MachODyldBinding{import.library_ordinal, *import.name, addend, import.weak_import, row.import_row};
                return fail(R::runtime_binding);
            }
            if (!row.target)
                return fail(R::unavailable_field);
            target = *row.target | (std::uint64_t(row.high8) << 56);
            if (row.target_is_offset) {
                if (!header_anchor)
                    return fail(R::missing_anchor);
                if (target > UINT64_MAX - header_anchor->offset)
                    return fail(R::overflow);
                target += header_anchor->offset;
            }
        }
        const Address value{at.space, target};
        if (!image->segment_at(value))
            return fail(R::unmapped_target);
        out.address = value;
        return fail(R::resolved);
    }
};
Result<MachODyldResolver> MachODyldResolver::create(const Image &image, const ImageMetadata &metadata,
                                                    std::stop_token stop) {
    return create(image, metadata, MachODyldResolutionLimits{}, stop);
}
Result<MachODyldResolver> MachODyldResolver::create(const Image &image, const ImageMetadata &metadata,
                                                    MachODyldResolutionLimits limits, std::stop_token stop) {
    return guarded([&]() -> Result<MachODyldResolver> {
        canceled(stop);
        require(limits.lookup_work && limits.max_matches && limits.max_matches <= 4096, "Invalid dyld lookup limits",
                ErrorCode::invalid_argument);
        require(!(metadata.macho && metadata.elf), "Multiple authoritative dyld formats", ErrorCode::invalid_argument);
        auto state = std::make_shared<State>();
        state->image = &image;
        state->work_left = limits.lookup_work;
        state->max_matches = limits.max_matches;
        if (!metadata.macho)
            return MachODyldResolver{std::move(state)};
        state->metadata = &*metadata.macho;
        const auto &m = *state->metadata;
        require(m.selected_slice < m.container.slices.size(), "Missing selected dyld slice");
        require(m.dyld_fixups.size() <= 1000000 && m.chained_pointers.size() <= 1000000, "Dyld source count limit",
                ErrorCode::resource_limit);
        const auto &slice = m.container.slices[m.selected_slice];
        require(slice.offset <= image.storage()->size() && slice.size <= image.storage()->size() - slice.offset,
                "Dyld slice exceeds original storage");
        const auto anchor = macho_header_anchor(image, slice, stop);
        if (!anchor)
            return anchor.error();
        state->header_anchor = anchor.value();
        std::uint64_t budget = 0;
        const auto index = [&](MachODyldIdentity id, std::uint32_t segment, std::uint64_t offset,
                               std::optional<Address> place, std::optional<FileOffset> file, std::uint8_t width) {
            require(segment < m.segments.size(), "Dyld segment outside command namespace");
            const auto &raw = m.segments[segment];
            const auto extent = width ? width : 1;
            require(offset <= raw.memory_size && extent <= raw.memory_size - offset, "Dyld slot exceeds segment");
            if (!place) {
                require(!file, "File dyld slot lacks canonical VM location");
                return;
            }
            require(offset <= UINT64_MAX - raw.address && *place == Address{{0}, raw.address + offset},
                    "Dyld VM location differs from original segment");
            require(extent <= UINT64_MAX - place->offset, "Dyld slot interval overflow", ErrorCode::overflow);
            std::optional<FileOffset> first;
            bool contiguous = true;
            for (std::uint64_t i = 0; i < extent; ++i) {
                canceled(stop);
                const Address at{place->space, place->offset + i};
                require(image.segment_at(at) != nullptr, "Dyld slot crosses unmapped image");
                const auto current = image.to_file_offset(at);
                if (!current)
                    contiguous = false;
                else if (!i)
                    first = current.value();
                else if (!first || current.value().value != first->value + i)
                    contiguous = false;
            }
            if (!width)
                contiguous = false;
            require(file == (contiguous ? first : std::nullopt), "Dyld source backing differs from canonical image");
            const auto cost = sizeof(State::Interval) * 2 + (state->domains.contains(place->space.value) ? 0 : 128);
            require(cost <= 64 * 1024 * 1024 - budget, "Dyld index allocation budget", ErrorCode::resource_limit);
            budget += cost;
            state->domains[place->space.value].push_back({place->offset, place->offset + extent, 0, id});
        };
        for (std::uint64_t i = 0; i < m.dyld_fixups.size(); ++i) {
            canceled(stop);
            const auto &row = m.dyld_fixups[static_cast<std::size_t>(i)];
            require(row.stream < m.dyld_streams.size() && row.operation < m.dyld_operations.size() &&
                        m.dyld_operations[row.operation].stream == row.stream,
                    "Invalid classic dyld source namespace");
            const auto kind = m.dyld_streams[row.stream].kind;
            require(kind == MachODyldStreamKind::rebase || kind == MachODyldStreamKind::bind ||
                        kind == MachODyldStreamKind::weak_bind || kind == MachODyldStreamKind::lazy_bind,
                    "Classic dyld fixup belongs to non-opcode stream");
            require(row.field_size == 0 || row.field_size == 4 || row.field_size == 8,
                    "Invalid classic dyld field width");
            index({MachODyldSource::classic, i}, row.segment_index, row.segment_offset, row.place, row.file_place,
                  row.field_size);
        }
        for (std::uint64_t i = 0; i < m.chained_pointers.size(); ++i) {
            canceled(stop);
            const auto &row = m.chained_pointers[static_cast<std::size_t>(i)];
            require(row.header < m.chained_headers.size() && row.starts < m.chained_starts.size() &&
                        m.chained_starts[row.starts].header == row.header,
                    "Invalid chained dyld source namespace");
            const auto &header = m.chained_headers[row.header];
            require(header.stream < m.dyld_streams.size() &&
                        m.dyld_streams[header.stream].kind == MachODyldStreamKind::chained,
                    "Chained dyld header belongs to non-chained stream");
            require(row.field_size == 4 || row.field_size == 8, "Invalid chained dyld field width");
            if (row.import_row) {
                require(row.bind && row.import_index && *row.import_index < header.imports_count &&
                            *row.import_row < m.chained_imports.size(),
                        "Invalid chained import identity");
                const auto &import = m.chained_imports[static_cast<std::size_t>(*row.import_row)];
                require(import.header == row.header && import.index == *row.import_index &&
                            header.first_import_row <= *row.import_row &&
                            *row.import_row - header.first_import_row == *row.import_index,
                        "Chained pointer import crosses header namespace");
            }
            index({MachODyldSource::chained, i}, m.chained_starts[row.starts].segment_index, row.segment_offset,
                  row.place, row.file_place, row.field_size);
        }
        for (auto &[domain, rows] : state->domains)
            State::build(rows, stop);
        return MachODyldResolver{std::move(state)};
    });
}
Result<MachODyldResolution> MachODyldResolver::slot(Address at, std::uint8_t width, std::stop_token stop) const {
    return guarded([&]() -> Result<MachODyldResolution> {
        canceled(stop);
        MachODyldResolution out;
        state_->query(at, width, out.origins, stop);
        return state_->solve(std::move(out), at, width);
    });
}
Result<MachODyldResolution> MachODyldResolver::data(MachODyldIdentity id, std::stop_token stop) const {
    return guarded([&]() -> Result<MachODyldResolution> {
        canceled(stop);
        const auto [at, width] = state_->location(id);
        MachODyldResolution out;
        if (!at) {
            out.origins.push_back(id);
            out.reason = MachODyldResolutionReason::unavailable_field;
            return out;
        }
        state_->query(*at, width ? width : 1, out.origins, stop);
        return state_->solve(std::move(out), *at, width);
    });
}
std::optional<Address> MachODyldResolver::preferred_header() const noexcept { return state_->header_anchor; }
} // namespace hexlab

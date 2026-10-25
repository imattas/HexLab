#include "hexlab/analysis/string_references.hpp"

#include <algorithm>

namespace hexlab {
namespace {
constexpr std::size_t max_string_references = 4000000;
using Key = std::tuple<unsigned, std::uint32_t, std::uint64_t>;
Key key(Location location) {
    if (const auto *address = std::get_if<Address>(&location))
        return {0, address->space.value, address->offset};
    return {1, 0, std::get<FileOffset>(location).value};
}
}

Result<StringReferenceScan> find_string_references(const ReferenceIndex &references, const StringScan &strings,
                                                    std::stop_token stop) {
    if (stop.stop_requested())
        return Error{ErrorCode::canceled, "String reference scan canceled"};
    try {
        StringReferenceScan result;
        result.complete = references.complete() && strings.complete;
        std::map<Key, std::vector<const Reference *>> targets;
        for (const auto &reference : references.all()) {
            if (stop.stop_requested())
                return Error{ErrorCode::canceled, "String reference scan canceled"};
            const auto *target = std::get_if<Location>(&reference.target);
            if (target)
                targets[key(*target)].push_back(&reference);
        }
        const auto emit_matches = [&](std::size_t string_index, Key begin, std::uint64_t length) {
            if (!length)
                return;
            auto current = targets.lower_bound(begin);
            for (; current != targets.end(); ++current) {
                const auto &[domain, space, offset] = current->first;
                const auto &[start_domain, start_space, start_offset] = begin;
                if (domain != start_domain || space != start_space || offset < start_offset ||
                    offset - start_offset >= length)
                    break;
                if (stop.stop_requested())
                    return;
                for (const auto *reference : current->second) {
                    if (result.records.size() == max_string_references) {
                        result.complete = false;
                        return;
                    }
                    result.records.push_back({reference->id, reference->source, reference->operand_index,
                                              string_index, reference->kind});
                }
            }
        };
        for (std::size_t i = 0; i < strings.records.size(); ++i) {
            if (stop.stop_requested())
                return Error{ErrorCode::canceled, "String reference scan canceled"};
            const auto &string = strings.records[i];
            emit_matches(i, {1, 0, string.file_offset.value}, string.byte_length);
            if (stop.stop_requested())
                return Error{ErrorCode::canceled, "String reference scan canceled"};
            if (result.records.size() == max_string_references) {
                result.complete = false;
                break;
            }
            if (string.address)
                emit_matches(i, {0, string.address->space.value, string.address->offset}, string.byte_length);
            if (stop.stop_requested())
                return Error{ErrorCode::canceled, "String reference scan canceled"};
            if (result.records.size() == max_string_references) {
                result.complete = false;
                break;
            }
        }
        std::sort(result.records.begin(), result.records.end(), [](const auto &a, const auto &b) {
            return std::tuple{key(a.source), a.operand_index, a.reference, a.string_index} <
                   std::tuple{key(b.source), b.operand_index, b.reference, b.string_index};
        });
        return result;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate string reference results"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "String reference results exceed allocation limits"};
    }
}
} // namespace hexlab

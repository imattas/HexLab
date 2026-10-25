#include "hexlab/image/image.hpp"
#include "hexlab/core/encoding.hpp"
#include <algorithm>
#include <string_view>
namespace hexlab {
namespace {
struct Failed {
    Error error;
};
struct MappingHash {
    Sha256 sha;
    std::stop_token stop;
    void bytes(std::span<const std::byte> value) {
        if (stop.stop_requested())
            throw Failed{{ErrorCode::canceled, "Image mapping fingerprint canceled"}};
        auto updated = sha.update(value);
        if (!updated)
            throw Failed{updated.error()};
    }
    void number(std::uint64_t value) { bytes(encode_u64(value)); }
    void text(std::string_view value) {
        number(value.size());
        bytes(std::as_bytes(std::span(value)));
    }
    void space(const AddressSpace &value) {
        number(value.id.value);
        number(value.width_bits);
        number(value.unit_bytes);
        number(static_cast<std::uint64_t>(value.order));
    }
    void address(Address value) {
        number(value.space.value);
        number(value.offset);
    }
    void context(DecodeContext value) {
        number(static_cast<std::uint64_t>(value.architecture));
        number(static_cast<std::uint64_t>(value.mode));
        number(static_cast<std::uint64_t>(value.order));
        number(value.stack_address_width);
        number(value.segmented_memory);
    }
    void descriptor(const X86SegmentDescriptor &d) {
        number(d.base);
        number(d.effective_limit);
        number(d.present);
        number(d.executable);
        number(d.readable);
        number(d.writable);
        number(d.expand_down);
        number(d.default_big);
        number(d.conforming);
        number(d.dpl);
    }
    void arm_sources(const std::vector<ArmContextSource> &sources) {
        number(sources.size());
        for (const auto &source : sources) {
            number(static_cast<std::uint64_t>(source.kind));
            number(source.namespace_id);
            number(source.record_index);
            number(source.evidence.has_value());
            if (source.evidence) {
                number(source.evidence->begin.value);
                number(source.evidence->size);
            }
        }
    }
};
} // namespace
Result<Sha256Digest> Image::mapping_fingerprint(std::stop_token stop) const {
    try {
        MappingHash out{{}, stop};
        out.text("HexLab/image-basis/v1");
        out.number(storage_->size());
        out.space(layout_.space);
        out.context(decode_context());
        out.number(layout_.domains.size());
        for (const auto &d : layout_.domains) {
            out.space(d.space);
            out.context(d.context);
        }
        out.number(layout_.segments.size());
        for (const auto &s : layout_.segments) {
            out.text(s.name);
            out.address(s.begin);
            out.number(s.size);
            out.number(s.file_begin.value);
            out.number(s.file_size);
            out.number(s.readable);
            out.number(s.writable);
            out.number(s.executable);
        }
        out.number(layout_.entries.size());
        for (const auto entry : layout_.entries)
            out.address(entry);
        out.number(layout_.x86_profile.has_value());
        if (layout_.x86_profile) {
            const auto &p = *layout_.x86_profile;
            out.number(static_cast<std::uint64_t>(p.environment));
            out.number(static_cast<std::uint64_t>(p.a20));
            out.number(p.input_load_address.has_value());
            if (p.input_load_address)
                out.number(*p.input_load_address);
            out.number(p.stack_selector.has_value());
            if (p.stack_selector)
                out.number(*p.stack_selector);
            std::vector<const X86ImageBinding *> bindings;
            for (const auto &b : p.bindings)
                bindings.push_back(&b);
            std::sort(bindings.begin(), bindings.end(), [](auto a, auto b) { return a->space.value < b->space.value; });
            out.number(bindings.size());
            for (const auto *b : bindings) {
                out.number(b->space.value);
                out.number(b->selector);
                out.number(b->descriptor.has_value());
                if (b->descriptor)
                    out.descriptor(*b->descriptor);
            }
        }
        // Empty policy retains the exact historical mapping identity.
        if (!layout_.code_exclusions.empty() || !layout_.encrypted_ranges.empty()) {
            out.text("HexLab/code-policy/v1");
            for (const auto *rows : {&layout_.code_exclusions, &layout_.encrypted_ranges}) {
                out.number(rows->size());
                for (const auto &row : *rows) {
                    out.address(row.begin);
                    out.number(row.size);
                }
            }
        }
        // Absent ARM profiles retain exact historical mapping bytes.
        if (layout_.arm_profile) {
            out.text("HexLab/arm-context/v1");
            out.number(layout_.arm_profile->ranges.size());
            for (const auto &range : layout_.arm_profile->ranges) {
                out.address(range.begin);
                out.number(range.size);
                out.number(static_cast<std::uint64_t>(range.kind));
                out.arm_sources(range.sources);
            }
            out.number(layout_.arm_profile->roots.size());
            for (const auto &root : layout_.arm_profile->roots) {
                out.address(root.at);
                out.number(static_cast<std::uint64_t>(root.mode));
                out.number(root.known_thumb_it_clear);
                out.arm_sources(root.sources);
            }
        }
        if (layout_.execution_profile) {
            out.text("HexLab/execution-profile/v1");
            out.number(layout_.execution_profile->ranges.size());
            for (const auto &range : layout_.execution_profile->ranges) {
                out.address(range.begin);
                out.number(range.size);
                out.context(range.context);
            }
        }
        return out.sha.digest();
    } catch (const Failed &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate mapping fingerprint metadata"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "Mapping fingerprint metadata exceeds container bounds"};
    }
}
} // namespace hexlab

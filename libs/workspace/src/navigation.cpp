#include "hexlab/workspace/navigation.hpp"
#include "hexlab/workspace/project.hpp"
#include <algorithm>
namespace hexlab {
Result<std::uint64_t> parse_address(std::wstring_view text) {
    unsigned base = 10;
    if (text.size() >= 2 && text[0] == L'0' && (text[1] == L'x' || text[1] == L'X')) {
        base = 16;
        text.remove_prefix(2);
    }
    if (text.empty())
        return Error{ErrorCode::invalid_argument, "Address requires digits"};
    std::uint64_t value = 0;
    for (const auto character : text) {
        unsigned digit;
        if (character >= L'0' && character <= L'9')
            digit = static_cast<unsigned>(character - L'0');
        else if (character >= L'a' && character <= L'f')
            digit = static_cast<unsigned>(character - L'a' + 10);
        else if (character >= L'A' && character <= L'F')
            digit = static_cast<unsigned>(character - L'A' + 10);
        else
            return Error{ErrorCode::invalid_argument, "Address contains an invalid character"};
        if (digit >= base)
            return Error{ErrorCode::invalid_argument, "Address digit is not valid for its base"};
        auto product = checked_multiply(value, base);
        if (!product)
            return product.error();
        auto sum = checked_add(product.value(), digit);
        if (!sum)
            return sum.error();
        value = sum.value();
    }
    return value;
}
Result<X86LogicalAddress> parse_x86_logical_address(std::wstring_view text) {
    if (text.size() > 32)
        return Error{ErrorCode::invalid_argument, "Selector:offset exceeds supported width"};
    const auto colon = text.find(L':');
    if (colon == text.npos || text.find(L':', colon + 1) != text.npos)
        return Error{ErrorCode::invalid_argument, "Enter selector:offset in hexadecimal"};
    const auto field = [](std::wstring_view part) -> Result<std::uint64_t> {
        if (part.starts_with(L"0x") || part.starts_with(L"0X"))
            part.remove_prefix(2);
        if (part.empty())
            return Error{ErrorCode::invalid_argument, "Selector:offset requires both fields"};
        std::uint64_t value = 0;
        for (auto c : part) {
            const unsigned digit = c >= L'0' && c <= L'9'   ? unsigned(c - L'0')
                                   : c >= L'a' && c <= L'f' ? unsigned(c - L'a') + 10
                                   : c >= L'A' && c <= L'F' ? unsigned(c - L'A') + 10
                                                            : 16;
            if (digit == 16 || value > (UINT32_MAX - digit) / 16)
                return Error{ErrorCode::invalid_argument, "Invalid or oversized hexadecimal selector:offset"};
            value = value * 16 + digit;
        }
        return value;
    };
    auto selector = field(text.substr(0, colon));
    if (!selector)
        return selector.error();
    auto offset = field(text.substr(colon + 1));
    if (!offset)
        return offset.error();
    if (selector.value() > UINT16_MAX)
        return Error{ErrorCode::invalid_argument, "Selector exceeds 16 bits"};
    return X86LogicalAddress{static_cast<std::uint16_t>(selector.value()), static_cast<std::uint32_t>(offset.value())};
}
Result<Address> parse_segment_address(const Image &image, std::wstring_view text) {
    auto logical = parse_x86_logical_address(text);
    if (!logical)
        return logical.error();
    return image.from_logical(logical.value());
}
namespace {
std::string hexadecimal(std::uint64_t value, unsigned width = 1) {
    char buffer[16];
    auto cursor = std::end(buffer);
    do {
        *--cursor = "0123456789ABCDEF"[value & 15];
        value >>= 4;
    } while (value);
    while (std::end(buffer) - cursor < width)
        *--cursor = '0';
    return {cursor, std::end(buffer)};
}
} // namespace
std::string format_location(Location location, const Image *image) {
    if (const auto *file = std::get_if<FileOffset>(&location))
        return "file:0x" + hexadecimal(file->value);
    const auto at = std::get<Address>(location);
    if (image && image->layout().x86_profile) {
        const auto logical = image->logical_address(at);
        if (logical) {
            auto context = image->context_at(at);
            const auto width =
                logical.value().offset > 0xffff || (context && context.value().mode == ExecutionMode::x86_32) ? 8u : 4u;
            return hexadecimal(logical.value().selector, 4) + ":" + hexadecimal(logical.value().offset, width);
        }
    }
    return (at.space.value ? "va:" + std::to_string(at.space.value) + ":" : "") + "0x" + hexadecimal(at.offset);
}
Result<std::optional<Address>> project_follow_target(const ProjectSnapshot &project, Address source) {
    if (!project.state || !project.loaded || !project.functions || !project.references || !project.derived_key ||
        !project.basis || (project.status != DerivedStatus::fresh && project.status != DerivedStatus::incomplete))
        return Error{ErrorCode::conflict, "Follow requires current decoded references"};
    const auto &key = *project.derived_key;
    if (key.input != project.state->input || key.byte_revision != project.state->revisions.bytes ||
        key.decision_revision != project.state->revisions.decisions || project.functions->key != project.derived_key ||
        project.references->key() != project.derived_key || project.basis->key != key ||
        project.basis->image != project.loaded->image)
        return Error{ErrorCode::conflict, "Follow references belong to another source"};
    const auto fact = std::lower_bound(project.functions->instructions.begin(), project.functions->instructions.end(),
                                       source, [](const auto &fact, Address at) {
                                           const auto value = fact->instruction.address;
                                           return value.space.value < at.space.value ||
                                                  (value.space == at.space && value.offset < at.offset);
                                       });
    if (fact == project.functions->instructions.end() || (*fact)->instruction.address != source)
        return std::optional<Address>{};
    if (project.loaded->image->code_window(source, (*fact)->instruction.length) != (*fact)->instruction.length)
        return std::optional<Address>{};
    std::optional<Address> target;
    for (const auto &reference : project.references->outgoing_view(source)) {
        if ((reference.provenance.kind != ReferenceProvenanceKind::decoded &&
             reference.provenance.kind != ReferenceProvenanceKind::dataflow &&
             reference.provenance.kind != ReferenceProvenanceKind::elf_relocation &&
             reference.provenance.kind != ReferenceProvenanceKind::macho_relocation &&
             reference.provenance.kind != ReferenceProvenanceKind::macho_dyld) ||
            reference.provenance.instruction_id != (*fact)->id ||
            (reference.kind != ReferenceKind::call && reference.kind != ReferenceKind::jump &&
             reference.kind != ReferenceKind::conditional_jump))
            continue;
        const auto *location = std::get_if<Location>(&reference.target);
        const auto *address = location ? std::get_if<Address>(location) : nullptr;
        if (!address || !project.loaded->image->code_window(*address, 1))
            continue;
        if (target && *target != *address)
            return Error{ErrorCode::conflict, "Decoded instruction has ambiguous Follow targets"};
        target = *address;
    }
    return target;
}
} // namespace hexlab

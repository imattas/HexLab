// Native automation SDK example: resolve archive symbols to bounded member
// metadata and inspect a small object-header prefix without loading a member.
#include "hexlab/automation/api.hpp"
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string_view>

int main(int argc, char** argv) {
    if (argc != 2 && argc != 3) {
        std::cerr << "usage: hexlab_archive_inspect archive.a [symbol-substring]\n";
        return 2;
    }
    const std::string_view filter = argc == 3 ? argv[2] : "";
    auto fail = [](const hexlab::Error& error) {
        std::cerr << error.message << '\n';
        return 1;
    };
    auto opened = hexlab::automation::Archive::open(argv[1]);
    if (!opened) return fail(opened.error());
    const auto& archive = opened.value();
    auto summary = archive->summary();
    if (!summary) return fail(summary.error());
    std::cout << "members=" << summary.value().member_count
              << " symbols=" << summary.value().symbol_count
              << " indexed=" << std::boolalpha << summary.value().has_symbol_index
              << " index_complete=" << summary.value().symbol_index_complete
              << " thin=" << summary.value().thin << '\n';

    constexpr std::size_t page_size = 256;
    std::size_t matched = 0;
    for (std::size_t start = 0; start < summary.value().symbol_count;) {
        auto page = archive->symbols(start, page_size);
        if (!page) return fail(page.error());
        if (page.value().empty()) break;
        for (const auto& symbol : page.value()) {
            if (!filter.empty() && symbol.name.find(filter) == std::string::npos) continue;
            auto members = archive->members(symbol.member_index, 1);
            if (!members) return fail(members.error());
            if (members.value().empty()) {
                std::cerr << "archive symbol references a missing member\n";
                return 1;
            }
            const auto& member = members.value().front();
            std::cout << std::quoted(symbol.name) << " -> [" << member.index << "] "
                      << std::quoted(member.name) << " size=" << member.size;
            if (member.kind == hexlab::ArMemberKind::regular) {
                const auto amount = static_cast<std::size_t>(std::min<std::uint64_t>(member.size, 8));
                auto prefix = archive->read_member(member.index, 0, amount);
                if (!prefix) return fail(prefix.error());
                std::cout << " prefix=";
                for (const auto byte : prefix.value())
                    std::cout << std::hex << std::setw(2) << std::setfill('0')
                              << std::to_integer<unsigned>(byte);
                std::cout << std::dec << std::setfill(' ');
            } else {
                std::cout << " prefix=<not a regular member>";
            }
            std::cout << '\n';
            ++matched;
        }
        start += page.value().size();
    }
    if (filter.empty())
        std::cout << "Pass a symbol substring to show member resolution and object prefixes.\n";
    else if (!matched)
        std::cout << "No indexed symbols contain " << std::quoted(filter) << ".\n";
    return 0;
}

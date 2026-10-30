// Native SDK example: export one bounded annotation page per invocation and
// reopen the next cursor checkpoint in another process. See ../README-workflow-state.md.
#include "hexlab/automation/api.hpp"
#include <charconv>
#include <iomanip>
#include <iostream>
#include <limits>

int main(int argc, char** argv) {
    if (argc != 3 && argc != 4) {
        std::cerr << "usage: hexlab_resume_inventory project.hxproj NEW.state [PREVIOUS.state]\n";
        return 2;
    }
    constexpr auto application = "hexlab.examples.annotation-inventory";
    constexpr std::uint32_t schema = 1;
    auto report = [](const hexlab::Error& error) {
        std::cerr << error.message << '\n';
        return 1;
    };
    auto opened = hexlab::automation::Project::open(argv[1]);
    if (!opened) return report(opened.error());
    const auto& project = opened.value();
    const auto snapshot = project->snapshot();
    if (!snapshot) return report(snapshot.error());
    const auto revision = snapshot.value()->state->revisions.edit;
    std::size_t cursor = 0;
    if (argc == 4) {
        const auto loaded = project->load_workflow_state(argv[3], application, schema);
        if (!loaded) return report(loaded.error());
        const auto& payload = loaded.value().payload;
        if (payload.empty() || payload.size() > 20) {
            std::cerr << "invalid inventory cursor payload\n";
            return 1;
        }
        const auto* begin = reinterpret_cast<const char*>(payload.data());
        const auto parsed = std::from_chars(begin, begin + payload.size(), cursor);
        if (parsed.ec != std::errc{} || parsed.ptr != begin + payload.size()) {
            std::cerr << "invalid inventory cursor payload\n";
            return 1;
        }
    }
    constexpr std::size_t page_size = 64;
    const auto rows = project->annotations(cursor, page_size);
    if (!rows) return report(rows.error());
    if (cursor > std::numeric_limits<std::size_t>::max() - rows.value().size()) {
        std::cerr << "inventory cursor overflow\n";
        return 1;
    }
    // IDs identify replayed rows if the process stops after output but before
    // checkpoint publication. The output sink owns deduplication/transactions.
    for (const auto& row : rows.value())
        std::cout << row.id << ' ' << std::quoted(row.name) << ' ' << std::quoted(row.comment) << '\n';
    std::cout.flush();
    if (!std::cout) { std::cerr << "inventory output failed; checkpoint not saved\n"; return 1; }
    const auto next = std::to_string(cursor + rows.value().size());
    const auto bytes = std::as_bytes(std::span(next.data(), next.size()));
    const auto saved = project->save_workflow_state(argv[2], application, schema, bytes, revision);
    if (!saved) return report(saved.error());
    std::cerr << "saved cursor " << next << "; "
              << (rows.value().size() < page_size ? "inventory complete" : "run again with this checkpoint") << '\n';
    return 0;
}

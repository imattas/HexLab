#include "hexlab/compare/compare.hpp"
#include "hexlab/compare/session.hpp"
#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <stop_token>

namespace {
void check(bool value, const char *message) {
    if (!value) { std::cerr << "FAIL: " << message << '\n'; std::exit(1); }
}
}

int main() {
    using namespace hexlab::compare;
    {
        // All helper bodies are identical. Only the already distinctive roots
        // and their call graph distinguish the relocated, reordered helpers.
        FunctionFeature root_a, root_b, helper_a, helper_b, leaf_a, leaf_b;
        root_a.entry = 0x100; root_a.architecture = 1;
        root_a.instruction_fingerprints = {1, 2, 3};
        root_b = root_a; root_b.entry = 0x200; root_b.instruction_fingerprints = {4, 5, 6};
        helper_a = root_a; helper_a.entry = 0x300; helper_a.instruction_fingerprints = {7, 8, 9};
        helper_b = helper_a; helper_b.entry = 0x400;
        leaf_a = root_a; leaf_a.entry = 0x500; leaf_a.instruction_fingerprints = {10, 11, 12};
        leaf_b = leaf_a; leaf_b.entry = 0x600;
        root_a.direct_calls = {{0x300, 0}}; root_b.direct_calls = {{0x400, 0}};
        helper_a.direct_calls = {{0x500, 0}}; helper_b.direct_calls = {{0x600, 0}};
        const std::array old_set{root_a, root_b, helper_a, helper_b, leaf_a, leaf_b};
        auto relocated = old_set;
        for (auto &fn : relocated) {
            fn.entry += 0x8000;
            for (auto &call : fn.direct_calls) call.entry += 0x8000;
        }
        const std::array new_set{relocated[5], relocated[3], relocated[1],
                                 relocated[4], relocated[0], relocated[2]};
        const auto refined = match_functions_detailed(old_set, new_set);
        check(refined && refined.value().size() == 6 &&
              refined.value()[2].kind == FunctionMatchKind::matched &&
              refined.value()[2].new_entry == 0x8300 &&
              refined.value()[3].new_entry == 0x8400 &&
              refined.value()[4].new_entry == 0x8500 &&
              refined.value()[5].new_entry == 0x8600,
              "anchored call neighborhoods resolve relocated duplicate bodies in successive waves");
        check(refined.value()[0].evidence.call_graph_round == 0 &&
              refined.value()[2].evidence.call_graph_round == 1 &&
              refined.value()[4].evidence.call_graph_round == 2 &&
              refined.value()[2].evidence.supporting_call_neighbors == 1 &&
              refined.value()[2].evidence.base_confidence == 100,
              "function matches expose the base score and independent call-graph evidence");
        const auto evidence_path = std::filesystem::temp_directory_path() / "hexlab-compare-evidence-test.hxc";
        Session evidence_session{"before", "after", {}, refined.value()};
        check(save_session(evidence_path, evidence_session).has_value(), "graph evidence session saves");
        const auto evidence_restored = load_session(evidence_path);
        std::filesystem::remove(evidence_path);
        check(evidence_restored && evidence_restored.value().functions[4].evidence.call_graph_round == 2 &&
              evidence_restored.value().functions[2].evidence.supporting_call_neighbors == 1 &&
              evidence_restored.value().functions[0].evidence.base_confidence == 100,
              "comparison sessions preserve call-graph correspondence evidence");

        FunctionMatchOptions one_wave;
        one_wave.max_call_graph_rounds = 1;
        const auto limited_waves = match_functions_detailed(old_set, new_set, one_wave);
        check(limited_waves && limited_waves.value()[2].kind == FunctionMatchKind::matched &&
              limited_waves.value()[4].kind == FunctionMatchKind::ambiguous,
              "round limit leaves functions beyond established evidence ambiguous");
        one_wave.max_call_graph_rounds = 0;
        const auto no_graph = match_functions_detailed(old_set, new_set, one_wave);
        check(no_graph && no_graph.value()[2].kind == FunctionMatchKind::ambiguous,
              "call-graph refinement can be disabled without changing base matching");

        auto reversed_old = old_set, reversed_new = relocated;
        for (auto &fn : reversed_old) fn.direct_calls.clear();
        for (auto &fn : reversed_new) fn.direct_calls.clear();
        reversed_old[2].direct_calls = {{0x100, 0}, {0x100, 0}, {0xdead, 0}};
        reversed_old[3].direct_calls = {{0x200, 0}};
        reversed_old[4].direct_calls = {{0x300, 0}};
        reversed_old[5].direct_calls = {{0x400, 0}};
        reversed_new[2].direct_calls = {{0x8100, 0}, {0x8100, 0}, {0xbeef, 0}};
        reversed_new[3].direct_calls = {{0x8200, 0}};
        reversed_new[4].direct_calls = {{0x8300, 0}};
        reversed_new[5].direct_calls = {{0x8400, 0}};
        const auto outgoing = match_functions_detailed(reversed_old, reversed_new);
        check(outgoing && outgoing.value()[2].new_entry == 0x8300 &&
              outgoing.value()[4].new_entry == 0x8500 &&
              outgoing.value()[2].evidence.supporting_call_neighbors == 1,
              "outgoing anchors resolve helpers while duplicate and unknown calls add no evidence");

        auto conflicting = relocated;
        conflicting[2].direct_calls.push_back({0x8100, 0});
        const auto conflict = match_functions_detailed(old_set, conflicting);
        check(conflict && conflict.value()[2].kind == FunctionMatchKind::ambiguous &&
              conflict.value()[3].kind == FunctionMatchKind::matched,
              "contradictory anchored call neighborhoods cannot establish correspondence");

        const std::array cycles_old{helper_a, helper_b};
        auto cycles_new = cycles_old;
        for (auto &fn : cycles_new) fn.entry += 0x8000;
        cycles_new[0].direct_calls = {{0x8400, 0}};
        cycles_new[1].direct_calls = {{0x8300, 0}};
        auto cycles_input = cycles_old;
        cycles_input[0].direct_calls = {{0x400, 0}};
        cycles_input[1].direct_calls = {{0x300, 0}};
        const auto cycles = match_functions_detailed(cycles_input, cycles_new);
        check(cycles && cycles.value().size() == 4 &&
              cycles.value()[0].kind == FunctionMatchKind::ambiguous &&
              cycles.value()[1].kind == FunctionMatchKind::ambiguous,
              "unanchored recursive cycles never bootstrap arbitrary matches");

        auto scoped_old = old_set, scoped_new = relocated;
        scoped_old[1].entry = 0x100; scoped_old[1].address_space = 2;
        scoped_old[0].direct_calls = {{0x300, 0}};
        scoped_old[1].direct_calls = {{0x400, 0}};
        scoped_new[1].entry = 0x8100; scoped_new[1].address_space = 9;
        scoped_new[0].direct_calls = {{0x8300, 0}};
        scoped_new[1].direct_calls = {{0x8400, 0}};
        const auto spaces = match_functions_detailed(scoped_old, scoped_new);
        check(spaces && spaces.value()[1].old_space == 2 && spaces.value()[1].new_space == 9 &&
              spaces.value()[2].new_entry == 0x8300 && spaces.value()[3].new_entry == 0x8400,
              "function address lookup distinguishes identical offsets in separate spaces");
        scoped_old[0].direct_calls.clear(); scoped_old[1].direct_calls.clear();
        scoped_new[0].direct_calls.clear(); scoped_new[1].direct_calls.clear();
        scoped_old[2].direct_calls = {{0x100, 0}}; scoped_old[3].direct_calls = {{0x100, 2}};
        scoped_new[2].direct_calls = {{0x8100, 0}}; scoped_new[3].direct_calls = {{0x8100, 9}};
        const auto scoped_targets = match_functions_detailed(scoped_old, scoped_new);
        check(scoped_targets && scoped_targets.value()[2].new_entry == 0x8300 &&
              scoped_targets.value()[3].new_entry == 0x8400,
              "direct-call target resolution uses the target address space");

        auto competing_old = old_set, competing_new = relocated;
        competing_old[0].direct_calls = {{0x300, 0}, {0x400, 0}};
        competing_old[1].direct_calls.clear();
        competing_new[0].direct_calls = {{0x8300, 0}};
        competing_new[1].direct_calls.clear();
        const auto competing = match_functions_detailed(competing_old, competing_new);
        check(competing && competing.value()[2].kind == FunctionMatchKind::ambiguous &&
              competing.value()[3].kind == FunctionMatchKind::ambiguous,
              "two helpers sharing the same anchored caller cannot claim one candidate");

        auto unrelated_new = relocated;
        unrelated_new[2].instruction_fingerprints = {100, 101, 102};
        const auto unrelated_context = match_functions_detailed(old_set, unrelated_new);
        check(unrelated_context && unrelated_context.value()[2].kind == FunctionMatchKind::ambiguous &&
              unrelated_context.value()[3].new_entry == 0x8400,
              "call context cannot override insufficient instruction similarity");

        const std::array reordered_old{old_set[5], old_set[3], old_set[1], old_set[4], old_set[0], old_set[2]};
        const auto reordered = match_functions_detailed(reordered_old, relocated);
        check(reordered && reordered.value()[0].new_entry == 0x8600 &&
              reordered.value()[0].evidence.call_graph_round == 2 &&
              reordered.value()[5].new_entry == 0x8300 &&
              reordered.value()[5].evidence.call_graph_round == 1,
              "refinement evidence is independent of old-side iteration order");

        FunctionMatchOptions small_budget;
        small_budget.max_call_edges = 1;
        const auto edge_limit = match_functions_detailed(old_set, new_set, small_budget);
        check(!edge_limit && edge_limit.error().code == ErrorCode::invalid_argument,
              "direct-call input exceeding the edge budget is rejected");
        small_budget.max_call_edges = 100;
        small_budget.max_context_edge_visits = 1;
        const auto work_limit = match_functions_detailed(old_set, new_set, small_budget);
        check(!work_limit && work_limit.error().code == ErrorCode::invalid_argument,
              "call-context work exceeding the visit budget returns no partial matches");
        auto duplicate_addresses = old_set;
        duplicate_addresses[1].entry = duplicate_addresses[0].entry;
        check(!match_functions_detailed(duplicate_addresses, new_set),
              "ambiguous call-graph function addresses are rejected");

        FunctionMatchOptions cancel_graph;
        std::uint64_t previous = 0;
        bool canceled_in_graph = false;
        cancel_graph.progress = [&](std::uint64_t visited, std::uint64_t total) {
            check(visited >= previous && visited <= total, "function progress stays monotonic and bounded");
            previous = visited;
            if (visited > 36 && visited < total) { canceled_in_graph = true; return false; }
            return true;
        };
        const auto interrupted = match_functions_detailed(old_set, new_set, cancel_graph);
        check(!interrupted && interrupted.error().code == ErrorCode::canceled && canceled_in_graph,
              "progress can cancel during graph refinement before final completion");
    }
    {
        FunctionFeature before;
        before.entry = 0x1000; before.architecture = 7; before.instruction_count = 3;
        before.block_count = 1; before.instruction_fingerprints = {0x11, 0x22, 0x33};
        FunctionFeature after = before;
        after.entry = 0x9000; after.name = "renamed";
        after.instruction_fingerprints = {0x33, 0x11, 0x22};
        const std::array old_set{before};
        const std::array new_set{after};
        auto relocation = match_functions_detailed(old_set, new_set);
        check(relocation && relocation.value().size() == 1 &&
              relocation.value()[0].kind == FunctionMatchKind::matched &&
              relocation.value()[0].new_entry == 0x9000 && relocation.value()[0].confidence >= 90,
              "normalized instruction fingerprints match stripped renamed functions across bases");

        auto unrelated = after;
        unrelated.architecture = 8;
        const std::array wrong_arch{unrelated};
        auto cross_arch = match_functions_detailed(old_set, wrong_arch);
        check(cross_arch && cross_arch.value()[0].kind == FunctionMatchKind::removed &&
              cross_arch.value()[1].kind == FunctionMatchKind::added,
              "functions from different architectures never correspond");
        FunctionMatchOptions permissive;
        permissive.minimum_confidence = 0;
        const auto zero_threshold = match_functions_detailed(old_set, wrong_arch, permissive);
        check(zero_threshold && zero_threshold.value().size() == 2 &&
              zero_threshold.value()[0].kind != FunctionMatchKind::matched,
              "even a zero confidence threshold cannot pair different architectures");

        FunctionFeature duplicate_a = before, duplicate_b = before;
        duplicate_a.entry = 0x1100; duplicate_b.entry = 0x1200;
        FunctionFeature candidate_a = after, candidate_b = after;
        candidate_a.entry = 0x9100; candidate_b.entry = 0x9200;
        const std::array duplicate_old{duplicate_a, duplicate_b};
        const std::array duplicate_new{candidate_a, candidate_b};
        auto ambiguous = match_functions_detailed(duplicate_old, duplicate_new);
        check(ambiguous && ambiguous.value()[0].kind == FunctionMatchKind::ambiguous &&
              ambiguous.value()[1].kind == FunctionMatchKind::ambiguous,
              "indistinguishable fingerprint groups are not forced into arbitrary pairs");

        FunctionMatchOptions bounded;
        bounded.max_candidate_pairs = 0;
        auto limited = match_functions_detailed(old_set, new_set, bounded);
        check(!limited && limited.error().code == ErrorCode::invalid_argument,
              "zero candidate budget is rejected");
        std::stop_source stop;
        stop.request_stop();
        FunctionMatchOptions canceled_options;
        canceled_options.stop_token = stop.get_token();
        auto canceled_match = match_functions_detailed(old_set, new_set, canceled_options);
        check(!canceled_match && canceled_match.error().code == ErrorCode::canceled,
              "function matching honors stop tokens");
    }
    const std::array old_functions{
        FunctionFeature{0x1000, "parse", 1, 10, 2, 1, {4, 3, 3}},
        FunctionFeature{0x1100, "legacy", 1, 3, 1, 0, {1, 2}},
        FunctionFeature{0x1200, "amb_a", 1, 6, 2, 0, {2, 2, 2}},
        FunctionFeature{0x1300, "amb_b", 1, 6, 2, 0, {2, 2, 2}}
    };
    const std::array new_functions{
        FunctionFeature{0x5000, "parse", 1, 10, 2, 1, {4, 3, 3}},
        FunctionFeature{0x5100, "new", 2, 4, 1, 0, {1, 1}},
        FunctionFeature{0x5200, "candidate", 1, 6, 2, 0, {2, 2, 2}}
    };
    const auto function_matches = match_functions(old_functions, new_functions);
    check(function_matches.size() == 6, "function matcher reports every old and new function");
    check(function_matches[0].kind == FunctionMatchKind::matched && function_matches[0].old_entry == 0x1000 &&
          function_matches[0].new_entry == 0x5000 && function_matches[0].confidence == 100,
          "stable function identity matches across relocation");
    check(function_matches[1].kind == FunctionMatchKind::removed, "unmatched old function is removed");
    check(function_matches[2].kind == FunctionMatchKind::ambiguous &&
          function_matches[2].old_entry == 0x1200 && !function_matches[2].new_entry,
          "duplicate shape candidates are left ambiguous");
    check(function_matches[3].kind == FunctionMatchKind::ambiguous &&
          function_matches[3].old_entry == 0x1300, "all sides of a duplicate shape stay ambiguous");
    check(function_matches.back().kind == FunctionMatchKind::added, "unmatched new function is added");
    constexpr std::array old_bytes{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    constexpr std::array new_bytes{std::byte{1}, std::byte{9}, std::byte{3}, std::byte{4}, std::byte{5}};
    const ImageView old_image{{RegionView{"text", 0x1000, old_bytes}}};
    const ImageView new_image{{RegionView{"text", 0x2000, new_bytes}}};
    auto result = compare(old_image, new_image);
    check(result.has_value(), "compare succeeds");
    const auto &report = result.value();
    check(report.summary.compared_bytes == 4, "compares overlap bytes");
    check(report.summary.equal_bytes == 3, "equal byte count");
    check(report.summary.changed_bytes == 1, "changed byte count");
    check(report.summary.added_bytes == 1 && report.summary.removed_bytes == 0, "added tail");
    check(report.runs.size() == 2, "adjacent result classes are separate");
    check(report.runs[0].kind == ChangeKind::changed && report.runs[0].old_address.value() == 0x1001 &&
          report.runs[0].new_address.value() == 0x2001, "region key maps moved addresses");
    check(report.runs[1].kind == ChangeKind::added && report.runs[1].new_address.value() == 0x2004,
          "new tail address");

    constexpr std::array aligned_old{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4},
        std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}};
    constexpr std::array aligned_new{std::byte{1}, std::byte{99}, std::byte{2}, std::byte{3},
        std::byte{4}, std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}};
    CompareOptions resync;
    resync.resync_window_bytes = 4;
    std::uint64_t aligned_progress = 0, aligned_total = 0;
    resync.progress_interval = 1;
    resync.progress = [&](std::uint64_t visited, std::uint64_t total) {
        aligned_progress = visited;
        aligned_total = total;
        return true;
    };
    auto inserted = compare(ImageView{{RegionView{"text", 0x1000, aligned_old}}},
                            ImageView{{RegionView{"text", 0x2000, aligned_new}}}, resync);
    check(inserted && inserted.value().summary.equal_bytes == 8 && inserted.value().summary.changed_bytes == 0 &&
          inserted.value().summary.added_bytes == 1 && inserted.value().runs.size() == 1 &&
          inserted.value().runs[0].kind == ChangeKind::added &&
          inserted.value().runs[0].new_address == 0x2001 && aligned_progress == 9 && aligned_total == 9,
          "bounded anchor resynchronizes after an insertion");
    auto deleted = compare(ImageView{{RegionView{"text", 0x1000, aligned_new}}},
                           ImageView{{RegionView{"text", 0x2000, aligned_old}}}, resync);
    check(deleted && deleted.value().summary.equal_bytes == 8 && deleted.value().summary.changed_bytes == 0 &&
          deleted.value().summary.removed_bytes == 1 && deleted.value().runs.size() == 1 &&
          deleted.value().runs[0].kind == ChangeKind::removed &&
          deleted.value().runs[0].old_address == 0x1001,
          "bounded anchor resynchronizes after a deletion");
    constexpr std::array mixed_gap_old{std::byte{1}, std::byte{2}, std::byte{9}, std::byte{3},
        std::byte{4}, std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}};
    constexpr std::array mixed_gap_new{std::byte{1}, std::byte{99}, std::byte{3}, std::byte{4},
        std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}};
    resync.resync_window_bytes = 3;
    auto mixed_gap = compare(ImageView{{RegionView{"text", 0x1000, mixed_gap_old}}},
                             ImageView{{RegionView{"text", 0x2000, mixed_gap_new}}}, resync);
    check(mixed_gap && mixed_gap.value().summary.equal_bytes == 7 &&
          mixed_gap.value().summary.changed_bytes == 1 && mixed_gap.value().summary.added_bytes == 0 &&
          mixed_gap.value().summary.removed_bytes == 1 && mixed_gap.value().runs.size() == 2 &&
          mixed_gap.value().runs[0].kind == ChangeKind::changed && mixed_gap.value().runs[0].old_address == 0x1001 &&
          mixed_gap.value().runs[1].kind == ChangeKind::removed && mixed_gap.value().runs[1].old_address == 0x1002,
          "bounded anchor resynchronizes across nearby insertion and deletion together");
    resync.resync_window_bytes = 0;
    auto strict = compare(ImageView{{RegionView{"text", 0x1000, aligned_old}}},
                          ImageView{{RegionView{"text", 0x2000, aligned_new}}}, resync);
    check(strict && strict.value().summary.changed_bytes == 7 && strict.value().summary.added_bytes == 1,
          "zero resynchronization window preserves strict offset comparison");

    const std::array other{std::byte{7}, std::byte{8}};
    auto unmatched = compare(ImageView{{RegionView{"gone", 4, other}}}, ImageView{});
    check(unmatched && unmatched.value().summary.removed_bytes == 2 &&
          unmatched.value().runs[0].kind == ChangeKind::removed, "unmatched old region removed");
    auto bad = compare(ImageView{{RegionView{"dup", 0, other}, RegionView{"dup", 9, other}}}, ImageView{});
    check(!bad && bad.error().code == ErrorCode::invalid_argument, "duplicate region keys rejected");
    auto overflow = compare(ImageView{{RegionView{"x", UINT64_MAX, other}}}, ImageView{});
    check(!overflow && overflow.error().code == ErrorCode::overflow, "address extent overflow rejected");
    CompareOptions canceled;
    canceled.stop_token = std::stop_token{};
    canceled.progress = [](std::uint64_t, std::uint64_t) { return false; };
    auto stopped = compare(old_image, new_image, canceled);
    check(!stopped && stopped.error().code == ErrorCode::canceled, "progress can cancel");
    std::uint64_t last_visited = 0, last_total = 0;
    CompareOptions tracked;
    tracked.progress_interval = 2;
    tracked.progress = [&](std::uint64_t visited, std::uint64_t total) {
        check(visited >= last_visited, "progress is monotonic");
        last_visited = visited;
        last_total = total;
        return true;
    };
    check(compare(old_image, new_image, tracked).has_value(), "progress-enabled compare succeeds");
    check(last_visited == 5 && last_total == 5, "final progress reaches estimated work total");

    Session session{"old.exe", "new.exe", report, function_matches};
    const auto session_path = std::filesystem::temp_directory_path() / "hexlab-compare-session-test.hxc";
    auto saved = save_session(session_path, session);
    check(saved && saved.value(), "comparison session saves");
    auto restored = load_session(session_path);
    check(restored && restored.value().old_name == session.old_name &&
          restored.value().new_name == session.new_name &&
          restored.value().report.runs.size() == report.runs.size() &&
          restored.value().report.runs[0].old_address == report.runs[0].old_address &&
          restored.value().report.summary.changed_bytes == report.summary.changed_bytes &&
          restored.value().functions.size() == function_matches.size() &&
          restored.value().functions[0].new_entry == function_matches[0].new_entry &&
          restored.value().functions[0].old_name == function_matches[0].old_name,
          "saved session round trips summaries, run addresses, and function matches");
    session.old_name = "replacement.exe";
    check(save_session(session_path, session).has_value(), "saving replaces an existing comparison session");
    restored = load_session(session_path);
    check(restored && restored.value().old_name == "replacement.exe", "replacement session is readable");
    {
        std::ofstream truncated(session_path, std::ios::binary | std::ios::trunc);
        truncated << "HX";
    }
    check(!load_session(session_path), "truncated comparison session is rejected");
    std::filesystem::remove(session_path);
    {
        // A literal version 1 wire fixture: one matched function at old 0x10
        // in space 2 and new 0x20 in space 3, confidence 99, no names or runs.
        std::array<char, 135> legacy{};
        constexpr std::array legacy_header{'H', 'X', 'C', 'M', 'P', 'R', '1', '\0'};
        std::copy(legacy_header.begin(), legacy_header.end(), legacy.begin());
        legacy[88] = 1; legacy[97] = 1; legacy[98] = 0x10;
        legacy[106] = 1; legacy[107] = 0x20; legacy[115] = 99;
        legacy[119] = 2; legacy[123] = 3;
        {
            std::ofstream output(session_path, std::ios::binary | std::ios::trunc);
            output.write(legacy.data(), legacy.size());
        }
        const auto version_one = load_session(session_path);
        check(version_one && version_one.value().functions.size() == 1 &&
              version_one.value().functions[0].old_entry == 0x10 &&
              version_one.value().functions[0].new_entry == 0x20 &&
              version_one.value().functions[0].old_space == 2 &&
              version_one.value().functions[0].new_space == 3 &&
              version_one.value().functions[0].confidence == 99 &&
              version_one.value().functions[0].evidence.base_confidence == 0 &&
              version_one.value().functions[0].evidence.call_graph_round == 0,
              "literal version 1 sessions load with explicitly absent refinement evidence");
        Session malformed{"a", "b", {}, {function_matches[0]}};
        check(save_session(session_path, malformed).has_value(), "v2 session fixture saves");
        {
            std::fstream output(session_path, std::ios::binary | std::ios::in | std::ios::out);
            output.seekp(-16, std::ios::end);
            output.put(101);
        }
        check(!load_session(session_path), "v2 confidence evidence above 100 is rejected");
        check(save_session(session_path, malformed).has_value(), "v2 session fixture resets");
        {
            std::fstream output(session_path, std::ios::binary | std::ios::in | std::ios::out);
            output.seekp(-4, std::ios::end);
            output.put(1);
        }
        check(!load_session(session_path), "v2 refinement without supporting neighbors is rejected");
        check(save_session(session_path, malformed).has_value(), "v2 truncation fixture resets");
        std::filesystem::resize_file(session_path, std::filesystem::file_size(session_path) - 1);
        check(!load_session(session_path), "truncated v2 correspondence evidence is rejected");
        std::filesystem::remove(session_path);
    }
    std::stop_source source;
    source.request_stop();
    CompareOptions token_cancel;
    token_cancel.stop_token = source.get_token();
    auto token_stopped = compare(old_image, new_image, token_cancel);
    check(!token_stopped && token_stopped.error().code == ErrorCode::canceled, "stop token cancels");
    std::cout << "binary comparison tests passed\n";
}




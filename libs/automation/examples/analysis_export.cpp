// Export an immutable, paged native-SDK analysis snapshot as JSON.
#include "hexlab/automation/api.hpp"

#include <array>
#include <charconv>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <random>
#include <string_view>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cstring>
#endif

namespace fs = std::filesystem;
using namespace hexlab;

namespace {
void json_string(std::ostream &out, std::string_view value) {
    constexpr char hex[] = "0123456789abcdef";
    out << '"';
    for (const unsigned char byte : value) {
        switch (byte) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (byte < 0x20) out << "\\u00" << hex[byte >> 4] << hex[byte & 15];
            else out.put(static_cast<char>(byte));
        }
    }
    out << '"';
}

void address_json(std::ostream &out, Address address) {
    out << "{\"space\":" << address.space.value << ",\"offset\":" << address.offset << '}';
}

void location_json(std::ostream &out, const Location &location) {
    if (const auto *address = std::get_if<Address>(&location)) {
        out << "{\"kind\":\"address\",\"value\":";
        address_json(out, *address);
    } else {
        out << "{\"kind\":\"file_offset\",\"value\":" << std::get<FileOffset>(location).value;
    }
    out << '}';
}

void target_json(std::ostream &out, const ReferenceTarget &target) {
    if (const auto *location = std::get_if<Location>(&target)) {
        location_json(out, *location);
    } else if (const auto *external = std::get_if<ExternalIdentity>(&target)) {
        out << "{\"kind\":\"external\",\"library\":";
        json_string(out, external->library);
        out << ",\"name\":";
        if (external->name) json_string(out, *external->name); else out << "null";
        out << ",\"ordinal\":";
        if (external->ordinal) out << *external->ordinal; else out << "null";
        out << '}';
    } else {
        const auto &unresolved = std::get<UnresolvedTarget>(target);
        out << "{\"kind\":\"unresolved\",\"reason\":"
            << static_cast<unsigned>(unresolved.reason) << '}';
    }
}

template<class Fetch, class Emit>
bool write_vector_pages(std::ostream &out, Fetch fetch, Emit emit, std::string &error) {
    constexpr std::size_t page_size = 4096;
    std::size_t start = 0;
    bool first = true;
    for (;;) {
        auto page = fetch(start, page_size);
        if (!page) { error = page.error().message; return false; }
        if (page.value().size() > page_size) { error = "SDK returned an oversized page"; return false; }
        for (const auto &row : page.value()) {
            if (!first) out << ',';
            emit(out, row);
            first = false;
        }
        if (!out) { error = "writing analysis JSON failed"; return false; }
        if (page.value().size() < page_size) return true;
        if (start > std::numeric_limits<std::size_t>::max() - page.value().size()) {
            error = "analysis page cursor overflow";
            return false;
        }
        start += page.value().size();
    }
}

bool write_report(std::ostream &out, const automation::Project &project, std::string &error) {
    auto snapshot = project.snapshot();
    if (!snapshot) { error = snapshot.error().message; return false; }
    auto image = project.image_info();
    if (!image) { error = image.error().message; return false; }
    const auto &state = *snapshot.value()->state;
    const auto &workspace = *snapshot.value();
    const bool analysis_complete = (!workspace.functions || workspace.functions->complete) &&
        (!workspace.references || workspace.references->complete()) &&
        (!workspace.strings || workspace.strings->complete);
    out << "{\"schema\":\"hexlab.native-analysis.v1\",\"api_version\":"
        << automation::api_version << ",\"project\":{\"edit_revision\":"
        << state.revisions.edit << ",\"byte_revision\":" << state.revisions.bytes
        << ",\"decision_revision\":" << state.revisions.decisions
        << ",\"format\":";
    json_string(out, image.value().format);
    out << ",\"machine\":" << image.value().machine << ",\"architecture\":"
        << static_cast<unsigned>(image.value().architecture) << ",\"mode\":"
        << static_cast<unsigned>(image.value().mode) << ",\"metadata_complete\":"
        << (image.value().metadata_complete ? "true" : "false")
        << "},\"analysis_complete\":" << (analysis_complete ? "true" : "false")
        << ",\"functions\":[";

    if (!write_vector_pages(out, [&](auto start, auto count) { return project.functions(start, count); },
        [](auto &stream, const FunctionRecord &row) {
            stream << "{\"id\":" << row.id.value << ",\"entry\":";
            address_json(stream, row.entry);
            stream << ",\"complete\":" << (row.complete ? "true" : "false")
                   << ",\"thunk\":" << (row.thunk ? "true" : "false")
                   << ",\"block_count\":" << row.blocks.size() << ",\"stop_count\":" << row.stops.size() << '}';
        }, error)) return false;
    out << "],\"instructions\":[";
    if (!write_vector_pages(out, [&](auto start, auto count) { return project.instructions(start, count); },
        [](auto &stream, const Instruction &row) {
            stream << "{\"address\":";
            address_json(stream, row.address);
            stream << ",\"length\":" << row.length << ",\"opcode\":"
                   << static_cast<unsigned>(row.opcode) << ",\"flow\":"
                   << static_cast<unsigned>(row.flow) << ",\"bytes_hex\":";
            constexpr char hex[] = "0123456789abcdef";
            std::string bytes;
            for (const auto byte : row.encoded_bytes()) {
                const auto value = std::to_integer<unsigned char>(byte);
                bytes.push_back(hex[value >> 4]);
                bytes.push_back(hex[value & 15]);
            }
            json_string(stream, bytes);
            stream << '}';
        }, error)) return false;
    out << "],\"segments\":[";
    if (!write_vector_pages(out, [&](auto start, auto count) { return project.segments(start, count); },
        [](auto &stream, const automation::MappedSegment &row) {
            stream << "{\"name\":";
            json_string(stream, row.name);
            stream << ",\"begin\":";
            address_json(stream, row.begin);
            stream << ",\"size\":" << row.size << ",\"file_begin\":" << row.file_begin.value
                   << ",\"file_size\":" << row.file_size << ",\"readable\":" << (row.readable ? "true" : "false")
                   << ",\"writable\":" << (row.writable ? "true" : "false")
                   << ",\"executable\":" << (row.executable ? "true" : "false") << '}';
        }, error)) return false;
    out << "],\"references\":[";
    std::size_t reference_start = 0;
    bool first_reference = true;
    for (;;) {
        auto page = project.all_references(reference_start, 4096);
        if (!page) { error = page.error().message; return false; }
        for (const auto &row : page.value().rows) {
            if (!first_reference) out << ',';
            first_reference = false;
            out << "{\"id\":" << row.id.value << ",\"source\":";
            location_json(out, row.source);
            out << ",\"target\":";
            target_json(out, row.target);
            out << ",\"kind\":" << static_cast<unsigned>(row.kind)
                << ",\"access\":" << static_cast<unsigned>(row.access) << '}';
        }
        if (page.value().rows.size() < 4096 || !page.value().next_offset) break;
        if (*page.value().next_offset <= reference_start ||
            *page.value().next_offset > std::numeric_limits<std::size_t>::max()) {
            error = "reference page cursor did not advance";
            return false;
        }
        reference_start = static_cast<std::size_t>(*page.value().next_offset);
    }
    out << "],\"strings\":[";
    if (!write_vector_pages(out, [&](auto start, auto count) { return project.strings(start, count); },
        [](auto &stream, const StringRecord &row) {
            stream << "{\"encoding\":" << static_cast<unsigned>(row.encoding) << ",\"preview\":";
            json_string(stream, row.preview);
            stream << ",\"characters\":" << row.characters << ",\"byte_length\":" << row.byte_length
                   << ",\"file_offset\":" << row.file_offset.value << ",\"address\":";
            if (row.address) address_json(stream, *row.address); else stream << "null";
            stream << ",\"terminated\":" << (row.terminated ? "true" : "false") << '}';
        }, error)) return false;
    out << "]}\n";
    if (!out) { error = "writing analysis JSON failed"; return false; }
    return true;
}

int fail(const Error &error) {
    std::cerr << error.message << '\n';
    return 1;
}

bool publish_no_replace(const fs::path &temporary_file, const fs::path &destination, std::string &error) {
#ifdef _WIN32
    if (MoveFileW(temporary_file.c_str(), destination.c_str())) return true;
    error = "publishing analysis JSON failed with Windows error " + std::to_string(GetLastError());
    return false;
#else
    std::error_code link_error;
    fs::create_hard_link(temporary_file, destination, link_error);
    if (!link_error) return true;
    error = "publishing analysis JSON failed: " + link_error.message();
    return false;
#endif
}
}

int main(int argc, char **argv) {
    if (argc != 3) {
        std::cerr << "usage: hexlab_analysis_export project.hxproj output.json\n"
                     "output must not already exist; export is published from a temporary sibling file\n";
        return 2;
    }
    const fs::path destination = fs::absolute(fs::u8path(argv[2]));
    std::error_code filesystem_error;
    if (fs::exists(destination, filesystem_error) || filesystem_error) {
        std::cerr << (filesystem_error ? filesystem_error.message() : "output already exists") << '\n';
        return 2;
    }
    auto opened = automation::Project::open(fs::u8path(argv[1]), false);
    if (!opened) return fail(opened.error());
    auto analyzed = opened.value()->analyze();
    if (!analyzed) return fail(analyzed.error());
    auto captured = opened.value()->capture(analyzed.value()->state->revisions.edit);
    if (!captured) return fail(captured.error());
    auto captured_snapshot = captured.value()->snapshot();
    if (!captured_snapshot) return fail(captured_snapshot.error());
    if (captured_snapshot.value()->state->revisions != analyzed.value()->state->revisions) {
        std::cerr << "project changed while the analysis snapshot was being captured\n";
        return 1;
    }

    std::random_device random;
    fs::path temporary_directory;
    for (unsigned attempt = 0; attempt < 32; ++attempt) {
        temporary_directory = destination.parent_path() /
            ("." + destination.filename().string() + ".hexlab-" + std::to_string(random()) + ".tmp");
        if (fs::create_directory(temporary_directory, filesystem_error)) break;
        if (filesystem_error && filesystem_error != std::errc::file_exists) {
            std::cerr << filesystem_error.message() << '\n';
            return 1;
        }
        filesystem_error.clear();
        temporary_directory.clear();
    }
    if (temporary_directory.empty()) {
        std::cerr << "could not allocate a unique temporary export directory\n";
        return 1;
    }
    const auto temporary_file = temporary_directory / "analysis.json";
    std::string error;
    {
        std::ofstream output(temporary_file, std::ios::binary | std::ios::out);
        if (!output) error = "could not open temporary analysis output";
        else if (write_report(output, *captured.value(), error)) {
            output.flush();
            if (!output) error = "flushing analysis JSON failed";
        }
    }
    if (!error.empty()) {
        fs::remove_all(temporary_directory, filesystem_error);
        std::cerr << error << '\n';
        return 1;
    }
    if (!publish_no_replace(temporary_file, destination, error)) {
        fs::remove_all(temporary_directory, filesystem_error);
        std::cerr << error << '\n';
        return 1;
    }
    fs::remove(temporary_file, filesystem_error);
    if (filesystem_error) {
        std::cerr << "export published, but temporary file cleanup failed: "
                  << filesystem_error.message() << '\n';
        return 0;
    }
    fs::remove(temporary_directory, filesystem_error);
    if (filesystem_error)
        std::cerr << "export published, but temporary directory cleanup failed: "
                  << filesystem_error.message() << '\n';
    return 0;
}

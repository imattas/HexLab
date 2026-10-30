#pragma once

#include <wx/string.h>
#include <algorithm>
#include <optional>
#include <span>
#include <vector>

namespace hexlab::desktop {

enum class MetadataQueryField { any, address, library, name, ordinal, forwarder };

struct MetadataQueryValue {
    MetadataQueryField field = MetadataQueryField::any;
    wxString value;
};

struct MetadataQueryTerm {
    MetadataQueryField field = MetadataQueryField::any;
    wxString value;
};

struct MetadataQuery {
    std::vector<MetadataQueryTerm> terms;
    bool valid = true;
};

inline MetadataQuery parse_metadata_query(wxString query) {
    MetadataQuery result;
    std::size_t position = 0;
    const auto is_space = [&](std::size_t at) { return at < query.length() && wxIsspace(query[at]); };
    while (position < query.length()) {
        while (is_space(position)) ++position;
        if (position == query.length()) break;

        MetadataQueryField field = MetadataQueryField::any;
        const auto token_start = position;
        auto separator = position;
        while (separator < query.length() && !is_space(separator) && query[separator] != '"' && query[separator] != '\'') {
            if (query[separator] == ':') break;
            ++separator;
        }
        if (separator < query.length() && query[separator] == ':') {
            auto name = query.Mid(token_start, separator - token_start).Lower();
            if (name == "addr" || name == "address") field = MetadataQueryField::address;
            else if (name == "lib" || name == "library") field = MetadataQueryField::library;
            else if (name == "name") field = MetadataQueryField::name;
            else if (name == "ordinal") field = MetadataQueryField::ordinal;
            else if (name == "forwarder") field = MetadataQueryField::forwarder;
            if (field != MetadataQueryField::any) position = separator + 1;
        }

        wxString value;
        if (position < query.length() && (query[position] == '"' || query[position] == '\'')) {
            const auto quote = query[position++];
            bool closed = false;
            while (position < query.length()) {
                const auto ch = query[position++];
                if (ch == quote) { closed = true; break; }
                if (ch == '\\' && position < query.length() && query[position] == quote) value += query[position++];
                else value += ch;
            }
            if (!closed || (position < query.length() && !is_space(position))) { result.valid = false; return result; }
        } else {
            const auto value_start = position;
            while (position < query.length() && !is_space(position)) ++position;
            value = query.Mid(value_start, position - value_start);
        }
        if (value.empty()) { result.valid = false; return result; }
        value.MakeLower();
        result.terms.push_back({field, std::move(value)});
    }
    return result;
}

inline bool metadata_query_matches(const MetadataQuery &query, std::span<const MetadataQueryValue> values) {
    if (!query.valid) return false;
    for (const auto &term : query.terms) {
        bool matched = false;
        for (const auto &candidate : values) {
            if (term.field != MetadataQueryField::any && term.field != candidate.field) continue;
            auto value = candidate.value;
            value.MakeLower();
            if (value.Find(term.value) != wxNOT_FOUND) { matched = true; break; }
        }
        if (!matched) return false;
    }
    return true;
}

} // namespace hexlab::desktop

#pragma once
#include "hexlab/image/metadata.hpp"
#include <optional>
#include <string>
namespace hexlab::desktop {
struct AnalysisIssueDiagnostic {
    std::string source;
    DiagnosticSeverity severity = DiagnosticSeverity::warning;
    std::string message;
    std::optional<Address> address;
    std::optional<Address> function_entry;
};
}

#pragma once
#include "hexlab/analysis/strings.hpp"
#include "hexlab/image/read_set.hpp"

namespace hexlab {
Result<StringScan> refresh_strings(const Image &, const AnalysisOptions &, const StringScan &, const ReadSet &,
                                   std::stop_token);
}

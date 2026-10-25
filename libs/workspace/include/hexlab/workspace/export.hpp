#pragma once
#include "hexlab/workspace/project.hpp"
namespace hexlab {
struct ExportReceipt {std::uint64_t bytes=0,revision=0;Sha256Digest sha256{};std::string caveat;};
HEXLAB_WORKSPACE_EXPORT Result<ExportReceipt> export_patched(const ProjectSnapshot&,const std::filesystem::path&,database::ReplacePolicy,std::stop_token);
}

#include "hexlab/workspace/export.hpp"
#include "hexlab/image/file_publication.hpp"
#include "project_internal.hpp"
namespace hexlab {
Result<ExportReceipt> export_patched(const ProjectSnapshot& snapshot,const std::filesystem::path& destination,database::ReplacePolicy policy,std::stop_token stop){return project_detail::guarded([&]()->Result<ExportReceipt>{
    using namespace project_detail;require(snapshot.state && snapshot.state->user && snapshot.original,"No embedded project input is available");require(policy==database::ReplacePolicy::fail_if_exists || policy==database::ReplacePolicy::replace_existing,"Unknown export replacement policy");canceled(stop);require(snapshot.original->size()==snapshot.state->input.size,"Original input extent does not match project identity",ErrorCode::integrity);
    auto publication=take(FilePublication::create(destination,policy==database::ReplacePolicy::replace_existing?ExistingFilePolicy::replace:ExistingFilePolicy::reject,snapshot.protected_paths,stop));auto effective=take(make_overlay(snapshot.original,snapshot.state->user->patches));Sha256 original_hash,output_hash;
    ExportReceipt receipt;receipt.bytes=snapshot.original->size();receipt.revision=snapshot.state->revisions.edit;receipt.caveat="PE checksums and cryptographic signatures are not rebuilt; existing signatures may no longer validate after patches.";
    for(uint64_t offset=0;offset<receipt.bytes;){canceled(stop);auto amount=static_cast<size_t>(std::min<uint64_t>(65536,receipt.bytes-offset));auto original=take(snapshot.original->read_at({offset},amount));require(original.bytes.size()==amount,"Original input returned a short export read",ErrorCode::io);take(original_hash.update(original.bytes));auto view=take(effective->read_at({offset},amount));require(view.bytes.size()==amount,"Effective input returned a short export read",ErrorCode::io);take(output_hash.update(view.bytes));take(publication->append(view.bytes));offset+=amount;}
    require(original_hash.digest()==snapshot.state->input.sha256,"Original input does not match project SHA-256 identity",ErrorCode::integrity);receipt.sha256=output_hash.digest();canceled(stop);take(publication->publish());return receipt;
});}
}

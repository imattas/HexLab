#include "hexlab/workspace/document.hpp"
#include "hexlab/workspace/open_recipe.hpp"
#include "hexlab/loaders/recipe.hpp"
#include "hexlab/workspace/project.hpp"

namespace hexlab {
const StringScan& DocumentSnapshot::strings()const noexcept {if(project && project->strings)return *project->strings;return analysis?analysis->strings:inspection_strings;}
const ImageMetadata& DocumentSnapshot::metadata_view()const noexcept {return project && project->loaded?project->loaded->metadata:metadata;}
const ByteStorage& DocumentSnapshot::file_storage()const noexcept {
    if(project && project->effective)return *project->effective;
    return input_storage?*input_storage:*image->storage();
}
Result<std::shared_ptr<const DocumentSnapshot>> load_document(const OpenRequest& request,OpenTicket ticket,std::stop_token stop) {
    if(stop.stop_requested())return Error{ErrorCode::canceled,"Opening canceled"};
    auto recipe=resolve_open_recipe(request,stop);
    if(!recipe)return recipe.error();
    try {
        std::shared_ptr<const ByteStorage> storage=request.input_storage;
        if(!storage){auto file=FileStorage::open(request.path);if(!file)return file.error();storage=std::move(file.value());}
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Opening canceled"};
        auto document=std::make_shared<DocumentSnapshot>();
        document->id=ticket.document;document->revision=ticket.generation;
        document->analysis_requested=request.run_analysis;
        document->input_storage=storage;
        auto loaded=load_image(storage,recipe.value(),stop);
        if(!loaded)return loaded.error();
        document->image=std::move(loaded.value().image);document->metadata=std::move(loaded.value().metadata);
        document->diagnostics=std::move(loaded.value().diagnostics);document->metadata_complete=loaded.value().metadata_complete;
        if(request.run_analysis) {
            const bool range_decode = document->image->layout().execution_profile &&
                std::any_of(document->image->layout().execution_profile->ranges.begin(),
                            document->image->layout().execution_profile->ranges.end(),
                            [](const auto &range) { return processor_capabilities(range.context).can_decode; });
            if(processor_capabilities(document->image->decode_context()).can_decode || range_decode) {
                auto analysis=analyze(*document->image,document->metadata,request.analysis_options,stop);
                if(!analysis)return analysis.error();
                document->analysis=std::move(analysis.value());
            } else {
                auto strings=find_strings(*document->image,request.analysis_options,stop);
                if(!strings)return strings.error();
                document->inspection_strings=std::move(strings.value());
                document->diagnostics.push_back({DiagnosticSeverity::info,"Instruction analysis is not yet supported for this image's CPU/mode",{}});
            }
        }
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Opening canceled"};
        return std::shared_ptr<const DocumentSnapshot>(std::move(document));
    } catch(const std::bad_alloc&) {return Error{ErrorCode::resource_limit,"Cannot allocate document snapshot"};}
      catch(const std::filesystem::filesystem_error& error) {return Error{ErrorCode::io,error.what()};}
}
}

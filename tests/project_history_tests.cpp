#include "hexlab/database/transaction.hpp"
#include "hexlab/database/collaboration.hpp"
#include "hexlab/database/connection.hpp"
#include "hexlab/core/encoding.hpp"
#include "hexlab/image/file_storage.hpp"
#include "testing.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
using namespace hexlab;
using namespace hexlab::database;
using namespace hexlab_test;
struct ProjectFixture {
    FixtureFile marker{std::span<const std::byte>{}};std::filesystem::path path=marker.path.wstring()+L".hxproj";
    ~ProjectFixture(){std::error_code ignored;std::filesystem::remove(path,ignored);auto wal=path;wal+=L"-wal";std::filesystem::remove(wal,ignored);auto shm=path;shm+=L"-shm";std::filesystem::remove(shm,ignored);}
};
Annotation named(std::uint64_t id,std::string name){return {id,Address{{0},0x1000},std::move(name),{}};}
StateDelta rename(std::optional<Annotation> before,std::optional<Annotation> after){return {{AnnotationChange{std::move(before),std::move(after)}}};}
void history_tests(){
    ProjectFixture fixture;auto store=ProjectStore::create(fixture.path,{}).value();auto initial=store->snapshot().value();
    auto first=named(1,"first");auto ack=store->commit(0,rename({},first),7,{}).value();check(ack.revisions.edit==1 && ack.history_cursor==1,"first accepted edit has durable revision and history position");
    check(initial->user->annotations.empty() && initial->revisions.edit==0,"preceding snapshot remains immutable");
    auto second=first;second.name="second";check(bool(store->commit(1,rename(first,second),7,{})),"second change in same group commits");
    auto stale=store->commit(1,rename(second,first),0,{});check(!stale && stale.error().code==ErrorCode::conflict,"stale revision rejected");
    auto bad_before=first;bad_before.name="wrong";auto rejected=store->commit(2,rename(bad_before,first),0,{});check(!rejected && rejected.error().code==ErrorCode::conflict,"incorrect entity precondition rejected");
    check(store->snapshot().value()->revisions.edit==2 && store->snapshot().value()->user->annotations[0].name=="second","failed edits do not change state or history");
    auto undo=store->undo(2,{}).value();check(undo.revisions.edit==3 && undo.history_cursor==0 && store->snapshot().value()->user->annotations.empty(),"grouped changes undo as one monotonic edit");
    check(store->snapshot().value()->next_entity==2,"undo never rewinds stable ID allocation");store.reset();
    store=ProjectStore::open(fixture.path,ProjectMode::read_write,{}).value();auto redo=store->redo(3,{}).value();check(redo.revisions.edit==4 && redo.history_cursor==2 && store->snapshot().value()->user->annotations[0].name=="second","redo grouping and cursor survive reopen");
    check(bool(store->undo(4,{})),"reopened group undo succeeds");auto branch=named(2,"branch");check(bool(store->commit(5,rename({},branch),0,{})),"new command branches after undo");
    check(!store->redo(6,{}) && store->snapshot().value()->user->annotations[0].name=="branch","new edit atomically truncates redo branch");
    auto changed=branch;changed.comment="persisted\ncomment";testing::fail_next_commit(ErrorCode::io);
    auto failed=store->commit(6,rename(branch,changed),0,{});check(!failed && failed.error().code==ErrorCode::io && store->snapshot().value()->revisions.edit==6,"commit failure cannot publish a new snapshot");store.reset();
    store=ProjectStore::open(fixture.path,ProjectMode::read_write,{}).value();check(store->snapshot().value()->revisions.edit==6 && store->snapshot().value()->user->annotations[0]==branch,"failed SQL commit leaves durable state unchanged");
    auto readonly=ProjectStore::open(fixture.path,ProjectMode::read_only,{}).value();auto denied=readonly->commit(6,rename(branch,changed),0,{});check(!denied && denied.error().code==ErrorCode::read_only,"read only store rejects commands");
    check(!readonly->undo(6,{}) && !readonly->redo(6,{}),"read only store rejects history mutation");
    std::stop_source stopped;stopped.request_stop();auto canceled=store->commit(6,rename(branch,changed),0,stopped.get_token());check(!canceled && canceled.error().code==ErrorCode::canceled,"canceled edit is not accepted");
}
void type_origin_history_tests(){
    ProjectFixture fixture;auto store=ProjectStore::create(fixture.path,{}).value();
    TypeDefinition imported{1,"Imported",types::Type::void_type(),DwarfSourceOrigin{"unit.o",".debug_info",8,24,12}};
    check(bool(store->commit(0,{{TypeDefinitionChange{{},imported}}},0,{})),"DWARF type with source origin commits");
    store.reset();store=ProjectStore::open(fixture.path,ProjectMode::read_write,{}).value();
    check(store->snapshot().value()->user->types==std::vector<TypeDefinition>{imported},"named type DIE origin survives SQLite reopen");
    check(bool(store->undo(1,{}))&&store->snapshot().value()->user->types.empty(),"undo removes the provenance-bearing type definition");
    check(bool(store->redo(2,{}))&&store->snapshot().value()->user->types==std::vector<TypeDefinition>{imported},"redo restores the complete named type origin from history payload");
}
void decision_and_patch_tests(){
    ProjectFixture fixture;auto store=ProjectStore::create(fixture.path,{}).value();store.reset();
    // Independently embed a two-byte original before the input-import API exists.
    const auto original=bytes({0x90,0xc3});Sha256 sha;check(bool(sha.update(original)),"fixture identity computed");auto sql=Connection::open(fixture.path,OpenMode::read_write,{}).value();
    auto identity=sql->prepare("UPDATE project SET input_size=?1,input_sha256=?2 WHERE singleton=1").value();check(bool(identity->bind_blob(1,encode_u64(2))) && bool(identity->bind_blob(2,sha.digest())) && !identity->step().value(),"fixture input identity stored");identity.reset();check(bool(sql->execute("INSERT INTO input_chunks VALUES(x'0000000000000000',x'90c3')")),"fixture original embedded");sql.reset();
    store=ProjectStore::open(fixture.path,ProjectMode::read_write,{}).value();
    RegionDecision region{1,{{0},0},1,RegionKind::data};std::vector<PatchSpan> patches{{{0},bytes({0x90}),bytes({0xcc})}};
    StateDelta change{{RegionChange{{},region},PatchChange{{},patches}}};auto ack=store->commit(0,change,0,{}).value();
    check(ack.revisions==ProjectRevisions{1,1,1},"one mixed edit advances exact byte and decision revisions");
    auto preceding=store->snapshot().value();check(store->undo(1,{}).value().revisions==ProjectRevisions{2,2,2},"undo changes relevant revisions monotonically");
    check(preceding->user->patches.size()==1 && store->snapshot().value()->user->patches.empty(),"patch undo retains old immutable snapshot");
    check(store->redo(2,{}).value().revisions==ProjectRevisions{3,3,3},"redo restores patch and decision together");
    auto annotation=named(2,"label");auto edited=store->commit(3,rename({},annotation),0,{}).value();check(edited.revisions==ProjectRevisions{4,3,3},"presentation edit does not invalidate bytes or decisions");
}
void inverse_and_chunk_tests(){
    ProjectFixture fixture;auto store=ProjectStore::create(fixture.path,{}).value();auto first=named(1,"first");check(bool(store->commit(0,rename({},first),0,{})),"inverse fixture committed");
    auto sql=Connection::open(fixture.path,OpenMode::read_write,{}).value();check(bool(sql->execute("UPDATE annotations SET name='external'")),"independent mutation changes inverse precondition");sql.reset();
    auto rejected=store->undo(1,{});check(!rejected && rejected.error().code==ErrorCode::conflict,"mismatching inverse cannot partially undo");store.reset();
    store=ProjectStore::open(fixture.path,ProjectMode::read_write,{}).value();check(store->snapshot().value()->revisions.edit==1 && store->snapshot().value()->history_cursor==1 && store->snapshot().value()->user->annotations[0].name=="external","failed inverse leaves durable values and history cursor unchanged");
    auto before=store->snapshot().value()->user->annotations[0],after=before;after.comment=std::string(1024*1024,'x');check(bool(store->commit(1,rename(before,after),0,{})),"maximum-sized comment commits");
    sql=Connection::open(fixture.path,OpenMode::read_only,{}).value();auto chunks=sql->prepare("SELECT count(*),max(length(data)) FROM history_payload WHERE step=x'0000000000000002' AND side=0").value();check(chunks->step().value() && chunks->integer(0).value()>=2 && chunks->integer(1).value()<=1024*1024,"large history delta is stored in bounded chunks");chunks.reset();sql.reset();
    check(bool(store->undo(2,{})) && store->snapshot().value()->user->annotations[0].comment.empty(),"chunked inverse reconstructs complete previous value");store.reset();
    store=ProjectStore::open(fixture.path,ProjectMode::read_write,{}).value();check(bool(store->redo(3,{})) && store->snapshot().value()->user->annotations[0].comment==after.comment,"chunked forward history survives reopening");
}
void entity_tests(){
    ProjectFixture fixture;auto store=ProjectStore::create(fixture.path,{}).value();auto a=named(1,"a"),b=named(2,"b");b.location=Address{{0},0x2000};
    StateDelta initial{{AnnotationChange{{},a},AnnotationChange{{},b}}};check(bool(store->commit(0,initial,0,{})),"multi-entity command allocates consecutive stable IDs");
    auto swapped_a=a,swapped_b=b;swapped_a.name="b";swapped_b.name="a";
    StateDelta swap{{AnnotationChange{a,swapped_a},AnnotationChange{b,swapped_b}}};check(bool(store->commit(1,swap,0,{})),"unique names can swap atomically without transient conflicts");check(bool(store->undo(2,{})) && store->snapshot().value()->user->annotations[0].name=="a","name swap reverses as one command");
    Bookmark bookmark{3,FileOffset{0},"start"};FunctionDecision function{4,{{0},0x1000},false,{{{{0},0x1000},8},{{{0},0x2000},8}}};UserReference reference{5,Address{{0},0x1000},FileOffset{0},UserReferenceKind::address};
    StateDelta definitions{{BookmarkChange{{},bookmark},FunctionChange{{},function},ReferenceChange{{},reference}}};check(bool(store->commit(3,definitions,0,{})),"bookmark function and explicit reference commit together");store.reset();
    store=ProjectStore::open(fixture.path,ProjectMode::read_write,{}).value();auto state=store->snapshot().value();check(state->user->bookmarks[0]==bookmark && state->user->decisions.functions[0]==function && state->user->decisions.references[0]==reference,"all typed entities and ordered child chunks survive reopen");
    check(bool(store->undo(4,{})) && store->snapshot().value()->user->decisions.functions.empty() && store->snapshot().value()->user->bookmarks.empty(),"group undo removes parent children and associated decisions atomically");
}
void collaboration_tests(){
    ProjectFixture fixture;auto owner=ProjectStore::create(fixture.path,{}).value();
    auto first=named(1,"owner");check(bool(owner->commit(0,rename({},first),0,{})),"owner establishes first shared revision");
    auto peer=ProjectCollaboration::open(fixture.path,{}).value();
    check(peer->project()->mode()==ProjectMode::read_write,"collaborative open remains editable alongside leased owner");
    auto proposed=named(1,"peer");
    auto submitted=peer->submit(0,rename({},proposed),0,{}).value();
    check(!submitted.committed && submitted.conflict && submitted.conflict->base_revision==0 &&
          submitted.conflict->observed_revision==1,"stale collaboration delta becomes a durable conflict proposal");
    auto pending=peer->conflicts().value();
    check(pending.size()==1 && pending[0].id==submitted.conflict->id &&
          std::get<AnnotationChange>(pending[0].proposal.changes[0]).after->name=="peer",
          "conflict inbox exposes the retained proposed edit");
    auto latest=peer->refresh({}).value();
    check(latest->revisions.edit==1 && latest->user->annotations[0].name=="owner",
          "collaborator refresh supplies the head snapshot needed for rebase");
    auto rebased=named(1,"peer");auto applied=peer->resolve(pending[0].id,true,1,rename(first,rebased),0,{});
    check(bool(applied) && applied.value().revisions.edit==2,"rebased proposal can be accepted at the current revision");
    auto all=peer->conflicts(true).value();
    check(all.size()==1 && all[0].resolved && all[0].accepted,"resolution state survives conflict query");
    peer.reset();owner.reset();
    auto reopened=ProjectCollaboration::open(fixture.path,{}).value();
    auto durable=reopened->conflicts(true).value();
    check(durable.size()==1 && durable[0].resolved && durable[0].accepted &&
          reopened->project()->snapshot().value()->user->annotations.size()==1 &&
          reopened->project()->snapshot().value()->user->annotations[0].name=="peer",
          "accepted conflict and resolved project state survive reopen");
    check(bool(reopened->dismiss(durable[0].id,2,{}))==false,"resolved conflicts cannot be dismissed twice");
}
void metadata_three_way_merge_tests(){
    ProjectFixture fixture;auto owner=ProjectStore::create(fixture.path,{}).value();
    auto base=named(1,"base");check(bool(owner->commit(0,rename({},base),0,{})),"shared annotation base is committed");
    auto peer=ProjectCollaboration::open(fixture.path,{}).value();
    auto owner_edit=base;owner_edit.comment="owner comment";
    check(bool(owner->commit(1,rename(base,owner_edit),0,{})),"owner changes annotation comment");
    auto peer_edit=base;peer_edit.name="peer name";
    auto merged=peer->submit(1,rename(base,peer_edit),0,{}).value();
    auto merged_row=peer->project()->snapshot().value()->user->annotations[0];
    check(merged.committed && !merged.conflict && merged_row.name=="peer name" && merged_row.comment=="owner comment",
          "stale name edit merges with an independent comment edit");
    auto shared=merged_row;shared.comment="latest owner comment";
    check(bool(owner->commit(3,rename(merged_row,shared),0,{})),"owner advances the comment again");
    auto competing=merged_row;competing.comment="peer competing comment";
    auto conflict=peer->submit(3,rename(merged_row,competing),0,{}).value();
    check(!conflict.committed && conflict.conflict.has_value(),"different edits to the same comment remain a reviewable conflict");
    peer.reset();owner.reset();
    auto reopened=ProjectCollaboration::open(fixture.path,{}).value();
    auto inbox=reopened->conflicts().value();auto final_row=reopened->project()->snapshot().value()->user->annotations[0];
    check(inbox.size()==1 && std::get<AnnotationChange>(inbox[0].proposal.changes[0]).after->comment=="peer competing comment" &&
          final_row.name=="peer name" && final_row.comment=="latest owner comment",
          "unmerged same-field proposal and winning state both survive reopen without choosing the proposal");
}
void type_assignment_rebase_tests(){
    for (const bool erase : {false,true}) {
        ProjectFixture fixture;auto owner=ProjectStore::create(fixture.path,{}).value();
        TypeDefinition first{1,"First",types::Type::void_type()},second{2,"Second",types::Type::void_type()};
        TypeAssignment left{3,Address{{0},0x1000},1},right{4,Address{{0},0x2000},1};
        StateDelta initial{{TypeDefinitionChange{{},first},TypeDefinitionChange{{},second},
                            TypeAssignmentChange{{},left},TypeAssignmentChange{{},right}}};
        check(bool(owner->commit(0,initial,0,{})),"type rebase fixture commits");
        auto peer=ProjectCollaboration::open(fixture.path,{}).value();
        auto owner_edit=left;owner_edit.type_id=2;
        check(bool(owner->commit(1,{{TypeAssignmentChange{left,owner_edit}}},0,{})),"owner changes the first address type");
        auto peer_edit=right;peer_edit.type_id=2;
        StateDelta proposal{{TypeAssignmentChange{right,erase?std::optional<TypeAssignment>{}:peer_edit}}};
        auto submission=peer->submit(1,proposal,72,{}).value();
        check(submission.committed && !submission.conflict,
              "stale type replacement or deletion rebases across a different address edit");
        if (!submission.committed) continue;
        const auto state=peer->project()->snapshot().value();
        check(state->revisions.edit==3 && state->user->type_assignments[0]==owner_edit &&
              state->user->type_assignments.size()==(erase?1u:2u) &&
              (erase || state->user->type_assignments[1]==peer_edit),
              "rebased type change preserves both peers' intended address values");
        check(bool(peer->project()->undo(3,{})) &&
              peer->project()->snapshot().value()->user->type_assignments==std::vector<TypeAssignment>{owner_edit,right},
              "undo of rebased type change preserves the concurrent owner's change");
        check(bool(peer->project()->redo(4,{})),"rebased type change remains redoable");
        peer.reset();owner.reset();
        auto reopened=ProjectCollaboration::open(fixture.path,{}).value();
        check(reopened->project()->snapshot().value()->user->type_assignments==state->user->type_assignments &&
              reopened->conflicts().value().empty(),"rebased assignments survive reopen without an inbox entry");
    }
}
void type_assignment_insert_rebase_tests(){
    ProjectFixture fixture;auto owner=ProjectStore::create(fixture.path,{}).value();
    TypeDefinition first{1,"First",types::Type::void_type()},second{2,"Second",types::Type::void_type()};
    check(bool(owner->commit(0,{{TypeDefinitionChange{{},first},TypeDefinitionChange{{},second}}},0,{})),
          "type insertion fixture commits");
    auto peer=ProjectCollaboration::open(fixture.path,{}).value();
    TypeAssignment left{3,Address{{0},0x1000},1},right{3,Address{{0},0x2000},2};
    check(bool(owner->commit(1,{{TypeAssignmentChange{{},left}}},0,{})),"owner consumes the peer's proposed stable ID");
    TypeAssignment other_space{4,Address{{1},0x1000},2};
    auto submission=peer->submit(1,{{TypeAssignmentChange{{},right},TypeAssignmentChange{{},other_space}}},0,{}).value();
    check(submission.committed && !submission.conflict,"stale insertion at another address receives a fresh stable ID");
    if (!submission.committed) return;
    const TypeAssignment rebased_right{4,Address{{0},0x2000},2};
    const TypeAssignment rebased_other_space{5,Address{{1},0x1000},2};
    auto state=peer->project()->snapshot().value();
    check(state->user->type_assignments==std::vector<TypeAssignment>{left,rebased_right,rebased_other_space} && state->next_entity==6,
          "insertion rebase preserves the owner and allocates the next available ID");
    check(bool(peer->project()->undo(3,{})) &&
          peer->project()->snapshot().value()->user->type_assignments==std::vector<TypeAssignment>{left},
          "undo removes only the assignment inserted by rebase");
    check(bool(peer->project()->redo(4,{})) &&
          peer->project()->snapshot().value()->user->type_assignments==state->user->type_assignments,
          "redo restores the newly allocated assignment identity");
    peer.reset();owner.reset();
    auto reopened=ProjectCollaboration::open(fixture.path,{}).value();
    check(reopened->project()->snapshot().value()->user->type_assignments==state->user->type_assignments &&
          reopened->project()->snapshot().value()->next_entity==6 && reopened->conflicts().value().empty(),
          "fresh assignment IDs and their allocation cursor survive reopen");
}
void type_assignment_overlap_conflict_tests(){
    for (const bool owner_erases : {false,true}) {
    for (const bool erase : {false,true}) {
        ProjectFixture fixture;auto owner=ProjectStore::create(fixture.path,{}).value();
        TypeDefinition first{1,"First",types::Type::void_type()},second{2,"Second",types::Type::void_type()};
        TypeAssignment base{3,Address{{0},0x1000},1};
        check(bool(owner->commit(0,{{TypeDefinitionChange{{},first},TypeDefinitionChange{{},second},
                                    TypeAssignmentChange{{},base}}},0,{})),"overlapping type fixture commits");
        auto peer=ProjectCollaboration::open(fixture.path,{}).value();
        auto owner_edit=base;owner_edit.type_id=2;
        check(bool(owner->commit(1,{{TypeAssignmentChange{base,owner_erases?std::optional<TypeAssignment>{}:owner_edit}}},0,{})),
              "owner changes or removes the contested address");
        // Even convergent same-address replacements retain the original proposal.
        StateDelta proposal{{TypeAssignmentChange{base,erase?std::optional<TypeAssignment>{}:owner_edit}}};
        auto submission=peer->submit(1,proposal,0,{}).value();
        check(!submission.committed && submission.conflict.has_value(),"same-address type replacement or deletion remains a conflict");
        peer.reset();owner.reset();
        auto reopened=ProjectCollaboration::open(fixture.path,{}).value();
        auto inbox=reopened->conflicts().value();
        check(inbox.size()==1 && std::get<TypeAssignmentChange>(inbox[0].proposal.changes[0]).before==base &&
              std::get<TypeAssignmentChange>(inbox[0].proposal.changes[0]).after==std::get<TypeAssignmentChange>(proposal.changes[0]).after &&
              reopened->project()->snapshot().value()->user->type_assignments==
                  (owner_erases?std::vector<TypeAssignment>{}:std::vector<TypeAssignment>{owner_edit}),
              "same-address proposal survives reopen while the owner's assignment remains unchanged");
    }
    }
}
void type_assignment_insert_overlap_tests(){
    ProjectFixture fixture;auto owner=ProjectStore::create(fixture.path,{}).value();
    TypeDefinition type{1,"First",types::Type::void_type()};
    check(bool(owner->commit(0,{{TypeDefinitionChange{{},type}}},0,{})),"same-address insertion fixture commits");
    auto peer=ProjectCollaboration::open(fixture.path,{}).value();
    TypeAssignment owner_row{2,Address{{0},0x1000},1};
    check(bool(owner->commit(1,{{TypeAssignmentChange{{},owner_row}}},0,{})),"owner assigns the contested address");
    TypeAssignment independent{2,Address{{0},0x2000},1};
    TypeAssignment overlapping{3,Address{{0},0x1000},1};
    auto submission=peer->submit(1,{{TypeAssignmentChange{{},independent},TypeAssignmentChange{{},overlapping}}},0,{}).value();
    check(!submission.committed && submission.conflict && submission.conflict->proposal.changes.size()==2 &&
          peer->project()->snapshot().value()->user->type_assignments==std::vector<TypeAssignment>{owner_row} &&
          peer->project()->snapshot().value()->next_entity==3,
          "a same-address insertion retains the whole proposal without partially allocating or inserting its independent assignment");
}
void type_assignment_rebase_boundary_tests(){
    enum class Boundary {move,identity,missing_definition,unsupported_change};
    for (const auto boundary : {Boundary::move,Boundary::identity,Boundary::missing_definition,Boundary::unsupported_change}) {
        ProjectFixture fixture;auto owner=ProjectStore::create(fixture.path,{}).value();
        TypeDefinition first{1,"First",types::Type::void_type()},second{2,"Second",types::Type::void_type()};
        TypeAssignment left{3,Address{{0},0x1000},1},right{4,Address{{0},0x2000},1};
        check(bool(owner->commit(0,{{TypeDefinitionChange{{},first},TypeDefinitionChange{{},second},
                                    TypeAssignmentChange{{},left},TypeAssignmentChange{{},right}}},0,{})),
              "type rebase boundary fixture commits");
        auto peer=ProjectCollaboration::open(fixture.path,{}).value();
        auto owner_edit=left;owner_edit.type_id=2;
        StateDelta owner_delta=boundary==Boundary::missing_definition?
            StateDelta{{TypeDefinitionChange{second,{}}}}:StateDelta{{TypeAssignmentChange{left,owner_edit}}};
        check(bool(owner->commit(1,owner_delta,0,{})),"owner advances the boundary fixture");
        const auto current=owner->snapshot().value();
        auto proposed=right;proposed.type_id=2;
        if (boundary==Boundary::move) proposed.location=Address{{0},0x3000};
        if (boundary==Boundary::identity) proposed.id=5;
        StateDelta proposal{{TypeAssignmentChange{right,proposed}}};
        if (boundary==Boundary::unsupported_change) {
            auto renamed=first;renamed.name="Renamed";
            proposal.changes.emplace_back(TypeDefinitionChange{first,renamed});
        }
        auto submission=peer->submit(1,proposal,0,{}).value();
        const auto after=peer->project()->snapshot().value();
        check(!submission.committed && submission.conflict && submission.conflict->proposal.changes.size()==proposal.changes.size() &&
              after->revisions==current->revisions && *after->user==*current->user && after->next_entity==current->next_entity,
              "moves, identity changes, removed definitions, and unsupported mixed deltas stay atomic reviewable conflicts");
    }
}
void import_patch_source(ProjectStore& store,const std::filesystem::path& path){
    auto opened=FileStorage::open(path);
    if(!opened)throw std::runtime_error("opening collaboration patch input failed: "+opened.error().message);
    auto source=std::move(opened.value());
    auto snapshot=store.snapshot();
    if(!snapshot)throw std::runtime_error("reading collaboration patch project failed: "+snapshot.error().message);
    auto recipe=snapshot.value()->recipe;
    auto imported=[&]{
        try{return store.import_input(*source,recipe,path,{});}
        catch(const std::exception& error){throw std::runtime_error(std::string("importing collaboration patch input threw: ")+error.what());}
    }();
    if(!imported)throw std::runtime_error("importing collaboration patch input failed: "+imported.error().message);
    check(imported.value(),"collaboration patch fixture imports original bytes");
}
void patch_three_way_merge_tests(){
    {
        FixtureFile input(bytes({0x10,0x20,0x30,0x40}));ProjectFixture fixture;
        auto created=ProjectStore::create(fixture.path,{});
        if(!created)throw std::runtime_error("creating disjoint patch project failed: "+created.error().message);
        auto owner=std::move(created.value());import_patch_source(*owner,input.path);
        PatchSpan base_patch{{1},bytes({0x20}),bytes({0xaa})};
        check(bool(owner->commit(0,{{PatchChange{{},{base_patch}}}},0,{})),"owner establishes existing base patch");
        auto opened=ProjectCollaboration::open(fixture.path,{});
        if(!opened)throw std::runtime_error("opening disjoint patch peer failed: "+opened.error().message);
        auto peer=std::move(opened.value());
        PatchSpan owner_patch{{0},bytes({0x10}),bytes({0xcc})};
        PatchSpan peer_patch{{2},bytes({0x30}),bytes({0xdd})};
        check(bool(owner->commit(1,{{PatchChange{{base_patch},{owner_patch,base_patch}}}},0,{})),"owner commits first byte patch");
        auto result=peer->submit(1,{{PatchChange{{base_patch},{base_patch,peer_patch}}}},0,{});
        if(!result)throw std::runtime_error("disjoint patch submission failed: "+result.error().message);
        auto merged=std::move(result.value());
        const std::vector<PatchSpan> expected{{{0},bytes({0x10,0x20,0x30}),bytes({0xcc,0xaa,0xdd})}};
        auto merged_state=peer->project()->snapshot();
        if(!merged_state)throw std::runtime_error("reading merged disjoint patch state failed: "+merged_state.error().message);
        check(merged.committed && !merged.conflict && merged_state.value()->user->patches==expected,
              "non-overlapping stale patch edits merge over the current head");
        auto undo=[&]{try{return peer->project()->undo(3,{});}catch(const std::exception& error){throw std::runtime_error(std::string("undo of merged patch threw: ")+error.what());}}();
        if(!undo)throw std::runtime_error("undo of merged patch failed: "+undo.error().message);
        auto undone=peer->project()->snapshot();if(!undone)throw std::runtime_error("reading undone patch state failed: "+undone.error().message);
        check(undone.value()->user->patches==std::vector<PatchSpan>{owner_patch,base_patch},
              "undo of rebased patch keeps the concurrent owner's patch");
        auto redo=[&]{try{return peer->project()->redo(4,{});}catch(const std::exception& error){throw std::runtime_error(std::string("redo of merged patch threw: ")+error.what());}}();
        if(!redo)throw std::runtime_error("redo of merged patch failed: "+redo.error().message);
        auto redone=peer->project()->snapshot();if(!redone)throw std::runtime_error("reading redone patch state failed: "+redone.error().message);
        check(redone.value()->user->patches==expected,
              "redo restores the rebased patch set");
    }
    {
        FixtureFile input(bytes({0x10,0x20}));ProjectFixture fixture;
        auto created=ProjectStore::create(fixture.path,{});
        if(!created)throw std::runtime_error("creating convergent patch project failed: "+created.error().message);
        auto owner=std::move(created.value());import_patch_source(*owner,input.path);
        auto opened=ProjectCollaboration::open(fixture.path,{});
        if(!opened)throw std::runtime_error("opening convergent patch peer failed: "+opened.error().message);
        auto peer=std::move(opened.value());
        PatchSpan same{{1},bytes({0x20}),bytes({0xaa})};
        check(bool(owner->commit(0,{{PatchChange{{},{same}}}},0,{})),"owner commits convergent patch");
        auto submission=peer->submit(0,{{PatchChange{{},{same}}}},0,{});
        if(!submission)throw std::runtime_error("convergent patch submission failed: "+submission.error().message);
        auto merged=std::move(submission.value());
        auto merged_state=peer->project()->snapshot();
        if(!merged_state)throw std::runtime_error("reading merged convergent patch state failed: "+merged_state.error().message);
        check(merged.committed && !merged.conflict && merged.committed->revisions.edit==1 &&
              merged_state.value()->user->patches==std::vector<PatchSpan>{same},
              "convergent edits to the same byte merge once");
    }
    {
        FixtureFile input(bytes({0x10,0x20}));ProjectFixture fixture;
        auto created=ProjectStore::create(fixture.path,{});
        if(!created)throw std::runtime_error("creating conflicting patch project failed: "+created.error().message);
        auto owner=std::move(created.value());import_patch_source(*owner,input.path);
        auto opened=ProjectCollaboration::open(fixture.path,{});
        if(!opened)throw std::runtime_error("opening conflicting patch peer failed: "+opened.error().message);
        auto peer=std::move(opened.value());
        PatchSpan owner_patch{{1},bytes({0x20}),bytes({0xaa})};
        PatchSpan peer_patch{{1},bytes({0x20}),bytes({0xbb})};
        check(bool(owner->commit(0,{{PatchChange{{},{owner_patch}}}},0,{})),"owner commits contested patch");
        auto submission=peer->submit(0,{{PatchChange{{},{peer_patch}}}},0,{});
        if(!submission)throw std::runtime_error("conflicting patch submission failed: "+submission.error().message);
        auto proposal=std::move(submission.value());
        auto state_result=peer->project()->snapshot();
        if(!state_result)throw std::runtime_error("reading contested patch state failed: "+state_result.error().message);
        auto state=std::move(state_result.value());
        check(!proposal.committed && proposal.conflict && state->revisions.edit==1 && state->user->patches==std::vector<PatchSpan>{owner_patch},
              "different replacements of the same byte remain an atomic durable conflict");
        peer.reset();owner.reset();
        auto reopened=ProjectCollaboration::open(fixture.path,{});
        if(!reopened)throw std::runtime_error("reopening patch conflict project failed: "+reopened.error().message);
        auto inbox=reopened.value()->conflicts();
        if(!inbox)throw std::runtime_error("reading persisted patch conflict failed: "+inbox.error().message);
        check(inbox.value().size()==1 &&
              std::get<PatchChange>(inbox.value()[0].proposal.changes[0]).after==std::vector<PatchSpan>{peer_patch} &&
              reopened.value()->project()->snapshot().value()->user->patches==std::vector<PatchSpan>{owner_patch},
              "conflicting patch proposal survives reopen without changing the owner's bytes");
    }
}
int main(){return run([]{history_tests();type_origin_history_tests();decision_and_patch_tests();inverse_and_chunk_tests();entity_tests();collaboration_tests();metadata_three_way_merge_tests();type_assignment_rebase_tests();type_assignment_insert_rebase_tests();type_assignment_overlap_conflict_tests();type_assignment_insert_overlap_tests();type_assignment_rebase_boundary_tests();patch_three_way_merge_tests();});}

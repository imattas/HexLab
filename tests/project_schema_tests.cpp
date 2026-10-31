#include "hexlab/database/project_state.hpp"
#include "hexlab/database/codec.hpp"
#include "hexlab/database/connection.hpp"
#include "hexlab/core/encoding.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include "testing.hpp"
using namespace hexlab;
using namespace hexlab::database;
using namespace hexlab_test;
void codec_tests(){
    UserState empty;
    // Version 5 predates type source origins and project breakpoints. Encode
    // its empty record shape directly instead of changing only the version
    // byte of a newer version-10 payload (which has an extra breakpoint list).
    std::vector<std::byte> legacy_v5(2 + 9 * 4, std::byte{0});
    legacy_v5[0]=std::byte{5};
    check(decode_user_state(legacy_v5)&&decode_user_state(legacy_v5).value()==empty,"user-state codec remains compatible with v5 records without type origins");
    UserState user;user.annotations.push_back({1,Address{{0xffffffff},0xfffffffffffffff0},"\xc3\xa9_name","line one\nline two"});
    user.bookmarks.push_back({2,FileOffset{0xfffffffffffffffe},"overlay"});
    user.decisions.regions.push_back({3,{{0xffffffff},0xfffffffffffffff0},4,RegionKind::data});
    user.decisions.functions.push_back({4,{{0},0x1000},false,{{{{0},0x1000},16}}});
    user.decisions.references.push_back({5,Address{{0},0x1000},FileOffset{0xfffffffffffffff0},UserReferenceKind::address});
    user.patches.push_back({{9},bytes({1,2}),bytes({3,4})});
    auto encoded=encode_user_state(user).value();auto restored=decode_user_state(encoded).value();
    check(restored.annotations[0].location==user.annotations[0].location && restored.bookmarks[0].location==user.bookmarks[0].location,"typed unsigned locations survive codec");
    check(encode_user_state(restored).value()==encoded,"user records have deterministic canonical encoding");
    for(size_t i=0;i<encoded.size();++i)check(!decode_user_state(std::span(encoded).first(i)),"every truncated record vector rejected");
    auto extra=encoded;extra.push_back(std::byte{0});check(!decode_user_state(extra),"trailing data rejected");extra=encoded;extra[0]=std::byte{99};check(!decode_user_state(extra),"unknown record version rejected");
    check(!decode_user_state(bytes({1,0,255,255,255,255})),"hostile vector count rejected before allocation");
    auto bad=user;bad.annotations[0].name=std::string(513,'x');check(!encode_user_state(bad),"name limit enforced");
    bad=user;bad.annotations[0].name="bad\nname";check(!encode_user_state(bad),"name control characters rejected");
    bad=user;bad.annotations[0].name="\xc0\xaf";check(!encode_user_state(bad),"overlong UTF8 rejected");
    bad=user;bad.annotations[0].comment=std::string(1024*1024+1,'x');check(!encode_user_state(bad),"comment size bound enforced");
    bad=user;bad.annotations.push_back({6,Address{{0xffffffff},0x100},bad.annotations[0].name,{}});check(!encode_user_state(bad),"duplicate explicit name in address space rejected");
    bad=user;bad.bookmarks[0].id=1;check(!encode_user_state(bad),"duplicate stable entity IDs rejected across record kinds");
    auto byte=types::Type::integer("u8",1,1,false).value();
    auto pair=types::Type::structure("Pair",{{"left",byte,0},{"right",byte,1}},2,1).value();
    user.types.push_back({7,"Pair",pair,DwarfSourceOrigin{"fixture.o",".debug_info",12,44,16}});user.type_assignments.push_back({8,Address{{2},0x44},7});
    user.debug_variables.push_back({9,{{0},0x1000},"local",7,false,24,{}, {0x91,0x78},{{4,0,-8,0,0}}, {"fixture-id",".debug_info",0,40,12}});
    user.debug_variables.back().cfa_offset=-8;
    user.debug_variables.back().location_ranges={{0x1000,0x1008,{0x50},{{2,0,0,0,0}}}};
    encoded=encode_user_state(user).value();restored=decode_user_state(encoded).value();
    check(restored.types.size()==1 && restored.types[0].type->id()==pair->id() && restored.types[0].origin==user.types[0].origin &&
              restored.type_assignments[0].type_id==7 && restored.debug_variables==user.debug_variables &&
              encode_user_state(restored).value()==encoded,
          "type assignment and DWARF variable origins/locations including CFA offsets have canonical user-state encoding");
    auto bad_type=user;bad_type.types[0].origin->record_size=0;check(!encode_user_state(bad_type),"DWARF type origin requires a nonempty DIE extent");
    auto bad_variable=user;bad_variable.debug_variables[0].type_id=99;check(!encode_user_state(bad_variable),"debug variable cannot reference an absent project type");
    bad_variable=user;bad_variable.debug_variables[0].function_entry.offset=0x2000;check(!encode_user_state(bad_variable),"debug variable cannot reference an absent function root");
    bad_variable=user;bad_variable.debug_variables[0].location_operations[0].expression_offset=2;check(!encode_user_state(bad_variable),"decoded location operation must point inside its raw expression");
}
void schema_tests(){

    FixtureFile marker({});auto path=marker.path;path+=L".hxproj";
    struct Cleanup{std::filesystem::path p;~Cleanup(){std::error_code ec;std::filesystem::remove(p,ec);auto w=p;w+=L"-wal";std::filesystem::remove(w,ec);auto s=p;s+=L"-shm";std::filesystem::remove(s,ec);}} cleanup{path};
    auto created=ProjectStore::create(path,{});if(!created)throw std::runtime_error("schema fixture create: "+created.error().message);auto store=std::move(created.value());auto first_snapshot=store->snapshot();if(!first_snapshot)throw std::runtime_error("schema fixture snapshot: "+first_snapshot.error().message);auto first=std::move(first_snapshot.value());

    check(first->uuid.size()==16 && first->revisions.edit==0 && first->user->annotations.empty(),"new project has UUID and immutable empty state");
    auto duplicate=ProjectStore::create(path,{});check(!duplicate && duplicate.error().code==ErrorCode::conflict,"creating over an existing project is rejected");store.reset();

    auto sql=Connection::open(path,OpenMode::read_write,{}).value();auto app=sql->prepare("PRAGMA application_id").value();check(app->step().value() && app->integer(0).value()==0x48584c42,"project application ID is literal H X L B");app.reset();
    auto version=sql->prepare("PRAGMA user_version").value();check(version->step().value() && version->integer(0).value()==current_project_schema_version,"schema version initialized");version.reset();
    auto header=sql->prepare("SELECT uuid,edit_revision,input_sha256 FROM project WHERE singleton=1").value();check(header->step().value() && header->blob(0).value().size()==16 && header->blob(1).value()==bytes({0,0,0,0,0,0,0,0}) && header->blob(2).value().size()==32,"SQL stores canonical UUID revision and digest sizes");header.reset();
    auto insert=sql->prepare("INSERT INTO annotations(id,location,name,comment) VALUES(?1,?2,?3,?4)").value();
    auto high=encode_location(Address{{0xffffffff},0xfffffffffffffff0}).value();
    check(bool(insert->bind_blob(1,encode_u64(1))) && bool(insert->bind_blob(2,high)) && bool(insert->bind_text(3,"high")) && bool(insert->bind_text(4,"persisted\ncomment")) && !insert->step().value(),"canonical unsigned location inserted independently");insert.reset();check(bool(sql->execute("UPDATE project SET next_entity=x'0000000000000002'")),"fixture advances stable ID cursor");sql.reset();
    auto reopened_result=ProjectStore::open(path,ProjectMode::read_only,{});if(!reopened_result)throw std::runtime_error("schema readonly reopen: "+reopened_result.error().message);auto reopened=std::move(reopened_result.value());auto snapshot_result=reopened->snapshot();if(!snapshot_result)throw std::runtime_error("schema readonly snapshot: "+snapshot_result.error().message);auto snapshot=std::move(snapshot_result.value());check(snapshot->uuid==first->uuid && snapshot->user->annotations[0].location==Location{Address{{0xffffffff},0xfffffffffffffff0}},"project reopen preserves identity and unsigned address");reopened.reset();
    sql=Connection::open(path,OpenMode::read_write,{}).value();
    auto duplicate_name=sql->execute("INSERT INTO annotations VALUES(x'0000000000000002',x'00ffffffff0000000000000100','high','')");check(!duplicate_name && duplicate_name.error().code==ErrorCode::conflict,"SQL uniqueness rejects duplicate address-space name");
    check(bool(sql->execute("INSERT INTO bookmarks VALUES(x'0000000000000002',x'01fffffffffffffffe','overlay')")),"literal file bookmark inserted");
    check(bool(sql->execute("INSERT INTO regions VALUES(x'0000000000000003',x'00000000000000000000001000',x'0000000000000010',1)")),"literal region inserted");
    check(bool(sql->execute("INSERT INTO functions VALUES(x'0000000000000004',x'00000000000000000000001000',0)")) && bool(sql->execute("INSERT INTO function_chunks VALUES(x'0000000000000004',0,x'00000000000000000000001000',x'0000000000000010')")),"literal function with related chunk inserted");
    check(bool(sql->execute("INSERT INTO explicit_references VALUES(x'0000000000000005',x'00000000000000000000001000',x'01fffffffffffffffe',6)")),"literal typed reference inserted");
    check(bool(sql->execute("UPDATE project SET next_entity=x'0000000000000006'")),"fixture advances global IDs");sql.reset();
    auto normalized_reopen=[&]{try{return ProjectStore::open(path,ProjectMode::read_only,{});}catch(const std::exception& e){throw std::runtime_error(std::string("normalized schema reopen threw: ")+e.what());}}();if(!normalized_reopen)throw std::runtime_error("normalized schema reopen: "+normalized_reopen.error().message);reopened=std::move(normalized_reopen.value());auto normalized_snapshot=reopened->snapshot();if(!normalized_snapshot)throw std::runtime_error("normalized schema snapshot: "+normalized_snapshot.error().message);snapshot=std::move(normalized_snapshot.value());
    check(snapshot->user->bookmarks[0].location==Location{FileOffset{0xfffffffffffffffe}} && snapshot->user->decisions.regions[0].kind==RegionKind::data && snapshot->user->decisions.functions[0].chunks[0].size==16 && snapshot->user->decisions.references[0].kind==UserReferenceKind::address,"normalized SQL records restore all decision collections");reopened.reset();


    sql=Connection::open(path,OpenMode::read_write,{}).value();
    check(bool(sql->execute("ALTER TABLE debug_variables DROP COLUMN location_ranges")),"v4 fixture drops variable location ranges");
    check(bool(sql->execute("ALTER TABLE debug_variables DROP COLUMN cfa_offset")),"v4 fixture drops CFA offset");
    check(bool(sql->execute("ALTER TABLE history DROP COLUMN created_unix_ms")),"v4 fixture drops the later history timestamp");
    check(bool(sql->execute("DROP TABLE project_breakpoints")) &&
          bool(sql->execute("DROP TABLE loader_diagnostics")) &&
          bool(sql->execute("DROP TABLE type_import_diagnostics")) &&
          bool(sql->execute("DROP TABLE reviewed_analysis_issues")) &&
          bool(sql->execute("DROP TABLE project_preferences")),
          "v4 fixture removes tables introduced by later schema versions");
    check(bool(sql->execute("DELETE FROM type_assignments")),"v4 fixture clears type assignments before rebuilding type table");
    check(bool(sql->execute("DROP TABLE type_definitions")),"v4 fixture drops type table");
    auto create_legacy_types=sql->execute("CREATE TABLE type_definitions(id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=8),name TEXT UNIQUE NOT NULL CHECK(length(CAST(name AS BLOB)) BETWEEN 1 AND 512),payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 16777216))");
    check(bool(create_legacy_types),"v4 fixture recreates legacy type table");
    check(bool(sql->execute("PRAGMA user_version=4")),"v4 fixture sets schema version");{auto fixture_version=sql->prepare("PRAGMA user_version").value();check(fixture_version->step().value()&&fixture_version->integer(0).value()==4,"v4 fixture persists version 4");}sql.reset();
    auto v4_migrated_result=ProjectStore::open(path,ProjectMode::read_write,{});if(!v4_migrated_result)throw std::runtime_error("v4 migration: "+v4_migrated_result.error().message);auto v4_migrated=std::move(v4_migrated_result.value());v4_migrated.reset();

    sql=Connection::open(path,OpenMode::read_only,{}).value();version=sql->prepare("PRAGMA user_version").value();check(version->step().value() && version->integer(0).value()==current_project_schema_version,"v4 project migrates transactionally through the current schema");version.reset();sql.reset();
    sql=Connection::open(path,OpenMode::read_write,{}).value();check(bool(sql->execute("DROP TABLE type_definitions"))&&bool(sql->execute("CREATE TABLE type_definitions(id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=8),name TEXT UNIQUE NOT NULL CHECK(length(CAST(name AS BLOB)) BETWEEN 1 AND 512),payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 16777216))"))&&bool(sql->execute("ALTER TABLE history DROP COLUMN created_unix_ms"))&&bool(sql->execute("DROP TABLE project_breakpoints"))&&bool(sql->execute("DROP TABLE loader_diagnostics"))&&bool(sql->execute("DROP TABLE type_import_diagnostics"))&&bool(sql->execute("DROP TABLE reviewed_analysis_issues"))&&bool(sql->execute("DROP TABLE project_preferences"))&&bool(sql->execute("PRAGMA user_version=6")),"literal v6 fixture matches the historical table and type shapes");sql.reset();
    auto v6_migrated_result=ProjectStore::open(path,ProjectMode::read_write,{});if(!v6_migrated_result)throw std::runtime_error("v6 migration: "+v6_migrated_result.error().message);auto v6_migrated=std::move(v6_migrated_result.value());v6_migrated.reset();

    sql=Connection::open(path,OpenMode::read_only,{}).value();version=sql->prepare("PRAGMA user_version").value();check(version->step().value()&&version->integer(0).value()==current_project_schema_version,"v6 project migrates transactionally to the current schema");version.reset();sql.reset();
    sql=Connection::open(path,OpenMode::read_write,{}).value();check(bool(sql->execute("PRAGMA user_version=99")),"future schema fixture created");sql.reset();
    FixtureFile before({});auto contents=FileStorage::open(path).value();const auto digest=hash_source(*contents,{}).value();contents.reset();
    auto future=ProjectStore::open(path,ProjectMode::read_write,{});check(!future && future.error().code==ErrorCode::unsupported,"newer schema rejected before mutation");

    check(hash_source(*FileStorage::open(path).value(),{}).value()==digest,"rejected newer project remains byte identical");
    sql=Connection::open(path,OpenMode::read_write,{}).value();check(bool(sql->execute("DROP TABLE debug_variables")) && bool(sql->execute("DROP TABLE collaboration_conflicts")) && bool(sql->execute("DROP TABLE type_assignments")) && bool(sql->execute("DROP TABLE type_definitions")) && bool(sql->execute("DROP TABLE project_breakpoints")) && bool(sql->execute("DROP TABLE loader_diagnostics")) && bool(sql->execute("DROP TABLE type_import_diagnostics")) && bool(sql->execute("DROP TABLE reviewed_analysis_issues")) && bool(sql->execute("DROP TABLE project_preferences")) && bool(sql->execute("ALTER TABLE history DROP COLUMN created_unix_ms")) && bool(sql->execute("PRAGMA user_version=0")) && bool(sql->execute("ALTER TABLE project DROP COLUMN decision_revision")),"literal v0 fixture lacks newer schema columns and tables");sql.reset();
    check(!ProjectStore::open(path,ProjectMode::read_only,{}),"readonly open does not migrate old project");
    std::stop_source interrupted;testing::set_migration_callback([&]{interrupted.request_stop();});
    auto canceled=ProjectStore::open(path,ProjectMode::read_write,interrupted.get_token());check(!canceled && canceled.error().code==ErrorCode::canceled,"migration cancellation is returned");
    sql=Connection::open(path,OpenMode::read_only,{}).value();version=sql->prepare("PRAGMA user_version").value();check(version->step().value() && version->integer(0).value()==0,"failed migration rolls back schema version");version.reset();
    auto columns=sql->prepare("SELECT count(*) FROM pragma_table_info('project') WHERE name='decision_revision'").value();check(columns->step().value() && columns->integer(0).value()==0,"failed migration rolls back added column too");columns.reset();sql.reset();
    auto migrated_result=ProjectStore::open(path,ProjectMode::read_write,{});if(!migrated_result)throw std::runtime_error("v0 migration: "+migrated_result.error().message);auto migrated=std::move(migrated_result.value());check(migrated->snapshot().value()->uuid==first->uuid && migrated->snapshot().value()->revisions.decisions==0,"v0 migration preserves UUID and data");migrated.reset();
    sql=Connection::open(path,OpenMode::read_write,{}).value();
    check(bool(sql->execute("DROP TABLE debug_variables"))&&bool(sql->execute("DROP TABLE type_definitions"))&&bool(sql->execute("CREATE TABLE type_definitions(id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=8),name TEXT UNIQUE NOT NULL CHECK(length(CAST(name AS BLOB)) BETWEEN 1 AND 512),payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 16777216))"))&&bool(sql->execute("ALTER TABLE history DROP COLUMN created_unix_ms"))&&bool(sql->execute("DROP TABLE project_breakpoints"))&&bool(sql->execute("DROP TABLE loader_diagnostics"))&&bool(sql->execute("DROP TABLE type_import_diagnostics"))&&bool(sql->execute("DROP TABLE reviewed_analysis_issues"))&&bool(sql->execute("DROP TABLE project_preferences"))&&bool(sql->execute("PRAGMA user_version=3")),"v3 project fixture matches historical type, variable, and table shapes");sql.reset();
    auto v3_migrated_result=ProjectStore::open(path,ProjectMode::read_write,{});if(!v3_migrated_result)throw std::runtime_error("v3 migration: "+v3_migrated_result.error().message);migrated=std::move(v3_migrated_result.value());migrated.reset();
    sql=Connection::open(path,OpenMode::read_only,{}).value();version=sql->prepare("PRAGMA user_version").value();check(version->step().value() && version->integer(0).value()==current_project_schema_version,"v3 project migrates transactionally through the current schema");sql.reset();
    sql=Connection::open(path,OpenMode::read_write,{}).value();check(bool(sql->execute("DROP TABLE debug_variables"))&&bool(sql->execute("DROP TABLE collaboration_conflicts"))&&bool(sql->execute("DROP TABLE type_assignments"))&&bool(sql->execute("DROP TABLE type_definitions"))&&bool(sql->execute("DROP TABLE project_breakpoints"))&&bool(sql->execute("DROP TABLE loader_diagnostics"))&&bool(sql->execute("DROP TABLE type_import_diagnostics"))&&bool(sql->execute("DROP TABLE reviewed_analysis_issues"))&&bool(sql->execute("DROP TABLE project_preferences"))&&bool(sql->execute("ALTER TABLE history DROP COLUMN created_unix_ms"))&&bool(sql->execute("PRAGMA user_version=1")),"v1 project fixture matches historical type, collaboration, and variable tables");sql.reset();
    auto legacy_readonly=ProjectStore::open(path,ProjectMode::read_only,{}).value();check(legacy_readonly->snapshot().value()->user->types.empty(),"v1 projects remain readable before writable migration");legacy_readonly.reset();
    migrated=ProjectStore::open(path,ProjectMode::read_write,{}).value();migrated.reset();
    sql=Connection::open(path,OpenMode::read_only,{}).value();version=sql->prepare("PRAGMA user_version").value();check(version->step().value() && version->integer(0).value()==current_project_schema_version,"v1 project migrates transactionally through the current schema");sql.reset();
    sql=Connection::open(path,OpenMode::read_write,{}).value();check(bool(sql->execute("PRAGMA application_id=42")),"foreign project fixture created");sql.reset();
    check(!ProjectStore::open(path,ProjectMode::read_write,{}),"wrong application identifier rejected");
}
void corrupt_schema_tests(){
    const std::vector<std::string> corruptions{
        "DROP TABLE bookmarks",
        "CREATE VIEW unexpected AS SELECT 1",
        "UPDATE project SET recipe=x'010063'",
        "UPDATE project SET next_entity=x'0000000000000000'",
        "INSERT INTO annotations VALUES(x'0000000000000001',x'00fffffffffffffffffffffff0','bad\nname','')",
        "INSERT INTO annotations VALUES(x'0000000000000000',x'010000000000000001','','invalid id')",
        "INSERT INTO bookmarks VALUES(x'0000000000000001',x'070000000000000001','unknown domain')"
    };
    for(const auto& corruption:corruptions){
        FixtureFile marker({});auto path=marker.path;path+=L".hxproj";
        auto store=ProjectStore::create(path,{}).value();store.reset();
        auto sql=Connection::open(path,OpenMode::read_write,{}).value();check(bool(sql->execute(corruption)),"malformed fixture constructed independently");sql.reset();
        const auto before=hash_source(*FileStorage::open(path).value(),{}).value();
        check(!ProjectStore::open(path,ProjectMode::read_write,{}),"invalid project rejected before writable open");
        check(hash_source(*FileStorage::open(path).value(),{}).value()==before,"rejected malformed project remains byte identical");
        std::error_code ignored;std::filesystem::remove(path,ignored);auto wal=path;wal+=L"-wal";std::filesystem::remove(wal,ignored);auto shm=path;shm+=L"-shm";std::filesystem::remove(shm,ignored);
    }
    FixtureFile marker({});auto path=marker.path;path+=L".integrity.hxproj";
    auto store=ProjectStore::create(path,{}).value();store.reset();
    auto sql=Connection::open(path,OpenMode::read_write,{}).value();
    check(bool(sql->execute("PRAGMA ignore_check_constraints=ON")) &&
          bool(sql->execute("INSERT INTO history(step,group_id,byte_change,decision_change) VALUES(x'0000000000000001',x'0000000000000001',0,0)")) &&
              bool(sql->execute("INSERT INTO history_payload VALUES(x'0000000000000001',0,0,zeroblob(1048577))")),
          "fixture injects an oversized history payload while checks are disabled");
    sql.reset();
    const auto before=hash_source(*FileStorage::open(path).value(),{}).value();
    auto invalid=ProjectStore::open(path,ProjectMode::read_only,{});
    check(!invalid && invalid.error().code==ErrorCode::integrity,
          "SQLite integrity check rejects a persisted CHECK-constraint violation");
    check(hash_source(*FileStorage::open(path).value(),{}).value()==before,
          "integrity rejection leaves the corrupt project byte-identical");
    std::error_code ignored;std::filesystem::remove(path,ignored);auto wal=path;wal+=L"-wal";std::filesystem::remove(wal,ignored);auto shm=path;shm+=L"-shm";std::filesystem::remove(shm,ignored);
}
int main(){return run([]{codec_tests();schema_tests();corrupt_schema_tests();});}


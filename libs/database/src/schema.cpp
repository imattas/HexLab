#include "project_internal.hpp"
#include "testing.hpp"
#include <map>
#include <set>
namespace hexlab::database::detail {
namespace {
constexpr const char* statements[]={
    "CREATE TABLE project(singleton INTEGER PRIMARY KEY CHECK(singleton=1),uuid BLOB NOT NULL CHECK(typeof(uuid)='blob' AND length(uuid)=16),recipe BLOB NOT NULL,input_size BLOB NOT NULL CHECK(length(input_size)=8),input_sha256 BLOB NOT NULL CHECK(length(input_sha256)=32),edit_revision BLOB NOT NULL CHECK(length(edit_revision)=8),byte_revision BLOB NOT NULL CHECK(length(byte_revision)=8),history_cursor BLOB NOT NULL CHECK(length(history_cursor)=8),next_entity BLOB NOT NULL CHECK(length(next_entity)=8),decision_revision BLOB NOT NULL CHECK(length(decision_revision)=8))",
    "CREATE TABLE annotations(id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=8),location BLOB UNIQUE NOT NULL CHECK(length(location) IN(9,13)),name TEXT NOT NULL CHECK(length(CAST(name AS BLOB))<=512),comment TEXT NOT NULL CHECK(length(CAST(comment AS BLOB))<=1048576))",
    "CREATE UNIQUE INDEX annotation_names ON annotations(substr(location,2,4),name COLLATE BINARY) WHERE length(name)>0 AND substr(location,1,1)=x'00'",
    "CREATE TABLE bookmarks(id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=8),location BLOB UNIQUE NOT NULL CHECK(length(location) IN(9,13)),label TEXT NOT NULL CHECK(length(CAST(label AS BLOB))<=512))",
    "CREATE TABLE regions(id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=8),begin BLOB NOT NULL CHECK(length(begin)=13),size BLOB NOT NULL CHECK(length(size)=8),kind INTEGER NOT NULL CHECK(kind IN(0,1)))",
    "CREATE TABLE functions(id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=8),entry BLOB UNIQUE NOT NULL CHECK(length(entry)=13),suppressed INTEGER NOT NULL CHECK(suppressed IN(0,1)))",
    "CREATE TABLE function_chunks(function_id BLOB NOT NULL REFERENCES functions(id) ON DELETE CASCADE,ordinal INTEGER NOT NULL CHECK(ordinal>=0),begin BLOB NOT NULL CHECK(length(begin)=13),size BLOB NOT NULL CHECK(length(size)=8),PRIMARY KEY(function_id,ordinal))",
    "CREATE TABLE explicit_references(id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=8),source BLOB NOT NULL CHECK(length(source) IN(9,13)),target BLOB NOT NULL CHECK(length(target) IN(9,13)),kind INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 6))",
    "CREATE TABLE patches(begin BLOB PRIMARY KEY NOT NULL CHECK(length(begin)=8),original BLOB NOT NULL CHECK(length(original) BETWEEN 1 AND 1048576),replacement BLOB NOT NULL CHECK(length(replacement)=length(original)))",
    "CREATE TABLE input_chunks(position BLOB PRIMARY KEY NOT NULL CHECK(length(position)=8),data BLOB NOT NULL CHECK(length(data) BETWEEN 1 AND 1048576))",
    "CREATE TABLE input_provenance(singleton INTEGER PRIMARY KEY CHECK(singleton=1),encoding INTEGER NOT NULL,native_path BLOB NOT NULL,relative_path TEXT NOT NULL)",
    "CREATE TABLE history(step BLOB PRIMARY KEY NOT NULL CHECK(length(step)=8),group_id BLOB NOT NULL CHECK(length(group_id)=8),byte_change INTEGER NOT NULL CHECK(byte_change IN(0,1)),decision_change INTEGER NOT NULL CHECK(decision_change IN(0,1)),created_unix_ms BLOB CHECK(created_unix_ms IS NULL OR length(created_unix_ms)=8))",
    "CREATE TABLE history_payload(step BLOB NOT NULL REFERENCES history(step) ON DELETE CASCADE,side INTEGER NOT NULL CHECK(side IN(0,1)),ordinal INTEGER NOT NULL CHECK(ordinal>=0),data BLOB NOT NULL CHECK(length(data) BETWEEN 1 AND 1048576),PRIMARY KEY(step,side,ordinal))",
    "CREATE TABLE derived_cache(cache_key BLOB PRIMARY KEY NOT NULL,kind INTEGER NOT NULL,engine_version INTEGER NOT NULL,payload BLOB NOT NULL CHECK(length(payload)<=67108864))",
    "CREATE TABLE type_definitions(id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=8),name TEXT UNIQUE NOT NULL CHECK(length(CAST(name AS BLOB)) BETWEEN 1 AND 512),payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 16777216),source_id TEXT,source_section TEXT,unit_offset BLOB CHECK(unit_offset IS NULL OR length(unit_offset)=8),record_offset BLOB CHECK(record_offset IS NULL OR length(record_offset)=8),record_size BLOB CHECK(record_size IS NULL OR length(record_size)=8),declaration_kind INTEGER NOT NULL DEFAULT 0 CHECK(declaration_kind BETWEEN 0 AND 2),CHECK((source_id IS NULL AND source_section IS NULL AND unit_offset IS NULL AND record_offset IS NULL AND record_size IS NULL) OR (source_id IS NOT NULL AND source_section IS NOT NULL AND unit_offset IS NOT NULL AND record_offset IS NOT NULL AND record_size IS NOT NULL)))",
    "CREATE TABLE type_assignments(id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=8),location BLOB UNIQUE NOT NULL CHECK(length(location)=13),type_id BLOB NOT NULL REFERENCES type_definitions(id) ON DELETE CASCADE CHECK(length(type_id)=8))",
    "CREATE TABLE collaboration_conflicts(id INTEGER PRIMARY KEY AUTOINCREMENT,base_revision BLOB NOT NULL CHECK(length(base_revision)=8),observed_revision BLOB NOT NULL CHECK(length(observed_revision)=8),proposal BLOB NOT NULL CHECK(length(proposal) BETWEEN 1 AND 67108864),resolved INTEGER NOT NULL DEFAULT 0 CHECK(resolved IN(0,1)),accepted INTEGER NOT NULL DEFAULT 0 CHECK(accepted IN(0,1)),resolution_revision BLOB CHECK(resolution_revision IS NULL OR length(resolution_revision)=8))",
    "CREATE TABLE debug_variables(id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=8),function_entry BLOB NOT NULL CHECK(length(function_entry)=13),name TEXT NOT NULL CHECK(length(CAST(name AS BLOB)) BETWEEN 1 AND 1024),type_id BLOB REFERENCES type_definitions(id) ON DELETE SET NULL CHECK(type_id IS NULL OR length(type_id)=8),is_parameter INTEGER NOT NULL CHECK(is_parameter IN(0,1)),scope_offset BLOB NOT NULL CHECK(length(scope_offset)=8),address BLOB CHECK(address IS NULL OR length(address)=8),location_expression BLOB NOT NULL CHECK(length(location_expression)<=65536),location_operations BLOB NOT NULL CHECK(length(location_operations)<=262144),source_id TEXT NOT NULL CHECK(length(CAST(source_id AS BLOB)) BETWEEN 1 AND 1024),source_section TEXT NOT NULL CHECK(length(CAST(source_section AS BLOB)) BETWEEN 1 AND 256),unit_offset BLOB NOT NULL CHECK(length(unit_offset)=8),record_offset BLOB NOT NULL CHECK(length(record_offset)=8),record_size BLOB NOT NULL CHECK(length(record_size)=8),cfa_offset BLOB CHECK(cfa_offset IS NULL OR length(cfa_offset)=8),location_ranges BLOB NOT NULL DEFAULT X'' CHECK(length(location_ranges)<=1048576),UNIQUE(source_id,source_section,unit_offset,record_offset))",
    "CREATE TABLE project_breakpoints(id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=8),address BLOB UNIQUE NOT NULL CHECK(length(address)=13),kind INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 5),enabled INTEGER NOT NULL CHECK(enabled IN(0,1)),size INTEGER NOT NULL CHECK(size BETWEEN 1 AND 8),condition TEXT NOT NULL DEFAULT '' CHECK(length(CAST(condition AS BLOB))<=256),logpoint INTEGER NOT NULL DEFAULT 0 CHECK(logpoint IN(0,1)),log_message TEXT NOT NULL DEFAULT '' CHECK(length(CAST(log_message AS BLOB))<=1024),ignore_count BLOB NOT NULL DEFAULT X'0000000000000000' CHECK(length(ignore_count)=8),hit_count BLOB NOT NULL DEFAULT X'0000000000000000' CHECK(length(hit_count)=8),one_shot INTEGER NOT NULL DEFAULT 0 CHECK(one_shot IN(0,1)))",
    "CREATE TABLE loader_diagnostics(source INTEGER NOT NULL CHECK(source IN(0,1)),ordinal INTEGER NOT NULL CHECK(ordinal>=0),severity INTEGER NOT NULL CHECK(severity BETWEEN 0 AND 2),location BLOB CHECK(location IS NULL OR length(location) IN(9,13)),message TEXT NOT NULL CHECK(length(CAST(message AS BLOB))<=65536),PRIMARY KEY(source,ordinal))",
    "CREATE TABLE type_import_diagnostics(ordinal INTEGER PRIMARY KEY CHECK(ordinal>=0),source TEXT NOT NULL CHECK(length(CAST(source AS BLOB)) BETWEEN 1 AND 4096),severity INTEGER NOT NULL CHECK(severity BETWEEN 0 AND 2),location BLOB CHECK(location IS NULL OR length(location)=13),function_entry BLOB CHECK(function_entry IS NULL OR length(function_entry)=13),message TEXT NOT NULL CHECK(length(CAST(message AS BLOB))<=65536),analysis_key BLOB CHECK(analysis_key IS NULL OR length(analysis_key)=120))",
    "CREATE TABLE reviewed_analysis_issues(issue_key BLOB PRIMARY KEY NOT NULL CHECK(length(issue_key) BETWEEN 1 AND 131072))",
    "CREATE TABLE project_preferences(key TEXT PRIMARY KEY NOT NULL CHECK(length(CAST(key AS BLOB)) BETWEEN 1 AND 128),value TEXT NOT NULL CHECK(length(CAST(value AS BLOB))<=16384))"
};
const std::map<std::string,std::vector<std::pair<std::string,std::string>>> shapes={
    {"project",{{"singleton","INTEGER"},{"uuid","BLOB"},{"recipe","BLOB"},{"input_size","BLOB"},{"input_sha256","BLOB"},{"edit_revision","BLOB"},{"byte_revision","BLOB"},{"history_cursor","BLOB"},{"next_entity","BLOB"},{"decision_revision","BLOB"}}},
    {"annotations",{{"id","BLOB"},{"location","BLOB"},{"name","TEXT"},{"comment","TEXT"}}},
    {"bookmarks",{{"id","BLOB"},{"location","BLOB"},{"label","TEXT"}}},
    {"regions",{{"id","BLOB"},{"begin","BLOB"},{"size","BLOB"},{"kind","INTEGER"}}},
    {"functions",{{"id","BLOB"},{"entry","BLOB"},{"suppressed","INTEGER"}}},
    {"function_chunks",{{"function_id","BLOB"},{"ordinal","INTEGER"},{"begin","BLOB"},{"size","BLOB"}}},
    {"explicit_references",{{"id","BLOB"},{"source","BLOB"},{"target","BLOB"},{"kind","INTEGER"}}},
    {"patches",{{"begin","BLOB"},{"original","BLOB"},{"replacement","BLOB"}}},
    {"input_chunks",{{"position","BLOB"},{"data","BLOB"}}},
    {"input_provenance",{{"singleton","INTEGER"},{"encoding","INTEGER"},{"native_path","BLOB"},{"relative_path","TEXT"}}},
    {"history",{{"step","BLOB"},{"group_id","BLOB"},{"byte_change","INTEGER"},{"decision_change","INTEGER"},{"created_unix_ms","BLOB"}}},
    {"history_payload",{{"step","BLOB"},{"side","INTEGER"},{"ordinal","INTEGER"},{"data","BLOB"}}},
    {"derived_cache",{{"cache_key","BLOB"},{"kind","INTEGER"},{"engine_version","INTEGER"},{"payload","BLOB"}}},
    {"type_definitions",{{"id","BLOB"},{"name","TEXT"},{"payload","BLOB"},{"source_id","TEXT"},{"source_section","TEXT"},{"unit_offset","BLOB"},{"record_offset","BLOB"},{"record_size","BLOB"},{"declaration_kind","INTEGER"}}},
    {"type_assignments",{{"id","BLOB"},{"location","BLOB"},{"type_id","BLOB"}}},
    {"collaboration_conflicts",{{"id","INTEGER"},{"base_revision","BLOB"},{"observed_revision","BLOB"},{"proposal","BLOB"},{"resolved","INTEGER"},{"accepted","INTEGER"},{"resolution_revision","BLOB"}}},
    {"debug_variables",{{"id","BLOB"},{"function_entry","BLOB"},{"name","TEXT"},{"type_id","BLOB"},{"is_parameter","INTEGER"},{"scope_offset","BLOB"},{"address","BLOB"},{"location_expression","BLOB"},{"location_operations","BLOB"},{"source_id","TEXT"},{"source_section","TEXT"},{"unit_offset","BLOB"},{"record_offset","BLOB"},{"record_size","BLOB"},{"cfa_offset","BLOB"},{"location_ranges","BLOB"}}},
    {"project_breakpoints",{{"id","BLOB"},{"address","BLOB"},{"kind","INTEGER"},{"enabled","INTEGER"},{"size","INTEGER"},{"condition","TEXT"},{"logpoint","INTEGER"},{"log_message","TEXT"},{"ignore_count","BLOB"},{"hit_count","BLOB"},{"one_shot","INTEGER"}}},
    {"loader_diagnostics",{{"source","INTEGER"},{"ordinal","INTEGER"},{"severity","INTEGER"},{"location","BLOB"},{"message","TEXT"}}},
    {"type_import_diagnostics",{{"ordinal","INTEGER"},{"source","TEXT"},{"severity","INTEGER"},{"location","BLOB"},{"function_entry","BLOB"},{"message","TEXT"},{"analysis_key","BLOB"}}},
    {"reviewed_analysis_issues",{{"issue_key","BLOB"}}},
    {"project_preferences",{{"key","TEXT"},{"value","TEXT"}}}
};
constexpr const char* legacy_type_definitions="CREATE TABLE type_definitions(id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=8),name TEXT UNIQUE NOT NULL CHECK(length(CAST(name AS BLOB)) BETWEEN 1 AND 512),payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 16777216))";
}
int schema_version(Connection& connection){
    auto app=take(connection.prepare("PRAGMA application_id"));require(take(app->step()) && take(app->integer(0))==0x48584c42,"File is not a HexLab project");app.reset();
    auto version=take(connection.prepare("PRAGMA user_version"));require(take(version->step()),"Project has no schema version");const auto value=take(version->integer(0));
    if(value>18)throw Failure{{ErrorCode::unsupported,"Project schema is newer than this HexLab build"}};
    require(value>=0,"Invalid project schema version");return static_cast<int>(value);
}
void validate_schema(Connection& connection,int version){
    std::set<std::string> seen;
    auto objects=take(connection.prepare("SELECT name,type FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"));
    while(take(objects->step())){
        const auto name=take(objects->text(0)),type=take(objects->text(1));
        if(type=="index"){require(name=="annotation_names","Unknown project index");continue;}
        require(type=="table" && shapes.contains(name),"Unknown project schema object");seen.insert(name);
    }
    const auto expected=(version>=4?shapes.size():(version==3?shapes.size()-1:(version==2?shapes.size()-2:shapes.size()-4)))-(version<9?1:0)-(version<12?1:0)-(version<13?1:0)-(version<14?1:0)-(version<16?1:0);
    require(seen.size()==expected,"Project is missing required tables");
    for(const auto& [table,columns]:shapes){
        if(version<2 && (table=="type_definitions" || table=="type_assignments"))continue;
        if(version<3 && table=="collaboration_conflicts")continue;
        if(version<4 && table=="debug_variables")continue;
        if(version<9 && table=="project_breakpoints")continue;
        if(version<12 && table=="loader_diagnostics")continue;
        if(version<13 && table=="type_import_diagnostics")continue;
        if(version<14 && table=="reviewed_analysis_issues")continue;
        if(version<16 && table=="project_preferences")continue;
        auto info=take(connection.prepare("PRAGMA table_info("+table+")"));size_t index=0;
        while(take(info->step())){require(index<columns.size(),"Unexpected project table column");const auto& expected_column=columns[index++];require(take(info->text(1))==expected_column.first && take(info->text(2))==expected_column.second,"Project column shape mismatch");}
        require(index==columns.size()-(version==0 && table=="project"?1:0)-(version<5 && table=="debug_variables"?1:0)-(version<6 && table=="debug_variables"?1:0)-(version<7 && table=="type_definitions"?5:0)-(version<8 && table=="type_definitions"?1:0)-(version==9 && table=="project_breakpoints"?5:0)-(version==10 && table=="project_breakpoints"?1:0)-(version<15 && table=="type_import_diagnostics"?1:0)-(version<17 && table=="project_breakpoints"?1:0)-(version<18 && table=="history"?1:0),"Project table has missing columns");
    }
    auto index=take(connection.prepare("SELECT sql FROM sqlite_schema WHERE name='annotation_names' AND type='index'"));
    require(take(index->step()) && take(index->text(0))==statements[2],"Name uniqueness index is missing or incompatible");
    auto foreign_keys=take(connection.prepare("PRAGMA foreign_key_check"));require(!take(foreign_keys->step()),"Project contains invalid foreign keys");
    auto integrity=take(connection.prepare("PRAGMA integrity_check(1)"));
    require(take(integrity->step()),"SQLite integrity check returned no result");
    if(take(integrity->text(0))!="ok")throw Failure{{ErrorCode::integrity,"Project database failed SQLite integrity check"}};
    require(!take(integrity->step()),"SQLite integrity check returned unexpected extra results");
    auto oversized_history=take(connection.prepare("SELECT 1 FROM history_payload WHERE length(data)>1048576 LIMIT 1"));
    require(!take(oversized_history->step()),"Project history payload exceeds its size limit");
}
void create_schema(Connection& connection,const ProjectState& state){
    for(const auto* sql:statements)take(connection.execute(sql));
    take(connection.execute("PRAGMA application_id=1213746242"));take(connection.execute("PRAGMA user_version=18"));
    auto header=take(connection.prepare("INSERT INTO project VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9)"));
    take(header->bind_blob(1,state.uuid));take(header->bind_blob(2,take(encode_recipe(state.recipe))));take(header->bind_blob(3,encode_u64(state.input.size)));take(header->bind_blob(4,state.input.sha256));
    take(header->bind_blob(5,encode_u64(state.revisions.edit)));take(header->bind_blob(6,encode_u64(state.revisions.bytes)));take(header->bind_blob(7,encode_u64(state.history_cursor)));take(header->bind_blob(8,encode_u64(state.next_entity)));take(header->bind_blob(9,encode_u64(state.revisions.decisions)));take(header->step());
}
void migrate_schema(Connection& connection){
    auto current=take(connection.prepare("PRAGMA user_version"));require(take(current->step()),"Missing schema version");auto version=take(current->integer(0));current.reset();
    if(version==0)take(connection.execute("ALTER TABLE project ADD COLUMN decision_revision BLOB NOT NULL DEFAULT X'0000000000000000' CHECK(length(decision_revision)=8)"));
#ifdef HEXLAB_DATABASE_TESTING
    testing::migration_checkpoint();
#endif
    if(version==0)take(connection.execute("PRAGMA user_version=1"));
    if(version<2){take(connection.execute(legacy_type_definitions));take(connection.execute(statements[15]));take(connection.execute("PRAGMA user_version=2"));version=2;}
    if(version<3){take(connection.execute(statements[16]));take(connection.execute("PRAGMA user_version=3"));}
    if(version<4){take(connection.execute(statements[17]));take(connection.execute("PRAGMA user_version=4"));}
    if(version==4){take(connection.execute("ALTER TABLE debug_variables ADD COLUMN cfa_offset BLOB CHECK(cfa_offset IS NULL OR length(cfa_offset)=8)"));take(connection.execute("PRAGMA user_version=5"));}
    if(version<4)take(connection.execute("PRAGMA user_version=5"));
    bool has_ranges=false;auto columns=take(connection.prepare("PRAGMA table_info(debug_variables)"));while(take(columns->step()))if(take(columns->text(1))=="location_ranges")has_ranges=true;
    if(!has_ranges)take(connection.execute("ALTER TABLE debug_variables ADD COLUMN location_ranges BLOB NOT NULL DEFAULT X'' CHECK(length(location_ranges)<=1048576)"));
    take(connection.execute("PRAGMA user_version=6"));
    if(version<7){
        take(connection.execute("ALTER TABLE type_definitions ADD COLUMN source_id TEXT"));
        take(connection.execute("ALTER TABLE type_definitions ADD COLUMN source_section TEXT"));
        take(connection.execute("ALTER TABLE type_definitions ADD COLUMN unit_offset BLOB CHECK(unit_offset IS NULL OR length(unit_offset)=8)"));
        take(connection.execute("ALTER TABLE type_definitions ADD COLUMN record_offset BLOB CHECK(record_offset IS NULL OR length(record_offset)=8)"));
        take(connection.execute("ALTER TABLE type_definitions ADD COLUMN record_size BLOB CHECK(record_size IS NULL OR length(record_size)=8)"));
        take(connection.execute("PRAGMA user_version=7"));
    }
    if(version<8)take(connection.execute("ALTER TABLE type_definitions ADD COLUMN declaration_kind INTEGER NOT NULL DEFAULT 0 CHECK(declaration_kind BETWEEN 0 AND 2)"));
    if(version<9){
        take(connection.execute("CREATE TABLE project_breakpoints(id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=8),address BLOB UNIQUE NOT NULL CHECK(length(address)=13),kind INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 5),enabled INTEGER NOT NULL CHECK(enabled IN(0,1)),size INTEGER NOT NULL CHECK(size BETWEEN 1 AND 8))"));
        take(connection.execute("PRAGMA user_version=9"));version=9;
    }
    if(version<10){
        take(connection.execute("ALTER TABLE project_breakpoints ADD COLUMN condition TEXT NOT NULL DEFAULT '' CHECK(length(CAST(condition AS BLOB))<=256)"));
        take(connection.execute("ALTER TABLE project_breakpoints ADD COLUMN logpoint INTEGER NOT NULL DEFAULT 0 CHECK(logpoint IN(0,1))"));
        take(connection.execute("ALTER TABLE project_breakpoints ADD COLUMN log_message TEXT NOT NULL DEFAULT '' CHECK(length(CAST(log_message AS BLOB))<=1024)"));
        take(connection.execute("ALTER TABLE project_breakpoints ADD COLUMN ignore_count BLOB NOT NULL DEFAULT X'0000000000000000' CHECK(length(ignore_count)=8)"));
        take(connection.execute("PRAGMA user_version=10"));
        version=10;
    }
    if(version<11){
        take(connection.execute("ALTER TABLE project_breakpoints ADD COLUMN hit_count BLOB NOT NULL DEFAULT X'0000000000000000' CHECK(length(hit_count)=8)"));
        take(connection.execute("PRAGMA user_version=11"));
    }
    if(version<12){take(connection.execute(statements[20]));take(connection.execute("PRAGMA user_version=12"));}
    if(version<13){take(connection.execute(statements[21]));take(connection.execute("PRAGMA user_version=13"));}
    if(version<14){take(connection.execute(statements[22]));take(connection.execute("PRAGMA user_version=14"));version=14;}
    if(version<15){
        take(connection.execute("ALTER TABLE type_import_diagnostics ADD COLUMN analysis_key BLOB CHECK(analysis_key IS NULL OR length(analysis_key)=120)"));
        take(connection.execute("PRAGMA user_version=15"));
        version=15;
    }
    if(version<16){take(connection.execute(statements[23]));take(connection.execute("PRAGMA user_version=16"));}
    if(version<17){take(connection.execute("ALTER TABLE project_breakpoints ADD COLUMN one_shot INTEGER NOT NULL DEFAULT 0 CHECK(one_shot IN(0,1))"));take(connection.execute("PRAGMA user_version=17"));}
    if(version<18){
        take(connection.execute("ALTER TABLE history ADD COLUMN created_unix_ms BLOB CHECK(created_unix_ms IS NULL OR length(created_unix_ms)=8)"));
        take(connection.execute("PRAGMA user_version=18"));
    }
}
}

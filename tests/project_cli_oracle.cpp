#include <sqlite3.h>
#include "support/test_entrypoint.hpp"
#include "hexlab/core/sha256.hpp"
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
namespace {
std::string scalar(sqlite3* db,const char* sql){
    sqlite3_stmt* raw=nullptr;if(sqlite3_prepare_v2(db,sql,-1,&raw,nullptr)!=SQLITE_OK)throw std::runtime_error(sqlite3_errmsg(db));std::unique_ptr<sqlite3_stmt,decltype(&sqlite3_finalize)> statement(raw,sqlite3_finalize);if(sqlite3_step(raw)!=SQLITE_ROW)throw std::runtime_error("Oracle query has no row");auto text=sqlite3_column_text(raw,0);auto size=sqlite3_column_bytes(raw,0);std::string result(reinterpret_cast<const char*>(text),std::size_t(size));if(sqlite3_step(raw)!=SQLITE_DONE)throw std::runtime_error("Oracle query is not scalar");return result;
}
void expected(sqlite3* db,const char* sql,std::string_view value){if(auto actual=scalar(db,sql);actual!=value)throw std::runtime_error(std::string("Literal SQL oracle mismatch: ")+sql+" -> "+actual);}
}
int HEXLAB_TEST_MAIN(int argc,hexlab_test_arg_char** argv){
    try{
        if(argc!=3)return 2;auto encoded=hexlab_test_path(argv[2]).u8string();sqlite3* raw=nullptr;int status=sqlite3_open_v2(reinterpret_cast<const char*>(encoded.c_str()),&raw,SQLITE_OPEN_READONLY|SQLITE_OPEN_NOMUTEX,nullptr);std::unique_ptr<sqlite3,decltype(&sqlite3_close)> db(raw,sqlite3_close);if(status!=SQLITE_OK)throw std::runtime_error(raw?sqlite3_errmsg(raw):"Oracle cannot open SQL input");sqlite3_busy_timeout(raw,2000);
        if(hexlab_test_arg_equals(argv[1],"verify")){
            expected(raw,"SELECT hex(edit_revision)||'|'||hex(byte_revision)||'|'||hex(decision_revision)||'|'||hex(history_cursor) FROM project","0000000000000007|0000000000000003|0000000000000001|0000000000000005");
            expected(raw,"SELECT count(*) FROM annotations","2");expected(raw,"SELECT name FROM annotations WHERE length(name)>0","entry_name");expected(raw,"SELECT hex(comment) FROM annotations WHERE length(comment)>0","6C696E65310A6C696E6532");expected(raw,"SELECT hex(location) FROM annotations WHERE length(name)>0","00000000000000000000001000");expected(raw,"SELECT label FROM bookmarks","return_here");expected(raw,"SELECT hex(original)||'|'||hex(replacement) FROM patches","90|CC");expected(raw,"SELECT hex(data) FROM input_chunks","90C348454C4C4F00");expected(raw,"SELECT count(*) FROM explicit_references","1");expected(raw,"PRAGMA integrity_check","ok");std::cout<<"Independent SQL oracle passed\n";
        }else if(hexlab_test_arg_equals(argv[1],"digest")){
            sqlite3_int64 count=0;auto bytes=sqlite3_serialize(raw,"main",&count,0);if(!bytes || count<0)throw std::runtime_error("Cannot serialize independent SQL snapshot");std::unique_ptr<unsigned char,decltype(&sqlite3_free)> owner(bytes,sqlite3_free);hexlab::Sha256 hash;auto result=hash.update({reinterpret_cast<const std::byte*>(bytes),std::size_t(count)});if(!result)throw std::runtime_error(result.error().message);std::cout<<hexlab::digest_hex(hash.digest())<<'\n';
        }else return 2;return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}

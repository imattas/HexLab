#include "hexlab/database/connection.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include <chrono>
#include <thread>
using namespace hexlab;
using namespace hexlab::database;
using namespace hexlab_test;
int main(){return run([]{
    const auto info=database_build_info();check(info.version=="3.54.1" && info.threadsafe && !info.load_extensions,"pinned thread safe runtime without extension loading");
    FixtureFile marker({});auto path=marker.path;path+=L"-\u9879\u76ee-\u00e9.hxl";
    struct Cleanup {std::filesystem::path path;~Cleanup(){std::error_code ec;std::filesystem::remove(path,ec);auto wal=path;wal+=L"-wal";std::filesystem::remove(wal,ec);auto shm=path;shm+=L"-shm";std::filesystem::remove(shm,ec);}} cleanup{path};
    auto connection=Connection::open(path,OpenMode::create,{});check(bool(connection),"Unicode native database path opens");if(!connection)return;
    auto& db=*connection.value();
    auto journal=db.prepare("PRAGMA journal_mode").value();check(journal->step().value() && journal->text(0).value()=="wal","WAL is active");journal.reset();
    auto fk=db.prepare("PRAGMA foreign_keys").value();check(fk->step().value() && fk->integer(0).value()==1,"foreign keys active");fk.reset();
    auto sync=db.prepare("PRAGMA synchronous").value();check(sync->step().value() && sync->integer(0).value()==2,"FULL synchronous active");sync.reset();
    check(bool(db.execute("CREATE TABLE facts(id INTEGER PRIMARY KEY, name TEXT UNIQUE, value BLOB)")),"schema creation succeeds");
    auto insert=db.prepare("INSERT INTO facts VALUES(?1,?2,?3)").value();std::string hostile="quote'; DROP TABLE facts;--\n\xc3\xa9";hostile.push_back('\0');hostile+="tail";const auto blob=bytes({0,255,0,128});
    check(bool(insert->bind_integer(1,1)) && bool(insert->bind_text(2,hostile)) && bool(insert->bind_blob(3,blob)) && !insert->step().value(),"bound hostile text and binary data insert literally");insert.reset();
    auto select=db.prepare("SELECT name,value FROM facts WHERE id=?1").value();check(bool(select->bind_integer(1,1)) && select->step().value() && select->text(0).value()==hostile && select->blob(1).value()==blob,"prepared values round trip");select.reset();
    {auto transaction=Transaction::begin(db).value();check(bool(db.execute("INSERT INTO facts VALUES(2,'temporary',x'')")),"transaction can stage changes");check(!db.execute("INSERT INTO facts VALUES(1,'duplicate',x'')"),"constraint error returned");}
    auto count=db.prepare("SELECT count(*) FROM facts").value();check(count->step().value() && count->integer(0).value()==1,"failed uncommitted transaction rolls back on scope exit");count.reset();
    auto second=Connection::open(path,OpenMode::read_write,{}).value();
    {auto lock=Transaction::begin(db).value();const auto start=std::chrono::steady_clock::now();auto busy=second->execute("INSERT INTO facts VALUES(3,'busy',x'')");check(!busy && busy.error().code==ErrorCode::busy,"competing writer reports busy");check(std::chrono::steady_clock::now()-start>=std::chrono::milliseconds(1800),"configured busy timeout is honored");}
    auto readonly=Connection::open(path,OpenMode::read_only,{}).value();auto denied=readonly->execute("DELETE FROM facts");check(!denied && denied.error().code==ErrorCode::read_only,"readonly connection cannot mutate");
    check(!db.execute("SELECT load_extension('missing')"),"load_extension unavailable in runtime");
    std::stop_source stop;auto canceled=Connection::open(path,OpenMode::read_write,stop.get_token()).value();
    {
        auto transaction=Transaction::begin(*canceled).value();check(bool(canceled->execute("INSERT INTO facts VALUES(4,'canceled',x'')")),"canceled transaction stages a change first");
        std::jthread interrupter([&]{std::this_thread::sleep_for(std::chrono::milliseconds(20));stop.request_stop();});
        auto interrupted=canceled->execute("WITH RECURSIVE n(x) AS(VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<1000000000) SELECT sum(x) FROM n");check(!interrupted && interrupted.error().code==ErrorCode::canceled,"progress handler interrupts an executing query");
    }
    auto durable=db.prepare("SELECT count(*) FROM facts").value();check(durable->step().value() && durable->integer(0).value()==1,"rollback succeeds even after cancellation");durable.reset();
    auto retained=Connection::open(path,OpenMode::read_only,{}).value()->prepare("SELECT 7").value();check(retained->step().value() && retained->integer(0).value()==7 && !retained->step().value() && !retained->step().value(),"statement retains connection and end does not rerun SQL");
    check(!db.prepare("SELECT 1; DELETE FROM facts"),"multiple statements rejected at prepared boundary");
});}

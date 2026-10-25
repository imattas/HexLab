#include "hexlab/workspace/project.hpp"
#include "tests/support/macho_symbol_fixture.hpp"
#include <fstream>
#include <iostream>
using namespace hexlab;
template<class T>T take(Result<T> r){if(!r)throw std::runtime_error(r.error().message);return std::move(r.value());}
int wmain(int argc,wchar_t**argv){try{
 if(argc!=2)return 2;const std::filesystem::path root(argv[1]);
 const auto path=root/"input.o",project=root/"producer.hxproj";
 if(std::filesystem::exists(project))throw std::runtime_error("Capture already exists; never replace historical payload");
 const auto bytes=hexlab_test::macho_fixture::symbols(true);
 {std::ofstream out(path,std::ios::binary);out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());if(!out)throw std::runtime_error("source write");}
 auto source=take(FileStorage::open(path));auto store=take(database::ProjectStore::create(project,{}));
 auto recipe=take(resolve_load_recipe(*source,{Format::macho,{},{}},{}));take(store->import_input(*source,recipe,path,{}));
 auto session=take(ProjectSession::attach(store,{},{}));auto snapshot=take(session->refresh_analysis({}));
 if(!snapshot->derived_key||!snapshot->functions)throw std::runtime_error("Missing real derived analysis");
 const auto raw=take(store->read_derived_cache(*snapshot->derived_key,{}));
 if(raw.status!=database::CacheStatus::hit||!raw.payload)throw std::runtime_error("No actual stored payload");
 {std::ofstream out(root/"derived_v5_macho_v13.hxdc",std::ios::binary);out.write(reinterpret_cast<const char*>(raw.payload->data()),raw.payload->size());if(!out)throw std::runtime_error("payload write");}
 std::cout<<"engine_sha256="<<digest_hex(snapshot->derived_key->engine_fingerprint)<<"\nsource_sha256="<<digest_hex(snapshot->state->input.sha256)<<"\npayload_bytes="<<raw.payload->size()<<"\nfunctions="<<snapshot->functions->functions.size()<<"\n";
 return 0;
 }catch(const std::exception&e){std::cerr<<e.what()<<"\n";return 1;}}

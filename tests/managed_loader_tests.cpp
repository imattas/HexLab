#include "hexlab/loaders/managed.hpp"
#include "hexlab/loaders/loaded_image.hpp"
#include "hexlab/loaders/cil.hpp"
#include "support/analysis_fixture.hpp"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string_view>
#include <vector>
using namespace hexlab;
#define CHECK(expr) do { if (!(expr)) { std::cerr << "CHECK failed at line " << __LINE__ << ": " #expr << std::endl; return 1; } } while (false)
static void u16(std::vector<std::byte>& b,std::uint16_t v){b.push_back(std::byte(v));b.push_back(std::byte(v>>8));}
static void u32(std::vector<std::byte>& b,std::uint32_t v){for(int i=0;i<4;++i)b.push_back(std::byte(v>>(8*i)));}
static void u64(std::vector<std::byte>& b,std::uint64_t v){for(int i=0;i<8;++i)b.push_back(std::byte(v>>(8*i)));}
static void put32(std::vector<std::byte>& b,std::size_t p,std::uint32_t v){for(int i=0;i<4;++i)b[p+i]=std::byte(v>>(8*i));}
static void append(std::vector<std::byte>& a,const std::vector<std::byte>& b){a.insert(a.end(),b.begin(),b.end());}
static std::vector<std::byte> minimal_metadata(){
  std::vector<std::byte> strings{std::byte{0},std::byte{'M'},std::byte{'o'},std::byte{'d'},std::byte{0}};
  std::vector<std::byte> tables;u32(tables,0);tables.push_back(std::byte{2});tables.push_back(std::byte{0});tables.push_back(std::byte{0});tables.push_back(std::byte{1});u64(tables,1);u64(tables,0);u32(tables,1);u16(tables,0);u16(tables,1);u16(tables,0);u16(tables,0);u16(tables,0);while(tables.size()%4)tables.push_back(std::byte{0});
  std::vector<std::byte> streams; // headers are patched below
  std::vector<std::byte> root;u32(root,0x424a5342);u16(root,1);u16(root,1);u32(root,0);u32(root,4);append(root,{std::byte{'v'},std::byte{'4'},std::byte{0},std::byte{0}});while(root.size()%4)root.push_back(std::byte{0});u16(root,0);u16(root,2);
  auto add_header=[&](std::uint32_t off,std::uint32_t size,const char* n){u32(root,off);u32(root,size);while(*n)root.push_back(std::byte(*n++));root.push_back(std::byte{0});while(root.size()%4)root.push_back(std::byte{0});};
  const std::size_t header_start=root.size();add_header(0,static_cast<std::uint32_t>(tables.size()),"#~");add_header(0,static_cast<std::uint32_t>(strings.size()),"#Strings");
  const auto data_start=root.size();const auto table_off=static_cast<std::uint32_t>(data_start);const auto string_off=table_off+static_cast<std::uint32_t>(tables.size());
  auto patch32=[&](std::size_t p,std::uint32_t v){for(int i=0;i<4;++i)root[p+i]=std::byte(v>>(8*i));};
  patch32(header_start,table_off);patch32(header_start+4,static_cast<std::uint32_t>(tables.size()));
  const auto second=header_start+12;patch32(second,string_off);patch32(second+4,static_cast<std::uint32_t>(strings.size()));
  (void)streams;append(root,tables);append(root,strings);return root;
}
static std::vector<std::byte> metadata_with_method(){
  std::vector<std::byte> strings{std::byte{0},std::byte{'R'},std::byte{'u'},std::byte{'n'},std::byte{0},std::byte{'A'},std::byte{'b'},std::byte{'s'},std::byte{'t'},std::byte{'r'},std::byte{'a'},std::byte{'c'},std::byte{'t'},std::byte{0},std::byte{'B'},std::byte{'a'},std::byte{'d'},std::byte{0},std::byte{'T'},std::byte{0},std::byte{'D'},std::byte{'e'},std::byte{'m'},std::byte{'o'},std::byte{0}};
  while(strings.size()%4)strings.push_back(std::byte{0});
  std::vector<std::byte> blob{std::byte{0},std::byte{3},std::byte{0},std::byte{0},std::byte{1}};while(blob.size()%4)blob.push_back(std::byte{0});blob.push_back(std::byte{3});blob.push_back(std::byte{0});blob.push_back(std::byte{0});blob.push_back(std::byte{8});
  std::vector<std::byte> tables;u32(tables,0);tables.push_back(std::byte{2});tables.push_back(std::byte{0});tables.push_back(std::byte{0});tables.push_back(std::byte{1});u64(tables,(1ull<<0)|(1ull<<1)|(1ull<<2)|(1ull<<6)|(1ull<<10));u64(tables,0);u32(tables,1);u32(tables,1);u32(tables,1);u32(tables,3);u32(tables,1);
  // Module row, one TypeDef row, and three MethodDef rows.
  u16(tables,0);u16(tables,0);u16(tables,0);u16(tables,0);u16(tables,0);
  u16(tables,0);u16(tables,18);u16(tables,20); // TypeRef row referenced by MemberRef
  u32(tables,0);u16(tables,18);u16(tables,20);u16(tables,0);u16(tables,1);u16(tables,1);
  u32(tables,0x200);u16(tables,0);u16(tables,0x16);u16(tables,1);u16(tables,1);u16(tables,1);
  u32(tables,0);u16(tables,0);u16(tables,0x0401);u16(tables,5);u16(tables,1);u16(tables,1);
  u32(tables,0x400);u16(tables,0);u16(tables,0x16);u16(tables,14);u16(tables,1);u16(tables,1);
  u16(tables,9);u16(tables,1);u16(tables,8); // MemberRef parent is TypeRef row 1 (three tag bits)
  while(tables.size()%4)tables.push_back(std::byte{0});
  std::vector<std::byte> root;u32(root,0x424a5342);u16(root,1);u16(root,1);u32(root,0);u32(root,4);append(root,{std::byte{'v'},std::byte{'4'},std::byte{0},std::byte{0}});while(root.size()%4)root.push_back(std::byte{0});u16(root,0);u16(root,3);
  auto add_header=[&](std::uint32_t off,std::uint32_t size,const char* n){u32(root,off);u32(root,size);while(*n)root.push_back(std::byte(*n++));root.push_back(std::byte{0});while(root.size()%4)root.push_back(std::byte{0});};
  const auto headers=root.size();add_header(0,static_cast<std::uint32_t>(tables.size()),"#~");const auto strings_header=root.size();add_header(0,static_cast<std::uint32_t>(strings.size()),"#Strings");const auto blob_header=root.size();add_header(0,static_cast<std::uint32_t>(blob.size()),"#Blob");
  const auto table_off=static_cast<std::uint32_t>(root.size());const auto string_off=table_off+static_cast<std::uint32_t>(tables.size());
  auto patch32=[&](std::size_t p,std::uint32_t v){for(int i=0;i<4;++i)root[p+i]=std::byte(v>>(8*i));};
  patch32(headers,table_off);patch32(headers+4,static_cast<std::uint32_t>(tables.size()));patch32(strings_header,string_off);patch32(strings_header+4,static_cast<std::uint32_t>(strings.size()));patch32(blob_header,string_off+static_cast<std::uint32_t>(strings.size()));patch32(blob_header+4,static_cast<std::uint32_t>(blob.size()));
  append(root,tables);append(root,strings);append(root,blob);return root;
}
static std::vector<std::byte> metadata_with_fields(bool use_field_pointers=false){
  std::vector<std::byte> strings{std::byte{0},std::byte{'A'},std::byte{0},std::byte{'B'},std::byte{0},std::byte{'f'},std::byte{0},std::byte{'g'},std::byte{0}};while(strings.size()%4)strings.push_back(std::byte{0});
  // A Field signature includes both the FIELD calling-convention byte and
  // the field type.  Use I4 after FIELD so the fixture is a valid ECMA-335
  // signature rather than a truncated prefix.
  std::vector<std::byte> blob{std::byte{0},std::byte{2},std::byte{0x06},std::byte{0x08}};
  std::vector<std::byte> tables;u32(tables,0);tables.push_back(std::byte{2});tables.push_back(std::byte{0});tables.push_back(std::byte{0});tables.push_back(std::byte{1});u64(tables,(1ull<<0)|(1ull<<2)|(1ull<<4)|(use_field_pointers?1ull<<3:0));u64(tables,0);u32(tables,1);u32(tables,2);if(use_field_pointers)u32(tables,2);u32(tables,2);
  for(int i=0;i<5;++i)u16(tables,0); // Module row
  u32(tables,0);u16(tables,1);u16(tables,0);u16(tables,0);u16(tables,1);u16(tables,1);
  u32(tables,0);u16(tables,3);u16(tables,0);u16(tables,0);u16(tables,2);u16(tables,1);
  if(use_field_pointers){u16(tables,2);u16(tables,1);}
  u16(tables,1);u16(tables,5);u16(tables,1);
  u16(tables,2);u16(tables,7);u16(tables,1);
  while(tables.size()%4)tables.push_back(std::byte{0});
  std::vector<std::byte> root;u32(root,0x424a5342);u16(root,1);u16(root,1);u32(root,0);u32(root,4);append(root,{std::byte{'v'},std::byte{'4'},std::byte{0},std::byte{0}});while(root.size()%4)root.push_back(std::byte{0});u16(root,0);u16(root,3);
  const auto headers=root.size();
  auto add_header=[&](std::uint32_t off,std::uint32_t size,const char* n){u32(root,off);u32(root,size);while(*n)root.push_back(std::byte(*n++));root.push_back(std::byte{0});while(root.size()%4)root.push_back(std::byte{0});};
  add_header(0,static_cast<std::uint32_t>(tables.size()),"#~");const auto strings_header=root.size();add_header(0,static_cast<std::uint32_t>(strings.size()),"#Strings");const auto blob_header=root.size();add_header(0,static_cast<std::uint32_t>(blob.size()),"#Blob");
  const auto table_off=static_cast<std::uint32_t>(root.size());auto patch=[&](std::size_t p,std::uint32_t v){for(int i=0;i<4;++i)root[p+i]=std::byte(v>>(8*i));};
  patch(headers,table_off);patch(strings_header,table_off+static_cast<std::uint32_t>(tables.size()));patch(blob_header,table_off+static_cast<std::uint32_t>(tables.size()+strings.size()));
  append(root,tables);append(root,strings);append(root,blob);return root;
}
int main(){
  const std::vector<std::byte> managed_call_sig{std::byte{0x20},std::byte{0x02},std::byte{0x01},std::byte{0x08},std::byte{0x0e}};
  auto decoded_sig=decode_managed_method_signature(managed_call_sig);CHECK(decoded_sig);CHECK(decoded_sig.value().parameter_count==2);CHECK(decoded_sig.value().has_this);CHECK(!decoded_sig.value().returns_value);
  const std::vector<std::byte> malformed_sig{std::byte{0x00},std::byte{0x01},std::byte{0x01}};CHECK(!decode_managed_method_signature(malformed_sig));
  const std::vector<std::byte> array_sig{std::byte{0x00},std::byte{0x01},std::byte{0x01},std::byte{0x1d},std::byte{0x08}};CHECK(decode_managed_method_signature(array_sig));
  const std::vector<std::byte> unsupported_sig{std::byte{0x00},std::byte{0x00},std::byte{0x1b}};auto unsupported_decoded=decode_managed_method_signature(unsupported_sig);CHECK(!unsupported_decoded);CHECK(unsupported_decoded.error().code==ErrorCode::unsupported);
  auto body=std::vector<std::byte>{std::byte{0x06},std::byte{0x2a}}; // tiny body: 1-byte ret
  auto parsed=parse_cil_method_body(body);CHECK(parsed);CHECK(parsed.value().code_size==1);CHECK(parsed.value().il[0]==std::byte{0x2a});
  auto md=minimal_metadata();auto metadata=parse_cli_metadata(md);if(!metadata)std::cerr<<metadata.error().message<<std::endl;CHECK(metadata);CHECK(metadata.value().streams.contains("#Strings"));CHECK(metadata.value().tables.row_counts[0]==1);CHECK(metadata.value().tables.row_sizes[0]==10);
  body[0]=std::byte{0x07};CHECK(!parse_cil_method_body(body));
  std::vector<std::byte> fat(16);fat[0]=std::byte{0x03};fat[1]=std::byte{0x30};fat[2]=std::byte{8};put32(fat,4,1);put32(fat,8,0x11000001);fat[12]=std::byte{0x2a};
  auto fat_body=parse_cil_method_body(fat);CHECK(fat_body);CHECK(fat_body.value().local_signature_token==0x11000001);CHECK(fat_body.value().il.size()==1);
  // Fat body with a small-format catch section: try IL_0, handler IL_1.
  std::vector<std::byte> eh_body(32);eh_body[0]=std::byte{0x0b};eh_body[1]=std::byte{0x30};put32(eh_body,4,2);eh_body[12]=std::byte{0x00};eh_body[13]=std::byte{0x2a};
  eh_body[16]=std::byte{0x01};eh_body[17]=std::byte{0x10};eh_body[20]=std::byte{0x00};eh_body[21]=std::byte{0x00};eh_body[22]=std::byte{0x00};eh_body[23]=std::byte{0x00};eh_body[24]=std::byte{0x01};eh_body[25]=std::byte{0x01};eh_body[27]=std::byte{0x01};put32(eh_body,28,0x01000001);
  auto eh_parsed=parse_cil_method_body(eh_body);CHECK(eh_parsed);CHECK(eh_parsed.value().has_more_sections);CHECK(eh_parsed.value().exception_clauses.size()==1);CHECK(eh_parsed.value().exception_clauses[0].kind==CilExceptionKind::catch_clause);CHECK(eh_parsed.value().exception_clauses[0].class_token==0x01000001);CHECK(eh_parsed.value().exception_clauses[0].try_length==1);CHECK(eh_parsed.value().exception_clauses[0].handler_offset==1);
  auto bad_eh=eh_body;bad_eh[22]=std::byte{2};CHECK(!parse_cil_method_body(bad_eh));
  auto input=std::vector<std::byte>(512);auto root=minimal_metadata();put32(input,0x20,72);input[0x24]=std::byte{2};input[0x26]=std::byte{5};put32(input,0x28,0x80);put32(input,0x2c,static_cast<std::uint32_t>(root.size()));put32(input,0x30,1);put32(input,0x34,0x06000001);std::copy(root.begin(),root.end(),input.begin()+0x80);
  LoadedImage loaded;loaded.image=hexlab_test::memory_image(input);loaded.metadata.format="PE32+";loaded.metadata.pe.emplace();loaded.metadata.preferred_base=0x1000;loaded.metadata.directories.push_back({14,0x20,72,false});
  auto managed=parse_managed_pe(loaded);CHECK(managed);CHECK(managed.value().major==2);CHECK(managed.value().entry_point_token==0x06000001);
  auto method_input=std::vector<std::byte>(1536);auto method_root=metadata_with_method();put32(method_input,0x20,72);method_input[0x24]=std::byte{2};method_input[0x26]=std::byte{5};put32(method_input,0x28,0x80);put32(method_input,0x2c,static_cast<std::uint32_t>(method_root.size()));std::copy(method_root.begin(),method_root.end(),method_input.begin()+0x80);method_input[0x200]=std::byte{0x06};method_input[0x201]=std::byte{0x2a};method_input[0x400]=std::byte{0x07};
  LoadedImage method_loaded;method_loaded.image=hexlab_test::memory_image(method_input);method_loaded.metadata.format="PE32+";method_loaded.metadata.pe.emplace();method_loaded.metadata.preferred_base=0x1000;method_loaded.metadata.image_size=method_input.size();method_loaded.metadata.directories.push_back({14,0x20,72,false});
  auto types=parse_managed_types(method_root);if(!types)std::cerr<<types.error().message<<std::endl;CHECK(types);CHECK(types.value().size()==1);CHECK(types.value()[0].token==0x02000001);CHECK(types.value()[0].full_name=="Demo.T");CHECK(types.value()[0].method_tokens==std::vector<std::uint32_t>({0x06000001,0x06000002,0x06000003}));
  auto field_root=metadata_with_fields();auto fields=parse_managed_fields(field_root);if(!fields)std::cerr<<fields.error().message<<std::endl;CHECK(fields);CHECK(fields.value().size()==2);CHECK(fields.value()[0].token==0x04000001);CHECK(fields.value()[0].name=="f");CHECK(fields.value()[0].declaring_type=="A");CHECK(fields.value()[0].signature_index==1);CHECK(fields.value()[1].name=="g");CHECK(fields.value()[1].declaring_type=="B");
  auto pointer_fields=parse_managed_fields(metadata_with_fields(true));CHECK(pointer_fields);CHECK(pointer_fields.value()[0].name=="f");CHECK(pointer_fields.value()[0].declaring_type=="B");CHECK(pointer_fields.value()[1].name=="g");CHECK(pointer_fields.value()[1].declaring_type=="A");
  auto duplicate_pointer_root=metadata_with_fields(true);const auto pointer_metadata=parse_cli_metadata(duplicate_pointer_root);CHECK(pointer_metadata);const auto& pointer_tables=pointer_metadata.value().streams.at("#~");const auto pointer_row_at=pointer_tables.offset+pointer_metadata.value().tables.data_offset+10+28+2;duplicate_pointer_root[pointer_row_at]=std::byte{2};duplicate_pointer_root[pointer_row_at+1]=std::byte{0};CHECK(!parse_managed_fields(duplicate_pointer_root));
  auto bad_owner=method_root;auto method_metadata=parse_cli_metadata(bad_owner);CHECK(method_metadata);const auto type_row=method_metadata.value().tables.data_offset+method_metadata.value().tables.row_sizes.at(0)+method_metadata.value().tables.row_sizes.at(1);const auto tables_stream=method_metadata.value().streams.at("#~");bad_owner[tables_stream.offset+type_row+12]=std::byte{5};bad_owner[tables_stream.offset+type_row+13]=std::byte{0};CHECK(!parse_managed_types(bad_owner));
  auto methods=inspect_managed_methods(method_loaded);if(!methods)std::cerr<<methods.error().message<<std::endl;CHECK(methods);CHECK(methods.value().size()==3);CHECK(methods.value()[0].method.token==0x06000001);CHECK(methods.value()[0].method.name=="Run");CHECK(methods.value()[0].method.declaring_type=="Demo.T");CHECK(methods.value()[1].method.declaring_type=="Demo.T");CHECK(methods.value()[2].method.declaring_type=="Demo.T");CHECK(methods.value()[0].body);CHECK(methods.value()[0].instructions.size()==1);CHECK(std::string_view(methods.value()[0].instructions[0].mnemonic)=="ret");CHECK(methods.value()[1].status==ManagedMethodStatus::no_body);CHECK(methods.value()[1].method.name=="Abstract");CHECK(methods.value()[2].status==ManagedMethodStatus::malformed);
  CHECK(methods.value()[0].resolved_call_signatures.size()==4);CHECK(methods.value()[0].resolved_call_signatures.at(0x06000002).parameter_count==0);CHECK(!methods.value()[0].resolved_call_signatures.at(0x06000002).returns_value);CHECK(methods.value()[0].resolved_call_signatures.at(0x0a000001).returns_value);
  auto rebased_method=method_loaded;rebased_method.image=hexlab_test::memory_image(method_input,0x2000);rebased_method.load_base=0x2000;auto rebased_methods=inspect_managed_methods(rebased_method);CHECK(rebased_methods);CHECK(rebased_methods.value()[0].body);CHECK(rebased_methods.value()[0].instructions.size()==1);
  auto overlap=minimal_metadata();put32(overlap,36,48);CHECK(!parse_cli_metadata(overlap));
  md.resize(md.size()-1);CHECK(!parse_cli_metadata(md));
  std::cout<<"managed loader parser tests passed\n";
}

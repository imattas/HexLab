
#include "hexlab/loaders/managed.hpp"
#include "hexlab/loaders/loaded_image.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <set>
#include <string_view>

namespace hexlab {
namespace {
std::uint16_t u16(std::span<const std::byte> b,std::size_t p){return std::uint16_t(std::to_integer<unsigned char>(b[p]))|(std::uint16_t(std::to_integer<unsigned char>(b[p+1]))<<8);}
std::uint32_t u32(std::span<const std::byte> b,std::size_t p){return std::uint32_t(u16(b,p))|(std::uint32_t(u16(b,p+2))<<16);}
std::uint64_t u64(std::span<const std::byte> b,std::size_t p){return std::uint64_t(u32(b,p))|(std::uint64_t(u32(b,p+4))<<32);}
Error malformed(const char* s){return {ErrorCode::malformed,s};}
bool fits(std::size_t p,std::uint64_t n,std::size_t total){return p<=total && n<=total-p;}
const std::vector<int>& schema(std::uint8_t id){
  using V=std::vector<int>;static const std::array<V,45> s={
    V{2,100,101,101,101},V{300,100,100},V{4,100,100,301,204,206},V{203},V{2,100,102},V{206},V{4,2,2,100,102,208},V{208},V{2,2,100},V{202,301},
    V{306,100,102},V{2,302,102},V{2,303,102},V{304,102},V{2,305,102},V{2,4,202},V{4,204},V{102},V{202,220},V{220},V{2,100,301},
    V{202,223},V{223},V{2,100,102},V{2,206,307},V{202,308,308},V{100},V{102},V{2,309,100,226},V{4,204},V{4,4},V{4},
    V{4,2,2,2,2,4,102,100,100},V{4},V{4,4,4},V{2,2,2,2,4,102,100,100,102},V{4,235},V{4,4,4,235},V{4,100,102},V{4,4,100,100,310},
    V{4,4,100,310},V{202,202},V{2,2,312,100},V{308,102},V{242,301}
  };return s[id];
}
std::uint32_t coded_width(std::uint8_t id,const std::map<std::uint8_t,std::uint32_t>& rows){
  static const std::array<std::vector<std::uint8_t>,13> groups={
    std::vector<std::uint8_t>{0,26,35,1},{2,1,27},{4,8,23},{6,4,1,2,8,9,10,0,14,23,20,17,26,27,32,35,38,39,40,42,44},
    {4,8},{2,6,32},{2,1,26,6,27},{20,23},{6,10},{4,6},{38,35,39},{6,10},{2,6}
  };
  if(id>=groups.size())return 4;
  static constexpr std::array<unsigned,13> tagbits={2,2,2,5,1,2,3,1,1,1,2,3,1};
  std::uint32_t largest=0;for(auto t:groups[id]){auto it=rows.find(t);if(it!=rows.end())largest=std::max(largest,it->second);}
  return largest<(1u<<(16-tagbits[id]))?2:4;
}
std::uint32_t table_row_size(std::uint8_t id,const ManagedTables& t){
  std::uint32_t total=0;for(int c:schema(id)){
    std::uint32_t n=0;if(c==2||c==4)n=static_cast<std::uint32_t>(c);
    else if(c>=100&&c<=102){const auto heap=static_cast<unsigned>(c-100);n=(t.heap_sizes&(1u<<heap))?4:2;}
    else if(c>=200&&c<300){const auto it=t.row_counts.find(static_cast<std::uint8_t>(c-200));n=it!=t.row_counts.end()&&it->second>=65536?4:2;}
    else if(c>=300)n=coded_width(static_cast<std::uint8_t>(c-300),t.row_counts);
    total+=n;
  }return total;
}
Result<std::uint32_t> compressed_uint(std::span<const std::byte> b,std::size_t& p){
  if(p>=b.size())return malformed("Truncated ECMA-335 compressed integer");
  const auto first=std::to_integer<std::uint8_t>(b[p++]);
  if((first&0x80)==0)return std::uint32_t(first);
  if((first&0xc0)==0x80){if(p>=b.size())return malformed("Truncated ECMA-335 compressed integer");return (std::uint32_t(first&0x3f)<<8)|std::to_integer<std::uint8_t>(b[p++]);}
  if((first&0xe0)==0xc0){if(b.size()-p<3)return malformed("Truncated ECMA-335 compressed integer");const auto value=(std::uint32_t(first&0x1f)<<24)|(std::uint32_t(std::to_integer<std::uint8_t>(b[p]))<<16)|(std::uint32_t(std::to_integer<std::uint8_t>(b[p+1]))<<8)|std::to_integer<std::uint8_t>(b[p+2]);p+=3;return value;}
  return malformed("Invalid ECMA-335 compressed integer prefix");
}
Result<ManagedTypeSignature> signature_type(std::span<const std::byte> b,std::size_t& p,unsigned depth){
  if(depth>16)return Error{ErrorCode::resource_limit,"ECMA-335 signature nesting exceeds limit"};
  if(p>=b.size())return malformed("Truncated ECMA-335 signature type");
  const auto et=std::to_integer<std::uint8_t>(b[p++]);
  ManagedTypeSignature out;out.element_type=et;
  if(et==0x01)return malformed("Void is not valid in this signature position");
  if((et>=0x02&&et<=0x0e)||et==0x16||et==0x18||et==0x19||et==0x1c)return out;
  if(et==0x13||et==0x1e){auto index=compressed_uint(b,p);if(!index)return index.error();out.generic_index=index.value();return out;}
  if(et==0x0f||et==0x10){if(p>=b.size())return malformed("Missing pointer or byref signature target");if(std::to_integer<std::uint8_t>(b[p])==0x01){if(et==0x10)return malformed("Byref cannot target void");out.children.push_back(ManagedTypeSignature{0x01});++p;return out;}auto child=signature_type(b,p,depth+1);if(!child)return child.error();out.children.push_back(std::move(child.value()));return out;}
  if(et==0x11||et==0x12){auto token=compressed_uint(b,p);if(!token)return token.error();if(!token.value()||(token.value()>>2)==0)return malformed("Signature type has a null TypeDefOrRef token");if((token.value()&3)==3)return malformed("Signature type has an invalid TypeDefOrRef tag");out.metadata_type_coded_index=token.value();return out;}
  if(et==0x1d){auto child=signature_type(b,p,depth+1);if(!child)return child.error();out.children.push_back(std::move(child.value()));return out;}
  if(et==0x14){auto element=signature_type(b,p,depth+1);if(!element)return element.error();out.children.push_back(std::move(element.value()));auto rank=compressed_uint(b,p);if(!rank)return rank.error();if(!rank.value()||rank.value()>32)return malformed("Invalid ECMA-335 array rank");out.array_rank=rank.value();auto sizes=compressed_uint(b,p);if(!sizes)return sizes.error();if(sizes.value()>rank.value())return malformed("Array size count exceeds rank");for(std::uint32_t i=0;i<sizes.value();++i)if(!compressed_uint(b,p))return malformed("Invalid array size encoding");auto bounds=compressed_uint(b,p);if(!bounds)return bounds.error();if(bounds.value()>rank.value())return malformed("Array lower-bound count exceeds rank");for(std::uint32_t i=0;i<bounds.value();++i)if(!compressed_uint(b,p))return malformed("Invalid array lower-bound encoding");return out;}
  if(et==0x15){if(p>=b.size())return malformed("Missing generic-instantiation class/value marker");const auto kind=std::to_integer<std::uint8_t>(b[p++]);if(kind!=0x11&&kind!=0x12)return malformed("Invalid generic-instantiation class/value marker");out.generic_instance_is_value_type=kind==0x11;auto token=compressed_uint(b,p);if(!token)return token.error();if(!token.value()||(token.value()>>2)==0||(token.value()&3)==3)return malformed("Invalid generic-instantiation type token");out.metadata_type_coded_index=token.value();auto count=compressed_uint(b,p);if(!count)return count.error();if(!count.value()||count.value()>1024)return Error{ErrorCode::resource_limit,"Generic-instantiation argument limit exceeded"};for(std::uint32_t i=0;i<count.value();++i){auto argument=signature_type(b,p,depth+1);if(!argument)return argument.error();out.children.push_back(std::move(argument.value()));}return out;}
  return Error{ErrorCode::unsupported,"ECMA-335 signature contains an unsupported element type"};
}
Result<bool> resolve_type_signature(ManagedTypeSignature& signature,const ManagedTypeCatalog& catalog,
                                    std::set<std::uint32_t>& active_specs,unsigned depth,std::size_t& budget){
  if(depth>16)return Error{ErrorCode::resource_limit,"Resolved TypeSpec nesting exceeds limit"};
  if(!budget--)return Error{ErrorCode::resource_limit,"Resolved managed signature node limit exceeded"};
  if(signature.metadata_type_coded_index){const auto coded=signature.metadata_type_coded_index,tag=coded&3u,rid=coded>>2;if(!rid||tag==3)return malformed("Signature contains an invalid TypeDefOrRef coded index");const std::uint32_t table=tag==0?2u:tag==1?1u:27u;const auto token=(table<<24)|rid;signature.metadata_type_token=token;
    if(tag==0){if(rid>catalog.definitions.size())return malformed("Signature TypeDef token is out of range");signature.metadata_type_name=catalog.definitions[rid-1].full_name;signature.metadata_type_scope="module";}
    else if(tag==1){if(rid>catalog.references.size())return malformed("Signature TypeRef token is out of range");const auto& ref=catalog.references[rid-1];signature.metadata_type_name=ref.full_name;signature.metadata_type_scope=ref.unresolved_scope.empty()?"module":ref.unresolved_scope;signature.metadata_type_external_unresolved=ref.external_scope_unresolved;}
    else {if(rid>catalog.specifications.size())return malformed("Signature TypeSpec token is out of range");const auto& spec=catalog.specifications[rid-1];if(spec.token!=token)return malformed("Signature TypeSpec token is unresolved");if(!active_specs.insert(token).second)return malformed("Recursive TypeSpec signature cycle");signature.type_spec_signature=std::make_shared<ManagedTypeSignature>(spec.signature);auto resolved=resolve_type_signature(*signature.type_spec_signature,catalog,active_specs,depth+1,budget);active_specs.erase(token);if(!resolved)return resolved.error();signature.metadata_type_name="TypeSpec";signature.metadata_type_scope="metadata";}
  }
  // A GENERICINST carries its own argument vector. If its constructor is an
  // in-module TypeDef, validate against the authoritative GenericParam rows
  // before the CIL lifter uses VAR substitutions. Keep malformed-but-bounded
  // metadata inspectable while making the resulting value type unknown.
  if(signature.element_type==0x15 && signature.metadata_type_token &&
     (signature.metadata_type_token>>24)==2) {
    const auto rid=signature.metadata_type_token&0x00ffffffu;
    if(!rid||rid>catalog.definitions.size())return malformed("Generic instance TypeDef token is outside the type catalog");
    const auto& parameters=catalog.definitions[rid-1].generic_parameters;
    signature.generic_instance_arity_valid=parameters.size()==signature.children.size();
    for(std::size_t i=0;signature.generic_instance_arity_valid&&i<parameters.size();++i)
      signature.generic_instance_arity_valid=parameters[i].number==i;
  }
  for(auto& child:signature.children){auto resolved=resolve_type_signature(child,catalog,active_specs,depth+1,budget);if(!resolved)return resolved.error();}
  return true;
}
const ManagedTypeSignature* resolved_type_spec_root(const ManagedTypeSignature& signature,
                                                     unsigned depth=0){
  if(depth>16)return nullptr;
  if(!signature.type_spec_signature)return &signature;
  return resolved_type_spec_root(*signature.type_spec_signature,depth+1);
}
const ManagedTypeSignature* generic_instance_root(const ManagedTypeSignature& signature){
  const auto* root=resolved_type_spec_root(signature);
  return root&&root->element_type==0x15?root:nullptr;
}
}

namespace {
Result<ManagedMethodSignature> decode_method_signature(std::span<const std::byte> b, bool call_site){
  if(b.empty())return malformed("Empty ECMA-335 method signature");
  std::size_t p=0;const auto convention=std::to_integer<std::uint8_t>(b[p++]);
  const auto kind=convention&0x0f;
  const bool supported_kind=kind==0||kind==5||(call_site&&((kind>=1&&kind<=4)||kind==9));
  if(!supported_kind)return Error{ErrorCode::unsupported,call_site?"Unsupported ECMA-335 call-site convention":"Only default and vararg ECMA-335 method signatures are supported"};
  if((convention&0x80)||((convention&0x40)&&!(convention&0x20)))return malformed("Invalid ECMA-335 method calling-convention flags");
  std::uint32_t generic_arity=0;
  if(convention&0x10){auto generic_count=compressed_uint(b,p);if(!generic_count)return generic_count.error();if(!generic_count.value()||generic_count.value()>1024)return malformed("Invalid generic method arity in signature");generic_arity=generic_count.value();}
  auto count=compressed_uint(b,p);if(!count)return count.error();if(count.value()>4096)return Error{ErrorCode::resource_limit,"ECMA-335 method signature parameter limit exceeded"};
  if(p>=b.size())return malformed("Missing ECMA-335 method return type");
  ManagedMethodSignature out;out.parameter_count=count.value();out.generic_arity=generic_arity;out.has_this=(convention&0x20)!=0;
  if(std::to_integer<std::uint8_t>(b[p])==0x01){out.return_type.element_type=0x01;++p;out.returns_value=false;}else{auto result=signature_type(b,p,0);if(!result)return result.error();out.return_type=std::move(result.value());out.returns_value=true;}
  bool saw_sentinel=false;
  for(std::uint32_t n=0;n<count.value();++n){
    if(p<b.size()&&std::to_integer<std::uint8_t>(b[p])==0x41){if(kind!=5||saw_sentinel)return malformed("Invalid or duplicate vararg sentinel");++p;saw_sentinel=true;}
    auto parameter=signature_type(b,p,0);if(!parameter)return parameter.error();out.parameter_types.push_back(std::move(parameter.value()));
  }
  if(p!=b.size())return malformed("Trailing bytes in ECMA-335 method signature");
  return out;
}
}

Result<ManagedMethodSignature> decode_managed_method_signature(std::span<const std::byte> b){
  return decode_method_signature(b, false);
}

Result<ManagedTypeSignature> decode_managed_field_signature(std::span<const std::byte> b){
  if(b.empty())return malformed("Empty ECMA-335 field signature");
  if(std::to_integer<std::uint8_t>(b.front())!=0x06)
    return malformed("Invalid ECMA-335 FieldSig calling convention");
  std::size_t p=1;
  auto type=signature_type(b,p,0);
  if(!type)return type.error();
  if(p!=b.size())return malformed("Trailing bytes in ECMA-335 field signature");
  return type;
}

Result<ManagedMethodSignature> decode_managed_call_site_signature(std::span<const std::byte> b){
  return decode_method_signature(b, true);
}

Result<std::map<std::uint32_t,ManagedMethodSignature>> parse_managed_call_signatures(std::span<const std::byte> root){
  auto parsed=parse_cli_metadata(root);if(!parsed)return parsed.error();const auto& md=parsed.value();
  auto table_it=md.streams.find("#~");if(table_it==md.streams.end())table_it=md.streams.find("#-");
  const auto blob_it=md.streams.find("#Blob");if(table_it==md.streams.end()||blob_it==md.streams.end())return malformed("Call-signature resolution requires tables and #Blob heaps");
  const auto tables=root.subspan(table_it->second.offset,table_it->second.size),blob=root.subspan(blob_it->second.offset,blob_it->second.size);
  const auto rows=[&](std::uint8_t id){auto i=md.tables.row_counts.find(id);return i==md.tables.row_counts.end()?0u:i->second;};
  const auto width=[&](std::uint8_t id){return rows(id)<65536?2u:4u;};
  const auto table_offset=[&](std::uint8_t id){std::uint64_t off=md.tables.data_offset;for(std::uint8_t t=0;t<id;++t)if(auto r=md.tables.row_counts.find(t);r!=md.tables.row_counts.end())off+=std::uint64_t{r->second}*md.tables.row_sizes.at(t);return off;};
  const auto read_index=[&](std::span<const std::byte> b,std::size_t p,unsigned w){return w==2?std::uint32_t(u16(b,p)):u32(b,p);};
  const auto signature_at=[&](std::uint32_t index, bool call_site=false)->Result<ManagedMethodSignature>{
    if(!index||index>=blob.size())return malformed("Method signature blob index is outside #Blob heap");
    std::size_t p=index;auto size=compressed_uint(blob,p);if(!size)return size.error();if(size.value()>blob.size()-p)return malformed("Method signature blob exceeds #Blob heap");
    const auto bytes=blob.subspan(p,size.value());
    return call_site?decode_managed_call_site_signature(bytes):decode_managed_method_signature(bytes);
  };
  std::map<std::uint32_t,ManagedMethodSignature> result;
  const auto method_count=rows(6);if(method_count){const auto row_size=md.tables.row_sizes.at(6);const auto str_w=(md.tables.heap_sizes&1)?4u:2u;const auto blob_w=(md.tables.heap_sizes&4)?4u:2u;const auto off=table_offset(6);if(off>tables.size()||std::uint64_t{method_count}*row_size>tables.size()-off)return malformed("MethodDef rows exceed tables stream");
    for(std::uint32_t i=0;i<method_count;++i){const auto at=static_cast<std::size_t>(off+std::uint64_t{i}*row_size+8+str_w);auto sig=signature_at(read_index(tables,at,blob_w));if(!sig)return sig.error();result.emplace(0x06000000u|(i+1),sig.value());}}
  const auto member_count=rows(10);if(member_count){const auto row_size=md.tables.row_sizes.at(10);const auto parent_w=coded_width(6,md.tables.row_counts);const auto str_w=(md.tables.heap_sizes&1)?4u:2u;const auto blob_w=(md.tables.heap_sizes&4)?4u:2u;const auto off=table_offset(10);if(off>tables.size()||std::uint64_t{member_count}*row_size>tables.size()-off)return malformed("MemberRef rows exceed tables stream");
    for(std::uint32_t i=0;i<member_count;++i){const auto at=static_cast<std::size_t>(off+std::uint64_t{i}*row_size+parent_w+str_w);const auto index=read_index(tables,at,blob_w);if(!index||index>=blob.size())return malformed("MemberRef signature blob index is outside #Blob heap");std::size_t p=index;auto size=compressed_uint(blob,p);if(!size)return size.error();if(size.value()>blob.size()-p)return malformed("MemberRef signature exceeds #Blob heap");const auto bytes=blob.subspan(p,size.value());if(bytes.empty())return malformed("Empty MemberRef signature");if(std::to_integer<std::uint8_t>(bytes[0])==0x06)continue;auto sig=decode_managed_method_signature(bytes);if(!sig)return sig.error();result.emplace(0x0a000000u|(i+1),sig.value());}}
  const auto standalone_count=rows(17);if(standalone_count){const auto row_size=md.tables.row_sizes.at(17);const auto blob_w=(md.tables.heap_sizes&4)?4u:2u;const auto off=table_offset(17);if(off>tables.size()||std::uint64_t{standalone_count}*row_size>tables.size()-off)return malformed("StandAloneSig rows exceed tables stream");
    for(std::uint32_t i=0;i<standalone_count;++i){const auto at=static_cast<std::size_t>(off+std::uint64_t{i}*row_size);const auto index=read_index(tables,at,blob_w);if(!index||index>=blob.size())return malformed("StandAloneSig blob index is outside #Blob heap");std::size_t p=index;auto size=compressed_uint(blob,p);if(!size)return size.error();if(size.value()>blob.size()-p)return malformed("StandAloneSig blob exceeds #Blob heap");const auto bytes=blob.subspan(p,size.value());if(bytes.empty())return malformed("Empty StandAloneSig blob");const auto convention=std::to_integer<std::uint8_t>(bytes[0]);if((convention&0x0f)==0x07)continue;auto signature=decode_managed_call_site_signature(bytes);if(!signature){if(signature.error().code==ErrorCode::unsupported)continue;return signature.error();}result.emplace(0x11000000u|(i+1),std::move(signature.value()));}}
  std::map<std::uint32_t,std::uint32_t> method_spec_bases;
  const auto spec_count=rows(43);if(spec_count){const auto row_size=md.tables.row_sizes.at(43);const auto method_w=coded_width(8,md.tables.row_counts);const auto blob_w=(md.tables.heap_sizes&4)?4u:2u;const auto off=table_offset(43);if(off>tables.size()||std::uint64_t{spec_count}*row_size>tables.size()-off)return malformed("MethodSpec rows exceed tables stream");for(std::uint32_t i=0;i<spec_count;++i){const auto at=static_cast<std::size_t>(off+std::uint64_t{i}*row_size);const auto coded=read_index(tables,at,method_w);const auto tag=coded&1u,rid=coded>>1;if(!rid)return malformed("MethodSpec has a null MethodDefOrRef token");const auto base_token=(tag==0?0x06000000u:0x0a000000u)|rid;auto base=result.find(base_token);if(base==result.end())return Error{ErrorCode::unsupported,"MethodSpec target signature is unresolved"};const auto index=read_index(tables,at+method_w,blob_w);if(!index||index>=blob.size())return malformed("MethodSpec instantiation blob index is outside #Blob heap");std::size_t p=index;auto size=compressed_uint(blob,p);if(!size)return size.error();if(size.value()>blob.size()-p)return malformed("MethodSpec instantiation exceeds #Blob heap");auto inst=blob.subspan(p,size.value());if(inst.empty()||std::to_integer<std::uint8_t>(inst[0])!=0x0a)return malformed("Invalid MethodSpec instantiation signature");std::size_t q=1;auto count=compressed_uint(inst,q);if(!count)return count.error();if(!count.value()||count.value()>1024)return Error{ErrorCode::resource_limit,"MethodSpec argument limit exceeded"};auto specialized=base->second;if(specialized.generic_arity!=count.value())return malformed("MethodSpec argument count does not match generic method arity");specialized.method_spec_arguments.clear();for(std::uint32_t n=0;n<count.value();++n){auto type=signature_type(inst,q,0);if(!type)return type.error();specialized.method_spec_arguments.push_back(std::move(type.value()));}if(q!=inst.size())return malformed("Trailing bytes in MethodSpec instantiation");const auto method_spec_token=0x2b000000u|(i+1);result.emplace(method_spec_token,std::move(specialized));method_spec_bases.emplace(method_spec_token,base_token);}}
  auto catalog=parse_managed_type_catalog(root);if(!catalog)return catalog.error();
  std::map<std::uint32_t,const ManagedTypeDefinition*> definitions;
  std::map<std::uint32_t,const ManagedTypeReference*> references;
  std::map<std::uint32_t,const ManagedTypeSpecification*> specifications;
  std::map<std::uint32_t,const ManagedTypeDefinition*> method_owners;
  for(const auto& type:catalog.value().definitions){definitions.emplace(type.token,&type);for(const auto token:type.method_tokens)method_owners.emplace(token,&type);}
  for(const auto& type:catalog.value().references)references.emplace(type.token,&type);
  for(const auto& type:catalog.value().specifications)specifications.emplace(type.token,&type);
  const auto type_name=[&](std::uint32_t token)->std::string{
    if(const auto found=definitions.find(token);found!=definitions.end())return found->second->full_name;
    if(const auto found=references.find(token);found!=references.end())return found->second->full_name;
    if(const auto found=specifications.find(token);found!=specifications.end()){
      const auto* resolved=resolved_type_spec_root(found->second->signature);
      return resolved?resolved->metadata_type_name:std::string{};
    }
    return {};
  };
  const auto type_is_value=[&](std::uint32_t token)->std::optional<bool>{
    if(const auto found=specifications.find(token);found!=specifications.end()){
      const auto* resolved=resolved_type_spec_root(found->second->signature);
      if(!resolved)return {};
      const auto& signature=*resolved;
      if(signature.element_type==0x15)return signature.generic_instance_is_value_type;
      if(signature.element_type==0x11)return true;
      if(signature.element_type==0x12)return false;
    }
    if(const auto found=references.find(token);found!=references.end()){
      const auto& name=found->second->full_name;
      if(name=="System.Object"||name=="System.String"||name=="System.Exception"||name=="System.Type"||
         name=="System.Array"||name=="System.Delegate"||name=="System.MulticastDelegate"||name=="System.Attribute"||
         name=="System.Text.StringBuilder")return false;
      return {};
    }
    if(const auto found=definitions.find(token);found!=definitions.end()){
      const auto base=found->second->base_type_token;
      if(!base)return false;
      const auto name=type_name(base);
      if(name.empty())return {};
      return name=="System.ValueType"||name=="System.Enum";
    }
    return {};
  };
  const auto set_owner=[&](ManagedMethodSignature& signature,std::uint32_t token){
    signature.declaring_type_token=token;
    signature.declaring_type_name=type_name(token);
    signature.declaring_type_is_value_type=type_is_value(token);
    if(const auto found=specifications.find(token);found!=specifications.end()) {
      if(const auto* instance=generic_instance_root(found->second->signature)) {
        signature.declaring_type_arguments=instance->children;
        signature.declaring_type_generic_arguments_valid=
            instance->generic_instance_arity_valid;
      }
    }
  };
  for(auto& [token,signature]:result){
    if((token>>24)==0x06){if(const auto owner=method_owners.find(token);owner!=method_owners.end())set_owner(signature,owner->second->token);}
  }
  const auto memberref_count=rows(10);
  if(memberref_count){
    const auto row_size=md.tables.row_sizes.at(10),parent_width=coded_width(6,md.tables.row_counts);
    const auto offset=table_offset(10);
    if(offset>tables.size()||std::uint64_t{memberref_count}*row_size>tables.size()-offset)
      return malformed("MemberRef rows exceed tables stream while resolving owners");
    for(std::uint32_t rid=1;rid<=memberref_count;++rid){
      const auto coded=read_index(tables,static_cast<std::size_t>(offset+std::uint64_t{rid-1}*row_size),parent_width);
      const auto tag=coded&7u,parent_rid=coded>>3;
      if(!parent_rid||tag>4)return malformed("MemberRef has an invalid MemberRefParent coded index");
      const std::uint32_t table=tag==0?2u:tag==1?1u:tag==2?26u:tag==3?6u:27u;
      if(parent_rid>rows(static_cast<std::uint8_t>(table)))return malformed("MemberRef parent token is outside its metadata table");
      const auto method_token=0x0a000000u|rid;
      const auto signature_it=result.find(method_token);if(signature_it==result.end())continue;
      if(tag==0||tag==1||tag==4)set_owner(signature_it->second,(table<<24)|parent_rid);
      else if(tag==3){if(const auto owner=method_owners.find(0x06000000u|parent_rid);owner!=method_owners.end())set_owner(signature_it->second,owner->second->token);}
    }
  }
  for(const auto& [method_spec_token,base_token]:method_spec_bases){
    auto specialized=result.find(method_spec_token),base=result.find(base_token);
    if(specialized==result.end()||base==result.end())return malformed("MethodSpec owner signature is unavailable");
    auto arguments=std::move(specialized->second.method_spec_arguments);
    specialized->second=base->second;
    specialized->second.method_spec_arguments=std::move(arguments);
  }
  std::set<std::uint32_t> active_specs;std::size_t resolution_budget=100000;
  for(auto& [token,signature]:result){(void)token;auto resolved=resolve_type_signature(signature.return_type,catalog.value(),active_specs,0,resolution_budget);if(!resolved)return resolved.error();for(auto& parameter:signature.parameter_types){resolved=resolve_type_signature(parameter,catalog.value(),active_specs,0,resolution_budget);if(!resolved)return resolved.error();}for(auto& argument:signature.method_spec_arguments){resolved=resolve_type_signature(argument,catalog.value(),active_specs,0,resolution_budget);if(!resolved)return resolved.error();}}
  return result;
}

Result<ManagedUserStringCatalog> parse_managed_user_strings(std::span<const std::byte> root){
  auto parsed=parse_cli_metadata(root);if(!parsed)return parsed.error();
  const auto heap_it=parsed.value().streams.find("#US");
  if(heap_it==parsed.value().streams.end())return ManagedUserStringCatalog{};
  const auto heap=root.subspan(heap_it->second.offset,heap_it->second.size);
  if(heap.size()>64u*1024u*1024u)return Error{ErrorCode::resource_limit,"CLR #US heap exceeds 64 MiB inspection limit"};
  ManagedUserStringCatalog result;
  std::size_t cursor=1,total_code_units=0;
  while(cursor<heap.size()){
    // Heap alignment padding is zero-filled. Do not interpret it as another
    // entry, but reject nonzero data after a zero-sized prefix.
    if(std::to_integer<std::uint8_t>(heap[cursor])==0){
      if(std::any_of(heap.begin()+static_cast<std::ptrdiff_t>(cursor),heap.end(),[](std::byte value){return value!=std::byte{0};}))
        return malformed("Nonzero data follows CLR #US heap padding");
      break;
    }
    const auto entry_offset=cursor;
    if(entry_offset>0x00ffffffu)return Error{ErrorCode::resource_limit,"CLR #US entry offset exceeds the user-string token range"};
    auto byte_count=compressed_uint(heap,cursor);if(!byte_count)return byte_count.error();
    if(!byte_count.value())return malformed("CLR #US entry has an empty encoded length");
    if(byte_count.value()>4u*1024u*1024u)return Error{ErrorCode::resource_limit,"CLR user-string entry exceeds 4 MiB"};
    if(byte_count.value()>heap.size()-cursor)return malformed("CLR user-string entry exceeds #US heap");
    const auto character_bytes=byte_count.value()-1;
    if(character_bytes&1u)return malformed("CLR user-string UTF-16 payload has an odd byte count");
    const auto code_units=character_bytes/2;
    if(code_units>16u*1024u*1024u-total_code_units)
      return Error{ErrorCode::resource_limit,"CLR #US decoded code-unit budget exceeded"};
    const auto kind=std::to_integer<std::uint8_t>(heap[cursor+character_bytes]);
    if(kind>1)return malformed("CLR user-string kind byte is invalid");
    std::u16string text;text.reserve(code_units);
    for(std::size_t i=0;i<code_units;++i)text.push_back(static_cast<char16_t>(u16(heap,cursor+i*2)));
    const auto token=0x70000000u|static_cast<std::uint32_t>(entry_offset);
    if(!result.emplace(token,std::move(text)).second)return malformed("Duplicate CLR user-string token");
    total_code_units+=code_units;cursor+=byte_count.value();
    if(result.size()>1'000'000)return Error{ErrorCode::resource_limit,"CLR #US entry count exceeds one million"};
  }
  return result;
}

Result<ManagedMetadataRoot> parse_cli_metadata(std::span<const std::byte> b){
  if(b.size()>64*1024*1024)return Error{ErrorCode::resource_limit,"CLR metadata root exceeds 64 MiB inspection limit"};
  if(b.size()<20 || u32(b,0)!=0x424a5342)return malformed("Invalid CLR metadata root signature");
  const auto version_size=u32(b,12);
  if(version_size>1024 || !fits(16,version_size,b.size()))return malformed("CLR metadata version string exceeds root");
  ManagedMetadataRoot out;
  const auto version=b.subspan(16,version_size);
  for(auto c:version){const auto ch=std::to_integer<unsigned char>(c);if(ch==0)break;out.version.push_back(static_cast<char>(ch));}
  std::size_t p=16+version_size;p=(p+3)&~std::size_t{3};
  if(!fits(p,4,b.size()))return malformed("Truncated CLR metadata stream header");
  const auto count=u16(b,p+2);p+=4;
  if(count>32)return Error{ErrorCode::resource_limit,"CLR metadata declares too many streams"};
  std::vector<std::pair<std::string,ManagedStream>> streams;
  std::vector<std::pair<std::uint64_t,std::uint64_t>> extents;
  for(std::uint16_t i=0;i<count;++i){
    if(!fits(p,8,b.size()))return malformed("Truncated CLR metadata stream descriptor");
    ManagedStream s{u32(b,p),u32(b,p+4)};p+=8;
    std::string name;bool terminated=false;
    for(unsigned j=0;j<32 && p<b.size();++j){auto c=std::to_integer<unsigned char>(b[p++]);if(!c){terminated=true;break;}name.push_back(static_cast<char>(c));}
    if(!terminated)return malformed("CLR metadata stream name is not terminated");
    p=(p+3)&~std::size_t{3};
    if(!fits(s.offset,s.size,b.size()))return malformed("CLR metadata stream exceeds metadata root");
    if(s.size){if(s.offset%4)return malformed("CLR metadata stream offset is not four-byte aligned");extents.emplace_back(s.offset,std::uint64_t{s.offset}+s.size);}
    if(name.empty() || out.streams.contains(name))return malformed("Empty or duplicate CLR metadata stream name");
    out.streams.emplace(name,s);streams.emplace_back(name,s);
  }
  std::sort(extents.begin(),extents.end());
  for(std::size_t i=0;i<extents.size();++i){
    if(extents[i].first<p)return malformed("CLR metadata stream overlaps its stream directory");
    if(i && extents[i].first<extents[i-1].second)return malformed("CLR metadata streams overlap");
  }
  auto table=out.streams.find("#~");if(table==out.streams.end())table=out.streams.find("#-");
  if(table==out.streams.end())return malformed("CLR metadata has no tables stream");
  auto t=b.subspan(table->second.offset,table->second.size);
  if(t.size()<24)return malformed("Truncated CLR tables stream header");
  out.tables.major=std::to_integer<std::uint8_t>(t[4]);out.tables.minor=std::to_integer<std::uint8_t>(t[5]);out.tables.heap_sizes=std::to_integer<std::uint8_t>(t[6]);
  if(out.tables.heap_sizes&~std::uint8_t{7})return malformed("CLR tables stream has reserved heap-size flags");
  out.tables.valid=u64(t,8);out.tables.sorted=u64(t,16);
  if(out.tables.valid>>45)return Error{ErrorCode::unsupported,"CLR metadata uses tables beyond the supported ECMA-335 table range"};
  std::size_t cursor=24;
  for(std::uint8_t id=0;id<45;++id)if((out.tables.valid>>id)&1){
    if(!fits(cursor,4,t.size()))return malformed("Truncated CLR table row counts");
    auto rows=u32(t,cursor);cursor+=4;
    if(rows>1000000)return Error{ErrorCode::resource_limit,"CLR metadata table exceeds one-million-row inspection limit"};
    out.tables.row_counts.emplace(id,rows);
  }
  out.tables.data_offset=cursor;
  for(std::uint8_t id=0;id<45;++id)if((out.tables.valid>>id)&1){
    const auto width=table_row_size(id,out.tables);out.tables.row_sizes.emplace(id,width);
    const auto row_count=out.tables.row_counts.at(id);
    if(!fits(cursor,std::uint64_t{width}*row_count,t.size()))return malformed("CLR metadata table rows exceed tables stream");
    cursor+=std::size_t(width)*row_count;
  }
  return out;
}

Result<std::vector<ManagedTypeDefinition>> parse_managed_types(std::span<const std::byte> root){
  auto parsed=parse_cli_metadata(root);if(!parsed)return parsed.error();
  const auto& metadata=parsed.value();
  const auto type_it=metadata.tables.row_counts.find(2);
  const auto nested_count_it=metadata.tables.row_counts.find(41);
  if(type_it==metadata.tables.row_counts.end() || !type_it->second) {
    if(nested_count_it!=metadata.tables.row_counts.end() && nested_count_it->second)
      return malformed("CLR NestedClass rows have no TypeDef rows");
    return std::vector<ManagedTypeDefinition>{};
  }
  auto table_it=metadata.streams.find("#~");if(table_it==metadata.streams.end())table_it=metadata.streams.find("#-");
  const auto strings_it=metadata.streams.find("#Strings");
  if(table_it==metadata.streams.end() || strings_it==metadata.streams.end())return malformed("CLR TypeDef parsing requires tables and #Strings heaps");
  const auto tables=root.subspan(table_it->second.offset,table_it->second.size),strings=root.subspan(strings_it->second.offset,strings_it->second.size);
  const auto rows=[&](std::uint8_t id){const auto it=metadata.tables.row_counts.find(id);return it==metadata.tables.row_counts.end()?0u:it->second;};
  const auto index_width=[&](std::uint8_t id){return rows(id)<65536?2u:4u;};
  const auto method_count=rows(6),pointer_count=rows(5),list_count=pointer_count?pointer_count:method_count;
  std::vector<std::uint32_t> method_order;method_order.reserve(list_count);
  if(pointer_count){
    if(pointer_count!=method_count)return malformed("CLR MethodPtr count does not match MethodDef count");
    std::uint64_t offset=metadata.tables.data_offset;for(std::uint8_t id=0;id<5;++id)if(const auto size=metadata.tables.row_sizes.find(id);size!=metadata.tables.row_sizes.end())offset+=std::uint64_t{rows(id)}*size->second;
    const auto row_size=metadata.tables.row_sizes.at(5);if(offset>tables.size() || std::uint64_t{pointer_count}*row_size>tables.size()-offset)return malformed("CLR MethodPtr rows exceed tables stream");
    std::vector<bool> seen(method_count+1);
    for(std::uint32_t n=0;n<pointer_count;++n){const auto at=static_cast<std::size_t>(offset+std::uint64_t{n}*row_size);const auto row=row_size==2?u16(tables,at):u32(tables,at);if(!row || row>method_count || seen[row])return malformed("CLR MethodPtr contains an invalid or duplicate MethodDef index");seen[row]=true;method_order.push_back(row);}
  }else for(std::uint32_t n=1;n<=method_count;++n)method_order.push_back(n);
  std::uint64_t offset=metadata.tables.data_offset;for(std::uint8_t id=0;id<2;++id)if(const auto size=metadata.tables.row_sizes.find(id);size!=metadata.tables.row_sizes.end())offset+=std::uint64_t{rows(id)}*size->second;
  const auto row_size=metadata.tables.row_sizes.at(2),type_count=type_it->second;
  if(offset>tables.size() || std::uint64_t{type_count}*row_size>tables.size()-offset)return malformed("CLR TypeDef rows exceed tables stream");
  const auto string_width=(metadata.tables.heap_sizes&1)?4u:2u,extends_width=coded_width(1,metadata.tables.row_counts);
  const auto field_width=index_width(rows(3)?3:4),method_width=index_width(pointer_count?5:6);
  if(row_size!=4+2*string_width+extends_width+field_width+method_width)return malformed("CLR TypeDef row layout is inconsistent");
  const auto read_string=[&](std::uint32_t index)->Result<std::string>{
    if(!index)return std::string{};if(index>=strings.size())return malformed("CLR TypeDef string index exceeds #Strings heap");
    std::string value;for(std::size_t p=index;p<strings.size();++p){const auto c=std::to_integer<unsigned char>(strings[p]);if(!c)return value;value.push_back(static_cast<char>(c));if(value.size()>4096)return Error{ErrorCode::resource_limit,"CLR TypeDef name exceeds 4096 bytes"};}
    return malformed("CLR TypeDef string is unterminated in #Strings heap");
  };
  std::vector<ManagedTypeDefinition> result;std::vector<std::uint32_t> starts;result.reserve(type_count);starts.reserve(type_count);
  for(std::uint32_t n=0;n<type_count;++n){
    const auto at=static_cast<std::size_t>(offset+std::uint64_t{n}*row_size);ManagedTypeDefinition type;
    type.token=0x02000000u|(n+1);type.flags=u32(tables,at);const auto name_at=at+4;
    const auto name_index=string_width==2?u16(tables,name_at):u32(tables,name_at);
    const auto ns_at=name_at+string_width;
    const auto ns_index=string_width==2?u16(tables,ns_at):u32(tables,ns_at);
    auto name=read_string(name_index);if(!name)return name.error();auto ns=read_string(ns_index);if(!ns)return ns.error();
    if(name.value().empty())return malformed("CLR TypeDef has an empty name");
    type.name=std::move(name.value());type.namespace_name=std::move(ns.value());type.full_name=type.namespace_name.empty()?type.name:type.namespace_name+"."+type.name;
    const auto extends_at=ns_at+string_width;
    const auto extends=extends_width==2?u16(tables,extends_at):u32(tables,extends_at);
    if(extends){const auto tag=extends&3u,rid=extends>>2;if(!rid||tag==3)return malformed("CLR TypeDef Extends has an invalid TypeDefOrRef coded index");const auto table=tag==0?2u:tag==1?1u:27u;if(rid>rows(static_cast<std::uint8_t>(table)))return malformed("CLR TypeDef Extends token is outside its metadata table");type.base_type_token=(table<<24)|rid;}
    const auto list_at=ns_at+string_width+extends_width+field_width;const auto first=method_width==2?u16(tables,list_at):u32(tables,list_at);
    if(!first || first>list_count+1 || (!starts.empty() && first<starts.back()))return malformed("CLR TypeDef MethodList indexes are invalid or unsorted");
    starts.push_back(first);result.push_back(std::move(type));
  }
  if(starts.front()!=1)return malformed("CLR TypeDef MethodList does not begin at row one");
  std::vector<bool> assigned(method_count+1);
  for(std::size_t n=0;n<result.size();++n){const auto end=n+1<starts.size()?starts[n+1]:list_count+1;for(auto index=starts[n];index<end;++index){const auto row=method_order[index-1];if(assigned[row])return malformed("CLR MethodDef is owned by multiple TypeDefs");assigned[row]=true;result[n].method_tokens.push_back(0x06000000u|row);}}
  if(std::find(assigned.begin()+1,assigned.end(),false)!=assigned.end())return malformed("CLR TypeDef MethodList leaves a MethodDef unowned");
  auto generic_parameters=parse_managed_generic_parameters(root);if(!generic_parameters)return generic_parameters.error();
  std::map<std::uint32_t,std::size_t> type_by_token;
  for(std::size_t n=0;n<result.size();++n)type_by_token.emplace(result[n].token,n);
  // NestedClass stores two TypeDef indexes: the nested type, then its
  // enclosing type. Resolve these before publishing names so callers do not
  // mistake nested definitions for namespace-level siblings.
  if(nested_count_it!=metadata.tables.row_counts.end() && nested_count_it->second) {
    const auto nested_count=nested_count_it->second;
    const auto nested_row=metadata.tables.row_sizes.find(41);
    const auto type_index_width=index_width(2);
    std::uint64_t nested_offset=metadata.tables.data_offset;
    for(std::uint8_t id=0;id<41;++id)
      if(const auto rows_it=metadata.tables.row_counts.find(id);rows_it!=metadata.tables.row_counts.end())
        if(const auto size_it=metadata.tables.row_sizes.find(id);size_it!=metadata.tables.row_sizes.end())
          nested_offset+=std::uint64_t{rows_it->second}*size_it->second;
    if(nested_row==metadata.tables.row_sizes.end() || nested_row->second!=2*type_index_width ||
       nested_offset>tables.size() || std::uint64_t{nested_count}*nested_row->second>tables.size()-nested_offset)
      return malformed("CLR NestedClass rows exceed tables stream or have an inconsistent layout");
    for(std::uint32_t n=0;n<nested_count;++n) {
      const auto at=static_cast<std::size_t>(nested_offset+std::uint64_t{n}*nested_row->second);
      const auto child=type_index_width==2?u16(tables,at):u32(tables,at);
      const auto parent=type_index_width==2?u16(tables,at+type_index_width):u32(tables,at+type_index_width);
      if(!child || child>type_count || !parent || parent>type_count || child==parent)
        return malformed("CLR NestedClass contains an invalid or self-referential TypeDef index");
      auto &nested=result[child-1];
      if(nested.enclosing_type_token)
        return malformed("CLR TypeDef appears more than once in NestedClass");
      nested.enclosing_type_token=0x02000000u|parent;
    }
    // Resolve chains iteratively to keep nesting depth independent of the C++
    // call stack. A cycle makes every name on that chain ambiguous.
    std::vector<std::uint8_t> name_state(result.size());
    for(std::size_t start=0;start<result.size();++start) {
      if(name_state[start]==2)continue;
      std::vector<std::size_t> path;
      auto current=start;
      while(name_state[current]!=2) {
        if(name_state[current]==1)return malformed("CLR NestedClass relationships contain a cycle");
        name_state[current]=1;
        path.push_back(current);
        const auto enclosing=result[current].enclosing_type_token;
        if(!enclosing) { name_state[current]=2; break; }
        const auto parent=type_by_token.find(enclosing);
        if(parent==type_by_token.end())return malformed("CLR NestedClass enclosing TypeDef is unresolved");
        current=parent->second;
      }
      for(auto it=path.rbegin();it!=path.rend();++it) {
        auto &type=result[*it];
        if(type.enclosing_type_token) {
          const auto parent=type_by_token.find(type.enclosing_type_token);
          if(parent==type_by_token.end() || name_state[parent->second]!=2)
            return malformed("CLR NestedClass enclosing TypeDef name is unresolved");
          type.full_name=result[parent->second].full_name+"+"+type.name;
        }
        name_state[*it]=2;
      }
    }
  }
  for(auto &parameter:generic_parameters.value())if((parameter.owner_token>>24)==2){
    const auto owner=type_by_token.find(parameter.owner_token);
    if(owner==type_by_token.end())return malformed("GenericParam TypeDef owner is absent from the parsed type catalog");
    result[owner->second].generic_parameters.push_back(std::move(parameter));
  }
  for(auto &type:result)std::sort(type.generic_parameters.begin(),type.generic_parameters.end(),[](const auto &a,const auto &b){return a.number<b.number;});
  return result;
}

Result<ManagedTypeCatalog> parse_managed_type_catalog(std::span<const std::byte> root){
  auto metadata_result=parse_cli_metadata(root);if(!metadata_result)return metadata_result.error();
  const auto& metadata=metadata_result.value();
  auto definitions=parse_managed_types(root);if(!definitions)return definitions.error();
  ManagedTypeCatalog catalog;catalog.definitions=std::move(definitions.value());
  auto table_it=metadata.streams.find("#~");if(table_it==metadata.streams.end())table_it=metadata.streams.find("#-");
  const auto strings_it=metadata.streams.find("#Strings"),blob_it=metadata.streams.find("#Blob");
  if(table_it==metadata.streams.end()||strings_it==metadata.streams.end()||blob_it==metadata.streams.end())
    return malformed("Managed type catalog requires tables, #Strings, and #Blob heaps");
  const auto tables=root.subspan(table_it->second.offset,table_it->second.size);
  const auto strings=root.subspan(strings_it->second.offset,strings_it->second.size);
  const auto blobs=root.subspan(blob_it->second.offset,blob_it->second.size);
  const auto rows=[&](std::uint8_t id){const auto found=metadata.tables.row_counts.find(id);return found==metadata.tables.row_counts.end()?0u:found->second;};
  const auto index_width=[&](std::uint8_t id){return rows(id)<65536?2u:4u;};
  const auto table_offset=[&](std::uint8_t id){std::uint64_t offset=metadata.tables.data_offset;for(std::uint8_t table=0;table<id;++table)if(auto found=metadata.tables.row_counts.find(table);found!=metadata.tables.row_counts.end())offset+=std::uint64_t{found->second}*metadata.tables.row_sizes.at(table);return offset;};
  const auto read_index=[](std::span<const std::byte> bytes,std::size_t at,unsigned width){return width==2?std::uint32_t(u16(bytes,at)):u32(bytes,at);};
  const auto read_string=[&](std::uint32_t index)->Result<std::string>{
    if(!index)return std::string{};if(index>=strings.size())return malformed("Managed type string index exceeds #Strings heap");
    std::string value;for(std::size_t at=index;at<strings.size();++at){const auto ch=std::to_integer<unsigned char>(strings[at]);if(!ch)return value;value.push_back(static_cast<char>(ch));if(value.size()>4096)return Error{ErrorCode::resource_limit,"Managed type name exceeds 4096 bytes"};}
    return malformed("Managed type string is unterminated in #Strings heap");
  };
  const auto read_blob=[&](std::uint32_t index)->Result<std::vector<std::byte>>{
    if(!index)return std::vector<std::byte>{};
    if(index>=blobs.size())return malformed("Managed type blob index exceeds #Blob heap");
    std::size_t at=index;auto length=compressed_uint(blobs,at);if(!length)return length.error();
    if(length.value()>blobs.size()-at)return malformed("Managed identity blob exceeds #Blob heap");
    return std::vector<std::byte>(blobs.begin()+static_cast<std::ptrdiff_t>(at),
                                  blobs.begin()+static_cast<std::ptrdiff_t>(at+length.value()));
  };
  const auto assembly_count=rows(32);
  if(assembly_count>1)return malformed("Assembly table has more than one identity row");
  const auto string_width=(metadata.tables.heap_sizes&1)?4u:2u,blob_width=(metadata.tables.heap_sizes&4)?4u:2u;
  if(assembly_count){
    const auto row=metadata.tables.row_sizes.find(32);const auto offset=table_offset(32);
    if(row==metadata.tables.row_sizes.end()||row->second!=16+blob_width+2*string_width||offset>tables.size()||row->second>tables.size()-offset)
      return malformed("Assembly identity row exceeds tables stream");
    const auto at=static_cast<std::size_t>(offset);ManagedAssemblyIdentity identity;
    identity.major=u16(tables,at+4);identity.minor=u16(tables,at+6);identity.build=u16(tables,at+8);identity.revision=u16(tables,at+10);identity.flags=u32(tables,at+12);
    auto key=read_blob(read_index(tables,at+16,blob_width));if(!key)return key.error();identity.public_key_or_token=std::move(key.value());
    auto name=read_string(read_index(tables,at+16+blob_width,string_width));if(!name)return name.error();identity.name=std::move(name.value());
    auto culture=read_string(read_index(tables,at+16+blob_width+string_width,string_width));if(!culture)return culture.error();identity.culture=std::move(culture.value());
    if(identity.name.empty())return malformed("Assembly identity has an empty name");catalog.assembly_identity=std::move(identity);
  }
  const auto type_ref_count=rows(1);
  if(type_ref_count>1000000)return Error{ErrorCode::resource_limit,"TypeRef row limit exceeded"};
  if(type_ref_count){
    const auto row=metadata.tables.row_sizes.find(1);const auto offset=table_offset(1);const auto scope_width=coded_width(0,metadata.tables.row_counts);
    if(row==metadata.tables.row_sizes.end()||row->second!=scope_width+2*string_width||offset>tables.size()||std::uint64_t{type_ref_count}*row->second>tables.size()-offset)
      return malformed("TypeRef rows exceed tables stream or have inconsistent layout");
    catalog.references.reserve(type_ref_count);
    for(std::uint32_t n=0;n<type_ref_count;++n){const auto at=static_cast<std::size_t>(offset+std::uint64_t{n}*row->second);ManagedTypeReference ref;ref.token=0x01000000u|(n+1);const auto coded=read_index(tables,at,scope_width);ref.resolution_scope_coded_index=coded;const auto tag=coded&3u,rid=coded>>2;
      if(!coded){ref.resolution_scope_kind=ManagedTypeResolutionScopeKind::null_scope;ref.unresolved_scope="null scope; ExportedType implementation unresolved";ref.external_scope_unresolved=true;}
      else if(!rid)return malformed("TypeRef has a null non-module resolution scope");
      else if(tag==0){if(rid>rows(0))return malformed("TypeRef Module resolution scope is out of range");ref.resolution_scope_kind=ManagedTypeResolutionScopeKind::module;ref.resolution_scope_token=rid;}
      else if(tag==1){if(rid>rows(26))return malformed("TypeRef ModuleRef resolution scope is out of range");ref.resolution_scope_kind=ManagedTypeResolutionScopeKind::module_ref;ref.resolution_scope_token=0x1a000000u|rid;ref.external_scope_unresolved=true;const auto module_row=metadata.tables.row_sizes.find(26);const auto module_offset=module_row==metadata.tables.row_sizes.end()?UINT64_MAX:table_offset(26)+std::uint64_t{rid-1}*module_row->second;if(module_row==metadata.tables.row_sizes.end()||module_offset>tables.size()||module_row->second>tables.size()-module_offset)return malformed("TypeRef ModuleRef row exceeds tables stream");const auto module_name=read_string(read_index(tables,static_cast<std::size_t>(module_offset),string_width));if(!module_name)return module_name.error();ref.unresolved_scope="module:"+module_name.value();}
      else if(tag==2){if(rid>rows(35))return malformed("TypeRef AssemblyRef resolution scope is out of range");ref.resolution_scope_kind=ManagedTypeResolutionScopeKind::assembly_ref;ref.resolution_scope_token=0x23000000u|rid;ref.external_scope_unresolved=true;const auto assembly_row=metadata.tables.row_sizes.find(35);const auto assembly_offset=assembly_row==metadata.tables.row_sizes.end()?UINT64_MAX:table_offset(35)+std::uint64_t{rid-1}*assembly_row->second;if(assembly_row==metadata.tables.row_sizes.end()||assembly_offset>tables.size()||assembly_row->second>tables.size()-assembly_offset)return malformed("TypeRef AssemblyRef row exceeds tables stream");const auto aa=static_cast<std::size_t>(assembly_offset);ManagedAssemblyIdentity identity;identity.major=u16(tables,aa);identity.minor=u16(tables,aa+2);identity.build=u16(tables,aa+4);identity.revision=u16(tables,aa+6);identity.flags=u32(tables,aa+8);auto key=read_blob(read_index(tables,aa+12,blob_width));if(!key)return key.error();identity.public_key_or_token=std::move(key.value());auto assembly_name=read_string(read_index(tables,aa+12+blob_width,string_width));if(!assembly_name)return assembly_name.error();identity.name=std::move(assembly_name.value());auto culture=read_string(read_index(tables,aa+12+blob_width+string_width,string_width));if(!culture)return culture.error();identity.culture=std::move(culture.value());if(identity.name.empty())return malformed("AssemblyRef has an empty name");ref.unresolved_scope="assembly:"+identity.name;ref.assembly_scope=std::move(identity);}
      else {if(rid>type_ref_count)return malformed("Nested TypeRef resolution scope is out of range");ref.resolution_scope_kind=ManagedTypeResolutionScopeKind::nested_type_ref;ref.resolution_scope_token=0x01000000u|rid;}
      const auto name_at=at+scope_width;auto name=read_string(read_index(tables,name_at,string_width));if(!name)return name.error();auto ns=read_string(read_index(tables,name_at+string_width,string_width));if(!ns)return ns.error();if(name.value().empty())return malformed("TypeRef has an empty name");ref.name=std::move(name.value());ref.namespace_name=std::move(ns.value());catalog.references.push_back(std::move(ref));
    }
    std::vector<std::uint8_t> state(catalog.references.size());
    for(std::size_t start=0;start<catalog.references.size();++start){if(state[start]==2)continue;std::vector<std::size_t> path;auto current=start;while(state[current]!=2){if(state[current]==1)return malformed("TypeRef nested resolution scopes contain a cycle");state[current]=1;path.push_back(current);const auto& ref=catalog.references[current];if(ref.resolution_scope_kind!=ManagedTypeResolutionScopeKind::nested_type_ref){state[current]=2;break;}current=(ref.resolution_scope_token&0x00ffffffu)-1;}
      for(auto it=path.rbegin();it!=path.rend();++it){auto& ref=catalog.references[*it];if(ref.resolution_scope_kind==ManagedTypeResolutionScopeKind::nested_type_ref){const auto parent=(ref.resolution_scope_token&0x00ffffffu)-1;if(parent>=catalog.references.size()||state[parent]!=2)return malformed("Nested TypeRef parent is unresolved");const auto& outer=catalog.references[parent];ref.full_name=outer.full_name+"+"+ref.name;ref.external_scope_unresolved=outer.external_scope_unresolved;ref.unresolved_scope=outer.unresolved_scope;ref.assembly_scope=outer.assembly_scope;}else ref.full_name=ref.namespace_name.empty()?ref.name:ref.namespace_name+"."+ref.name;state[*it]=2;}
    }
  }
  const auto spec_count=rows(27);
  if(spec_count>1000000)return Error{ErrorCode::resource_limit,"TypeSpec row limit exceeded"};
  const auto spec_row=metadata.tables.row_sizes.find(27);const auto spec_offset=table_offset(27);const auto spec_blob_width=(metadata.tables.heap_sizes&4)?4u:2u;
  if(spec_count&&(spec_row==metadata.tables.row_sizes.end()||spec_row->second!=spec_blob_width||spec_offset>tables.size()||std::uint64_t{spec_count}*spec_row->second>tables.size()-spec_offset))return malformed("TypeSpec rows exceed tables stream or have inconsistent layout");
  catalog.specifications.reserve(spec_count);
  for(std::uint32_t n=0;n<spec_count;++n){const auto at=static_cast<std::size_t>(spec_offset+std::uint64_t{n}*spec_row->second);const auto index=read_index(tables,at,spec_blob_width);if(!index||index>=blobs.size())return malformed("TypeSpec signature blob index is outside #Blob heap");std::size_t p=index;auto size=compressed_uint(blobs,p);if(!size)return size.error();if(size.value()>blobs.size()-p)return malformed("TypeSpec signature exceeds #Blob heap");auto bytes=blobs.subspan(p,size.value());std::size_t q=0;auto signature=signature_type(bytes,q,0);if(!signature)return signature.error();if(q!=bytes.size())return malformed("Trailing bytes in TypeSpec signature");catalog.specifications.push_back({0x1b000000u|(n+1),std::move(signature.value())});}
  std::set<std::uint32_t> active_specs;std::size_t resolution_budget=100000;
  for(auto& spec:catalog.specifications){active_specs.insert(spec.token);auto resolved=resolve_type_signature(spec.signature,catalog,active_specs,0,resolution_budget);active_specs.erase(spec.token);if(!resolved)return resolved.error();}
  const auto interface_count=rows(9);
  if(interface_count>1000000)return Error{ErrorCode::resource_limit,"InterfaceImpl row limit exceeded"};
  if(interface_count){
    const auto row=metadata.tables.row_sizes.find(9);const auto offset=table_offset(9);
    const auto type_width=index_width(2),interface_width=coded_width(2,metadata.tables.row_counts);
    if(row==metadata.tables.row_sizes.end()||row->second!=type_width+interface_width||offset>tables.size()||std::uint64_t{interface_count}*row->second>tables.size()-offset)
      return malformed("InterfaceImpl rows exceed tables stream or have inconsistent layout");
    std::map<std::uint32_t,ManagedTypeDefinition*> definitions_by_token;
    for(auto& definition:catalog.definitions)definitions_by_token.emplace(definition.token,&definition);
    std::set<std::pair<std::uint32_t,std::uint32_t>> unique_edges;
    for(std::uint32_t i=0;i<interface_count;++i){const auto at=static_cast<std::size_t>(offset+std::uint64_t{i}*row->second);const auto owner=read_index(tables,at,type_width);const auto coded=read_index(tables,at+type_width,interface_width);const auto rid=coded>>2,tag=coded&3u;
      if(!owner||owner>rows(2)||!rid||tag==3)return malformed("InterfaceImpl row has an invalid TypeDefOrRef index");
      const auto target_table=tag==0?2u:tag==1?1u:27u;if(rid>rows(static_cast<std::uint8_t>(target_table)))return malformed("InterfaceImpl target is outside its metadata table");
      const auto owner_token=0x02000000u|owner,target_token=(target_table<<24)|rid;
      if(!unique_edges.emplace(owner_token,target_token).second)return malformed("Duplicate InterfaceImpl edge");
      if(auto found=definitions_by_token.find(owner_token);found!=definitions_by_token.end())found->second->interface_tokens.push_back(target_token);
    }
  }
  return catalog;
}

bool managed_type_is_assignable(const ManagedTypeCatalog& catalog,std::uint32_t candidate,std::uint32_t target){
  if(!candidate||!target)return false;
  if(candidate==target)return true;
  std::map<std::uint32_t,const ManagedTypeDefinition*> definitions;
  for(const auto& definition:catalog.definitions)definitions.emplace(definition.token,&definition);
  std::vector<std::uint32_t> pending{candidate};std::set<std::uint32_t> visited;std::size_t budget=100000;
  while(!pending.empty()&&budget--){const auto token=pending.back();pending.pop_back();if(!visited.insert(token).second)continue;
    const auto found=definitions.find(token);if(found==definitions.end())continue;
    const auto add=[&](std::uint32_t edge){if(edge==target)return true;if(definitions.contains(edge)&&!visited.contains(edge))pending.push_back(edge);return false;};
    if(found->second->base_type_token&&add(found->second->base_type_token))return true;
    for(const auto edge:found->second->interface_tokens)if(add(edge))return true;
  }
  return false;
}

namespace {
bool assembly_scope_matches(const ManagedAssemblyIdentity& requested,const ManagedAssemblyIdentity& candidate){
  const auto equal_folded=[](std::string_view a,std::string_view b){
    if(a.size()!=b.size())return false;
    for(std::size_t i=0;i<a.size();++i){auto x=static_cast<unsigned char>(a[i]),y=static_cast<unsigned char>(b[i]);
      if(x>='A'&&x<='Z')x=static_cast<unsigned char>(x+('a'-'A'));
      if(y>='A'&&y<='Z')y=static_cast<unsigned char>(y+('a'-'A'));
      if(x!=y)return false;
    }
    return true;
  };
  return equal_folded(requested.name,candidate.name)&&equal_folded(requested.culture,candidate.culture)&&
    requested.major==candidate.major&&requested.minor==candidate.minor&&requested.build==candidate.build&&
    requested.revision==candidate.revision&&requested.flags==candidate.flags&&
    requested.public_key_or_token==candidate.public_key_or_token;
}
using ManagedTypeNode=std::pair<std::uint32_t,std::uint32_t>;
std::optional<ManagedTypeNode> bound_type_node(const ManagedTypeCatalog& catalog,std::uint32_t catalog_index,
                                                std::uint32_t token){
  if((token>>24)==2)return ManagedTypeNode{catalog_index,token};
  if((token>>24)!=1)return std::nullopt;
  const auto found=std::find_if(catalog.references.begin(),catalog.references.end(),
                                [&](const auto& reference){return reference.token==token;});
  if(found==catalog.references.end()||!found->resolved_catalog_index||!found->resolved_definition_token)return std::nullopt;
  return ManagedTypeNode{*found->resolved_catalog_index,*found->resolved_definition_token};
}
}

Result<bool> bind_managed_type_references(std::span<ManagedTypeCatalog> catalogs){
  if(catalogs.size()>4096)return Error{ErrorCode::resource_limit,"Managed assembly binding exceeds 4096 catalogs"};
  for(auto& source:catalogs)for(auto& reference:source.references){
    reference.resolved_catalog_index.reset();reference.resolved_definition_token.reset();
    if(!reference.assembly_scope)continue;
    std::optional<std::uint32_t> target_catalog;std::size_t assembly_matches=0;
    for(std::uint32_t i=0;i<catalogs.size();++i){
      const auto& identity=catalogs[i].assembly_identity;
      if(identity&&assembly_scope_matches(*reference.assembly_scope,*identity)){target_catalog=i;++assembly_matches;}
    }
    if(assembly_matches!=1)continue;
    std::optional<std::uint32_t> target_definition;std::size_t type_matches=0;
    for(const auto& definition:catalogs[*target_catalog].definitions)
      if(definition.full_name==reference.full_name){target_definition=definition.token;++type_matches;}
    if(type_matches==1){reference.resolved_catalog_index=*target_catalog;reference.resolved_definition_token=*target_definition;}
  }
  return true;
}

bool managed_type_is_assignable_across_catalogs(std::span<const ManagedTypeCatalog> catalogs,
                                                 std::uint32_t candidate_catalog,std::uint32_t candidate,
                                                 std::uint32_t target_catalog,std::uint32_t target){
  if(!candidate||!target||candidate_catalog>=catalogs.size()||target_catalog>=catalogs.size())return false;
  const ManagedTypeNode wanted{target_catalog,target};
  std::vector<ManagedTypeNode> pending{{candidate_catalog,candidate}};
  std::set<ManagedTypeNode> visited;std::size_t budget=100000;
  while(!pending.empty()&&budget--){
    const auto node=pending.back();pending.pop_back();if(node==wanted)return true;
    if(!visited.insert(node).second||node.first>=catalogs.size())continue;
    const auto& catalog=catalogs[node.first];
    const auto definition=std::find_if(catalog.definitions.begin(),catalog.definitions.end(),
                                       [&](const auto& value){return value.token==node.second;});
    if(definition==catalog.definitions.end())continue;
    const auto add=[&](std::uint32_t edge){
      if(auto resolved=bound_type_node(catalog,node.first,edge);resolved&&!visited.contains(*resolved))pending.push_back(*resolved);
    };
    if(definition->base_type_token)add(definition->base_type_token);
    for(const auto edge:definition->interface_tokens)add(edge);
  }
  return false;
}

Result<std::vector<ManagedField>> parse_managed_fields(std::span<const std::byte> root){
  auto parsed=parse_cli_metadata(root);if(!parsed)return parsed.error();
  const auto& metadata=parsed.value();
  const auto row_count=[&](std::uint8_t id){const auto it=metadata.tables.row_counts.find(id);return it==metadata.tables.row_counts.end()?0u:it->second;};
  const auto field_count=row_count(4),type_count=row_count(2),pointer_count=row_count(3);
  if(field_count>250000)return Error{ErrorCode::resource_limit,"CLR FieldDef catalog exceeds 250,000 rows"};
  if(pointer_count && pointer_count!=field_count)return malformed("CLR FieldPtr count does not match FieldDef count");
  if(!field_count)return std::vector<ManagedField>{};
  if(!type_count)return malformed("CLR FieldDef rows have no owning TypeDef rows");
  auto tables_it=metadata.streams.find("#~");if(tables_it==metadata.streams.end())tables_it=metadata.streams.find("#-");
  const auto strings_it=metadata.streams.find("#Strings"),blobs_it=metadata.streams.find("#Blob");
  if(tables_it==metadata.streams.end() || strings_it==metadata.streams.end() || blobs_it==metadata.streams.end())return malformed("CLR FieldDef parsing requires tables, #Strings, and #Blob heaps");
  const auto tables=root.subspan(tables_it->second.offset,tables_it->second.size),strings=root.subspan(strings_it->second.offset,strings_it->second.size),blobs=root.subspan(blobs_it->second.offset,blobs_it->second.size);
  const auto string_width=(metadata.tables.heap_sizes&1)?4u:2u,blob_width=(metadata.tables.heap_sizes&4)?4u:2u;
  const auto field_index_width=row_count(pointer_count?3:4)<65536?2u:4u;
  const auto field_row_it=metadata.tables.row_sizes.find(4);
  if(field_row_it==metadata.tables.row_sizes.end() || field_row_it->second!=2+string_width+blob_width)return malformed("CLR FieldDef row layout is inconsistent");
  std::uint64_t field_offset=metadata.tables.data_offset;
  for(std::uint8_t id=0;id<4;++id){const auto rows=metadata.tables.row_counts.find(id),size=metadata.tables.row_sizes.find(id);if(rows!=metadata.tables.row_counts.end() && size!=metadata.tables.row_sizes.end())field_offset+=std::uint64_t{rows->second}*size->second;}
  const auto field_row_size=field_row_it->second;
  if(field_offset>tables.size() || std::uint64_t{field_count}*field_row_size>tables.size()-field_offset)return malformed("CLR FieldDef rows exceed tables stream");
  const auto read_index=[&](std::span<const std::byte> bytes,std::size_t at,std::uint32_t width){return width==2?std::uint32_t(u16(bytes,at)):u32(bytes,at);};
  std::vector<std::uint32_t> order;order.reserve(field_count);
  if(pointer_count){
    std::uint64_t pointer_offset=metadata.tables.data_offset;
    for(std::uint8_t id=0;id<3;++id){const auto rows=metadata.tables.row_counts.find(id),size=metadata.tables.row_sizes.find(id);if(rows!=metadata.tables.row_counts.end() && size!=metadata.tables.row_sizes.end())pointer_offset+=std::uint64_t{rows->second}*size->second;}
    const auto pointer_size=metadata.tables.row_sizes.find(3);
    if(pointer_size==metadata.tables.row_sizes.end() || pointer_size->second!=field_index_width || pointer_offset>tables.size() || std::uint64_t{pointer_count}*field_index_width>tables.size()-pointer_offset)return malformed("CLR FieldPtr rows exceed tables stream");
    std::vector<bool> seen(field_count+1);
    for(std::uint32_t n=0;n<pointer_count;++n){const auto row=read_index(tables,static_cast<std::size_t>(pointer_offset+std::uint64_t{n}*field_index_width),field_index_width);if(!row || row>field_count || seen[row])return malformed("CLR FieldPtr contains an invalid or duplicate FieldDef index");seen[row]=true;order.push_back(row);}
  } else for(std::uint32_t row=1;row<=field_count;++row)order.push_back(row);
  auto type_catalog=parse_managed_type_catalog(root);if(!type_catalog)return type_catalog.error();
  auto type_offset=metadata.tables.data_offset;
  for(std::uint8_t id=0;id<2;++id){const auto rows=metadata.tables.row_counts.find(id),size=metadata.tables.row_sizes.find(id);if(rows!=metadata.tables.row_counts.end() && size!=metadata.tables.row_sizes.end())type_offset+=std::uint64_t{rows->second}*size->second;}
  const auto type_row_it=metadata.tables.row_sizes.find(2);
  const auto extends_width=coded_width(2,metadata.tables.row_counts);
  const auto field_list_offset=4+2*string_width+extends_width;
  const auto method_index_width=row_count(row_count(5)?5:6)<65536?2u:4u;
  if(type_row_it==metadata.tables.row_sizes.end() || type_row_it->second!=field_list_offset+field_index_width+method_index_width || type_offset>tables.size() || std::uint64_t{type_count}*type_row_it->second>tables.size()-type_offset)return malformed("CLR TypeDef field-list layout is inconsistent");
  std::vector<std::uint32_t> starts;starts.reserve(type_count);
  for(std::uint32_t i=0;i<type_count;++i){const auto at=static_cast<std::size_t>(type_offset+std::uint64_t{i}*type_row_it->second+field_list_offset);const auto first=read_index(tables,at,field_index_width);if(!first || first>field_count+1 || (!starts.empty() && first<starts.back()))return malformed("CLR TypeDef FieldList indexes are invalid or unsorted");starts.push_back(first);}
  if(starts.front()!=1)return malformed("CLR TypeDef FieldList does not begin at row one");
  std::vector<std::string> owners(field_count+1);std::vector<bool> assigned(field_count+1);
  for(std::size_t i=0;i<type_catalog.value().definitions.size();++i){const auto end=i+1<starts.size()?starts[i+1]:field_count+1;for(auto index=starts[i];index<end;++index){const auto row=order[index-1];if(assigned[row])return malformed("CLR FieldDef is owned by multiple TypeDefs");assigned[row]=true;owners[row]=type_catalog.value().definitions[i].full_name;}}
  if(std::find(assigned.begin()+1,assigned.end(),false)!=assigned.end())return malformed("CLR TypeDef FieldList leaves a FieldDef unowned");
  const auto read_string=[&](std::uint32_t index)->Result<std::string>{if(!index)return std::string{};if(index>=strings.size())return malformed("CLR FieldDef name index exceeds #Strings heap");std::string value;for(auto p=index;p<strings.size();++p){const auto ch=std::to_integer<unsigned char>(strings[p]);if(!ch)return value;value.push_back(static_cast<char>(ch));if(value.size()>4096)return Error{ErrorCode::resource_limit,"CLR FieldDef name exceeds 4096 bytes"};}return malformed("CLR FieldDef name is unterminated in #Strings heap");};
  std::vector<ManagedField> result;result.reserve(field_count);
  std::set<std::uint32_t> active_specs;std::size_t signature_budget=100000;
  for(std::uint32_t row=1;row<=field_count;++row){
    const auto at=static_cast<std::size_t>(field_offset+std::uint64_t{row-1}*field_row_size);
    ManagedField field;field.token=0x04000000u|row;field.flags=u16(tables,at);
    const auto name=read_string(read_index(tables,at+2,string_width));if(!name)return name.error();
    if(name.value().empty())return malformed("CLR FieldDef has an empty name");
    field.name=std::move(name.value());field.signature_index=read_index(tables,at+2+string_width,blob_width);field.declaring_type=owners[row];
    if(!field.signature_index||field.signature_index>=blobs.size())return malformed("CLR FieldDef signature index is outside #Blob heap");
    std::size_t blob_cursor=field.signature_index;auto blob_size=compressed_uint(blobs,blob_cursor);if(!blob_size)return blob_size.error();
    if(blob_size.value()>blobs.size()-blob_cursor)return malformed("CLR FieldDef signature exceeds #Blob heap");
    const auto bytes=blobs.subspan(blob_cursor,blob_size.value());
    auto signature=decode_managed_field_signature(bytes);
    if(!signature){
      if(signature.error().code!=ErrorCode::unsupported)return signature.error();
      field.signature_diagnostic=signature.error().message;
    }else{
      auto resolved=std::move(signature.value());
      const auto status=resolve_type_signature(resolved,type_catalog.value(),active_specs,0,signature_budget);
      if(!status)return status.error();
      field.type_signature=std::move(resolved);
    }
    result.push_back(std::move(field));
  }
  return result;
}

Result<std::vector<ManagedField>> parse_managed_field_references(std::span<const std::byte> root) {
  auto parsed=parse_cli_metadata(root);if(!parsed)return parsed.error();const auto& metadata=parsed.value();
  auto table_it=metadata.streams.find("#~");if(table_it==metadata.streams.end())table_it=metadata.streams.find("#-");
  if(table_it==metadata.streams.end())return malformed("CLR field-reference parsing requires a tables stream");
  const auto member_count=metadata.tables.row_counts.contains(10)?metadata.tables.row_counts.at(10):0u;
  if(member_count>250000)return Error{ErrorCode::resource_limit,"CLR MemberRef field catalog exceeds 250,000 rows"};
  if(!member_count)return std::vector<ManagedField>{};
  const auto strings_it=metadata.streams.find("#Strings"),blob_it=metadata.streams.find("#Blob");
  if(strings_it==metadata.streams.end()||blob_it==metadata.streams.end())return malformed("CLR field-reference parsing requires string/blob heaps");
  const auto tables=root.subspan(table_it->second.offset,table_it->second.size);
  const auto strings=root.subspan(strings_it->second.offset,strings_it->second.size);
  const auto blobs=root.subspan(blob_it->second.offset,blob_it->second.size);
  const auto rows=[&](std::uint8_t id){auto it=metadata.tables.row_counts.find(id);return it==metadata.tables.row_counts.end()?0u:it->second;};
  const auto table_offset=[&](std::uint8_t id){std::uint64_t off=metadata.tables.data_offset;for(std::uint8_t t=0;t<id;++t)if(auto r=metadata.tables.row_counts.find(t);r!=metadata.tables.row_counts.end())off+=std::uint64_t{r->second}*metadata.tables.row_sizes.at(t);return off;};
  const auto index=[&](std::span<const std::byte> b,std::size_t p,unsigned w){return w==2?std::uint32_t(u16(b,p)):u32(b,p);};
  const auto parent_width=coded_width(6,metadata.tables.row_counts),string_width=(metadata.tables.heap_sizes&1)?4u:2u,blob_width=(metadata.tables.heap_sizes&4)?4u:2u;
  const auto row_size=metadata.tables.row_sizes.find(10);if(row_size==metadata.tables.row_sizes.end()||row_size->second!=parent_width+string_width+blob_width)return malformed("CLR MemberRef row layout is inconsistent");
  const auto offset=table_offset(10);if(offset>tables.size()||std::uint64_t{member_count}*row_size->second>tables.size()-offset)return malformed("CLR MemberRef rows exceed tables stream");
  const auto read_string=[&](std::uint32_t value)->Result<std::string>{if(!value||value>=strings.size())return malformed("CLR MemberRef name index is invalid");std::string text;for(std::size_t p=value;p<strings.size();++p){const auto c=std::to_integer<unsigned char>(strings[p]);if(!c)return text;text.push_back(static_cast<char>(c));if(text.size()>4096)return Error{ErrorCode::resource_limit,"CLR MemberRef name exceeds 4096 bytes"};}return malformed("CLR MemberRef name is unterminated");};
  auto catalog=parse_managed_type_catalog(root);if(!catalog)return catalog.error();
  std::map<std::uint32_t,std::string> names;std::map<std::uint32_t,const ManagedTypeSpecification*> specs;
  for(const auto& item:catalog.value().definitions)names.emplace(item.token,item.full_name);
  for(const auto& item:catalog.value().references)names.emplace(item.token,item.full_name);
  for(const auto& item:catalog.value().specifications)specs.emplace(item.token,&item);
  std::map<std::uint32_t,std::string> method_owners;
  for(const auto& type:catalog.value().definitions)for(const auto token:type.method_tokens)method_owners.emplace(token,type.full_name);
  std::vector<ManagedField> result;std::size_t budget=100000;std::set<std::uint32_t> active_specs;
  for(std::uint32_t rid=1;rid<=member_count;++rid){
    const auto at=static_cast<std::size_t>(offset+std::uint64_t{rid-1}*row_size->second);
    const auto coded=index(tables,at,parent_width),tag=coded&7u,parent_rid=coded>>3;
    if(!parent_rid||tag>4)return malformed("CLR MemberRef has an invalid parent coded index");
    const auto name=read_string(index(tables,at+parent_width,string_width));if(!name)return name.error();
    const auto signature_index=index(tables,at+parent_width+string_width,blob_width);
    if(!signature_index||signature_index>=blobs.size())return malformed("CLR MemberRef signature index is invalid");
    std::size_t cursor=signature_index;auto size=compressed_uint(blobs,cursor);if(!size)return size.error();
    if(size.value()>blobs.size()-cursor)return malformed("CLR MemberRef signature exceeds #Blob heap");
    const auto bytes=blobs.subspan(cursor,size.value());if(bytes.empty()||std::to_integer<std::uint8_t>(bytes.front())!=0x06)continue;
    const std::uint32_t parent_table=tag==0?2u:tag==1?1u:tag==2?26u:tag==3?6u:27u;
    if(parent_rid>rows(static_cast<std::uint8_t>(parent_table)))return malformed("CLR MemberRef parent token is outside its metadata table");
    const auto parent_token=(parent_table<<24)|parent_rid;
    ManagedField field;field.token=0x0a000000u|rid;field.name=name.value();field.signature_index=signature_index;
    if(tag==0||tag==1){const auto owner=names.find(parent_token);if(owner==names.end())return malformed("CLR MemberRef owner type is unresolved");field.declaring_type=owner->second;}
    else if(tag==2)field.declaring_type="<module-ref:"+std::to_string(parent_rid)+">";
    else if(tag==3){const auto owner=method_owners.find(parent_token);if(owner==method_owners.end())return malformed("CLR MemberRef method owner is unresolved");field.declaring_type=owner->second;}
    else {const auto owner=specs.find(parent_token);if(owner==specs.end())return malformed("CLR MemberRef TypeSpec owner is unresolved");const auto* spec_root=resolved_type_spec_root(owner->second->signature);if(!spec_root)return Error{ErrorCode::resource_limit,"MemberRef TypeSpec nesting exceeds limit"};field.declaring_type=spec_root->metadata_type_name;if(const auto* instance=generic_instance_root(owner->second->signature)){field.declaring_type_arguments=instance->children;field.declaring_type_generic_arguments_valid=instance->generic_instance_arity_valid;}}
    auto signature=decode_managed_field_signature(bytes);
    if(!signature){if(signature.error().code!=ErrorCode::unsupported)return signature.error();field.signature_diagnostic=signature.error().message;}
    else {auto resolved=std::move(signature.value());auto status=resolve_type_signature(resolved,catalog.value(),active_specs,0,budget);if(!status)return status.error();field.type_signature=std::move(resolved);}
    result.push_back(std::move(field));
  }
  return result;
}

Result<std::vector<ManagedGenericParameter>> parse_managed_generic_parameters(std::span<const std::byte> root){
  auto parsed=parse_cli_metadata(root);if(!parsed)return parsed.error();
  const auto& metadata=parsed.value();
  const auto rows=[&](std::uint8_t id){const auto it=metadata.tables.row_counts.find(id);return it==metadata.tables.row_counts.end()?0u:it->second;};
  const auto row_size=[&](std::uint8_t id){const auto it=metadata.tables.row_sizes.find(id);return it==metadata.tables.row_sizes.end()?0u:it->second;};
  const auto table_offset=[&](std::uint8_t id){std::uint64_t offset=metadata.tables.data_offset;for(std::uint8_t table=0;table<id;++table)if(rows(table)&&row_size(table))offset+=std::uint64_t{rows(table)}*row_size(table);return offset;};
  const auto index_width=[&](std::uint32_t count){return count<65536?2u:4u;};
  const auto read_index=[](std::span<const std::byte> bytes,std::size_t at,unsigned width){return width==2?std::uint32_t(u16(bytes,at)):u32(bytes,at);};
  const auto generic_count=rows(42),constraint_count=rows(44);
  if(!generic_count){if(constraint_count)return malformed("GenericParamConstraint rows have no GenericParam owners");return std::vector<ManagedGenericParameter>{};}
  auto tables_it=metadata.streams.find("#~");if(tables_it==metadata.streams.end())tables_it=metadata.streams.find("#-");
  const auto strings_it=metadata.streams.find("#Strings");
  if(tables_it==metadata.streams.end()||strings_it==metadata.streams.end())return malformed("Generic parameter parsing requires tables and #Strings heaps");
  const auto tables=root.subspan(tables_it->second.offset,tables_it->second.size),strings=root.subspan(strings_it->second.offset,strings_it->second.size);
  const auto string_width=(metadata.tables.heap_sizes&1)?4u:2u;
  const auto owner_width=coded_width(12,metadata.tables.row_counts),constraint_owner_width=index_width(generic_count),type_width=coded_width(1,metadata.tables.row_counts);
  if(row_size(42)!=4+owner_width+string_width)return malformed("CLR GenericParam row layout is inconsistent");
  const auto generic_offset=table_offset(42),generic_bytes=std::uint64_t{generic_count}*row_size(42);
  if(generic_offset>tables.size()||generic_bytes>tables.size()-generic_offset)return malformed("CLR GenericParam rows exceed tables stream");
  const auto read_string=[&](std::uint32_t index)->Result<std::string>{
    if(!index)return std::string{};
    if(index>=strings.size())return malformed("GenericParam name index exceeds #Strings heap");
    std::string value;
    for(std::size_t p=index;p<strings.size();++p){const auto ch=std::to_integer<unsigned char>(strings[p]);if(!ch)return value;value.push_back(static_cast<char>(ch));if(value.size()>4096)return Error{ErrorCode::resource_limit,"GenericParam name exceeds 4096 bytes"};}
    return malformed("GenericParam name is unterminated in #Strings heap");
  };
  std::vector<ManagedGenericParameter> result;result.reserve(generic_count);
  std::map<std::uint32_t,std::set<std::uint16_t>> seen_numbers;
  for(std::uint32_t rid=1;rid<=generic_count;++rid){
    const auto at=static_cast<std::size_t>(generic_offset+std::uint64_t{rid-1}*row_size(42));
    ManagedGenericParameter parameter;parameter.token=0x2a000000u|rid;parameter.number=u16(tables,at);parameter.flags=u16(tables,at+2);
    if(parameter.flags&~std::uint16_t{0x001f})return malformed("GenericParam has reserved flag bits set");
    if((parameter.flags&0x0003)==0x0003)return malformed("GenericParam cannot be both covariant and contravariant");
    if((parameter.flags&0x000c)==0x000c)return malformed("GenericParam cannot require both reference-type and value-type constraints");
    const auto owner=read_index(tables,at+4,owner_width),tag=owner&1u,owner_rid=owner>>1;
    if(!owner_rid)return malformed("GenericParam has a null TypeOrMethodDef owner");
    const auto owner_table=tag?6u:2u;
    if(owner_rid>rows(static_cast<std::uint8_t>(owner_table)))return malformed("GenericParam owner token is outside its metadata table");
    parameter.owner_token=(owner_table<<24)|owner_rid;
    if(tag&&(parameter.flags&0x0003))return malformed("Method GenericParam cannot declare variance");
    auto name=read_string(read_index(tables,at+4+owner_width,string_width));if(!name)return name.error();parameter.name=std::move(name.value());
    if(parameter.number>1023)return Error{ErrorCode::resource_limit,"GenericParam number exceeds 1023"};
    if(!seen_numbers[parameter.owner_token].insert(parameter.number).second)return malformed("GenericParam owner has duplicate parameter numbers");
    result.push_back(std::move(parameter));
  }
  if(constraint_count){
    if(row_size(44)!=constraint_owner_width+type_width)return malformed("CLR GenericParamConstraint row layout is inconsistent");
    const auto offset=table_offset(44),byte_count=std::uint64_t{constraint_count}*row_size(44);
    if(offset>tables.size()||byte_count>tables.size()-offset)return malformed("CLR GenericParamConstraint rows exceed tables stream");
    for(std::uint32_t n=0;n<constraint_count;++n){
      const auto at=static_cast<std::size_t>(offset+std::uint64_t{n}*row_size(44));
      const auto owner=read_index(tables,at,constraint_owner_width),coded=read_index(tables,at+constraint_owner_width,type_width),tag=coded&3u,rid=coded>>2;
      if(!owner||owner>generic_count)return malformed("GenericParamConstraint owner index is outside GenericParam table");
      if(!rid||tag==3)return malformed("GenericParamConstraint has an invalid TypeDefOrRef token");
      const auto type_table=tag==0?2u:tag==1?1u:27u;
      if(rid>rows(static_cast<std::uint8_t>(type_table)))return malformed("GenericParamConstraint type token is outside its metadata table");
      result[owner-1].constraint_tokens.push_back((type_table<<24)|rid);
    }
  }
  return result;
}

Result<ManagedPeInfo> parse_managed_pe(const LoadedImage& loaded){
  if(!loaded.image || !loaded.metadata.pe)return Error{ErrorCode::invalid_argument,"Managed PE inspection requires a loaded PE image"};
  const auto it=std::find_if(loaded.metadata.directories.begin(),loaded.metadata.directories.end(),[](const Directory& d){return d.index==14;});
  if(it==loaded.metadata.directories.end() || !it->location || !it->size)return Error{ErrorCode::unsupported,"PE image has no CLR runtime directory"};
  if(it->size<72)return malformed("CLR runtime header is shorter than IMAGE_COR20_HEADER");
  const auto base=loaded.load_base.value_or(loaded.metadata.preferred_base);
  const auto va=checked_add(base,std::uint64_t{it->location});
  if(!va)return va.error();
  auto header=loaded.image->read({loaded.image->layout().space.id,va.value()},72);
  if(!header)return header.error();
  auto h=std::span<const std::byte>(header.value());
  const auto cb=u32(h,0);if(cb<72 || cb>it->size)return malformed("Invalid CLR runtime header size");
  const auto metadata_rva=u32(h,8),metadata_size=u32(h,12);
  if(!metadata_rva || !metadata_size || metadata_size>64*1024*1024)return malformed("Invalid CLR metadata RVA or size");
  const auto metadata_va=checked_add(base,std::uint64_t{metadata_rva});if(!metadata_va)return metadata_va.error();
  auto data=loaded.image->read({loaded.image->layout().space.id,metadata_va.value()},metadata_size);if(!data)return data.error();
  auto root=parse_cli_metadata(data.value());if(!root)return root.error();
  ManagedPeInfo out;out.major=u16(h,4);out.minor=u16(h,6);out.flags=u32(h,16);out.entry_point_token=u32(h,20);out.metadata=std::move(root.value());return out;
}

Result<std::vector<ManagedMethod>> parse_managed_methods(std::span<const std::byte> root){
  auto parsed=parse_cli_metadata(root);if(!parsed)return parsed.error();
  auto types=parse_managed_types(root);if(!types)return types.error();
  auto generic_parameters=parse_managed_generic_parameters(root);if(!generic_parameters)return generic_parameters.error();
  std::map<std::uint32_t,const ManagedTypeDefinition*> owners;for(const auto& type:types.value())for(auto token:type.method_tokens)owners.emplace(token,&type);
  std::map<std::uint32_t,std::vector<ManagedGenericParameter>> method_generics;
  for(const auto &parameter:generic_parameters.value())if((parameter.owner_token>>24)==6)method_generics[parameter.owner_token].push_back(parameter);
  for(auto &[token,parameters]:method_generics){(void)token;std::sort(parameters.begin(),parameters.end(),[](const auto &a,const auto &b){return a.number<b.number;});}
  const auto& metadata=parsed.value();auto table_it=metadata.streams.find("#~");if(table_it==metadata.streams.end())table_it=metadata.streams.find("#-");
  const auto strings_it=metadata.streams.find("#Strings");if(strings_it==metadata.streams.end())return malformed("CLR metadata has no #Strings heap");
  const auto count_it=metadata.tables.row_counts.find(6);if(count_it==metadata.tables.row_counts.end())return std::vector<ManagedMethod>{};
  const auto row_size_it=metadata.tables.row_sizes.find(6);if(row_size_it==metadata.tables.row_sizes.end())return malformed("CLR MethodDef table has no row layout");
  const auto tables=root.subspan(table_it->second.offset,table_it->second.size);const auto strings=root.subspan(strings_it->second.offset,strings_it->second.size);
  std::uint64_t row_offset=metadata.tables.data_offset;
  for(std::uint8_t id=0;id<6;++id){auto rows=metadata.tables.row_counts.find(id);auto width=metadata.tables.row_sizes.find(id);if(rows!=metadata.tables.row_counts.end() && width!=metadata.tables.row_sizes.end())row_offset+=std::uint64_t{rows->second}*width->second;}
  const auto count=count_it->second, row_size=row_size_it->second;const bool wide_strings=(metadata.tables.heap_sizes&1)!=0,wide_blobs=(metadata.tables.heap_sizes&4)!=0;
  const std::uint32_t string_width=wide_strings?4:2;
  if(row_offset>tables.size() || std::uint64_t{count}*row_size>tables.size()-row_offset)return malformed("CLR MethodDef rows exceed tables stream");
  std::vector<ManagedMethod> methods;methods.reserve(count);
  for(std::uint32_t i=0;i<count;++i){const auto at=static_cast<std::size_t>(row_offset+std::uint64_t{i}*row_size);ManagedMethod method;method.token=0x06000000u|(i+1);method.rva=u32(tables,at);method.impl_flags=u16(tables,at+4);method.flags=u16(tables,at+6);const auto name_at=at+8;const auto name_index=wide_strings?u32(tables,name_at):u16(tables,name_at);const auto blob_at=name_at+string_width;method.signature_index=wide_blobs?u32(tables,blob_at):u16(tables,blob_at);
    if(name_index){if(name_index>=strings.size())return malformed("CLR MethodDef name index exceeds #Strings heap");auto end=name_index;while(end<strings.size() && strings[end]!=std::byte{0})++end;if(end==strings.size())return malformed("CLR MethodDef name is unterminated in #Strings heap");method.name.reserve(end-name_index);for(auto p=name_index;p<end;++p)method.name.push_back(static_cast<char>(std::to_integer<unsigned char>(strings[p])));}
    if(const auto owner=owners.find(method.token);owner!=owners.end()){method.declaring_type=owner->second->full_name;method.declaring_type_generic_parameters=owner->second->generic_parameters;}
    if(const auto generic=method_generics.find(method.token);generic!=method_generics.end())method.generic_parameters=generic->second;
    methods.push_back(std::move(method));
  }
  return methods;
}

Result<CilMethodBody> parse_cil_method_body(std::span<const std::byte> b){
  if(b.empty())return malformed("Empty CIL method body");
  CilMethodBody out;const auto first=std::to_integer<std::uint8_t>(b[0]);
  std::size_t code_at=0;std::uint16_t flags=0;
  if((first&3)==2){out.code_size=first>>2;out.max_stack=8;code_at=1;}
  else if((first&3)==3){
    if(b.size()<12)return malformed("Truncated fat CIL method header");
    flags=u16(b,0);const auto dwords=(flags>>12)&15;
    if(dwords<3)return malformed("Fat CIL method header is shorter than three words");
    code_at=std::size_t(dwords)*4;if(code_at>b.size())return malformed("Fat CIL method header exceeds body");
    out.max_stack=u16(b,2);out.code_size=u32(b,4);out.local_signature_token=u32(b,8);out.init_locals=(flags&0x10)!=0;out.has_more_sections=(flags&0x08)!=0;
  } else return malformed("Unknown CIL method header format");
  if(out.code_size>16*1024*1024)return Error{ErrorCode::resource_limit,"CIL method exceeds 16 MiB inspection limit"};
  if(!fits(code_at,out.code_size,b.size()))return malformed("CIL instruction bytes exceed method body");
  out.il.assign(b.begin()+static_cast<std::ptrdiff_t>(code_at),b.begin()+static_cast<std::ptrdiff_t>(code_at+out.code_size));
  if(out.has_more_sections){
    std::size_t p=(code_at+out.code_size+3)&~std::size_t{3};unsigned sections=0;
    do {
      if(++sections>16)return Error{ErrorCode::resource_limit,"CIL method has too many extra sections"};
      if(!fits(p,4,b.size()))return malformed("Truncated CIL extra section");
      const auto kind=std::to_integer<std::uint8_t>(b[p]);const bool fat=(kind&0x40)!=0, more=(kind&0x80)!=0;
      const std::uint32_t size=fat?(std::uint32_t(std::to_integer<std::uint8_t>(b[p+1]))|(std::uint32_t(std::to_integer<std::uint8_t>(b[p+2]))<<8)|(std::uint32_t(std::to_integer<std::uint8_t>(b[p+3]))<<16)):std::to_integer<std::uint8_t>(b[p+1]);
      if(size<4 || !fits(p,size,b.size()))return malformed("Invalid CIL extra-section size");
      const auto section_kind=kind&0x3f;
      if(p>UINT32_MAX)return Error{ErrorCode::resource_limit,"CIL data-section offset exceeds inspection limit"};
      CilMethodDataSection section;
      section.offset=static_cast<std::uint32_t>(p);section.size=size;
      section.kind=static_cast<std::uint8_t>(section_kind);section.fat_encoding=fat;section.more_sections=more;
      section.first_clause=static_cast<std::uint32_t>(out.exception_clauses.size());
      if(section_kind==1){
        const auto clause_size=fat?24u:12u;
        if((size-4)%clause_size)return malformed("CIL exception section has partial clause");
        const auto count=(size-4)/clause_size;
        if(count>4096-out.exception_clauses.size())return Error{ErrorCode::resource_limit,"CIL method exceeds 4096 exception clauses"};
        section.clause_count=count;
        for(std::size_t at=p+4;at<p+size;at+=clause_size){
          const auto clause_flags=fat?u32(b,at):u16(b,at);
          const auto try_offset=fat?u32(b,at+4):u16(b,at+2);
          const auto try_length=fat?u32(b,at+8):std::to_integer<std::uint8_t>(b[at+4]);
          const auto handler_offset=fat?u32(b,at+12):u16(b,at+5);
          const auto handler_length=fat?u32(b,at+16):std::to_integer<std::uint8_t>(b[at+7]);
          const auto extra=fat?u32(b,at+20):u32(b,at+8);
          if(clause_flags!=0 && clause_flags!=1 && clause_flags!=2 && clause_flags!=4)
            return malformed("Unsupported or invalid CIL exception-clause flags");
          auto in_il=[&](std::uint32_t start,std::uint32_t length){return length!=0 && start<=out.code_size && length<=out.code_size-start;};
          if(!in_il(try_offset,try_length)||!in_il(handler_offset,handler_length))
            return malformed("CIL exception clause range exceeds method IL");
          CilExceptionClause clause;
          clause.raw_flags=clause_flags;clause.section_offset=section.offset;
          clause.clause_offset=static_cast<std::uint32_t>(at);clause.fat_encoding=fat;
          clause.try_offset=try_offset;clause.try_length=try_length;
          clause.handler_offset=handler_offset;clause.handler_length=handler_length;
          if(clause_flags==0){
            const auto table=extra>>24;
            if(extra==0 || (extra&0x00ffffffu)==0 || (table!=0x01 && table!=0x02 && table!=0x1b))return malformed("Invalid CIL catch type token");
            clause.kind=CilExceptionKind::catch_clause;clause.class_token=extra;
          } else if(clause_flags==1){
            if(extra>=out.code_size || extra>=handler_offset)return malformed("Invalid CIL exception filter range");
            clause.kind=CilExceptionKind::filter;clause.filter_offset=extra;
          } else {
            if(extra!=0)return malformed("Reserved CIL finally/fault clause field is nonzero");
            clause.kind=clause_flags==2?CilExceptionKind::finally_clause:CilExceptionKind::fault_clause;
          }
          out.exception_clauses.push_back(clause);
        }
      } else if(section_kind!=2) return Error{ErrorCode::unsupported,"Unsupported CIL method data-section kind"};
      out.data_sections.push_back(section);
      p+=size;if(more)p=(p+3)&~std::size_t{3};
      if(!more)break;
    } while(true);
  }
  return out;
}
}

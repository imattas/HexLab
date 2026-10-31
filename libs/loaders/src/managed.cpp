
#include "hexlab/loaders/managed.hpp"
#include "hexlab/loaders/loaded_image.hpp"
#include "hexlab/core/sha256.hpp"
#include "hexlab/image/byte_storage.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <compare>
#include <limits>
#include <set>
#include <string_view>
#include <tuple>

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
    V{306,100,102},V{2,302,102},V{303,311,102},V{304,102},V{2,305,102},V{2,4,202},V{4,204},V{102},V{202,220},V{220},V{2,100,301},
    V{202,223},V{223},V{2,100,102},V{2,206,307},V{202,308,308},V{100},V{102},V{2,309,100,226},V{4,204},V{4,4},V{4},
    V{4,2,2,2,2,4,102,100,100},V{4},V{4,4,4},V{2,2,2,2,4,102,100,100,102},V{4,235},V{4,4,4,235},V{4,100,102},V{4,4,100,100,310},
    V{4,4,100,310},V{202,308,308},V{2,2,312,100},V{308,102},V{242,301}
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
    else if(tag==1){if(rid>catalog.references.size())return malformed("Signature TypeRef token is out of range");const auto& ref=catalog.references[rid-1];signature.metadata_type_name=ref.full_name;signature.metadata_type_scope=ref.resolved_catalog_index&&ref.assembly_scope?"assembly:"+ref.assembly_scope->name:ref.unresolved_scope.empty()?"module":ref.unresolved_scope;signature.metadata_type_external_unresolved=ref.external_scope_unresolved;signature.resolved_type_catalog_index=ref.resolved_catalog_index;signature.resolved_type_definition_token=ref.resolved_definition_token;}
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
// Substitute only the two ECMA-335 generic-variable spaces for which a
// metadata owner supplies an ordered argument vector. Missing arguments are
// legal open variables and stay intact. Expansion is bounded independently
// from signature resolution so recursive argument trees cannot grow without
// limit.
Result<ManagedTypeSignature> substitute_signature(
    const ManagedTypeSignature& source,
    const std::vector<ManagedTypeSignature>& type_arguments,
    const std::vector<ManagedTypeSignature>& method_arguments,
    unsigned depth=0, std::size_t* budget_ptr=nullptr,
    std::set<std::uint64_t>* active_ptr=nullptr){
  std::size_t local_budget=100000;
  std::set<std::uint64_t> local_active;
  auto& budget=budget_ptr?*budget_ptr:local_budget;
  auto& active=active_ptr?*active_ptr:local_active;
  if(depth>16)return Error{ErrorCode::resource_limit,"Generic signature substitution nesting exceeds limit"};
  if(!budget--)return Error{ErrorCode::resource_limit,"Generic signature substitution node limit exceeded"};
  const auto* arguments=source.element_type==0x13?&type_arguments:
      source.element_type==0x1e?&method_arguments:nullptr;
  if(arguments&&source.generic_index<arguments->size()){
    const auto key=(std::uint64_t{source.element_type}<<32)|source.generic_index;
    if(!active.insert(key).second)return source;
    auto result=(*arguments)[source.generic_index];
    // Revisit the inserted argument so composed open substitutions resolve
    // transitively while unbound VAR/MVAR nodes remain explicit.
    if(result.element_type==0x13||result.element_type==0x1e){auto next=substitute_signature(result,type_arguments,method_arguments,depth+1,&budget,&active);active.erase(key);if(!next)return next.error();return next.value();}
    for(auto& child:result.children){auto next=substitute_signature(child,type_arguments,method_arguments,depth+1,&budget,&active);if(!next){active.erase(key);return next.error();}child=std::move(next.value());}
    if(result.type_spec_signature){auto next=substitute_signature(*result.type_spec_signature,type_arguments,method_arguments,depth+1,&budget,&active);if(!next){active.erase(key);return next.error();}result.type_spec_signature=std::make_shared<ManagedTypeSignature>(std::move(next.value()));}
    active.erase(key);
    return result;
  }
  auto result=source;
  for(auto& child:result.children){auto next=substitute_signature(child,type_arguments,method_arguments,depth+1,&budget,&active);if(!next)return next.error();child=std::move(next.value());}
  if(result.type_spec_signature){auto next=substitute_signature(*result.type_spec_signature,type_arguments,method_arguments,depth+1,&budget,&active);if(!next)return next.error();result.type_spec_signature=std::make_shared<ManagedTypeSignature>(std::move(next.value()));}
  return result;
}
std::optional<bool> same_property_type(const ManagedTypeSignature& left,
                                      const ManagedTypeSignature& right,unsigned depth=0){
  if(depth>16)return {};
  if(left.element_type!=right.element_type)return false;
  // The current array signature node retains rank but not its optional size
  // and lower-bound vectors, so rank equality alone is insufficient proof.
  if(left.element_type==0x14)return {};
  if(left.generic_index!=right.generic_index||
     left.metadata_type_token!=right.metadata_type_token||
     left.metadata_type_coded_index!=right.metadata_type_coded_index||
     left.generic_instance_is_value_type!=right.generic_instance_is_value_type||
     left.generic_instance_arity_valid!=right.generic_instance_arity_valid||
     left.array_rank!=right.array_rank||left.children.size()!=right.children.size()||
     bool(left.type_spec_signature)!=bool(right.type_spec_signature))return false;
  if(!left.generic_instance_arity_valid)return {};
  for(std::size_t i=0;i<left.children.size();++i){
    const auto equal=same_property_type(left.children[i],right.children[i],depth+1);
    if(!equal||!*equal)return equal;
  }
  if(left.type_spec_signature){
    const auto equal=same_property_type(*left.type_spec_signature,*right.type_spec_signature,depth+1);
    if(!equal||!*equal)return equal;
  }
  return true;
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

Result<ManagedLocalSignature> decode_managed_local_signature(std::span<const std::byte> b){
  if(b.empty()||std::to_integer<std::uint8_t>(b.front())!=0x07)
    return malformed("Invalid ECMA-335 LocalVarSig calling convention");
  std::size_t p=1;
  auto count=compressed_uint(b,p);if(!count)return count.error();
  if(count.value()>4096)return Error{ErrorCode::resource_limit,"ECMA-335 local variable count exceeds 4096"};
  ManagedLocalSignature result;result.reserve(count.value());
  for(std::uint32_t i=0;i<count.value();++i){
    bool pinned=false;
    if(p<b.size()&&std::to_integer<std::uint8_t>(b[p])==0x45){pinned=true;++p;}
    auto type=signature_type(b,p,0);if(!type)return type.error();
    result.push_back({std::move(type.value()),pinned});
  }
  if(p!=b.size())return malformed("Trailing bytes in ECMA-335 LocalVarSig");
  return result;
}

Result<ManagedPropertySignature> decode_managed_property_signature(std::span<const std::byte> b){
  if(b.empty()||(b[0]!=std::byte{0x08}&&b[0]!=std::byte{0x28}))return malformed("Invalid ECMA-335 PropertySig calling convention");
  std::size_t p=1;auto count=compressed_uint(b,p);if(!count)return count.error();
  if(count.value()>1024)return Error{ErrorCode::resource_limit,"PropertySig index parameter count exceeds 1024"};
  ManagedPropertySignature out;out.has_this=b[0]==std::byte{0x28};
  auto type=signature_type(b,p,0);if(!type)return type.error();out.property_type=std::move(type.value());
  out.index_parameter_types.reserve(count.value());
  for(std::uint32_t i=0;i<count.value();++i){auto parameter=signature_type(b,p,0);if(!parameter)return parameter.error();out.index_parameter_types.push_back(std::move(parameter.value()));}
  if(p!=b.size())return malformed("Trailing bytes in ECMA-335 PropertySig");
  return out;
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
  // Publish substituted signature trees only when the owner instantiation is
  // backed by an arity-checked local TypeDef.
  for(auto& [token,signature]:result){
    (void)token;
    bool type_identity_proven=signature.declaring_type_arguments.empty();
    if(!signature.declaring_type_arguments.empty()&&signature.declaring_type_generic_arguments_valid){
      const auto owner=specifications.find(signature.declaring_type_token);
      if(owner!=specifications.end())if(const auto* instance=generic_instance_root(owner->second->signature)){
        const auto constructed=instance->metadata_type_token;
        if((constructed>>24)==2)type_identity_proven=instance->generic_instance_arity_valid;
      }
    }
    if(!type_identity_proven)continue;
    std::size_t substitution_budget=100000;
    auto substitute=[&](ManagedTypeSignature& type)->Result<bool>{auto value=substitute_signature(type,signature.declaring_type_arguments,signature.method_spec_arguments,0,&substitution_budget);if(!value)return value.error();type=std::move(value.value());return true;};
    auto applied=substitute(signature.return_type);if(!applied)return applied.error();
    for(auto& parameter:signature.parameter_types){applied=substitute(parameter);if(!applied)return applied.error();}
  }
  return result;
}

Result<std::map<std::uint32_t,ManagedLocalSignature>> parse_managed_local_signatures(std::span<const std::byte> root){
  if(root.size()>64u*1024u*1024u)return Error{ErrorCode::resource_limit,"CLR local-signature root exceeds 64 MiB"};
  auto metadata=parse_cli_metadata(root);if(!metadata)return metadata.error();
  const auto table_it=metadata.value().streams.find("#~");
  const auto unoptimized=metadata.value().streams.find("#-");
  const auto blob_it=metadata.value().streams.find("#Blob");
  const auto tables_it=table_it!=metadata.value().streams.end()?table_it:unoptimized;
  if(tables_it==metadata.value().streams.end()||blob_it==metadata.value().streams.end())
    return malformed("Local-signature inspection requires tables and #Blob heaps");
  const auto rows_it=metadata.value().tables.row_counts.find(17);
  const auto count=rows_it==metadata.value().tables.row_counts.end()?0u:rows_it->second;
  if(count>65536)return Error{ErrorCode::resource_limit,"CLR StandAloneSig row limit exceeded"};
  if(!count)return std::map<std::uint32_t,ManagedLocalSignature>{};
  const auto tables=root.subspan(tables_it->second.offset,tables_it->second.size);
  const auto blob=root.subspan(blob_it->second.offset,blob_it->second.size);
  const auto row_size=metadata.value().tables.row_sizes.at(17);
  const auto blob_width=(metadata.value().tables.heap_sizes&4)?4u:2u;
  std::uint64_t offset=metadata.value().tables.data_offset;
  for(std::uint8_t table=0;table<17;++table)
    if(const auto rows=metadata.value().tables.row_counts.find(table);rows!=metadata.value().tables.row_counts.end())
      offset+=std::uint64_t{rows->second}*metadata.value().tables.row_sizes.at(table);
  if(offset>tables.size()||std::uint64_t{count}*row_size>tables.size()-offset)
    return malformed("StandAloneSig rows exceed tables stream");
  const auto read_index=[&](std::size_t at){return blob_width==2?std::uint32_t(u16(tables,at)):u32(tables,at);};
  auto catalog=parse_managed_type_catalog(root);if(!catalog)return catalog.error();
  std::map<std::uint32_t,ManagedLocalSignature> result;
  std::size_t signature_nodes=100000;
  for(std::uint32_t row=0;row<count;++row){
    const auto at=static_cast<std::size_t>(offset+std::uint64_t{row}*row_size);
    const auto index=read_index(at);
    if(!index||index>=blob.size())return malformed("StandAloneSig blob index is outside #Blob heap");
    std::size_t cursor=index;auto length=compressed_uint(blob,cursor);if(!length)return length.error();
    if(length.value()>blob.size()-cursor)return malformed("StandAloneSig blob exceeds #Blob heap");
    const auto bytes=blob.subspan(cursor,length.value());
    if(bytes.empty())return malformed("Empty StandAloneSig blob");
    if(std::to_integer<std::uint8_t>(bytes.front())!=0x07)continue;
    auto signature=decode_managed_local_signature(bytes);if(!signature)return signature.error();
    std::set<std::uint32_t> active_specs;
    for(auto& local:signature.value()){
      auto resolved=resolve_type_signature(local.type,catalog.value(),active_specs,0,signature_nodes);
      if(!resolved)return resolved.error();
    }
    result.emplace(0x11000000u|(row+1),std::move(signature.value()));
  }
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
  const auto class_layout_count=rows(15);
  if(class_layout_count) {
    const auto class_row=metadata.tables.row_sizes.find(15);
    const auto type_width=index_width(2);
    std::uint64_t class_offset=metadata.tables.data_offset;
    for(std::uint8_t id=0;id<15;++id)
      if(const auto count=metadata.tables.row_counts.find(id);count!=metadata.tables.row_counts.end())
        if(const auto size=metadata.tables.row_sizes.find(id);size!=metadata.tables.row_sizes.end())
          class_offset+=std::uint64_t{count->second}*size->second;
    if(class_row==metadata.tables.row_sizes.end() || class_row->second!=6+type_width ||
       class_offset>tables.size() || std::uint64_t{class_layout_count}*class_row->second>tables.size()-class_offset)
      return malformed("CLR ClassLayout rows exceed tables stream or have an inconsistent layout");
    std::vector<bool> seen(type_count+1);
    for(std::uint32_t n=0;n<class_layout_count;++n) {
      const auto at=static_cast<std::size_t>(class_offset+std::uint64_t{n}*class_row->second);
      const auto packing=u16(tables,at);
      const auto size=u32(tables,at+2);
      const auto parent=type_width==2?u16(tables,at+6):u32(tables,at+6);
      if(!parent || parent>type_count || seen[parent])
        return malformed("CLR ClassLayout has an invalid or duplicate TypeDef parent");
      if(packing && (packing>128 || (packing&(packing-1))))
        return malformed("CLR ClassLayout packing size is not a supported power of two");
      seen[parent]=true;
      auto &type=result[parent-1];type.packing_size=packing;type.declared_class_size=size;
      type.layout_metadata_offset=std::uint64_t{table_it->second.offset}+class_offset+std::uint64_t{n}*class_row->second;
    }
  }
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
    identity.hash_algorithm_id=u32(tables,at);
    identity.metadata_offset=table_it->second.offset+offset;
    identity.major=u16(tables,at+4);identity.minor=u16(tables,at+6);identity.build=u16(tables,at+8);identity.revision=u16(tables,at+10);identity.flags=u32(tables,at+12);
    const auto key_index=read_index(tables,at+16,blob_width);
    identity.public_key_blob_index=key_index;
    if(key_index){
      std::size_t key_cursor=key_index;auto key_size=compressed_uint(blobs,key_cursor);if(!key_size)return key_size.error();
      if(key_size.value()>blobs.size()-key_cursor)return malformed("Assembly public-key blob exceeds #Blob heap");
      if(key_size.value()>1024u*1024u)return Error{ErrorCode::resource_limit,"Assembly public key exceeds 1 MiB"};
      identity.public_key_blob_offset=blob_it->second.offset+key_cursor;
    }
    auto key=read_blob(key_index);if(!key)return key.error();identity.public_key_or_token=std::move(key.value());
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
  const auto exported_count=rows(39);
  if(exported_count>250000)return Error{ErrorCode::resource_limit,"ExportedType row limit exceeded"};
  if(exported_count){
    const auto row=metadata.tables.row_sizes.find(39);
    const auto offset=table_offset(39);
    const auto implementation_width=coded_width(10,metadata.tables.row_counts);
    if(row==metadata.tables.row_sizes.end()||row->second!=8+2*string_width+implementation_width||
       offset>tables.size()||std::uint64_t{exported_count}*row->second>tables.size()-offset)
      return malformed("ExportedType rows exceed tables stream or have inconsistent layout");
    catalog.exported_types.reserve(exported_count);
    for(std::uint32_t n=0;n<exported_count;++n){
      const auto at=static_cast<std::size_t>(offset+std::uint64_t{n}*row->second);
      ManagedExportedType type;type.token=0x27000000u|(n+1);
      type.flags=u32(tables,at);type.type_def_id=u32(tables,at+4);
      auto name=read_string(read_index(tables,at+8,string_width));if(!name)return name.error();
      auto ns=read_string(read_index(tables,at+8+string_width,string_width));if(!ns)return ns.error();
      if(name.value().empty())return malformed("ExportedType has an empty name");
      type.name=std::move(name.value());type.namespace_name=std::move(ns.value());
      const auto coded=read_index(tables,at+8+2*string_width,implementation_width);
      type.implementation_coded_index=coded;
      const auto tag=coded&3u,rid=coded>>2;
      if(!rid||tag==3)return malformed("ExportedType has an invalid Implementation coded index");
      if(tag==0){
        if(rid>rows(38))return malformed("ExportedType File implementation is out of range");
        type.implementation_kind=ManagedExportedTypeImplementationKind::file;
        type.implementation_token=0x26000000u|rid;
      }else if(tag==1){
        if(rid>rows(35))return malformed("ExportedType AssemblyRef implementation is out of range");
        type.implementation_kind=ManagedExportedTypeImplementationKind::assembly_ref;
        type.implementation_token=0x23000000u|rid;
        const auto assembly_row=metadata.tables.row_sizes.find(35);
        const auto assembly_offset=assembly_row==metadata.tables.row_sizes.end()?UINT64_MAX:table_offset(35)+std::uint64_t{rid-1}*assembly_row->second;
        if(assembly_row==metadata.tables.row_sizes.end()||assembly_row->second!=12+blob_width+2*string_width||
           assembly_offset>tables.size()||assembly_row->second>tables.size()-assembly_offset)
          return malformed("ExportedType AssemblyRef row exceeds tables stream");
        const auto aa=static_cast<std::size_t>(assembly_offset);ManagedAssemblyIdentity identity;
        identity.major=u16(tables,aa);identity.minor=u16(tables,aa+2);
        identity.build=u16(tables,aa+4);identity.revision=u16(tables,aa+6);identity.flags=u32(tables,aa+8);
        auto key=read_blob(read_index(tables,aa+12,blob_width));if(!key)return key.error();
        identity.public_key_or_token=std::move(key.value());
        auto assembly_name=read_string(read_index(tables,aa+12+blob_width,string_width));if(!assembly_name)return assembly_name.error();
        identity.name=std::move(assembly_name.value());
        auto culture=read_string(read_index(tables,aa+12+blob_width+string_width,string_width));if(!culture)return culture.error();
        identity.culture=std::move(culture.value());
        if(identity.name.empty())return malformed("ExportedType AssemblyRef has an empty name");
        type.assembly_scope=std::move(identity);
        type.forwarding_valid=(type.flags&0x00200000u)!=0;
      }else{
        if(rid>exported_count)return malformed("Nested ExportedType implementation is out of range");
        if(!type.namespace_name.empty())return malformed("Nested ExportedType has a namespace");
        type.implementation_kind=ManagedExportedTypeImplementationKind::exported_type;
        type.implementation_token=0x27000000u|rid;
      }
      catalog.exported_types.push_back(std::move(type));
    }
    std::vector<std::uint8_t> state(exported_count);
    std::set<std::string> names;
    for(std::size_t start=0;start<exported_count;++start){
      if(state[start]==2)continue;
      std::vector<std::size_t> path;auto current=start;
      while(state[current]!=2){
        if(state[current]==1)return malformed("ExportedType implementations contain a cycle");
        state[current]=1;path.push_back(current);
        const auto& type=catalog.exported_types[current];
        if(type.implementation_kind!=ManagedExportedTypeImplementationKind::exported_type)break;
        current=(type.implementation_token&0x00ffffffu)-1;
      }
      for(auto it=path.rbegin();it!=path.rend();++it){
        auto& type=catalog.exported_types[*it];
        if(type.implementation_kind==ManagedExportedTypeImplementationKind::exported_type){
          const auto& parent=catalog.exported_types[(type.implementation_token&0x00ffffffu)-1];
          if(parent.full_name.size()+1+type.name.size()>4096)
            return Error{ErrorCode::resource_limit,"Nested ExportedType name exceeds 4096 bytes"};
          type.full_name=parent.full_name+"+"+type.name;
          type.assembly_scope=parent.assembly_scope;
          type.forwarding_valid=parent.forwarding_valid;
        }else{
          if(type.namespace_name.size()+(!type.namespace_name.empty())+type.name.size()>4096)
            return Error{ErrorCode::resource_limit,"ExportedType full name exceeds 4096 bytes"};
          type.full_name=type.namespace_name.empty()?type.name:type.namespace_name+"."+type.name;
        }
        if(!names.insert(type.full_name).second)return malformed("Duplicate ExportedType full name");
        state[*it]=2;
      }
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
  // Attach resolved constraint identities after TypeSpec signatures and
  // TypeRef names/scopes are available. Keep the original tokens untouched so
  // callers can always trace a display identity back to its metadata row.
  std::map<std::uint32_t,const ManagedTypeReference*> references_by_token;
  std::map<std::uint32_t,const ManagedTypeSpecification*> specs_by_token;
  for(const auto& reference:catalog.references)references_by_token.emplace(reference.token,&reference);
  for(const auto& spec:catalog.specifications)specs_by_token.emplace(spec.token,&spec);
  auto all_generic_parameters=parse_managed_generic_parameters(root);if(!all_generic_parameters)return all_generic_parameters.error();
  for(auto& parameter:all_generic_parameters.value())if((parameter.owner_token>>24)==6)
    catalog.method_generic_parameters.push_back(std::move(parameter));
  const auto resolve_constraints=[&](std::vector<ManagedGenericParameter>& parameters)->Result<bool>{
  for(auto& parameter:parameters){
    parameter.resolved_constraints.clear();
    for(const auto token:parameter.constraint_tokens){
      ManagedGenericParameter::ConstraintIdentity identity;identity.token=token;
      const auto table=token>>24;
      if(table==2){
        const auto rid=token&0x00ffffffu;
        if(!rid||rid>catalog.definitions.size())return malformed("Generic constraint TypeDef token is outside the type catalog");
        identity.name=catalog.definitions[rid-1].full_name;identity.scope="module";
      }else if(table==1){
        const auto found=references_by_token.find(token);
        if(found==references_by_token.end())return malformed("Generic constraint TypeRef token is unresolved");
        const auto& reference=*found->second;identity.name=reference.full_name;
        identity.scope=reference.resolved_catalog_index&&reference.assembly_scope?"assembly:"+reference.assembly_scope->name:
          reference.unresolved_scope.empty()?"module":reference.unresolved_scope;
        identity.external_unresolved=reference.external_scope_unresolved;
      }else if(table==27){
        const auto found=specs_by_token.find(token);
        if(found==specs_by_token.end())return malformed("Generic constraint TypeSpec token is unresolved");
        identity.signature=std::make_shared<ManagedTypeSignature>(found->second->signature);
        const auto* root_type=resolved_type_spec_root(found->second->signature);
        if(!root_type)return Error{ErrorCode::resource_limit,"Generic constraint TypeSpec nesting exceeds limit"};
        identity.name=root_type->metadata_type_name;
        identity.scope=root_type->metadata_type_scope;
        identity.external_unresolved=root_type->metadata_type_external_unresolved;
      }else return malformed("Generic constraint token has an invalid metadata table");
      parameter.resolved_constraints.push_back(std::move(identity));
    }
  }
  return true;
  };
  for(auto& definition:catalog.definitions){auto resolved=resolve_constraints(definition.generic_parameters);if(!resolved)return resolved.error();}
  {auto resolved=resolve_constraints(catalog.method_generic_parameters);if(!resolved)return resolved.error();}
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
const ManagedTypeDefinition* managed_definition(std::span<const ManagedTypeCatalog> catalogs,
                                                std::uint32_t catalog_index,std::uint32_t token){
  if(catalog_index>=catalogs.size())return nullptr;
  const auto& definitions=catalogs[catalog_index].definitions;
  const auto found=std::find_if(definitions.begin(),definitions.end(),
      [&](const auto& definition){return definition.token==token;});
  return found==definitions.end()?nullptr:&*found;
}
Result<bool> refresh_generic_instance_arity(ManagedTypeSignature& signature,
                                             std::uint32_t source_catalog,
                                             std::span<const ManagedTypeCatalog> catalogs,
                                             unsigned depth,std::size_t& budget){
  if(depth>16)return Error{ErrorCode::resource_limit,"Generic TypeSpec identity nesting exceeds limit"};
  if(!budget--)return Error{ErrorCode::resource_limit,"Generic TypeSpec identity node limit exceeded"};
  if(signature.element_type==0x15){
    const ManagedTypeDefinition* definition=nullptr;
    if((signature.metadata_type_token>>24)==2)
      definition=managed_definition(catalogs,source_catalog,signature.metadata_type_token);
    else if((signature.metadata_type_token>>24)==1 && signature.resolved_type_catalog_index &&
            signature.resolved_type_definition_token)
      definition=managed_definition(catalogs,*signature.resolved_type_catalog_index,
                                    *signature.resolved_type_definition_token);
    if(definition){
      signature.generic_instance_arity_valid=definition->generic_parameters.size()==signature.children.size();
      for(std::size_t i=0;signature.generic_instance_arity_valid&&i<definition->generic_parameters.size();++i)
        signature.generic_instance_arity_valid=definition->generic_parameters[i].number==i;
    }
  }
  for(auto& child:signature.children){
    auto result=refresh_generic_instance_arity(child,source_catalog,catalogs,depth+1,budget);
    if(!result)return result.error();
  }
  if(signature.type_spec_signature){
    auto result=refresh_generic_instance_arity(*signature.type_spec_signature,source_catalog,catalogs,depth+1,budget);
    if(!result)return result.error();
  }
  return true;
}

struct ManagedCatalogIndex {
  std::map<std::uint32_t,const ManagedTypeDefinition*> definitions;
  std::map<std::uint32_t,const ManagedTypeReference*> references;
  std::map<std::uint32_t,const ManagedTypeSpecification*> specifications;
};
struct ManagedTypeShape {
  std::uint8_t element_type=0;
  bool generic_instance_is_value_type=false, type_variable=false, method_variable=false;
  std::uint32_t generic_index=0, array_rank=0;
  std::optional<ManagedTypeNode> definition, variable_owner;
  std::vector<ManagedTypeShape> children;
  bool operator==(const ManagedTypeShape&) const = default;
  bool operator<(const ManagedTypeShape& other) const {
    return std::tie(element_type,generic_instance_is_value_type,type_variable,method_variable,
                    generic_index,array_rank,definition,variable_owner,children)<
           std::tie(other.element_type,other.generic_instance_is_value_type,other.type_variable,
                    other.method_variable,other.generic_index,other.array_rank,other.definition,
                    other.variable_owner,other.children);
  }
};
struct ManagedConstructedType {
  ManagedTypeNode definition;
  bool value_type=false;
  std::vector<ManagedTypeShape> arguments;
  bool operator==(const ManagedConstructedType&) const = default;
  bool operator<(const ManagedConstructedType& other) const {
    return std::tie(definition,value_type,arguments)<
           std::tie(other.definition,other.value_type,other.arguments);
  }
};
constexpr std::size_t max_assignability_catalogs=4096;
constexpr std::size_t max_assignability_metadata_nodes=1'000'000;
constexpr std::size_t max_assignability_graph_nodes=100'000;
constexpr std::size_t max_assignability_signature_nodes=100'000;

std::optional<std::vector<ManagedCatalogIndex>> index_managed_catalogs(
    std::span<const ManagedTypeCatalog> catalogs){
  if(catalogs.size()>max_assignability_catalogs)return {};
  std::vector<ManagedCatalogIndex> result(catalogs.size());
  std::size_t total=0;
  for(std::size_t i=0;i<catalogs.size();++i){
    const auto& source=catalogs[i];
    if(source.definitions.size()>max_assignability_metadata_nodes-total)return {};
    total+=source.definitions.size();
    if(source.references.size()>max_assignability_metadata_nodes-total)return {};
    total+=source.references.size();
    if(source.specifications.size()>max_assignability_metadata_nodes-total)return {};
    total+=source.specifications.size();
    auto& target=result[i];
    for(const auto& definition:source.definitions)
      if(!definition.token||(definition.token>>24)!=2||!target.definitions.emplace(definition.token,&definition).second)return {};
    for(const auto& reference:source.references)
      if(!reference.token||(reference.token>>24)!=1||!target.references.emplace(reference.token,&reference).second)return {};
    for(const auto& specification:source.specifications)
      if(!specification.token||(specification.token>>24)!=27||!target.specifications.emplace(specification.token,&specification).second)return {};
  }
  return result;
}

std::optional<ManagedTypeNode> resolved_definition_node(
    std::span<const ManagedCatalogIndex> indexes,std::uint32_t source_catalog,std::uint32_t token){
  if(source_catalog>=indexes.size())return {};
  const auto table=token>>24;
  if(table==2){
    if(indexes[source_catalog].definitions.contains(token))return ManagedTypeNode{source_catalog,token};
    return {};
  }
  if(table!=1)return {};
  const auto found=indexes[source_catalog].references.find(token);
  if(found==indexes[source_catalog].references.end()||!found->second->resolved_catalog_index||
     !found->second->resolved_definition_token)return {};
  const auto catalog=*found->second->resolved_catalog_index;
  const auto definition=*found->second->resolved_definition_token;
  if(catalog>=indexes.size()||!indexes[catalog].definitions.contains(definition))return {};
  return ManagedTypeNode{catalog,definition};
}

std::optional<ManagedTypeShape> managed_signature_shape(
    std::span<const ManagedCatalogIndex> indexes,std::uint32_t source_catalog,
    const ManagedTypeSignature& signature,std::optional<ManagedTypeNode> variable_owner,
    unsigned depth,std::size_t& budget,std::set<ManagedTypeNode>& active_specs){
  if(depth>16||!budget||source_catalog>=indexes.size())return {};
  --budget;
  const auto token=signature.metadata_type_token;
  if(signature.element_type==0x15&&!signature.generic_instance_arity_valid)return {};
  if((token>>24)==27&&signature.type_spec_signature&&
     (signature.element_type==0x11||signature.element_type==0x12)){
    const ManagedTypeNode spec_node{source_catalog,token};
    if(!active_specs.insert(spec_node).second)return {};
    auto result=managed_signature_shape(indexes,source_catalog,*signature.type_spec_signature,
                                        variable_owner,depth+1,budget,active_specs);
    active_specs.erase(spec_node);
    return result;
  }
  if(signature.element_type==0x14)return {}; // Array sizes/lower bounds are not retained in the current signature model.
  ManagedTypeShape shape;
  shape.element_type=signature.element_type;
  shape.generic_instance_is_value_type=signature.generic_instance_is_value_type;
  shape.generic_index=signature.generic_index;
  shape.array_rank=signature.array_rank;
  if(signature.element_type==0x13){shape.type_variable=true;shape.variable_owner=variable_owner;return shape;}
  if(signature.element_type==0x1e){shape.method_variable=true;return shape;}
  if(signature.element_type==0x11||signature.element_type==0x12||signature.element_type==0x15){
    if((token>>24)==27)return {}; // A TypeSpec constructor is not a definition identity.
    auto definition=resolved_definition_node(indexes,source_catalog,token);
    if(!definition)return {};
    shape.definition=*definition;
  }
  for(const auto& child:signature.children){
    auto converted=managed_signature_shape(indexes,source_catalog,child,variable_owner,
                                           depth+1,budget,active_specs);
    if(!converted)return {};
    shape.children.push_back(std::move(*converted));
  }
  return shape;
}

bool managed_shape_is_closed(const ManagedTypeShape& shape){
  if(shape.type_variable||shape.method_variable)return false;
  return std::all_of(shape.children.begin(),shape.children.end(),managed_shape_is_closed);
}

std::optional<ManagedConstructedType> constructed_type_from_shape(
    std::span<const ManagedCatalogIndex> indexes,const ManagedTypeShape& shape){
  if(!shape.definition||shape.element_type!=0x11&&shape.element_type!=0x12&&shape.element_type!=0x15)return {};
  if(shape.element_type!=0x15&&!shape.children.empty())return {};
  const auto [catalog,token]=*shape.definition;
  if(catalog>=indexes.size())return {};
  const auto definition=indexes[catalog].definitions.find(token);
  if(definition==indexes[catalog].definitions.end())return {};
  const auto arity=definition->second->generic_parameters.size();
  if(shape.element_type==0x15){
    if(shape.children.size()!=arity)return {};
  }else if(arity!=0)return {};
  if(!std::all_of(shape.children.begin(),shape.children.end(),managed_shape_is_closed))return {};
  return ManagedConstructedType{*shape.definition,
      shape.element_type==0x11||shape.generic_instance_is_value_type,shape.children};
}

std::optional<ManagedConstructedType> constructed_type_from_token(
    std::span<const ManagedTypeCatalog> catalogs,std::span<const ManagedCatalogIndex> indexes,
    std::uint32_t source_catalog,std::uint32_t token,std::size_t& signature_budget){
  if(source_catalog>=indexes.size())return {};
  if((token>>24)==27){
    const auto found=indexes[source_catalog].specifications.find(token);
    if(found==indexes[source_catalog].specifications.end())return {};
    std::set<ManagedTypeNode> active_specs{{source_catalog,token}};
    auto shape=managed_signature_shape(indexes,source_catalog,found->second->signature,
                                       std::nullopt,0,signature_budget,active_specs);
    if(!shape)return {};
    return constructed_type_from_shape(indexes,*shape);
  }
  const auto node=resolved_definition_node(indexes,source_catalog,token);
  if(!node)return {};
  const auto [catalog,definition_token]=*node;
  const auto definition=indexes[catalog].definitions.find(definition_token);
  if(definition==indexes[catalog].definitions.end()||!definition->second->generic_parameters.empty())return {};
  (void)catalogs;
  return ManagedConstructedType{*node,false,{}};
}

bool catalog_has_type_token(std::span<const ManagedCatalogIndex> indexes,
                            std::uint32_t catalog,std::uint32_t token){
  if(catalog>=indexes.size())return false;
  const auto table=token>>24;
  if(table==2)return indexes[catalog].definitions.contains(token);
  if(table==1)return indexes[catalog].references.contains(token);
  if(table==27)return indexes[catalog].specifications.contains(token);
  return false;
}

std::optional<ManagedTypeShape> substitute_type_variables(
    const ManagedTypeShape& source,ManagedTypeNode owner,
    std::span<const ManagedTypeShape> arguments,unsigned depth,std::size_t& budget){
  if(depth>16||!budget)return {};
  --budget;
  if(source.method_variable)return {};
  if(source.type_variable){
    if(source.variable_owner!=owner||source.generic_index>=arguments.size())return {};
    return arguments[source.generic_index];
  }
  auto result=source;
  result.children.clear();
  for(const auto& child:source.children){
    auto substituted=substitute_type_variables(child,owner,arguments,depth+1,budget);
    if(!substituted)return {};
    result.children.push_back(std::move(*substituted));
  }
  return result;
}

std::optional<ManagedConstructedType> constructed_edge_type(
    std::span<const ManagedCatalogIndex> indexes,const ManagedConstructedType& owner,
    std::uint32_t edge_token,std::size_t& signature_budget){
  if((edge_token>>24)!=27){
    const auto node=resolved_definition_node(indexes,owner.definition.first,edge_token);
    if(!node)return {};
    const auto definition=indexes[node->first].definitions.find(node->second);
    if(definition==indexes[node->first].definitions.end()||!definition->second->generic_parameters.empty())return {};
    return ManagedConstructedType{*node,false,{}};
  }
  const auto found=indexes[owner.definition.first].specifications.find(edge_token);
  if(found==indexes[owner.definition.first].specifications.end())return {};
  std::set<ManagedTypeNode> active_specs{{owner.definition.first,edge_token}};
  auto shape=managed_signature_shape(indexes,owner.definition.first,found->second->signature,
                                     owner.definition,0,signature_budget,active_specs);
  if(!shape)return {};
  auto substituted=substitute_type_variables(*shape,owner.definition,owner.arguments,0,signature_budget);
  if(!substituted)return {};
  return constructed_type_from_shape(indexes,*substituted);
}
}

Result<bool> bind_managed_type_references(std::span<ManagedTypeCatalog> catalogs){
  if(catalogs.size()>4096)return Error{ErrorCode::resource_limit,"Managed assembly binding exceeds 4096 catalogs"};
  struct NamedType {
    std::uint32_t definition_token=0;
    const ManagedExportedType* exported=nullptr;
    bool duplicate=false;
  };
  std::vector<std::map<std::string,NamedType>> names(catalogs.size());
  for(std::size_t i=0;i<catalogs.size();++i){
    for(const auto& definition:catalogs[i].definitions){
      auto& entry=names[i][definition.full_name];
      if(entry.definition_token||entry.exported)entry.duplicate=true;
      entry.definition_token=definition.token;
    }
    for(const auto& exported:catalogs[i].exported_types){
      auto& entry=names[i][exported.full_name];
      if(entry.definition_token||entry.exported)entry.duplicate=true;
      entry.exported=&exported;
    }
  }
  for(auto& source:catalogs)for(auto& reference:source.references){
    reference.resolved_catalog_index.reset();reference.resolved_definition_token.reset();
    if(!reference.assembly_scope)continue;
    reference.external_scope_unresolved=true;
    reference.unresolved_scope="assembly:"+reference.assembly_scope->name;
    const ManagedAssemblyIdentity* scope=&*reference.assembly_scope;
    std::set<std::uint32_t> visited_catalogs;
    for(std::size_t hop=0;hop<=catalogs.size();++hop){
      std::optional<std::uint32_t> target_catalog;std::size_t assembly_matches=0;
      for(std::uint32_t i=0;i<catalogs.size();++i){
        const auto& identity=catalogs[i].assembly_identity;
        if(identity&&assembly_scope_matches(*scope,*identity)){target_catalog=i;++assembly_matches;}
      }
      if(assembly_matches!=1){reference.unresolved_scope=assembly_matches?"duplicate assembly identity":"assembly identity not supplied";break;}
      if(!visited_catalogs.insert(*target_catalog).second){reference.unresolved_scope="ExportedType forwarding cycle";break;}
      const auto found=names[*target_catalog].find(reference.full_name);
      if(found==names[*target_catalog].end()){reference.unresolved_scope="type name absent from assembly catalog";break;}
      const auto& named=found->second;
      if(named.duplicate){reference.unresolved_scope="duplicate type name in assembly catalog";break;}
      if(named.definition_token){
        reference.resolved_catalog_index=*target_catalog;
        reference.resolved_definition_token=named.definition_token;
        reference.unresolved_scope.clear();
        reference.external_scope_unresolved=false;
        break;
      }
      if(!named.exported->assembly_scope){reference.unresolved_scope="ExportedType File implementation unresolved";break;}
      if(!named.exported->forwarding_valid){reference.unresolved_scope="ExportedType AssemblyRef lacks Forwarder flag";break;}
      scope=&*named.exported->assembly_scope;
      if(hop==catalogs.size())reference.unresolved_scope="ExportedType forwarding budget exhausted";
    }
  }
  // TypeSpec signatures were resolved during parsing, before cross-catalog
  // binding. Refresh their TypeRef display state after the bindings settle.
  for(std::size_t catalog_index=0;catalog_index<catalogs.size();++catalog_index){
    auto& catalog=catalogs[catalog_index];
    std::set<std::uint32_t> active_specs;std::size_t budget=100000;
    for(auto& spec:catalog.specifications){
      active_specs.insert(spec.token);
      auto refreshed=resolve_type_signature(spec.signature,catalog,active_specs,0,budget);
      active_specs.erase(spec.token);
      if(!refreshed)return refreshed.error();
    }
    std::size_t identity_budget=100000;
    for(auto& spec:catalog.specifications){
      auto refreshed=refresh_generic_instance_arity(spec.signature,static_cast<std::uint32_t>(catalog_index),
                                                     catalogs,0,identity_budget);
      if(!refreshed)return refreshed.error();
    }
    std::map<std::uint32_t,const ManagedTypeReference*> references;
    std::map<std::uint32_t,const ManagedTypeSpecification*> specifications;
    for(const auto& reference:catalog.references)references.emplace(reference.token,&reference);
    for(const auto& spec:catalog.specifications)specifications.emplace(spec.token,&spec);
    const auto refresh_constraints=[&](std::vector<ManagedGenericParameter>& parameters)->Result<bool>{
    for(auto& parameter:parameters){
      for(auto& identity:parameter.resolved_constraints){
        if((identity.token>>24)==1){
          const auto found=references.find(identity.token);if(found==references.end())return malformed("Bound generic constraint TypeRef token is unresolved");
          const auto& reference=*found->second;identity.name=reference.full_name;
          identity.scope=reference.resolved_catalog_index&&reference.assembly_scope?"assembly:"+reference.assembly_scope->name:
            reference.unresolved_scope.empty()?"module":reference.unresolved_scope;
          identity.external_unresolved=reference.external_scope_unresolved;
        }else if((identity.token>>24)==27){
          const auto found=specifications.find(identity.token);if(found==specifications.end())return malformed("Bound generic constraint TypeSpec token is unresolved");
          identity.signature=std::make_shared<ManagedTypeSignature>(found->second->signature);
          const auto* root_type=resolved_type_spec_root(found->second->signature);
          if(!root_type)return Error{ErrorCode::resource_limit,"Generic constraint TypeSpec nesting exceeds limit"};
          identity.name=root_type->metadata_type_name;identity.scope=root_type->metadata_type_scope;
          identity.external_unresolved=root_type->metadata_type_external_unresolved;
        }
      }
    }
    return true;
    };
    for(auto& definition:catalog.definitions){auto refreshed=refresh_constraints(definition.generic_parameters);if(!refreshed)return refreshed.error();}
    {auto refreshed=refresh_constraints(catalog.method_generic_parameters);if(!refreshed)return refreshed.error();}
  }
  return true;
}

bool managed_type_is_assignable_across_catalogs(std::span<const ManagedTypeCatalog> catalogs,
                                                 std::uint32_t candidate_catalog,std::uint32_t candidate,
                                                 std::uint32_t target_catalog,std::uint32_t target){
  if(!candidate||!target||candidate_catalog>=catalogs.size()||target_catalog>=catalogs.size())return false;
  auto indexes=index_managed_catalogs(catalogs);
  if(!indexes||!catalog_has_type_token(*indexes,candidate_catalog,candidate)||
     !catalog_has_type_token(*indexes,target_catalog,target))return false;
  if(candidate_catalog==target_catalog&&candidate==target){
    if((candidate>>24)==27){
      // A shared TypeSpec token proves metadata identity, but an open or
      // otherwise unresolved signature is not a closed assignability proof.
      std::size_t identity_budget=max_assignability_signature_nodes;
      if(!constructed_type_from_token(catalogs,*indexes,candidate_catalog,candidate,
                                      identity_budget))return false;
    }
    return true;
  }

  // Preserve exact identity for two unconstructed references to the same
  // generic TypeDef, while requiring closed argument vectors for traversal or
  // comparison against a constructed TypeSpec.
  const auto raw_candidate=resolved_definition_node(*indexes,candidate_catalog,candidate);
  const auto raw_target=resolved_definition_node(*indexes,target_catalog,target);
  if((candidate>>24)!=27&&(target>>24)!=27&&raw_candidate&&raw_target&&*raw_candidate==*raw_target)
    return true;

  std::size_t signature_budget=max_assignability_signature_nodes;
  auto source=constructed_type_from_token(catalogs,*indexes,candidate_catalog,candidate,signature_budget);
  auto wanted=constructed_type_from_token(catalogs,*indexes,target_catalog,target,signature_budget);
  if(!source||!wanted)return false;
  if(*source==*wanted)return true;

  std::vector<ManagedConstructedType> pending{*source};
  std::set<ManagedConstructedType> visited;
  std::size_t graph_budget=max_assignability_graph_nodes;
  while(!pending.empty()&&graph_budget){
    auto current=std::move(pending.back());pending.pop_back();
    if(current==*wanted)return true;
    if(!visited.insert(current).second)continue;
    if(visited.size()>max_assignability_graph_nodes)return false;
    const auto definition=indexes->at(current.definition.first).definitions.find(current.definition.second);
    if(definition==indexes->at(current.definition.first).definitions.end())continue;
    const auto explore=[&](std::uint32_t edge)->bool{
      if(!graph_budget)return false;
      --graph_budget;
      auto next=constructed_edge_type(*indexes,current,edge,signature_budget);
      if(!next)return false;
      if(*next==*wanted)return true;
      if(!visited.contains(*next))pending.push_back(std::move(*next));
      return false;
    };
    if(definition->second->base_type_token&&explore(definition->second->base_type_token))return true;
    for(const auto edge:definition->second->interface_tokens)if(explore(edge))return true;
  }
  return false;
}

Result<std::vector<ManagedConstant>> parse_managed_constants(std::span<const std::byte> root){
  auto parsed=parse_cli_metadata(root);if(!parsed)return parsed.error();
  const auto& metadata=parsed.value();
  const auto rows=[&](std::uint8_t id){const auto it=metadata.tables.row_counts.find(id);return it==metadata.tables.row_counts.end()?0u:it->second;};
  const auto row_size=[&](std::uint8_t id){const auto it=metadata.tables.row_sizes.find(id);return it==metadata.tables.row_sizes.end()?0u:it->second;};
  const auto table_offset=[&](std::uint8_t id){std::uint64_t offset=metadata.tables.data_offset;for(std::uint8_t table=0;table<id;++table)offset+=std::uint64_t{rows(table)}*row_size(table);return offset;};
  const auto count=rows(11);
  if(count>250000)return Error{ErrorCode::resource_limit,"CLR Constant catalog exceeds 250,000 rows"};
  if(!count)return std::vector<ManagedConstant>{};
  auto tables_it=metadata.streams.find("#~");if(tables_it==metadata.streams.end())tables_it=metadata.streams.find("#-");
  const auto blob_it=metadata.streams.find("#Blob");
  if(tables_it==metadata.streams.end()||blob_it==metadata.streams.end())return malformed("CLR Constant parsing requires tables and #Blob heaps");
  const auto tables=root.subspan(tables_it->second.offset,tables_it->second.size);
  const auto blobs=root.subspan(blob_it->second.offset,blob_it->second.size);
  const auto parent_width=coded_width(2,metadata.tables.row_counts),blob_width=(metadata.tables.heap_sizes&4)?4u:2u;
  const auto offset=table_offset(11);
  if(row_size(11)!=2+parent_width+blob_width||offset>tables.size()||std::uint64_t{count}*row_size(11)>tables.size()-offset)
    return malformed("CLR Constant rows exceed tables stream");
  const auto read_index=[](std::span<const std::byte> bytes,std::size_t at,unsigned width){return width==2?std::uint32_t(u16(bytes,at)):u32(bytes,at);};
  std::vector<ManagedConstant> result;result.reserve(count);
  std::set<std::uint32_t> owners;
  std::uint64_t payload_bytes=0;
  for(std::uint32_t row=1;row<=count;++row){
    const auto at=static_cast<std::size_t>(offset+std::uint64_t{row-1}*row_size(11));
    ManagedConstant value;value.token=0x0b000000u|row;value.element_type=std::to_integer<std::uint8_t>(tables[at]);
    if(tables[at+1]!=std::byte{0})return malformed("CLR Constant has nonzero padding");
    const auto parent=read_index(tables,at+2,parent_width),tag=parent&3u,rid=parent>>2;
    if(tag==3||!rid||rid>0x00ffffffu)return malformed("CLR Constant has an invalid HasConstant parent");
    const std::uint8_t parent_table=tag==0?4:tag==1?8:23;
    if(rid>rows(parent_table))return malformed("CLR Constant parent token is outside its metadata table");
    value.parent_token=(std::uint32_t{parent_table}<<24)|rid;
    if(!owners.insert(value.parent_token).second)return malformed("CLR Constant parent has duplicate default values");
    const auto owner_at=table_offset(parent_table)+std::uint64_t{rid-1}*row_size(parent_table);
    if(row_size(parent_table)<2||owner_at>tables.size()||2>tables.size()-owner_at)
      return malformed("CLR Constant parent flags exceed tables stream");
    const std::uint16_t has_default=tag==0?0x8000:0x1000;
    if((u16(tables,static_cast<std::size_t>(owner_at))&has_default)==0)
      return malformed("CLR Constant parent is not marked HasDefault");
    value.blob_index=read_index(tables,at+2+parent_width,blob_width);
    if(value.blob_index>=blobs.size())return malformed("CLR Constant value index exceeds #Blob heap");
    std::size_t cursor=value.blob_index;auto length=compressed_uint(blobs,cursor);if(!length)return length.error();
    if(length.value()>blobs.size()-cursor)return malformed("CLR Constant value exceeds #Blob heap");
    if(length.value()>4u*1024*1024)return Error{ErrorCode::resource_limit,"CLR Constant value exceeds 4 MiB"};
    if(length.value()>64u*1024*1024-payload_bytes)return Error{ErrorCode::resource_limit,"CLR Constant payloads exceed 64 MiB"};
    payload_bytes+=length.value();
    const auto payload=blobs.subspan(cursor,length.value());
    std::size_t width=0;
    switch(value.element_type){
      case 0x02:case 0x04:case 0x05:width=1;break;
      case 0x03:case 0x06:case 0x07:width=2;break;
      case 0x08:case 0x09:case 0x0c:case 0x12:width=4;break;
      case 0x0a:case 0x0b:case 0x0d:width=8;break;
      case 0x0e:
        if(payload.size()%2)return malformed("CLR Constant string has an odd UTF-16 byte count");
        value.string_value.reserve(payload.size()/2);
        for(std::size_t p=0;p<payload.size();p+=2)value.string_value.push_back(static_cast<char16_t>(u16(payload,p)));
        break;
      default:return malformed("CLR Constant has an invalid element type");
    }
    if(width){
      if(payload.size()!=width)return malformed("CLR Constant scalar payload has an invalid width");
      for(std::size_t p=0;p<width;++p)value.scalar_bits|=std::uint64_t{std::to_integer<std::uint8_t>(payload[p])}<<(8*p);
      if(value.element_type==0x02&&value.scalar_bits>1)return malformed("CLR Constant Boolean is neither zero nor one");
      if(value.element_type==0x12&&value.scalar_bits!=0)return malformed("CLR Constant class value is not null");
    }
    result.push_back(std::move(value));
  }
  return result;
}

Result<std::vector<ManagedCustomAttribute>> parse_managed_custom_attributes(std::span<const std::byte> root) try {
  if(root.size()>64u*1024u*1024u)return Error{ErrorCode::resource_limit,"CLR custom-attribute inspection root exceeds 64 MiB"};
  auto parsed=parse_cli_metadata(root);if(!parsed)return parsed.error();const auto& md=parsed.value();
  const auto rows=[&](std::uint8_t id){const auto it=md.tables.row_counts.find(id);return it==md.tables.row_counts.end()?0u:it->second;};
  const auto count=rows(12);if(count>250000)return Error{ErrorCode::resource_limit,"CLR CustomAttribute catalog exceeds 250,000 rows"};
  if(!count)return std::vector<ManagedCustomAttribute>{};
  auto table_it=md.streams.find("#~");if(table_it==md.streams.end())table_it=md.streams.find("#-");
  const auto blob_it=md.streams.find("#Blob");if(table_it==md.streams.end()||blob_it==md.streams.end())return malformed("CustomAttribute parsing requires tables and #Blob heaps");
  const auto tables=root.subspan(table_it->second.offset,table_it->second.size),blobs=root.subspan(blob_it->second.offset,blob_it->second.size);
  const auto parent_width=coded_width(3,md.tables.row_counts),constructor_width=coded_width(11,md.tables.row_counts),blob_width=(md.tables.heap_sizes&4)?4u:2u;
  const auto row_it=md.tables.row_sizes.find(12);if(row_it==md.tables.row_sizes.end()||row_it->second!=parent_width+constructor_width+blob_width)return malformed("CustomAttribute row layout is inconsistent");
  std::uint64_t offset=md.tables.data_offset;for(std::uint8_t id=0;id<12;++id){const auto size=md.tables.row_sizes.find(id);if(rows(id)&&size==md.tables.row_sizes.end())return malformed("CustomAttribute preceding table has no row layout");if(size!=md.tables.row_sizes.end())offset+=std::uint64_t{rows(id)}*size->second;}
  if(offset>tables.size()||std::uint64_t{count}*row_it->second>tables.size()-offset)return malformed("CustomAttribute rows exceed tables stream");
  const auto index=[](std::span<const std::byte> b,std::size_t p,unsigned w){return w==2?std::uint32_t(u16(b,p)):u32(b,p);};
  static constexpr std::array<std::uint8_t,22> parent_tables={6,4,1,2,8,9,10,0,14,23,20,17,26,27,32,35,38,39,40,42,44,43};
  const auto parent_token=[&](std::uint32_t coded)->std::uint32_t{const auto tag=coded&31u,rid=coded>>5;if(tag>=parent_tables.size()||!rid||rid>0x00ffffffu)return 0;const auto table=parent_tables[tag];return rid<=rows(table)?(std::uint32_t{table}<<24)|rid:0;};
  std::vector<ManagedCustomAttribute> result;result.reserve(count);std::uint64_t payload_total=0;
  for(std::uint32_t rid=1;rid<=count;++rid){
    const auto at=static_cast<std::size_t>(offset+std::uint64_t{rid-1}*row_it->second);ManagedCustomAttribute value;value.token=0x0c000000u|rid;value.metadata_offset=table_it->second.offset+at;
    value.parent_token=parent_token(index(tables,at,parent_width));if(!value.parent_token)return malformed("CustomAttribute has an invalid HasCustomAttribute parent");
    const auto ctor=index(tables,at+parent_width,constructor_width),tag=ctor&7u,ctor_rid=ctor>>3;if(!ctor_rid||ctor_rid>0x00ffffffu||(tag!=2&&tag!=3))return malformed("CustomAttribute has an invalid constructor coded index");
    const auto ctor_table=tag==2?6u:10u;if(ctor_rid>rows(static_cast<std::uint8_t>(ctor_table)))return malformed("CustomAttribute constructor is outside its metadata table");value.constructor_token=(std::uint32_t{ctor_table}<<24)|ctor_rid;
    value.value_blob_index=index(tables,at+parent_width+constructor_width,blob_width);if(value.value_blob_index>=blobs.size())return malformed("CustomAttribute value index exceeds #Blob heap");
    std::size_t cursor=value.value_blob_index;auto length=compressed_uint(blobs,cursor);if(!length)return length.error();if(length.value()>blobs.size()-cursor)return malformed("CustomAttribute value exceeds #Blob heap");
    if(length.value()>4u*1024u*1024u)return Error{ErrorCode::resource_limit,"CustomAttribute value exceeds 4 MiB"};if(length.value()>64u*1024u*1024u-payload_total)return Error{ErrorCode::resource_limit,"CustomAttribute payloads exceed 64 MiB"};payload_total+=length.value();
    const auto payload=blobs.subspan(cursor,length.value());if(payload.size()<2||u16(payload,0)!=1)return malformed("CustomAttribute value has a missing or invalid prolog");value.serialized_value.assign(payload.begin()+2,payload.end());result.push_back(std::move(value));
  }
  return result;
} catch(const std::bad_alloc&) {return Error{ErrorCode::resource_limit,"Cannot allocate CLR custom-attribute catalog"};}
  catch(const std::length_error&) {return Error{ErrorCode::resource_limit,"CLR custom-attribute catalog exceeds container limits"};}

Result<std::vector<ManagedDeclarativeSecurity>> parse_managed_declarative_security(
    std::span<const std::byte> root) try {
  if (root.size() > 64u * 1024u * 1024u)
    return Error{ErrorCode::resource_limit, "CLR declarative-security inspection root exceeds 64 MiB"};
  auto parsed = parse_cli_metadata(root);
  if (!parsed) return parsed.error();
  const auto &md = parsed.value();
  const auto rows = [&](std::uint8_t id) {
    const auto it = md.tables.row_counts.find(id);
    return it == md.tables.row_counts.end() ? 0u : it->second;
  };
  const auto count = rows(14);
  if (count > 250000)
    return Error{ErrorCode::resource_limit, "CLR declarative-security catalog exceeds 250,000 rows"};
  if (!count) return std::vector<ManagedDeclarativeSecurity>{};
  auto tables_it = md.streams.find("#~");
  if (tables_it == md.streams.end()) tables_it = md.streams.find("#-");
  const auto blob_it = md.streams.find("#Blob");
  if (tables_it == md.streams.end() || blob_it == md.streams.end())
    return malformed("DeclSecurity parsing requires tables and #Blob heaps");
  const auto tables = root.subspan(tables_it->second.offset, tables_it->second.size);
  const auto blobs = root.subspan(blob_it->second.offset, blob_it->second.size);
  const auto parent_width = coded_width(5, md.tables.row_counts);
  const auto blob_width = (md.tables.heap_sizes & 4) ? 4u : 2u;
  const auto row_it = md.tables.row_sizes.find(14);
  if (row_it == md.tables.row_sizes.end() || row_it->second != 2 + parent_width + blob_width)
    return malformed("DeclSecurity row layout is inconsistent");
  std::uint64_t offset = md.tables.data_offset;
  for (std::uint8_t id = 0; id < 14; ++id) {
    const auto size = md.tables.row_sizes.find(id);
    if (rows(id) && size == md.tables.row_sizes.end())
      return malformed("DeclSecurity preceding table has no row layout");
    if (size != md.tables.row_sizes.end()) offset += std::uint64_t{rows(id)} * size->second;
  }
  if (offset > tables.size() || std::uint64_t{count} * row_it->second > tables.size() - offset)
    return malformed("DeclSecurity rows exceed tables stream");
  const auto read_index = [](std::span<const std::byte> bytes, std::size_t at, unsigned width) {
    return width == 2 ? std::uint32_t(u16(bytes, at)) : u32(bytes, at);
  };
  std::vector<ManagedDeclarativeSecurity> result;
  result.reserve(count);
  std::set<std::pair<std::uint32_t, std::uint16_t>> seen_parent_actions;
  std::uint64_t payload_bytes = 0;
  for (std::uint32_t rid = 1; rid <= count; ++rid) {
    const auto at = static_cast<std::size_t>(offset + std::uint64_t{rid - 1} * row_it->second);
    ManagedDeclarativeSecurity row;
    row.token = 0x0e000000u | rid;
    row.metadata_offset = tables_it->second.offset + at;
    row.action = u16(tables, at);
    const auto coded_parent = read_index(tables, at + 2, parent_width);
    const auto tag = coded_parent & 3u;
    const auto parent_rid = coded_parent >> 2;
    const auto parent_table = static_cast<std::uint8_t>(tag == 0 ? 2 : tag == 1 ? 6 : 32);
    if (tag == 3 || !parent_rid || parent_rid > 0x00ffffffu || parent_rid > rows(parent_table))
      return malformed("DeclSecurity has an invalid HasDeclSecurity parent");
    row.parent_token = (std::uint32_t{parent_table} << 24) | parent_rid;
    if (!seen_parent_actions.emplace(row.parent_token, row.action).second)
      return malformed("DeclSecurity parent/action pair is duplicated");
    row.permission_set_blob_index = read_index(tables, at + 2 + parent_width, blob_width);
    if (!row.permission_set_blob_index || row.permission_set_blob_index >= blobs.size())
      return malformed("DeclSecurity PermissionSet index is null or outside #Blob heap");
    std::size_t cursor = row.permission_set_blob_index;
    auto length = compressed_uint(blobs, cursor);
    if (!length) return length.error();
    if (length.value() > blobs.size() - cursor)
      return malformed("DeclSecurity PermissionSet exceeds #Blob heap");
    if (length.value() > 4u * 1024u * 1024u)
      return Error{ErrorCode::resource_limit, "DeclSecurity PermissionSet exceeds 4 MiB"};
    if (length.value() > 64u * 1024u * 1024u - payload_bytes)
      return Error{ErrorCode::resource_limit, "DeclSecurity payloads exceed 64 MiB"};
    payload_bytes += length.value();
    row.permission_set_blob_offset = blob_it->second.offset + cursor;
    row.permission_set.assign(blobs.begin() + cursor, blobs.begin() + cursor + length.value());
    result.push_back(std::move(row));
  }
  return result;
} catch (const std::bad_alloc &) {
  return Error{ErrorCode::resource_limit, "Cannot allocate CLR declarative-security catalog"};
} catch (const std::length_error &) {
  return Error{ErrorCode::resource_limit, "CLR declarative-security catalog exceeds container limits"};
}

Result<std::vector<ManagedMethodImplementation>> parse_managed_method_implementations(
    std::span<const std::byte> root) try {
  if (root.size() > 64u * 1024u * 1024u)
    return Error{ErrorCode::resource_limit, "CLR MethodImpl inspection root exceeds 64 MiB"};
  auto parsed = parse_cli_metadata(root);
  if (!parsed) return parsed.error();
  const auto &md = parsed.value();
  const auto rows = [&](std::uint8_t id) {
    const auto it = md.tables.row_counts.find(id);
    return it == md.tables.row_counts.end() ? 0u : it->second;
  };
  const auto count = rows(25);
  if (count > 250000)
    return Error{ErrorCode::resource_limit, "CLR MethodImpl catalog exceeds 250,000 rows"};
  if (!count) return std::vector<ManagedMethodImplementation>{};

  auto table_it = md.streams.find("#~");
  if (table_it == md.streams.end()) table_it = md.streams.find("#-");
  if (table_it == md.streams.end()) return malformed("MethodImpl parsing requires a metadata tables stream");
  const auto tables = root.subspan(table_it->second.offset, table_it->second.size);
  const auto class_width = rows(2) < 65536 ? 2u : 4u;
  const auto method_width = coded_width(8, md.tables.row_counts); // MethodDefOrRef
  const auto row_it = md.tables.row_sizes.find(25);
  if (row_it == md.tables.row_sizes.end() || row_it->second != class_width + 2 * method_width)
    return malformed("MethodImpl row layout is inconsistent");

  std::uint64_t offset = md.tables.data_offset;
  for (std::uint8_t id = 0; id < 25; ++id) {
    const auto size = md.tables.row_sizes.find(id);
    if (rows(id) && size == md.tables.row_sizes.end())
      return malformed("MethodImpl preceding table has no row layout");
    if (size != md.tables.row_sizes.end()) offset += std::uint64_t{rows(id)} * size->second;
  }
  if (offset > tables.size() || std::uint64_t{count} * row_it->second > tables.size() - offset)
    return malformed("MethodImpl rows exceed tables stream");

  const auto index = [](std::span<const std::byte> bytes, std::size_t at, unsigned width) {
    return width == 2 ? std::uint32_t(u16(bytes, at)) : u32(bytes, at);
  };
  const auto method_token = [&](std::uint32_t coded) -> std::uint32_t {
    const auto tag = coded & 1u;
    const auto rid = coded >> 1;
    const auto table = static_cast<std::uint8_t>(tag == 0 ? 6 : 10);
    if (!rid || rid > rows(table) || rid > 0x00ffffffu) return 0;
    return (std::uint32_t{table} << 24) | rid;
  };

  std::vector<ManagedMethodImplementation> result;
  result.reserve(count);
  for (std::uint32_t rid = 1; rid <= count; ++rid) {
    const auto at = static_cast<std::size_t>(offset + std::uint64_t{rid - 1} * row_it->second);
    const auto owner = index(tables, at, class_width);
    if (!owner || owner > rows(2) || owner > 0x00ffffffu)
      return malformed("MethodImpl Class is outside the TypeDef table");
    const auto body = method_token(index(tables, at + class_width, method_width));
    const auto declaration = method_token(index(tables, at + class_width + method_width, method_width));
    if (!body || !declaration)
      return malformed("MethodImpl body or declaration is outside MethodDef/MemberRef tables");
    result.push_back({0x19000000u | rid, 0x02000000u | owner, body, declaration,
                      table_it->second.offset + at});
  }
  return result;
} catch (const std::bad_alloc &) {
  return Error{ErrorCode::resource_limit, "Cannot allocate CLR MethodImpl catalog"};
} catch (const std::length_error &) {
  return Error{ErrorCode::resource_limit, "CLR MethodImpl catalog exceeds container limits"};
}

namespace {
bool resource_utf8_valid(std::string_view s);
void decode_managed_marshal_descriptor(ManagedMarshalDescriptor& descriptor) {
  if(descriptor.native_type.empty())return;
  const auto code=std::to_integer<std::uint8_t>(descriptor.native_type[0]);
  static constexpr std::array<std::pair<std::uint8_t,std::string_view>,20> scalar_types={{
    {0x02,"boolean"},{0x03,"i1"},{0x04,"u1"},{0x05,"i2"},{0x06,"u2"},
    {0x07,"i4"},{0x08,"u4"},{0x09,"i8"},{0x0a,"u8"},{0x0b,"r4"},
    {0x0c,"r8"},{0x13,"bstr"},{0x14,"lpstr"},{0x15,"lpwstr"},{0x16,"lptstr"},
    {0x23,"ansibstr"},{0x24,"tbstr"},
    {0x1f,"int"},{0x20,"uint"},{0x26,"func"}}};
  const auto scalar=std::find_if(scalar_types.begin(),scalar_types.end(),[&](const auto& item){return item.first==code;});
  if(scalar!=scalar_types.end()&&descriptor.native_type.size()==1){
    descriptor.decode_status=ManagedMarshalDescriptorStatus::decoded_scalar;
    descriptor.native_type_name=scalar->second;
    return;
  }
  if(code==0x2a&&descriptor.native_type.size()>=2){
    const auto element=std::to_integer<std::uint8_t>(descriptor.native_type[1]);
    const bool intrinsic_element=(element>=0x02&&element<=0x0c)||element==0x14||element==0x15||
                                 element==0x1f||element==0x20||element==0x26;
    if(intrinsic_element){
      std::size_t cursor=2;
      std::optional<std::uint32_t> parameter,count;
      bool valid=true;
      if(cursor<descriptor.native_type.size()){
        auto value=compressed_uint(descriptor.native_type,cursor);
        if(!value)valid=false;else parameter=value.value();
      }
      if(valid&&cursor<descriptor.native_type.size()){
        auto value=compressed_uint(descriptor.native_type,cursor);
        if(!value)valid=false;else count=value.value();
      }
      if(valid&&cursor==descriptor.native_type.size()&&
         (!parameter||!*parameter||(descriptor.parent_token>>24)==8)){
        descriptor.decode_status=ManagedMarshalDescriptorStatus::decoded_array;
        descriptor.native_type_name="array";
        descriptor.array_element_type=element;
        descriptor.array_parameter_index=parameter;
        descriptor.array_element_count=count;
        return;
      }
    }
  }
  // CustomMarshaler is a widely emitted Microsoft extension (UnmanagedType
  // value 44), with four serialized strings. Treat it as recognized only when
  // all four fields are bounded and consume the complete descriptor.
  if(code==0x2c){
    std::size_t cursor=1;
    std::vector<std::optional<std::string>> fields;
    fields.reserve(4);
    bool valid=true;
    for(unsigned i=0;i<4&&valid;++i){
      if(cursor>=descriptor.native_type.size()){valid=false;break;}
      if(descriptor.native_type[cursor]==std::byte{0xff}){++cursor;fields.emplace_back(std::nullopt);continue;}
      auto length=compressed_uint(descriptor.native_type,cursor);
      if(!length||length.value()>descriptor.native_type.size()-cursor){valid=false;break;}
      std::string value;value.reserve(length.value());
      for(std::uint32_t n=0;n<length.value();++n)value.push_back(static_cast<char>(std::to_integer<unsigned char>(descriptor.native_type[cursor+n])));
      if(!value.empty()&&value.back()=='\0')value.pop_back();
      if(!resource_utf8_valid(value)){valid=false;break;}
      cursor+=length.value();fields.emplace_back(std::move(value));
    }
    if(valid&&cursor==descriptor.native_type.size()){
      descriptor.decode_status=ManagedMarshalDescriptorStatus::decoded_custom_marshaler;
      descriptor.native_type_name="custom-marshaler";
      descriptor.custom_marshaler_strings=std::move(fields);
    }
  }
}
}

Result<std::vector<ManagedMarshalDescriptor>> parse_managed_marshal_descriptors(std::span<const std::byte> root) try {
  if(root.size()>64u*1024u*1024u)return Error{ErrorCode::resource_limit,"CLR marshal metadata root exceeds 64 MiB"};
  auto parsed=parse_cli_metadata(root);if(!parsed)return parsed.error();const auto& md=parsed.value();
  const auto rows=[&](std::uint8_t id){const auto it=md.tables.row_counts.find(id);return it==md.tables.row_counts.end()?0u:it->second;};
  const auto count=rows(13);if(count>250000)return Error{ErrorCode::resource_limit,"CLR FieldMarshal catalog exceeds 250,000 rows"};
  if(!count)return std::vector<ManagedMarshalDescriptor>{};
  auto table_it=md.streams.find("#~");if(table_it==md.streams.end())table_it=md.streams.find("#-");
  const auto blob_it=md.streams.find("#Blob");if(table_it==md.streams.end()||blob_it==md.streams.end())return malformed("FieldMarshal parsing requires tables and #Blob heaps");
  const auto tables=root.subspan(table_it->second.offset,table_it->second.size),blobs=root.subspan(blob_it->second.offset,blob_it->second.size);
  const auto parent_width=coded_width(12,md.tables.row_counts),blob_width=(md.tables.heap_sizes&4)?4u:2u;
  const auto row_it=md.tables.row_sizes.find(13);if(row_it==md.tables.row_sizes.end()||row_it->second!=parent_width+blob_width)return malformed("FieldMarshal row layout is inconsistent");
  std::uint64_t offset=md.tables.data_offset;for(std::uint8_t id=0;id<13;++id){const auto size=md.tables.row_sizes.find(id);if(rows(id)&&size==md.tables.row_sizes.end())return malformed("FieldMarshal preceding table has no row layout");if(size!=md.tables.row_sizes.end())offset+=std::uint64_t{rows(id)}*size->second;}
  if(offset>tables.size()||std::uint64_t{count}*row_it->second>tables.size()-offset)return malformed("FieldMarshal rows exceed tables stream");
  const auto index=[](std::span<const std::byte> b,std::size_t p,unsigned w){return w==2?std::uint32_t(u16(b,p)):u32(b,p);};
  std::vector<ManagedMarshalDescriptor> result;result.reserve(count);std::set<std::uint32_t> parents;std::uint64_t payload_total=0;
  for(std::uint32_t rid=1;rid<=count;++rid){
    const auto at=static_cast<std::size_t>(offset+std::uint64_t{rid-1}*row_it->second);ManagedMarshalDescriptor value;value.token=0x0d000000u|rid;value.metadata_offset=table_it->second.offset+at;
    const auto coded=index(tables,at,parent_width),tag=coded&1u,parent_rid=coded>>1;
    const auto parent_table=tag==0?4u:8u;
    if(!parent_rid||parent_rid>rows(static_cast<std::uint8_t>(parent_table)))return malformed("FieldMarshal has an invalid HasFieldMarshal parent");
    value.parent_token=(std::uint32_t{parent_table}<<24)|parent_rid;
    if(!parents.insert(value.parent_token).second)return malformed("FieldMarshal parent has duplicate descriptors");
    value.blob_index=index(tables,at+parent_width,blob_width);if(!value.blob_index||value.blob_index>=blobs.size())return malformed("FieldMarshal NativeType index is null or outside #Blob heap");
    std::size_t cursor=value.blob_index;auto length=compressed_uint(blobs,cursor);if(!length)return length.error();
    if(!length.value())return malformed("FieldMarshal NativeType descriptor is empty");
    if(length.value()>blobs.size()-cursor)return malformed("FieldMarshal NativeType descriptor exceeds #Blob heap");
    if(length.value()>1024u*1024u)return Error{ErrorCode::resource_limit,"FieldMarshal NativeType descriptor exceeds 1 MiB"};
    if(length.value()>16u*1024u*1024u-payload_total)return Error{ErrorCode::resource_limit,"FieldMarshal payloads exceed 16 MiB"};payload_total+=length.value();
    value.blob_data_offset=blob_it->second.offset+cursor;const auto payload=blobs.subspan(cursor,length.value());value.native_type.assign(payload.begin(),payload.end());
    decode_managed_marshal_descriptor(value);result.push_back(std::move(value));
  }
  return result;
} catch(const std::bad_alloc&) {return Error{ErrorCode::resource_limit,"Cannot allocate CLR FieldMarshal catalog"};}
  catch(const std::length_error&) {return Error{ErrorCode::resource_limit,"CLR FieldMarshal catalog exceeds container limits"};}

Result<std::vector<ManagedResource>> parse_managed_resources(std::span<const std::byte> root) try {
  if(root.size()>64u*1024u*1024u)return Error{ErrorCode::resource_limit,"CLR resource metadata root exceeds 64 MiB"};
  auto parsed=parse_cli_metadata(root);if(!parsed)return parsed.error();const auto& md=parsed.value();
  const auto rows=[&](std::uint8_t id){const auto it=md.tables.row_counts.find(id);return it==md.tables.row_counts.end()?0u:it->second;};
  const auto count=rows(40);if(count>65536)return Error{ErrorCode::resource_limit,"CLR ManifestResource catalog exceeds 65,536 rows"};
  if(!count)return std::vector<ManagedResource>{};
  auto table_it=md.streams.find("#~");if(table_it==md.streams.end())table_it=md.streams.find("#-");
  const auto strings_it=md.streams.find("#Strings");
  if(table_it==md.streams.end()||strings_it==md.streams.end())return malformed("ManifestResource parsing requires tables and #Strings heaps");
  const auto tables=root.subspan(table_it->second.offset,table_it->second.size),strings=root.subspan(strings_it->second.offset,strings_it->second.size);
  const auto string_width=(md.tables.heap_sizes&1)?4u:2u;
  const auto implementation_width=coded_width(10,md.tables.row_counts);
  const auto expected_size=8u+string_width+implementation_width;
  const auto row_it=md.tables.row_sizes.find(40);
  if(row_it==md.tables.row_sizes.end()||row_it->second!=expected_size)return malformed("ManifestResource row layout is inconsistent");
  std::uint64_t offset=md.tables.data_offset;
  for(std::uint8_t id=0;id<40;++id){const auto size=md.tables.row_sizes.find(id);if(rows(id)&&size==md.tables.row_sizes.end())return malformed("ManifestResource preceding table has no row layout");if(size!=md.tables.row_sizes.end())offset+=std::uint64_t{rows(id)}*size->second;}
  if(offset>tables.size()||std::uint64_t{count}*row_it->second>tables.size()-offset)return malformed("ManifestResource rows exceed tables stream");
  const auto index=[](std::span<const std::byte> bytes,std::size_t at,unsigned width){return width==2?std::uint32_t(u16(bytes,at)):u32(bytes,at);};
  const auto read_string=[&](std::uint32_t value)->Result<std::string>{
    if(!value||value>=strings.size())return malformed("ManifestResource implementation name index exceeds #Strings heap");
    std::string text;text.reserve(std::min<std::size_t>(strings.size()-value,128));
    for(auto p=value;p<strings.size();++p){if(strings[p]==std::byte{0}){if(text.empty())return malformed("ManifestResource implementation name is empty");if(text.size()>4096)return Error{ErrorCode::resource_limit,"ManifestResource implementation name exceeds 4096 bytes"};return text;}text.push_back(static_cast<char>(std::to_integer<unsigned char>(strings[p])));if(text.size()>4096)return Error{ErrorCode::resource_limit,"ManifestResource implementation name exceeds 4096 bytes"};}
    return malformed("ManifestResource implementation name is unterminated");
  };
  const auto read_table_row=[&](std::uint8_t table,std::uint32_t rid)->Result<std::span<const std::byte>>{
    if(!rid||rid>rows(table))return malformed("ManifestResource implementation row is outside its metadata table");
    std::uint64_t table_offset=md.tables.data_offset;
    for(std::uint8_t id=0;id<table;++id){
      const auto size=md.tables.row_sizes.find(id);
      if(rows(id)&&size==md.tables.row_sizes.end())return malformed("ManifestResource implementation table has a missing row layout");
      if(size!=md.tables.row_sizes.end())table_offset+=std::uint64_t{rows(id)}*size->second;
    }
    const auto size=md.tables.row_sizes.find(table);
    if(size==md.tables.row_sizes.end()||table_offset>tables.size()||
       std::uint64_t{rows(table)}*size->second>tables.size()-table_offset)
      return malformed("ManifestResource implementation rows exceed tables stream");
    const auto row_offset=table_offset+std::uint64_t{rid-1}*size->second;
    return tables.subspan(static_cast<std::size_t>(row_offset),size->second);
  };
  const auto validate_blob=[&](std::uint32_t value)->Result<bool>{
    if(!value)return true;
    const auto blob_it=md.streams.find("#Blob");
    if(blob_it==md.streams.end())return malformed("ManifestResource implementation blob index has no #Blob heap");
    const auto blobs=root.subspan(blob_it->second.offset,blob_it->second.size);
    if(value>=blobs.size())return malformed("ManifestResource implementation blob index exceeds #Blob heap");
    std::size_t cursor=value;auto length=compressed_uint(blobs,cursor);if(!length)return length.error();
    if(length.value()>blobs.size()-cursor)return malformed("ManifestResource implementation blob exceeds #Blob heap");
    return true;
  };
  const auto read_blob_value=[&](std::uint32_t value)->Result<std::vector<std::byte>>{
    if(!value)return std::vector<std::byte>{};
    const auto blob_it=md.streams.find("#Blob");
    if(blob_it==md.streams.end())return malformed("ManifestResource implementation blob index has no #Blob heap");
    const auto blobs=root.subspan(blob_it->second.offset,blob_it->second.size);
    if(value>=blobs.size())return malformed("ManifestResource implementation blob index exceeds #Blob heap");
    std::size_t cursor=value;auto length=compressed_uint(blobs,cursor);if(!length)return length.error();
    if(length.value()>blobs.size()-cursor)return malformed("ManifestResource implementation blob exceeds #Blob heap");
    return std::vector<std::byte>(blobs.begin()+static_cast<std::ptrdiff_t>(cursor),
                                  blobs.begin()+static_cast<std::ptrdiff_t>(cursor+length.value()));
  };
  const auto file_width=4u+string_width+((md.tables.heap_sizes&4)?4u:2u);
  const auto assembly_ref_width=12u+((md.tables.heap_sizes&4)?4u:2u)+2u*string_width+((md.tables.heap_sizes&4)?4u:2u);
  const auto assembly_count=rows(32);
  if(assembly_count>1)return malformed("Assembly table has more than one row while resolving resource hashes");
  std::uint32_t assembly_hash_algorithm=0;
  if(assembly_count){
    const auto assembly_row_size=md.tables.row_sizes.find(32);
    const auto expected_assembly_size=16u+((md.tables.heap_sizes&4)?4u:2u)+2u*string_width;
    if(assembly_row_size==md.tables.row_sizes.end()||assembly_row_size->second!=expected_assembly_size)
      return malformed("Assembly table row layout is inconsistent while resolving resource hashes");
    auto assembly_row=read_table_row(32,1);if(!assembly_row)return assembly_row.error();
    assembly_hash_algorithm=u32(assembly_row.value(),0);
  }
  if(rows(38)&&(!md.tables.row_sizes.contains(38)||md.tables.row_sizes.at(38)!=file_width))return malformed("File table row layout is inconsistent");
  if(rows(35)&&(!md.tables.row_sizes.contains(35)||md.tables.row_sizes.at(35)!=assembly_ref_width))return malformed("AssemblyRef table row layout is inconsistent");
  std::vector<ManagedResource> result;result.reserve(count);std::size_t name_bytes=0;std::set<std::string> names;
  for(std::uint32_t rid=1;rid<=count;++rid){
    const auto at=static_cast<std::size_t>(offset+std::uint64_t{rid-1}*row_it->second);
    ManagedResource value;value.token=0x28000000u|rid;value.metadata_offset=table_it->second.offset+at;value.row_size=row_it->second;
    value.data_offset=u32(tables,at);value.flags=u32(tables,at+4);
    if((value.flags&~std::uint32_t{7})||(value.flags&7u)<1||(value.flags&7u)>2)return malformed("ManifestResource has invalid visibility flags");
    const auto name_index=index(tables,at+8,string_width);
    if(!name_index||name_index>=strings.size())return malformed("ManifestResource name index exceeds #Strings heap");
    auto end=name_index;while(end<strings.size()&&strings[end]!=std::byte{0}){if(end-name_index>=4096)return Error{ErrorCode::resource_limit,"ManifestResource name exceeds 4096 bytes"};++end;}
    if(end>=strings.size()||end==name_index)return malformed("ManifestResource name is empty or unterminated");
    value.name.reserve(end-name_index);for(auto p=name_index;p<end;++p)value.name.push_back(static_cast<char>(std::to_integer<unsigned char>(strings[p])));
    if(!names.insert(value.name).second)return malformed("ManifestResource names are duplicated");
    name_bytes+=value.name.size();if(name_bytes>8u*1024u*1024u)return Error{ErrorCode::resource_limit,"ManifestResource names exceed 8 MiB"};
    value.implementation_coded_index=index(tables,at+8+string_width,implementation_width);
    const auto tag=value.implementation_coded_index&3u,rid_value=value.implementation_coded_index>>2;
    if(!value.implementation_coded_index)value.implementation=ManagedResourceImplementationKind::embedded;
    else {
      if(!rid_value||rid_value>0x00ffffffu||tag==3)return malformed("ManifestResource has an invalid Implementation coded index");
      const std::uint8_t table=tag==0?38:tag==1?35:39;
      if(rid_value>rows(table))return malformed("ManifestResource Implementation is outside its metadata table");
      value.implementation_token=(std::uint32_t{table}<<24)|rid_value;
      value.implementation=tag==0?ManagedResourceImplementationKind::file:
          tag==1?ManagedResourceImplementationKind::assembly_ref:ManagedResourceImplementationKind::exported_type;
      if(value.implementation==ManagedResourceImplementationKind::file&&value.data_offset!=0)
        return malformed("File-backed ManifestResource must have a zero offset");
      if(value.implementation==ManagedResourceImplementationKind::file){
        auto file_row=read_table_row(38,rid_value);if(!file_row)return file_row.error();
        const auto file_flags=u32(file_row.value(),0);
        if(file_flags&~std::uint32_t{1})return malformed("File implementation has invalid flags");
        auto file_name=read_string(index(file_row.value(),4,string_width));if(!file_name)return file_name.error();
        value.implementation_name=std::move(file_name.value());
        value.implementation_file_contains_metadata=(file_flags&1u)==0;
        value.implementation_hash_blob_index=index(file_row.value(),4+string_width,(md.tables.heap_sizes&4)?4u:2u);
        auto hash_valid=validate_blob(value.implementation_hash_blob_index);if(!hash_valid)return hash_valid.error();
        auto file_hash=read_blob_value(value.implementation_hash_blob_index);if(!file_hash)return file_hash.error();
        value.implementation_hash=std::move(file_hash.value());
        value.implementation_hash_algorithm=assembly_hash_algorithm;
        value.resolution=ManagedResourceResolutionState::unresolved;
        value.resolution_diagnostic="File resource has not been resolved against caller-supplied input";
      }else if(value.implementation==ManagedResourceImplementationKind::assembly_ref){
        auto assembly_row=read_table_row(35,rid_value);if(!assembly_row)return assembly_row.error();
        const auto row=assembly_row.value();
        value.implementation_major=u16(row,0);value.implementation_minor=u16(row,2);
        value.implementation_build=u16(row,4);value.implementation_revision=u16(row,6);
        value.implementation_flags=u32(row,8);
        const auto blob_width=(md.tables.heap_sizes&4)?4u:2u;
        value.implementation_key_or_token_blob_index=index(row,12,blob_width);
        auto key_valid=validate_blob(value.implementation_key_or_token_blob_index);if(!key_valid)return key_valid.error();
        auto key_or_token=read_blob_value(value.implementation_key_or_token_blob_index);if(!key_or_token)return key_or_token.error();
        value.implementation_key_or_token=std::move(key_or_token.value());
        auto assembly_name=read_string(index(row,12+blob_width,string_width));if(!assembly_name)return assembly_name.error();
        const auto culture_index=index(row,12+blob_width+string_width,string_width);
        if(culture_index){auto culture=read_string(culture_index);if(!culture)return culture.error();value.implementation_culture=std::move(culture.value());}
        const auto hash_index=index(row,12+blob_width+2*string_width,blob_width);
        auto hash_valid=validate_blob(hash_index);if(!hash_valid)return hash_valid.error();
        auto assembly_hash=read_blob_value(hash_index);if(!assembly_hash)return assembly_hash.error();
        value.implementation_hash_blob_index=hash_index;
        value.implementation_hash=std::move(assembly_hash.value());
        value.implementation_hash_algorithm=assembly_hash_algorithm;
        value.implementation_name=std::move(assembly_name.value());
        value.resolution=ManagedResourceResolutionState::unresolved;
        value.resolution_diagnostic="AssemblyRef resource has not been resolved against caller-supplied input";
      }else{
        value.resolution=ManagedResourceResolutionState::unresolved;
        value.resolution_diagnostic="ExportedType resource implementations are not resolved";
      }
    }
    result.push_back(std::move(value));
  }
  return result;
} catch(const std::bad_alloc&) {return Error{ErrorCode::resource_limit,"Cannot allocate CLR ManifestResource catalog"};}
  catch(const std::length_error&) {return Error{ErrorCode::resource_limit,"CLR ManifestResource catalog exceeds container limits"};}

namespace {
Result<std::uint32_t> resource_7bit(std::span<const std::byte> b,std::size_t limit,std::size_t& p){
  std::uint32_t value=0;for(unsigned i=0;i<5;++i){if(p>=limit)return malformed("Truncated .resources 7-bit integer");const auto v=std::to_integer<std::uint8_t>(b[p++]);if(i==4&&(v&0xf0))return malformed("Overflowing .resources 7-bit integer");value|=std::uint32_t(v&0x7f)<<(i*7);if(!(v&0x80)){if(i&&value<(std::uint32_t{1}<<(i*7)))return malformed("Noncanonical .resources 7-bit integer");return value;}}return malformed("Overlong .resources 7-bit integer");
}
bool resource_utf8_valid(std::string_view s){
  for(std::size_t p=0;p<s.size();){const auto a=static_cast<std::uint8_t>(s[p++]);if(a<0x80)continue;std::uint32_t cp=0,min=0;unsigned n=0;if(a>=0xc2&&a<=0xdf){cp=a&31;min=0x80;n=1;}else if(a>=0xe0&&a<=0xef){cp=a&15;min=0x800;n=2;}else if(a>=0xf0&&a<=0xf4){cp=a&7;min=0x10000;n=3;}else return false;if(s.size()-p<n)return false;for(unsigned i=0;i<n;++i){const auto c=static_cast<std::uint8_t>(s[p++]);if((c&0xc0)!=0x80)return false;cp=(cp<<6)|(c&63);}if(cp<min||cp>0x10ffff||(cp>=0xd800&&cp<=0xdfff))return false;}return true;
}
bool append_resource_scalar(std::string& s,std::uint32_t cp){
  if(cp<=0x7f)s.push_back(static_cast<char>(cp));else if(cp<=0x7ff){s.push_back(static_cast<char>(0xc0|(cp>>6)));s.push_back(static_cast<char>(0x80|(cp&63)));}else if(cp<=0xffff){s.push_back(static_cast<char>(0xe0|(cp>>12)));s.push_back(static_cast<char>(0x80|((cp>>6)&63)));s.push_back(static_cast<char>(0x80|(cp&63)));}else if(cp<=0x10ffff){s.push_back(static_cast<char>(0xf0|(cp>>18)));s.push_back(static_cast<char>(0x80|((cp>>12)&63)));s.push_back(static_cast<char>(0x80|((cp>>6)&63)));s.push_back(static_cast<char>(0x80|(cp&63)));}else return false;return true;
}
Result<std::string> resource_name_utf16(std::span<const std::byte> b,std::size_t p,std::size_t n){
  if(n&1u)return malformed(".resources name has an odd UTF-16 byte count");std::string out;out.reserve(n);
  for(std::size_t i=0;i<n;i+=2){const auto hi=u16(b,p+i);std::uint32_t cp=hi;if(hi>=0xd800&&hi<=0xdbff){if(i+4>n)return malformed(".resources name has an unpaired UTF-16 high surrogate");const auto lo=u16(b,p+i+2);if(lo<0xdc00||lo>0xdfff)return malformed(".resources name has an invalid UTF-16 surrogate pair");cp=0x10000+((hi-0xd800)<<10)+(lo-0xdc00);i+=2;}else if(hi>=0xdc00&&hi<=0xdfff)return malformed(".resources name has an unpaired UTF-16 low surrogate");if(!append_resource_scalar(out,cp))return malformed(".resources name cannot be encoded as UTF-8");}return out;
}
Result<std::string> resource_string(std::span<const std::byte> b,std::size_t limit,std::size_t& p){
  auto n=resource_7bit(b,limit,p);if(!n)return n.error();if(n.value()>1024u*1024u)return Error{ErrorCode::resource_limit,".resources string exceeds 1 MiB"};if(n.value()>limit-p)return malformed(".resources string exceeds its data extent");std::string s;s.reserve(n.value());for(std::uint32_t i=0;i<n.value();++i)s.push_back(static_cast<char>(std::to_integer<unsigned char>(b[p+i])));p+=n.value();if(!resource_utf8_valid(s))return malformed(".resources string is invalid UTF-8");return s;
}
std::uint32_t resource_name_hash(std::span<const std::byte> b,std::size_t p,std::size_t n){
  std::uint32_t hash=5381;for(std::size_t i=0;i<n;i+=2)hash=((hash<<5)+hash)^u16(b,p+i);return hash;
}
Result<bool> parse_dotnet_resources(ManagedResource& resource){
  auto b=std::span<const std::byte>(resource.payload);if(b.size()<4||u32(b,0)!=0xbeefcaceu)return true;
  resource.payload_format=ManagedResourcePayloadFormat::dotnet_resources_v2;if(b.size()<12)return malformed("Truncated .resources header");
  const auto header_version=u32(b,4),header_size=u32(b,8);if(header_version!=1){resource.payload_format=ManagedResourcePayloadFormat::unsupported_dotnet_resources;resource.payload_diagnostic="Unsupported ResourceManager header version";return true;}
  if(header_size>64u*1024u||header_size>b.size()-12)return malformed(".resources ResourceManager header extent is invalid");
  const auto header_end=std::size_t{12}+header_size;std::size_t p=12;auto reader=resource_string(b,header_end,p);if(!reader)return reader.error();auto set=resource_string(b,header_end,p);if(!set)return set.error();
  if(!reader.value().starts_with("System.Resources.ResourceReader")||!set.value().starts_with("System.Resources.RuntimeResourceSet")){resource.payload_format=ManagedResourcePayloadFormat::unsupported_dotnet_resources;resource.payload_diagnostic="Nonstandard ResourceReader or ResourceSet implementation";return true;}
  p=header_end;if(b.size()-p<12)return malformed("Truncated .resources RuntimeResourceSet header");const auto version=u32(b,p);p+=4;if(version!=2){resource.payload_format=ManagedResourcePayloadFormat::unsupported_dotnet_resources;resource.payload_diagnostic="Unsupported RuntimeResourceSet version";return true;}
  const auto count=u32(b,p);p+=4;const auto type_count=u32(b,p);p+=4;if(count>65536||type_count>4096)return Error{ErrorCode::resource_limit,".resources exceeds 65,536 records or 4,096 type names"};
  std::vector<std::string> types;types.reserve(type_count);std::size_t type_bytes=0;for(std::uint32_t i=0;i<type_count;++i){auto type=resource_string(b,b.size(),p);if(!type)return type.error();if(type.value().empty())return malformed(".resources type name is empty");if(type.value().size()>4u*1024u*1024u-type_bytes)return Error{ErrorCode::resource_limit,".resources type names exceed 4 MiB"};type_bytes+=type.value().size();types.push_back(std::move(type.value()));}
  while(p&7u){if(p>=b.size())return malformed("Truncated .resources hash alignment");++p;}
  const auto arrays=std::uint64_t{count}*8;if(arrays>b.size()-p)return malformed(".resources hash/position arrays exceed the file");
  std::vector<std::uint32_t> name_hashes;name_hashes.reserve(count);std::uint32_t previous_hash_order=0;
  for(std::uint32_t i=0;i<count;++i){const auto hash=u32(b,p);p+=4;const auto order=hash^0x80000000u;if(i&&order<previous_hash_order)return malformed(".resources name hashes are not signed-sorted");previous_hash_order=order;name_hashes.push_back(hash);}
  std::vector<std::uint32_t> name_positions;name_positions.reserve(count);for(std::uint32_t i=0;i<count;++i){name_positions.push_back(u32(b,p));p+=4;}
  if(b.size()-p<4)return malformed("Truncated .resources data-section offset");const auto data_section=u32(b,p);p+=4;if(data_section<p||data_section>b.size())return malformed(".resources data-section offset overlaps its tables or exceeds the payload");
  const auto names_begin=p,name_size=std::size_t(data_section)-names_begin;std::set<std::uint32_t> seen_name_pos;std::set<std::string> seen_names;std::size_t name_bytes=0;
  struct NameEntry{std::string name;std::uint32_t data=0;};std::vector<NameEntry> names;names.reserve(count);std::vector<std::pair<std::size_t,std::size_t>> name_extents;name_extents.reserve(count);
  for(std::size_t name_index=0;name_index<name_positions.size();++name_index){const auto offset=name_positions[name_index];if(offset>=name_size||!seen_name_pos.insert(offset).second)return malformed(".resources name offset is duplicate or outside the name section");std::size_t q=names_begin+offset;auto byte_count=resource_7bit(b,data_section,q);if(!byte_count)return byte_count.error();if(byte_count.value()>data_section-q||data_section-q-byte_count.value()<4)return malformed(".resources name entry exceeds its section");if(byte_count.value()>4u*1024u*1024u-name_bytes)return Error{ErrorCode::resource_limit,".resources names exceed 4 MiB"};if(byte_count.value()&1u)return malformed(".resources name has an odd UTF-16 byte count");if(resource_name_hash(b,q,byte_count.value())!=name_hashes[name_index])return malformed(".resources name hash does not match its UTF-16 name");auto name=resource_name_utf16(b,q,byte_count.value());if(!name)return name.error();q+=byte_count.value();if(name.value().empty()||!seen_names.insert(name.value()).second)return malformed(".resources names are empty or duplicated");const auto data=u32(b,q);q+=4;if(count&&data>=b.size()-data_section)return malformed(".resources record data offset is outside the data section");names.push_back({std::move(name.value()),data});name_extents.emplace_back(names_begin+offset,q);name_bytes+=byte_count.value();}
  std::sort(name_extents.begin(),name_extents.end());for(std::size_t i=1;i<name_extents.size();++i)if(name_extents[i].first<name_extents[i-1].second)return malformed(".resources name entries overlap");
  std::vector<std::pair<std::uint32_t,std::size_t>> order;order.reserve(count);for(std::size_t i=0;i<names.size();++i)order.emplace_back(names[i].data,i);std::sort(order.begin(),order.end());
  for(std::size_t ri=0;ri<order.size();++ri){if((ri==0&&order[ri].first!=0)||(ri&&order[ri-1].first==order[ri].first))return malformed(".resources data offsets are not unique and contiguous");const auto start=std::size_t(data_section)+order[ri].first;const auto end=ri+1<order.size()?std::size_t(data_section)+order[ri+1].first:b.size();if(start>=end)return malformed(".resources record has an empty extent");std::size_t q=start;auto code=resource_7bit(b,end,q);if(!code)return code.error();ManagedResourceRecord rec;rec.name=names[order[ri].second].name;rec.type_code=code.value();rec.data_offset=static_cast<std::uint32_t>(q);rec.data_size=static_cast<std::uint32_t>(end-q);const auto body=q;
    if(rec.type_code>=64){const auto ti=rec.type_code-64;if(ti>=types.size())return malformed(".resources user type index exceeds its type table");rec.type_name=types[ti];rec.kind=ManagedResourceValueKind::user_type;rec.supported=false;}
    else {const auto n=end-q;const auto fixed=[&](std::size_t width,ManagedResourceValueKind kind)->Result<bool>{if(n!=width)return malformed(".resources fixed-width value has an incorrect size");rec.kind=kind;rec.supported=true;rec.scalar_bits=0;for(std::size_t i=0;i<std::min<std::size_t>(width,8);++i)rec.scalar_bits|=std::uint64_t(std::to_integer<std::uint8_t>(b[q+i]))<<(8*i);rec.data_size=static_cast<std::uint32_t>(width);q=end;return true;};
      switch(rec.type_code){case 0:rec.kind=ManagedResourceValueKind::null_value;rec.supported=true;rec.data_size=0;if(n)return malformed(".resources null record has trailing bytes");break;
      case 1:{rec.kind=ManagedResourceValueKind::string_value;auto value=resource_string(b,end,q);if(!value)return value.error();if(q!=end)return malformed(".resources string has trailing bytes");rec.string_value=std::move(value.value());rec.supported=true;rec.data_offset=static_cast<std::uint32_t>(body+(q-body-rec.string_value.size()));rec.data_size=static_cast<std::uint32_t>(rec.string_value.size());break;}
      case 2:if(n!=1||std::to_integer<std::uint8_t>(b[q])>1)return malformed("Invalid .resources Boolean value");{auto ok=fixed(1,ManagedResourceValueKind::boolean);if(!ok)return ok.error();}break;
      case 3:{auto ok=fixed(2,ManagedResourceValueKind::character);if(!ok)return ok.error();break;}
      case 4:case 5:{auto ok=fixed(1,rec.type_code==4?ManagedResourceValueKind::unsigned_integer:ManagedResourceValueKind::signed_integer);if(!ok)return ok.error();break;}
      case 6:case 7:{auto ok=fixed(2,rec.type_code==6?ManagedResourceValueKind::signed_integer:ManagedResourceValueKind::unsigned_integer);if(!ok)return ok.error();break;}
      case 8:case 9:{auto ok=fixed(4,rec.type_code==8?ManagedResourceValueKind::signed_integer:ManagedResourceValueKind::unsigned_integer);if(!ok)return ok.error();break;}
      case 10:case 11:{auto ok=fixed(8,rec.type_code==10?ManagedResourceValueKind::signed_integer:ManagedResourceValueKind::unsigned_integer);if(!ok)return ok.error();break;}
      case 12:{auto ok=fixed(4,ManagedResourceValueKind::single);if(!ok)return ok.error();break;}case 13:{auto ok=fixed(8,ManagedResourceValueKind::double_value);if(!ok)return ok.error();break;}
      case 14:{auto ok=fixed(16,ManagedResourceValueKind::decimal);if(!ok)return ok.error();break;}case 15:{auto ok=fixed(8,ManagedResourceValueKind::date_time);if(!ok)return ok.error();break;}case 16:{auto ok=fixed(8,ManagedResourceValueKind::time_span);if(!ok)return ok.error();break;}
      case 32:case 33:{if(n<4)return malformed("Truncated .resources byte-array/stream length");const auto length=u32(b,q);q+=4;if(length!=end-q)return malformed(".resources byte-array/stream length mismatches its record extent");rec.kind=rec.type_code==32?ManagedResourceValueKind::byte_array:ManagedResourceValueKind::stream;rec.supported=true;rec.data_offset=static_cast<std::uint32_t>(q);rec.data_size=length;q=end;break;}
      default:rec.kind=ManagedResourceValueKind::unsupported;rec.supported=false;break;}
    }
    if(rec.supported&&q!=end)return malformed(".resources record parser did not consume its extent");resource.records.push_back(std::move(rec));
  }
  return true;
}
} // namespace

Result<std::vector<ManagedFieldRva>> parse_managed_field_rvas(std::span<const std::byte> root) try {
  if (root.size() > 64u * 1024u * 1024u)
    return Error{ErrorCode::resource_limit, "CLR FieldRVA inspection root exceeds 64 MiB"};
  auto parsed = parse_cli_metadata(root);
  if (!parsed) return parsed.error();
  const auto &metadata = parsed.value();
  const auto rows = [&](std::uint8_t id) {
    const auto it = metadata.tables.row_counts.find(id);
    return it == metadata.tables.row_counts.end() ? 0u : it->second;
  };
  const auto count = rows(29);
  if (count > 250000)
    return Error{ErrorCode::resource_limit, "CLR FieldRVA catalog exceeds 250,000 rows"};
  if (!count) return std::vector<ManagedFieldRva>{};
  if (!rows(4)) return malformed("FieldRVA rows have no FieldDef owners");
  auto tables_it = metadata.streams.find("#~");
  if (tables_it == metadata.streams.end()) tables_it = metadata.streams.find("#-");
  if (tables_it == metadata.streams.end()) return malformed("FieldRVA parsing requires a metadata tables stream");
  const auto tables = root.subspan(tables_it->second.offset, tables_it->second.size);
  const auto field_width = rows(4) < 65536 ? 2u : 4u;
  const auto row_it = metadata.tables.row_sizes.find(29);
  if (row_it == metadata.tables.row_sizes.end() || row_it->second != 4 + field_width)
    return malformed("FieldRVA row layout is inconsistent");
  std::uint64_t offset = metadata.tables.data_offset;
  for (std::uint8_t id = 0; id < 29; ++id) {
    const auto table_rows = metadata.tables.row_counts.find(id);
    const auto size = metadata.tables.row_sizes.find(id);
    if (table_rows != metadata.tables.row_counts.end() && table_rows->second &&
        size == metadata.tables.row_sizes.end())
      return malformed("FieldRVA preceding table has no row layout");
    if (size != metadata.tables.row_sizes.end())
      offset += std::uint64_t{rows(id)} * size->second;
  }
  if (offset > tables.size() || std::uint64_t{count} * row_it->second > tables.size() - offset)
    return malformed("FieldRVA rows exceed tables stream");
  const auto read_index = [](std::span<const std::byte> bytes, std::size_t at, unsigned width) {
    return width == 2 ? std::uint32_t(u16(bytes, at)) : u32(bytes, at);
  };
  std::vector<ManagedFieldRva> result;
  result.reserve(count);
  std::set<std::uint32_t> seen_fields;
  for (std::uint32_t rid = 1; rid <= count; ++rid) {
    const auto at = static_cast<std::size_t>(offset + std::uint64_t{rid - 1} * row_it->second);
    const auto rva = u32(tables, at);
    const auto field = read_index(tables, at + 4, field_width);
    if (!rva || !field || field > rows(4) || field > 0x00ffffffu)
      return malformed("FieldRVA has an invalid RVA or FieldDef index");
    const auto token = 0x04000000u | field;
    if (!seen_fields.insert(token).second)
      return malformed("FieldDef has multiple FieldRVA rows");
    result.push_back({token, rva, tables_it->second.offset + at});
  }
  return result;
} catch (const std::bad_alloc &) {
  return Error{ErrorCode::resource_limit, "Cannot allocate CLR FieldRVA catalog"};
} catch (const std::length_error &) {
  return Error{ErrorCode::resource_limit, "CLR FieldRVA catalog exceeds container limits"};
}

Result<std::vector<ManagedFieldLayout>> parse_managed_field_layouts(std::span<const std::byte> root){
  auto parsed=parse_cli_metadata(root);if(!parsed)return parsed.error();
  const auto &metadata=parsed.value();
  const auto count_it=metadata.tables.row_counts.find(16);
  if(count_it==metadata.tables.row_counts.end() || !count_it->second)return std::vector<ManagedFieldLayout>{};
  const auto field_rows=metadata.tables.row_counts.find(4);
  const auto field_count=field_rows==metadata.tables.row_counts.end()?0u:field_rows->second;
  const auto index_width=field_count<65536?2u:4u;
  const auto row=metadata.tables.row_sizes.find(16);
  auto table_it=metadata.streams.find("#~");if(table_it==metadata.streams.end())table_it=metadata.streams.find("#-");
  if(row==metadata.tables.row_sizes.end() || row->second!=4+index_width || table_it==metadata.streams.end())
    return malformed("CLR FieldLayout row layout is inconsistent");
  const auto tables=root.subspan(table_it->second.offset,table_it->second.size);
  std::uint64_t offset=metadata.tables.data_offset;
  for(std::uint8_t id=0;id<16;++id)
    if(const auto rows=metadata.tables.row_counts.find(id);rows!=metadata.tables.row_counts.end())
      if(const auto size=metadata.tables.row_sizes.find(id);size!=metadata.tables.row_sizes.end())
        offset+=std::uint64_t{rows->second}*size->second;
  if(offset>tables.size() || std::uint64_t{count_it->second}*row->second>tables.size()-offset)
    return malformed("CLR FieldLayout rows exceed tables stream");
  std::vector<ManagedFieldLayout> result;result.reserve(count_it->second);
  std::vector<bool> seen(field_count+1);
  std::uint32_t previous=0;
  for(std::uint32_t n=0;n<count_it->second;++n) {
    const auto at=static_cast<std::size_t>(offset+std::uint64_t{n}*row->second);
    const auto field=index_width==2?u16(tables,at+4):u32(tables,at+4);
    if(!field || field>field_count || seen[field])
      return malformed("CLR FieldLayout contains an invalid or duplicate FieldDef index");
    if(n && field<previous)return malformed("CLR FieldLayout rows are not sorted by FieldDef");
    seen[field]=true;previous=field;
    result.push_back({0x04000000u|field,u32(tables,at),
      std::uint64_t{table_it->second.offset}+offset+std::uint64_t{n}*row->second});
  }
  return result;
}

Result<std::vector<ManagedField>> parse_managed_fields(std::span<const std::byte> root){
  auto parsed=parse_cli_metadata(root);if(!parsed)return parsed.error();
  const auto& metadata=parsed.value();
  const auto row_count=[&](std::uint8_t id){const auto it=metadata.tables.row_counts.find(id);return it==metadata.tables.row_counts.end()?0u:it->second;};
  const auto field_count=row_count(4),type_count=row_count(2),pointer_count=row_count(3);
  if(field_count>250000)return Error{ErrorCode::resource_limit,"CLR FieldDef catalog exceeds 250,000 rows"};
  if(pointer_count && pointer_count!=field_count)return malformed("CLR FieldPtr count does not match FieldDef count");
  auto field_rvas = parse_managed_field_rvas(root);
  if (!field_rvas) return field_rvas.error();
  std::map<std::uint32_t, ManagedFieldRva> field_rva_by_token;
  for (const auto &field_rva : field_rvas.value()) field_rva_by_token.emplace(field_rva.field_token, field_rva);
  auto field_layouts=parse_managed_field_layouts(root);if(!field_layouts)return field_layouts.error();
  std::map<std::uint32_t,ManagedFieldLayout> field_layout_by_token;
  for(const auto &layout:field_layouts.value())field_layout_by_token.emplace(layout.field_token,layout);
  if(!field_count)return std::vector<ManagedField>{};
  auto constants=parse_managed_constants(root);if(!constants)return constants.error();
  std::map<std::uint32_t,ManagedConstant> defaults;
  for(auto& value:constants.value())if((value.parent_token>>24)==4)defaults.emplace(value.parent_token,std::move(value));
  auto marshal_rows=parse_managed_marshal_descriptors(root);if(!marshal_rows)return marshal_rows.error();
  std::map<std::uint32_t,ManagedMarshalDescriptor> marshal_descriptors;
  for(auto& value:marshal_rows.value())if((value.parent_token>>24)==4)
    marshal_descriptors.emplace(value.parent_token,std::move(value));
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
    if(const auto layout=field_layout_by_token.find(field.token);layout!=field_layout_by_token.end()) {
      field.explicit_layout_offset=layout->second.offset;
      field.layout_metadata_offset=layout->second.metadata_offset;
    }
    const auto rva = field_rva_by_token.find(field.token);
    const bool has_rva_flag = (field.flags & 0x0100u) != 0;
    if (has_rva_flag != (rva != field_rva_by_token.end()))
      return malformed("FieldDef HasFieldRVA flag does not match FieldRVA table");
    if (rva != field_rva_by_token.end()) {
      field.rva = rva->second.rva;
      field.rva_metadata_offset = rva->second.metadata_offset;
    }
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
    if(const auto value=defaults.find(field.token);value!=defaults.end())field.default_value=std::move(value->second);
    if(const auto marshal=marshal_descriptors.find(field.token);marshal!=marshal_descriptors.end())
      field.marshal_descriptor=std::move(marshal->second);
    result.push_back(std::move(field));
  }
  return result;
}

Result<std::vector<ManagedProperty>> parse_managed_properties(std::span<const std::byte> root) try {
  if(root.size()>64u*1024u*1024u)return Error{ErrorCode::resource_limit,"CLR property inspection root exceeds 64 MiB"};
  auto parsed=parse_cli_metadata(root);if(!parsed)return parsed.error();const auto& md=parsed.value();
  const auto rows=[&](std::uint8_t id){const auto it=md.tables.row_counts.find(id);return it==md.tables.row_counts.end()?0u:it->second;};
  const auto count=rows(23),maps=rows(21),pointers=rows(22),semantics=rows(24);
  if(count>65536||maps>65536||semantics>250000)return Error{ErrorCode::resource_limit,"CLR property table count exceeds its limit"};
  if(pointers&&pointers!=count)return malformed("PropertyPtr count does not match Property count");
  if(!count){if(maps)return malformed("PropertyMap has no Property rows");return std::vector<ManagedProperty>{};}
  if(!maps)return malformed("Property rows have no PropertyMap owners");
  auto tables_it=md.streams.find("#~");if(tables_it==md.streams.end())tables_it=md.streams.find("#-");
  const auto strings_it=md.streams.find("#Strings"),blobs_it=md.streams.find("#Blob");
  if(tables_it==md.streams.end()||strings_it==md.streams.end()||blobs_it==md.streams.end())return malformed("Property parsing requires tables, #Strings and #Blob");
  const auto tables=root.subspan(tables_it->second.offset,tables_it->second.size),strings=root.subspan(strings_it->second.offset,strings_it->second.size),blobs=root.subspan(blobs_it->second.offset,blobs_it->second.size);
  const auto sw=(md.tables.heap_sizes&1)?4u:2u,bw=(md.tables.heap_sizes&4)?4u:2u;
  const auto index_width=[&](std::uint8_t id){return rows(id)<65536?2u:4u;};
  const auto read_index=[&](std::span<const std::byte> bytes,std::size_t at,std::uint32_t width){return width==2?std::uint32_t(u16(bytes,at)):u32(bytes,at);};
  const auto row_size=[&](std::uint8_t id){const auto it=md.tables.row_sizes.find(id);return it==md.tables.row_sizes.end()?0u:it->second;};
  const auto table_offset=[&](std::uint8_t id){std::uint64_t offset=md.tables.data_offset;for(std::uint8_t n=0;n<id;++n)offset+=std::uint64_t{rows(n)}*row_size(n);return offset;};
  const auto table_valid=[&](std::uint8_t id,std::uint32_t expected){const auto at=table_offset(id);return row_size(id)==expected&&at<=tables.size()&&std::uint64_t{rows(id)}*expected<=tables.size()-at;};
  const auto pw=index_width(23),tw=index_width(2),mw=index_width(6),aw=coded_width(7,md.tables.row_counts);
  if(!table_valid(23,2+sw+bw)||!table_valid(21,tw+pw)||(pointers&&!table_valid(22,pw))||(semantics&&!table_valid(24,2+mw+aw)))return malformed("Property table layout or extent is inconsistent");
  std::vector<std::uint32_t> order(count);std::vector<bool> seen(count+1);
  for(std::uint32_t n=0;n<count;++n){const auto rid=pointers?read_index(tables,static_cast<std::size_t>(table_offset(22)+std::uint64_t{n}*pw),pw):n+1;if(!rid||rid>count||seen[rid])return malformed("PropertyPtr contains an invalid or duplicate Property index");seen[rid]=true;order[n]=rid;}
  auto catalog=parse_managed_type_catalog(root);if(!catalog)return catalog.error();
  std::vector<std::uint32_t> owners(count+1),starts,parents;starts.reserve(maps);parents.reserve(maps);std::set<std::uint32_t> seen_parents;
  for(std::uint32_t n=0;n<maps;++n){const auto at=static_cast<std::size_t>(table_offset(21)+std::uint64_t{n}*row_size(21));const auto parent=read_index(tables,at,tw),first=read_index(tables,at+tw,pw);if(!parent||parent>catalog.value().definitions.size()||!seen_parents.insert(parent).second||!first||first>count||(!starts.empty()&&first<=starts.back()))return malformed("PropertyMap has invalid parents or list boundaries");parents.push_back(parent);starts.push_back(first);}
  if(starts.front()!=1)return malformed("PropertyMap leaves initial Property rows unowned");
  for(std::size_t n=0;n<starts.size();++n){const auto end=n+1<starts.size()?starts[n+1]:count+1;for(auto pos=starts[n];pos<end;++pos)owners[order[pos-1]]=parents[n];}
  auto constants=parse_managed_constants(root);if(!constants)return constants.error();std::map<std::uint32_t,ManagedConstant> defaults;for(auto& value:constants.value())if((value.parent_token>>24)==23)defaults.emplace(value.parent_token,std::move(value));
  std::size_t name_bytes=0,signature_bytes=0,signature_nodes=100000;std::set<std::uint32_t> active_specs;
  const auto read_name=[&](std::uint32_t index)->Result<std::string>{if(!index||index>=strings.size())return malformed("Property name index is outside #Strings");std::string text;for(auto at=index;at<strings.size();++at){if(strings[at]==std::byte{0}){if(text.empty())return malformed("Property has an empty name");name_bytes+=text.size();if(name_bytes>8u*1024u*1024u)return Error{ErrorCode::resource_limit,"Property names exceed 8 MiB"};return text;}if(text.size()>=4096)return Error{ErrorCode::resource_limit,"Property name exceeds 4096 bytes"};text.push_back(static_cast<char>(std::to_integer<unsigned char>(strings[at])));}return malformed("Property name is unterminated");};
  std::vector<ManagedProperty> result;result.reserve(count);
  for(std::uint32_t rid=1;rid<=count;++rid){
    const auto at=static_cast<std::size_t>(table_offset(23)+std::uint64_t{rid-1}*row_size(23));ManagedProperty property;property.token=0x17000000u|rid;property.flags=u16(tables,at);property.declaring_type_token=0x02000000u|owners[rid];
    const auto& owner_name=catalog.value().definitions[owners[rid]-1].full_name;if(owner_name.size()>8u*1024u*1024u-name_bytes)return Error{ErrorCode::resource_limit,"Property names and owners exceed 8 MiB"};name_bytes+=owner_name.size();property.declaring_type=owner_name;
    if((property.flags&~0x1600u)||((property.flags&0x400u)&&!(property.flags&0x200u)))return malformed("Property has reserved or inconsistent flags");
    auto name=read_name(read_index(tables,at+2,sw));if(!name)return name.error();property.name=std::move(name.value());property.signature_index=read_index(tables,at+2+sw,bw);property.metadata_offset=tables_it->second.offset+at;property.row_size=row_size(23);
    if(!property.signature_index||property.signature_index>=blobs.size())return malformed("Property signature index is outside #Blob");
    std::size_t cursor=property.signature_index;auto length=compressed_uint(blobs,cursor);if(!length)return length.error();if(length.value()>blobs.size()-cursor)return malformed("Property signature exceeds #Blob");
    if(length.value()>65536||length.value()>16u*1024u*1024u-signature_bytes)return Error{ErrorCode::resource_limit,"Property signature byte budget exceeded"};signature_bytes+=length.value();property.signature_metadata_offset=blobs_it->second.offset+cursor;property.signature_size=length.value();
    auto signature=decode_managed_property_signature(blobs.subspan(cursor,length.value()));if(!signature){if(signature.error().code!=ErrorCode::unsupported)return signature.error();property.signature_diagnostic=signature.error().message;}else{auto status=resolve_type_signature(signature.value().property_type,catalog.value(),active_specs,0,signature_nodes);if(!status)return status.error();for(auto& parameter:signature.value().index_parameter_types){status=resolve_type_signature(parameter,catalog.value(),active_specs,0,signature_nodes);if(!status)return status.error();}property.signature=std::move(signature.value());}
    const auto value=defaults.find(property.token);if(bool(property.flags&0x1000u)!=(value!=defaults.end()))return malformed("Property HasDefault flag disagrees with Constant metadata");if(value!=defaults.end())property.default_value=std::move(value->second);result.push_back(std::move(property));
  }
  std::map<std::uint32_t,std::uint32_t> method_owners;for(const auto& type:catalog.value().definitions)for(auto method:type.method_tokens)method_owners.emplace(method,type.token);
  std::set<std::pair<std::uint32_t,std::uint32_t>> seen_accessors;
  for(std::uint32_t n=0;n<semantics;++n){const auto at=static_cast<std::size_t>(table_offset(24)+std::uint64_t{n}*row_size(24));const auto flags=u16(tables,at);const auto method=read_index(tables,at+2,mw),association=read_index(tables,at+2+mw,aw),rid=association>>1;
    if(!rid||rid>rows((association&1)?23:20)||!method||method>rows(6))return malformed("MethodSemantics has an invalid method or association");if(!(association&1))continue;
    if(flags!=1&&flags!=2&&flags!=4)return malformed("Property MethodSemantics has an invalid accessor role");auto& property=result[rid-1];const auto token=0x06000000u|method;const auto owner=method_owners.find(token);if(owner==method_owners.end()||owner->second!=property.declaring_type_token)return malformed("Property accessor belongs to a different TypeDef");
    if(!seen_accessors.emplace(rid,method).second)return malformed("Property has duplicate accessor methods");if(flags!=4&&std::any_of(property.accessors.begin(),property.accessors.end(),[&](const auto& accessor){return accessor.semantics==flags;}))return malformed("Property has duplicate getter or setter roles");
    property.accessors.push_back({token,0x18000000u|(n+1),flags,tables_it->second.offset+at});
  }
  // Validate only methods explicitly associated with a Property. An unrelated
  // unsupported method signature must not make property inspection fail.
  const auto method_count=rows(6);
  if(method_count>1000000)return Error{ErrorCode::resource_limit,"MethodDef table exceeds property accessor validation limit"};
  const auto method_string_width=(md.tables.heap_sizes&1)?4u:2u;
  const auto method_blob_width=(md.tables.heap_sizes&4)?4u:2u;
  const auto parameter_rows=rows(8), parameter_pointer_rows=rows(7);
  const bool has_parameter_pointers=md.tables.row_counts.contains(7);
  if(has_parameter_pointers&&parameter_pointer_rows!=parameter_rows)
    return malformed("ParamPtr count does not match Param count during accessor validation");
  const auto parameter_list_rows=has_parameter_pointers?parameter_pointer_rows:parameter_rows;
  const auto parameter_list_width=parameter_list_rows<65536?2u:4u;
  const auto method_size=row_size(6);
  const auto method_offset=table_offset(6);
  if(method_count && (method_size!=8+method_string_width+method_blob_width+parameter_list_width ||
      method_offset>tables.size() || std::uint64_t{method_count}*method_size>tables.size()-method_offset))
    return malformed("MethodDef table layout is inconsistent during property accessor validation");
  std::size_t accessor_signature_bytes=0, accessor_signature_nodes=100000;
  for(auto& property:result)for(auto& accessor:property.accessors){
    if(accessor.semantics==4)continue;
    if(!property.signature){
      accessor.validation=ManagedPropertyAccessorValidation::unsupported;
      accessor.validation_diagnostic="property signature could not be decoded";
      continue;
    }
    const auto rid=accessor.method_token&0x00ffffffu;
    const auto at=static_cast<std::size_t>(method_offset+std::uint64_t{rid-1}*method_size);
    accessor.signature_index=read_index(tables,at+8+method_string_width,method_blob_width);
    if(!accessor.signature_index||accessor.signature_index>=blobs.size())return malformed("Property accessor signature index is outside #Blob");
    std::size_t cursor=accessor.signature_index;auto length=compressed_uint(blobs,cursor);if(!length)return length.error();
    if(length.value()>blobs.size()-cursor)return malformed("Property accessor signature exceeds #Blob");
    if(length.value()>65536||length.value()>16u*1024u*1024u-accessor_signature_bytes)
      return Error{ErrorCode::resource_limit,"Property accessor signature byte budget exceeded"};
    accessor_signature_bytes+=length.value();accessor.signature_size=length.value();
    accessor.signature_metadata_offset=blobs_it->second.offset+cursor;
    auto decoded=decode_managed_method_signature(blobs.subspan(cursor,length.value()));
    if(!decoded){
      if(decoded.error().code!=ErrorCode::unsupported)return decoded.error();
      accessor.validation=ManagedPropertyAccessorValidation::unsupported;
      accessor.validation_diagnostic=decoded.error().message;
      continue;
    }
    auto method_signature=std::move(decoded.value());
    if(method_signature.generic_arity){
      accessor.validation=ManagedPropertyAccessorValidation::unsupported;
      accessor.validation_diagnostic="generic property accessors are outside this validator";
      continue;
    }
    auto resolved=resolve_type_signature(method_signature.return_type,catalog.value(),active_specs,0,accessor_signature_nodes);
    bool resolution_complete=true;
    if(!resolved){
      if(resolved.error().code==ErrorCode::unsupported)resolution_complete=false;
      else return resolved.error();
    }
    for(auto& parameter:method_signature.parameter_types){
      if(!resolution_complete)break;
      resolved=resolve_type_signature(parameter,catalog.value(),active_specs,0,accessor_signature_nodes);
      if(!resolved){
        if(resolved.error().code==ErrorCode::unsupported){resolution_complete=false;break;}
        return resolved.error();
      }
    }
    if(!resolution_complete){
      accessor.validation=ManagedPropertyAccessorValidation::unsupported;
      accessor.validation_diagnostic="accessor signature contains an unresolved unsupported type";
      continue;
    }
    bool matches=method_signature.has_this==property.signature->has_this;
    if(accessor.semantics==2){
      matches=matches&&method_signature.returns_value&&
          method_signature.parameter_types.size()==property.signature->index_parameter_types.size();
      if(matches){
        const auto equal=same_property_type(method_signature.return_type,property.signature->property_type);
        if(!equal){accessor.validation=ManagedPropertyAccessorValidation::unsupported;accessor.validation_diagnostic="return/property type shape is not fully retained";continue;}
        matches=*equal;
      }
      for(std::size_t i=0;matches&&i<method_signature.parameter_types.size();++i){
        const auto equal=same_property_type(method_signature.parameter_types[i],property.signature->index_parameter_types[i]);
        if(!equal){accessor.validation=ManagedPropertyAccessorValidation::unsupported;accessor.validation_diagnostic="index parameter type shape is not fully retained";matches=false;break;}
        matches=*equal;
      }
    }else{
      matches=matches&&!method_signature.returns_value&&
          method_signature.parameter_types.size()==property.signature->index_parameter_types.size()+1;
      for(std::size_t i=0;matches&&i<property.signature->index_parameter_types.size();++i){
        const auto equal=same_property_type(method_signature.parameter_types[i],property.signature->index_parameter_types[i]);
        if(!equal){accessor.validation=ManagedPropertyAccessorValidation::unsupported;accessor.validation_diagnostic="index parameter type shape is not fully retained";matches=false;break;}
        matches=*equal;
      }
      if(matches){
        const auto equal=same_property_type(method_signature.parameter_types.back(),property.signature->property_type);
        if(!equal){accessor.validation=ManagedPropertyAccessorValidation::unsupported;accessor.validation_diagnostic="setter value type shape is not fully retained";continue;}
        matches=*equal;
      }
    }
    accessor.validation=matches?ManagedPropertyAccessorValidation::valid:ManagedPropertyAccessorValidation::invalid;
    if(!matches)accessor.validation_diagnostic=accessor.semantics==2
        ?"getter signature does not match PropertySig" : "setter signature does not match PropertySig";
  }
  return result;
} catch(const std::bad_alloc&) {return Error{ErrorCode::resource_limit,"Cannot allocate CLR property catalog"};}
  catch(const std::length_error&) {return Error{ErrorCode::resource_limit,"CLR property catalog exceeds container limits"};}

Result<std::vector<ManagedEvent>> parse_managed_events(std::span<const std::byte> root) try {
  if(root.size()>64u*1024u*1024u)return Error{ErrorCode::resource_limit,"CLR event inspection root exceeds 64 MiB"};
  auto parsed=parse_cli_metadata(root);if(!parsed)return parsed.error();const auto& md=parsed.value();
  const auto rows=[&](std::uint8_t id){const auto it=md.tables.row_counts.find(id);return it==md.tables.row_counts.end()?0u:it->second;};
  const auto count=rows(20),maps=rows(18),pointers=rows(19),semantics=rows(24);
  if(count>65536||maps>65536||semantics>250000)return Error{ErrorCode::resource_limit,"CLR event table count exceeds its limit"};
  if(pointers&&pointers!=count)return malformed("EventPtr count does not match Event count");
  if(!count){if(maps)return malformed("EventMap has no Event rows");return std::vector<ManagedEvent>{};}
  if(!maps)return malformed("Event rows have no EventMap owners");
  auto tables_it=md.streams.find("#~");if(tables_it==md.streams.end())tables_it=md.streams.find("#-");
  const auto strings_it=md.streams.find("#Strings");
  if(tables_it==md.streams.end()||strings_it==md.streams.end())return malformed("Event parsing requires tables and #Strings");
  const auto tables=root.subspan(tables_it->second.offset,tables_it->second.size),strings=root.subspan(strings_it->second.offset,strings_it->second.size);
  const auto sw=(md.tables.heap_sizes&1)?4u:2u;
  const auto index_width=[&](std::uint8_t id){return rows(id)<65536?2u:4u;};
  const auto read_index=[&](std::span<const std::byte> bytes,std::size_t at,std::uint32_t width){return width==2?std::uint32_t(u16(bytes,at)):u32(bytes,at);};
  const auto row_size=[&](std::uint8_t id){const auto it=md.tables.row_sizes.find(id);return it==md.tables.row_sizes.end()?0u:it->second;};
  const auto table_offset=[&](std::uint8_t id){std::uint64_t offset=md.tables.data_offset;for(std::uint8_t n=0;n<id;++n)offset+=std::uint64_t{rows(n)}*row_size(n);return offset;};
  const auto table_valid=[&](std::uint8_t id,std::uint32_t expected){const auto at=table_offset(id);return row_size(id)==expected&&at<=tables.size()&&std::uint64_t{rows(id)}*expected<=tables.size()-at;};
  const auto ew=index_width(20),tw=index_width(2),mw=index_width(6),event_type_width=coded_width(1,md.tables.row_counts),association_width=coded_width(7,md.tables.row_counts);
  if(!table_valid(20,2+sw+event_type_width)||!table_valid(18,tw+ew)||(pointers&&!table_valid(19,ew))||
     (semantics&&!table_valid(24,2+mw+association_width)))return malformed("Event table layout or extent is inconsistent");
  auto catalog=parse_managed_type_catalog(root);if(!catalog)return catalog.error();
  std::vector<std::uint32_t> order(count),owners(count+1),starts,parents;std::vector<bool> seen(count+1);
  for(std::uint32_t n=0;n<count;++n){const auto rid=pointers?read_index(tables,static_cast<std::size_t>(table_offset(19)+std::uint64_t{n}*ew),ew):n+1;if(!rid||rid>count||seen[rid])return malformed("EventPtr contains an invalid or duplicate Event index");seen[rid]=true;order[n]=rid;}
  starts.reserve(maps);parents.reserve(maps);std::set<std::uint32_t> seen_parents;
  for(std::uint32_t n=0;n<maps;++n){const auto at=static_cast<std::size_t>(table_offset(18)+std::uint64_t{n}*row_size(18));const auto parent=read_index(tables,at,tw),first=read_index(tables,at+tw,ew);if(!parent||parent>catalog.value().definitions.size()||!seen_parents.insert(parent).second||!first||first>count||(!starts.empty()&&first<=starts.back()))return malformed("EventMap has invalid parents or list boundaries");parents.push_back(parent);starts.push_back(first);}
  if(starts.front()!=1)return malformed("EventMap leaves initial Event rows unowned");
  for(std::size_t n=0;n<starts.size();++n){const auto end=n+1<starts.size()?starts[n+1]:count+1;for(auto pos=starts[n];pos<end;++pos)owners[order[pos-1]]=parents[n];}
  std::size_t name_bytes=0;std::vector<ManagedEvent> result;result.reserve(count);
  for(std::uint32_t rid=1;rid<=count;++rid){const auto at=static_cast<std::size_t>(table_offset(20)+std::uint64_t{rid-1}*row_size(20));const auto owner=owners[rid];if(!owner)return malformed("Event row is not owned by an EventMap");ManagedEvent event;event.token=0x14000000u|rid;event.declaring_type_token=0x02000000u|owner;event.flags=u16(tables,at);event.metadata_offset=tables_it->second.offset+at;event.row_size=row_size(20);const auto name_index=read_index(tables,at+2,sw);std::size_t name_at=name_index;if(!name_index||name_at>=strings.size())return malformed("Event name index is outside #Strings");for(;name_at<strings.size()&&strings[name_at]!=std::byte{0};++name_at){if(name_at-name_index>=4096)return Error{ErrorCode::resource_limit,"CLR event name exceeds 4096 bytes"};event.name.push_back(static_cast<char>(std::to_integer<unsigned char>(strings[name_at])));}if(name_at>=strings.size()||event.name.empty())return malformed("Event name is empty or unterminated");name_bytes+=event.name.size();if(name_bytes>8u*1024u*1024u)return Error{ErrorCode::resource_limit,"CLR event names exceed 8 MiB"};const auto coded=read_index(tables,at+2+sw,event_type_width),tag=coded&3u,type_rid=coded>>2;if(!type_rid||tag==3)return malformed("EventType has an invalid TypeDefOrRef coded index");const auto type_table=tag==0?2u:tag==1?1u:27u;if(type_rid>rows(static_cast<std::uint8_t>(type_table)))return malformed("EventType token is outside its metadata table");event.event_type_coded_index=coded;event.event_type_token=(type_table<<24)|type_rid;event.declaring_type=catalog.value().definitions[owner-1].full_name;result.push_back(std::move(event));}
  std::map<std::uint32_t,std::uint32_t> method_owners;for(const auto& type:catalog.value().definitions)for(auto method:type.method_tokens)method_owners.emplace(method,type.token);
  std::set<std::pair<std::uint32_t,std::uint32_t>> seen_accessors;
  for(std::uint32_t n=0;n<semantics;++n){const auto at=static_cast<std::size_t>(table_offset(24)+std::uint64_t{n}*row_size(24));const auto flags=u16(tables,at);const auto method=read_index(tables,at+2,mw);const auto association=read_index(tables,at+2+mw,association_width);const auto rid=association>>1;if(!rid||!method||method>rows(6))return malformed("MethodSemantics has an invalid method or association");if(association&1u){if(rid>rows(23))return malformed("MethodSemantics Property association is out of range");continue;}if(rid>count)return malformed("MethodSemantics Event association is out of range");if(flags!=4&&flags!=8&&flags!=16&&flags!=32)return malformed("Event MethodSemantics has an invalid accessor role");auto& event=result[rid-1];const auto token=0x06000000u|method;const auto owner=method_owners.find(token);if(owner==method_owners.end()||owner->second!=event.declaring_type_token)return malformed("Event accessor belongs to a different TypeDef");if(!seen_accessors.emplace(rid,method).second)return malformed("Event has duplicate accessor methods");if(flags!=4&&std::any_of(event.accessors.begin(),event.accessors.end(),[&](const auto& accessor){return accessor.semantics==flags;}))return malformed("Event has duplicate add, remove, or fire roles");event.accessors.push_back({token,0x18000000u|(n+1),flags,tables_it->second.offset+at});}
  return result;
} catch(const std::bad_alloc&) {return Error{ErrorCode::resource_limit,"Cannot allocate CLR event catalog"};}
  catch(const std::length_error&) {return Error{ErrorCode::resource_limit,"CLR event catalog exceeds container limits"};}

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
  if(generic_count>250000)return Error{ErrorCode::resource_limit,"CLR GenericParam catalog exceeds 250,000 rows"};
  if(constraint_count>1000000)return Error{ErrorCode::resource_limit,"CLR GenericParamConstraint catalog exceeds 1,000,000 rows"};
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
  std::size_t generic_name_bytes=0;
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
    auto name=read_string(read_index(tables,at+4+owner_width,string_width));if(!name)return name.error();
    if(name.value().size()>8u*1024u*1024u-generic_name_bytes)return Error{ErrorCode::resource_limit,"CLR generic parameter names exceed 8 MiB"};
    generic_name_bytes+=name.value().size();parameter.name=std::move(name.value());
    parameter.metadata_offset=tables_it->second.offset+at;
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
      result[owner-1].constraint_metadata_offsets.push_back(tables_it->second.offset+at);
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
  ManagedPeInfo out;out.major=u16(h,4);out.minor=u16(h,6);out.flags=u32(h,16);out.entry_point_token=u32(h,20);out.metadata=std::move(root.value());
  out.resources_rva=u32(h,24);out.resources_size=u32(h,28);
  if((out.resources_rva==0)!=(out.resources_size==0))return malformed("CLR Resources RVA and size must either both be zero or both be nonzero");
  return out;
}

namespace {
Result<std::vector<std::byte>> managed_metadata_root_bytes(const LoadedImage& loaded){
  if(!loaded.image||!loaded.metadata.pe)return Error{ErrorCode::invalid_argument,"Managed metadata input requires a loaded PE image"};
  const auto directory=std::find_if(loaded.metadata.directories.begin(),loaded.metadata.directories.end(),[](const Directory& d){return d.index==14;});
  if(directory==loaded.metadata.directories.end()||!directory->location||directory->size<72)return malformed("CLR metadata input requires a complete runtime header");
  const auto base=loaded.load_base.value_or(loaded.metadata.preferred_base);
  auto header_va=checked_add(base,std::uint64_t{directory->location});if(!header_va)return header_va.error();
  auto header=loaded.image->read({loaded.image->layout().space.id,header_va.value()},72);if(!header)return header.error();
  const auto metadata_rva=u32(header.value(),8),metadata_size=u32(header.value(),12);
  if(u32(header.value(),0)<72||u32(header.value(),0)>directory->size||!metadata_rva||!metadata_size||metadata_size>64u*1024u*1024u)
    return malformed("Invalid CLR metadata extent during resource binding");
  auto metadata_va=checked_add(base,std::uint64_t{metadata_rva});if(!metadata_va)return metadata_va.error();
  return loaded.image->read({loaded.image->layout().space.id,metadata_va.value()},metadata_size);
}

class ManagedSha1 {
public:
  void update(std::span<const std::byte> bytes){
    total_+=bytes.size();
    while(!bytes.empty()){
      const auto count=std::min(bytes.size(),block_.size()-used_);
      std::copy_n(bytes.begin(),count,block_.begin()+static_cast<std::ptrdiff_t>(used_));
      used_+=count;bytes=bytes.subspan(count);
      if(used_==block_.size()){compress(block_);used_=0;}
    }
  }
  std::array<std::byte,20> finish(){
    const auto bits=total_*8;
    block_[used_++]=std::byte{0x80};
    if(used_>56){std::fill(block_.begin()+static_cast<std::ptrdiff_t>(used_),block_.end(),std::byte{});compress(block_);used_=0;}
    std::fill(block_.begin()+static_cast<std::ptrdiff_t>(used_),block_.begin()+56,std::byte{});
    for(unsigned i=0;i<8;++i)block_[63-i]=std::byte(static_cast<unsigned char>(bits>>(i*8)));
    compress(block_);
    std::array<std::byte,20> digest{};
    for(unsigned word=0;word<5;++word)for(unsigned byte=0;byte<4;++byte)
      digest[word*4+byte]=std::byte(static_cast<unsigned char>(state_[word]>>(24-byte*8)));
    return digest;
  }
private:
  void compress(const std::array<std::byte,64>& block){
    std::array<std::uint32_t,80> words{};
    for(unsigned i=0;i<16;++i)words[i]=(std::uint32_t(std::to_integer<std::uint8_t>(block[i*4]))<<24)|
      (std::uint32_t(std::to_integer<std::uint8_t>(block[i*4+1]))<<16)|
      (std::uint32_t(std::to_integer<std::uint8_t>(block[i*4+2]))<<8)|
      std::uint32_t(std::to_integer<std::uint8_t>(block[i*4+3]));
    for(unsigned i=16;i<80;++i)words[i]=std::rotl(words[i-3]^words[i-8]^words[i-14]^words[i-16],1);
    auto a=state_[0],b=state_[1],c=state_[2],d=state_[3],e=state_[4];
    for(unsigned i=0;i<80;++i){
      std::uint32_t f=0,k=0;
      if(i<20){f=(b&c)|(~b&d);k=0x5a827999u;}
      else if(i<40){f=b^c^d;k=0x6ed9eba1u;}
      else if(i<60){f=(b&c)|(b&d)|(c&d);k=0x8f1bbcdcu;}
      else {f=b^c^d;k=0xca62c1d6u;}
      const auto next=std::rotl(a,5)+f+e+k+words[i];e=d;d=c;c=std::rotl(b,30);b=a;a=next;
    }
    state_[0]+=a;state_[1]+=b;state_[2]+=c;state_[3]+=d;state_[4]+=e;
  }
  std::array<std::uint32_t,5> state_{0x67452301u,0xefcdab89u,0x98badcfeu,0x10325476u,0xc3d2e1f0u};
  std::array<std::byte,64> block_{};
  std::uint64_t total_=0;
  std::size_t used_=0;
};

Result<std::vector<std::byte>> managed_resource_hash(const ByteStorage& storage,std::uint32_t algorithm,
                                                      std::stop_token stop){
  if(algorithm==0x800cu){
    auto hash=hash_source(storage,stop);if(!hash)return hash.error();
    return std::vector<std::byte>(hash.value().begin(),hash.value().end());
  }
  if(algorithm!=0x8004u)return Error{ErrorCode::unsupported,"Unsupported CLR Assembly.HashAlgId for File resource binding"};
  ManagedSha1 sha1;constexpr std::size_t chunk_size=1024u*1024u;
  for(std::uint64_t offset=0;offset<storage.size();){
    if(stop.stop_requested())return Error{ErrorCode::canceled,"CLR resource file hashing canceled"};
    const auto count=static_cast<std::size_t>(std::min<std::uint64_t>(chunk_size,storage.size()-offset));
    auto view=storage.read_at({offset},count);if(!view)return view.error();
    if(view.value().bytes.size()!=count)return Error{ErrorCode::io,"Short read while hashing CLR resource file"};
    sha1.update(view.value().bytes);offset+=count;
  }
  const auto digest=sha1.finish();return std::vector<std::byte>(digest.begin(),digest.end());
}

bool managed_resource_assembly_identity_matches(const ManagedAssemblyIdentity& requested,
                                                const ManagedAssemblyIdentity& candidate){
  const auto equal_folded=[](std::string_view left,std::string_view right){
    if(left.size()!=right.size())return false;
    for(std::size_t i=0;i<left.size();++i){
      auto a=static_cast<unsigned char>(left[i]),b=static_cast<unsigned char>(right[i]);
      if(a>='A'&&a<='Z')a=static_cast<unsigned char>(a+('a'-'A'));
      if(b>='A'&&b<='Z')b=static_cast<unsigned char>(b+('a'-'A'));
      if(a!=b)return false;
    }
    return true;
  };
  if(!equal_folded(requested.name,candidate.name)||!equal_folded(requested.culture,candidate.culture)||
     requested.major!=candidate.major||requested.minor!=candidate.minor||requested.build!=candidate.build||
     requested.revision!=candidate.revision||((requested.flags^candidate.flags)&~std::uint32_t{1})!=0)
    return false;
  const bool requested_full_key=(requested.flags&1u)!=0,candidate_full_key=(candidate.flags&1u)!=0;
  if(requested_full_key)return candidate_full_key&&requested.public_key_or_token==candidate.public_key_or_token;
  if(candidate_full_key){
    ManagedSha1 sha1;sha1.update(candidate.public_key_or_token);const auto digest=sha1.finish();
    std::array<std::byte,8> token{};
    for(unsigned i=0;i<8;++i)token[i]=digest[19-i];
    return requested.public_key_or_token.size()==token.size()&&
      std::equal(token.begin(),token.end(),requested.public_key_or_token.begin());
  }
  return requested.public_key_or_token==candidate.public_key_or_token;
}
}

Result<std::vector<ManagedResource>> inspect_managed_resources(const LoadedImage& loaded) try {
  if(!loaded.image||!loaded.metadata.pe)return Error{ErrorCode::invalid_argument,"Managed resource inspection requires a loaded PE image"};
  auto managed=parse_managed_pe(loaded);if(!managed)return managed.error();
  const auto directory=std::find_if(loaded.metadata.directories.begin(),loaded.metadata.directories.end(),[](const Directory& d){return d.index==14;});
  if(directory==loaded.metadata.directories.end()||!directory->location||directory->size<72)return malformed("CLR Resources inspection requires a complete runtime header");
  const auto base=loaded.load_base.value_or(loaded.metadata.preferred_base);
  auto header_va=checked_add(base,std::uint64_t{directory->location});if(!header_va)return header_va.error();
  auto header=loaded.image->read({loaded.image->layout().space.id,header_va.value()},72);if(!header)return header.error();
  const auto metadata_rva=u32(header.value(),8),metadata_size=u32(header.value(),12);
  if(!metadata_rva||!metadata_size||metadata_size>64u*1024u*1024u)return malformed("Invalid CLR metadata RVA or size during resource inspection");
  auto metadata_va=checked_add(base,std::uint64_t{metadata_rva});if(!metadata_va)return metadata_va.error();
  auto root=loaded.image->read({loaded.image->layout().space.id,metadata_va.value()},metadata_size);if(!root)return root.error();
  auto resources=parse_managed_resources(root.value());if(!resources)return resources.error();
  const auto embedded=std::count_if(resources.value().begin(),resources.value().end(),[](const auto& resource){return resource.implementation==ManagedResourceImplementationKind::embedded;});
  if(!embedded)return resources.value();
  if(!managed.value().resources_rva||!managed.value().resources_size)return malformed("Embedded ManifestResource rows exist without a CLR Resources directory");
  if(managed.value().resources_size>256u*1024u*1024u)return Error{ErrorCode::resource_limit,"CLR Resources directory exceeds 256 MiB"};
  std::uint64_t total=0;constexpr std::uint32_t single_limit=16u*1024u*1024u;constexpr std::uint64_t total_limit=64u*1024u*1024u;
  const auto image_space=loaded.image->layout().space.id;
  for(auto& resource:resources.value()){
    if(resource.implementation!=ManagedResourceImplementationKind::embedded)continue;
    if(resource.data_offset>managed.value().resources_size||managed.value().resources_size-resource.data_offset<4)
      return malformed("Embedded ManifestResource length prefix exceeds the CLR Resources directory");
    auto rva=checked_add(std::uint64_t{managed.value().resources_rva},std::uint64_t{resource.data_offset});if(!rva)return rva.error();
    auto address=checked_add(base,rva.value());if(!address)return address.error();
    auto prefix=loaded.image->read({image_space,address.value()},4);if(!prefix)return prefix.error();
    const auto length=u32(prefix.value(),0);resource.data_size=length;
    if(length>managed.value().resources_size-resource.data_offset-4)return malformed("Embedded ManifestResource payload exceeds the CLR Resources directory");
    if(length>single_limit)return Error{ErrorCode::resource_limit,"Embedded CLR resource exceeds 16 MiB"};
    if(length>total_limit-total)return Error{ErrorCode::resource_limit,"Embedded CLR resources exceed 64 MiB total"};
    total+=length;
    if(!length){resource.payload.clear();continue;}
    auto payload_rva=checked_add(rva.value(),std::uint64_t{4});if(!payload_rva)return payload_rva.error();
    auto payload_va=checked_add(base,payload_rva.value());if(!payload_va)return payload_va.error();
    auto payload=loaded.image->read({image_space,payload_va.value()},length);if(!payload)return payload.error();
    resource.payload=std::move(payload.value());
    auto decoded=parse_dotnet_resources(resource);if(!decoded)return decoded.error();
  }
  return resources;
} catch(const std::bad_alloc&) {return Error{ErrorCode::resource_limit,"Cannot allocate embedded CLR resource catalog"};}
  catch(const std::length_error&) {return Error{ErrorCode::resource_limit,"Embedded CLR resource catalog exceeds container limits"};}

Result<std::vector<ManagedResource>> inspect_managed_resources(
    const LoadedImage& loaded,std::span<const ManagedResourceInput> supplied,
    const ManagedResourceResolutionLimits& limits,std::stop_token stop) try {
  if(supplied.size()>limits.max_inputs||limits.max_inputs>256||
     limits.max_input_bytes>512u*1024u*1024u||limits.max_payload_bytes>512u*1024u*1024u)
    return Error{ErrorCode::resource_limit,"CLR resource input or payload budget is invalid or exceeded"};
  auto resources=inspect_managed_resources(loaded);if(!resources)return resources.error();
  struct Candidate {
    const ManagedResourceInput* input=nullptr;
    std::shared_ptr<const ByteStorage> storage;
    std::optional<ManagedAssemblyIdentity> identity;
    bool identity_checked=false;
    std::optional<std::vector<ManagedResource>> resources;
    std::uint64_t cached_payload_bytes=0;
    std::map<std::uint32_t,std::vector<std::byte>> hashes;
    std::map<std::uint32_t,std::string> hash_errors;
  };
  std::vector<Candidate> candidates; candidates.reserve(supplied.size());
  std::uint64_t input_bytes=0;
  for(const auto& input:supplied){
    if(stop.stop_requested())return Error{ErrorCode::canceled,"CLR resource binding canceled"};
    auto storage=input.storage;
    if(input.loaded_image){
      if(!input.loaded_image->image)return Error{ErrorCode::invalid_argument,"Supplied CLR resource image has no mapped image"};
      const auto image_storage=input.loaded_image->image->storage();
      if(storage&&storage!=image_storage)return Error{ErrorCode::invalid_argument,"Supplied CLR resource storage does not match its loaded image"};
      storage=image_storage;
    }
    if(!storage)return Error{ErrorCode::invalid_argument,"Supplied CLR resource input has no byte storage"};
    if(storage->size()>limits.max_input_bytes-input_bytes)
      return Error{ErrorCode::resource_limit,"Supplied CLR resource inputs exceed the cumulative byte budget"};
    input_bytes+=storage->size();
    candidates.push_back({&input,std::move(storage)});
  }
  std::uint64_t external_payload_bytes=0,cached_payload_bytes=0;
  const auto candidate_identity=[&](Candidate& candidate)->std::optional<ManagedAssemblyIdentity>{
    if(candidate.identity_checked)return candidate.identity;
    candidate.identity_checked=true;
    if(!candidate.input->loaded_image)return {};
    auto root=managed_metadata_root_bytes(*candidate.input->loaded_image);if(!root)return {};
    auto catalog=parse_managed_type_catalog(root.value());if(!catalog)return {};
    candidate.identity=std::move(catalog.value().assembly_identity);
    return candidate.identity;
  };
  const auto candidate_resources=[&](Candidate& candidate)->Result<const std::vector<ManagedResource>*>{
    if(!candidate.input->loaded_image)return Error{ErrorCode::unsupported,"Supplied resource provider is not a managed PE image"};
    if(!candidate.resources){
      auto parsed=inspect_managed_resources(*candidate.input->loaded_image);if(!parsed)return parsed.error();
      std::uint64_t bytes=0;for(const auto& item:parsed.value())bytes+=item.payload.size();
      if(bytes>limits.max_payload_bytes-cached_payload_bytes)
        return Error{ErrorCode::resource_limit,"Supplied managed resource catalogs exceed the binding cache budget"};
      cached_payload_bytes+=bytes;candidate.cached_payload_bytes=bytes;
      candidate.resources=std::move(parsed.value());
    }
    return &*candidate.resources;
  };
  const auto copy_payload=[&](ManagedResource& destination,const ManagedResource& source,
                              ManagedResourceResolutionState state)->Result<bool>{
    if(source.implementation!=ManagedResourceImplementationKind::embedded)
      return Error{ErrorCode::unsupported,"Nested external CLR resource providers are not followed"};
    if(source.payload.size()>limits.max_payload_bytes-external_payload_bytes)
      return Error{ErrorCode::resource_limit,"Resolved CLR resource payloads exceed the cumulative byte budget"};
    external_payload_bytes+=source.payload.size();
    destination.data_size=source.data_size;destination.payload=source.payload;
    destination.payload_format=source.payload_format;destination.payload_diagnostic=source.payload_diagnostic;
    destination.records=source.records;destination.resolution=state;
    destination.resolution_input_index.reset();destination.resolution_diagnostic.clear();
    return true;
  };

  for(auto& resource:resources.value()){
    if(stop.stop_requested())return Error{ErrorCode::canceled,"CLR resource binding canceled"};
    if(resource.implementation==ManagedResourceImplementationKind::embedded)continue;
    if(resource.implementation==ManagedResourceImplementationKind::file){
      if(resource.implementation_hash.empty()||resource.implementation_hash_algorithm==0){
        resource.resolution=ManagedResourceResolutionState::unsupported_hash;
        resource.resolution_diagnostic="File resource has no usable Assembly.HashAlgId/File.HashValue pair";
        continue;
      }
      std::vector<std::size_t> named,matched;
      bool saw_unsupported_hash=false,saw_hash_mismatch=false;
      for(std::size_t i=0;i<candidates.size();++i){
        auto& candidate=candidates[i];
        if(candidate.input->file_name!=resource.implementation_name)continue;
        named.push_back(i);
        if(const auto found=candidate.hashes.find(resource.implementation_hash_algorithm);found!=candidate.hashes.end()){
          if(found->second==resource.implementation_hash)matched.push_back(i);else saw_hash_mismatch=true;
          continue;
        }
        if(candidate.hash_errors.contains(resource.implementation_hash_algorithm)){
          saw_unsupported_hash=true;continue;
        }
        auto hash=managed_resource_hash(*candidate.storage,resource.implementation_hash_algorithm,stop);
        if(!hash){
          if(hash.error().code==ErrorCode::canceled)return hash.error();
          if(hash.error().code==ErrorCode::unsupported){candidate.hash_errors[resource.implementation_hash_algorithm]=hash.error().message;saw_unsupported_hash=true;}
          else return hash.error();
        }else if(hash.value()==resource.implementation_hash){
          candidate.hashes.emplace(resource.implementation_hash_algorithm,std::move(hash.value()));matched.push_back(i);
        }else{
          candidate.hashes.emplace(resource.implementation_hash_algorithm,std::move(hash.value()));saw_hash_mismatch=true;
        }
      }
      if(matched.empty()){
        resource.resolution=saw_hash_mismatch?ManagedResourceResolutionState::hash_mismatch:
            saw_unsupported_hash?ManagedResourceResolutionState::unsupported_hash:ManagedResourceResolutionState::unresolved;
        resource.resolution_diagnostic=named.empty()?"No exact caller-supplied File.Name candidate":
            saw_hash_mismatch?"Supplied File.Name candidate hash does not match File.HashValue":
            saw_unsupported_hash?"Supplied File.Name candidate uses an unsupported Assembly.HashAlgId":
            "No supplied File.Name candidate could be verified";
        continue;
      }
      if(matched.size()!=1){resource.resolution=ManagedResourceResolutionState::ambiguous;resource.resolution_diagnostic="Multiple supplied File.Name candidates match File.HashValue";continue;}
      auto& candidate=candidates[matched.front()];
      if(resource.implementation_file_contains_metadata){
        auto parsed=candidate_resources(candidate);
        if(!parsed){resource.resolution_diagnostic=parsed.error().message;continue;}
        const ManagedResource* target=nullptr;
        for(const auto& item:*parsed.value())if(item.name==resource.name){if(target){target=nullptr;resource.resolution=ManagedResourceResolutionState::ambiguous;resource.resolution_diagnostic="Multiple same-name ManifestResource rows exist in supplied File module";break;}target=&item;}
        if(resource.resolution==ManagedResourceResolutionState::ambiguous)continue;
        if(!target){resource.resolution_diagnostic="Supplied File module has no same-name ManifestResource";continue;}
        auto copied=copy_payload(resource,*target,ManagedResourceResolutionState::resolved_file);
        if(!copied){if(copied.error().code==ErrorCode::resource_limit)return copied.error();resource.resolution_diagnostic=copied.error().message;}
        else resource.resolution_input_index=matched.front();
      }else{
        constexpr std::uint64_t item_limit=16u*1024u*1024u;
        const auto size=candidate.storage->size();
        if(size>item_limit||size>limits.max_payload_bytes-external_payload_bytes)
          return Error{ErrorCode::resource_limit,"Supplied raw CLR resource file exceeds its payload budget"};
        if(stop.stop_requested())return Error{ErrorCode::canceled,"CLR resource file read canceled"};
        if(size){auto bytes=candidate.storage->read_at({0},static_cast<std::size_t>(size));if(!bytes)return bytes.error();if(bytes.value().bytes.size()!=size)return Error{ErrorCode::io,"Short read from supplied CLR resource file"};resource.payload.assign(bytes.value().bytes.begin(),bytes.value().bytes.end());}
        resource.data_size=static_cast<std::uint32_t>(size);external_payload_bytes+=size;
        auto decoded=parse_dotnet_resources(resource);if(!decoded)return decoded.error();
        resource.resolution=ManagedResourceResolutionState::resolved_file;
        resource.resolution_input_index=matched.front();resource.resolution_diagnostic.clear();
      }
      continue;
    }
    if(resource.implementation==ManagedResourceImplementationKind::assembly_ref){
      ManagedAssemblyIdentity wanted{resource.implementation_name,resource.implementation_culture,
        resource.implementation_major,resource.implementation_minor,resource.implementation_build,
        resource.implementation_revision,resource.implementation_flags,resource.implementation_key_or_token};
      std::vector<std::size_t> matches;
      bool saw_hash_mismatch=false,saw_unsupported_hash=false;
      if(!resource.implementation_hash.empty()&&resource.implementation_hash_algorithm==0){
        resource.resolution=ManagedResourceResolutionState::unsupported_hash;
        resource.resolution_diagnostic="AssemblyRef HashValue has no usable owning Assembly.HashAlgId";
        continue;
      }
      for(std::size_t i=0;i<candidates.size();++i){
        if(stop.stop_requested())return Error{ErrorCode::canceled,"CLR AssemblyRef resource binding canceled"};
        auto& candidate=candidates[i];
        const auto identity=candidate_identity(candidate);
        if(!identity||!managed_resource_assembly_identity_matches(wanted,*identity))continue;
        if(resource.implementation_hash.empty()){matches.push_back(i);continue;}
        if(const auto found=candidate.hashes.find(resource.implementation_hash_algorithm);found!=candidate.hashes.end()){
          if(found->second==resource.implementation_hash)matches.push_back(i);else saw_hash_mismatch=true;
          continue;
        }
        if(candidate.hash_errors.contains(resource.implementation_hash_algorithm)){saw_unsupported_hash=true;continue;}
        auto hash=managed_resource_hash(*candidate.storage,resource.implementation_hash_algorithm,stop);
        if(!hash){
          if(hash.error().code==ErrorCode::canceled)return hash.error();
          if(hash.error().code==ErrorCode::unsupported){candidate.hash_errors[resource.implementation_hash_algorithm]=hash.error().message;saw_unsupported_hash=true;}
          else return hash.error();
        }else if(hash.value()==resource.implementation_hash){
          candidate.hashes.emplace(resource.implementation_hash_algorithm,std::move(hash.value()));matches.push_back(i);
        }else{
          candidate.hashes.emplace(resource.implementation_hash_algorithm,std::move(hash.value()));saw_hash_mismatch=true;
        }
      }
      if(matches.empty()){
        resource.resolution=saw_hash_mismatch?ManagedResourceResolutionState::hash_mismatch:
            saw_unsupported_hash?ManagedResourceResolutionState::unsupported_hash:ManagedResourceResolutionState::unresolved;
        resource.resolution_diagnostic=saw_hash_mismatch?"Supplied AssemblyRef identity candidate hash does not match AssemblyRef.HashValue":
            saw_unsupported_hash?"Supplied AssemblyRef identity candidate uses an unsupported Assembly.HashAlgId":
            "No supplied managed assembly has the exact AssemblyRef identity";
        continue;
      }
      if(matches.size()!=1){resource.resolution=ManagedResourceResolutionState::ambiguous;resource.resolution_diagnostic="Multiple supplied managed assemblies match the AssemblyRef identity and hash";continue;}
      auto parsed=candidate_resources(candidates[matches.front()]);
      if(!parsed){resource.resolution_diagnostic=parsed.error().message;continue;}
      const ManagedResource* target=nullptr;
      for(const auto& item:*parsed.value())if(item.name==resource.name){if(target){target=nullptr;resource.resolution=ManagedResourceResolutionState::ambiguous;resource.resolution_diagnostic="Multiple same-name resources exist in supplied AssemblyRef target";break;}target=&item;}
      if(resource.resolution==ManagedResourceResolutionState::ambiguous)continue;
      if(!target){resource.resolution_diagnostic="Supplied AssemblyRef target has no same-name ManifestResource";continue;}
      if(target->data_offset!=resource.data_offset){
        resource.resolution_diagnostic="Supplied AssemblyRef resource offset differs from the referenced ManifestResource";
        continue;
      }
      auto copied=copy_payload(resource,*target,ManagedResourceResolutionState::resolved_assembly);
      if(!copied&&copied.error().code==ErrorCode::resource_limit)return copied.error();
      if(!copied)resource.resolution_diagnostic=copied.error().message;
      else resource.resolution_input_index=matches.front();
    }
  }
  return resources;
} catch(const std::bad_alloc&) {return Error{ErrorCode::resource_limit,"Cannot allocate supplied CLR resource binding state"};}
  catch(const std::length_error&) {return Error{ErrorCode::resource_limit,"Supplied CLR resource binding exceeds container limits"};}

Result<std::vector<ManagedMethod>> parse_managed_methods(std::span<const std::byte> root){
  auto parsed=parse_cli_metadata(root);if(!parsed)return parsed.error();
  auto types=parse_managed_types(root);if(!types)return types.error();
  auto type_catalog=parse_managed_type_catalog(root);if(!type_catalog)return type_catalog.error();
  std::map<std::uint32_t,const ManagedTypeDefinition*> owners;for(const auto& type:types.value())for(auto token:type.method_tokens)owners.emplace(token,&type);
  std::map<std::uint32_t,std::vector<ManagedGenericParameter>> method_generics;
  for(const auto &parameter:type_catalog.value().method_generic_parameters)method_generics[parameter.owner_token].push_back(parameter);
  for(auto &[token,parameters]:method_generics){(void)token;std::sort(parameters.begin(),parameters.end(),[](const auto &a,const auto &b){return a.number<b.number;});}
  const auto& metadata=parsed.value();auto table_it=metadata.streams.find("#~");if(table_it==metadata.streams.end())table_it=metadata.streams.find("#-");
  const auto strings_it=metadata.streams.find("#Strings");if(strings_it==metadata.streams.end())return malformed("CLR metadata has no #Strings heap");
  const auto count_it=metadata.tables.row_counts.find(6);if(count_it==metadata.tables.row_counts.end())return std::vector<ManagedMethod>{};
  const auto row_size_it=metadata.tables.row_sizes.find(6);if(row_size_it==metadata.tables.row_sizes.end())return malformed("CLR MethodDef table has no row layout");
  const auto tables=root.subspan(table_it->second.offset,table_it->second.size);const auto strings=root.subspan(strings_it->second.offset,strings_it->second.size);
  const auto table_offset=[&](std::uint8_t id)->std::uint64_t{std::uint64_t offset=metadata.tables.data_offset;for(std::uint8_t prior=0;prior<id;++prior){const auto rows=metadata.tables.row_counts.find(prior);const auto width=metadata.tables.row_sizes.find(prior);if(rows!=metadata.tables.row_counts.end()&&width!=metadata.tables.row_sizes.end())offset+=std::uint64_t{rows->second}*width->second;}return offset;};
  const auto read_index=[](std::span<const std::byte> bytes,std::size_t at,unsigned width){return width==2?std::uint32_t(u16(bytes,at)):u32(bytes,at);};
  std::uint64_t row_offset=metadata.tables.data_offset;
  for(std::uint8_t id=0;id<6;++id){auto rows=metadata.tables.row_counts.find(id);auto width=metadata.tables.row_sizes.find(id);if(rows!=metadata.tables.row_counts.end() && width!=metadata.tables.row_sizes.end())row_offset+=std::uint64_t{rows->second}*width->second;}
  const auto count=count_it->second, row_size=row_size_it->second;const bool wide_strings=(metadata.tables.heap_sizes&1)!=0,wide_blobs=(metadata.tables.heap_sizes&4)!=0;
  const std::uint32_t string_width=wide_strings?4:2;
  if(row_offset>tables.size() || std::uint64_t{count}*row_size>tables.size()-row_offset)return malformed("CLR MethodDef rows exceed tables stream");
  const auto param_count_it=metadata.tables.row_counts.find(8);const std::uint32_t param_count=param_count_it==metadata.tables.row_counts.end()?0:param_count_it->second;
  const auto param_ptr_count_it=metadata.tables.row_counts.find(7);const bool has_param_ptr=param_ptr_count_it!=metadata.tables.row_counts.end();
  if(has_param_ptr&&param_ptr_count_it->second!=param_count)return malformed("CLR ParamPtr count does not match Param count");
  const std::uint32_t param_list_count=has_param_ptr?param_ptr_count_it->second:param_count;
  const auto param_index_width=param_count<65536?2u:4u;
  const auto param_ptr_index_width=param_list_count<65536?2u:4u;
  const auto list_width=has_param_ptr?param_ptr_index_width:param_index_width;
  if(row_size<8+string_width+ (wide_blobs?4u:2u)+list_width)return malformed("CLR MethodDef row is shorter than its ParamList field");
  const auto list_at=8+string_width+(wide_blobs?4u:2u);
  if(row_size!=list_at+list_width)return malformed("CLR MethodDef row layout has unexpected trailing bytes");
  std::vector<std::uint32_t> parameter_order(param_list_count);
  if(has_param_ptr){const auto pointer_offset=table_offset(7);const auto pointer_width=metadata.tables.row_sizes.find(7);if(pointer_width==metadata.tables.row_sizes.end()||pointer_width->second!=param_ptr_index_width)return malformed("CLR ParamPtr row layout is inconsistent");if(pointer_offset>tables.size()||std::uint64_t{param_list_count}*pointer_width->second>tables.size()-pointer_offset)return malformed("CLR ParamPtr rows exceed tables stream");std::vector<bool> seen(param_count+1,false);for(std::uint32_t p=0;p<param_list_count;++p){const auto at=static_cast<std::size_t>(pointer_offset+std::uint64_t{p}*pointer_width->second);const auto row=pointer_width->second==2?u16(tables,at):u32(tables,at);if(!row||row>param_count||seen[row])return malformed("CLR ParamPtr contains an invalid or duplicate Param index");seen[row]=true;parameter_order[p]=row;}}
  else for(std::uint32_t p=0;p<param_count;++p)parameter_order[p]=p+1;
  std::vector<ManagedParameter> parameter_rows(param_count+1);
  if(param_count){const auto parameter_offset=table_offset(8);const auto param_row_size_it=metadata.tables.row_sizes.find(8);const auto param_row_size=param_row_size_it==metadata.tables.row_sizes.end()?0:param_row_size_it->second;const auto param_string_width=(metadata.tables.heap_sizes&1)?4u:2u;if(param_row_size!=4+param_string_width)return malformed("CLR Param row layout is inconsistent");if(parameter_offset>tables.size()||std::uint64_t{param_count}*param_row_size>tables.size()-parameter_offset)return malformed("CLR Param rows exceed tables stream");for(std::uint32_t p=1;p<=param_count;++p){const auto at=static_cast<std::size_t>(parameter_offset+std::uint64_t{p-1}*param_row_size);ManagedParameter parameter;parameter.token=0x08000000u|p;parameter.flags=u16(tables,at);parameter.sequence=u16(tables,at+2);if(parameter.flags&~std::uint16_t{0x3013})return malformed("CLR Param has reserved flag bits set");const auto name_at=at+4;const auto name_index=param_string_width==4?u32(tables,name_at):u16(tables,name_at);if(name_index){if(name_index>=strings.size())return malformed("CLR Param name index exceeds #Strings heap");auto end=name_index;while(end<strings.size()&&strings[end]!=std::byte{0})++end;if(end==strings.size())return malformed("CLR Param name is unterminated in #Strings heap");parameter.name.reserve(end-name_index);for(auto n=name_index;n<end;++n)parameter.name.push_back(static_cast<char>(std::to_integer<unsigned char>(strings[n])));}parameter_rows[p]=std::move(parameter);}}
  auto constants=parse_managed_constants(root);if(!constants)return constants.error();
  for(auto& value:constants.value())if((value.parent_token>>24)==8)
    parameter_rows[value.parent_token&0x00ffffffu].default_value=std::move(value);
  auto marshal_rows=parse_managed_marshal_descriptors(root);if(!marshal_rows)return marshal_rows.error();
  for(auto& value:marshal_rows.value())if((value.parent_token>>24)==8){
    const auto rid=value.parent_token&0x00ffffffu;
    if(!rid||rid>param_count)return malformed("FieldMarshal Param parent is outside the Param table");
    parameter_rows[rid].marshal_descriptor=std::move(value);
  }
  std::vector<ManagedMethod> methods;methods.reserve(count);std::vector<std::uint32_t> param_starts;param_starts.reserve(count);
  for(std::uint32_t i=0;i<count;++i){const auto at=static_cast<std::size_t>(row_offset+std::uint64_t{i}*row_size);ManagedMethod method;method.token=0x06000000u|(i+1);method.rva=u32(tables,at);method.impl_flags=u16(tables,at+4);method.flags=u16(tables,at+6);const auto name_at=at+8;const auto name_index=wide_strings?u32(tables,name_at):u16(tables,name_at);const auto blob_at=name_at+string_width;method.signature_index=wide_blobs?u32(tables,blob_at):u16(tables,blob_at);const auto param_start=read_index(tables,at+list_at,list_width);if(param_start==0||param_start>param_list_count+1)return malformed("CLR MethodDef ParamList index is out of range");param_starts.push_back(param_start);
    if(name_index){if(name_index>=strings.size())return malformed("CLR MethodDef name index exceeds #Strings heap");auto end=name_index;while(end<strings.size() && strings[end]!=std::byte{0})++end;if(end==strings.size())return malformed("CLR MethodDef name is unterminated in #Strings heap");method.name.reserve(end-name_index);for(auto p=name_index;p<end;++p)method.name.push_back(static_cast<char>(std::to_integer<unsigned char>(strings[p])));}
    if(const auto owner=owners.find(method.token);owner!=owners.end()){method.declaring_type=owner->second->full_name;method.declaring_type_generic_parameters=owner->second->generic_parameters;}
    if(const auto generic=method_generics.find(method.token);generic!=method_generics.end())method.generic_parameters=generic->second;
    methods.push_back(std::move(method));
  }
  for(std::size_t m=0;m<methods.size();++m){const auto end=m+1<param_starts.size()?param_starts[m+1]:param_list_count+1;if(end<param_starts[m]||end>param_list_count+1)return malformed("CLR MethodDef ParamList indexes are not monotonic");std::set<std::uint16_t> sequences;for(auto index=param_starts[m];index<end;++index){const auto row=parameter_order[index-1];auto parameter=parameter_rows[row];if(!sequences.insert(parameter.sequence).second)return malformed("CLR method has duplicate Param sequence numbers");methods[m].parameters.push_back(std::move(parameter));}}
  std::vector<bool> assigned(param_count+1,false);for(const auto& method:methods)for(const auto& parameter:method.parameters){const auto row=parameter.token&0x00ffffffu;if(row>param_count||assigned[row])return malformed("CLR Param row is assigned to multiple methods");assigned[row]=true;}if(std::find(assigned.begin()+1,assigned.end(),false)!=assigned.end())return malformed("CLR MethodDef ParamList leaves a Param row unowned");
  const auto import_count_it=metadata.tables.row_counts.find(28);
  const auto import_count=import_count_it==metadata.tables.row_counts.end()?0u:import_count_it->second;
  if(import_count>250000)return Error{ErrorCode::resource_limit,"CLR ImplMap row limit exceeded"};
  if(import_count){
    const auto row_size_it=metadata.tables.row_sizes.find(28),module_count_it=metadata.tables.row_counts.find(26);
    const auto module_count=module_count_it==metadata.tables.row_counts.end()?0u:module_count_it->second;
    const auto member_width=coded_width(9,metadata.tables.row_counts),module_width=module_count<65536?2u:4u;
    const auto module_row_size_it=metadata.tables.row_sizes.find(26);
    const auto import_offset=table_offset(28),module_offset=table_offset(26);
    const auto module_row_size=module_row_size_it==metadata.tables.row_sizes.end()?0u:module_row_size_it->second;
    if(row_size_it==metadata.tables.row_sizes.end()||row_size_it->second!=2+member_width+string_width+module_width||
       import_offset>tables.size()||std::uint64_t{import_count}*row_size_it->second>tables.size()-import_offset||
       !module_count||!module_row_size||module_row_size!=string_width||module_offset>tables.size()||
       std::uint64_t{module_count}*module_row_size>tables.size()-module_offset)
      return malformed("CLR ImplMap or ModuleRef rows exceed their metadata tables");
    const auto read_string=[&](std::uint32_t index)->Result<std::string>{
      if(index==0)return std::string{};
      if(index>=strings.size())return malformed("CLR ImplMap string index exceeds #Strings heap");
      auto end=index;while(end<strings.size()&&strings[end]!=std::byte{0})++end;
      if(end==strings.size())return malformed("CLR ImplMap string is unterminated in #Strings heap");
      std::string value;value.reserve(end-index);
      for(auto p=index;p<end;++p)value.push_back(static_cast<char>(std::to_integer<unsigned char>(strings[p])));
      return value;
    };
    std::map<std::uint32_t,std::size_t> methods_by_token;
    for(std::size_t i=0;i<methods.size();++i)methods_by_token.emplace(methods[i].token,i);
    std::set<std::uint32_t> mapped_members;
    for(std::uint32_t i=0;i<import_count;++i){
      const auto at=static_cast<std::size_t>(import_offset+std::uint64_t{i}*row_size_it->second);
      const auto flags=u16(tables,at);constexpr std::uint16_t known_flags=0x3777;
      if((flags&~known_flags)||((flags&0x0030)==0x0030)||((flags&0x3000)==0x3000)||((flags&0x0700)>0x0500))
        return malformed("CLR ImplMap has reserved or invalid mapping flags");
      const auto forwarded=read_index(tables,at+2,member_width),tag=forwarded&1u,rid=forwarded>>1;
      const auto field_count_it=metadata.tables.row_counts.find(4);
      const auto field_count=field_count_it==metadata.tables.row_counts.end()?0u:field_count_it->second;
      if(!rid||(tag==0?rid>field_count:rid>count))return malformed("CLR ImplMap MemberForwarded index is out of range");
      const auto token=(tag==0?0x04000000u:0x06000000u)|rid;
      if(!mapped_members.insert(token).second)return malformed("CLR member has duplicate ImplMap rows");
      const auto name_index=read_index(tables,at+2+member_width,string_width);
      auto import_name=read_string(name_index);if(!import_name)return import_name.error();
      const auto module_index=read_index(tables,at+2+member_width+string_width,module_width);
      if(!module_index||module_index>module_count)return malformed("CLR ImplMap ModuleRef index is out of range");
      const auto module_name_index=read_index(tables,static_cast<std::size_t>(module_offset+std::uint64_t{module_index-1}*module_row_size),string_width);
      auto module_name=read_string(module_name_index);if(!module_name)return module_name.error();
      if(module_name.value().empty())return malformed("CLR ImplMap ModuleRef has an empty name");
      if(tag==1){
        const auto method=methods_by_token.find(token);
        if(method==methods_by_token.end()||(methods[method->second].flags&0x2000)==0)
          return malformed("CLR ImplMap MethodDef is not marked PInvokeImpl");
        methods[method->second].import_map=ManagedMethodImport{flags,std::move(import_name.value()),
            std::move(module_name.value()),0x1a000000u|module_index};
      }
    }
  }
  for(const auto &method:methods)
    if((method.flags&0x2000)!=0&&!method.import_map)
      return malformed("CLR PInvokeImpl MethodDef has no ImplMap row");
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

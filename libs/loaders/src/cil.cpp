
#include "hexlab/loaders/cil.hpp"
#include "hexlab/loaders/loaded_image.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <limits>
#include <new>
#include <stdexcept>
#include <string_view>

namespace hexlab {
namespace {
enum class OperandKind { none, i8, u8, u16, i32, i64, f32, f64, token, branch8, branch32, switch_table };
struct Op { const char* name; OperandKind operand; CilInstructionStatus status; };
constexpr Op known(const char* name,OperandKind k=OperandKind::none){return {name,k,CilInstructionStatus::decoded};}
constexpr Op unsupported(const char* name,OperandKind k=OperandKind::none){return {name,k,CilInstructionStatus::unsupported};}
Op lookup(std::uint16_t code){
  switch(code){
  case 0x00:return known("nop");case 0x01:return known("break");
  case 0x02:return known("ldarg.0");case 0x03:return known("ldarg.1");case 0x04:return known("ldarg.2");case 0x05:return known("ldarg.3");
  case 0x06:return known("ldloc.0");case 0x07:return known("ldloc.1");case 0x08:return known("ldloc.2");case 0x09:return known("ldloc.3");
  case 0x0a:return known("stloc.0");case 0x0b:return known("stloc.1");case 0x0c:return known("stloc.2");case 0x0d:return known("stloc.3");
  case 0x0e:return known("ldarg.s",OperandKind::u8);case 0x0f:return known("ldarga.s",OperandKind::u8);case 0x10:return known("starg.s",OperandKind::u8);
  case 0x11:return known("ldloc.s",OperandKind::u8);case 0x12:return known("ldloca.s",OperandKind::u8);case 0x13:return known("stloc.s",OperandKind::u8);
  case 0x14:return known("ldnull");case 0x15:return known("ldc.i4.m1");case 0x16:return known("ldc.i4.0");case 0x17:return known("ldc.i4.1");
  case 0x18:return known("ldc.i4.2");case 0x19:return known("ldc.i4.3");case 0x1a:return known("ldc.i4.4");case 0x1b:return known("ldc.i4.5");
  case 0x1c:return known("ldc.i4.6");case 0x1d:return known("ldc.i4.7");case 0x1e:return known("ldc.i4.8");
  case 0x1f:return known("ldc.i4.s",OperandKind::i8);case 0x20:return known("ldc.i4",OperandKind::i32);case 0x21:return known("ldc.i8",OperandKind::i64);
  case 0x22:return known("ldc.r4",OperandKind::f32);case 0x23:return known("ldc.r8",OperandKind::f64);
  case 0x25:return known("dup");case 0x26:return known("pop");case 0x27:return unsupported("jmp",OperandKind::token);case 0x28:return known("call",OperandKind::token);case 0x29:return known("calli",OperandKind::token);case 0x2a:return known("ret");
  case 0x2b:return known("br.s",OperandKind::branch8);case 0x2c:return known("brfalse.s",OperandKind::branch8);case 0x2d:return known("brtrue.s",OperandKind::branch8);
  case 0x2e:return known("beq.s",OperandKind::branch8);case 0x2f:return known("bge.s",OperandKind::branch8);case 0x30:return known("bgt.s",OperandKind::branch8);case 0x31:return known("ble.s",OperandKind::branch8);case 0x32:return known("blt.s",OperandKind::branch8);case 0x33:return known("bne.un.s",OperandKind::branch8);case 0x34:return known("bge.un.s",OperandKind::branch8);case 0x35:return known("bgt.un.s",OperandKind::branch8);case 0x36:return known("ble.un.s",OperandKind::branch8);case 0x37:return known("blt.un.s",OperandKind::branch8);
  case 0x38:return known("br",OperandKind::branch32);case 0x39:return known("brfalse",OperandKind::branch32);case 0x3a:return known("brtrue",OperandKind::branch32);case 0x3b:return known("beq",OperandKind::branch32);case 0x3c:return known("bge",OperandKind::branch32);case 0x3d:return known("bgt",OperandKind::branch32);case 0x3e:return known("ble",OperandKind::branch32);case 0x3f:return known("blt",OperandKind::branch32);case 0x40:return known("bne.un",OperandKind::branch32);case 0x41:return known("bge.un",OperandKind::branch32);case 0x42:return known("bgt.un",OperandKind::branch32);case 0x43:return known("ble.un",OperandKind::branch32);case 0x44:return known("blt.un",OperandKind::branch32);case 0x45:return known("switch",OperandKind::switch_table);
  case 0x46:return known("ldind.i1");case 0x47:return known("ldind.u1");case 0x48:return known("ldind.i2");case 0x49:return known("ldind.u2");case 0x4a:return known("ldind.i4");case 0x4b:return known("ldind.u4");case 0x4c:return known("ldind.i8");case 0x4d:return known("ldind.i");case 0x4e:return known("ldind.r4");case 0x4f:return known("ldind.r8");case 0x50:return known("ldind.ref");
  case 0x51:return known("stind.ref");case 0x52:return known("stind.i1");case 0x53:return known("stind.i2");case 0x54:return known("stind.i4");case 0x55:return known("stind.i8");case 0x56:return known("stind.r4");case 0x57:return known("stind.r8");case 0x58:return known("add");case 0x59:return known("sub");case 0x5a:return known("mul");case 0x5b:return known("div");case 0x5c:return known("div.un");case 0x5d:return known("rem");case 0x5e:return known("rem.un");case 0x5f:return known("and");case 0x60:return known("or");case 0x61:return known("xor");case 0x62:return known("shl");case 0x63:return known("shr");case 0x64:return known("shr.un");case 0x65:return known("neg");case 0x66:return known("not");
  case 0x67:return known("conv.i1");case 0x68:return known("conv.i2");case 0x69:return known("conv.i4");case 0x6a:return known("conv.i8");case 0x6b:return known("conv.r4");case 0x6c:return known("conv.r8");case 0x6d:return known("conv.u4");case 0x6e:return known("conv.u8");
  case 0x6f:return known("callvirt",OperandKind::token);case 0x70:return known("cpobj",OperandKind::token);case 0x71:return known("ldobj",OperandKind::token);case 0x72:return known("ldstr",OperandKind::token);case 0x73:return known("newobj",OperandKind::token);case 0x74:return known("castclass",OperandKind::token);case 0x75:return known("isinst",OperandKind::token);case 0x76:return known("conv.r.un");case 0x79:return known("unbox",OperandKind::token);case 0x7a:return known("throw");
  case 0x7b:return known("ldfld",OperandKind::token);case 0x7c:return unsupported("ldflda",OperandKind::token);case 0x7d:return known("stfld",OperandKind::token);case 0x7e:return known("ldsfld",OperandKind::token);case 0x7f:return unsupported("ldsflda",OperandKind::token);case 0x80:return known("stsfld",OperandKind::token);case 0x81:return known("stobj",OperandKind::token);
  case 0x82:return unsupported("conv.ovf.i1.un");case 0x83:return unsupported("conv.ovf.i2.un");case 0x84:return unsupported("conv.ovf.i4.un");case 0x85:return unsupported("conv.ovf.i8.un");case 0x86:return unsupported("conv.ovf.u1.un");case 0x87:return unsupported("conv.ovf.u2.un");case 0x88:return unsupported("conv.ovf.u4.un");case 0x89:return unsupported("conv.ovf.u8.un");case 0x8a:return unsupported("conv.ovf.i.un");case 0x8b:return unsupported("conv.ovf.u.un");
  case 0x8c:return known("box",OperandKind::token);case 0x8d:return known("newarr",OperandKind::token);case 0x8e:return known("ldlen");case 0x8f:return known("ldelema",OperandKind::token);
  case 0x90:return known("ldelem.i1");case 0x91:return known("ldelem.u1");case 0x92:return known("ldelem.i2");case 0x93:return known("ldelem.u2");case 0x94:return known("ldelem.i4");case 0x95:return known("ldelem.u4");case 0x96:return known("ldelem.i8");case 0x97:return known("ldelem.i");case 0x98:return known("ldelem.r4");case 0x99:return known("ldelem.r8");case 0x9a:return known("ldelem.ref");case 0x9b:return known("stelem.i");case 0x9c:return known("stelem.i1");case 0x9d:return known("stelem.i2");case 0x9e:return known("stelem.i4");case 0x9f:return known("stelem.i8");case 0xa0:return known("stelem.r4");case 0xa1:return known("stelem.r8");case 0xa2:return known("stelem.ref");
  case 0xa3:return unsupported("ldelem",OperandKind::token);case 0xa4:return unsupported("stelem",OperandKind::token);case 0xa5:return known("unbox.any",OperandKind::token);
  case 0xb3:return unsupported("conv.ovf.i1");case 0xb4:return unsupported("conv.ovf.i2");case 0xb5:return unsupported("conv.ovf.i4");case 0xb6:return unsupported("conv.ovf.i8");case 0xb7:return unsupported("conv.ovf.u1");case 0xb8:return unsupported("conv.ovf.u2");case 0xb9:return unsupported("conv.ovf.u4");case 0xba:return unsupported("conv.ovf.u8");
  case 0xc2:return unsupported("refanyval",OperandKind::token);case 0xc3:return unsupported("ckfinite");case 0xc6:return unsupported("mkrefany",OperandKind::token);
  case 0xd0:return known("ldtoken",OperandKind::token);case 0xd1:return known("conv.u2");case 0xd2:return known("conv.u1");case 0xd3:return unsupported("conv.i");case 0xd4:return unsupported("conv.ovf.i");case 0xd5:return unsupported("conv.ovf.u");case 0xd6:return unsupported("add.ovf");case 0xd7:return unsupported("add.ovf.un");case 0xd8:return unsupported("mul.ovf");case 0xd9:return unsupported("mul.ovf.un");case 0xda:return unsupported("sub.ovf");case 0xdb:return unsupported("sub.ovf.un");case 0xdc:return known("endfinally");case 0xdd:return known("leave",OperandKind::branch32);case 0xde:return known("leave.s",OperandKind::branch8);case 0xdf:return known("stind.i");case 0xe0:return unsupported("conv.u");
  case 0xfe00:return known("arglist");case 0xfe01:return known("ceq");case 0xfe02:return known("cgt");case 0xfe03:return known("cgt.un");case 0xfe04:return known("clt");case 0xfe05:return known("clt.un");
  case 0xfe06:return known("ldftn",OperandKind::token);case 0xfe07:return known("ldvirtftn",OperandKind::token);
  case 0xfe09:return known("ldarg",OperandKind::u16);case 0xfe0a:return known("ldarga",OperandKind::u16);case 0xfe0b:return known("starg",OperandKind::u16);case 0xfe0c:return known("ldloc",OperandKind::u16);case 0xfe0d:return known("ldloca",OperandKind::u16);case 0xfe0e:return known("stloc",OperandKind::u16);case 0xfe0f:return unsupported("localloc");case 0xfe11:return known("endfilter");case 0xfe12:return unsupported("unaligned.",OperandKind::u8);case 0xfe13:return known("volatile.");case 0xfe14:return known("tail.");case 0xfe15:return known("initobj",OperandKind::token);case 0xfe16:return known("constrained.",OperandKind::token);case 0xfe17:return known("cpblk");case 0xfe18:return known("initblk");case 0xfe19:return unsupported("no.",OperandKind::u8);case 0xfe1a:return known("rethrow");case 0xfe1c:return known("sizeof",OperandKind::token);case 0xfe1d:return unsupported("refanytype");case 0xfe1e:return known("readonly.");
  default:return {"unknown",OperandKind::none,CilInstructionStatus::unknown};
  }
}
std::uint16_t read16(std::span<const std::byte> b,std::size_t p){return std::uint16_t(std::to_integer<std::uint8_t>(b[p]))|(std::uint16_t(std::to_integer<std::uint8_t>(b[p+1]))<<8);}
std::uint32_t read32(std::span<const std::byte> b,std::size_t p){return std::uint32_t(read16(b,p))|(std::uint32_t(read16(b,p+2))<<16);}
std::uint64_t read64(std::span<const std::byte> b,std::size_t p){return std::uint64_t(read32(b,p))|(std::uint64_t(read32(b,p+4))<<32);}
Error malformed(const char* text){return {ErrorCode::malformed,text};}
}

Result<std::vector<CilInstruction>> decode_cil_instructions(std::span<const std::byte> il) try {
  if(il.size()>16*1024*1024)return Error{ErrorCode::resource_limit,"CIL stream exceeds 16 MiB inspection limit"};
  std::vector<CilInstruction> out;std::size_t p=0;
  while(p<il.size()){
    if(out.size()>=1000000)return Error{ErrorCode::resource_limit,"CIL stream exceeds one-million-instruction inspection limit"};
    const auto start=p;std::uint16_t opcode=std::to_integer<std::uint8_t>(il[p++]);
    if(opcode==0xfe){if(p>=il.size())return malformed("Truncated two-byte CIL opcode");opcode=static_cast<std::uint16_t>(0xfe00|std::to_integer<std::uint8_t>(il[p++]));}
    const auto op=lookup(opcode);CilInstruction ins;ins.offset=static_cast<std::uint32_t>(start);ins.opcode=opcode;ins.status=op.status;ins.mnemonic=op.name;
    auto require=[&](std::size_t n)->bool{return p<=il.size() && n<=il.size()-p;};
    switch(op.operand){
    case OperandKind::none:break;
    case OperandKind::i8:if(!require(1))return malformed("Truncated signed-byte CIL operand");ins.operand=static_cast<std::int8_t>(std::to_integer<std::uint8_t>(il[p++]));break;
    case OperandKind::u8:if(!require(1))return malformed("Truncated byte CIL operand");ins.operand=std::to_integer<std::uint8_t>(il[p++]);break;
    case OperandKind::u16:if(!require(2))return malformed("Truncated 16-bit CIL operand");ins.operand=read16(il,p);p+=2;break;
    case OperandKind::i32:if(!require(4))return malformed("Truncated 32-bit CIL operand");ins.operand=std::bit_cast<std::int32_t>(read32(il,p));p+=4;break;
    case OperandKind::i64:if(!require(8))return malformed("Truncated 64-bit CIL operand");ins.operand=std::bit_cast<std::int64_t>(read64(il,p));p+=8;break;
    case OperandKind::f32:if(!require(4))return malformed("Truncated float CIL operand");ins.operand=std::bit_cast<float>(read32(il,p));p+=4;break;
    case OperandKind::f64:if(!require(8))return malformed("Truncated double CIL operand");ins.operand=std::bit_cast<double>(read64(il,p));p+=8;break;
    case OperandKind::token:if(!require(4))return malformed("Truncated metadata-token CIL operand");ins.operand=CilTokenOperand{read32(il,p)};p+=4;break;
    case OperandKind::branch8:case OperandKind::branch32:{
      const auto width=op.operand==OperandKind::branch8?1u:4u;if(!require(width))return malformed("Truncated branch CIL operand");
      const std::int32_t delta=width==1?std::int32_t(std::bit_cast<std::int8_t>(std::to_integer<std::uint8_t>(il[p]))):std::bit_cast<std::int32_t>(read32(il,p));p+=width;
      const auto target=static_cast<std::int64_t>(p)+delta;if(target<0||target>=static_cast<std::int64_t>(il.size()))return malformed("CIL branch target is outside the method body");
      ins.operand=CilBranchOperand{delta,static_cast<std::uint32_t>(target)};break;
    }
    case OperandKind::switch_table:{
      if(!require(4))return malformed("Truncated CIL switch case count");const auto n=read32(il,p);p+=4;
      if(n>65536)return Error{ErrorCode::resource_limit,"CIL switch exceeds 65536-case inspection limit"};
      if(!require(std::size_t{n}*4))return malformed("CIL switch target table exceeds method body");
      const auto base=p+std::size_t{n}*4;CilSwitchOperand sw;sw.displacements.reserve(n);sw.target_offsets.reserve(n);
      for(std::uint32_t i=0;i<n;++i){const auto d=std::bit_cast<std::int32_t>(read32(il,p));p+=4;const auto target=static_cast<std::int64_t>(base)+d;if(target<0||target>=static_cast<std::int64_t>(il.size()))return malformed("CIL switch target is outside the method body");sw.displacements.push_back(d);sw.target_offsets.push_back(static_cast<std::uint32_t>(target));}
      ins.operand=std::move(sw);break;
 }
 }

    ins.size=static_cast<std::uint32_t>(p-start);ins.encoding.assign(il.begin()+static_cast<std::ptrdiff_t>(start),il.begin()+static_cast<std::ptrdiff_t>(p));out.push_back(std::move(ins));
  }
  std::vector<std::uint8_t> boundaries(il.size());for(const auto& ins:out)boundaries[ins.offset]=1;
  for(const auto& ins:out){
    if(const auto* b=std::get_if<CilBranchOperand>(&ins.operand)){
      if(!boundaries[b->target_offset])return malformed("CIL branch target does not begin an instruction");
    } else if(const auto* sw=std::get_if<CilSwitchOperand>(&ins.operand)){
      for(auto target:sw->target_offsets)if(!boundaries[target])return malformed("CIL switch target does not begin an instruction");
    }
  }
  return out;
} catch(const std::bad_alloc&) {return Error{ErrorCode::resource_limit,"Cannot allocate CIL instruction stream"};}
  catch(const std::length_error&) {return Error{ErrorCode::resource_limit,"CIL instruction stream allocation exceeds container limits"};}
}
namespace hexlab {
namespace {
Result<std::vector<std::byte>> read_managed_metadata_root(const LoadedImage &loaded) {
  if(!loaded.image || !loaded.metadata.pe)return Error{ErrorCode::invalid_argument,"Managed inspection requires a loaded PE image"};
  auto managed=parse_managed_pe(loaded);if(!managed)return managed.error();
  const auto directory=std::find_if(loaded.metadata.directories.begin(),loaded.metadata.directories.end(),[](const Directory& d){return d.index==14;});
  if(directory==loaded.metadata.directories.end() || !directory->location || directory->size<72)return Error{ErrorCode::unsupported,"PE image has no complete CLR runtime directory"};
  const auto base=loaded.load_base.value_or(loaded.metadata.preferred_base);
  auto header_va=checked_add(base,std::uint64_t{directory->location});if(!header_va)return header_va.error();
  auto header=loaded.image->read({loaded.image->layout().space.id,header_va.value()},72);if(!header)return header.error();
  const auto metadata_rva=read32(header.value(),8),metadata_size=read32(header.value(),12);
  if(metadata_size>64*1024*1024 || !metadata_size)return Error{ErrorCode::resource_limit,"CLR metadata root exceeds inspection limit"};
  auto metadata_va=checked_add(base,std::uint64_t{metadata_rva});if(!metadata_va)return metadata_va.error();
  return loaded.image->read({loaded.image->layout().space.id,metadata_va.value()},metadata_size);
}
}
Result<std::vector<ManagedTypeDefinition>> inspect_managed_types(const LoadedImage &loaded) try {
  auto metadata=read_managed_metadata_root(loaded);if(!metadata)return metadata.error();
  return parse_managed_types(metadata.value());
} catch(const std::bad_alloc&) {return Error{ErrorCode::resource_limit,"Cannot allocate CLR type catalog"};}
  catch(const std::length_error&) {return Error{ErrorCode::resource_limit,"CLR type catalog exceeds container limits"};}

Result<std::vector<ManagedField>> inspect_managed_fields(const LoadedImage &loaded) try {
  auto metadata=read_managed_metadata_root(loaded);if(!metadata)return metadata.error();
  return parse_managed_fields(metadata.value());
} catch(const std::bad_alloc&) {return Error{ErrorCode::resource_limit,"Cannot allocate CLR field catalog"};}
  catch(const std::length_error&) {return Error{ErrorCode::resource_limit,"CLR field catalog exceeds container limits"};}

Result<ManagedUserStringCatalog> inspect_managed_user_strings(const LoadedImage &loaded) try {
  auto metadata=read_managed_metadata_root(loaded);if(!metadata)return metadata.error();
  return parse_managed_user_strings(metadata.value());
} catch(const std::bad_alloc&) {return Error{ErrorCode::resource_limit,"Cannot allocate CLR user-string catalog"};}
  catch(const std::length_error&) {return Error{ErrorCode::resource_limit,"CLR user-string catalog exceeds container limits"};}

Result<std::vector<ManagedMethodAnalysis>> inspect_managed_methods(const LoadedImage& loaded,std::stop_token stop) try {
  auto metadata_bytes=read_managed_metadata_root(loaded);if(!metadata_bytes)return metadata_bytes.error();
  const auto base=loaded.load_base.value_or(loaded.metadata.preferred_base);
  auto methods=parse_managed_methods(metadata_bytes.value());if(!methods)return methods.error();
  auto call_signatures=parse_managed_call_signatures(metadata_bytes.value());
  auto fields=parse_managed_fields(metadata_bytes.value());
  if(!fields)return fields.error();
  auto field_references=parse_managed_field_references(metadata_bytes.value());
  if(!field_references)return field_references.error();
  std::map<std::uint32_t,ManagedField> field_catalog;
  for(auto &field:fields.value())field_catalog.emplace(field.token,std::move(field));
  for(auto &field:field_references.value())field_catalog.emplace(field.token,std::move(field));
  // Older/minimal metadata roots can expose method bodies without carrying the
  // tables and #Blob heaps needed for call-effect recovery. Keep body decoding
  // available in that case; malformed signature data still fails explicitly.
  if(!call_signatures && call_signatures.error().message!="Call-signature resolution requires tables and #Blob heaps")return call_signatures.error();
  auto user_strings=parse_managed_user_strings(metadata_bytes.value());
  std::shared_ptr<const ManagedUserStringCatalog> user_string_catalog;
  std::optional<Error> user_string_error;
  if(user_strings)user_string_catalog=std::make_shared<const ManagedUserStringCatalog>(std::move(user_strings.value()));
  else user_string_error=user_strings.error();
  std::map<std::uint32_t,std::string> exception_type_names;
  std::map<std::uint32_t,ManagedAssemblyIdentity> exception_type_assemblies;
  std::shared_ptr<const ManagedTypeCatalog> exception_type_catalog;
  auto type_catalog=parse_managed_type_catalog(metadata_bytes.value());
  if(type_catalog){
    exception_type_catalog=std::make_shared<const ManagedTypeCatalog>(std::move(type_catalog.value()));
    for(const auto &type:exception_type_catalog->definitions)
      if(!type.full_name.empty())exception_type_names.emplace(type.token,type.full_name);
    for(const auto &type:exception_type_catalog->references) {
      if(!type.full_name.empty())exception_type_names.emplace(type.token,type.full_name);
      if(type.assembly_scope)exception_type_assemblies.emplace(type.token,*type.assembly_scope);
    }
  }
  std::vector<ManagedMethodAnalysis> result;result.reserve(methods.value().size());
  for(auto& method:methods.value()){
    if(stop.stop_requested())return Error{ErrorCode::canceled,"Managed method inspection canceled"};
    ManagedMethodAnalysis analysis;analysis.method=std::move(method);if(call_signatures)analysis.resolved_call_signatures=call_signatures.value();analysis.resolved_fields=field_catalog;analysis.resolved_exception_types=exception_type_catalog;
    if(!analysis.method.rva){analysis.status=ManagedMethodStatus::no_body;analysis.diagnostic="MethodDef has no IL RVA";result.push_back(std::move(analysis));continue;}
    if((analysis.method.impl_flags&3)!=0){analysis.status=ManagedMethodStatus::unsupported;analysis.diagnostic="MethodDef is native, runtime-provided, or uses a non-IL code type";result.push_back(std::move(analysis));continue;}
    auto fail=[&](const Error& error){analysis.status=ManagedMethodStatus::malformed;analysis.diagnostic=error.message;};
    auto body_va=checked_add(base,std::uint64_t{analysis.method.rva});if(!body_va){fail(body_va.error());result.push_back(std::move(analysis));continue;}
    const Address address{loaded.image->layout().space.id,body_va.value()};const auto* segment=loaded.image->segment_at(address);
    if(!segment || !segment->file_size || address.offset<segment->begin.offset){fail(malformed("MethodDef RVA is not backed by initialized image bytes"));result.push_back(std::move(analysis));continue;}
    const auto relative=address.offset-segment->begin.offset;if(relative>=segment->file_size){fail(malformed("MethodDef RVA points into uninitialized image memory"));result.push_back(std::move(analysis));continue;}const auto available=segment->file_size-relative;
    auto get=[&](std::size_t count)->Result<std::vector<std::byte>>{
      if(count>available)return Error{ErrorCode::malformed,"CIL method body exceeds initialized image bytes"};
      return loaded.image->read(address,count);
    };
    auto first=get(1);if(!first){fail(first.error());result.push_back(std::move(analysis));continue;}
    const auto format=std::to_integer<std::uint8_t>(first.value()[0]);std::size_t body_size=0;bool more_sections=false;
    if((format&3)==2)body_size=1+(format>>2);
    else if((format&3)==3){
      auto fat=get(12);if(!fat){fail(fat.error());result.push_back(std::move(analysis));continue;}
      const auto flags=read16(fat.value(),0);const auto dwords=(flags>>12)&15;const auto code_size=read32(fat.value(),4);
      if(dwords<3 || code_size>16*1024*1024){fail(malformed("Invalid or oversized fat CIL method body"));result.push_back(std::move(analysis));continue;}
      const auto code_at=static_cast<std::size_t>(dwords)*4;if(code_at>SIZE_MAX-code_size){fail(malformed("CIL method size overflows address space"));result.push_back(std::move(analysis));continue;}
      body_size=code_at+code_size;more_sections=(flags&0x08)!=0;
    } else {fail(malformed("Unknown CIL method header format"));result.push_back(std::move(analysis));continue;}
    if(body_size>16*1024*1024+64){fail(malformed("CIL method body exceeds bounded reader"));result.push_back(std::move(analysis));continue;}
    if(more_sections){
      body_size=(body_size+3)&~std::size_t{3};unsigned section_count=0;
      while(more_sections){
        if(++section_count>16 || body_size>available || available-body_size<4){body_size=SIZE_MAX;break;}
        auto section=get(body_size+4);if(!section){body_size=SIZE_MAX;break;}
        const auto kind=std::to_integer<std::uint8_t>(section.value()[body_size]);more_sections=(kind&0x80)!=0;const bool fat=(kind&0x40)!=0;
        const auto size=fat?(std::uint32_t(std::to_integer<std::uint8_t>(section.value()[body_size+1]))|(std::uint32_t(std::to_integer<std::uint8_t>(section.value()[body_size+2]))<<8)|(std::uint32_t(std::to_integer<std::uint8_t>(section.value()[body_size+3]))<<16)):std::to_integer<std::uint8_t>(section.value()[body_size+1]);
        if(size<4 || size>16*1024*1024 || size>available-body_size || body_size>32*1024*1024-size){body_size=SIZE_MAX;break;}body_size+=size;
        if(more_sections)body_size=(body_size+3)&~std::size_t{3};
      }
      if(body_size==SIZE_MAX){fail(malformed("Invalid or oversized CIL method section chain"));result.push_back(std::move(analysis));continue;}
    }
    auto raw=get(body_size);if(!raw){fail(raw.error());result.push_back(std::move(analysis));continue;}
    auto body=parse_cil_method_body(raw.value());if(!body){fail(body.error());result.push_back(std::move(analysis));continue;}
    auto instructions=decode_cil_instructions(body.value().il);if(!instructions){fail(instructions.error());result.push_back(std::move(analysis));continue;}
    analysis.body=std::move(body.value());analysis.instructions=std::move(instructions.value());
    const auto uses_user_strings=std::any_of(analysis.instructions.begin(),analysis.instructions.end(),[](const auto &instruction){return std::string_view(instruction.mnemonic)=="ldstr";});
    if(uses_user_strings){
      if(user_string_error){fail(*user_string_error);result.push_back(std::move(analysis));continue;}
      analysis.resolved_user_strings=user_string_catalog;
      bool unresolved=false;
      for(const auto &instruction:analysis.instructions)if(std::string_view(instruction.mnemonic)=="ldstr"){
        const auto *operand=std::get_if<CilTokenOperand>(&instruction.operand);
        if(!operand || (operand->token>>24)!=0x70 || !user_string_catalog || !user_string_catalog->contains(operand->token)){unresolved=true;break;}
      }
      if(unresolved){fail(malformed("CIL ldstr operand does not resolve to a CLR #US entry"));result.push_back(std::move(analysis));continue;}
    }
    for(const auto &clause:analysis.body->exception_clauses){
      if(clause.kind!=CilExceptionKind::catch_clause)continue;
      if(const auto type=exception_type_names.find(clause.class_token);type!=exception_type_names.end())
        analysis.resolved_exception_type_names.emplace(type->first,type->second);
      if(const auto assembly=exception_type_assemblies.find(clause.class_token);assembly!=exception_type_assemblies.end())
        analysis.resolved_exception_type_assemblies.emplace(assembly->first,assembly->second);
    }
    analysis.status=ManagedMethodStatus::decoded;result.push_back(std::move(analysis));
  }
  return result;
} catch(const std::bad_alloc&) {return Error{ErrorCode::resource_limit,"Cannot allocate CLR method analysis"};}
  catch(const std::length_error&) {return Error{ErrorCode::resource_limit,"CLR method analysis exceeds container limits"};}
}

#pragma once
#include "hexlab/analysis/references.hpp"
#include "hexlab/core/encoding.hpp"
namespace hexlab::reference_detail {
struct Failure {Error error;};
template<class T>T take(Result<T> value){if(!value)throw Failure{value.error()};return std::move(value.value());}
inline void require(bool condition,const char* message){if(!condition)throw Failure{{ErrorCode::malformed,message}};}
inline void canceled(std::stop_token stop){if(stop.stop_requested())throw Failure{{ErrorCode::canceled,"Reference operation canceled"}};}
template<class F>auto guarded(F operation)->decltype(operation()){
    try{return operation();}catch(const Failure& failure){return failure.error;}
    catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot allocate reference records"};}
    catch(const std::length_error&){return Error{ErrorCode::resource_limit,"Reference records exceed allocation limits"};}
}
bool valid_external(const ExternalIdentity&);
std::string external_key(const ExternalIdentity&);
void validate_reference(const Reference&);
std::vector<std::byte> reference_key(const Reference&);
Sha256Digest checked_hash(std::span<const std::byte>,std::stop_token);
std::size_t elf_provenance_weight(const ElfReferenceProvenance&);
void validate_elf_provenance(const ElfReferenceProvenance&);
std::vector<std::byte> elf_provenance_bytes(const ElfReferenceProvenance&);
ElfReferenceProvenance read_elf_provenance(std::span<const std::byte>);
std::string elf_symbol_key(const ElfSymbolIdentity&);
std::size_t macho_provenance_weight(const MachOReferenceProvenance&);
void validate_macho_provenance(const MachOReferenceProvenance&);
std::vector<std::byte> macho_provenance_bytes(const MachOReferenceProvenance&);
MachOReferenceProvenance read_macho_provenance(std::span<const std::byte>);
std::string macho_symbol_key(const MachOSymbolIdentity&);
std::size_t dyld_provenance_weight(const MachODyldReferenceProvenance&);
void validate_dyld_provenance(const MachODyldReferenceProvenance&);
std::vector<std::byte> dyld_provenance_bytes(const MachODyldReferenceProvenance&);
MachODyldReferenceProvenance read_dyld_provenance(std::span<const std::byte>);
MachODyldReferenceProvenance own_dyld_provenance(const MachOMetadata&,const MachODyldResolution&,std::optional<Address>,std::stop_token);
}

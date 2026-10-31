hexlab_add_library(loaders SOURCES src/detect.cpp src/recipe.cpp src/raw.cpp src/ar.cpp src/ar_elf.cpp src/ar_coff.cpp src/ar_xcoff.cpp src/xcoff64.cpp src/ar_macho.cpp src/elf_link.cpp src/elf_dependency_resolution.cpp src/elf_dependency_symbols.cpp src/elf32_link.cpp src/coff_link.cpp src/macho_link.cpp src/pe_headers.cpp src/elf_headers.cpp src/macho_headers.cpp
  src/pe_imports.cpp src/pe_bound_imports.cpp src/pe_delay_imports.cpp src/pe_certificates.cpp src/pe_authenticode.cpp src/pe_authenticode_pkcs7.cpp src/pe_authenticode_verify.cpp src/pe_exports.cpp src/pe_relocations.cpp src/pe_tls.cpp src/pe_tls_template.cpp src/pe_load_config.cpp src/pe_chpe.cpp src/x86_raw_profile.cpp src/x86_profile_codec.cpp src/arm_raw_profile.cpp
  src/pe_exceptions.cpp src/pe_rtti.cpp src/pe_rich.cpp src/pe_section_profile.cpp src/minidump.cpp
  src/segmented_raw.cpp src/elf_sections.cpp src/elf_debug_link.cpp src/elf_core.cpp src/elf_image.cpp src/elf_symbols.cpp src/elf_symbol_versions.cpp src/elf_relocations.cpp
  src/elf_dynamic.cpp src/elf_dynamic_symbols.cpp src/elf_dynamic_relocations.cpp src/elf_virtual.cpp src/elf_unwind.cpp src/elf_cfi.cpp src/elf_rtti.cpp
  src/macho_segments.cpp src/macho_image.cpp src/macho_symbols.cpp src/macho_lines.cpp src/macho_commands.cpp src/macho_relocations.cpp src/macho_dyld.cpp src/macho_exports.cpp src/macho_chained.cpp src/macho_shared_cache.cpp src/macho_protections.cpp src/macho_codesign_hashes.cpp src/macho_unwind.cpp src/managed.cpp src/cil.cpp src/firmware.cpp src/wasm.cpp src/wasm_link.cpp src/dex.cpp src/dex_container.cpp src/dex_archive.cpp src/apk_signing_block.cpp src/vdex.cpp src/jvm.cpp src/jvm_module_path.cpp src/jar.cpp src/jmod.cpp src/elf_lines.cpp src/elf_dwarf.cpp src/elf_debug_macro.cpp src/elf_debug_compression.cpp src/pdb_lines.cpp DEPENDS hexlab::image hexlab::firmware hexlab::symbols hexlab::types)
target_sources(hexlab_loaders PRIVATE src/pe_debug.cpp)
target_sources(hexlab_loaders PRIVATE src/elf_debug_frame.cpp)
target_sources(hexlab_loaders PRIVATE src/minidump_context.cpp)
target_sources(hexlab_loaders PRIVATE src/jvm_signature.cpp)
target_link_libraries(hexlab_loaders PRIVATE hexlab_miniz)
if(WIN32)
  target_link_libraries(hexlab_loaders PRIVATE Crypt32)
endif()

# StackMapTable offsets are validated by the shared JVM instruction decoder.
target_link_libraries(hexlab_loaders PRIVATE hexlab::processors)

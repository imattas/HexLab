hexlab_add_library(analysis SOURCES src/abi.cpp src/reachable.cpp src/strings.cpp src/functions.cpp src/functions_a64.cpp src/blocks.cpp src/stack.cpp src/switches.cpp src/dependencies.cpp
  src/references.cpp src/reference_range.cpp src/references_codec.cpp src/elf_reference_codec.cpp src/macho_reference_codec.cpp src/macho_dyld_reference_codec.cpp src/string_references.cpp src/graph.cpp src/graph_layout.cpp src/graph_export.cpp src/incremental.cpp
  src/derived_cache.cpp src/derived_cache_instruction.cpp src/source_context.cpp src/search.cpp src/search_query.cpp src/signatures.cpp src/flirt.cpp src/elf_relocations.cpp src/macho_relocations.cpp src/macho_dyld.cpp src/relocations.cpp src/macho_objc.cpp src/macho_objc_types.cpp
  DEPENDS hexlab::image hexlab::processors hexlab::types)
target_link_libraries(hexlab_analysis PRIVATE hexlab_miniz)
if(MSVC)
  target_compile_options(hexlab_analysis PRIVATE /FS)
endif()

add_library(hexlab_miniz STATIC miniz.c miniz_tinfl.c)
include(GenerateExportHeader)
generate_export_header(hexlab_miniz
  EXPORT_FILE_NAME "${CMAKE_CURRENT_BINARY_DIR}/miniz_export.h"
  EXPORT_MACRO_NAME MINIZ_EXPORT
  STATIC_DEFINE MINIZ_STATIC)
target_include_directories(hexlab_miniz PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${CMAKE_CURRENT_BINARY_DIR}")
target_compile_definitions(hexlab_miniz PRIVATE
  MINIZ_STATIC
  MINIZ_NO_ARCHIVE_APIS
  MINIZ_NO_STDIO
  MINIZ_NO_TIME
  MINIZ_NO_DEFLATE_APIS
  MINIZ_NO_ZLIB_COMPATIBLE_NAMES)
set_target_properties(hexlab_miniz PROPERTIES POSITION_INDEPENDENT_CODE ON)

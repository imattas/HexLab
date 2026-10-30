set(BROTLI_COMMON_SOURCES
  c/common/constants.c c/common/context.c c/common/dictionary.c
  c/common/platform.c c/common/shared_dictionary.c c/common/transform.c)
file(GLOB BROTLI_DECODER_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/c/dec/*.c")
add_library(hexlab_brotli_decoder STATIC ${BROTLI_COMMON_SOURCES} ${BROTLI_DECODER_SOURCES})
target_include_directories(hexlab_brotli_decoder PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/c/include"
  PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/c/common" "${CMAKE_CURRENT_SOURCE_DIR}/c/dec")
set_target_properties(hexlab_brotli_decoder PROPERTIES POSITION_INDEPENDENT_CODE ON)

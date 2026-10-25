include(FetchContent)
set(wxBUILD_SHARED ON CACHE BOOL "Shared wxWidgets runtime" FORCE)
set(wxBUILD_SAMPLES OFF CACHE STRING "No wx samples" FORCE)
set(wxBUILD_TESTS OFF CACHE STRING "No wx tests" FORCE)
set(wxBUILD_DEMOS OFF CACHE BOOL "No wx demos" FORCE)
set(wxBUILD_INSTALL OFF CACHE BOOL "Install application only" FORCE)
set(wxUSE_AUI ON CACHE BOOL "Docking support" FORCE)
set(wxUSE_STC OFF CACHE BOOL "Styled editor not needed by foundation" FORCE)
set(wxUSE_WEBVIEW OFF CACHE BOOL "No embedded browser" FORCE)
set(wxUSE_MEDIACTRL OFF CACHE BOOL "No media backend" FORCE)
FetchContent_Declare(wxwidgets
  GIT_REPOSITORY https://github.com/wxWidgets/wxWidgets.git
  GIT_TAG 3b7c7fc839093ad28146bd17555af2565c792c96
  GIT_SHALLOW FALSE
  GIT_CONFIG core.longpaths=true
  GIT_PROGRESS TRUE)
FetchContent_MakeAvailable(wxwidgets)
set_property(DIRECTORY "${wxwidgets_SOURCE_DIR}" PROPERTY EXCLUDE_FROM_ALL TRUE)
add_library(hexlab_wx INTERFACE)
target_link_libraries(hexlab_wx INTERFACE wx::core wx::base wx::aui)

set(_hexlab_notices_wxwidgets docs/licence.txt docs/lgpl.txt docs/gpl.txt)
set(_hexlab_notices_pcre 3rdparty/pcre/LICENCE)
set(_hexlab_notices_zlib src/zlib/LICENSE)
set(_hexlab_notices_png src/png/LICENSE)
set(_hexlab_notices_jpeg src/jpeg/README)
set(_hexlab_notices_tiff src/tiff/COPYRIGHT)
set(_hexlab_notices_expat src/expat/expat/COPYING)
set(_hexlab_notices_nanosvg 3rdparty/nanosvg/LICENSE.txt)
foreach(component IN ITEMS wxwidgets pcre zlib png jpeg tiff expat nanosvg)
  foreach(notice IN LISTS _hexlab_notices_${component})
    if(NOT EXISTS "${wxwidgets_SOURCE_DIR}/${notice}")
      message(FATAL_ERROR "Required ${component} notice is missing: ${notice}")
    endif()
    install(FILES "${wxwidgets_SOURCE_DIR}/${notice}"
      DESTINATION "${CMAKE_INSTALL_DATADIR}/hexlab/licenses/${component}")
  endforeach()
endforeach()

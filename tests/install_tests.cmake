foreach(path IN ITEMS bin/hexlab_cli.exe bin/hexlab_core.dll
    lib/hexlab_core.lib include/hexlab/core/address.hpp
    include/hexlab/core/core_export.hpp share/hexlab/docs/third-party.md)
  if(NOT EXISTS "${PREFIX}/${path}")
    message(FATAL_ERROR "Incomplete distribution: missing ${path}")
  endif()
endforeach()
foreach(component IN ITEMS image loaders processors analysis database workspace)
  foreach(path IN ITEMS "bin/hexlab_${component}.dll" "lib/hexlab_${component}.lib"
      "include/hexlab/${component}/${component}_export.hpp")
    if(NOT EXISTS "${PREFIX}/${path}")
      message(FATAL_ERROR "Incomplete engine distribution: missing ${path}")
    endif()
  endforeach()
endforeach()
foreach(path IN ITEMS bin/hexlab_sqlite3.dll lib/hexlab_sqlite3.lib
    include/hexlab/core/architecture.hpp include/hexlab/processors/decoder.hpp
    share/hexlab/docs/x86-32-coverage.csv share/hexlab/docs/x86-32-validation.md
    include/hexlab/database/project_state.hpp include/hexlab/database/input.hpp
    include/hexlab/workspace/project_graph.hpp
    include/hexlab/core/x86_segments.hpp include/hexlab/loaders/x86_raw_profile.hpp
    include/hexlab/workspace/navigation.hpp include/hexlab/workspace/open_recipe.hpp
    share/hexlab/docs/x86-profiles.md share/hexlab/docs/segmented-analysis-validation.md
    share/hexlab/docs/x86-16-coverage.csv
    share/hexlab/docs/project-format.md share/hexlab/docs/project-analysis-validation.md
    share/hexlab/licenses/sqlite/NOTICE share/hexlab/licenses/sqlite/provenance.json)
  if(NOT EXISTS "${PREFIX}/${path}")
    message(FATAL_ERROR "Incomplete project distribution: missing ${path}")
  endif()
endforeach()
if(NOT EXISTS "${GENERATOR}")
  message(FATAL_ERROR "Provide -DGENERATOR=<built hexlab_fixture_generator.exe> for installed binary verification")
endif()
set(CLI "${PREFIX}/bin/hexlab_cli.exe")
set(FIXTURES "${PREFIX}/test-fixtures")
include("${CMAKE_CURRENT_LIST_DIR}/cli_binary_tests.cmake")
set(FIXTURES "${PREFIX}/test-fixtures/segmented-cli")
include("${CMAKE_CURRENT_LIST_DIR}/segmented_cli_tests.cmake")
execute_process(COMMAND "${PREFIX}/bin/hexlab_cli.exe" --version
  RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 10)
if(NOT "${status}" STREQUAL "0" OR NOT output MATCHES "^HexLab 0\\.1\\.1[\r\n]+$")
  message(FATAL_ERROR "Installed CLI failed: ${status}; ${output}; ${error}")
endif()
if(DESKTOP)
  foreach(component IN ITEMS base core aui)
    file(GLOB dlls "${PREFIX}/bin/wx*${component}*.dll")
    if(NOT dlls)
      message(FATAL_ERROR "Missing wxWidgets ${component} runtime DLL")
    endif()
  endforeach()
  foreach(notice IN ITEMS wxwidgets pcre zlib png jpeg tiff expat nanosvg)
    file(GLOB files "${PREFIX}/share/hexlab/licenses/${notice}/*")
    if(NOT files)
      message(FATAL_ERROR "Missing ${notice} notices")
    endif()
  endforeach()
  set(APP "${PREFIX}/bin/hexlab.exe")
  include("${CMAKE_CURRENT_LIST_DIR}/desktop_smoke.cmake")
endif()
message(STATUS "Installed distribution verified: ${PREFIX}")

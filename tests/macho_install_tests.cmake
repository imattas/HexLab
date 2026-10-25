if(NOT IS_ABSOLUTE "${PREFIX}" OR NOT IS_DIRECTORY "${PREFIX}/bin" OR NOT IS_DIRECTORY "${TEST_BIN}")
  message(FATAL_ERROR "Supply absolute installed PREFIX and current matching TEST_BIN")
endif()
foreach(path IN ITEMS include/hexlab/loaders/macho.hpp include/hexlab/image/macho_metadata.hpp
    include/hexlab/analysis/macho_relocations.hpp include/hexlab/analysis/macho_dyld.hpp
    include/hexlab/workspace/macho_presentation.hpp share/hexlab/docs/macho-analysis-validation.md)
  if(NOT EXISTS "${PREFIX}/${path}")
    message(FATAL_ERROR "Missing public Mach-O distribution file: ${path}")
  endif()
endforeach()
set(validation "${PREFIX}/validation/macho")
file(MAKE_DIRECTORY "${validation}/tools" "${validation}/fixtures")
set(ENV{PATH} "${PREFIX}/bin;$ENV{PATH}")
function(run_installed name)
  execute_process(COMMAND ${ARGN} WORKING_DIRECTORY "${validation}"
    RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 180)
  file(WRITE "${validation}/${name}.stdout" "${output}")
  file(WRITE "${validation}/${name}.stderr" "${error}")
  if(NOT "${status}" STREQUAL "0")
    message(FATAL_ERROR "Installed ${name}: ${status}; ${output}; ${error}")
  endif()
  message(STATUS "Installed ${name}: ${output}")
endfunction()
foreach(kind IN ITEMS macho_header macho_image macho_symbol macho_command macho_recipe
    macho_project_symbol macho_relocation macho_resolution macho_reference macho_flow
    macho_project macho_worker macho_export_flow macho_dyld macho_chained
    macho_dyld_resolution macho_dyld_flow)
  file(COPY "${TEST_BIN}/hexlab_${kind}_tests.exe" DESTINATION "${validation}/tools")
  run_installed("${kind}" "${validation}/tools/hexlab_${kind}_tests.exe")
endforeach()
file(GLOB historical "${CMAKE_CURRENT_LIST_DIR}/fixtures/*_macho_*" "${CMAKE_CURRENT_LIST_DIR}/fixtures/*_arm_v*")
file(COPY ${historical} "${CMAKE_CURRENT_LIST_DIR}/fixtures/macho_guard_x64.o"
  "${CMAKE_CURRENT_LIST_DIR}/fixtures/macho_guard_x64.s" DESTINATION "${validation}/fixtures")
foreach(kind IN ITEMS macho_cache macho_guard macho_dyld_reference)
  file(COPY "${TEST_BIN}/hexlab_${kind}_tests.exe" DESTINATION "${validation}/tools")
endforeach()
run_installed(cache "${validation}/tools/hexlab_macho_cache_tests.exe"
  "${validation}/fixtures/derived_v5_macho_v13.hxdc" "${validation}/fixtures/derived_v5_macho_v13_input.o"
  "${validation}/fixtures/derived_v6_macho_v15.hxdc" "${validation}/fixtures/derived_v6_macho_v15_input.o"
  "${validation}/fixtures/derived_v7_macho_v16.hxdc" "${validation}/fixtures/derived_v7_macho_v16_input.macho"
  "${validation}/fixtures/derived_v8_macho_v17.hxdc" "${validation}/fixtures/derived_v8_macho_v17_input.macho"
  "${validation}/fixtures/derived_v8_macho_v18.hxdc" "${validation}/fixtures/derived_v8_macho_v18_input.macho"
  "${validation}/fixtures/derived_v8_macho_v19.hxdc" "${validation}/fixtures/derived_v8_macho_v19_input.macho"
  "${validation}/fixtures/derived_v8_arm_v20.hxdc" "${validation}/fixtures/derived_v8_arm_v20_input.macho"
  "${validation}/fixtures/derived_v8_arm_v21.hxdc" "${validation}/fixtures/derived_v8_arm_v21_input.macho")
run_installed(guards "${validation}/tools/hexlab_macho_guard_tests.exe" "${validation}/fixtures/macho_guard_x64.o")
run_installed(dyld_provenance "${validation}/tools/hexlab_macho_dyld_reference_tests.exe" "${validation}/fixtures/references_v6_macho_v16.hxrf")
file(COPY "${CMAKE_CURRENT_LIST_DIR}/macho_oracle.py" "${CMAKE_CURRENT_LIST_DIR}/macho_oracle_probe.cpp"
  DESTINATION "${validation}")
file(COPY "${CMAKE_CURRENT_LIST_DIR}/fixtures/macho_oracle" DESTINATION "${validation}/fixtures")
file(COPY "${CMAKE_CURRENT_LIST_DIR}/sdk/macho" DESTINATION "${PREFIX}/validation/sdk-source")
file(COPY "${TEST_BIN}/hexlab_macho_oracle_probe.exe" "${TEST_BIN}/hexlab_macho_fixture_generator.exe"
  DESTINATION "${validation}/tools")
find_package(Python3 REQUIRED COMPONENTS Interpreter)
find_program(CLANG NAMES clang HINTS "C:/Program Files/LLVM/bin" REQUIRED)
find_program(READOBJ NAMES llvm-readobj HINTS "C:/Program Files/LLVM/bin" REQUIRED)
find_program(OBJDUMP NAMES llvm-objdump HINTS "C:/Program Files/LLVM/bin" REQUIRED)
find_program(LD64 NAMES ld64.lld HINTS "C:/Program Files/LLVM/bin" REQUIRED)
run_installed(oracle "${Python3_EXECUTABLE}" "${validation}/macho_oracle.py"
  --clang "${CLANG}" --readobj "${READOBJ}" --objdump "${OBJDUMP}" --lld "${LD64}"
  --probe "${validation}/tools/hexlab_macho_oracle_probe.exe" --runtime-dir "${PREFIX}/bin"
  --sources "${validation}/fixtures/macho_oracle" --artifacts "${validation}/oracle")
run_installed(cli "${CMAKE_COMMAND}" "-DCLI=${PREFIX}/bin/hexlab_cli.exe"
  "-DGENERATOR=${validation}/tools/hexlab_macho_fixture_generator.exe" "-DFIXTURES=${validation}/cli"
  -P "${CMAKE_CURRENT_LIST_DIR}/macho_cli_tests.cmake")
run_installed(sdk_inputs "${validation}/tools/hexlab_macho_fixture_generator.exe" "${validation}/sdk-inputs")
if(DESKTOP)
  file(COPY "${TEST_BIN}/hexlab_desktop_macho_tests.exe" DESTINATION "${validation}/tools")
  run_installed(native "${validation}/tools/hexlab_desktop_macho_tests.exe")
endif()
if(DESKTOP)
  message(STATUS "Installed Mach-O engine/CLI/native/oracle verification passed: ${PREFIX}")
else()
  message(STATUS "Installed Mach-O engine/CLI/oracle verification passed: ${PREFIX}; native workflow requires DESKTOP=ON")
endif()

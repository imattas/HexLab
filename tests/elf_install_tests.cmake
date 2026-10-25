if(NOT IS_ABSOLUTE "${PREFIX}" OR NOT IS_DIRECTORY "${PREFIX}/bin" OR NOT IS_DIRECTORY "${TEST_BIN}")
  message(FATAL_ERROR "Supply absolute installed PREFIX and built TEST_BIN")
endif()
set(validation "${PREFIX}/validation/elf")
file(MAKE_DIRECTORY "${validation}/tools")
set(ENV{PATH} "${PREFIX}/bin;$ENV{PATH}")
foreach(kind IN ITEMS elf_header elf_image elf_symbol elf_relocation elf_dynamic
    elf_dynamic_symbol elf_dynamic_relocation elf_flow elf_reference_provenance elf_project)
  set(tool "hexlab_${kind}_tests.exe")
  file(COPY "${TEST_BIN}/${tool}" DESTINATION "${validation}/tools")
  execute_process(COMMAND "${validation}/tools/${tool}" WORKING_DIRECTORY "${validation}"
    RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 45)
  if(NOT "${status}" STREQUAL "0")
    message(FATAL_ERROR "Installed ${kind}: ${status}; ${output}; ${error}")
  endif()
  message(STATUS "${kind}: ${output}")
endforeach()
file(COPY "${TEST_BIN}/hexlab_fixture_generator.exe" "${TEST_BIN}/hexlab_elf_oracle_probe.exe"
  DESTINATION "${validation}/tools")
file(COPY "${CMAKE_CURRENT_LIST_DIR}/elf_oracle.py" "${CMAKE_CURRENT_LIST_DIR}/fixtures/elf_oracle"
  DESTINATION "${validation}")
find_package(Python3 REQUIRED COMPONENTS Interpreter)
find_program(CLANG NAMES clang HINTS "C:/Program Files/LLVM/bin" REQUIRED)
find_program(LLD NAMES ld.lld HINTS "C:/Program Files/LLVM/bin" REQUIRED)
find_program(READOBJ NAMES llvm-readobj HINTS "C:/Program Files/LLVM/bin" REQUIRED)
execute_process(COMMAND "${Python3_EXECUTABLE}" "${validation}/elf_oracle.py"
  --clang "${CLANG}" --lld "${LLD}" --readobj "${READOBJ}"
  --probe "${validation}/tools/hexlab_elf_oracle_probe.exe" --generator "${validation}/tools/hexlab_fixture_generator.exe"
  --sources "${validation}/elf_oracle" --artifacts "${validation}/oracle"
  RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 180)
if(NOT "${status}" STREQUAL "0")
  message(FATAL_ERROR "Installed independent ELF oracle: ${status}; ${output}; ${error}")
endif()
message(STATUS "Installed oracle: ${output}")
execute_process(COMMAND "${CMAKE_COMMAND}" "-DCLI=${PREFIX}/bin/hexlab_cli.exe"
  "-DGENERATOR=${validation}/tools/hexlab_fixture_generator.exe" "-DFIXTURES=${validation}/cli"
  -P "${CMAKE_CURRENT_LIST_DIR}/elf_cli_tests.cmake"
  RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 120)
if(NOT "${status}" STREQUAL "0")
  message(FATAL_ERROR "Installed ELF CLI workflow: ${status}; ${output}; ${error}")
endif()
message(STATUS "Installed ELF CLI workflows passed")

if(NOT EXISTS "${CLI}")
  message(FATAL_ERROR "CLI executable does not exist: ${CLI}")
endif()
file(MAKE_DIRECTORY "${ARTIFACTS}")
execute_process(COMMAND "${PYTHON}" "${CMAKE_CURRENT_LIST_DIR}/archive_aarch64_tests.py"
  --cli "${CLI}" --artifacts "${ARTIFACTS}/aarch64" RESULT_VARIABLE aarch64_status
  OUTPUT_VARIABLE aarch64_stdout ERROR_VARIABLE aarch64_stderr TIMEOUT 60)
if(NOT "${aarch64_status}" STREQUAL "0")
  message(FATAL_ERROR "AArch64 archive link validation failed: ${aarch64_stdout}; ${aarch64_stderr}")
endif()
execute_process(COMMAND "${PYTHON}" "${CMAKE_CURRENT_LIST_DIR}/archive_link_select_fixtures.py"
  --artifacts "${ARTIFACTS}/link-select" RESULT_VARIABLE fixture_status
  OUTPUT_VARIABLE fixture_stdout ERROR_VARIABLE fixture_stderr TIMEOUT 10)
if(NOT "${fixture_status}" STREQUAL "0")
  message(FATAL_ERROR "Could not generate link-select fixtures; status=${fixture_status}; stderr=${fixture_stderr}")
endif()
set(link_archive "${ARTIFACTS}/link-select/link-lib.a")
set(root_object "${ARTIFACTS}/link-select/link-root.o")
set(archive "${CMAKE_CURRENT_LIST_DIR}/fixtures/archive-single-member.a")
set(output "${ARTIFACTS}/member.bin")
file(REMOVE "${output}" "${ARTIFACTS}/fresh.bin" "${ARTIFACTS}/invalid.bin")

file(WRITE "${output}" "old")
execute_process(COMMAND "${CLI}" archive extract "${archive}" --member 0 --output "${output}"
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 10)
if(NOT "${status}" STREQUAL "1" OR NOT stderr MATCHES "already exists")
  message(FATAL_ERROR "Extraction should refuse overwrite by default; status=${status}; stdout=${stdout}; stderr=${stderr}")
endif()
file(READ "${output}" contents)
if(NOT "${contents}" STREQUAL "old")
  message(FATAL_ERROR "Refused extraction changed the existing output")
endif()

execute_process(COMMAND "${CLI}" archive extract "${archive}" --member 0 --output "${output}" --replace
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 10)
if(NOT "${status}" STREQUAL "0" OR NOT stdout MATCHES "Extracted archive member 0" OR NOT "${stderr}" STREQUAL "")
  message(FATAL_ERROR "Explicit replacement failed; status=${status}; stdout=${stdout}; stderr=${stderr}")
endif()
file(READ "${output}" contents)
if(NOT "${contents}" STREQUAL "hello\n")
  message(FATAL_ERROR "Extracted member contents do not match: '${contents}'")
endif()

set(fresh "${ARTIFACTS}/fresh.bin")
execute_process(COMMAND "${CLI}" archive extract "${archive}" --member 0 --output "${fresh}"
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 10)
if(NOT "${status}" STREQUAL "0")
  message(FATAL_ERROR "Extraction to a new output failed; status=${status}; stderr=${stderr}")
endif()
file(READ "${fresh}" contents)
if(NOT "${contents}" STREQUAL "hello\n")
  message(FATAL_ERROR "New output contents do not match: '${contents}'")
endif()

execute_process(COMMAND "${CLI}" archive extract "${archive}" --member 7 --output "${ARTIFACTS}/invalid.bin"
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 10)
if(NOT "${status}" STREQUAL "2" OR NOT stderr MATCHES "out of range")
  message(FATAL_ERROR "Out-of-range member should be rejected as an argument error; status=${status}; stderr=${stderr}")
endif()

execute_process(COMMAND "${CLI}" archive link-select "${link_archive}" --root-object "${root_object}"
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 10)
if(NOT "${status}" STREQUAL "0" OR NOT "${stderr}" STREQUAL "")
  message(FATAL_ERROR "Archive fixed-point selection failed; status=${status}; stdout=${stdout}; stderr=${stderr}")
endif()
if(NOT stdout MATCHES "Selected: member=0 name=first\.o triggered-by=first_needed" OR
   NOT stdout MATCHES "Selected: member=1 name=second\.o triggered-by=second_needed" OR
   NOT stdout MATCHES "Unresolved: not_available")
  message(FATAL_ERROR "Archive fixed-point selection did not report the expected members/provenance/unresolved symbol: ${stdout}")
endif()

execute_process(COMMAND "${CLI}" archive link-audit "${link_archive}" --root-object "${root_object}"
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 10)
if(NOT "${status}" STREQUAL "0" OR NOT "${stderr}" STREQUAL "" OR
   NOT stdout MATCHES "Relocation: object=<root> type=2 symbol=first_needed provider=first\.o" OR
   NOT stdout MATCHES "Link audit: objects=3 unresolved-relocations=0 unsupported-relocations=0 output=none")
  message(FATAL_ERROR "Archive relocation audit did not resolve the root PC32 relocation: status=${status}; stdout=${stdout}; stderr=${stderr}")
endif()

set(linked_output "${ARTIFACTS}/link-select/combined.o")
file(REMOVE "${linked_output}" "${ARTIFACTS}/link-select/unresolved.o")
execute_process(COMMAND "${CLI}" archive link "${ARTIFACTS}/link-select/link-good.a"
  --root-object "${root_object}" --output "${linked_output}"
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 10)
if(NOT "${status}" STREQUAL "0" OR NOT "${stderr}" STREQUAL "" OR
   NOT stdout MATCHES "Linked ELF ET_REL: objects=3 .*relocations-applied=true")
  message(FATAL_ERROR "Archive x86-64 link failed: status=${status}; stdout=${stdout}; stderr=${stderr}")
endif()
execute_process(COMMAND "${PYTHON}" "${CMAKE_CURRENT_LIST_DIR}/archive_link_output_check.py" "${linked_output}"
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 10)
if(NOT "${status}" STREQUAL "0")
  message(FATAL_ERROR "Linked ET_REL output validation failed: status=${status}; stdout=${stdout}; stderr=${stderr}")
endif()

set(data_linked_output "${ARTIFACTS}/link-select/data-relocated.o")
file(REMOVE "${data_linked_output}")
execute_process(COMMAND "${CLI}" archive link "${ARTIFACTS}/link-select/link-data-good.a"
  --root-object "${ARTIFACTS}/link-select/link-data-relocation.o" --output "${data_linked_output}"
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 10)
if(NOT "${status}" STREQUAL "0" OR NOT "${stderr}" STREQUAL "")
  message(FATAL_ERROR "Archive .data relocation link failed: status=${status}; stdout=${stdout}; stderr=${stderr}")
endif()
execute_process(COMMAND "${PYTHON}" "${CMAKE_CURRENT_LIST_DIR}/archive_link_output_check.py" "${data_linked_output}" data-relocation
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 10)
if(NOT "${status}" STREQUAL "0")
  message(FATAL_ERROR "Linked .data relocation validation failed: status=${status}; stdout=${stdout}; stderr=${stderr}")
endif()

set(executable_output "${ARTIFACTS}/link-select/combined.exe")
file(REMOVE "${executable_output}")
execute_process(COMMAND "${CLI}" archive link-exec "${ARTIFACTS}/link-select/link-data-good.a"
  --root-object "${ARTIFACTS}/link-select/link-data-relocation.o" --entry root_symbol --output "${executable_output}"
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 10)
if(NOT "${status}" STREQUAL "0" OR NOT "${stderr}" STREQUAL "" OR
   NOT stdout MATCHES "Linked ELF ET_EXEC: objects=3 .*relocations-applied=true")
  message(FATAL_ERROR "Archive executable link failed: status=${status}; stdout=${stdout}; stderr=${stderr}")
endif()
execute_process(COMMAND "${PYTHON}" "${CMAKE_CURRENT_LIST_DIR}/archive_link_output_check.py" "${executable_output}" executable-data-relocation
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 10)
if(NOT "${status}" STREQUAL "0")
  message(FATAL_ERROR "Linked ET_EXEC output validation failed: status=${status}; stdout=${stdout}; stderr=${stderr}")
endif()

set(absolute_executable_output "${ARTIFACTS}/link-select/absolute-relocation.exe")
file(REMOVE "${absolute_executable_output}")
execute_process(COMMAND "${CLI}" archive link-exec "${ARTIFACTS}/link-select/link-data-good.a"
  --root-object "${ARTIFACTS}/link-select/link-exec-relocation.o" --entry root_symbol --output "${absolute_executable_output}"
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 10)
if(NOT "${status}" STREQUAL "0" OR NOT "${stderr}" STREQUAL "")
  message(FATAL_ERROR "Archive absolute-relocation executable link failed: status=${status}; stdout=${stdout}; stderr=${stderr}")
endif()
execute_process(COMMAND "${PYTHON}" "${CMAKE_CURRENT_LIST_DIR}/archive_link_output_check.py" "${absolute_executable_output}" executable-absolute-relocation
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 10)
if(NOT "${status}" STREQUAL "0")
  message(FATAL_ERROR "Linked absolute ET_EXEC relocation validation failed: status=${status}; stdout=${stdout}; stderr=${stderr}")
endif()

execute_process(COMMAND "${CLI}" archive link-exec "${ARTIFACTS}/link-select/link-data-good.a"
  --root-object "${ARTIFACTS}/link-select/link-data-relocation.o" --entry missing_entry
  --output "${ARTIFACTS}/link-select/no-entry.exe"
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 10)
if(NOT "${status}" STREQUAL "1" OR NOT stderr MATCHES "entry symbol is undefined: missing_entry")
  message(FATAL_ERROR "Missing executable entry was not rejected: status=${status}; stdout=${stdout}; stderr=${stderr}")
endif()

execute_process(COMMAND "${CLI}" archive link "${link_archive}" --root-object "${root_object}"
  --output "${ARTIFACTS}/link-select/unresolved.o"
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 10)
if(NOT "${status}" STREQUAL "1" OR NOT stderr MATCHES "Unresolved strong ELF symbol not_available")
  message(FATAL_ERROR "Unresolved strong symbol was not rejected with its name: status=${status}; stdout=${stdout}; stderr=${stderr}")
endif()

execute_process(COMMAND "${CLI}" archive link "${ARTIFACTS}/link-select/link-good.a"
  --root-object "${ARTIFACTS}/link-select/link-unsupported.o" --output "${ARTIFACTS}/link-select/unsupported.o"
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 10)
if(NOT "${status}" STREQUAL "1" OR NOT stderr MATCHES "Unsupported x86-64 ELF relocation type 999")
  message(FATAL_ERROR "Unsupported relocation was not rejected explicitly: status=${status}; stdout=${stdout}; stderr=${stderr}")
endif()

execute_process(COMMAND "${CLI}" archive link "${ARTIFACTS}/link-select/link-good.a"
  --root-object "${ARTIFACTS}/link-select/link-out-of-bounds.o" --output "${ARTIFACTS}/link-select/out-of-bounds.o"
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 10)
if(NOT "${status}" STREQUAL "1" OR NOT stderr MATCHES "ELF relocation field exceeds target section")
  message(FATAL_ERROR "Out-of-bounds relocation was not rejected explicitly: status=${status}; stdout=${stdout}; stderr=${stderr}")
endif()

execute_process(COMMAND "${CLI}" archive link "${ARTIFACTS}/link-select/link-good.a"
  --root-object "${ARTIFACTS}/link-select/link-data-out-of-bounds.o" --output "${ARTIFACTS}/link-select/data-out-of-bounds.o"
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 10)
if(NOT "${status}" STREQUAL "1" OR NOT stderr MATCHES "ELF relocation field exceeds target section")
  message(FATAL_ERROR "Out-of-bounds .data relocation was not rejected explicitly: status=${status}; stdout=${stdout}; stderr=${stderr}")
endif()

set(pe_output "${ARTIFACTS}/link-select/coff-linked.exe")
file(REMOVE "${pe_output}")
execute_process(COMMAND "${CLI}" archive link-pe "${ARTIFACTS}/link-select/coff-lib.lib"
  --root-object "${ARTIFACTS}/link-select/coff-root.obj" --entry _start --output "${pe_output}"
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 10)
if(NOT "${status}" STREQUAL "0" OR NOT "${stderr}" STREQUAL "" OR
   NOT stdout MATCHES "Linked PE32.*objects=2 .*relocations-applied=true")
  message(FATAL_ERROR "COFF archive executable link failed: status=${status}; stdout=${stdout}; stderr=${stderr}")
endif()
execute_process(COMMAND "${PYTHON}" "${CMAKE_CURRENT_LIST_DIR}/coff_link_output_check.py" "${pe_output}"
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 10)
if(NOT "${status}" STREQUAL "0")
  message(FATAL_ERROR "Linked PE output validation failed: status=${status}; stdout=${stdout}; stderr=${stderr}")
endif()

set(pe_bss_output "${ARTIFACTS}/link-select/coff-linked-bss.exe")
file(REMOVE "${pe_bss_output}")
execute_process(COMMAND "${CLI}" archive link-pe "${ARTIFACTS}/link-select/coff-lib.lib"
  --root-object "${ARTIFACTS}/link-select/coff-bss-root.obj" --entry _start --output "${pe_bss_output}"
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 10)
if(NOT "${status}" STREQUAL "0" OR NOT "${stderr}" STREQUAL "")
  message(FATAL_ERROR "COFF archive executable link with BSS failed: status=${status}; stdout=${stdout}; stderr=${stderr}")
endif()
execute_process(COMMAND "${PYTHON}" "${CMAKE_CURRENT_LIST_DIR}/coff_link_output_check.py" "${pe_bss_output}" bss
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 10)
if(NOT "${status}" STREQUAL "0")
  message(FATAL_ERROR "Linked PE BSS output validation failed: status=${status}; stdout=${stdout}; stderr=${stderr}")
endif()
execute_process(COMMAND "${CLI}" archive link-pe "${ARTIFACTS}/link-select/coff-lib.lib"
  --root-object "${ARTIFACTS}/link-select/coff-bss-out-of-range.obj" --entry _start
  --output "${ARTIFACTS}/link-select/coff-linked-invalid-bss.exe"
  RESULT_VARIABLE status OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr TIMEOUT 10)
if(NOT "${status}" STREQUAL "1" OR NOT stderr MATCHES "COFF symbol value exceeds its section extent")
  message(FATAL_ERROR "Out-of-range COFF BSS symbol was not rejected: status=${status}; stdout=${stdout}; stderr=${stderr}")
endif()

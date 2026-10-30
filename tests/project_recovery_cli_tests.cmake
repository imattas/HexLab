if(NOT DEFINED CLI OR NOT DEFINED INPUT OR NOT DEFINED WORK)
  message(FATAL_ERROR "CLI, INPUT, and WORK are required")
endif()
file(MAKE_DIRECTORY "${WORK}")
set(target "${WORK}/recovery-target.hxproj")
set(artifact "${WORK}/.hexlab-save-same-project.tmp")
file(REMOVE "${target}" "${target}-wal" "${target}-shm" "${artifact}")

function(recovery_check expected output_pattern error_pattern)
  execute_process(COMMAND "${CLI}" project ${ARGN}
    RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 20)
  if(NOT "${status}" STREQUAL "${expected}" OR
     NOT "${output}" MATCHES "${output_pattern}" OR
     NOT "${error}" MATCHES "${error_pattern}")
    message(FATAL_ERROR "project ${ARGN}: expected ${expected}, got ${status}\nstdout=${output}\nstderr=${error}")
  endif()
  set(last_output "${output}" PARENT_SCOPE)
endfunction()

recovery_check(0 "Saved:" "^$" create "${target}" --input "${INPUT}" --format raw --arch x86-64 --base 0x1000)
file(COPY_FILE "${target}" "${artifact}")
recovery_check(0 "Edit revision: 1" "^$" patch "${target}" --at file:0 --bytes CC)
recovery_check(0 "kind.*interrupted_save" "^$" recovery list "${WORK}" --json)
recovery_check(0 "target_uuid_preserved.*true" "^$" recovery restore-in-place "${artifact}" --target "${target}" --json)
if(NOT EXISTS "${artifact}")
  message(FATAL_ERROR "Recovery removed the source interrupted-save artifact")
endif()
recovery_check(0 "Edit revision: 0" "^$" inspect "${target}")

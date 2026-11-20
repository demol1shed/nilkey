# Runs a program that must fail. Passes only if the exit status is non-zero AND
# its output matches PATTERN, so a usage error or crash for an unrelated
# reason cannot satisfy it (CTest's WILL_FAIL accepts any non-zero exit).
#
# Usage: cmake -DEXE=<program> [-DARG=<argument>] -DPATTERN=<regex> -P expect_failure.cmake

execute_process(
  COMMAND ${EXE} ${ARG}
  RESULT_VARIABLE rc
  OUTPUT_VARIABLE out
  ERROR_VARIABLE err)

if(rc EQUAL 0)
  message(FATAL_ERROR "expected a failure, but the program exited with status 0")
endif()

if(NOT "${out}${err}" MATCHES "${PATTERN}")
  message(FATAL_ERROR "program failed (${rc}) but output did not match '${PATTERN}':\n${out}${err}")
endif()

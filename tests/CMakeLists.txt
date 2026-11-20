# Sanitizer runtime options come from here, never from the caller's shell.
set(NILKEY_TEST_ENVIRONMENT
  "ASAN_OPTIONS=detect_leaks=1:strict_string_checks=1:detect_stack_use_after_return=1:abort_on_error=1"
  "UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1")

# A test executable built from <name>.cpp that must exit with status 0.
function(nilkey_add_test name)
  add_executable(${name} ${name}.cpp)
  target_link_libraries(${name} PRIVATE nilkey_core)
  add_test(NAME ${name} COMMAND ${name})
  set_tests_properties(${name} PROPERTIES ENVIRONMENT "${NILKEY_TEST_ENVIRONMENT}")
endfunction()

# Registers a test that passes only if `exe` (with `arg`) fails with output
# matching `pattern`. See expect_failure.cmake.
function(nilkey_add_expected_failure test_name exe arg pattern)
  add_test(NAME ${test_name}
    COMMAND ${CMAKE_COMMAND}
      -DEXE=$<TARGET_FILE:${exe}> -DARG=${arg} -DPATTERN=${pattern}
      -P ${CMAKE_CURRENT_SOURCE_DIR}/expect_failure.cmake)
  set_tests_properties(${test_name} PROPERTIES ENVIRONMENT "${NILKEY_TEST_ENVIRONMENT}")
endfunction()

nilkey_add_test(test_result)

# Gate self-checks: each of these must fail for the stated reason.
add_executable(test_framework_failure test_framework_failure.cpp)
target_link_libraries(test_framework_failure PRIVATE nilkey_core)
nilkey_add_expected_failure(framework_failure test_framework_failure ""
  "FAIL .*test_framework_failure.cpp:[0-9]+: false")

add_executable(test_framework_empty test_framework_empty.cpp)
target_link_libraries(test_framework_empty PRIVATE nilkey_core)
nilkey_add_expected_failure(framework_empty test_framework_empty ""
  "no tests registered")

# These two deliberately trigger sanitizer findings. They are not real
# findings: they prove that the sanitizer gate aborts instead of continuing.
if(NILKEY_ENABLE_SANITIZERS)
  add_executable(sanitizer_canary sanitizer_canary.cpp)
  target_link_libraries(sanitizer_canary PRIVATE nilkey_options)
  nilkey_add_expected_failure(sanitizer_canary_ubsan sanitizer_canary ubsan
    "runtime error: signed integer overflow")
  nilkey_add_expected_failure(sanitizer_canary_asan sanitizer_canary asan
    "AddressSanitizer: heap-buffer-overflow")
endif()

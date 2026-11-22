# Sanitizer runtime options come from here, never from the caller's shell.
set(NILKEY_TEST_ENVIRONMENT
  "ASAN_OPTIONS=detect_leaks=1:strict_string_checks=1:detect_stack_use_after_return=1:abort_on_error=1"
  "UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1")

# A test executable built from <name>.cpp that must exit with status 0.
# Tests that derive keys pass nilkey_core_test (fast KDF limits) as the
# second argument.
function(nilkey_add_test name)
  set(lib nilkey_core)
  if(ARGC GREATER 1)
    set(lib ${ARGV1})
  endif()
  add_executable(${name} ${name}.cpp)
  target_link_libraries(${name} PRIVATE ${lib})
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
nilkey_add_test(test_secure_buffer)
nilkey_add_test(test_hardening)
nilkey_add_test(test_vault_format nilkey_core_test)
nilkey_add_test(test_crypto nilkey_core_test)
nilkey_add_test(test_atomic_file nilkey_core_test)
nilkey_add_test(test_tlv)
nilkey_add_test(test_vault nilkey_core_test)
nilkey_add_test(test_store nilkey_core_test)
set_tests_properties(test_store PROPERTIES TIMEOUT 60)
nilkey_add_test(test_args)
nilkey_add_test(test_fd_io)
nilkey_add_test(test_passgen)
nilkey_add_test(test_cli)
nilkey_add_test(test_cli_generate)
set_tests_properties(test_cli_generate PROPERTIES TIMEOUT 60)

# Drives real pseudo-terminals; a hang must fail the test, not the CI job.
nilkey_add_test(test_terminal)
set_tests_properties(test_terminal PROPERTIES TIMEOUT 60)

# Real Argon2id costs (64 MiB, 3 passes). Links nilkey_core, which has no
# test-only macros. Skip with `ctest -LE slow`.
nilkey_add_test(test_crypto_production_kdf)
set_tests_properties(test_crypto_production_kdf PROPERTIES LABELS slow TIMEOUT 120)

# Sanitizer runtimes intercept mlock() and always report success, so the
# lock-failure policy can only be tested without them.
if(NOT NILKEY_ENABLE_SANITIZERS)
  nilkey_add_test(test_memlock_policy)
endif()

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

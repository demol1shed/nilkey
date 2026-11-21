cmake_minimum_required(VERSION 3.20)
project(nilkey VERSION 0.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(NILKEY_ENABLE_SANITIZERS "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(NILKEY_WERROR "Treat compiler warnings as errors" ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# SPEC.md section 3 asks for -O2; CMake's default Release flags are -O3 -DNDEBUG.
set(CMAKE_CXX_FLAGS_RELEASE "-O2")

# Makes CMake pass -fPIE to compiles and -pie to links of executables.
include(CheckPIESupported)
check_pie_supported(LANGUAGES CXX)
if(NOT CMAKE_CXX_LINK_PIE_SUPPORTED)
  message(FATAL_ERROR "The toolchain does not support PIE executables")
endif()
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium>=1.0.18)

# Every target in the project, tests included, links this one target.
add_library(nilkey_options INTERFACE)
target_compile_options(nilkey_options INTERFACE
  -Wall -Wextra -Wpedantic -Wconversion -Wshadow
  -fno-exceptions -fno-rtti)

if(NILKEY_WERROR)
  target_compile_options(nilkey_options INTERFACE -Werror)
endif()

if(NILKEY_ENABLE_SANITIZERS)
  # -fno-sanitize-recover=all makes any finding abort; without it UBSan
  # prints a report and the process still exits with status 0.
  set(NILKEY_SANITIZER_FLAGS
    -fsanitize=address,undefined
    -fno-omit-frame-pointer
    -fno-sanitize-recover=all)
  target_compile_options(nilkey_options INTERFACE ${NILKEY_SANITIZER_FLAGS})
  target_link_options(nilkey_options INTERFACE ${NILKEY_SANITIZER_FLAGS})
endif()

# Hardening applies to Release only. Ubuntu's GCC predefines _FORTIFY_SOURCE,
# so it is undefined first to avoid a redefinition warning under -Werror.
target_compile_options(nilkey_options INTERFACE
  $<$<CONFIG:Release>:-fstack-protector-strong>
  $<$<CONFIG:Release>:-U_FORTIFY_SOURCE>
  $<$<CONFIG:Release>:-D_FORTIFY_SOURCE=2>)
target_link_options(nilkey_options INTERFACE
  $<$<CONFIG:Release>:-Wl,-z,relro,-z,now>)

set(NILKEY_CORE_SOURCES
  src/crypto.cpp
  src/hardening.cpp
  src/secure_buffer.cpp
  src/vault_format.cpp)

add_library(nilkey_core STATIC ${NILKEY_CORE_SOURCES})
target_include_directories(nilkey_core PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(nilkey_core PUBLIC nilkey_options PkgConfig::SODIUM)

# The same sources with the test-only KDF limits (SPEC.md 4.1 and 10). Only
# tests link this target; the nilkey binary never gets these macros.
add_library(nilkey_core_test STATIC ${NILKEY_CORE_SOURCES})
target_include_directories(nilkey_core_test PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(nilkey_core_test PUBLIC nilkey_options PkgConfig::SODIUM)
target_compile_definitions(nilkey_core_test PUBLIC
  NILKEY_ALLOW_TEST_KDF
  NILKEY_TEST_MAX_KDF_MEM_KIB=1024)

add_executable(nilkey src/main.cpp)
target_compile_definitions(nilkey PRIVATE NILKEY_VERSION="${PROJECT_VERSION}")
target_link_libraries(nilkey PRIVATE nilkey_core)

enable_testing()
add_subdirectory(tests)

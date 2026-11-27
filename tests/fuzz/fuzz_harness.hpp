#ifndef NILKEY_FUZZ_HARNESS_HPP
#define NILKEY_FUZZ_HARNESS_HPP

// Shared part of the parser fuzz harnesses (SPEC.md 10). Each harness defines
// the two functions below and is linked either with libFuzzer or with
// fuzz_replay_main.cpp.
//
// Fuzz inputs are made-up bytes, never secrets, so the harnesses keep them in
// ordinary containers instead of paying for a SecureBuffer per input.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

// Runs one input through the parser and traps if a property does not hold.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);

// Starting inputs, built by code so that the repository holds no opaque binary
// files. An input that once made a fuzzer fail belongs here too.
std::vector<std::vector<std::byte>> FuzzSeeds();

// Prints the expression and its location, never a value.
#define NILKEY_FUZZ_CHECK(condition)                                                \
  do {                                                                              \
    if (!(condition)) {                                                             \
      std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition);     \
      __builtin_trap();                                                             \
    }                                                                               \
  } while (false)

#endif  // NILKEY_FUZZ_HARNESS_HPP

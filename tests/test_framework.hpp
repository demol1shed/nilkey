#ifndef NILKEY_TEST_FRAMEWORK_HPP
#define NILKEY_TEST_FRAMEWORK_HPP

// Minimal single-header test framework. No exceptions: every check macro
// records the failure and `return`s from the current test function, so checks
// can only be used directly inside NILKEY_TEST bodies (not in helpers that
// return a value).
//
// Failure output contains only the expression text and file:line, never the
// values involved, so a failing test cannot leak secret bytes.

#include <sodium.h>

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <span>

namespace nilkey::test {

struct TestCase {
  const char* name;
  void (*fn)();
  TestCase* next;
};

struct Registry {
  TestCase* head = nullptr;
  TestCase* tail = nullptr;
  bool current_failed = false;
};

inline Registry& registry() {
  static Registry r;
  return r;
}

struct Registrar {
  explicit Registrar(TestCase* tc) {
    Registry& r = registry();
    if (r.tail == nullptr) {
      r.head = tc;
    } else {
      r.tail->next = tc;
    }
    r.tail = tc;
  }
};

inline void report_failure(const char* expr, const char* file, int line) {
  registry().current_failed = true;
  std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, expr);
}

// Constant-time comparison for byte ranges that may hold secrets.
inline bool secret_equal(std::span<const std::byte> a, std::span<const std::byte> b) {
  if (a.size() != b.size()) return false;
  if (a.empty()) return true;
  return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

inline int run_all() {
  if (sodium_init() < 0) {
    std::fputs("FAIL: sodium_init failed\n", stderr);
    return EXIT_FAILURE;
  }
  Registry& r = registry();
  int total = 0;
  int failed = 0;
  for (TestCase* tc = r.head; tc != nullptr; tc = tc->next) {
    r.current_failed = false;
    std::fprintf(stderr, "[ RUN  ] %s\n", tc->name);
    tc->fn();
    ++total;
    if (r.current_failed) {
      ++failed;
      std::fprintf(stderr, "[ FAIL ] %s\n", tc->name);
    }
  }
  // A broken registration mechanism must not look like a green run.
  if (total == 0) {
    std::fputs("FAIL: no tests registered\n", stderr);
    return EXIT_FAILURE;
  }
  std::fprintf(stderr, "%d test(s) run, %d failed\n", total, failed);
  return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

}  // namespace nilkey::test

#define NILKEY_TEST(name)                                                              \
  static void name();                                                                  \
  static ::nilkey::test::TestCase nilkey_case_##name{#name, name, nullptr};            \
  [[maybe_unused]] static const ::nilkey::test::Registrar nilkey_reg_##name{           \
      &nilkey_case_##name};                                                            \
  static void name()

#define NILKEY_EXPECT(expr)                                                  \
  do {                                                                       \
    if (!(expr)) {                                                           \
      ::nilkey::test::report_failure(#expr, __FILE__, __LINE__);             \
      return;                                                                \
    }                                                                        \
  } while (false)

// Compares two std::span<const std::byte> in constant time.
#define NILKEY_EXPECT_SECRET_EQ(a, b) NILKEY_EXPECT(::nilkey::test::secret_equal((a), (b)))

#define NILKEY_TEST_MAIN() \
  int main() { return ::nilkey::test::run_all(); }

#endif  // NILKEY_TEST_FRAMEWORK_HPP

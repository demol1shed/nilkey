#include <climits>
#include <cstdio>
#include <cstring>

// Triggers one deliberate sanitizer finding. It returns 0 right after the
// faulty line, so the only way to exit non-zero is the sanitizer aborting.
// CTest runs it through expect_failure.cmake to prove that
// -fno-sanitize-recover=all is active, i.e. that findings fail the build gate.
int main(int argc, char** argv) {
  if (argc != 2) {
    std::fputs("usage: sanitizer_canary <ubsan|asan>\n", stderr);
    return 2;
  }

  if (std::strcmp(argv[1], "ubsan") == 0) {
    volatile int a = INT_MAX;
    volatile int b = a + 1;  // signed overflow
    (void)b;
    return 0;
  }

  if (std::strcmp(argv[1], "asan") == 0) {
    int* volatile p = new int[4];
    volatile int idx = 4;
    p[idx] = 1;  // heap buffer overflow
    delete[] p;
    return 0;
  }

  std::fputs("unknown mode\n", stderr);
  return 2;
}

#include <cstdio>
#include <cstdlib>

#include "nilkey/hardening.hpp"

// Phase 1 stub: the real CLI arrives in Phase 4.
int main() {
  const nilkey::Status hardened = nilkey::HardenProcess();
  if (!hardened.ok()) {
    std::fprintf(stderr, "nilkey: %s\n", hardened.error().message);
    return EXIT_FAILURE;
  }
  std::fputs("nilkey " NILKEY_VERSION ": not implemented yet (phase 1 stub)\n", stderr);
  return EXIT_FAILURE;
}

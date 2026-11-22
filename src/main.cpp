#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <span>

#include "nilkey/cli.hpp"
#include "nilkey/hardening.hpp"

int main(int argc, char** argv) {
  // SPEC.md 7.1: harden before any vault or password data is touched.
  const nilkey::Status hardened = nilkey::HardenProcess();
  if (!hardened.ok()) {
    std::fprintf(stderr, "nilkey: %s\n", hardened.error().message);
    return nilkey::kExitError;
  }
  const std::span<const char* const> args =
      argc > 1 ? std::span<const char* const>(argv + 1, static_cast<std::size_t>(argc - 1))
               : std::span<const char* const>();
  return nilkey::Run(args, nilkey::Io{stdout, stderr, STDOUT_FILENO});
}

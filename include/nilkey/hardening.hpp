#ifndef NILKEY_HARDENING_HPP
#define NILKEY_HARDENING_HPP

#include "nilkey/result.hpp"

namespace nilkey {

// Process startup hardening (SPEC.md 7.1). Must run before any vault or
// password data is read. In order:
//   1. sodium_init()
//   2. prctl(PR_SET_DUMPABLE, 0): no core dumps, no unprivileged ptrace
//   3. setrlimit(RLIMIT_CORE, {0, 0})
//   4. umask(0077)
// Returns kHardeningFailed if any step fails; the caller must then exit.
[[nodiscard]] Status HardenProcess();

}  // namespace nilkey

#endif  // NILKEY_HARDENING_HPP

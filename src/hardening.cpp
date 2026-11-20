#include "nilkey/hardening.hpp"

#include <sodium.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>

namespace nilkey {

Status HardenProcess() {
  // sodium_init() returns 1 if it was already initialised, -1 on failure.
  if (sodium_init() < 0) return make_error(ErrorCode::kHardeningFailed);

  if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) return make_error(ErrorCode::kHardeningFailed);

  const rlimit no_core = {0, 0};
  if (setrlimit(RLIMIT_CORE, &no_core) != 0) return make_error(ErrorCode::kHardeningFailed);

  umask(0077);  // Cannot fail.
  return Ok();
}

}  // namespace nilkey

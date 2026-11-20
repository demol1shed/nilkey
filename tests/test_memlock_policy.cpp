// SPEC.md 10, item 7: the hybrid RLIMIT_MEMLOCK policy.
//
// Not built with sanitizers: ASan and UBSan intercept mlock() and always
// report success, so a lock failure cannot be simulated under them. CI covers
// this test in the release profile.

#include <sys/resource.h>

#include <cstdio>
#include <utility>

#include "nilkey/secure_buffer.hpp"
#include "test_framework.hpp"

using nilkey::ErrorCode;
using nilkey::MemlockPolicy;
using nilkey::SecureBuffer;

// Lowers the soft RLIMIT_MEMLOCK to 0 so sodium_mlock() fails, then restores it.
NILKEY_TEST(lock_failure_is_fail_closed_unless_allowed) {
  rlimit saved{};
  NILKEY_EXPECT(getrlimit(RLIMIT_MEMLOCK, &saved) == 0);
  rlimit zero = saved;
  zero.rlim_cur = 0;
  NILKEY_EXPECT(setrlimit(RLIMIT_MEMLOCK, &zero) == 0);

  auto strict = SecureBuffer::Create(4096, MemlockPolicy::kRequire);
  auto lenient = SecureBuffer::Create(4096, MemlockPolicy::kAllowUnlocked);

  NILKEY_EXPECT(setrlimit(RLIMIT_MEMLOCK, &saved) == 0);

  if (strict.ok()) {
    // CAP_IPC_LOCK (e.g. root) ignores the limit, so this cannot be simulated.
    std::fputs("SKIP: memory locking succeeds despite RLIMIT_MEMLOCK=0\n", stderr);
    return;
  }
  NILKEY_EXPECT(strict.error().code == ErrorCode::kMemoryLockFailed);
  NILKEY_EXPECT(lenient.ok());
}

NILKEY_TEST_MAIN()

#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include "nilkey/hardening.hpp"
#include "test_framework.hpp"

NILKEY_TEST(harden_process_applies_all_settings) {
  NILKEY_EXPECT(nilkey::HardenProcess().ok());

  NILKEY_EXPECT(prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0);

  rlimit core{};
  NILKEY_EXPECT(getrlimit(RLIMIT_CORE, &core) == 0);
  NILKEY_EXPECT(core.rlim_cur == 0);
  NILKEY_EXPECT(core.rlim_max == 0);

  // umask() can only be read by setting it, so set and restore.
  const mode_t current = umask(0);
  umask(current);
  NILKEY_EXPECT(current == 0077);
}

NILKEY_TEST(harden_process_is_idempotent) {
  NILKEY_EXPECT(nilkey::HardenProcess().ok());
  NILKEY_EXPECT(nilkey::HardenProcess().ok());
}

NILKEY_TEST_MAIN()

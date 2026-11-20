#include "test_framework.hpp"

// Deliberately failing: CTest runs this through expect_failure.cmake to prove
// that a failed check really produces a non-zero exit status.
NILKEY_TEST(deliberate_failure) { NILKEY_EXPECT(false); }

NILKEY_TEST_MAIN()

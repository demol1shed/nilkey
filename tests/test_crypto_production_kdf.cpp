// Slow test with the production KDF costs. It links nilkey_core, not
// nilkey_core_test, so none of the test-only KDF macros are defined and the
// real limits of SPEC.md 4.1 apply.

#include <array>
#include <cstddef>
#include <span>

#include "nilkey/crypto.hpp"
#include "nilkey/vault_format.hpp"
#include "test_framework.hpp"

using nilkey::ErrorCode;
using nilkey::KdfParams;
using nilkey::MemlockPolicy;

namespace {

constexpr std::array<std::byte, 7> kPassword = {std::byte{'c'}, std::byte{'o'}, std::byte{0x00},
                                                std::byte{'r'}, std::byte{'k'}, std::byte{0xC3},
                                                std::byte{0xA9}};
constexpr std::array<std::byte, 7> kWrongPassword = {std::byte{'c'}, std::byte{'o'}, std::byte{0x00},
                                                     std::byte{'r'}, std::byte{'k'}, std::byte{0xC3},
                                                     std::byte{0xAA}};
constexpr std::array<std::byte, 5> kPlain = {std::byte{0x00}, std::byte{1}, std::byte{2},
                                             std::byte{0xFF}, std::byte{0x00}};

}  // namespace

NILKEY_TEST(production_kdf_limits) {
  const struct {
    KdfParams params;
    bool ok;
  } cases[] = {
      {{19455, 2}, false},        // below the 19 MiB floor
      {{19456, 2}, true},         // exactly the floor
      {{19456, 1}, false},        // too few iterations
      {{65536, 3}, true},         // the defaults
      {{2097152, 20}, true},      // exactly the ceiling
      {{2097153, 3}, false},      // above 2 GiB
      {{65536, 21}, false},       // too many iterations
  };
  for (const auto& c : cases) {
    auto r = nilkey::ValidateKdfParams(c.params);
    NILKEY_EXPECT(r.ok() == c.ok);
    if (!c.ok) NILKEY_EXPECT(r.error().code == ErrorCode::kKdfParamsRejected);
  }
}

NILKEY_TEST(default_kdf_params_match_spec) {
  NILKEY_EXPECT(nilkey::kDefaultKdfParams.mem_kib == 65536);
  NILKEY_EXPECT(nilkey::kDefaultKdfParams.iterations == 3);
}

// Runs Argon2id with 64 MiB and 3 passes, three times.
NILKEY_TEST(round_trip_with_default_kdf_params) {
  auto key = nilkey::NewVaultKey(kPassword, nilkey::kDefaultKdfParams, MemlockPolicy::kRequire);
  NILKEY_EXPECT(key.ok());
  auto file = nilkey::Seal(key.value(), kPlain);
  NILKEY_EXPECT(file.ok());

  auto header = nilkey::ParseHeader(std::span<const std::byte>(file.value()).first(nilkey::kHeaderSize));
  NILKEY_EXPECT(header.ok());
  NILKEY_EXPECT(header.value().kdf.mem_kib == 65536);
  NILKEY_EXPECT(header.value().kdf.iterations == 3);

  auto opened = nilkey::OpenWithPassword(file.value(), kPassword, MemlockPolicy::kRequire);
  NILKEY_EXPECT(opened.ok());
  auto guard = nilkey::ScopedReadGuard::Open(opened.value().plaintext);
  NILKEY_EXPECT(guard.ok());
  NILKEY_EXPECT_SECRET_EQ(guard.value().bytes(), std::span<const std::byte>(kPlain));

  auto wrong = nilkey::OpenWithPassword(file.value(), kWrongPassword, MemlockPolicy::kRequire);
  NILKEY_EXPECT(!wrong.ok());
  NILKEY_EXPECT(wrong.error().code == ErrorCode::kAuthenticationFailed);
}

NILKEY_TEST_MAIN()

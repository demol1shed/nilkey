// Built against nilkey_core_test: Argon2id runs at 8 KiB and 1 iteration here
// so the ~900 key derivations of the bit-flipping test stay fast. The
// production costs are covered by test_crypto_production_kdf.

#include <sys/resource.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

#include "nilkey/crypto.hpp"
#include "nilkey/vault_format.hpp"
#include "test_framework.hpp"

using nilkey::ErrorCode;
using nilkey::KdfParams;
using nilkey::MemlockPolicy;
using nilkey::NewVaultKey;
using nilkey::Open;
using nilkey::OpenWithPassword;
using nilkey::ParseHeader;
using nilkey::ScopedReadGuard;
using nilkey::SecureBuffer;
using nilkey::Seal;

namespace {

constexpr KdfParams kFast = {8, 1};
constexpr MemlockPolicy kRequire = MemlockPolicy::kRequire;

// UTF-8 text with an embedded NUL: "pa\0ss é" + a 4 byte emoji.
constexpr std::array<std::byte, 13> kPassword = {
    std::byte{'p'},  std::byte{'a'},  std::byte{0x00}, std::byte{'s'},  std::byte{'s'},
    std::byte{' '},  std::byte{0xC3}, std::byte{0xA9}, std::byte{' '},  std::byte{0xF0},
    std::byte{0x9F}, std::byte{0x94}, std::byte{0x91}};
// Same length, last byte differs.
constexpr std::array<std::byte, 13> kWrongPassword = {
    std::byte{'p'},  std::byte{'a'},  std::byte{0x00}, std::byte{'s'},  std::byte{'s'},
    std::byte{' '},  std::byte{0xC3}, std::byte{0xA9}, std::byte{' '},  std::byte{0xF0},
    std::byte{0x9F}, std::byte{0x94}, std::byte{0x92}};
constexpr std::array<std::byte, 9> kPlain = {std::byte{0x00}, std::byte{'a'},  std::byte{0xC3},
                                             std::byte{0xA9}, std::byte{0x00}, std::byte{0xF0},
                                             std::byte{0x9F}, std::byte{0x94}, std::byte{0x91}};

// Helpers cannot use the NILKEY_EXPECT macros (they return from the test).
bool SameBytes(const SecureBuffer& buf, std::span<const std::byte> expected) {
  auto guard = ScopedReadGuard::Open(buf);
  if (!guard.ok()) return false;
  return nilkey::test::secret_equal(guard.value().bytes(), expected);
}

std::byte Bit(std::size_t bit) { return static_cast<std::byte>(1U << (bit % 8)); }

}  // namespace

NILKEY_TEST(seal_open_round_trip) {
  auto key = NewVaultKey(kPassword, kFast, kRequire);
  NILKEY_EXPECT(key.ok());
  std::vector<std::byte> big(65536);
  for (std::size_t i = 0; i < big.size(); ++i) big[i] = static_cast<std::byte>(i * 7U);
  const std::span<const std::byte> inputs[] = {
      kPlain, {}, std::span<const std::byte>(kPlain).first(1), big};
  for (std::span<const std::byte> in : inputs) {
    auto file = Seal(key.value(), in);
    NILKEY_EXPECT(file.ok());
    NILKEY_EXPECT(file.value().size() == nilkey::kHeaderSize + in.size() + nilkey::kTagSize);
    auto opened = OpenWithPassword(file.value(), kPassword, kRequire);
    NILKEY_EXPECT(opened.ok());
    NILKEY_EXPECT(SameBytes(opened.value().plaintext, in));
  }
}

NILKEY_TEST(empty_password_is_not_rejected_by_crypto_layer) {
  // Rejecting weak or empty passwords is a CLI policy (Phase 4).
  auto key = NewVaultKey({}, kFast, kRequire);
  NILKEY_EXPECT(key.ok());
  auto file = Seal(key.value(), kPlain);
  NILKEY_EXPECT(file.ok());
  auto opened = OpenWithPassword(file.value(), {}, kRequire);
  NILKEY_EXPECT(opened.ok());
  NILKEY_EXPECT(SameBytes(opened.value().plaintext, kPlain));
  NILKEY_EXPECT(!OpenWithPassword(file.value(), kPassword, kRequire).ok());
}

NILKEY_TEST(wrong_password_fails_authentication) {
  auto key = NewVaultKey(kPassword, kFast, kRequire);
  NILKEY_EXPECT(key.ok());
  auto file = Seal(key.value(), kPlain);
  NILKEY_EXPECT(file.ok());

  auto same_length = OpenWithPassword(file.value(), kWrongPassword, kRequire);
  NILKEY_EXPECT(!same_length.ok());
  NILKEY_EXPECT(same_length.error().code == ErrorCode::kAuthenticationFailed);
  auto empty = OpenWithPassword(file.value(), {}, kRequire);
  NILKEY_EXPECT(!empty.ok());
  NILKEY_EXPECT(empty.error().code == ErrorCode::kAuthenticationFailed);
}

// SPEC.md 10, item 1: every single-bit change in the 66 byte header must be
// rejected. Flips of kdf_mem_kib that stay within the test limit derive a
// different key; the rest are rejected by ParseHeader.
NILKEY_TEST(every_header_bit_flip_is_rejected) {
  auto key = NewVaultKey(kPassword, kFast, kRequire);
  NILKEY_EXPECT(key.ok());
  auto file = Seal(key.value(), kPlain);
  NILKEY_EXPECT(file.ok());
  for (std::size_t bit = 0; bit < nilkey::kHeaderSize * 8; ++bit) {
    std::vector<std::byte> tampered = file.value();
    tampered[bit / 8] ^= Bit(bit);
    NILKEY_EXPECT(!OpenWithPassword(tampered, kPassword, kRequire).ok());
  }
}

// With the key fixed, a changed salt or KDF cost cannot change the derived
// key, so only the header acting as AEAD additional data can reject it.
NILKEY_TEST(every_header_bit_flip_is_rejected_with_a_fixed_key) {
  auto key = NewVaultKey(kPassword, kFast, kRequire);
  NILKEY_EXPECT(key.ok());
  auto file = Seal(key.value(), kPlain);
  NILKEY_EXPECT(file.ok());
  for (std::size_t bit = 0; bit < nilkey::kHeaderSize * 8; ++bit) {
    std::vector<std::byte> tampered = file.value();
    tampered[bit / 8] ^= Bit(bit);
    NILKEY_EXPECT(!Open(tampered, key.value(), kRequire).ok());
  }
}

// SPEC.md 10, item 1: every bit of the ciphertext and of the 16 byte tag.
NILKEY_TEST(every_ciphertext_and_tag_bit_flip_is_rejected) {
  auto key = NewVaultKey(kPassword, kFast, kRequire);
  NILKEY_EXPECT(key.ok());
  auto file = Seal(key.value(), kPlain);
  NILKEY_EXPECT(file.ok());
  NILKEY_EXPECT(Open(file.value(), key.value(), kRequire).ok());
  for (std::size_t bit = nilkey::kHeaderSize * 8; bit < file.value().size() * 8; ++bit) {
    std::vector<std::byte> tampered = file.value();
    tampered[bit / 8] ^= Bit(bit);
    auto r = Open(tampered, key.value(), kRequire);
    NILKEY_EXPECT(!r.ok());
    NILKEY_EXPECT(r.error().code == ErrorCode::kAuthenticationFailed);
  }
}

NILKEY_TEST(truncated_or_extended_files_are_rejected) {
  auto key = NewVaultKey(kPassword, kFast, kRequire);
  NILKEY_EXPECT(key.ok());
  auto file = Seal(key.value(), kPlain);
  NILKEY_EXPECT(file.ok());
  const std::vector<std::byte>& good = file.value();

  NILKEY_EXPECT(!Open(std::span<const std::byte>(good).first(good.size() - 1), key.value(), kRequire).ok());
  std::vector<std::byte> trailing = good;
  trailing.push_back(std::byte{0});
  NILKEY_EXPECT(!Open(trailing, key.value(), kRequire).ok());
  NILKEY_EXPECT(!OpenWithPassword(trailing, kPassword, kRequire).ok());
  NILKEY_EXPECT(!Open(std::span<const std::byte>(good).first(nilkey::kHeaderSize - 1), key.value(), kRequire).ok());
  NILKEY_EXPECT(!Open({}, key.value(), kRequire).ok());
  auto empty = OpenWithPassword({}, kPassword, kRequire);
  NILKEY_EXPECT(!empty.ok());
  NILKEY_EXPECT(empty.error().code == ErrorCode::kInvalidFormat);
}

// SPEC.md 10, item 3: a new nonce on every save, same salt.
NILKEY_TEST(every_seal_uses_a_new_nonce) {
  auto key = NewVaultKey(kPassword, kFast, kRequire);
  NILKEY_EXPECT(key.ok());
  std::vector<std::array<std::byte, nilkey::kNonceSize>> nonces;
  for (int i = 0; i < 64; ++i) {
    auto file = Seal(key.value(), kPlain);
    NILKEY_EXPECT(file.ok());
    auto header = ParseHeader(std::span<const std::byte>(file.value()).first(nilkey::kHeaderSize));
    NILKEY_EXPECT(header.ok());
    NILKEY_EXPECT(header.value().salt == key.value().salt);
    NILKEY_EXPECT(Open(file.value(), key.value(), kRequire).ok());
    nonces.push_back(header.value().nonce);
  }
  for (std::size_t a = 0; a < nonces.size(); ++a) {
    for (std::size_t b = a + 1; b < nonces.size(); ++b) NILKEY_EXPECT(nonces[a] != nonces[b]);
  }
}

// SPEC.md 10, item 4: passwd renews salt and nonce, and invalidates the old password.
NILKEY_TEST(rekeying_changes_salt_and_nonce_and_old_password) {
  auto old_key = NewVaultKey(kPassword, kFast, kRequire);
  NILKEY_EXPECT(old_key.ok());
  auto old_file = Seal(old_key.value(), kPlain);
  NILKEY_EXPECT(old_file.ok());

  auto opened = OpenWithPassword(old_file.value(), kPassword, kRequire);
  NILKEY_EXPECT(opened.ok());
  auto new_key = NewVaultKey(kWrongPassword, kFast, kRequire);
  NILKEY_EXPECT(new_key.ok());
  auto plain_guard = ScopedReadGuard::Open(opened.value().plaintext);
  NILKEY_EXPECT(plain_guard.ok());
  auto new_file = Seal(new_key.value(), plain_guard.value().bytes());
  NILKEY_EXPECT(new_file.ok());

  auto old_header = ParseHeader(std::span<const std::byte>(old_file.value()).first(nilkey::kHeaderSize));
  auto new_header = ParseHeader(std::span<const std::byte>(new_file.value()).first(nilkey::kHeaderSize));
  NILKEY_EXPECT(old_header.ok());
  NILKEY_EXPECT(new_header.ok());
  NILKEY_EXPECT(old_header.value().salt != new_header.value().salt);
  NILKEY_EXPECT(old_header.value().nonce != new_header.value().nonce);

  auto with_old = OpenWithPassword(new_file.value(), kPassword, kRequire);
  NILKEY_EXPECT(!with_old.ok());
  NILKEY_EXPECT(with_old.error().code == ErrorCode::kAuthenticationFailed);
  auto with_new = OpenWithPassword(new_file.value(), kWrongPassword, kRequire);
  NILKEY_EXPECT(with_new.ok());
  NILKEY_EXPECT(SameBytes(with_new.value().plaintext, kPlain));
}

NILKEY_TEST(new_vault_keys_get_different_salts) {
  auto a = NewVaultKey(kPassword, kFast, kRequire);
  auto b = NewVaultKey(kPassword, kFast, kRequire);
  NILKEY_EXPECT(a.ok());
  NILKEY_EXPECT(b.ok());
  NILKEY_EXPECT(a.value().salt != b.value().salt);
}

NILKEY_TEST(kdf_params_outside_limits_are_rejected) {
  const KdfParams bad[] = {{7, 1}, {8, 0}, {1025, 1}, {8, 21}};
  for (const KdfParams& p : bad) {
    auto key = NewVaultKey(kPassword, p, kRequire);
    NILKEY_EXPECT(!key.ok());
    NILKEY_EXPECT(key.error().code == ErrorCode::kKdfParamsRejected);
  }
}

NILKEY_TEST(plaintext_size_limit_is_enforced) {
  auto key = NewVaultKey(kPassword, kFast, kRequire);
  NILKEY_EXPECT(key.ok());

  std::vector<std::byte> data(nilkey::kMaxPlaintextSize + 1);
  auto too_big = Seal(key.value(), data);
  NILKEY_EXPECT(!too_big.ok());
  NILKEY_EXPECT(too_big.error().code == ErrorCode::kOutOfRange);

  // Exactly 16 MiB works. The plaintext buffer may not fit in RLIMIT_MEMLOCK,
  // so allow unlocked memory here; this test is about size, not locking.
  const std::span<const std::byte> max_size = std::span<const std::byte>(data).first(nilkey::kMaxPlaintextSize);
  auto file = Seal(key.value(), max_size);
  NILKEY_EXPECT(file.ok());
  auto opened = Open(file.value(), key.value(), MemlockPolicy::kAllowUnlocked);
  NILKEY_EXPECT(opened.ok());
  NILKEY_EXPECT(opened.value().size() == nilkey::kMaxPlaintextSize);
}

// getrlimit/setrlimit are not intercepted by the sanitizers, unlike mlock().
// The limit is restored before any check, because a failed check returns early.
NILKEY_TEST(memlock_limit_check_and_warn_and_continue) {
  rlimit saved{};
  NILKEY_EXPECT(getrlimit(RLIMIT_MEMLOCK, &saved) == 0);

  auto set_soft_limit = [&](rlim_t soft) {
    rlimit r = saved;
    r.rlim_cur = soft;
    return setrlimit(RLIMIT_MEMLOCK, &r) == 0;
  };

  const bool set_zero = set_soft_limit(0);
  const bool zero_covers = nilkey::MemlockLimitCoversKdf({8, 1});
  // Derivation still succeeds, with a warning on stderr, when the limit is too low.
  auto key_while_low = NewVaultKey(kPassword, kFast, MemlockPolicy::kAllowUnlocked);
  const bool set_exact = set_soft_limit(1024 * 1024);
  const bool exact_covers = nilkey::MemlockLimitCoversKdf({1024, 1});
  const bool one_over_covers = nilkey::MemlockLimitCoversKdf({1025, 1});
  const bool restored = setrlimit(RLIMIT_MEMLOCK, &saved) == 0;

  NILKEY_EXPECT(restored);
  NILKEY_EXPECT(set_zero);
  NILKEY_EXPECT(set_exact);
  NILKEY_EXPECT(!zero_covers);
  NILKEY_EXPECT(key_while_low.ok());
  NILKEY_EXPECT(exact_covers);
  NILKEY_EXPECT(!one_over_covers);
}

NILKEY_TEST_MAIN()

#include <array>
#include <cstddef>
#include <span>
#include <utility>

#include "nilkey/secure_buffer.hpp"
#include "test_framework.hpp"

using nilkey::CopyToSecureBuffer;
using nilkey::ErrorCode;
using nilkey::MemlockPolicy;
using nilkey::ScopedReadGuard;
using nilkey::ScopedWriteGuard;
using nilkey::SecureBuffer;

namespace {

// UTF-8 text with embedded NUL bytes: must survive unchanged (SPEC.md 4.1).
constexpr std::array<std::byte, 9> kSecret = {
    std::byte{0x00}, std::byte{'a'},  std::byte{0xC3}, std::byte{0xA9}, std::byte{0x00},
    std::byte{0xF0}, std::byte{0x9F}, std::byte{0x94}, std::byte{0x91}};

}  // namespace

NILKEY_TEST(new_buffer_is_zero_filled) {
  auto r = SecureBuffer::Create(64, MemlockPolicy::kRequire);
  NILKEY_EXPECT(r.ok());
  SecureBuffer buf = std::move(r).value();
  NILKEY_EXPECT(buf.size() == 64);
  auto g = ScopedReadGuard::Open(buf);
  NILKEY_EXPECT(g.ok());
  for (std::byte b : g.value().bytes()) NILKEY_EXPECT(b == std::byte{0});
}

NILKEY_TEST(write_then_read_roundtrip_keeps_nul_and_utf8_bytes) {
  auto r = SecureBuffer::Create(kSecret.size(), MemlockPolicy::kRequire);
  NILKEY_EXPECT(r.ok());
  SecureBuffer buf = std::move(r).value();
  {
    auto w = ScopedWriteGuard::Open(buf);
    NILKEY_EXPECT(w.ok());
    std::span<std::byte> out = w.value().bytes();
    NILKEY_EXPECT(out.size() == kSecret.size());
    for (std::size_t i = 0; i < kSecret.size(); ++i) out[i] = kSecret[i];
  }
  auto g = ScopedReadGuard::Open(buf);
  NILKEY_EXPECT(g.ok());
  NILKEY_EXPECT_SECRET_EQ(g.value().bytes(), std::span<const std::byte>(kSecret));
}

NILKEY_TEST(empty_buffer_is_valid) {
  auto r = SecureBuffer::Create(0, MemlockPolicy::kRequire);
  NILKEY_EXPECT(r.ok());
  SecureBuffer buf = std::move(r).value();
  NILKEY_EXPECT(buf.size() == 0);
  auto g = ScopedReadGuard::Open(buf);
  NILKEY_EXPECT(g.ok());
  NILKEY_EXPECT(g.value().bytes().empty());
}

NILKEY_TEST(second_guard_is_rejected_until_first_closes) {
  auto r = SecureBuffer::Create(16, MemlockPolicy::kRequire);
  NILKEY_EXPECT(r.ok());
  SecureBuffer buf = std::move(r).value();
  {
    auto first = ScopedReadGuard::Open(buf);
    NILKEY_EXPECT(first.ok());
    auto second = ScopedWriteGuard::Open(buf);
    NILKEY_EXPECT(!second.ok());
    NILKEY_EXPECT(second.error().code == ErrorCode::kInvalidArgument);
  }
  auto again = ScopedWriteGuard::Open(buf);
  NILKEY_EXPECT(again.ok());
}

NILKEY_TEST(move_construction_transfers_ownership) {
  auto r = SecureBuffer::Create(kSecret.size(), MemlockPolicy::kRequire);
  NILKEY_EXPECT(r.ok());
  SecureBuffer a = std::move(r).value();
  {
    auto w = ScopedWriteGuard::Open(a);
    NILKEY_EXPECT(w.ok());
    for (std::size_t i = 0; i < kSecret.size(); ++i) w.value().bytes()[i] = kSecret[i];
  }
  SecureBuffer b = std::move(a);
  NILKEY_EXPECT(a.size() == 0);  // NOLINT: moved-from state is specified.
  NILKEY_EXPECT(b.size() == kSecret.size());
  auto g = ScopedReadGuard::Open(b);
  NILKEY_EXPECT(g.ok());
  NILKEY_EXPECT_SECRET_EQ(g.value().bytes(), std::span<const std::byte>(kSecret));
}

NILKEY_TEST(move_assignment_releases_old_and_takes_new) {
  auto ra = SecureBuffer::Create(8, MemlockPolicy::kRequire);
  auto rb = SecureBuffer::Create(32, MemlockPolicy::kRequire);
  NILKEY_EXPECT(ra.ok());
  NILKEY_EXPECT(rb.ok());
  SecureBuffer a = std::move(ra).value();
  SecureBuffer b = std::move(rb).value();
  a = std::move(b);
  NILKEY_EXPECT(a.size() == 32);
  NILKEY_EXPECT(b.size() == 0);  // NOLINT: moved-from state is specified.
}

NILKEY_TEST(copy_has_exactly_the_size_and_content_of_the_source) {
  auto r = CopyToSecureBuffer(kSecret, MemlockPolicy::kRequire);
  NILKEY_EXPECT(r.ok());
  NILKEY_EXPECT(r.value().size() == kSecret.size());
  auto g = ScopedReadGuard::Open(r.value());
  NILKEY_EXPECT(g.ok());
  NILKEY_EXPECT_SECRET_EQ(g.value().bytes(), std::span<const std::byte>(kSecret));
}

NILKEY_TEST(copy_of_an_empty_source_is_an_empty_buffer) {
  auto r = CopyToSecureBuffer({}, MemlockPolicy::kRequire);
  NILKEY_EXPECT(r.ok());
  NILKEY_EXPECT(r.value().size() == 0);
}

NILKEY_TEST_MAIN()

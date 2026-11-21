// Built against nilkey_core_test: the KDF limits are 8..1024 KiB and 1..20
// iterations here, instead of the production 19456..2097152 KiB and 2..20.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "nilkey/vault_format.hpp"
#include "test_framework.hpp"

using nilkey::ErrorCode;
using nilkey::ParseHeader;
using nilkey::SerializeHeader;
using nilkey::VaultHeader;

namespace {

constexpr std::size_t kOffVersion = 8;
constexpr std::size_t kOffMem = 10;
constexpr std::size_t kOffIterations = 14;
constexpr std::size_t kOffParallelism = 18;
constexpr std::size_t kOffPayloadLen = 62;

VaultHeader SampleHeader() {
  VaultHeader h{};
  h.kdf = {8, 1};
  for (std::size_t i = 0; i < h.salt.size(); ++i) h.salt[i] = static_cast<std::byte>(0x20 + i);
  for (std::size_t i = 0; i < h.nonce.size(); ++i) h.nonce[i] = static_cast<std::byte>(0x40 + i);
  h.payload_len = 48;
  return h;
}

void Put32(std::array<std::byte, nilkey::kHeaderSize>& raw, std::size_t off, std::uint32_t v) {
  for (std::size_t i = 0; i < 4; ++i) raw[off + i] = static_cast<std::byte>((v >> (8 * i)) & 0xFFU);
}

}  // namespace

NILKEY_TEST(serialize_matches_golden_bytes) {
  // Written out by hand from the SPEC.md 5.1 table, not by the code under test.
  std::array<std::byte, nilkey::kHeaderSize> expected{};
  const unsigned char magic[8] = {'N', 'I', 'L', 'K', 'E', 'Y', '1', 0};
  for (std::size_t i = 0; i < 8; ++i) expected[i] = static_cast<std::byte>(magic[i]);
  expected[8] = std::byte{0x01};   // version 1, LE
  expected[10] = std::byte{0x08};  // mem_kib 8
  expected[14] = std::byte{0x01};  // iterations 1
  expected[18] = std::byte{0x01};  // parallelism 1
  for (std::size_t i = 0; i < 16; ++i) expected[22 + i] = static_cast<std::byte>(0x20 + i);
  for (std::size_t i = 0; i < 24; ++i) expected[38 + i] = static_cast<std::byte>(0x40 + i);
  expected[62] = std::byte{0x30};  // payload_len 48

  const auto actual = SerializeHeader(SampleHeader());
  NILKEY_EXPECT(actual == expected);
}

NILKEY_TEST(header_round_trips) {
  const VaultHeader h = SampleHeader();
  const auto raw = SerializeHeader(h);
  auto parsed = ParseHeader(raw);
  NILKEY_EXPECT(parsed.ok());
  NILKEY_EXPECT(parsed.value().kdf.mem_kib == 8);
  NILKEY_EXPECT(parsed.value().kdf.iterations == 1);
  NILKEY_EXPECT(parsed.value().salt == h.salt);
  NILKEY_EXPECT(parsed.value().nonce == h.nonce);
  NILKEY_EXPECT(parsed.value().payload_len == 48);
}

NILKEY_TEST(parse_rejects_wrong_size) {
  const auto raw = SerializeHeader(SampleHeader());
  auto shorter = ParseHeader(std::span<const std::byte>(raw).first(nilkey::kHeaderSize - 1));
  NILKEY_EXPECT(!shorter.ok());
  NILKEY_EXPECT(shorter.error().code == ErrorCode::kInvalidFormat);
  std::array<std::byte, nilkey::kHeaderSize + 1> longer{};
  auto too_long = ParseHeader(longer);
  NILKEY_EXPECT(!too_long.ok());
}

NILKEY_TEST(parse_rejects_bad_magic) {
  auto raw = SerializeHeader(SampleHeader());
  raw[0] = std::byte{'X'};
  auto r = ParseHeader(raw);
  NILKEY_EXPECT(!r.ok());
  NILKEY_EXPECT(r.error().code == ErrorCode::kInvalidFormat);
}

NILKEY_TEST(parse_rejects_unsupported_version) {
  for (std::byte v : {std::byte{0}, std::byte{2}, std::byte{0xFF}}) {
    auto raw = SerializeHeader(SampleHeader());
    raw[kOffVersion] = v;
    auto r = ParseHeader(raw);
    NILKEY_EXPECT(!r.ok());
    NILKEY_EXPECT(r.error().code == ErrorCode::kUnsupportedVersion);
  }
  auto raw = SerializeHeader(SampleHeader());
  raw[kOffVersion + 1] = std::byte{1};  // 0x0101
  NILKEY_EXPECT(!ParseHeader(raw).ok());
}

NILKEY_TEST(parse_rejects_parallelism_other_than_one) {
  for (std::uint32_t p : {0U, 2U, 4U, 0x01000000U}) {
    auto raw = SerializeHeader(SampleHeader());
    Put32(raw, kOffParallelism, p);
    auto r = ParseHeader(raw);
    NILKEY_EXPECT(!r.ok());
    NILKEY_EXPECT(r.error().code == ErrorCode::kKdfParamsRejected);
  }
}

NILKEY_TEST(parse_enforces_kdf_memory_limits) {
  const struct {
    std::uint32_t mem;
    bool ok;
  } cases[] = {{0, false}, {7, false}, {8, true}, {1024, true}, {1025, false}, {0xFFFFFFFFU, false}};
  for (const auto& c : cases) {
    auto raw = SerializeHeader(SampleHeader());
    Put32(raw, kOffMem, c.mem);
    auto r = ParseHeader(raw);
    NILKEY_EXPECT(r.ok() == c.ok);
    if (!c.ok) NILKEY_EXPECT(r.error().code == ErrorCode::kKdfParamsRejected);
  }
}

NILKEY_TEST(parse_enforces_kdf_iteration_limits) {
  const struct {
    std::uint32_t iterations;
    bool ok;
  } cases[] = {{0, false}, {1, true}, {20, true}, {21, false}, {0xFFFFFFFFU, false}};
  for (const auto& c : cases) {
    auto raw = SerializeHeader(SampleHeader());
    Put32(raw, kOffIterations, c.iterations);
    auto r = ParseHeader(raw);
    NILKEY_EXPECT(r.ok() == c.ok);
    if (!c.ok) NILKEY_EXPECT(r.error().code == ErrorCode::kKdfParamsRejected);
  }
}

NILKEY_TEST(parse_enforces_payload_length_limits) {
  const struct {
    std::uint32_t len;
    bool ok;
  } cases[] = {{0, false},
               {15, false},
               {16, true},
               {nilkey::kMaxPayloadSize, true},
               {nilkey::kMaxPayloadSize + 1, false},
               {0xFFFFFFFFU, false}};
  for (const auto& c : cases) {
    auto raw = SerializeHeader(SampleHeader());
    Put32(raw, kOffPayloadLen, c.len);
    auto r = ParseHeader(raw);
    NILKEY_EXPECT(r.ok() == c.ok);
    if (!c.ok) NILKEY_EXPECT(r.error().code == ErrorCode::kInvalidFormat);
  }
}

NILKEY_TEST(file_size_must_match_exactly) {
  const VaultHeader h = SampleHeader();  // payload_len 48 -> 114 bytes
  NILKEY_EXPECT(nilkey::ValidateFileSize(114, h).ok());
  NILKEY_EXPECT(!nilkey::ValidateFileSize(113, h).ok());  // truncated
  NILKEY_EXPECT(!nilkey::ValidateFileSize(115, h).ok());  // trailing byte
  NILKEY_EXPECT(!nilkey::ValidateFileSize(0, h).ok());
  NILKEY_EXPECT(!nilkey::ValidateFileSize(UINT64_MAX, h).ok());
}

NILKEY_TEST(validate_kdf_params_matches_parser_limits) {
  NILKEY_EXPECT(nilkey::ValidateKdfParams({8, 1}).ok());
  NILKEY_EXPECT(!nilkey::ValidateKdfParams({7, 1}).ok());
  NILKEY_EXPECT(!nilkey::ValidateKdfParams({8, 0}).ok());
  NILKEY_EXPECT(!nilkey::ValidateKdfParams({1025, 1}).ok());
  NILKEY_EXPECT(!nilkey::ValidateKdfParams({8, 21}).ok());
}

NILKEY_TEST_MAIN()

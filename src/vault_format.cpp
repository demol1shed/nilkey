#include "nilkey/vault_format.hpp"

#include <algorithm>

namespace nilkey {

namespace {

constexpr std::array<std::byte, 8> kMagic = {std::byte{'N'}, std::byte{'I'},  std::byte{'L'},
                                             std::byte{'K'}, std::byte{'E'},  std::byte{'Y'},
                                             std::byte{'1'}, std::byte{0x00}};

// Header offsets (SPEC.md 5.1).
constexpr std::size_t kOffVersion = 8;
constexpr std::size_t kOffMem = 10;
constexpr std::size_t kOffIterations = 14;
constexpr std::size_t kOffParallelism = 18;
constexpr std::size_t kOffSalt = 22;
constexpr std::size_t kOffNonce = 38;
constexpr std::size_t kOffPayloadLen = 62;

// Production limits. Only test targets may define the macros below; the
// nilkey binary never does (SPEC.md 4.1, CLAUDE.md 3).
#ifdef NILKEY_ALLOW_TEST_KDF
constexpr std::uint32_t kMinMemKib = 8;
constexpr std::uint32_t kMinIterations = 1;
#else
constexpr std::uint32_t kMinMemKib = 19456;
constexpr std::uint32_t kMinIterations = 2;
#endif

#ifdef NILKEY_TEST_MAX_KDF_MEM_KIB
constexpr std::uint32_t kMaxMemKib = NILKEY_TEST_MAX_KDF_MEM_KIB;
#else
constexpr std::uint32_t kMaxMemKib = 2097152;
#endif
constexpr std::uint32_t kMaxIterations = 20;

std::uint32_t ReadLe32(std::span<const std::byte> bytes, std::size_t off) {
  std::uint32_t v = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    v |= static_cast<std::uint32_t>(bytes[off + i]) << (8 * i);
  }
  return v;
}

std::uint16_t ReadLe16(std::span<const std::byte> bytes, std::size_t off) {
  return static_cast<std::uint16_t>(static_cast<std::uint32_t>(bytes[off]) |
                                    (static_cast<std::uint32_t>(bytes[off + 1]) << 8));
}

void WriteLe32(std::span<std::byte> bytes, std::size_t off, std::uint32_t v) {
  for (std::size_t i = 0; i < 4; ++i) {
    bytes[off + i] = static_cast<std::byte>((v >> (8 * i)) & 0xFFU);
  }
}

void WriteLe16(std::span<std::byte> bytes, std::size_t off, std::uint16_t v) {
  bytes[off] = static_cast<std::byte>(v & 0xFFU);
  bytes[off + 1] = static_cast<std::byte>((v >> 8) & 0xFFU);
}

}  // namespace

Status ValidateKdfParams(const KdfParams& params) {
  if (params.mem_kib < kMinMemKib || params.iterations < kMinIterations) {
    return make_error(ErrorCode::kKdfParamsRejected);
  }
  if (params.mem_kib > kMaxMemKib || params.iterations > kMaxIterations) {
    return make_error(ErrorCode::kKdfParamsRejected);
  }
  return Ok();
}

Result<VaultHeader> ParseHeader(std::span<const std::byte> bytes) {
  if (bytes.size() != kHeaderSize) return make_error(ErrorCode::kInvalidFormat);

  if (!std::equal(kMagic.begin(), kMagic.end(), bytes.begin())) {
    return make_error(ErrorCode::kInvalidFormat);
  }
  if (ReadLe16(bytes, kOffVersion) != kFormatVersion) {
    return make_error(ErrorCode::kUnsupportedVersion);
  }
  if (ReadLe32(bytes, kOffParallelism) != 1) return make_error(ErrorCode::kKdfParamsRejected);

  VaultHeader header{};
  header.kdf.mem_kib = ReadLe32(bytes, kOffMem);
  header.kdf.iterations = ReadLe32(bytes, kOffIterations);
  Status kdf_ok = ValidateKdfParams(header.kdf);
  if (!kdf_ok.ok()) return kdf_ok.error();

  header.payload_len = ReadLe32(bytes, kOffPayloadLen);
  if (header.payload_len < kTagSize || header.payload_len > kMaxPayloadSize) {
    return make_error(ErrorCode::kInvalidFormat);
  }

  std::copy_n(bytes.begin() + kOffSalt, kSaltSize, header.salt.begin());
  std::copy_n(bytes.begin() + kOffNonce, kNonceSize, header.nonce.begin());
  return header;
}

std::array<std::byte, kHeaderSize> SerializeHeader(const VaultHeader& header) {
  std::array<std::byte, kHeaderSize> out{};
  std::copy(kMagic.begin(), kMagic.end(), out.begin());
  WriteLe16(out, kOffVersion, kFormatVersion);
  WriteLe32(out, kOffMem, header.kdf.mem_kib);
  WriteLe32(out, kOffIterations, header.kdf.iterations);
  WriteLe32(out, kOffParallelism, 1);
  std::copy(header.salt.begin(), header.salt.end(), out.begin() + kOffSalt);
  std::copy(header.nonce.begin(), header.nonce.end(), out.begin() + kOffNonce);
  WriteLe32(out, kOffPayloadLen, header.payload_len);
  return out;
}

Status ValidateFileSize(std::uint64_t file_size, const VaultHeader& header) {
  // payload_len <= 16 MiB + 16, so this sum cannot overflow a uint64.
  const std::uint64_t expected = std::uint64_t{kHeaderSize} + header.payload_len;
  if (file_size != expected) return make_error(ErrorCode::kInvalidFormat);
  return Ok();
}

}  // namespace nilkey

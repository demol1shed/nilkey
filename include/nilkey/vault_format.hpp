#ifndef NILKEY_VAULT_FORMAT_HPP
#define NILKEY_VAULT_FORMAT_HPP

// Vault file header, version 1 (SPEC.md 5). All multi-byte integers are
// little-endian. The header holds no secrets: salt, nonce and KDF costs are
// public, so plain std::array is fine here.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "nilkey/result.hpp"

namespace nilkey {

inline constexpr std::size_t kHeaderSize = 66;
inline constexpr std::size_t kSaltSize = 16;
inline constexpr std::size_t kNonceSize = 24;
inline constexpr std::size_t kTagSize = 16;
inline constexpr std::uint16_t kFormatVersion = 1;

// Largest plaintext, and therefore the largest payload minus its tag.
inline constexpr std::uint32_t kMaxPlaintextSize = 16U * 1024U * 1024U;
inline constexpr std::uint32_t kMaxPayloadSize = kMaxPlaintextSize + kTagSize;

// Argon2id costs. Parallelism is not stored: libsodium fixes it to 1 and the
// parser rejects any other value.
struct KdfParams {
  std::uint32_t mem_kib;
  std::uint32_t iterations;
};

inline constexpr KdfParams kDefaultKdfParams = {65536, 3};

struct VaultHeader {
  KdfParams kdf;
  std::array<std::byte, kSaltSize> salt;
  std::array<std::byte, kNonceSize> nonce;
  std::uint32_t payload_len;  // Ciphertext plus the 16 byte tag.
};

// Downgrade and OOM limits (SPEC.md 4.1). Used both when reading a file and
// when creating a new key.
[[nodiscard]] Status ValidateKdfParams(const KdfParams& params);

// Checks magic, version, parallelism, KDF limits and payload_len, all before
// any memory is allocated for the payload. `bytes` must be exactly 66 bytes.
[[nodiscard]] Result<VaultHeader> ParseHeader(std::span<const std::byte> bytes);

// Encodes a header. The caller must have validated it; this cannot fail.
std::array<std::byte, kHeaderSize> SerializeHeader(const VaultHeader& header);

// The file must be exactly 66 + payload_len bytes: no truncation, no trailing
// bytes (SPEC.md 5.2).
[[nodiscard]] Status ValidateFileSize(std::uint64_t file_size, const VaultHeader& header);

}  // namespace nilkey

#endif  // NILKEY_VAULT_FORMAT_HPP

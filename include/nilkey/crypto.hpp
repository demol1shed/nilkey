#ifndef NILKEY_CRYPTO_HPP
#define NILKEY_CRYPTO_HPP

// Argon2id key derivation and XChaCha20-Poly1305 sealing (SPEC.md 4). All
// primitives come from libsodium. Passwords are length-carrying byte spans, so
// UTF-8 and embedded NUL bytes are handled without strlen (CLAUDE.md 2.3).

#include <array>
#include <cstddef>
#include <span>
#include <vector>

#include "nilkey/result.hpp"
#include "nilkey/secure_buffer.hpp"
#include "nilkey/vault_format.hpp"

namespace nilkey {

inline constexpr std::size_t kKeySize = 32;

// The derived 32 byte key plus the KDF costs and salt it was derived with, so
// Seal() can write a header that lets the same password re-derive it.
struct VaultKey {
  SecureBuffer key;
  KdfParams kdf;
  std::array<std::byte, kSaltSize> salt;
};

// Derives a key with a freshly generated salt. Used by init and passwd.
[[nodiscard]] Result<VaultKey> NewVaultKey(std::span<const std::byte> password,
                                           const KdfParams& params, MemlockPolicy policy);

// Derives the key for an existing file, using the salt and costs in its header.
[[nodiscard]] Result<VaultKey> DeriveVaultKey(std::span<const std::byte> password,
                                              const VaultHeader& header, MemlockPolicy policy);

// Encrypts `plaintext` into a complete vault file (header, ciphertext, tag).
// A fresh random nonce is generated on every call, so sealing the same data
// twice never reuses a (key, nonce) pair. The 66 byte header is the AEAD
// additional data. The result is public (encrypted) data, hence a plain vector.
[[nodiscard]] Result<std::vector<std::byte>> Seal(const VaultKey& key,
                                                  std::span<const std::byte> plaintext);

// Authenticates and decrypts a vault file. Any failure after the header checks,
// whether a wrong key or a modified file, is kAuthenticationFailed and yields
// no plaintext.
[[nodiscard]] Result<SecureBuffer> Open(std::span<const std::byte> file, const VaultKey& key,
                                        MemlockPolicy policy);

struct Opened {
  VaultKey key;  // Kept so the caller can Seal() again without re-deriving.
  SecureBuffer plaintext;
};

// Parses the header, derives the key from `password` and decrypts. The file
// size is validated before the expensive key derivation runs.
[[nodiscard]] Result<Opened> OpenWithPassword(std::span<const std::byte> file,
                                              std::span<const std::byte> password,
                                              MemlockPolicy policy);

// True if RLIMIT_MEMLOCK can hold Argon2id's working memory. libsodium locks
// that memory on a best-effort basis and ignores failure (SPEC.md 7.3), so the
// key derivation functions only warn when this is false. Also false if the
// limit cannot be read.
[[nodiscard]] bool MemlockLimitCoversKdf(const KdfParams& params);

}  // namespace nilkey

#endif  // NILKEY_CRYPTO_HPP

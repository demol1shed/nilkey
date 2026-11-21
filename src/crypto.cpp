#include "nilkey/crypto.hpp"

#include <sodium.h>
#include <sys/resource.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <utility>

namespace nilkey {

namespace {

static_assert(kKeySize == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
static_assert(kSaltSize == crypto_pwhash_SALTBYTES);

const unsigned char* AsU8(const std::byte* p) { return reinterpret_cast<const unsigned char*>(p); }

std::uint64_t MemoryBytes(const KdfParams& params) {
  // mem_kib is at most 2 GiB (ValidateKdfParams), so this cannot overflow.
  return std::uint64_t{params.mem_kib} * 1024U;
}

Result<SecureBuffer> DeriveKey(std::span<const std::byte> password, const KdfParams& params,
                               const std::array<std::byte, kSaltSize>& salt,
                               MemlockPolicy policy) {
  Status params_ok = ValidateKdfParams(params);
  if (!params_ok.ok()) return params_ok.error();

  if (!MemlockLimitCoversKdf(params)) {
    std::fputs(
        "warning: RLIMIT_MEMLOCK is below the Argon2id memory cost; key derivation memory may "
        "be written to swap (see `ulimit -l`)\n",
        stderr);
  }

  Result<SecureBuffer> created = SecureBuffer::Create(kKeySize, policy);
  if (!created.ok()) return created.error();
  SecureBuffer key = std::move(created).value();

  {  // The guard must be closed before `key` is moved out.
    Result<ScopedWriteGuard> guard = ScopedWriteGuard::Open(key);
    if (!guard.ok()) return guard.error();
    std::span<std::byte> out = guard.value().bytes();

    // An empty span may carry a null pointer; give libsodium a valid one.
    static const char kNoPassword = 0;
    const char* pw = password.empty() ? &kNoPassword : reinterpret_cast<const char*>(password.data());

    const int rc = crypto_pwhash(reinterpret_cast<unsigned char*>(out.data()), out.size(), pw,
                                 password.size(), AsU8(salt.data()),
                                 static_cast<unsigned long long>(params.iterations),
                                 static_cast<std::size_t>(MemoryBytes(params)),
                                 crypto_pwhash_ALG_ARGON2ID13);
    if (rc != 0) return make_error(ErrorCode::kCryptoFailed);
  }

  sodium_stackzero(4096);
  return key;
}

}  // namespace

bool MemlockLimitCoversKdf(const KdfParams& params) {
  rlimit limit{};
  if (getrlimit(RLIMIT_MEMLOCK, &limit) != 0) return false;
  if (limit.rlim_cur == RLIM_INFINITY) return true;
  return std::uint64_t{limit.rlim_cur} >= MemoryBytes(params);
}

Result<VaultKey> NewVaultKey(std::span<const std::byte> password, const KdfParams& params,
                             MemlockPolicy policy) {
  std::array<std::byte, kSaltSize> salt{};
  randombytes_buf(salt.data(), salt.size());

  Result<SecureBuffer> key = DeriveKey(password, params, salt, policy);
  if (!key.ok()) return key.error();
  return VaultKey{std::move(key).value(), params, salt};
}

Result<VaultKey> DeriveVaultKey(std::span<const std::byte> password, const VaultHeader& header,
                                MemlockPolicy policy) {
  Result<SecureBuffer> key = DeriveKey(password, header.kdf, header.salt, policy);
  if (!key.ok()) return key.error();
  return VaultKey{std::move(key).value(), header.kdf, header.salt};
}

Result<std::vector<std::byte>> Seal(const VaultKey& key, std::span<const std::byte> plaintext) {
  if (plaintext.size() > kMaxPlaintextSize) return make_error(ErrorCode::kOutOfRange);
  if (key.key.size() != kKeySize) return make_error(ErrorCode::kInvalidArgument);

  VaultHeader header{};
  header.kdf = key.kdf;
  header.salt = key.salt;
  randombytes_buf(header.nonce.data(), header.nonce.size());  // New for every save.
  header.payload_len = static_cast<std::uint32_t>(plaintext.size() + kTagSize);

  const std::array<std::byte, kHeaderSize> header_bytes = SerializeHeader(header);
  std::vector<std::byte> file(kHeaderSize + header.payload_len);
  std::copy(header_bytes.begin(), header_bytes.end(), file.begin());

  Result<ScopedReadGuard> key_guard = ScopedReadGuard::Open(key.key);
  if (!key_guard.ok()) return key_guard.error();

  // libsodium may dislike a null message pointer even when the length is 0.
  static const unsigned char kNoBytes = 0;
  const unsigned char* msg = plaintext.empty() ? &kNoBytes : AsU8(plaintext.data());

  unsigned long long ciphertext_len = 0;
  const int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
      reinterpret_cast<unsigned char*>(file.data() + kHeaderSize), &ciphertext_len, msg,
      plaintext.size(), AsU8(header_bytes.data()), header_bytes.size(), nullptr,
      AsU8(header.nonce.data()), AsU8(key_guard.value().bytes().data()));
  if (rc != 0 || ciphertext_len != header.payload_len) return make_error(ErrorCode::kCryptoFailed);
  return file;
}

Result<SecureBuffer> Open(std::span<const std::byte> file, const VaultKey& key,
                          MemlockPolicy policy) {
  if (key.key.size() != kKeySize) return make_error(ErrorCode::kInvalidArgument);
  if (file.size() < kHeaderSize) return make_error(ErrorCode::kInvalidFormat);

  const std::span<const std::byte> header_bytes = file.first(kHeaderSize);
  Result<VaultHeader> header = ParseHeader(header_bytes);
  if (!header.ok()) return header.error();
  Status size_ok = ValidateFileSize(file.size(), header.value());
  if (!size_ok.ok()) return size_ok.error();

  const std::size_t ciphertext_len = header.value().payload_len;
  Result<SecureBuffer> created = SecureBuffer::Create(ciphertext_len - kTagSize, policy);
  if (!created.ok()) return created.error();
  SecureBuffer plaintext = std::move(created).value();

  {  // Both guards must be closed before `plaintext` is moved out.
    Result<ScopedReadGuard> key_guard = ScopedReadGuard::Open(key.key);
    if (!key_guard.ok()) return key_guard.error();
    Result<ScopedWriteGuard> out_guard = ScopedWriteGuard::Open(plaintext);
    if (!out_guard.ok()) return out_guard.error();

    unsigned long long plaintext_len = 0;
    const int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        reinterpret_cast<unsigned char*>(out_guard.value().bytes().data()), &plaintext_len,
        nullptr, AsU8(file.data() + kHeaderSize), ciphertext_len, AsU8(header_bytes.data()),
        header_bytes.size(), AsU8(header.value().nonce.data()),
        AsU8(key_guard.value().bytes().data()));
    if (rc != 0 || plaintext_len != ciphertext_len - kTagSize) {
      return make_error(ErrorCode::kAuthenticationFailed);
    }
  }

  sodium_stackzero(4096);
  return plaintext;
}

Result<Opened> OpenWithPassword(std::span<const std::byte> file,
                                std::span<const std::byte> password, MemlockPolicy policy) {
  if (file.size() < kHeaderSize) return make_error(ErrorCode::kInvalidFormat);
  Result<VaultHeader> header = ParseHeader(file.first(kHeaderSize));
  if (!header.ok()) return header.error();
  Status size_ok = ValidateFileSize(file.size(), header.value());
  if (!size_ok.ok()) return size_ok.error();

  Result<VaultKey> key = DeriveVaultKey(password, header.value(), policy);
  if (!key.ok()) return key.error();
  Result<SecureBuffer> plaintext = Open(file, key.value(), policy);
  if (!plaintext.ok()) return plaintext.error();
  return Opened{std::move(key).value(), std::move(plaintext).value()};
}

}  // namespace nilkey

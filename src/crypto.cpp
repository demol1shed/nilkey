#include "nilkey/crypto.hpp"

#include <sodium.h>
#include <sys/resource.h>

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

}  // namespace nilkey

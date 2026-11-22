#ifndef NILKEY_STORE_HPP
#define NILKEY_STORE_HPP

// Loading and saving a vault on disk, and the lock that makes a
// read-modify-write cycle safe against another nilkey process (SPEC.md 8,
// "Eşzamanlı yazma"). The file layer (atomic_file.hpp) has no lock; this is the
// layer that owns the cycle.
//
// A mutating command takes the lock, loads, changes, saves and releases it.
// Reading needs no lock: a save replaces the file with rename(), so a reader
// always sees one complete version.

#include <cstddef>
#include <span>
#include <string>

#include "nilkey/crypto.hpp"
#include "nilkey/result.hpp"
#include "nilkey/secure_buffer.hpp"
#include "nilkey/vault.hpp"
#include "nilkey/vault_format.hpp"

namespace nilkey {

// An exclusive lock on `<vault>.lock`, held until the object is destroyed. The
// lock file is a separate file because a save replaces the vault's inode, which
// would silently drop a lock on the vault itself. It stays in the directory
// after use; deleting it would reopen the race. Acquire() waits for another
// holder. Does not work on file systems where flock() is only advisory per
// host (some network file systems).
//
// A child created with fork() while the lock is held inherits it and keeps it
// until the child exits or closes it (O_CLOEXEC only covers exec). Nothing may
// fork while holding a VaultLock.
class [[nodiscard]] VaultLock {
 public:
  // The directory of the vault must exist. kSymlinkRejected if the lock file is
  // a symbolic link, kIoError otherwise on failure.
  [[nodiscard]] static Result<VaultLock> Acquire(const std::string& vault_path);

  VaultLock(const VaultLock&) = delete;
  VaultLock& operator=(const VaultLock&) = delete;
  VaultLock(VaultLock&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
  VaultLock& operator=(VaultLock&&) = delete;
  ~VaultLock();

 private:
  explicit VaultLock(int fd) : fd_(fd) {}
  int fd_;
};

// Creates the directories above `vault_path` that do not exist yet, with mode
// 0700. Existing directories are left alone. kIoError if a component exists
// and is not a directory, or cannot be created.
[[nodiscard]] Status EnsureParentDirectory(const std::string& vault_path);

// kVaultNotFound if there is no file (or link) at `vault_path`. The check does
// not follow a symbolic link; reading one fails later with kSymlinkRejected.
[[nodiscard]] Status RequireVaultExists(const std::string& vault_path);

// kVaultExists if anything, even a dangling link, is at `vault_path`.
[[nodiscard]] Status RequireVaultAbsent(const std::string& vault_path);

struct LoadedVault {
  Vault vault;
  VaultKey key;  // Kept so SaveVault() can seal again without re-deriving.
};

// Reads, derives the key from `password` and decrypts the vault at `path`.
// Errors: kVaultNotFound, kSymlinkRejected, kInvalidFormat,
// kKdfParamsRejected, kAuthenticationFailed (wrong password or damaged file;
// the two are not told apart).
[[nodiscard]] Result<LoadedVault> LoadVault(const std::string& path,
                                            std::span<const std::byte> password,
                                            MemlockPolicy policy);

// Seals the vault with a fresh nonce and replaces the file atomically.
[[nodiscard]] Status SaveVault(const std::string& path, const VaultKey& key, const Vault& vault);

// The Argon2id costs for a new vault (init, passwd). The production defaults,
// except in the test targets (NILKEY_ALLOW_TEST_KDF), which use the lowest
// costs so end-to-end tests run in milliseconds. The nilkey binary never
// defines that macro.
KdfParams ParamsForNewVault();

}  // namespace nilkey

#endif  // NILKEY_STORE_HPP

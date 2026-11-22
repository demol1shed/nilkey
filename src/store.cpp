#include "nilkey/store.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <utility>
#include <vector>

#include "nilkey/atomic_file.hpp"

namespace nilkey {

namespace {

// Directory part of `path`; empty if there is none (the current directory).
std::string DirectoryOf(const std::string& path) {
  const std::size_t slash = path.rfind('/');
  if (slash == std::string::npos) return "";
  if (slash == 0) return "/";
  return path.substr(0, slash);
}

}  // namespace

Result<VaultLock> VaultLock::Acquire(const std::string& vault_path) {
  if (vault_path.empty()) return make_error(ErrorCode::kInvalidArgument);
  const std::string lock_path = vault_path + ".lock";

  const int fd = open(lock_path.c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) {
    return make_error(errno == ELOOP ? ErrorCode::kSymlinkRejected : ErrorCode::kIoError);
  }
  while (flock(fd, LOCK_EX) != 0) {
    if (errno == EINTR) continue;
    if (close(fd) != 0) {
      // The lock was never taken, so there is nothing to lose.
    }
    return make_error(ErrorCode::kIoError);
  }
  return VaultLock(fd);
}

VaultLock::~VaultLock() {
  // Closing the descriptor releases the lock. The file holds no data, so a
  // failing close() cannot lose anything.
  if (fd_ >= 0 && close(fd_) != 0) {
    // Nothing more to do.
  }
}

Status EnsureParentDirectory(const std::string& vault_path) {
  const std::string dir = DirectoryOf(vault_path);
  if (dir.empty() || dir == "/") return Ok();  // The current or the root directory.

  // Create every missing prefix: "a", "a/b", "a/b/c".
  for (std::size_t end = 1; end <= dir.size(); ++end) {
    if (end != dir.size() && dir[end] != '/') continue;
    const std::string prefix = dir.substr(0, end);
    if (mkdir(prefix.c_str(), 0700) != 0 && errno != EEXIST) {
      return make_error(ErrorCode::kIoError);
    }
  }
  struct stat st;
  if (stat(dir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
    return make_error(ErrorCode::kIoError);
  }
  return Ok();
}

Status RequireVaultExists(const std::string& vault_path) {
  struct stat st;
  if (lstat(vault_path.c_str(), &st) == 0) return Ok();
  return make_error(errno == ENOENT ? ErrorCode::kVaultNotFound : ErrorCode::kIoError);
}

Status RequireVaultAbsent(const std::string& vault_path) {
  struct stat st;
  if (lstat(vault_path.c_str(), &st) == 0) return make_error(ErrorCode::kVaultExists);
  if (errno == ENOENT) return Ok();
  return make_error(ErrorCode::kIoError);
}

Result<LoadedVault> LoadVault(const std::string& path, std::span<const std::byte> password,
                              MemlockPolicy policy) {
  if (const Status s = RequireVaultExists(path); !s.ok()) return s.error();

  const Result<std::vector<std::byte>> file = ReadVaultFile(path.c_str());
  if (!file.ok()) return file.error();

  Result<Opened> opened = OpenWithPassword(file.value(), password, policy);
  if (!opened.ok()) return opened.error();
  Opened parts = std::move(opened).value();

  Result<Vault> vault = Vault::FromPlaintext(std::move(parts.plaintext), policy);
  if (!vault.ok()) return vault.error();
  return LoadedVault{std::move(vault).value(), std::move(parts.key)};
}

Status SaveVault(const std::string& path, const VaultKey& key, const Vault& vault) {
  // The reader keeps the payload readable, so it is closed before writing.
  const Result<std::vector<std::byte>> sealed = [&]() -> Result<std::vector<std::byte>> {
    const Result<VaultReader> reader = vault.Open();
    if (!reader.ok()) return reader.error();
    return Seal(key, reader.value().payload());
  }();
  if (!sealed.ok()) return sealed.error();
  return WriteFileAtomic(path.c_str(), sealed.value());
}

KdfParams ParamsForNewVault() {
#ifdef NILKEY_ALLOW_TEST_KDF
  return KdfParams{8, 1};
#else
  return kDefaultKdfParams;
#endif
}

}  // namespace nilkey

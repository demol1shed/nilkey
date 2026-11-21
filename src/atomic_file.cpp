#include "nilkey/atomic_file.hpp"
#include "nilkey/fd_io.hpp"
#include "nilkey/vault_format.hpp"

#include <fcntl.h>
#include <sodium.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <string>
#include <vector>

namespace nilkey {

namespace {

// A collision on 64 random bits is not realistic; the retries only guard
// against a stale file left by a crash with the same name.
constexpr int kMaxTempAttempts = 8;
constexpr std::size_t kTempSuffixBytes = 8;

std::string MakeTempPath(const char* path) {
  unsigned char random[kTempSuffixBytes];
  randombytes_buf(random, sizeof random);
  static constexpr char kHex[] = "0123456789abcdef";
  std::string tmp = path;
  tmp += ".tmp.";
  for (const unsigned char b : random) {
    tmp += kHex[b >> 4];
    tmp += kHex[b & 0x0FU];
  }
  return tmp;
}

// Directory part of `path`, used for the final directory fsync.
std::string DirectoryOf(const std::string& path) {
  const std::size_t slash = path.rfind('/');
  if (slash == std::string::npos) return ".";
  if (slash == 0) return "/";
  return path.substr(0, slash);
}

Status FsyncFd(int fd) {
  while (fsync(fd) != 0) {
    if (errno != EINTR) return make_error(ErrorCode::kIoError);
  }
  return Ok();
}

// Error path only: the caller already has an error to report, so a failing
// cleanup call cannot change the outcome. A leftover temp file holds only
// ciphertext.
void DiscardTemp(int fd, const std::string& tmp) {
  if (fd >= 0 && close(fd) != 0) {
    // Nothing more to do.
  }
  if (unlink(tmp.c_str()) != 0) {
    // Nothing more to do.
  }
}

Status SyncDirectory(const std::string& dir) {
  const int dir_fd = open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dir_fd < 0) return make_error(ErrorCode::kIoError);
  const Status synced = FsyncFd(dir_fd);
  // The descriptor is released either way; Linux must not retry close().
  if (close(dir_fd) != 0) return make_error(ErrorCode::kIoError);
  return synced;
}

}  // namespace

Status WriteFileAtomic(const char* path, std::span<const std::byte> data) {
  if (path == nullptr || path[0] == '\0') return make_error(ErrorCode::kInvalidArgument);

  struct stat st;
  if (lstat(path, &st) == 0) {
    if (S_ISLNK(st.st_mode)) return make_error(ErrorCode::kSymlinkRejected);
  } else if (errno != ENOENT) {
    return make_error(ErrorCode::kIoError);  // A new vault (ENOENT) is fine.
  }

  std::string tmp;
  int fd = -1;
  for (int attempt = 0; attempt < kMaxTempAttempts && fd < 0; ++attempt) {
    tmp = MakeTempPath(path);
    fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0 && errno != EEXIST) return make_error(ErrorCode::kIoError);
  }
  if (fd < 0) return make_error(ErrorCode::kIoError);

  if (const Status written = WriteAll(fd, data); !written.ok()) {
    DiscardTemp(fd, tmp);
    return written;
  }
  if (const Status synced = FsyncFd(fd); !synced.ok()) {
    DiscardTemp(fd, tmp);
    return synced;
  }
  if (close(fd) != 0) {
    DiscardTemp(-1, tmp);  // The descriptor is already released.
    return make_error(ErrorCode::kIoError);
  }
  if (rename(tmp.c_str(), path) != 0) {
    DiscardTemp(-1, tmp);
    return make_error(ErrorCode::kIoError);
  }

  // From here on the new file is in place; see the header for the failure case.
  return SyncDirectory(DirectoryOf(path));
}

Result<std::vector<std::byte>> ReadVaultFile(const char* path) {
  if (path == nullptr || path[0] == '\0') return make_error(ErrorCode::kInvalidArgument);

  // O_NONBLOCK: opening a FIFO must not hang; it is then rejected by fstat.
  const int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0) {
    return make_error(errno == ELOOP ? ErrorCode::kSymlinkRejected : ErrorCode::kIoError);
  }

  // Everything after open() goes through this lambda so close() runs once.
  const auto read_all = [fd]() -> Result<std::vector<std::byte>> {
    struct stat st;
    if (fstat(fd, &st) != 0) return make_error(ErrorCode::kIoError);
    if (!S_ISREG(st.st_mode)) return make_error(ErrorCode::kInvalidFormat);
    // st_size is non-negative for a regular file.
    const auto size = static_cast<std::uint64_t>(st.st_size);
    if (size > kHeaderSize + kMaxPayloadSize) return make_error(ErrorCode::kInvalidFormat);

    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    std::size_t got = 0;
    while (got < bytes.size()) {
      const ssize_t n = read(fd, bytes.data() + got, bytes.size() - got);
      if (n < 0) {
        if (errno == EINTR) continue;
        return make_error(ErrorCode::kIoError);
      }
      if (n == 0) return make_error(ErrorCode::kInvalidFormat);  // Shrank while reading.
      got += static_cast<std::size_t>(n);
    }

    // The file must end here; a byte more means it grew while being read.
    std::byte extra;
    for (;;) {
      const ssize_t n = read(fd, &extra, 1);
      if (n < 0 && errno == EINTR) continue;
      if (n < 0) return make_error(ErrorCode::kIoError);
      if (n > 0) return make_error(ErrorCode::kInvalidFormat);
      break;
    }
    return bytes;
  };

  Result<std::vector<std::byte>> result = read_all();
  // A failed close() of a read-only descriptor loses no data, but is still reported.
  if (close(fd) != 0 && result.ok()) return make_error(ErrorCode::kIoError);
  return result;
}

}  // namespace nilkey

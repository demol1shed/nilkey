#include "nilkey/fd_io.hpp"

#include <unistd.h>

#include <cerrno>
#include <span>

namespace nilkey {

Status WriteAll(int fd, std::span<const std::byte> data) {
  const std::byte* p = data.data();
  std::size_t left = data.size();
  while (left > 0) {
    const ssize_t n = write(fd, p, left);
    if (n < 0) {
      if (errno == EINTR) continue;
      return make_error(ErrorCode::kIoError);
    }
    if (n == 0) return make_error(ErrorCode::kIoError);  // No progress: avoid spinning.
    p += n;
    left -= static_cast<std::size_t>(n);
  }
  return Ok();
}

Result<SecureBuffer> ReadAllSecret(int fd, std::size_t max_size, MemlockPolicy policy) {
  // One byte more than allowed, so that "too long" can be told from "exactly full".
  Result<SecureBuffer> buffer = SecureBuffer::Create(max_size + 1, policy);
  if (!buffer.ok()) return buffer;
  Result<ScopedWriteGuard> guard = ScopedWriteGuard::Open(buffer.value());
  if (!guard.ok()) return guard.error();
  const std::span<std::byte> space = guard.value().bytes();

  std::size_t length = 0;
  for (;;) {
    if (length == space.size()) return make_error(ErrorCode::kInputTooLong);
    const ssize_t n = read(fd, space.data() + length, space.size() - length);
    if (n < 0) {
      if (errno == EINTR) continue;
      return make_error(ErrorCode::kIoError);
    }
    if (n == 0) break;
    length += static_cast<std::size_t>(n);
  }
  // The copy is a different buffer, so returning it while `guard` is still open
  // moves nothing that has a guard on it.
  return CopyToSecureBuffer(space.first(length), policy);
}

}  // namespace nilkey

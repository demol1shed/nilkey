#include "nilkey/fd_io.hpp"

#include <unistd.h>

#include <cerrno>

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

}  // namespace nilkey

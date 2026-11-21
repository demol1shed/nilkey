#ifndef NILKEY_FD_IO_HPP
#define NILKEY_FD_IO_HPP

#include <cstddef>
#include <span>

#include "nilkey/result.hpp"

namespace nilkey {

// Writes all of `data` to `fd`, continuing after partial writes and EINTR.
// kIoError if write() fails or makes no progress.
[[nodiscard]] Status WriteAll(int fd, std::span<const std::byte> data);

}  // namespace nilkey

#endif  // NILKEY_FD_IO_HPP

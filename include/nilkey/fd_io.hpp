#ifndef NILKEY_FD_IO_HPP
#define NILKEY_FD_IO_HPP

#include <cstddef>
#include <span>

#include "nilkey/result.hpp"
#include "nilkey/secure_buffer.hpp"

namespace nilkey {

// Writes all of `data` to `fd`, continuing after partial writes and EINTR.
// kIoError if write() fails or makes no progress.
[[nodiscard]] Status WriteAll(int fd, std::span<const std::byte> data);

// Reads `fd` to its end into a SecureBuffer of exactly the bytes that came
// (no terminator, embedded NUL bytes kept), for input that may be secret, such
// as notes from stdin. At most `max_size` bytes are accepted; one more is
// kInputTooLong, and memory for more than max_size + 1 bytes is never
// allocated. kIoError if read() fails.
[[nodiscard]] Result<SecureBuffer> ReadAllSecret(int fd, std::size_t max_size,
                                                 MemlockPolicy policy);

}  // namespace nilkey

#endif  // NILKEY_FD_IO_HPP

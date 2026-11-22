#ifndef NILKEY_PASSGEN_HPP
#define NILKEY_PASSGEN_HPP

// Random password generator (SPEC.md 9.2). Characters are picked with
// libsodium's randombytes_uniform(), which is free of modulo bias; nothing
// else is used as a source of randomness. The password is written straight
// into a SecureBuffer.
//
// The alphabet (88 characters when every class is on):
//   lower   a-z
//   upper   A-Z
//   digits  0-9
//   symbols !@#$%^&*()-_=+[]{};:,.<>/?
// Quotes, backslash, backtick, '|', '~' and space are left out on purpose so a
// password can be pasted into a shell or a web form without escaping.
//
// sodium_init() must have been called first.

#include <cstddef>

#include "nilkey/result.hpp"
#include "nilkey/secure_buffer.hpp"

namespace nilkey {

inline constexpr std::size_t kDefaultPasswordLength = 20;
inline constexpr std::size_t kMinPasswordLength = 8;
inline constexpr std::size_t kMaxPasswordLength = 1024;

struct PasswordSpec {
  std::size_t length = kDefaultPasswordLength;
  bool lower = true;
  bool upper = true;
  bool digits = true;
  bool symbols = true;
};

// A password of exactly `spec.length` characters from the enabled classes,
// with at least one character of every enabled class and no NUL byte.
//
// The class guarantee is met by drawing the whole password again until it
// holds, not by forcing characters into chosen positions, so the passwords
// that remain are uniformly distributed among all that satisfy it.
//
// kInvalidArgument if the length is outside [kMinPasswordLength,
// kMaxPasswordLength] or no class is enabled.
[[nodiscard]] Result<SecureBuffer> GeneratePassword(const PasswordSpec& spec,
                                                    MemlockPolicy policy);

}  // namespace nilkey

#endif  // NILKEY_PASSGEN_HPP

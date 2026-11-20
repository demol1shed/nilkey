#ifndef NILKEY_ERROR_HPP
#define NILKEY_ERROR_HPP

#include <cstdint>

namespace nilkey {

// Structural error categories only. Later phases add codes as they need them.
enum class ErrorCode : std::uint8_t {
  kInvalidArgument,
  kOutOfRange,
  kInternal,
};

// Carries a code and a static description. It never holds passwords, keys or
// any other runtime data, so an Error is always safe to print.
struct Error {
  ErrorCode code;
  const char* message;
};

constexpr const char* describe(ErrorCode code) {
  switch (code) {
    case ErrorCode::kInvalidArgument:
      return "invalid argument";
    case ErrorCode::kOutOfRange:
      return "value out of range";
    case ErrorCode::kInternal:
      return "internal error";
  }
  return "unknown error";
}

constexpr Error make_error(ErrorCode code) { return Error{code, describe(code)}; }

}  // namespace nilkey

#endif  // NILKEY_ERROR_HPP

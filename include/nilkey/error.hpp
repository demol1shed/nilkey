#ifndef NILKEY_ERROR_HPP
#define NILKEY_ERROR_HPP

#include <cstdint>

namespace nilkey {

// Structural error categories only. Later phases add codes as they need them.
enum class ErrorCode : std::uint8_t {
  kInvalidArgument,
  kOutOfRange,
  kInternal,
  kAllocationFailed,
  kMemoryLockFailed,
  kMemoryProtectFailed,
  kHardeningFailed,
  kInvalidFormat,
  kUnsupportedVersion,
  kKdfParamsRejected,
  kAuthenticationFailed,
  kCryptoFailed,
  kIoError,
  kSymlinkRejected,
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
    case ErrorCode::kAllocationFailed:
      return "secure memory allocation failed";
    case ErrorCode::kMemoryLockFailed:
      return "cannot lock memory (RLIMIT_MEMLOCK too low); run `nilkey doctor` and check `ulimit -l`";
    case ErrorCode::kMemoryProtectFailed:
      return "cannot change secure memory protection";
    case ErrorCode::kHardeningFailed:
      return "process hardening failed";
    case ErrorCode::kInvalidFormat:
      return "invalid vault file format";
    case ErrorCode::kUnsupportedVersion:
      return "unsupported vault file version";
    case ErrorCode::kKdfParamsRejected:
      return "key derivation parameters are outside the allowed range";
    // One code for a wrong password and for a tampered file: telling them
    // apart would leak information (SPEC.md 1, zero knowledge).
    case ErrorCode::kAuthenticationFailed:
      return "wrong password or corrupted vault file";
    case ErrorCode::kCryptoFailed:
      return "cryptographic operation failed";
    case ErrorCode::kIoError:
      return "file operation failed";
    case ErrorCode::kSymlinkRejected:
      return "vault path is a symbolic link";
  }
  return "unknown error";
}

constexpr Error make_error(ErrorCode code) { return Error{code, describe(code)}; }

}  // namespace nilkey

#endif  // NILKEY_ERROR_HPP

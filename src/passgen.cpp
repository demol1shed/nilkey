#include "nilkey/passgen.hpp"

#include <sodium.h>

#include <array>
#include <cstdint>
#include <string_view>

namespace nilkey {

namespace {

constexpr std::string_view kLower = "abcdefghijklmnopqrstuvwxyz";
constexpr std::string_view kUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
constexpr std::string_view kDigits = "0123456789";
constexpr std::string_view kSymbols = "!@#$%^&*()-_=+[]{};:,.<>/?";

constexpr std::size_t kMaxAlphabetSize = kLower.size() + kUpper.size() + kDigits.size() +
                                         kSymbols.size();

// With the shortest length (8) and every class on, about half the draws pass,
// so this limit is never reached in practice; it only rules out an endless loop.
constexpr int kMaxAttempts = 10000;

bool Contains(std::string_view set, std::byte value) {
  return set.find(static_cast<char>(value)) != std::string_view::npos;
}

// True if `password` has a character of every class enabled in `spec`.
bool HasEveryClass(std::span<const std::byte> password, const PasswordSpec& spec) {
  bool lower = !spec.lower;
  bool upper = !spec.upper;
  bool digits = !spec.digits;
  bool symbols = !spec.symbols;
  for (const std::byte c : password) {
    lower = lower || Contains(kLower, c);
    upper = upper || Contains(kUpper, c);
    digits = digits || Contains(kDigits, c);
    symbols = symbols || Contains(kSymbols, c);
  }
  return lower && upper && digits && symbols;
}

Result<SecureBuffer> GenerateUncleaned(const PasswordSpec& spec, MemlockPolicy policy) {
  if (spec.length < kMinPasswordLength || spec.length > kMaxPasswordLength) {
    return make_error(ErrorCode::kInvalidArgument);
  }
  if (!spec.lower && !spec.upper && !spec.digits && !spec.symbols) {
    return make_error(ErrorCode::kInvalidArgument);
  }

  // The alphabet is public, so a plain array is fine.
  std::array<char, kMaxAlphabetSize> alphabet;
  std::size_t alphabet_size = 0;
  const auto add = [&](bool enabled, std::string_view set) {
    if (!enabled) return;
    for (const char c : set) alphabet[alphabet_size++] = c;
  };
  add(spec.lower, kLower);
  add(spec.upper, kUpper);
  add(spec.digits, kDigits);
  add(spec.symbols, kSymbols);

  Result<SecureBuffer> made = SecureBuffer::Create(spec.length, policy);
  if (!made.ok()) return made;

  bool accepted = false;
  {
    // The guard must be closed before the buffer is moved out.
    Result<ScopedWriteGuard> guard = ScopedWriteGuard::Open(made.value());
    if (!guard.ok()) return guard.error();
    const std::span<std::byte> password = guard.value().bytes();

    for (int attempt = 0; attempt < kMaxAttempts && !accepted; ++attempt) {
      for (std::byte& c : password) {
        const std::uint32_t pick = randombytes_uniform(static_cast<std::uint32_t>(alphabet_size));
        c = static_cast<std::byte>(alphabet[pick]);
      }
      accepted = HasEveryClass(password, spec);
    }
  }
  if (!accepted) return make_error(ErrorCode::kInternal);
  return made;
}

}  // namespace

Result<SecureBuffer> GeneratePassword(const PasswordSpec& spec, MemlockPolicy policy) {
  Result<SecureBuffer> password = GenerateUncleaned(spec, policy);
  // Clears what the calls above left on the stack, on every path (SPEC.md 7.4).
  sodium_stackzero(4096);
  return password;
}

}  // namespace nilkey

// Random password generator (SPEC.md 9.2). The alphabet is written out again
// here on purpose, independent of the code under test. Generated passwords
// are random test data, not secrets, so they may be copied into a std::string
// for inspection; nothing is ever printed.

#include <array>
#include <cmath>
#include <cstddef>
#include <string>
#include <string_view>

#include "nilkey/passgen.hpp"
#include "test_framework.hpp"

using nilkey::ErrorCode;
using nilkey::GeneratePassword;
using nilkey::MemlockPolicy;
using nilkey::PasswordSpec;
using nilkey::ScopedReadGuard;
using nilkey::SecureBuffer;

namespace {

constexpr MemlockPolicy kRequire = MemlockPolicy::kRequire;

constexpr std::string_view kLower = "abcdefghijklmnopqrstuvwxyz";
constexpr std::string_view kUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
constexpr std::string_view kDigits = "0123456789";
constexpr std::string_view kSymbols = "!@#$%^&*()-_=+[]{};:,.<>/?";

std::string Text(const SecureBuffer& buffer) {
  const auto guard = ScopedReadGuard::Open(buffer);
  if (!guard.ok()) return "<unreadable>";
  const auto bytes = guard.value().bytes();
  return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

bool HasAnyOf(const std::string& text, std::string_view set) {
  return text.find_first_of(set) != std::string::npos;
}

bool OnlyFrom(const std::string& text, const PasswordSpec& spec) {
  for (const char c : text) {
    const bool allowed = (spec.lower && kLower.find(c) != std::string_view::npos) ||
                         (spec.upper && kUpper.find(c) != std::string_view::npos) ||
                         (spec.digits && kDigits.find(c) != std::string_view::npos) ||
                         (spec.symbols && kSymbols.find(c) != std::string_view::npos);
    if (!allowed) return false;
  }
  return true;
}

PasswordSpec SpecFromMask(unsigned mask, std::size_t length) {
  PasswordSpec spec;
  spec.length = length;
  spec.lower = (mask & 1U) != 0;
  spec.upper = (mask & 2U) != 0;
  spec.digits = (mask & 4U) != 0;
  spec.symbols = (mask & 8U) != 0;
  return spec;
}

// How often each byte value occurs in 160 default-spec passwords of length
// 1024, computed once. At this length the class guarantee practically never
// rejects a draw, so the counts follow the plain uniform distribution. (At
// short lengths the guarantee raises the frequency of every class on purpose,
// so a bias test there would fail a correct generator.)
const std::array<long, 256>& SampleCounts() {
  static const std::array<long, 256> counts = [] {
    std::array<long, 256> c{};
    for (int i = 0; i < 160; ++i) {
      PasswordSpec spec;
      spec.length = 1024;
      const auto password = GeneratePassword(spec, kRequire);
      if (!password.ok()) return c;
      for (const char ch : Text(password.value())) ++c[static_cast<unsigned char>(ch)];
    }
    return c;
  }();
  return counts;
}

}  // namespace

NILKEY_TEST(produces_the_requested_length) {
  for (const std::size_t length : {std::size_t{8}, std::size_t{20}, std::size_t{1024}}) {
    PasswordSpec spec;
    spec.length = length;
    const auto password = GeneratePassword(spec, kRequire);
    NILKEY_EXPECT(password.ok());
    NILKEY_EXPECT(password.value().size() == length);
  }
}

NILKEY_TEST(default_spec_is_twenty_characters_from_every_class) {
  const auto password = GeneratePassword(PasswordSpec{}, kRequire);
  NILKEY_EXPECT(password.ok());
  NILKEY_EXPECT(password.value().size() == 20);
}

NILKEY_TEST(rejects_a_length_outside_the_limits) {
  PasswordSpec spec;
  spec.length = 7;
  const auto short_one = GeneratePassword(spec, kRequire);
  NILKEY_EXPECT(!short_one.ok());
  NILKEY_EXPECT(short_one.error().code == ErrorCode::kInvalidArgument);

  spec.length = 1025;
  const auto long_one = GeneratePassword(spec, kRequire);
  NILKEY_EXPECT(!long_one.ok());
  NILKEY_EXPECT(long_one.error().code == ErrorCode::kInvalidArgument);

  spec.length = 0;
  NILKEY_EXPECT(!GeneratePassword(spec, kRequire).ok());
}

NILKEY_TEST(rejects_a_spec_without_any_class) {
  const auto password = GeneratePassword(SpecFromMask(0, 20), kRequire);
  NILKEY_EXPECT(!password.ok());
  NILKEY_EXPECT(password.error().code == ErrorCode::kInvalidArgument);
}

NILKEY_TEST(uses_only_enabled_classes_and_every_one_of_them) {
  for (unsigned mask = 1; mask <= 15; ++mask) {
    const PasswordSpec spec = SpecFromMask(mask, 20);
    for (int i = 0; i < 50; ++i) {
      const auto password = GeneratePassword(spec, kRequire);
      NILKEY_EXPECT(password.ok());
      const std::string text = Text(password.value());
      NILKEY_EXPECT(OnlyFrom(text, spec));
      NILKEY_EXPECT(!spec.lower || HasAnyOf(text, kLower));
      NILKEY_EXPECT(!spec.upper || HasAnyOf(text, kUpper));
      NILKEY_EXPECT(!spec.digits || HasAnyOf(text, kDigits));
      NILKEY_EXPECT(!spec.symbols || HasAnyOf(text, kSymbols));
    }
  }
}

// Length 8 with four classes is the hardest case for the class guarantee:
// without it, about half of all draws would miss a class.
NILKEY_TEST(shortest_password_still_has_every_class) {
  for (int i = 0; i < 500; ++i) {
    const auto password = GeneratePassword(SpecFromMask(15, 8), kRequire);
    NILKEY_EXPECT(password.ok());
    const std::string text = Text(password.value());
    NILKEY_EXPECT(text.size() == 8);
    NILKEY_EXPECT(HasAnyOf(text, kLower));
    NILKEY_EXPECT(HasAnyOf(text, kUpper));
    NILKEY_EXPECT(HasAnyOf(text, kDigits));
    NILKEY_EXPECT(HasAnyOf(text, kSymbols));
  }
}

NILKEY_TEST(no_nul_byte_and_passwords_differ) {
  const auto first = GeneratePassword(PasswordSpec{}, kRequire);
  const auto second = GeneratePassword(PasswordSpec{}, kRequire);
  NILKEY_EXPECT(first.ok() && second.ok());
  const std::string a = Text(first.value());
  const std::string b = Text(second.value());
  NILKEY_EXPECT(a.find('\0') == std::string::npos);
  NILKEY_EXPECT(a != b);
}

// 163 840 characters over 88 symbols: 1861.8 expected each, standard deviation
// sqrt(N * p * (1 - p)) = 42.9. A bound of 260 is about 6 sigma, so a correct
// generator essentially never fails (about 2e-7 over 88 bins). A single random
// byte taken modulo 88 gives eight symbols about 31% fewer hits (13.6 sigma
// low) and fails this test every time.
NILKEY_TEST(characters_are_uniformly_distributed) {
  const auto& counts = SampleCounts();
  const std::string alphabet = std::string(kLower) + std::string(kUpper) + std::string(kDigits) +
                               std::string(kSymbols);
  NILKEY_EXPECT(alphabet.size() == 88);
  const double expected = 160.0 * 1024.0 / 88.0;
  for (const char c : alphabet) {
    const double deviation = static_cast<double>(counts[static_cast<unsigned char>(c)]) - expected;
    NILKEY_EXPECT(std::fabs(deviation) <= 260.0);
  }
}

NILKEY_TEST(quotes_backslash_and_space_never_appear) {
  const auto& counts = SampleCounts();
  for (const char c : std::string_view("\"'`\\|~ ")) {
    NILKEY_EXPECT(counts[static_cast<unsigned char>(c)] == 0);
  }
  long total = 0;
  for (const long n : counts) total += n;
  NILKEY_EXPECT(total == 160L * 1024L);
}

NILKEY_TEST_MAIN()

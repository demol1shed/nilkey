#include "nilkey/commands.hpp"

#include <unistd.h>

#include <charconv>
#include <cstddef>
#include <optional>
#include <span>
#include <string_view>
#include <system_error>

#include "nilkey/fd_io.hpp"
#include "nilkey/passgen.hpp"

namespace nilkey {

namespace {

// Writes the password to `fd` and, if `fd` is a terminal, a line break after
// it. Into a pipe or file the bytes go out exactly as they are, so that
// `nilkey generate | xclip` does not put a newline on the clipboard.
Status WriteSecretLine(int fd, const SecureBuffer& secret) {
  const Result<ScopedReadGuard> guard = ScopedReadGuard::Open(secret);
  if (!guard.ok()) return guard.error();
  if (const Status s = WriteAll(fd, guard.value().bytes()); !s.ok()) return s;
  if (isatty(fd) == 1) {
    const std::byte newline{'\n'};
    return WriteAll(fd, std::span<const std::byte>(&newline, 1));
  }
  return Ok();
}

Result<PasswordSpec> ParseGenerateSpec(const ParsedArgs& request) {
  PasswordSpec spec;
  if (const std::optional<std::string_view> text = request.Value("length"); text.has_value()) {
    const char* const first = text->data();
    const char* const last = first + text->size();
    std::size_t length = 0;
    const std::from_chars_result parsed = std::from_chars(first, last, length);
    if (parsed.ec != std::errc() || parsed.ptr != last || length < kMinPasswordLength ||
        length > kMaxPasswordLength) {
      return Error{ErrorCode::kUsage, "--length must be a number from 8 to 1024"};
    }
    spec.length = length;
  }
  spec.lower = !request.Has("no-lower");
  spec.upper = !request.Has("no-upper");
  spec.digits = !request.Has("no-digits");
  spec.symbols = !request.Has("no-symbols");
  if (!spec.lower && !spec.upper && !spec.digits && !spec.symbols) {
    return Error{ErrorCode::kUsage, "at least one character class must stay enabled"};
  }
  return spec;
}

}  // namespace

int ReportError(const Error& error, std::FILE* err) {
  std::fprintf(err, "nilkey: %s\n", error.message);
  if (error.code == ErrorCode::kUsage) {
    std::fputs("Try 'nilkey --help'.\n", err);
    return kExitUsage;
  }
  return kExitError;
}

MemlockPolicy PolicyFor(const GlobalOptions& globals) {
  return globals.allow_unlocked_memory ? MemlockPolicy::kAllowUnlocked : MemlockPolicy::kRequire;
}

int RunGenerate(const ParsedArgs& request, const Io& io) {
  const Result<PasswordSpec> spec = ParseGenerateSpec(request);
  if (!spec.ok()) return ReportError(spec.error(), io.err);

  const Result<SecureBuffer> password =
      GeneratePassword(spec.value(), PolicyFor(request.globals));
  if (!password.ok()) return ReportError(password.error(), io.err);

  const Status written = WriteSecretLine(io.out_fd, password.value());
  if (!written.ok()) return ReportError(written.error(), io.err);
  return kExitOk;
}

}  // namespace nilkey

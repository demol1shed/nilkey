#include "nilkey/commands.hpp"

#include <unistd.h>

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include "nilkey/display.hpp"
#include "nilkey/fd_io.hpp"
#include "nilkey/passgen.hpp"
#include "nilkey/store.hpp"
#include "nilkey/terminal.hpp"
#include "nilkey/tlv.hpp"
#include "nilkey/vault.hpp"

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


// The longest notes accepted from stdin. The buffer is fixed in size, so the
// limit is applied before anything is allocated.
constexpr std::size_t kMaxNotesSize = 64 * 1024;

std::span<const std::byte> AsBytes(std::string_view text) {
  return {reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

Result<std::string> VaultPathFor(const ParsedArgs& request) {
  return ResolveVaultPath(request.globals.vault, std::getenv("NILKEY_PATH"),
                          std::getenv("HOME"));
}

// The time stamped on a changed record. Vault does not read the clock itself.
Result<std::int64_t> Now() {
  const std::time_t now = std::time(nullptr);
  if (now == static_cast<std::time_t>(-1)) return make_error(ErrorCode::kInternal);
  return static_cast<std::int64_t>(now);
}

// A bad name or option text is a mistake in the command line, so it is a usage
// error; left to the vault it would surface as "invalid vault file format".
Status ValidateRecordArguments(const ParsedArgs& request) {
  const std::string_view name = request.positionals[0];
  if (name.empty() || name.size() > kMaxNameSize || !IsValidUtf8(AsBytes(name))) {
    return Error{ErrorCode::kUsage, "the name must be 1 to 1024 bytes of valid UTF-8"};
  }
  if (const auto text = request.Value("username"); text && !IsValidUtf8(AsBytes(*text))) {
    return Error{ErrorCode::kUsage, "--username must be valid UTF-8"};
  }
  if (const auto text = request.Value("url"); text && !IsValidUtf8(AsBytes(*text))) {
    return Error{ErrorCode::kUsage, "--url must be valid UTF-8"};
  }
  return Ok();
}

// Notes from stdin, into a SecureBuffer (never a std::string).
Result<SecureBuffer> ReadNotes(MemlockPolicy policy) {
  Result<SecureBuffer> notes = ReadAllSecret(STDIN_FILENO, kMaxNotesSize, policy);
  if (!notes.ok()) {
    if (notes.error().code == ErrorCode::kInputTooLong) {
      return Error{ErrorCode::kUsage, "the notes are longer than 64 KiB"};
    }
    return notes;
  }
  {
    const Result<ScopedReadGuard> guard = ScopedReadGuard::Open(notes.value());
    if (!guard.ok()) return guard.error();
    if (!IsValidUtf8(guard.value().bytes())) {
      return Error{ErrorCode::kUsage, "the notes are not valid UTF-8"};
    }
  }
  return notes;
}

// Typed twice, or generated with the default settings.
Result<SecureBuffer> RecordPassword(const ParsedArgs& request, MemlockPolicy policy) {
  if (request.Has("generate")) return GeneratePassword(PasswordSpec{}, policy);
  return ReadNewSecret("Password for the record: ", "Repeat the password: ", policy);
}

Result<LoadedVault> LoadWithMaster(const std::string& path, const SecureBuffer& master,
                                   MemlockPolicy policy) {
  const Result<ScopedReadGuard> guard = ScopedReadGuard::Open(master);
  if (!guard.ok()) return guard.error();
  return LoadVault(path, guard.value().bytes(), policy);
}

Status PutChar(std::FILE* out, char c) {
  return std::fputc(c, out) == EOF ? Status(make_error(ErrorCode::kIoError)) : Ok();
}

// `2026-11-22T10:15:00Z`, or "?" for a time that cannot be shown.
std::string FormatUtc(std::int64_t seconds) {
  const auto time = static_cast<std::time_t>(seconds);
  struct tm parts;
  if (gmtime_r(&time, &parts) == nullptr) return "?";
  char text[32];
  if (std::strftime(text, sizeof text, "%Y-%m-%dT%H:%M:%SZ", &parts) == 0) return "?";
  return text;
}

// One line of `list`: name, user name and last change, separated by tabs. Tabs
// inside the text are replaced, so the columns can be relied on.
Status WriteListRow(std::FILE* out, const Record& record) {
  if (const Status s = WritePrintable(out, record.name); !s.ok()) return s;
  if (const Status s = PutChar(out, '\t'); !s.ok()) return s;
  if (const Status s = WritePrintable(out, record.username); !s.ok()) return s;
  if (const Status s = PutChar(out, '\t'); !s.ok()) return s;
  if (std::fputs(FormatUtc(record.updated_at).c_str(), out) == EOF) {
    return make_error(ErrorCode::kIoError);
  }
  return PutChar(out, '\n');
}

}  // namespace

int ReportError(const Error& error, std::FILE* err) {
  std::fprintf(err, "nilkey: %s\n", error.message);
  if (error.code == ErrorCode::kUsage) {
    std::fputs("Try 'nilkey --help'.\n", err);
    return kExitUsage;
  }
  if (error.code == ErrorCode::kAborted) return kExitAborted;
  return kExitError;
}

MemlockPolicy PolicyFor(const GlobalOptions& globals) {
  return globals.allow_unlocked_memory ? MemlockPolicy::kAllowUnlocked : MemlockPolicy::kRequire;
}

int RunInit(const ParsedArgs& request, const Io& io) {
  const MemlockPolicy policy = PolicyFor(request.globals);
  const Result<std::string> path = VaultPathFor(request);
  if (!path.ok()) return ReportError(path.error(), io.err);

  // Asked before any prompt, so nobody types a password twice to be told no.
  if (const Status s = RequireVaultAbsent(path.value()); !s.ok()) {
    return ReportError(s.error(), io.err);
  }

  // The master password lives only inside this call.
  const Result<VaultKey> key = [&]() -> Result<VaultKey> {
    Result<SecureBuffer> master =
        ReadNewSecret("New master password: ", "Repeat the new master password: ", policy);
    if (!master.ok()) return master.error();
    const Result<ScopedReadGuard> guard = ScopedReadGuard::Open(master.value());
    if (!guard.ok()) return guard.error();
    return NewVaultKey(guard.value().bytes(), ParamsForNewVault(), policy);
  }();
  if (!key.ok()) return ReportError(key.error(), io.err);

  const Result<Vault> vault = Vault::CreateEmpty(policy);
  if (!vault.ok()) return ReportError(vault.error(), io.err);

  if (const Status s = EnsureParentDirectory(path.value()); !s.ok()) {
    return ReportError(s.error(), io.err);
  }
  const Result<VaultLock> lock = VaultLock::Acquire(path.value());
  if (!lock.ok()) return ReportError(lock.error(), io.err);
  // Checked again under the lock: another init may have finished meanwhile.
  if (const Status s = RequireVaultAbsent(path.value()); !s.ok()) {
    return ReportError(s.error(), io.err);
  }
  if (const Status s = SaveVault(path.value(), key.value(), vault.value()); !s.ok()) {
    return ReportError(s.error(), io.err);
  }

  std::fputs("Created vault: ", io.err);
  if (const Status s = WritePrintable(io.err, AsBytes(path.value())); !s.ok()) {
    return ReportError(s.error(), io.err);
  }
  std::fputs("\n", io.err);
  return kExitOk;
}

int RunAdd(const ParsedArgs& request, const Io& io) {
  const MemlockPolicy policy = PolicyFor(request.globals);
  const Result<std::string> path = VaultPathFor(request);
  if (!path.ok()) return ReportError(path.error(), io.err);

  // Everything that can be checked without a password comes first.
  if (const Status s = ValidateRecordArguments(request); !s.ok()) {
    return ReportError(s.error(), io.err);
  }
  if (const Status s = RequireVaultExists(path.value()); !s.ok()) {
    return ReportError(s.error(), io.err);
  }
  Result<SecureBuffer> notes = request.Has("notes-stdin") ? ReadNotes(policy)
                                                          : CopyToSecureBuffer({}, policy);
  if (!notes.ok()) return ReportError(notes.error(), io.err);

  // Then every prompt, so the lock is not held while the user types.
  Result<SecureBuffer> typed_master = ReadSecret("Master password: ", policy);
  if (!typed_master.ok()) return ReportError(typed_master.error(), io.err);
  std::optional<SecureBuffer> master(std::move(typed_master).value());
  const Result<SecureBuffer> password = RecordPassword(request, policy);
  if (!password.ok()) return ReportError(password.error(), io.err);
  const Result<std::int64_t> now = Now();
  if (!now.ok()) return ReportError(now.error(), io.err);

  const Result<VaultLock> lock = VaultLock::Acquire(path.value());
  if (!lock.ok()) return ReportError(lock.error(), io.err);
  Result<LoadedVault> loaded = LoadWithMaster(path.value(), *master, policy);
  master.reset();  // Not needed any more.
  if (!loaded.ok()) return ReportError(loaded.error(), io.err);

  {
    const Result<ScopedReadGuard> password_bytes = ScopedReadGuard::Open(password.value());
    const Result<ScopedReadGuard> notes_bytes = ScopedReadGuard::Open(notes.value());
    if (!password_bytes.ok()) return ReportError(password_bytes.error(), io.err);
    if (!notes_bytes.ok()) return ReportError(notes_bytes.error(), io.err);
    const RecordInput input{AsBytes(request.positionals[0]),
                            AsBytes(request.Value("username").value_or("")),
                            password_bytes.value().bytes(),
                            AsBytes(request.Value("url").value_or("")),
                            notes_bytes.value().bytes()};
    if (const Status s = loaded.value().vault.Add(input, now.value()); !s.ok()) {
      return ReportError(s.error(), io.err);
    }
  }
  if (const Status s = SaveVault(path.value(), loaded.value().key, loaded.value().vault);
      !s.ok()) {
    return ReportError(s.error(), io.err);
  }

  std::fputs("Added \"", io.err);
  if (const Status s = WritePrintable(io.err, AsBytes(request.positionals[0])); !s.ok()) {
    return ReportError(s.error(), io.err);
  }
  std::fputs("\".\n", io.err);
  return kExitOk;
}

int RunList(const ParsedArgs& request, const Io& io) {
  const MemlockPolicy policy = PolicyFor(request.globals);
  const Result<std::string> path = VaultPathFor(request);
  if (!path.ok()) return ReportError(path.error(), io.err);
  if (const Status s = RequireVaultExists(path.value()); !s.ok()) {
    return ReportError(s.error(), io.err);
  }

  // No lock: a save replaces the file atomically, so this is one whole version.
  const Result<LoadedVault> loaded = [&]() -> Result<LoadedVault> {
    Result<SecureBuffer> master = ReadSecret("Master password: ", policy);
    if (!master.ok()) return master.error();
    return LoadWithMaster(path.value(), master.value(), policy);
  }();
  if (!loaded.ok()) return ReportError(loaded.error(), io.err);

  const Result<VaultReader> reader = loaded.value().vault.Open();
  if (!reader.ok()) return ReportError(reader.error(), io.err);
  for (std::size_t i = 0; i < reader.value().size(); ++i) {
    const Result<Record> record = reader.value().Get(i);
    if (!record.ok()) return ReportError(record.error(), io.err);
    if (const Status s = WriteListRow(io.out, record.value()); !s.ok()) {
      return ReportError(s.error(), io.err);
    }
  }
  if (std::fflush(io.out) != 0) return ReportError(make_error(ErrorCode::kIoError), io.err);
  return kExitOk;
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

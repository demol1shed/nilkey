#include "nilkey/commands.hpp"

#include <sodium.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>

#include <algorithm>
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

#include "nilkey/atomic_file.hpp"
#include "nilkey/clipboard.hpp"
#include "nilkey/crypto.hpp"
#include "nilkey/display.hpp"
#include "nilkey/doctor.hpp"
#include "nilkey/fd_io.hpp"
#include "nilkey/passgen.hpp"
#include "nilkey/store.hpp"
#include "nilkey/terminal.hpp"
#include "nilkey/tlv.hpp"
#include "nilkey/vault.hpp"
#include "nilkey/vault_format.hpp"

namespace nilkey {

namespace {

// Writes the secret to `fd` and, if `fd` is a terminal, a line break after it.
// Into a pipe or file the bytes go out exactly as they are, so that
// `nilkey generate | xclip` does not put a newline on the clipboard.
Status WriteSecretLine(int fd, std::span<const std::byte> secret) {
  if (const Status s = WriteAll(fd, secret); !s.ok()) return s;
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

bool IsValidName(std::string_view name) {
  return !name.empty() && name.size() <= kMaxNameSize && IsValidUtf8(AsBytes(name));
}

// A bad name or option text is a mistake in the command line, so it is a usage
// error; left to the vault it would surface as "invalid vault file format".
Status ValidateName(const ParsedArgs& request) {
  if (!IsValidName(request.positionals[0])) {
    return Error{ErrorCode::kUsage, "the name must be 1 to 1024 bytes of valid UTF-8"};
  }
  return Ok();
}

Status ValidateTextOptions(const ParsedArgs& request) {
  if (const auto text = request.Value("username"); text && !IsValidUtf8(AsBytes(*text))) {
    return Error{ErrorCode::kUsage, "--username must be valid UTF-8"};
  }
  if (const auto text = request.Value("url"); text && !IsValidUtf8(AsBytes(*text))) {
    return Error{ErrorCode::kUsage, "--url must be valid UTF-8"};
  }
  return Ok();
}

Status ValidateRecordArguments(const ParsedArgs& request) {
  if (const Status s = ValidateName(request); !s.ok()) return s;
  return ValidateTextOptions(request);
}

// Text the user creates must read back as written, so a name, user name or URL
// with a control character (ESC, tab, newline, a direction mark) is refused.
// This applies only to what is being written: a lookup by name stays
// permissive, so a record that already has such a name (from an older version
// or another writer) can still be found, renamed and deleted.
Status ValidateNewText(const ParsedArgs& request, std::string_view name,
                       const char* name_message) {
  if (!ShowsAsWritten(AsBytes(name))) return Error{ErrorCode::kUsage, name_message};
  if (const auto text = request.Value("username"); text && !ShowsAsWritten(AsBytes(*text))) {
    return Error{ErrorCode::kUsage, "--username must not contain control characters"};
  }
  if (const auto text = request.Value("url"); text && !ShowsAsWritten(AsBytes(*text))) {
    return Error{ErrorCode::kUsage, "--url must not contain control characters"};
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

// Opens the vault only to learn whether `master` is right, and drops it again.
// A command that asks for more after the master password calls this first, so
// a wrong one is reported before the user types anything else. It costs one key
// derivation; the check under the lock in ChangeVault stays the one that counts.
Status VerifyMaster(const std::string& path, const SecureBuffer& master, MemlockPolicy policy) {
  const Result<LoadedVault> loaded = LoadWithMaster(path, master, policy);
  if (!loaded.ok()) return loaded.error();
  return Ok();
}

// The cycle of every command that changes the vault: take the lock, open the
// vault, let `change` edit it, save it, release the lock. The master password
// is destroyed as soon as the vault is open. Nothing here may fork (see
// VaultLock).
template <typename Change>
Status ChangeVault(const std::string& path, std::optional<SecureBuffer>& master,
                   MemlockPolicy policy, Change change) {
  const Result<VaultLock> lock = VaultLock::Acquire(path);
  if (!lock.ok()) return lock.error();
  Result<LoadedVault> loaded = LoadWithMaster(path, *master, policy);
  master.reset();
  if (!loaded.ok()) return loaded.error();
  if (const Status s = change(loaded.value()); !s.ok()) return s;
  return SaveVault(path, loaded.value().key, loaded.value().vault);
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

// The headings of the aligned `list`, and the spaces between two columns. A
// column is never narrower than its heading.
constexpr std::string_view kNameHeader = "NAME";
constexpr std::string_view kUserHeader = "USERNAME";
constexpr std::size_t kColumnGap = 2;

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

// Writes `count` spaces.
Status PutSpaces(std::FILE* out, std::size_t count) {
  for (std::size_t i = 0; i < count; ++i) {
    if (const Status s = PutChar(out, ' '); !s.ok()) return s;
  }
  return Ok();
}

// The spaces that follow a text of `used` cells in a column `width` cells wide:
// the rest of the column and the gap before the next one. The gap is always
// written; the rest is zero if the column is too narrow, so a wrong width shows
// up as a row that does not line up, not as a write of about 2^64 spaces.
std::size_t Padding(std::size_t width, std::size_t used) {
  return (width > used ? width - used : 0) + kColumnGap;
}

// Writes `text` and the spaces that bring the next column to the same cell in
// every row. `width` is the width of the widest text of the column, so it is
// never less than the width of `text`.
Status PutColumn(std::FILE* out, std::span<const std::byte> text, std::size_t width) {
  if (const Status s = WritePrintable(out, text); !s.ok()) return s;
  return PutSpaces(out, Padding(width, PrintableWidth(text)));
}

// `list` on a terminal: a header and one row per record, with the user names
// and the times each starting at the same cell. Each of the first two columns is
// as wide as its longest entry, measured in terminal cells. Nothing at all for
// an empty vault. The widths need a first pass over the records.
Status WriteAlignedList(std::FILE* out, const VaultReader& reader) {
  if (reader.size() == 0) return Ok();

  std::size_t name_width = kNameHeader.size();
  std::size_t user_width = kUserHeader.size();
  for (std::size_t i = 0; i < reader.size(); ++i) {
    const Result<Record> record = reader.Get(i);
    if (!record.ok()) return record.error();
    name_width = std::max(name_width, PrintableWidth(record.value().name));
    user_width = std::max(user_width, PrintableWidth(record.value().username));
  }

  if (std::fputs(kNameHeader.data(), out) == EOF) return make_error(ErrorCode::kIoError);
  if (const Status s = PutSpaces(out, Padding(name_width, kNameHeader.size())); !s.ok()) return s;
  if (std::fputs(kUserHeader.data(), out) == EOF) return make_error(ErrorCode::kIoError);
  if (const Status s = PutSpaces(out, Padding(user_width, kUserHeader.size())); !s.ok()) return s;
  if (std::fputs("UPDATED\n", out) == EOF) return make_error(ErrorCode::kIoError);

  for (std::size_t i = 0; i < reader.size(); ++i) {
    const Result<Record> record = reader.Get(i);
    if (!record.ok()) return record.error();
    if (const Status s = PutColumn(out, record.value().name, name_width); !s.ok()) return s;
    if (const Status s = PutColumn(out, record.value().username, user_width); !s.ok()) return s;
    if (std::fputs(FormatUtc(record.value().updated_at).c_str(), out) == EOF) {
      return make_error(ErrorCode::kIoError);
    }
    if (const Status s = PutChar(out, '\n'); !s.ok()) return s;
  }
  return Ok();
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
        ReadNewSecret("New master password: ", "Repeat the new master password: ", policy,
                    kMinMasterCharacters);
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
  if (const Status s = ValidateNewText(request, request.positionals[0],
                                       "the name must not contain control characters");
      !s.ok()) {
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
  if (const Status s = VerifyMaster(path.value(), *master, policy); !s.ok()) {
    return ReportError(s.error(), io.err);
  }
  const Result<SecureBuffer> password = RecordPassword(request, policy);
  if (!password.ok()) return ReportError(password.error(), io.err);
  const Result<std::int64_t> now = Now();
  if (!now.ok()) return ReportError(now.error(), io.err);

  const Status saved =
      ChangeVault(path.value(), master, policy, [&](LoadedVault& loaded) -> Status {
        const Result<ScopedReadGuard> password_bytes = ScopedReadGuard::Open(password.value());
        const Result<ScopedReadGuard> notes_bytes = ScopedReadGuard::Open(notes.value());
        if (!password_bytes.ok()) return password_bytes.error();
        if (!notes_bytes.ok()) return notes_bytes.error();
        const RecordInput input{AsBytes(request.positionals[0]),
                                AsBytes(request.Value("username").value_or("")),
                                password_bytes.value().bytes(),
                                AsBytes(request.Value("url").value_or("")),
                                notes_bytes.value().bytes()};
        return loaded.vault.Add(input, now.value());
      });
  if (!saved.ok()) return ReportError(saved.error(), io.err);

  std::fputs("Added \"", io.err);
  if (const Status s = WritePrintable(io.err, AsBytes(request.positionals[0])); !s.ok()) {
    return ReportError(s.error(), io.err);
  }
  std::fputs("\".\n", io.err);
  return kExitOk;
}

// Opens a read guard on `buffer`, if there is one.
Status OpenIfPresent(const std::optional<SecureBuffer>& buffer,
                     std::optional<ScopedReadGuard>& guard) {
  if (!buffer.has_value()) return Ok();
  Result<ScopedReadGuard> opened = ScopedReadGuard::Open(*buffer);
  if (!opened.ok()) return opened.error();
  guard.emplace(std::move(opened).value());
  return Ok();
}

Status WriteQuotedName(std::FILE* err, const char* before, std::string_view name,
                       const char* after) {
  std::fputs(before, err);
  if (const Status s = WritePrintable(err, AsBytes(name)); !s.ok()) return s;
  std::fputs(after, err);
  return Ok();
}

int RunUpdate(const ParsedArgs& request, const Io& io) {
  const MemlockPolicy policy = PolicyFor(request.globals);
  const Result<std::string> path = VaultPathFor(request);
  if (!path.ok()) return ReportError(path.error(), io.err);

  // Everything that can be checked without a password comes first.
  if (request.Has("prompt-password") && request.Has("generate")) {
    return ReportError(Error{ErrorCode::kUsage, "use either --prompt-password or --generate"},
                       io.err);
  }
  const bool new_password = request.Has("prompt-password") || request.Has("generate");
  if (!new_password && !request.Has("rename") && !request.Has("username") &&
      !request.Has("url") && !request.Has("notes-stdin")) {
    return ReportError(Error{ErrorCode::kUsage, "nothing to change; give at least one option"},
                       io.err);
  }
  if (const Status s = ValidateRecordArguments(request); !s.ok()) {
    return ReportError(s.error(), io.err);
  }
  const std::optional<std::string_view> rename = request.Value("rename");
  if (rename.has_value() && !IsValidName(*rename)) {
    return ReportError(
        Error{ErrorCode::kUsage, "--rename must be 1 to 1024 bytes of valid UTF-8"}, io.err);
  }
  if (const Status s = ValidateNewText(request, rename.value_or(std::string_view()),
                                       "--rename must not contain control characters");
      !s.ok()) {
    return ReportError(s.error(), io.err);
  }
  if (const Status s = RequireVaultExists(path.value()); !s.ok()) {
    return ReportError(s.error(), io.err);
  }

  std::optional<SecureBuffer> notes;
  if (request.Has("notes-stdin")) {
    Result<SecureBuffer> read = ReadNotes(policy);
    if (!read.ok()) return ReportError(read.error(), io.err);
    notes.emplace(std::move(read).value());
  }

  // Then every prompt, so the lock is not held while the user types.
  Result<SecureBuffer> typed_master = ReadSecret("Master password: ", policy);
  if (!typed_master.ok()) return ReportError(typed_master.error(), io.err);
  std::optional<SecureBuffer> master(std::move(typed_master).value());
  if (const Status s = VerifyMaster(path.value(), *master, policy); !s.ok()) {
    return ReportError(s.error(), io.err);
  }
  std::optional<SecureBuffer> password;
  if (new_password) {
    Result<SecureBuffer> chosen = RecordPassword(request, policy);
    if (!chosen.ok()) return ReportError(chosen.error(), io.err);
    password.emplace(std::move(chosen).value());
  }
  const Result<std::int64_t> now = Now();
  if (!now.ok()) return ReportError(now.error(), io.err);

  const Status saved =
      ChangeVault(path.value(), master, policy, [&](LoadedVault& loaded) -> Status {
        std::optional<ScopedReadGuard> password_bytes;
        std::optional<ScopedReadGuard> notes_bytes;
        if (const Status s = OpenIfPresent(password, password_bytes); !s.ok()) return s;
        if (const Status s = OpenIfPresent(notes, notes_bytes); !s.ok()) return s;

        // Only what was asked for is set; the vault keeps the rest as it is.
        RecordPatch patch;
        if (rename.has_value()) patch.name = AsBytes(*rename);
        if (const auto text = request.Value("username")) patch.username = AsBytes(*text);
        if (const auto text = request.Value("url")) patch.url = AsBytes(*text);
        if (password_bytes.has_value()) patch.password = password_bytes->bytes();
        if (notes_bytes.has_value()) patch.notes = notes_bytes->bytes();
        return loaded.vault.Patch(AsBytes(request.positionals[0]), patch, now.value());
      });
  if (!saved.ok()) return ReportError(saved.error(), io.err);

  if (const Status s = WriteQuotedName(io.err, "Updated \"", request.positionals[0], "\".\n");
      !s.ok()) {
    return ReportError(s.error(), io.err);
  }
  return kExitOk;
}

int RunDelete(const ParsedArgs& request, const Io& io) {
  const MemlockPolicy policy = PolicyFor(request.globals);
  const Result<std::string> path = VaultPathFor(request);
  if (!path.ok()) return ReportError(path.error(), io.err);

  if (const Status s = ValidateName(request); !s.ok()) return ReportError(s.error(), io.err);
  if (const Status s = RequireVaultExists(path.value()); !s.ok()) {
    return ReportError(s.error(), io.err);
  }

  // Asked before the master password, so nobody types it and then backs out.
  // The name is not part of the question: it came from the command line, and
  // text from there must not reach the terminal unchecked.
  if (!request.Has("yes")) {
    const Result<bool> confirmed = Confirm("Delete this record? [y/N] ");
    if (!confirmed.ok()) return ReportError(confirmed.error(), io.err);
    if (!confirmed.value()) return ReportError(make_error(ErrorCode::kNotConfirmed), io.err);
  }

  Result<SecureBuffer> typed_master = ReadSecret("Master password: ", policy);
  if (!typed_master.ok()) return ReportError(typed_master.error(), io.err);
  std::optional<SecureBuffer> master(std::move(typed_master).value());

  const Status saved =
      ChangeVault(path.value(), master, policy, [&](LoadedVault& loaded) -> Status {
        return loaded.vault.Remove(AsBytes(request.positionals[0]));
      });
  if (!saved.ok()) return ReportError(saved.error(), io.err);

  if (const Status s = WriteQuotedName(io.err, "Deleted \"", request.positionals[0], "\".\n");
      !s.ok()) {
    return ReportError(s.error(), io.err);
  }
  return kExitOk;
}

int RunPasswd(const ParsedArgs& request, const Io& io) {
  const MemlockPolicy policy = PolicyFor(request.globals);
  const Result<std::string> path = VaultPathFor(request);
  if (!path.ok()) return ReportError(path.error(), io.err);
  if (const Status s = RequireVaultExists(path.value()); !s.ok()) {
    return ReportError(s.error(), io.err);
  }

  // Every prompt first, so the lock is not held while the user types.
  Result<SecureBuffer> typed_master = ReadSecret("Current master password: ", policy);
  if (!typed_master.ok()) return ReportError(typed_master.error(), io.err);
  std::optional<SecureBuffer> master(std::move(typed_master).value());
  if (const Status s = VerifyMaster(path.value(), *master, policy); !s.ok()) {
    return ReportError(s.error(), io.err);
  }
  Result<SecureBuffer> typed_next =
      ReadNewSecret("New master password: ", "Repeat the new master password: ", policy,
                    kMinMasterCharacters);
  if (!typed_next.ok()) return ReportError(typed_next.error(), io.err);
  std::optional<SecureBuffer> next(std::move(typed_next).value());

  // The new key is derived only once the current password has opened the vault
  // (it was checked above, and is checked again here under the lock). The lock
  // is held meanwhile; this command is rare.
  const Status saved =
      ChangeVault(path.value(), master, policy, [&](LoadedVault& loaded) -> Status {
        Result<VaultKey> key = [&]() -> Result<VaultKey> {
          const Result<ScopedReadGuard> guard = ScopedReadGuard::Open(*next);
          if (!guard.ok()) return guard.error();
          return NewVaultKey(guard.value().bytes(), ParamsForNewVault(), policy);
        }();
        next.reset();  // Not needed any more.
        if (!key.ok()) return key.error();
        // A fresh salt came with the key; Seal() adds a fresh nonce when saving.
        loaded.key = std::move(key).value();
        return Ok();
      });
  if (!saved.ok()) return ReportError(saved.error(), io.err);

  std::fputs("Master password changed.\n", io.err);
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
  // On a terminal the columns are lined up; into a pipe or a file the rows stay
  // separated by tabs, which a script can split even if a name holds spaces.
  if (isatty(io.out_fd) == 1) {
    if (const Status s = WriteAlignedList(io.out, reader.value()); !s.ok()) {
      return ReportError(s.error(), io.err);
    }
  } else {
    for (std::size_t i = 0; i < reader.value().size(); ++i) {
      const Result<Record> record = reader.value().Get(i);
      if (!record.ok()) return ReportError(record.error(), io.err);
      if (const Status s = WriteListRow(io.out, record.value()); !s.ok()) {
        return ReportError(s.error(), io.err);
      }
    }
  }
  if (std::fflush(io.out) != 0) return ReportError(make_error(ErrorCode::kIoError), io.err);
  return kExitOk;
}

// How long the clipboard keeps a copied value (SPEC.md 9.2): 15 seconds unless
// --timeout says otherwise, and never longer than an hour.
constexpr unsigned kDefaultClearSeconds = 15;
constexpr unsigned kMaxClearSeconds = 3600;

// Zeroes the digest of the copied value, if there is one.
void WipeDigest(std::optional<ClipboardFingerprint>& fingerprint) {
  if (fingerprint.has_value()) {
    sodium_memzero(fingerprint->digest.data(), fingerprint->digest.size());
  }
}

// Enough to cover the frames a vault read and a copy used (see RunGet).
constexpr std::size_t kStackToScrub = 16 * 1024;

Result<unsigned> ParseClearSeconds(const ParsedArgs& request) {
  const std::optional<std::string_view> text = request.Value("timeout");
  if (!text.has_value()) return kDefaultClearSeconds;
  if (request.Has("print")) {
    return Error{ErrorCode::kUsage, "--timeout does not apply to --print"};
  }
  const char* const first = text->data();
  const char* const last = first + text->size();
  unsigned seconds = 0;
  const std::from_chars_result parsed = std::from_chars(first, last, seconds);
  if (parsed.ec != std::errc() || parsed.ptr != last || seconds < 1 ||
      seconds > kMaxClearSeconds) {
    return Error{ErrorCode::kUsage, "--timeout must be a number of seconds from 1 to 3600"};
  }
  return seconds;
}

// The bytes of the field that --field names. The name was checked before.
std::span<const std::byte> FieldOf(const Record& record, std::string_view field) {
  if (field == "username") return record.username;
  if (field == "url") return record.url;
  if (field == "notes") return record.notes;
  return record.password;
}

int RunGet(const ParsedArgs& request, const Io& io) {
  const MemlockPolicy policy = PolicyFor(request.globals);
  const Result<std::string> path = VaultPathFor(request);
  if (!path.ok()) return ReportError(path.error(), io.err);

  // Everything that can be checked without a password comes first.
  const std::string_view field = request.Value("field").value_or("password");
  if (field != "password" && field != "username" && field != "url" && field != "notes") {
    return ReportError(
        Error{ErrorCode::kUsage, "--field must be password, username, url or notes"}, io.err);
  }
  const Result<unsigned> seconds = ParseClearSeconds(request);
  if (!seconds.ok()) return ReportError(seconds.error(), io.err);
  if (const Status s = ValidateName(request); !s.ok()) return ReportError(s.error(), io.err);
  if (const Status s = RequireVaultExists(path.value()); !s.ok()) {
    return ReportError(s.error(), io.err);
  }
  const bool print = request.Has("print");
  // No tool, no password prompt: nobody should type the master password and
  // then be told there is nowhere to copy to.
  std::optional<ClipboardTool> tool;
  if (!print) {
    Result<ClipboardTool> found = DetectClipboardTool(
        {std::getenv("PATH"), std::getenv("WAYLAND_DISPLAY"), std::getenv("DISPLAY")});
    if (!found.ok()) return ReportError(found.error(), io.err);
    tool.emplace(std::move(found).value());
  }

  // The master password, the vault, its key and the value all live only inside
  // this call, so none of them is alive when the cleaner process is forked.
  std::optional<ClipboardFingerprint> copied;
  const Status shown = [&]() -> Status {
    Result<SecureBuffer> master = ReadSecret("Master password: ", policy);
    if (!master.ok()) return master.error();
    const Result<LoadedVault> loaded = LoadWithMaster(path.value(), master.value(), policy);
    if (!loaded.ok()) return loaded.error();
    const Result<VaultReader> reader = loaded.value().vault.Open();
    if (!reader.ok()) return reader.error();
    const std::optional<std::size_t> index =
        reader.value().Find(AsBytes(request.positionals[0]));
    if (!index.has_value()) return make_error(ErrorCode::kNotFound);
    const Result<Record> record = reader.value().Get(*index);
    if (!record.ok()) return record.error();
    const std::span<const std::byte> value = FieldOf(record.value(), field);

    if (print) {
      // Anything buffered on `out` goes first; the value is written directly.
      if (std::fflush(io.out) != 0) return make_error(ErrorCode::kIoError);
      return WriteSecretLine(io.out_fd, value);
    }
    // Straight from the vault's buffer: no further copy of the value is made.
    if (value.empty()) return make_error(ErrorCode::kFieldEmpty);
    Result<ClipboardFingerprint> made = FingerprintOf(value);
    if (!made.ok()) return made.error();
    copied = made.value();
    // `copied` is the one copy the cleaner will inherit. This frame can be part
    // of RunGet's own (the compiler may inline the lambda), where the scrubbing
    // below does not reach.
    sodium_memzero(made.value().digest.data(), made.value().digest.size());
    return CopyToClipboard(*tool, value);
  }();
  if (!shown.ok()) {
    WipeDigest(copied);
    return ReportError(shown.error(), io.err);
  }
  if (print) return kExitOk;

  // The frames of the call above held the value for a while; fork() would copy
  // them into the cleaner.
  sodium_stackzero(kStackToScrub);
  const Status started = StartCleaner(*tool, *copied, seconds.value(), policy);
  WipeDigest(copied);  // The cleaner has its own copy by now, or there is none.
  if (!started.ok()) {
    // Without a cleaner the value must not stay on the clipboard.
    if (const Status cleared = ClearClipboard(*tool); !cleared.ok()) {
      std::fputs("nilkey: the clipboard may still hold the value; clear it yourself\n", io.err);
    }
    return ReportError(started.error(), io.err);
  }

  std::fprintf(io.err, "Copied the %.*s of \"", static_cast<int>(field.size()), field.data());
  if (const Status s = WritePrintable(io.err, AsBytes(request.positionals[0])); !s.ok()) {
    return ReportError(s.error(), io.err);
  }
  std::fprintf(io.err, "\" to the clipboard; it is cleared in %u seconds.\n", seconds.value());
  return kExitOk;
}

int RunGenerate(const ParsedArgs& request, const Io& io) {
  const Result<PasswordSpec> spec = ParseGenerateSpec(request);
  if (!spec.ok()) return ReportError(spec.error(), io.err);

  const Result<SecureBuffer> password =
      GeneratePassword(spec.value(), PolicyFor(request.globals));
  if (!password.ok()) return ReportError(password.error(), io.err);

  const Result<ScopedReadGuard> guard = ScopedReadGuard::Open(password.value());
  if (!guard.ok()) return ReportError(guard.error(), io.err);
  const Status written = WriteSecretLine(io.out_fd, guard.value().bytes());
  if (!written.ok()) return ReportError(written.error(), io.err);
  return kExitOk;
}

// ---- doctor (SPEC.md 9.2) ----
//
// Every check prints one line, "ok", "note" or "problem" and a label. It asks
// for no password, allocates no SecureBuffer, takes no lock and writes no file.
// The rules are in doctor.cpp; what follows gathers the facts.

namespace {

class DoctorReport {
 public:
  explicit DoctorReport(std::FILE* out) : out_(out) {}

  // Starts a line; the caller writes the rest with the stream from out().
  std::FILE* Begin(Finding level) {
    if (level == Finding::kProblem) ++problems_;
    const char* const name = level == Finding::kOk     ? "ok     "
                             : level == Finding::kNote ? "note   "
                                                       : "problem";
    std::fprintf(out_, "%s ", name);
    return out_;
  }

  void Line(Finding level, const char* label, const char* text) {
    std::fprintf(Begin(level), "%s: %s\n", label, text);
  }

  std::FILE* out() const { return out_; }
  bool HasProblem() const { return problems_ > 0; }

 private:
  std::FILE* out_;
  unsigned problems_ = 0;
};

// The mode, the owner and the kind of a vault or lock file. False if there is no
// such file (nothing is printed then).
bool CheckPlainFile(DoctorReport& report, const std::string& path, const char* label,
                    bool* is_regular) {
  struct stat st;
  if (lstat(path.c_str(), &st) != 0) {
    if (errno == ENOENT) return false;
    report.Line(Finding::kProblem, label, "cannot check it");
    return true;
  }
  if (S_ISLNK(st.st_mode)) {
    report.Line(Finding::kProblem, label, "is a symbolic link, which nilkey refuses to follow");
    return true;
  }
  if (!S_ISREG(st.st_mode)) {
    report.Line(Finding::kProblem, label, "is not a regular file");
    return true;
  }
  *is_regular = true;
  const Check check = ClassifyFileMode(st.st_mode, st.st_uid, geteuid());
  std::fprintf(report.Begin(check.level), "%s: mode %04o; %s\n", label,
               static_cast<unsigned>(st.st_mode & 07777), check.text);
  return true;
}

void CheckDirectory(DoctorReport& report, const std::string& path) {
  struct stat st;
  if (stat(path.c_str(), &st) != 0) {
    // A missing directory is no finding of its own: the vault is missing too.
    if (errno != ENOENT) report.Line(Finding::kProblem, "directory", "cannot check it");
    return;
  }
  if (!S_ISDIR(st.st_mode)) {
    report.Line(Finding::kProblem, "directory", "the vault's parent is not a directory");
    return;
  }
  const Check check = ClassifyDirectoryMode(st.st_mode, st.st_uid, geteuid());
  std::fprintf(report.Begin(check.level), "directory: mode %04o; %s\n",
               static_cast<unsigned>(st.st_mode & 07777), check.text);
}

// The KiB figure of a lock limit, or "unlimited".
void PrintLimit(std::FILE* out, rlim_t limit) {
  if (limit == RLIM_INFINITY) {
    std::fputs("unlimited", out);
  } else {
    std::fprintf(out, "%llu KiB", static_cast<unsigned long long>(limit / 1024));
  }
}

// The header of the vault at `path`, read without a password. kOk and the
// header if it is valid; nothing is printed here.
Result<VaultHeader> ReadHeaderOnly(const std::string& path) {
  const Result<std::vector<std::byte>> file = ReadVaultFile(path.c_str());
  if (!file.ok()) return file.error();
  if (file.value().size() < kHeaderSize) return make_error(ErrorCode::kInvalidFormat);
  const Result<VaultHeader> header =
      ParseHeader(std::span<const std::byte>(file.value().data(), kHeaderSize));
  if (!header.ok()) return header.error();
  if (const Status s = ValidateFileSize(file.value().size(), header.value()); !s.ok()) {
    return s.error();
  }
  return header.value();
}

// One line: the limit, what the commands in `what` need, and whether it fits.
void PrintLockNeed(DoctorReport& report, rlim_t limit, const char* what, std::uint64_t needed) {
  const bool fits = limit == RLIM_INFINITY || limit >= needed;
  std::FILE* const out = report.Begin(fits ? Finding::kOk : Finding::kProblem);
  std::fputs("memory lock limit: ", out);
  PrintLimit(out, limit);
  std::fprintf(out, "; %s needs about %llu KiB", what,
               static_cast<unsigned long long>((needed + 1023) / 1024));
  std::fputs(fits ? "\n"
                  : "; raise `ulimit -l`, or pass --allow-unlocked-memory to run without it\n",
             out);
}

// SPEC.md 7.3: running out of lockable memory for the vault stops nilkey (a
// problem); too little for the Argon2id working memory only warns at run time,
// so it is a note here.
void CheckMemoryLock(DoctorReport& report, const std::optional<VaultHeader>& header) {
  rlimit limit{};
  if (getrlimit(RLIMIT_MEMLOCK, &limit) != 0) {
    report.Line(Finding::kProblem, "memory lock limit", "cannot check it");
    return;
  }
  if (header.has_value()) {
    const long page = sysconf(_SC_PAGESIZE);
    const std::uint64_t page_size = page > 0 ? static_cast<std::uint64_t>(page) : 4096;
    PrintLockNeed(report, limit.rlim_cur, "reading (list, get)",
                  LockedBytesToRead(header->payload_len, page_size));
    PrintLockNeed(report, limit.rlim_cur, "changing (add, update, delete, passwd)",
                  LockedBytesToChange(header->payload_len, page_size));
  }
  const KdfParams kdf = header.has_value() ? header->kdf : kDefaultKdfParams;
  if (MemlockLimitCoversKdf(kdf)) {
    std::fprintf(report.Begin(Finding::kOk),
                 "key derivation memory: the lock limit covers the %u KiB Argon2id uses\n",
                 kdf.mem_kib);
  } else {
    std::fprintf(report.Begin(Finding::kNote),
                 "key derivation memory: the lock limit is below the %u KiB Argon2id uses; "
                 "that memory may be written to swap (see `ulimit -l`)\n",
                 kdf.mem_kib);
  }
}

void CheckHardening(DoctorReport& report) {
  const int dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
  if (dumpable < 0) {
    report.Line(Finding::kProblem, "core dumps", "cannot check whether the process is dumpable");
  } else if (dumpable != 0) {
    report.Line(Finding::kProblem, "core dumps",
                "the process is dumpable; its memory could be dumped or traced");
  } else {
    report.Line(Finding::kOk, "core dumps", "the process is not dumpable");
  }

  rlimit core{};
  if (getrlimit(RLIMIT_CORE, &core) != 0) {
    report.Line(Finding::kProblem, "core file size", "cannot check it");
  } else if (core.rlim_cur != 0) {
    report.Line(Finding::kProblem, "core file size", "the limit is not 0; a crash could write a core file");
  } else {
    report.Line(Finding::kOk, "core file size", "the limit is 0");
  }
}

void CheckSwap(DoctorReport& report) {
  std::FILE* const file = std::fopen("/proc/swaps", "re");
  if (file == nullptr) {
    report.Line(Finding::kNote, "swap", "cannot read /proc/swaps");
    return;
  }
  // Read to the end: one fread() may stop short, and a machine can list many
  // areas. The cap only keeps a broken file from growing without limit.
  constexpr std::size_t kMaxSwapsText = 1024 * 1024;
  std::string text;
  char chunk[4096];
  while (text.size() < kMaxSwapsText) {
    const std::size_t n = std::fread(chunk, 1, sizeof chunk, file);
    text.append(chunk, n);
    if (n < sizeof chunk) break;  // End of the file, or an error (checked below).
  }
  const bool read_failed = std::ferror(file) != 0;
  if (std::fclose(file) != 0 || read_failed) {
    report.Line(Finding::kNote, "swap", "cannot read /proc/swaps");
    return;
  }
  const unsigned areas = CountSwapAreas(text);
  if (areas == 0) {
    report.Line(Finding::kOk, "swap", "no swap area is active");
    return;
  }
  std::fprintf(report.Begin(Finding::kNote),
               "swap: %u area(s) active; nilkey locks the memory that holds secrets, but "
               "hibernation writes all memory to disk; use an encrypted swap or no hibernation\n",
               areas);
}

void CheckClipboard(DoctorReport& report) {
  const char* const wayland = std::getenv("WAYLAND_DISPLAY");
  const bool is_wayland = wayland != nullptr && wayland[0] != '\0';
  const Result<ClipboardTool> tool =
      DetectClipboardTool({std::getenv("PATH"), wayland, std::getenv("DISPLAY")});
  if (!tool.ok()) {
    report.Line(Finding::kNote, "clipboard",
                "no tool found; `get` works only with --print (install wl-clipboard, xclip or xsel)");
    return;
  }
  std::FILE* const out = report.Begin(Finding::kOk);
  std::fprintf(out, "clipboard: %s session, using ", is_wayland ? "Wayland" : "X11");
  if (const Status s = WritePrintable(out, AsBytes(tool.value().copy_path)); !s.ok()) {
    std::fputs("?", out);
  }
  std::fputs("\n", out);
}

}  // namespace

int RunDoctor(const ParsedArgs& request, const Io& io) {
  const Result<std::string> path = VaultPathFor(request);
  if (!path.ok()) return ReportError(path.error(), io.err);

  DoctorReport report(io.out);
  std::fputs("vault: ", io.out);
  if (const Status s = WritePrintable(io.out, AsBytes(path.value())); !s.ok()) {
    return ReportError(s.error(), io.err);
  }
  std::fputs("\n", io.out);

  bool vault_is_regular = false;
  if (!CheckPlainFile(report, path.value(), "vault file", &vault_is_regular)) {
    report.Line(Finding::kNote, "vault file", "not found; run `nilkey init` to create it");
  }
  bool lock_is_regular = false;  // Only the vault's kind matters further on.
  static_cast<void>(CheckPlainFile(report, path.value() + ".lock", "lock file", &lock_is_regular));
  CheckDirectory(report, ParentDirectory(path.value()));

  std::optional<VaultHeader> header;
  if (vault_is_regular) {
    const Result<VaultHeader> read = ReadHeaderOnly(path.value());
    if (read.ok()) {
      header = read.value();
    } else {
      report.Line(Finding::kProblem, "vault header", "is not valid, or the file cannot be read");
    }
  }
  CheckMemoryLock(report, header);
  CheckHardening(report);
  CheckSwap(report);
  CheckClipboard(report);

  if (std::fflush(io.out) != 0) return kExitError;
  return report.HasProblem() ? kExitError : kExitOk;
}

}  // namespace nilkey

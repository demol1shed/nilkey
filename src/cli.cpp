#include "nilkey/cli.hpp"

#include <unistd.h>

#include <array>
#include <charconv>
#include <cstddef>
#include <system_error>

#include "nilkey/args.hpp"
#include "nilkey/fd_io.hpp"
#include "nilkey/passgen.hpp"
#include "nilkey/secure_buffer.hpp"

namespace nilkey {

namespace {

// The command table (SPEC.md 9.2). No command has an option that carries a
// password: master and record passwords come from the terminal (SPEC.md 9.3).
// `--prompt-password` only asks for one; `--notes-stdin` reads notes from stdin
// so they stay out of argv, `ps` and the shell history.
constexpr std::array<OptionSpec, 4> kAddOptions = {{
    {"username", true},
    {"url", true},
    {"notes-stdin", false},
    {"generate", false},
}};
constexpr std::array<OptionSpec, 3> kGetOptions = {{
    {"field", true},
    {"print", false},
    {"timeout", true},
}};
constexpr std::array<OptionSpec, 6> kUpdateOptions = {{
    {"rename", true},
    {"username", true},
    {"url", true},
    {"notes-stdin", false},
    {"prompt-password", false},
    {"generate", false},
}};
constexpr std::array<OptionSpec, 1> kDeleteOptions = {{{"yes", false}}};
constexpr std::array<OptionSpec, 5> kGenerateOptions = {{
    {"length", true},
    {"no-lower", false},
    {"no-upper", false},
    {"no-digits", false},
    {"no-symbols", false},
}};

constexpr std::array<CommandSpec, 9> kCommands = {{
    {"init", "init", "Create a new vault", {}, 0, 0},
    {"add", "add <name> [--username <text>] [--url <text>] [--notes-stdin] [--generate]",
     "Add a record", kAddOptions, 1, 1},
    {"get", "get <name> [--field password|username|url|notes] [--print] [--timeout <seconds>]",
     "Copy a field to the clipboard, or print it", kGetOptions, 1, 1},
    {"list", "list", "List record names", {}, 0, 0},
    {"update",
     "update <name> [--rename <new>] [--username <text>] [--url <text>] [--notes-stdin]\n"
     "                 [--prompt-password | --generate]",
     "Change fields of a record", kUpdateOptions, 1, 1},
    {"delete", "delete <name> [--yes]", "Delete a record", kDeleteOptions, 1, 1},
    {"generate",
     "generate [--length <n>] [--no-lower] [--no-upper] [--no-digits] [--no-symbols]",
     "Generate a random password", kGenerateOptions, 0, 0},
    {"passwd", "passwd", "Change the master password", {}, 0, 0},
    {"doctor", "doctor", "Check the security of this environment", {}, 0, 0},
}};

void PrintUsage(std::FILE* out) {
  std::fputs(
      "nilkey - zero-knowledge command line password vault\n"
      "\n"
      "Usage: nilkey [global options] <command> [options]\n"
      "\n"
      "Commands:\n",
      out);
  for (const CommandSpec& command : kCommands) {
    std::fprintf(out, "  %.*s\n      %.*s\n", static_cast<int>(command.usage.size()),
                 command.usage.data(), static_cast<int>(command.summary.size()),
                 command.summary.data());
  }
  std::fputs(
      "\n"
      "Global options:\n"
      "  --vault <path>           Vault file (default: $NILKEY_PATH, then\n"
      "                           ~/.local/share/nilkey/default.vault)\n"
      "  --allow-unlocked-memory  Continue, with a warning, if memory cannot be locked\n"
      "  --help                   Show this help\n"
      "  --version                Show the version\n"
      "\n"
      "Passwords are read from the terminal, never from the command line.\n",
      out);
}

// Prints `error` and returns the exit status for it: 2 for a wrong command
// line (with a pointer to --help), 1 for anything else. Only the static
// message is printed, never a value that came from the user.
int ReportError(const Error& error, std::FILE* err) {
  std::fprintf(err, "nilkey: %s\n", error.message);
  if (error.code == ErrorCode::kUsage) {
    std::fputs("Try 'nilkey --help'.\n", err);
    return kExitUsage;
  }
  return kExitError;
}

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

MemlockPolicy PolicyFor(const GlobalOptions& globals) {
  return globals.allow_unlocked_memory ? MemlockPolicy::kAllowUnlocked : MemlockPolicy::kRequire;
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

}  // namespace

Result<std::string> ResolveVaultPath(std::optional<std::string_view> flag,
                                     const char* env_nilkey_path, const char* env_home) {
  if (flag.has_value()) {
    if (flag->empty()) return Error{ErrorCode::kUsage, "--vault needs a non-empty path"};
    return std::string(*flag);
  }
  if (env_nilkey_path != nullptr && env_nilkey_path[0] != '\0') {
    return std::string(env_nilkey_path);
  }
  if (env_home == nullptr || env_home[0] == '\0') {
    return Error{ErrorCode::kInvalidArgument,
                 "cannot find the vault: pass --vault or set NILKEY_PATH or HOME"};
  }
  return std::string(env_home) + "/.local/share/nilkey/default.vault";
}

int Run(std::span<const char* const> args, const Io& io) {
  const Result<ParsedArgs> parsed = ParseArgs(args, kCommands);
  if (!parsed.ok()) return ReportError(parsed.error(), io.err);
  const ParsedArgs& request = parsed.value();

  if (request.globals.help) {
    PrintUsage(io.out);
    return kExitOk;
  }
  if (request.globals.version) {
    std::fputs("nilkey " NILKEY_VERSION "\n", io.out);
    return kExitOk;
  }

  if (request.command->name == "generate") return RunGenerate(request, io);

  // The other commands arrive in the next steps of Phase 4.
  std::fprintf(io.err, "nilkey: '%.*s' is not implemented yet\n",
               static_cast<int>(request.command->name.size()), request.command->name.data());
  return kExitError;
}

}  // namespace nilkey

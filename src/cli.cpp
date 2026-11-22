#include "nilkey/cli.hpp"

#include <array>
#include <cstddef>
#include <string_view>

#include "nilkey/args.hpp"
#include "nilkey/commands.hpp"

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

// Which function runs each command. The names match kCommands.
struct Handler {
  std::string_view name;
  CommandHandler run;
};

constexpr std::array<Handler, 9> kHandlers = {{
    {"init", RunInit},
    {"add", RunAdd},
    {"get", RunGet},
    {"list", RunList},
    {"update", RunUpdate},
    {"delete", RunDelete},
    {"generate", RunGenerate},
    {"passwd", RunPasswd},
    {"doctor", RunDoctor},
}};

// Every command in the table has a handler.
static_assert(kHandlers.size() == kCommands.size());

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

  for (const Handler& handler : kHandlers) {
    if (handler.name == request.command->name) return handler.run(request, io);
  }

  // Unreachable: the static_assert above ties the two tables together.
  std::fputs("nilkey: internal error: command without a handler\n", io.err);
  return kExitError;
}

}  // namespace nilkey

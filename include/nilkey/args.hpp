#ifndef NILKEY_ARGS_HPP
#define NILKEY_ARGS_HPP

// Command line parser (SPEC.md 9). Hand written on purpose: no global state
// like getopt, and no argument reordering.
//
// Grammar: `nilkey [global options] <command> [arguments and options]`.
//   * Options are long only: `--name value`, `--name=value` or `--flag`.
//   * Global options are accepted before and after the command; a command's own
//     options only after it.
//   * `--` ends option parsing; everything after it is a positional argument.
//     A lone `-` is a positional argument.
//   * An option given twice is an error.
//
// Passwords never travel on the command line (SPEC.md 9.3), so no command has
// an option for one. Error messages are static strings and never repeat the
// offending argument: an unknown `--password=hunter2` must not be echoed to
// stderr or a log.
//
// Everything parsed here is public. Secrets are read from the terminal or
// stdin elsewhere, never from argv.

#include <cstddef>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "nilkey/result.hpp"

namespace nilkey {

struct OptionSpec {
  std::string_view name;  // Without the leading "--".
  bool takes_value;
};

struct CommandSpec {
  std::string_view name;
  std::string_view usage;    // Synopsis after "nilkey ", for --help.
  std::string_view summary;  // One line, for --help.
  std::span<const OptionSpec> options;
  std::size_t min_positionals;
  std::size_t max_positionals;
};

// Options that apply to every command (SPEC.md 9.1).
struct GlobalOptions {
  std::optional<std::string_view> vault;  // --vault <path>
  bool allow_unlocked_memory = false;
  bool help = false;
  bool version = false;
};

struct ParsedOption {
  std::string_view name;
  std::string_view value;  // Empty for flags.
};

// The views point into the argv the parser was given, which must outlive this.
struct ParsedArgs {
  GlobalOptions globals;
  const CommandSpec* command = nullptr;  // Null if no command was given.
  std::vector<std::string_view> positionals;
  std::vector<ParsedOption> options;  // The command's options, in order.

  bool Has(std::string_view name) const;
  std::optional<std::string_view> Value(std::string_view name) const;
};

// `args` excludes argv[0]. Fails with kUsage for: an unknown command or option,
// a missing or unexpected option value, a repeated option, the wrong number of
// positional arguments, or no command at all. When --help or --version is
// present, a missing command and the positional count are not errors.
[[nodiscard]] Result<ParsedArgs> ParseArgs(std::span<const char* const> args,
                                           std::span<const CommandSpec> commands);

}  // namespace nilkey

#endif  // NILKEY_ARGS_HPP

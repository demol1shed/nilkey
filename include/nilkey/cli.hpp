#ifndef NILKEY_CLI_HPP
#define NILKEY_CLI_HPP

// Command line front end (SPEC.md 9): parses the arguments and routes to the
// subcommand. main() hardens the process (SPEC.md 7.1) and then calls Run().

#include <cstdio>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "nilkey/result.hpp"

namespace nilkey {

inline constexpr int kExitOk = 0;
inline constexpr int kExitError = 1;  // The command ran and failed.
inline constexpr int kExitUsage = 2;  // The command line was wrong.

// Which vault file to use (SPEC.md 9.1): `--vault`, else $NILKEY_PATH, else
// $HOME/.local/share/nilkey/default.vault. `env_nilkey_path` and `env_home`
// are the raw getenv() results (null or empty means unset). kUsage if the
// path comes out empty; kInvalidArgument if none of the three is available.
[[nodiscard]] Result<std::string> ResolveVaultPath(std::optional<std::string_view> flag,
                                                   const char* env_nilkey_path,
                                                   const char* env_home);

// Runs one invocation; `args` excludes argv[0]. Normal output goes to `out`,
// diagnostics to `err`. Returns the process exit status.
int Run(std::span<const char* const> args, std::FILE* out, std::FILE* err);

}  // namespace nilkey

#endif  // NILKEY_CLI_HPP

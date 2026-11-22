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
inline constexpr int kExitAborted = 130;  // The user aborted (Ctrl-C, Ctrl-D); 128 + SIGINT.

// Which vault file to use (SPEC.md 9.1): `--vault`, else $NILKEY_PATH, else
// $HOME/.local/share/nilkey/default.vault. `env_nilkey_path` and `env_home`
// are the raw getenv() results (null or empty means unset). kUsage if the
// path comes out empty; kInvalidArgument if none of the three is available.
[[nodiscard]] Result<std::string> ResolveVaultPath(std::optional<std::string_view> flag,
                                                   const char* env_nilkey_path,
                                                   const char* env_home);

// Where a run writes. Secrets (a generated or stored password) must never pass
// through a stdio buffer, which would leave an unlocked, unzeroed copy in
// memory, so they are written straight to `out_fd`.
//
// In production `out` and `out_fd` are the same stream (stdout and fd 1); in
// tests they are a memory stream and a pipe. A command that writes to both
// must fflush(out) before its first raw write to `out_fd`, or the order is
// lost; no test can catch that.
struct Io {
  std::FILE* out;  // Help, version and other output that is not secret.
  std::FILE* err;  // Diagnostics.
  int out_fd;      // The descriptor behind `out`, for secrets.
};

// Runs one invocation; `args` excludes argv[0]. Returns the process exit
// status.
int Run(std::span<const char* const> args, const Io& io);

}  // namespace nilkey

#endif  // NILKEY_CLI_HPP

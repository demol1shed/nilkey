#ifndef NILKEY_COMMANDS_HPP
#define NILKEY_COMMANDS_HPP

// The subcommands (SPEC.md 9.2) and what they share. Each handler gets the
// parsed command line and the streams to write to, and returns the process exit
// status. The command table and the dispatch live in cli.cpp.

#include <cstdio>

#include "nilkey/args.hpp"
#include "nilkey/cli.hpp"
#include "nilkey/error.hpp"
#include "nilkey/secure_buffer.hpp"

namespace nilkey {

using CommandHandler = int (*)(const ParsedArgs& request, const Io& io);

// Prints `error` to `err` and returns the exit status for it: 2 for a wrong
// command line (with a pointer to --help), 1 for anything else. Only the static
// message is printed, never a value that came from the user.
int ReportError(const Error& error, std::FILE* err);

// kAllowUnlocked if --allow-unlocked-memory was given, kRequire otherwise.
MemlockPolicy PolicyFor(const GlobalOptions& globals);

int RunGenerate(const ParsedArgs& request, const Io& io);

}  // namespace nilkey

#endif  // NILKEY_COMMANDS_HPP

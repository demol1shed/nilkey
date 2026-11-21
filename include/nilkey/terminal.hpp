#ifndef NILKEY_TERMINAL_HPP
#define NILKEY_TERMINAL_HPP

// Interactive input from the controlling terminal (SPEC.md 9.3). Everything
// here opens /dev/tty and never touches stdin or stdout, so a password can
// never be taken from a pipe or a redirected stream. Prompts go to the
// terminal as well.
//
// While a line is read, the terminal keeps canonical mode (backspace works) but
// loses ECHO, and SIGINT, SIGTERM, SIGHUP, SIGQUIT and SIGTSTP are caught so
// the terminal settings are restored before the call returns kAborted. SIGKILL
// and crashes cannot be caught; if echo stays off after one, run `stty sane`.
//
// Not thread-safe (it uses process-wide signal handlers). sodium_init() must
// have been called first.

#include <cstddef>

#include "nilkey/result.hpp"
#include "nilkey/secure_buffer.hpp"

namespace nilkey {

// Longest secret, in bytes, without the line terminator.
inline constexpr std::size_t kMaxSecretSize = 1024;

// Reads one secret line with echo off. The bytes go straight into a
// SecureBuffer; embedded NUL bytes are kept (the length travels with the
// buffer). Errors: kNoTerminal (no /dev/tty), kEmptyInput (empty line),
// kInputTooLong (more than kMaxSecretSize bytes; the rest of the line is
// discarded), kAborted (a signal, or Ctrl-D at the start of a line),
// kIoError, and the SecureBuffer errors.
[[nodiscard]] Result<SecureBuffer> ReadSecret(const char* prompt, MemlockPolicy policy);

// Reads a secret twice and returns it if both entries are identical
// (compared in constant time); kInputMismatch otherwise.
[[nodiscard]] Result<SecureBuffer> ReadNewSecret(const char* prompt, const char* confirm_prompt,
                                                 MemlockPolicy policy);

// Asks a yes/no question with echo on. Only "y" and "yes" (any case) are yes;
// an empty, long or unrecognised answer is no. kNoTerminal and kAborted are
// errors, not answers.
[[nodiscard]] Result<bool> Confirm(const char* prompt);

}  // namespace nilkey

#endif  // NILKEY_TERMINAL_HPP

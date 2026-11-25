#include "nilkey/terminal.hpp"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sodium.h>
#include <termios.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <span>

#include "nilkey/fd_io.hpp"
#include "nilkey/tlv.hpp"

namespace nilkey {

namespace {

constexpr std::size_t kMaxAnswerSize = 15;  // "yes" plus slack; the buffer adds the newline.

// Signals that would otherwise leave the terminal with echo off: the process
// would die or stop without running any destructor.
constexpr std::array<int, 5> kHandledSignals = {SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGTSTP};

volatile sig_atomic_t g_signal = 0;

void OnSignal(int signo) { g_signal = signo; }

// Closes the terminal on every path. The descriptor is only read and written,
// so a failing close() cannot lose data.
class TtyFd {
 public:
  explicit TtyFd(int fd) : fd_(fd) {}
  TtyFd(const TtyFd&) = delete;
  TtyFd& operator=(const TtyFd&) = delete;
  ~TtyFd() {
    if (fd_ >= 0 && close(fd_) != 0) {
      // Nothing more to do.
    }
  }
  int get() const { return fd_; }

 private:
  int fd_;
};

// Blocks the handled signals, installs a flag-setting handler for each and
// remembers how to undo both. With the signals blocked, ReadLine() can
// unblock them atomically inside ppoll(), so a signal can never arrive
// between checking the flag and going to sleep.
class ScopedSignals {
 public:
  ScopedSignals() = default;
  ScopedSignals(const ScopedSignals&) = delete;
  ScopedSignals& operator=(const ScopedSignals&) = delete;

  [[nodiscard]] Status Install() {
    sigset_t handled;
    sigemptyset(&handled);
    for (const int signo : kHandledSignals) sigaddset(&handled, signo);
    if (sigprocmask(SIG_BLOCK, &handled, &original_mask_) != 0) {
      return make_error(ErrorCode::kInternal);
    }
    mask_saved_ = true;
    g_signal = 0;

    struct sigaction action;
    std::memset(&action, 0, sizeof action);
    action.sa_handler = OnSignal;
    sigemptyset(&action.sa_mask);
    // No SA_RESTART: a handled signal must interrupt ppoll().
    for (std::size_t i = 0; i < kHandledSignals.size(); ++i) {
      if (sigaction(kHandledSignals[i], &action, &original_actions_[i]) != 0) {
        return make_error(ErrorCode::kInternal);
      }
      ++installed_;
    }
    return Ok();
  }

  // The signal mask from before Install(): the handled signals are unblocked.
  const sigset_t& original_mask() const { return original_mask_; }

  ~ScopedSignals() {
    for (std::size_t i = 0; i < installed_; ++i) {
      if (sigaction(kHandledSignals[i], &original_actions_[i], nullptr) != 0) {
        std::abort();  // Leaving our handler installed would outlive its purpose.
      }
    }
    // A signal still pending is delivered here, with the old action in place.
    if (mask_saved_ && sigprocmask(SIG_SETMASK, &original_mask_, nullptr) != 0) std::abort();
  }

 private:
  sigset_t original_mask_{};
  std::array<struct sigaction, kHandledSignals.size()> original_actions_{};
  std::size_t installed_ = 0;
  bool mask_saved_ = false;
};

// Turns echo off (or leaves it as is) for the lifetime of the object. Applying
// the settings also discards input typed ahead (TCSAFLUSH), so stale
// keystrokes cannot answer a prompt that had not been shown yet.
class TermiosGuard {
 public:
  TermiosGuard() = default;
  TermiosGuard(const TermiosGuard&) = delete;
  TermiosGuard& operator=(const TermiosGuard&) = delete;

  [[nodiscard]] Status Apply(int fd, bool echo) {
    if (tcgetattr(fd, &saved_) != 0) return make_error(ErrorCode::kIoError);
    struct termios changed = saved_;
    if (!echo) changed.c_lflag &= static_cast<tcflag_t>(~ECHO);
    while (tcsetattr(fd, TCSAFLUSH, &changed) != 0) {
      if (errno != EINTR) return make_error(ErrorCode::kIoError);
    }
    fd_ = fd;
    return Ok();
  }

  ~TermiosGuard() {
    if (fd_ < 0) return;
    while (tcsetattr(fd_, TCSADRAIN, &saved_) != 0) {
      if (errno == EINTR) continue;
      // The caller cannot be told from a destructor, but echo may be off.
      std::fputs("warning: could not restore the terminal settings; run `stty sane`\n", stderr);
      return;
    }
  }

 private:
  int fd_ = -1;
  struct termios saved_{};
};

struct Line {
  std::size_t length;  // Bytes in the buffer, without the terminator.
  bool too_long;
};

// Reads one line into `buffer`, which must hold the longest accepted line plus
// its newline. A longer line is read to its end and thrown away, so nothing of
// it stays queued in the terminal.
Result<Line> ReadLine(int fd, std::span<std::byte> buffer, const sigset_t& wait_mask) {
  std::size_t length = 0;
  bool too_long = false;
  bool saw_data = false;
  for (;;) {
    if (g_signal != 0) return make_error(ErrorCode::kAborted);

    struct pollfd ready = {fd, POLLIN, 0};
    if (ppoll(&ready, 1, nullptr, &wait_mask) < 0) {
      if (errno == EINTR) continue;
      return make_error(ErrorCode::kIoError);
    }
    if (g_signal != 0) return make_error(ErrorCode::kAborted);

    // In canonical mode a readable terminal holds a whole line (or EOF), so
    // this read does not block.
    const ssize_t n = read(fd, buffer.data() + length, buffer.size() - length);
    if (n < 0) {
      if (errno == EINTR) continue;
      return make_error(ErrorCode::kIoError);
    }
    if (n == 0) {  // EOF: Ctrl-D on an empty line.
      if (!saw_data) return make_error(ErrorCode::kAborted);
      return Line{length, too_long};
    }
    saw_data = true;
    length += static_cast<std::size_t>(n);

    if (buffer[length - 1] == std::byte{'\n'}) return Line{length - 1, too_long};
    if (length == buffer.size()) {
      // Full without a newline: the line is too long. Drop what was read and
      // keep going until the line ends.
      too_long = true;
      sodium_memzero(buffer.data(), length);
      length = 0;
    }
  }
}

// Shows `prompt` and reads one line from the terminal into `buffer`. `echo`
// selects whether the typed characters are shown.
Result<Line> PromptAndReadLine(const char* prompt, bool echo, std::span<std::byte> buffer) {
  const int fd = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (fd < 0) return make_error(ErrorCode::kNoTerminal);
  const TtyFd tty(fd);

  // Declaration order matters: the terminal settings are restored (guard
  // destroyed first) before the signal handlers and mask are, so a signal that
  // was held back kills the process only once the terminal is back in order.
  ScopedSignals signals;
  if (const Status s = signals.Install(); !s.ok()) return s.error();
  TermiosGuard guard;
  if (const Status s = guard.Apply(fd, echo); !s.ok()) return s.error();

  const auto* text = reinterpret_cast<const std::byte*>(prompt);
  if (const Status s = WriteAll(fd, std::span<const std::byte>(text, std::strlen(prompt)));
      !s.ok()) {
    return s.error();
  }

  Result<Line> line = ReadLine(fd, buffer, signals.original_mask());

  // With echo off the Enter key was not shown; end the prompt line ourselves,
  // also after an abort, so the shell prompt does not land on it.
  if (!echo) {
    const std::byte newline{'\n'};
    const Status s = WriteAll(fd, std::span<const std::byte>(&newline, 1));
    if (line.ok() && !s.ok()) return s.error();
  }
  return line;
}

Result<SecureBuffer> ReadSecretUncleaned(const char* prompt, MemlockPolicy policy) {
  Result<SecureBuffer> line_buffer = SecureBuffer::Create(kMaxSecretSize + 1, policy);
  if (!line_buffer.ok()) return line_buffer;

  Result<ScopedWriteGuard> guard = ScopedWriteGuard::Open(line_buffer.value());
  if (!guard.ok()) return guard.error();

  const Result<Line> line = PromptAndReadLine(prompt, /*echo=*/false, guard.value().bytes());
  if (!line.ok()) return line.error();
  if (line.value().too_long) return make_error(ErrorCode::kInputTooLong);
  if (line.value().length == 0) return make_error(ErrorCode::kEmptyInput);

  return CopyToSecureBuffer(guard.value().bytes().first(line.value().length), policy);
}

}  // namespace

Result<SecureBuffer> ReadSecret(const char* prompt, MemlockPolicy policy) {
  Result<SecureBuffer> secret = ReadSecretUncleaned(prompt, policy);
  // Clears what the calls above left on the stack, on every path (SPEC.md 7.4).
  sodium_stackzero(4096);
  return secret;
}

std::size_t CountCharacters(std::span<const std::byte> text) {
  std::size_t count = 0;
  while (!text.empty()) {
    std::size_t length = 1;  // ASCII, or one byte that is not valid UTF-8.
    if (std::to_integer<unsigned>(text[0]) >= 0x80U) {
      // The shortest valid prefix after such a lead byte is exactly one sequence.
      for (std::size_t n = 2; n <= 4 && n <= text.size(); ++n) {
        if (IsValidUtf8(text.first(n))) {
          length = n;
          break;
        }
      }
    }
    text = text.subspan(length);
    ++count;
  }
  return count;
}

Result<SecureBuffer> ReadNewSecret(const char* prompt, const char* confirm_prompt,
                                   MemlockPolicy policy, std::size_t min_characters) {
  Result<SecureBuffer> first = ReadSecret(prompt, policy);
  if (!first.ok()) return first;
  {
    const Result<ScopedReadGuard> guard = ScopedReadGuard::Open(first.value());
    if (!guard.ok()) return guard.error();
    if (CountCharacters(guard.value().bytes()) < min_characters) {
      return make_error(ErrorCode::kMasterTooShort);
    }
  }
  const Result<SecureBuffer> second = ReadSecret(confirm_prompt, policy);
  if (!second.ok()) return second.error();

  bool same = false;
  {
    const Result<ScopedReadGuard> a = ScopedReadGuard::Open(first.value());
    if (!a.ok()) return a.error();
    const Result<ScopedReadGuard> b = ScopedReadGuard::Open(second.value());
    if (!b.ok()) return b.error();
    same = a.value().bytes().size() == b.value().bytes().size() &&
           sodium_memcmp(a.value().bytes().data(), b.value().bytes().data(),
                         a.value().bytes().size()) == 0;
  }
  if (!same) return make_error(ErrorCode::kInputMismatch);
  return first;
}

Result<bool> Confirm(const char* prompt) {
  // An answer is not a secret, so a plain array will do.
  std::array<std::byte, kMaxAnswerSize + 1> answer{};
  const Result<Line> line = PromptAndReadLine(prompt, /*echo=*/true, answer);
  if (!line.ok()) return line.error();
  if (line.value().too_long) return false;

  char text[kMaxAnswerSize + 1];
  const std::size_t n = line.value().length;
  for (std::size_t i = 0; i < n; ++i) {
    const char c = static_cast<char>(answer[i]);
    text[i] = (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
  }
  text[n] = '\0';
  return std::strcmp(text, "y") == 0 || std::strcmp(text, "yes") == 0;
}

}  // namespace nilkey

#include "nilkey/clipboard.hpp"

#include <fcntl.h>
#include <signal.h>
#include <sodium.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <optional>
#include <string_view>

#include "nilkey/fd_io.hpp"

extern char** environ;  // NOLINT: POSIX declares it nowhere in a header.

namespace nilkey {

namespace {

bool IsSet(const char* value) { return value != nullptr && value[0] != '\0'; }

bool IsExecutableFile(const std::string& path) {
  struct stat st;
  return stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode) &&
         access(path.c_str(), X_OK) == 0;
}

// The first PATH entry that holds an executable `name`. Only absolute entries
// count (see DetectClipboardTool).
std::optional<std::string> FindInPath(const char* path_env, std::string_view name) {
  if (!IsSet(path_env)) return std::nullopt;
  const std::string_view path(path_env);
  std::size_t start = 0;
  while (start <= path.size()) {
    std::size_t end = path.find(':', start);
    if (end == std::string_view::npos) end = path.size();
    const std::string_view dir = path.substr(start, end - start);
    if (!dir.empty() && dir.front() == '/') {
      std::string candidate(dir);
      candidate += '/';
      candidate += name;
      if (IsExecutableFile(candidate)) return candidate;
    }
    start = end + 1;
  }
  return std::nullopt;
}

static_assert(crypto_generichash_BYTES == 32, "ClipboardFingerprint holds a 32 byte digest");

// How long a clipboard tool may take. They only hand the text over (and fork
// to keep serving it), so this is generous; a stuck one is killed.
constexpr int kToolTimeoutMs = 5000;
constexpr unsigned kReadBackTimeoutSeconds = 30;

std::span<const std::byte> AsBytes(const std::string& text) {
  return {reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

// Closes `fd` if it is open, remembering a failure. Used on paths that already
// have an error to report, so a failing close cannot change the outcome.
void CloseQuietly(int fd) {
  if (fd >= 0 && close(fd) != 0) {
    // Nothing more to do.
  }
}

struct Pipe {
  int read_end = -1;
  int write_end = -1;
};

Result<Pipe> MakePipe() {
  int fds[2];
  if (pipe2(fds, O_CLOEXEC) != 0) return make_error(ErrorCode::kClipboardFailed);
  return Pipe{fds[0], fds[1]};
}

// Starts `path` with stdin from `in_fd` (or /dev/null if negative) and stdout
// to `out_fd` (or /dev/null); stderr always goes to /dev/null. The pipe ends
// are close-on-exec, so the tool gets only the one it was given. The tool runs
// in this process's environment: xclip and wl-copy need DISPLAY, XAUTHORITY,
// WAYLAND_DISPLAY and XDG_RUNTIME_DIR to find the display.
Result<pid_t> StartTool(const std::string& path, const std::vector<std::string>& args, int in_fd,
                        int out_fd) {
  std::vector<char*> argv;
  argv.push_back(const_cast<char*>(path.c_str()));
  for (const std::string& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
  argv.push_back(nullptr);

  posix_spawn_file_actions_t actions;
  if (posix_spawn_file_actions_init(&actions) != 0) return make_error(ErrorCode::kClipboardFailed);

  const bool prepared =
      (in_fd >= 0 ? posix_spawn_file_actions_adddup2(&actions, in_fd, STDIN_FILENO)
                  : posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null",
                                                     O_RDONLY, 0)) == 0 &&
      (out_fd >= 0 ? posix_spawn_file_actions_adddup2(&actions, out_fd, STDOUT_FILENO)
                   : posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null",
                                                      O_WRONLY, 0)) == 0 &&
      posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) == 0;

  pid_t pid = -1;
  const int started =
      prepared ? posix_spawn(&pid, path.c_str(), &actions, nullptr, argv.data(), environ) : -1;
  const bool destroyed = posix_spawn_file_actions_destroy(&actions) == 0;
  if (started != 0 || !destroyed) {
    if (started == 0) {  // Started, but the actions could not be released: do not leave it.
      if (kill(pid, SIGKILL) != 0) {
        // Already gone.
      }
      int ignored = 0;
      if (waitpid(pid, &ignored, 0) < 0) {
        // Nothing more to do.
      }
    }
    return make_error(ErrorCode::kClipboardFailed);
  }
  return pid;
}

void SleepMs(long ms) {
  struct timespec pause = {0, ms * 1000 * 1000};
  // An interrupted sleep only makes the next poll come earlier.
  if (nanosleep(&pause, nullptr) != 0 && errno != EINTR) {
    // Nothing more to do.
  }
}

std::int64_t NowMs() {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
  return static_cast<std::int64_t>(now.tv_sec) * 1000 + now.tv_nsec / 1000000;
}

// Waits for the tool to exit with status 0. One that is still running after
// kToolTimeoutMs is killed.
Status WaitForTool(pid_t pid) {
  const std::int64_t deadline = NowMs() + kToolTimeoutMs;
  for (;;) {
    int status = 0;
    const pid_t done = waitpid(pid, &status, WNOHANG);
    if (done == pid) {
      return WIFEXITED(status) && WEXITSTATUS(status) == 0
                 ? Ok()
                 : Status(make_error(ErrorCode::kClipboardFailed));
    }
    if (done < 0 && errno != EINTR) return make_error(ErrorCode::kClipboardFailed);
    if (NowMs() >= deadline) {
      if (kill(pid, SIGKILL) != 0) {
        // Exited in the meantime.
      }
      while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
      }
      return make_error(ErrorCode::kClipboardFailed);
    }
    SleepMs(5);
  }
}

// Ignores SIGPIPE while alive: a tool that quits without reading its input
// must make write() fail, not kill nilkey.
class SigpipeIgnored {
 public:
  SigpipeIgnored() {
    struct sigaction ignore = {};
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    active_ = sigaction(SIGPIPE, &ignore, &previous_) == 0;
  }
  SigpipeIgnored(const SigpipeIgnored&) = delete;
  SigpipeIgnored& operator=(const SigpipeIgnored&) = delete;
  ~SigpipeIgnored() {
    if (active_ && sigaction(SIGPIPE, &previous_, nullptr) != 0) {
      // Nothing more to do in a destructor.
    }
  }
  bool ok() const { return active_; }

 private:
  struct sigaction previous_ = {};
  bool active_ = false;
};

// Runs a tool that reads `input` from stdin.
Status RunWithInput(const std::string& path, const std::vector<std::string>& args,
                    std::span<const std::byte> input) {
  const SigpipeIgnored guard;
  if (!guard.ok()) return make_error(ErrorCode::kClipboardFailed);
  const Result<Pipe> pipe = MakePipe();
  if (!pipe.ok()) return pipe.error();

  const Result<pid_t> pid = StartTool(path, args, pipe.value().read_end, -1);
  CloseQuietly(pipe.value().read_end);
  if (!pid.ok()) {
    CloseQuietly(pipe.value().write_end);
    return pid.error();
  }

  const Status written = WriteAll(pipe.value().write_end, input);
  const bool closed = close(pipe.value().write_end) == 0;
  const Status exited = WaitForTool(pid.value());  // Also reaps it if writing failed.
  if (!written.ok() || !closed || !exited.ok()) return make_error(ErrorCode::kClipboardFailed);
  return Ok();
}

// Runs the paste tool and returns what it printed, at most `max_size` bytes.
Result<SecureBuffer> ReadClipboard(const ClipboardTool& tool, std::size_t max_size,
                                   MemlockPolicy policy) {
  const Result<Pipe> pipe = MakePipe();
  if (!pipe.ok()) return pipe.error();
  const Result<pid_t> pid = StartTool(tool.paste_path, tool.paste_args, -1, pipe.value().write_end);
  CloseQuietly(pipe.value().write_end);
  if (!pid.ok()) {
    CloseQuietly(pipe.value().read_end);
    return pid.error();
  }

  Result<SecureBuffer> text = ReadAllSecret(pipe.value().read_end, max_size, policy);
  CloseQuietly(pipe.value().read_end);
  const Status exited = WaitForTool(pid.value());
  if (!text.ok()) return make_error(ErrorCode::kClipboardFailed);
  if (!exited.ok()) return exited.error();
  return text;
}

}  // namespace

Result<ClipboardTool> DetectClipboardTool(const ClipboardEnv& env) {
  if (IsSet(env.wayland_display)) {
    const auto copy = FindInPath(env.path, "wl-copy");
    const auto paste = FindInPath(env.path, "wl-paste");
    if (!copy || !paste) return make_error(ErrorCode::kNoClipboardTool);
    return ClipboardTool{*copy, *paste, {}, {"--no-newline"}, {"--clear"}, ""};
  }
  if (!IsSet(env.display)) return make_error(ErrorCode::kNoClipboardTool);

  if (const auto xclip = FindInPath(env.path, "xclip")) {
    const std::vector<std::string> copy = {"-selection", "clipboard", "-in"};
    // xclip has no clear option; copying nothing takes the selection over.
    return ClipboardTool{*xclip, *xclip, copy, {"-selection", "clipboard", "-out"}, copy, ""};
  }
  if (const auto xsel = FindInPath(env.path, "xsel")) {
    // Without --clipboard, xsel works on PRIMARY and would never see the
    // text that was copied.
    return ClipboardTool{*xsel,
                         *xsel,
                         {"--clipboard", "--input"},
                         {"--clipboard", "--output"},
                         {"--clipboard", "--clear"},
                         ""};
  }
  return make_error(ErrorCode::kNoClipboardTool);
}

Result<ClipboardFingerprint> FingerprintOf(std::span<const std::byte> text) {
  ClipboardFingerprint fingerprint{{}, text.size()};
  if (crypto_generichash(fingerprint.digest.data(), fingerprint.digest.size(),
                         reinterpret_cast<const unsigned char*>(text.data()), text.size(), nullptr,
                         0) != 0) {
    return make_error(ErrorCode::kCryptoFailed);
  }
  return fingerprint;
}

Status CopyToClipboard(const ClipboardTool& tool, std::span<const std::byte> text) {
  return RunWithInput(tool.copy_path, tool.copy_args, text);
}

Status ClearClipboard(const ClipboardTool& tool) {
  return RunWithInput(tool.copy_path, tool.clear_args, AsBytes(tool.clear_input));
}

Result<bool> RunCleaner(const ClipboardTool& tool, const ClipboardFingerprint& fingerprint,
                        unsigned seconds, MemlockPolicy policy) {
  if (seconds > 0) {
    struct timespec until;
    if (clock_gettime(CLOCK_MONOTONIC, &until) != 0) return make_error(ErrorCode::kInternal);
    until.tv_sec += static_cast<time_t>(seconds);
    // EINTR: sleep on until the same absolute time.
    int rc = 0;
    while ((rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &until, nullptr)) == EINTR) {
    }
    if (rc != 0) return make_error(ErrorCode::kInternal);
  }

  // A tool that hangs while printing would otherwise keep this process alive
  // for ever; SIGALRM ends it (the default action).
  alarm(kReadBackTimeoutSeconds);
  Result<SecureBuffer> current = ReadClipboard(tool, fingerprint.length, policy);
  alarm(0);
  if (!current.ok()) return current.error();

  // Unequal means somebody copied something else: not ours to clear.
  Result<ClipboardFingerprint> now = [&]() -> Result<ClipboardFingerprint> {
    const Result<ScopedReadGuard> guard = ScopedReadGuard::Open(current.value());
    if (!guard.ok()) return guard.error();
    return FingerprintOf(guard.value().bytes());
  }();
  if (!now.ok()) return now.error();
  const bool same = now.value().length == fingerprint.length &&
                    sodium_memcmp(now.value().digest.data(), fingerprint.digest.data(),
                                  fingerprint.digest.size()) == 0;
  sodium_memzero(now.value().digest.data(), now.value().digest.size());
  if (!same) return false;

  if (const Status cleared = ClearClipboard(tool); !cleared.ok()) return cleared.error();
  return true;
}

}  // namespace nilkey

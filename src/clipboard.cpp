#include "nilkey/clipboard.hpp"

#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sodium.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdio>
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

// The cleaner's promise is "cleared N seconds after the copy", and a laptop that
// is closed in between must not stretch that: CLOCK_BOOTTIME keeps counting
// while the machine is suspended, CLOCK_MONOTONIC does not. The reading and the
// sleep have to use the same clock, or the absolute time is meaningless.
constexpr clockid_t kCleanerClock = CLOCK_BOOTTIME;

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

// Waits for the tool to exit with status 0. One that is still running at
// `deadline` (a NowMs() time) is killed.
Status WaitForTool(pid_t pid, std::int64_t deadline) {
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

// Writes all of `data` to the pipe `fd`, giving up at `deadline` (a NowMs()
// time). A plain blocking write would wait for ever on a tool that never reads
// its input once the text no longer fits in the pipe's buffer. Only this end of
// the pipe is made non-blocking; the other end belongs to the tool.
Status WriteWithin(int fd, std::span<const std::byte> data, std::int64_t deadline) {
  const int flags = fcntl(fd, F_GETFL);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
    return make_error(ErrorCode::kClipboardFailed);
  }
  std::size_t done = 0;
  while (done < data.size()) {
    const ssize_t n = write(fd, data.data() + done, data.size() - done);
    if (n > 0) {
      done += static_cast<std::size_t>(n);
      continue;
    }
    if (n < 0 && errno == EINTR) continue;
    if (n < 0 && errno == EAGAIN) {
      const std::int64_t left = deadline - NowMs();
      if (left <= 0) return make_error(ErrorCode::kClipboardFailed);
      // Whatever poll() reports, write again: a reader that is gone shows up as
      // POLLERR, not POLLOUT, and write() then fails with EPIPE at once.
      struct pollfd waiting = {fd, POLLOUT, 0};
      if (poll(&waiting, 1, static_cast<int>(left)) < 0 && errno != EINTR) {
        return make_error(ErrorCode::kClipboardFailed);
      }
      continue;
    }
    return make_error(ErrorCode::kClipboardFailed);  // EPIPE, or no progress.
  }
  return Ok();
}

// Runs a tool that reads `input` from stdin.
Status RunWithInput(const std::string& path, const std::vector<std::string>& args,
                    std::span<const std::byte> input) {
  const SigpipeIgnored guard;
  if (!guard.ok()) return make_error(ErrorCode::kClipboardFailed);
  // Writing and waiting share one time limit.
  const std::int64_t deadline = NowMs() + kToolTimeoutMs;
  const Result<Pipe> pipe = MakePipe();
  if (!pipe.ok()) return pipe.error();

  const Result<pid_t> pid = StartTool(path, args, pipe.value().read_end, -1);
  CloseQuietly(pipe.value().read_end);
  if (!pid.ok()) {
    CloseQuietly(pipe.value().write_end);
    return pid.error();
  }

  const Status written = WriteWithin(pipe.value().write_end, input, deadline);
  const bool closed = close(pipe.value().write_end) == 0;
  // Also reaps the tool if writing failed (and kills it if it is still there
  // once the time is up).
  const Status exited = WaitForTool(pid.value(), deadline);
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
  const Status exited = WaitForTool(pid.value(), NowMs() + kToolTimeoutMs);
  if (!text.ok()) return make_error(ErrorCode::kClipboardFailed);
  if (!exited.ok()) return exited.error();
  return text;
}

constexpr int kReadyTimeoutMs = 2000;

// The detached process. Never returns.
[[noreturn]] void CleanerProcess(const ClipboardTool& tool,
                                 const ClipboardFingerprint& fingerprint, unsigned seconds,
                                 MemlockPolicy policy, const sigset_t& inherited_mask,
                                 int ready_fd) {
  // The terminal's hang-up and keyboard signals must not stop the cleaner. The
  // parent blocked SIGHUP before the fork, so one that arrived in between is
  // still pending and is dropped when it is ignored here.
  for (const int signo : {SIGHUP, SIGINT, SIGQUIT, SIGTSTP}) {
    struct sigaction ignore = {};
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    if (sigaction(signo, &ignore, nullptr) != 0) _exit(1);
  }
  if (setsid() < 0) _exit(1);
  if (pthread_sigmask(SIG_SETMASK, &inherited_mask, nullptr) != 0) _exit(1);

  const int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
  if (null_fd < 0) _exit(1);
  if (dup2(null_fd, STDIN_FILENO) < 0 || dup2(null_fd, STDOUT_FILENO) < 0 ||
      dup2(null_fd, STDERR_FILENO) < 0) {
    _exit(1);
  }

  const char up = 1;
  ssize_t sent = -1;
  while ((sent = write(ready_fd, &up, 1)) < 0 && errno == EINTR) {
  }
  if (sent != 1) _exit(1);

  // Nothing else may stay open: the terminal, the pipe above, whatever the
  // parent had.
  if (close_range(3, UINT_MAX, 0) != 0) {
    for (int fd = 3; fd < 1024; ++fd) {
      if (close(fd) != 0 && errno != EBADF) _exit(1);
    }
  }

  const Result<bool> done = RunCleaner(tool, fingerprint, seconds, policy);
  // The result has nobody to go to; _exit() runs no atexit handlers and no
  // leak checks, and does not touch any stdio buffer.
  _exit(done.ok() ? 0 : 1);
}

// Waits up to kReadyTimeoutMs for the cleaner's first byte.
bool CleanerIsUp(int ready_fd) {
  struct pollfd waiting = {ready_fd, POLLIN, 0};
  const std::int64_t deadline = NowMs() + kReadyTimeoutMs;
  for (;;) {
    const std::int64_t left = deadline - NowMs();
    if (left <= 0) return false;
    const int r = poll(&waiting, 1, static_cast<int>(left));
    if (r < 0 && errno == EINTR) continue;
    if (r <= 0) return false;
    char byte = 0;
    ssize_t got = -1;
    while ((got = read(ready_fd, &byte, 1)) < 0 && errno == EINTR) {
    }
    return got == 1;
  }
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
    if (clock_gettime(kCleanerClock, &until) != 0) return make_error(ErrorCode::kInternal);
    until.tv_sec += static_cast<time_t>(seconds);
    // EINTR: sleep on until the same absolute time.
    int rc = 0;
    while ((rc = clock_nanosleep(kCleanerClock, TIMER_ABSTIME, &until, nullptr)) == EINTR) {
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

Status StartCleaner(const ClipboardTool& tool, const ClipboardFingerprint& fingerprint,
                    unsigned seconds, MemlockPolicy policy) {
  // First of all: fork() copies the stack below this frame too, and the frames
  // that were used for the secret (hashing, writing it to the tool) have not
  // been overwritten since.
  sodium_stackzero(4096);

  // Output that is still buffered must not be written a second time by a child.
  if (std::fflush(nullptr) != 0) return make_error(ErrorCode::kIoError);

  const Result<Pipe> ready = MakePipe();
  if (!ready.ok()) return make_error(ErrorCode::kIoError);
  // The child redirects 0-2 and writes to this pipe; it must not be one of them.
  if (ready.value().read_end <= STDERR_FILENO || ready.value().write_end <= STDERR_FILENO) {
    CloseQuietly(ready.value().read_end);
    CloseQuietly(ready.value().write_end);
    return make_error(ErrorCode::kIoError);
  }

  // SIGHUP is blocked across the fork: until the child has its own session it
  // is still in the parent's process group, and a hang-up sent to that group
  // (the terminal closing, the session leader exiting) would kill it before it
  // could do its job.
  sigset_t hangup;
  sigset_t before;
  sigemptyset(&hangup);
  sigaddset(&hangup, SIGHUP);
  if (pthread_sigmask(SIG_BLOCK, &hangup, &before) != 0) {
    CloseQuietly(ready.value().read_end);
    CloseQuietly(ready.value().write_end);
    return make_error(ErrorCode::kIoError);
  }

  const pid_t pid = fork();
  if (pid == 0) {
    CleanerProcess(tool, fingerprint, seconds, policy, before, ready.value().write_end);
  }
  const bool restored = pthread_sigmask(SIG_SETMASK, &before, nullptr) == 0;
  CloseQuietly(ready.value().write_end);
  if (pid < 0 || !restored) {
    CloseQuietly(ready.value().read_end);
    if (pid > 0 && kill(pid, SIGKILL) == 0) {
      int status = 0;
      while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
      }
    }
    return make_error(ErrorCode::kIoError);
  }

  const bool up = CleanerIsUp(ready.value().read_end);
  CloseQuietly(ready.value().read_end);
  if (!up) {
    if (kill(pid, SIGKILL) != 0) {
      // Already gone.
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    return make_error(ErrorCode::kClipboardFailed);
  }
  return Ok();
}

}  // namespace nilkey

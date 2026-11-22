#ifndef NILKEY_TEST_PTY_HARNESS_HPP
#define NILKEY_TEST_PTY_HARNESS_HPP

// Runs a function, or a program, in a child process whose terminal is a
// pseudo-terminal the test controls, so code that reads /dev/tty can be tested
// for real.
//
// A function reports its result through its exit status (one code per check)
// and never prints values, so a failing test cannot leak a secret. A missing
// pty makes the test fail loudly instead of being skipped. A program is judged
// by its exit status and its output.

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace nilkey::test {

class PtyChild {
 public:
  // Forks a child that becomes a session leader, uses the pty slave as stdin,
  // stdout and stderr, and exits with the value body() returns. With
  // `controlling_tty` false the slave is not made the controlling terminal, so
  // opening /dev/tty fails in the child.
  static PtyChild Start(int (*body)(), bool controlling_tty = true) {
    return Spawn(controlling_tty, body);
  }

  // What a program started with StartExec() gets besides the terminal.
  struct ExecOptions {
    const char* stdin_path = nullptr;   // A file to read as stdin, instead of the terminal.
    const char* stdout_path = nullptr;  // A file (mode 0600) that receives stdout.
    bool no_memlock = false;            // RLIMIT_MEMLOCK of 0: locking memory fails.
    // Changes to the program's environment, applied in this order: the names
    // in env_unset are removed, then each pair in env_set is set.
    std::vector<std::string> env_unset;
    std::vector<std::pair<std::string, std::string>> env_set;
  };

  // Runs `program` with `args` (args[0] is the program name). Prompts and
  // messages on stderr and /dev/tty appear in output(). Files, not pipes, carry
  // stdin and stdout: a parent that writes a large stdin before the program asks
  // for it would block against a child that waits for the terminal.
  static PtyChild StartExec(const char* program, const std::vector<std::string>& args) {
    return StartExec(program, args, ExecOptions{});
  }
  static PtyChild StartExec(const char* program, const std::vector<std::string>& args,
                            const ExecOptions& options) {
    std::vector<char*> argv;
    for (const std::string& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
    argv.push_back(nullptr);

    return Spawn(/*controlling_tty=*/true, [&]() -> int {
      if (options.stdin_path != nullptr) {
        const int in = open(options.stdin_path, O_RDONLY | O_CLOEXEC);
        if (in < 0 || dup2(in, 0) < 0) return 127;
      }
      if (options.stdout_path != nullptr) {
        const int out = open(options.stdout_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (out < 0 || dup2(out, 1) < 0) return 127;
      }
      if (options.no_memlock) {
        const struct rlimit none = {0, 0};
        if (setrlimit(RLIMIT_MEMLOCK, &none) != 0) return 127;
      }
      for (const std::string& name : options.env_unset) {
        if (unsetenv(name.c_str()) != 0) return 127;
      }
      for (const auto& [name, value] : options.env_set) {
        if (setenv(name.c_str(), value.c_str(), 1) != 0) return 127;
      }
      execv(program, argv.data());
      return 126;  // exec failed
    });
  }

  PtyChild(const PtyChild&) = delete;
  PtyChild& operator=(const PtyChild&) = delete;

  ~PtyChild() {
    if (pid_ > 0 && !reaped_) {
      kill(pid_, SIGKILL);
      int status = 0;
      waitpid(pid_, &status, 0);
    }
    if (close(master_) != 0) {
      // Nothing more to do in a destructor.
    }
  }

  // Reads what the child printed until it contains `text`. False on timeout
  // or if the child's output ended first.
  bool WaitFor(const char* text, int timeout_ms) {
    const Deadline deadline(timeout_ms);
    for (;;) {
      if (output_.find(text) != std::string::npos) return true;
      if (eof_ || deadline.Expired()) return false;
      ReadSome(kStepMs);
    }
  }

  // Types bytes at the terminal (NUL, Ctrl-C = "\x03" and Ctrl-D = "\x04"
  // included, which is why it takes a string_view and not a C string).
  void Send(std::string_view bytes) {
    std::size_t done = 0;
    while (done < bytes.size()) {
      const ssize_t n = write(master_, bytes.data() + done, bytes.size() - done);
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) Die("write to the pty failed");
      done += static_cast<std::size_t>(n);
    }
  }

  // Whether the terminal currently echoes typed characters. On Linux,
  // tcgetattr() on the master returns the slave's settings.
  bool EchoEnabled() const {
    struct termios t;
    if (tcgetattr(master_, &t) != 0) Die("tcgetattr on the pty failed");
    return (t.c_lflag & ECHO) != 0;
  }

  void Kill(int signo) const { kill(pid_, signo); }

  // True while the child has not exited. Collects its exit if it has, so a
  // later Wait() still reports it.
  bool Running() {
    if (pid_ <= 0 || reaped_) return false;
    int status = 0;
    const pid_t r = waitpid(pid_, &status, WNOHANG);
    if (r == pid_) {
      reaped_ = true;
      status_ = status;
      return false;
    }
    return true;
  }

  // Reads what the child prints for `duration_ms`, to let it get on with
  // things (or to show that it does not).
  void Pump(int duration_ms) {
    const Deadline deadline(duration_ms);
    while (!eof_ && !deadline.Expired()) ReadSome(kStepMs);
  }

  // Waits for the child to exit and returns its exit status, or minus the
  // signal number if a signal killed it. Returns -1000 (after killing the
  // child) on timeout. Collects the remaining output first, so output() is
  // complete afterwards.
  int Wait(int timeout_ms) {
    const Deadline deadline(timeout_ms);
    while (!reaped_) {
      const pid_t r = waitpid(pid_, &status_, WNOHANG);
      if (r == pid_) {
        reaped_ = true;
        break;
      }
      if (r < 0 && errno != EINTR) Die("waitpid failed");
      if (deadline.Expired()) {
        kill(pid_, SIGKILL);
        waitpid(pid_, &status_, 0);
        pid_ = -1;
        return -1000;
      }
      ReadSome(kStepMs);
    }
    pid_ = -1;
    while (!eof_) ReadSome(kStepMs);
    const int result = WIFEXITED(status_) ? WEXITSTATUS(status_) : -WTERMSIG(status_);
    // The status identifies a failed check in the child; it is never a secret.
    if (result != 0) std::fprintf(stderr, "pty harness: child ended with status %d\n", result);
    return result;
  }

  // Everything the child has printed so far. For assertions about what must
  // not be there; never print it.
  const std::string& output() const { return output_; }

 private:
  static constexpr int kStepMs = 50;

  // Wall-clock limit. Counting loop iterations would not do: once the child has
  // closed the terminal, poll() returns at once, so the iterations of a fixed
  // count can pass in microseconds before waitpid() sees the exit.
  class Deadline {
   public:
    explicit Deadline(int timeout_ms)
        : end_(std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms)) {}
    bool Expired() const { return std::chrono::steady_clock::now() >= end_; }

   private:
    std::chrono::steady_clock::time_point end_;
  };

  // The common part of Start() and StartExec(): the pty, the fork and the
  // child's setup. `body` runs in the child once its terminal is in place.
  template <typename Body>
  static PtyChild Spawn(bool controlling_tty, Body body) {
    // O_NOCTTY: the test process itself must never acquire this terminal.
    const int master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0) Die("posix_openpt failed (no pty available)");
    char slave_name[128];
    if (grantpt(master) != 0 || unlockpt(master) != 0 ||
        ptsname_r(master, slave_name, sizeof slave_name) != 0) {
      Die("cannot set up the pty");
    }

    const pid_t pid = fork();
    if (pid < 0) Die("fork failed");
    if (pid == 0) {
      if (close(master) != 0) _exit(120);
      if (setsid() < 0) _exit(121);
      // Without O_NOCTTY a session leader would acquire the terminal on open.
      const int slave = open(slave_name, O_RDWR | O_NOCTTY);
      if (slave < 0) _exit(122);
      if (controlling_tty && ioctl(slave, TIOCSCTTY, 0) != 0) _exit(123);
      if (dup2(slave, 0) < 0 || dup2(slave, 1) < 0 || dup2(slave, 2) < 0) _exit(124);
      if (slave > 2 && close(slave) != 0) _exit(125);
      _exit(body());  // _exit: no atexit handlers, no sanitizer leak check.
    }
    return PtyChild(master, pid);
  }

  PtyChild(int master, pid_t pid) : master_(master), pid_(pid) {}

  [[noreturn]] static void Die(const char* message) {
    std::fprintf(stderr, "pty harness: %s\n", message);
    std::abort();
  }

  // Appends what the child printed. Once the child has exited and closed its
  // side, Linux reports the end of the stream as EIO on the master.
  void ReadSome(int timeout_ms) {
    if (eof_) {
      // Nothing more will come; poll() would return at once, so just wait.
      poll(nullptr, 0, 2);
      return;
    }
    struct pollfd ready = {master_, POLLIN, 0};
    const int r = poll(&ready, 1, timeout_ms);
    if (r < 0 && errno != EINTR) Die("poll on the pty failed");
    if (r <= 0) return;
    char chunk[4096];
    const ssize_t n = read(master_, chunk, sizeof chunk);
    if (n > 0) {
      output_.append(chunk, static_cast<std::size_t>(n));
    } else if (n == 0 || errno == EIO) {
      eof_ = true;
    } else if (errno != EINTR) {
      Die("read from the pty failed");
    }
  }

  int master_;
  pid_t pid_;
  bool eof_ = false;
  bool reaped_ = false;  // waitpid() has returned the exit status.
  int status_ = 0;
  std::string output_;
};

}  // namespace nilkey::test

#endif  // NILKEY_TEST_PTY_HARNESS_HPP

// The command get, end to end: the real command line, in a child process on a
// pseudo-terminal, against a vault file on disk, with a fake xclip (see
// fake_clipboard.hpp) standing in for the desktop. The real clipboard is never
// touched. The child is nilkey_e2e; the helpers are shared with the other
// end-to-end tests (e2e_support.hpp). The passwords here are test data.

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include "e2e_support.hpp"
#include "fake_clipboard.hpp"
#include "nilkey/store.hpp"
#include "pty_harness.hpp"
#include "temp_dir.hpp"
#include "test_framework.hpp"

using nilkey::test::ModeOf;
using nilkey::test::PtyChild;
using nilkey::test::TempDir;

using namespace nilkey::test::e2e;

namespace {

// The fake desktop for the CLI under test: a directory with the fake xclip,
// first in PATH, an X11 display and no Wayland.
class Desktop {
 public:
  Desktop() : ok_(nilkey::test::InstallFakeXclip(dir_)) {
    env_.unset = {"WAYLAND_DISPLAY", "FAKE_FAIL", "FAKE_NOREAD", "FAKE_HANG"};
    env_.set = {{"PATH", dir_.dir() + ":/usr/bin:/bin"},
                {"DISPLAY", ":fake"},
                {"FAKE_CLIP", Clip()},
                {"FAKE_LOG", Log()}};
  }
  bool ok() const { return ok_; }
  const CliEnv& env() const { return env_; }
  std::string Clip() const { return dir_.Path("clip"); }
  std::string Log() const { return dir_.Path("log"); }
  std::string ClipText() const { return TextOf(ReadFile(Clip())); }
  std::string LogText() const { return TextOf(ReadFile(Log())); }
  bool SetClip(std::string_view text) const { return WriteFile(Clip(), text); }

 private:
  TempDir dir_;
  bool ok_;
  CliEnv env_;
};

// Polls until the fake clipboard is empty, for at most `limit_ms` (real time).
bool BecomesEmpty(const Desktop& desktop, int limit_ms) {
  const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(limit_ms);
  while (std::chrono::steady_clock::now() < end) {
    if (desktop.ClipText().empty()) return true;
    usleep(50 * 1000);
  }
  return desktop.ClipText().empty();
}

// The processes whose command line contains `needle`, other than this one. The
// cleaner is a fork of the CLI, so it has the CLI's command line.
std::vector<pid_t> ProcessesWithArgument(const std::string& needle) {
  std::vector<pid_t> found;
  DIR* const proc = opendir("/proc");
  if (proc == nullptr) return found;
  while (const dirent* entry = readdir(proc)) {
    const pid_t pid = static_cast<pid_t>(std::atoi(entry->d_name));
    if (pid <= 0 || pid == getpid()) continue;
    Bytes cmdline;
    if (!nilkey::test::Slurp(std::string("/proc/") + entry->d_name + "/cmdline", cmdline)) continue;
    if (TextOf(cmdline).find(needle) != std::string::npos) found.push_back(pid);
  }
  if (closedir(proc) != 0) found.clear();
  return found;
}

// Fields of /proc/<pid>/stat after the command name: state, ppid, pgrp, session.
bool StatOf(pid_t pid, char& state, long& session) {
  Bytes raw;
  if (!nilkey::test::Slurp("/proc/" + std::to_string(pid) + "/stat", raw)) return false;
  const std::string text = TextOf(raw);
  const std::size_t close_paren = text.rfind(')');
  if (close_paren == std::string::npos) return false;
  long ppid = 0;
  long pgrp = 0;
  return std::sscanf(text.c_str() + close_paren + 2, "%c %ld %ld %ld", &state, &ppid, &pgrp,
                     &session) == 4;
}

// The sanitizer runtimes intercept mlock() and report success without locking
// anything (SPEC.md 7.4), so VmLck can only be checked in the other build.
#if defined(__SANITIZE_ADDRESS__)
#define NILKEY_TEST_UNDER_SANITIZER 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define NILKEY_TEST_UNDER_SANITIZER 1
#endif
#endif

#ifndef NILKEY_TEST_UNDER_SANITIZER
// The memory this process has locked, in KiB (VmLck in /proc/<pid>/status); -1
// if it cannot be read.
long LockedKiB(pid_t pid) {
  Bytes raw;
  if (!nilkey::test::Slurp("/proc/" + std::to_string(pid) + "/status", raw)) return -1;
  const std::string text = TextOf(raw);
  const std::size_t at = text.find("VmLck:");
  long kib = -1;
  if (at == std::string::npos || std::sscanf(text.c_str() + at + 6, "%ld", &kib) != 1) return -1;
  return kib;
}
#endif

bool IsGone(pid_t pid) {
  char state = 0;
  long session = 0;
  return !StatOf(pid, state, session) || state == 'Z';
}

Run Get(const TempDir& dir, const std::string& vault, const Desktop& desktop,
        const std::vector<std::string>& options, const std::vector<Answer>& answers) {
  std::vector<std::string> args = {"get"};
  args.insert(args.end(), options.begin(), options.end());
  return RunCli(dir, vault, args, answers, nullptr, &desktop.env());
}

// A vault with `alpha` (all fields) and `beta` (a password only).
bool Seed(const TempDir& dir, const std::string& vault, const std::string& master) {
  return MakeVault(dir, vault, master) &&
         AddRecord(dir, vault, master, "alpha", "pw-alpha",
                   {"--username", "alice", "--url", "https://alpha.example"})
                 .status == 0 &&
         AddRecord(dir, vault, master, "beta", "pw-beta").status == 0;
}

}  // namespace

// The parent must come back before the text is cleared, and the cleaner must
// still do its job: the clipboard holds the text right after the command has
// ended and is empty later. The test child is a session leader, so when it
// exits the kernel hangs up its process group; the cleaner has to survive that.
NILKEY_TEST(get_copies_to_the_clipboard_and_a_detached_cleaner_clears_it_later) {
  TempDir dir;
  Desktop desktop;
  NILKEY_EXPECT(dir.ok() && desktop.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass g1";
  NILKEY_EXPECT(Seed(dir, vault, master));

  const Run run = Get(dir, vault, desktop, {"alpha", "--timeout", "5"}, {{kMasterPrompt, master}});
  NILKEY_EXPECT(run.answered);
  NILKEY_EXPECT(run.status == 0);
  NILKEY_EXPECT(run.out.empty());
  NILKEY_EXPECT(Has(run.terminal,
                    "Copied the password of \"alpha\" to the clipboard; it is cleared in 5 seconds."));
  NILKEY_EXPECT(!Has(run.terminal, "pw-alpha"));
  NILKEY_EXPECT(!Has(run.terminal, master));

  // The command is over; the text is still there (it was not waited for) ...
  NILKEY_EXPECT(desktop.ClipText() == "pw-alpha");
  NILKEY_EXPECT(Has(desktop.LogText(), "-selection clipboard -in"));
  // ... and goes away by itself.
  NILKEY_EXPECT(BecomesEmpty(desktop, 20000));
}

NILKEY_TEST(the_cleaner_does_not_clear_what_was_copied_in_the_meantime) {
  TempDir dir;
  Desktop desktop;
  NILKEY_EXPECT(dir.ok() && desktop.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass g2";
  NILKEY_EXPECT(Seed(dir, vault, master));

  const Run run = Get(dir, vault, desktop, {"alpha", "--timeout", "1"}, {{kMasterPrompt, master}});
  NILKEY_EXPECT(run.status == 0);
  NILKEY_EXPECT(desktop.SetClip("copied by someone else"));
  usleep(3500 * 1000);  // Well past the time the cleaner was given.
  NILKEY_EXPECT(desktop.ClipText() == "copied by someone else");
}

NILKEY_TEST(get_can_copy_any_field) {
  TempDir dir;
  Desktop desktop;
  NILKEY_EXPECT(dir.ok() && desktop.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass g3";
  NILKEY_EXPECT(Seed(dir, vault, master));
  NILKEY_EXPECT(SeedRecord(vault, master, "gamma", "", "x", "line one\nline two"));

  const struct {
    const char* record;
    const char* field;
    const char* expected;
  } cases[] = {{"alpha", "username", "alice"},
               {"alpha", "url", "https://alpha.example"},
               {"alpha", "password", "pw-alpha"},
               {"gamma", "notes", "line one\nline two"}};
  for (const auto& c : cases) {
    const Run run = Get(dir, vault, desktop, {c.record, "--field", c.field, "--timeout", "3"},
                        {{kMasterPrompt, master}});
    NILKEY_EXPECT(run.status == 0);
    NILKEY_EXPECT(Has(run.terminal, std::string("Copied the ") + c.field + " of "));
    NILKEY_EXPECT(desktop.ClipText() == c.expected);
  }
}

NILKEY_TEST(a_value_with_nul_and_utf8_bytes_goes_over_unchanged) {
  TempDir dir;
  Desktop desktop;
  NILKEY_EXPECT(dir.ok() && desktop.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass g4";
  NILKEY_EXPECT(MakeVault(dir, vault, master));
  const std::string password("pa\0ss \xC3\xA9 \xF0\x9F\x94\x91", 12);
  NILKEY_EXPECT(SeedRecord(vault, master, "odd", "", password, ""));

  NILKEY_EXPECT(Get(dir, vault, desktop, {"odd", "--timeout", "3"}, {{kMasterPrompt, master}})
                    .status == 0);
  NILKEY_EXPECT(desktop.ClipText() == password);

  // --print writes the same bytes, with nothing added, to a file.
  const Run printed = Get(dir, vault, desktop, {"odd", "--print"}, {{kMasterPrompt, master}});
  NILKEY_EXPECT(printed.status == 0);
  NILKEY_EXPECT(printed.out == password);
}

NILKEY_TEST(print_writes_only_the_value_to_stdout_and_needs_no_clipboard_tool) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass g5";
  NILKEY_EXPECT(Seed(dir, vault, master));

  // A PATH without any clipboard tool and no display at all.
  CliEnv bare;
  bare.unset = {"WAYLAND_DISPLAY", "DISPLAY"};
  bare.set = {{"PATH", dir.dir()}};
  const Run run = RunCli(dir, vault, {"get", "alpha", "--print"}, {{kMasterPrompt, master}},
                         nullptr, &bare);
  NILKEY_EXPECT(run.status == 0);
  NILKEY_EXPECT(run.out == "pw-alpha");  // No line break: stdout is a file.
  NILKEY_EXPECT(!Has(run.terminal, "pw-alpha"));
  NILKEY_EXPECT(!Has(run.terminal, master));

  const Run user = RunCli(dir, vault, {"get", "alpha", "--print", "--field", "username"},
                          {{kMasterPrompt, master}}, nullptr, &bare);
  NILKEY_EXPECT(user.status == 0 && user.out == "alice");

  // An empty field prints nothing and is not an error.
  const Run empty = RunCli(dir, vault, {"get", "beta", "--print", "--field", "url"},
                           {{kMasterPrompt, master}}, nullptr, &bare);
  NILKEY_EXPECT(empty.status == 0 && empty.out.empty());
}

NILKEY_TEST(bad_options_are_refused_before_any_prompt) {
  TempDir dir;
  Desktop desktop;
  NILKEY_EXPECT(dir.ok() && desktop.ok());
  const std::string vault = dir.Path("v.vault");
  NILKEY_EXPECT(Seed(dir, vault, "master pass g6"));
  NILKEY_EXPECT(desktop.SetClip("untouched"));

  const std::vector<std::vector<std::string>> bad = {
      {"alpha", "--field", "bogus"},
      {"alpha", "--field", ""},
      {"alpha", "--timeout", "0"},
      {"alpha", "--timeout", "3601"},
      {"alpha", "--timeout", "abc"},
      {"alpha", "--timeout", ""},
      {"alpha", "--timeout", "-5"},
      {"alpha", "--timeout", "10x"},
      {"alpha", "--print", "--timeout", "5"},
      {"", "--print"},
      {"\xFF", "--print"},
  };
  for (const std::vector<std::string>& options : bad) {
    const Run run = Get(dir, vault, desktop, options, {});
    NILKEY_EXPECT(run.status == 2);
    NILKEY_EXPECT(!Has(run.terminal, kMasterPrompt));
  }
  NILKEY_EXPECT(desktop.ClipText() == "untouched");
  NILKEY_EXPECT(desktop.LogText().empty());  // The tool was never run.
}

// The longest timeout is accepted, and the cleaner that stays behind is a
// process of its own: the leader of a new session, which a plain SIGTERM ends.
NILKEY_TEST(the_largest_timeout_is_accepted_and_the_cleaner_is_a_session_of_its_own) {
  TempDir dir;
  Desktop desktop;
  NILKEY_EXPECT(dir.ok() && desktop.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass g7";
  NILKEY_EXPECT(Seed(dir, vault, master));

  const Run run = Get(dir, vault, desktop, {"alpha", "--timeout", "3600"},
                      {{kMasterPrompt, master}});
  NILKEY_EXPECT(run.status == 0);
  NILKEY_EXPECT(Has(run.terminal, "it is cleared in 3600 seconds."));

  const std::vector<pid_t> cleaners = ProcessesWithArgument(vault);
  NILKEY_EXPECT(cleaners.size() == 1);
  const pid_t cleaner = cleaners[0];
  char state = 0;
  long session = 0;
  NILKEY_EXPECT(StatOf(cleaner, state, session));
  NILKEY_EXPECT(session == cleaner);  // setsid(): no terminal, no shared process group.
#ifndef NILKEY_TEST_UNDER_SANITIZER
  // It keeps the digest of the copied text for the whole wait, out of swap.
  NILKEY_EXPECT(LockedKiB(cleaner) > 0);
#endif
  NILKEY_EXPECT(kill(cleaner, SIGTERM) == 0);
  bool gone = false;
  for (int i = 0; i < 100 && !gone; ++i) {
    gone = IsGone(cleaner);
    if (!gone) usleep(50 * 1000);
  }
  NILKEY_EXPECT(gone);
}

NILKEY_TEST(an_empty_field_is_not_copied) {
  TempDir dir;
  Desktop desktop;
  NILKEY_EXPECT(dir.ok() && desktop.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass g8";
  NILKEY_EXPECT(Seed(dir, vault, master));
  NILKEY_EXPECT(desktop.SetClip("what was there"));

  const Run run = Get(dir, vault, desktop, {"beta", "--field", "username"},
                      {{kMasterPrompt, master}});
  NILKEY_EXPECT(run.status == 1);
  NILKEY_EXPECT(Has(run.terminal, "the field is empty"));
  NILKEY_EXPECT(desktop.ClipText() == "what was there");
  NILKEY_EXPECT(desktop.LogText().empty());
}

NILKEY_TEST(a_missing_record_and_a_wrong_master_password_touch_nothing) {
  TempDir dir;
  Desktop desktop;
  NILKEY_EXPECT(dir.ok() && desktop.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass g9";
  NILKEY_EXPECT(Seed(dir, vault, master));
  NILKEY_EXPECT(desktop.SetClip("untouched"));

  const Run missing = Get(dir, vault, desktop, {"nope"}, {{kMasterPrompt, master}});
  NILKEY_EXPECT(missing.status == 1);
  NILKEY_EXPECT(Has(missing.terminal, "record not found"));

  const Run wrong = Get(dir, vault, desktop, {"alpha"}, {{kMasterPrompt, "not the master"}});
  NILKEY_EXPECT(wrong.status == 1);
  NILKEY_EXPECT(Has(wrong.terminal, "wrong password or corrupted vault file"));
  NILKEY_EXPECT(!Has(wrong.terminal, "pw-alpha"));

  const Run none = Get(dir, dir.Path("none.vault"), desktop, {"alpha"}, {});
  NILKEY_EXPECT(none.status == 1);
  NILKEY_EXPECT(Has(none.terminal, "vault file not found"));
  NILKEY_EXPECT(!Has(none.terminal, kMasterPrompt));

  NILKEY_EXPECT(desktop.ClipText() == "untouched");
  NILKEY_EXPECT(desktop.LogText().empty());
}

NILKEY_TEST(without_a_clipboard_tool_get_fails_before_asking_for_the_password) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  NILKEY_EXPECT(Seed(dir, vault, "master pass g10"));

  // X11, but nothing installed.
  CliEnv none;
  none.unset = {"WAYLAND_DISPLAY"};
  none.set = {{"PATH", dir.dir()}, {"DISPLAY", ":fake"}};
  const Run run = RunCli(dir, vault, {"get", "alpha"}, {}, nullptr, &none);
  NILKEY_EXPECT(run.status == 1);
  NILKEY_EXPECT(Has(run.terminal, "no clipboard tool found"));
  NILKEY_EXPECT(Has(run.terminal, "--print"));
  NILKEY_EXPECT(!Has(run.terminal, kMasterPrompt));

  // Wayland, with only an X11 tool: no quiet fall-back.
  Desktop desktop;
  NILKEY_EXPECT(desktop.ok());
  CliEnv wayland = desktop.env();
  wayland.set.emplace_back("WAYLAND_DISPLAY", "wayland-fake");
  wayland.unset.clear();
  const Run wl = RunCli(dir, vault, {"get", "alpha"}, {}, nullptr, &wayland);
  NILKEY_EXPECT(wl.status == 1);
  NILKEY_EXPECT(Has(wl.terminal, "no clipboard tool found"));
  NILKEY_EXPECT(!Has(wl.terminal, kMasterPrompt));
  NILKEY_EXPECT(desktop.LogText().empty());
}

NILKEY_TEST(get_can_be_aborted_at_the_master_password) {
  TempDir dir;
  Desktop desktop;
  NILKEY_EXPECT(dir.ok() && desktop.ok());
  const std::string vault = dir.Path("v.vault");
  NILKEY_EXPECT(Seed(dir, vault, "master pass g11"));

  PtyChild child = StartCli(dir, vault, {"get", "alpha"}, nullptr, &desktop.env());
  NILKEY_EXPECT(child.WaitFor(kMasterPrompt, kWaitMs));
  child.Send("\x03");
  NILKEY_EXPECT(child.Wait(kWaitMs) == 130);
  NILKEY_EXPECT(desktop.LogText().empty());
}

// get only reads, so it must not queue up behind a writer.
NILKEY_TEST(get_does_not_wait_for_the_vault_lock) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass g12";
  NILKEY_EXPECT(Seed(dir, vault, master));

  const int lock_fd = open((vault + ".lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  NILKEY_EXPECT(lock_fd >= 0);
  NILKEY_EXPECT(flock(lock_fd, LOCK_EX) == 0);
  CliEnv bare;
  bare.set = {{"PATH", dir.dir()}};
  const Run run = RunCli(dir, vault, {"get", "alpha", "--print"}, {{kMasterPrompt, master}},
                         nullptr, &bare);
  NILKEY_EXPECT(close(lock_fd) == 0);
  NILKEY_EXPECT(run.status == 0);
  NILKEY_EXPECT(run.out == "pw-alpha");
}

// A tool that fails must not be reported as success, and the value must not be
// left behind: nothing was copied, nothing is started.
NILKEY_TEST(a_failing_clipboard_tool_is_an_error) {
  TempDir dir;
  Desktop desktop;
  NILKEY_EXPECT(dir.ok() && desktop.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass g13";
  NILKEY_EXPECT(Seed(dir, vault, master));

  CliEnv failing = desktop.env();
  failing.set.emplace_back("FAKE_FAIL", "1");
  const Run run = RunCli(dir, vault, {"get", "alpha"}, {{kMasterPrompt, master}}, nullptr,
                         &failing);
  NILKEY_EXPECT(run.status == 1);
  NILKEY_EXPECT(Has(run.terminal, "the clipboard tool failed"));
  NILKEY_EXPECT(!Has(run.terminal, "Copied"));
  NILKEY_EXPECT(!Has(run.terminal, "pw-alpha"));
  NILKEY_EXPECT(desktop.ClipText().empty());
}

NILKEY_TEST_MAIN()

// Clipboard tool detection (SPEC.md 9.3) against directories of fake tools.
// Nothing here starts a tool or touches the real clipboard.

#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#include "nilkey/clipboard.hpp"
#include "temp_dir.hpp"
#include "test_framework.hpp"

using nilkey::ClipboardEnv;
using nilkey::ClipboardTool;
using nilkey::DetectClipboardTool;
using nilkey::ClipboardFingerprint;
using nilkey::ErrorCode;
using nilkey::MemlockPolicy;
using nilkey::test::Slurp;
using nilkey::test::TempDir;

namespace {

// A file in `dir` with the given mode. Its content does not matter here.
bool MakeFile(const TempDir& dir, const char* name, mode_t mode) {
  const std::string path = dir.Path(name);
  const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
  if (fd < 0) return false;
  return fchmod(fd, mode) == 0 && close(fd) == 0;
}

bool MakeTools(const TempDir& dir, std::initializer_list<const char*> names) {
  for (const char* name : names) {
    if (!MakeFile(dir, name, 0755)) return false;
  }
  return true;
}

bool EndsWith(const std::string& text, std::string_view suffix) {
  return text.size() >= suffix.size() &&
         text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool Fails(const nilkey::Result<ClipboardTool>& result, ErrorCode code) {
  return !result.ok() && result.error().code == code;
}

bool Has(const std::vector<std::string>& args, std::string_view wanted) {
  for (const std::string& arg : args) {
    if (arg == wanted) return true;
  }
  return false;
}

// The text of a fake clipboard, as the tests build it. Not a secret.
using Bytes = std::vector<std::byte>;

Bytes ToBytes(std::string_view text) {
  const auto* first = reinterpret_cast<const std::byte*>(text.data());
  return Bytes(first, first + text.size());
}

bool WriteText(const std::string& path, std::string_view text) {
  const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) return false;
  const bool wrote = write(fd, text.data(), text.size()) == static_cast<ssize_t>(text.size());
  return close(fd) == 0 && wrote;
}

std::string ReadText(const std::string& path) {
  Bytes bytes;
  if (!Slurp(path, bytes)) return "<unreadable>";
  return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

// A stand-in for xclip. "-in" stores stdin in $FAKE_CLIP, "-out" prints it; the
// arguments of every call are appended to $FAKE_LOG. $FAKE_FAIL makes it fail,
// $FAKE_NOREAD makes it quit without reading, $FAKE_HANG makes it hang.
constexpr const char* kFakeXclip =
    "#!/bin/sh\n"
    "echo \"$*\" >> \"$FAKE_LOG\"\n"
    "[ -n \"$FAKE_FAIL\" ] && exit 3\n"
    "[ -n \"$FAKE_NOREAD\" ] && exit 0\n"
    "[ -n \"$FAKE_HANG\" ] && exec sleep 60\n"
    "case \"$*\" in\n"
    "  *-in*) cat > \"$FAKE_CLIP\" ;;\n"
    "  *-out*) cat \"$FAKE_CLIP\" ;;\n"
    "esac\n";

// A directory with the fake xclip, the clipboard file and the log, and the
// environment variables the script reads. The tool found is the one a real
// session on X11 would get.
class FakeDesktop {
 public:
  FakeDesktop() {
    ok_ = dir_.ok() && WriteText(dir_.Path("xclip"), kFakeXclip) &&
          chmod(dir_.Path("xclip").c_str(), 0755) == 0 && WriteText(Clip(), "") &&
          WriteText(Log(), "") && setenv("FAKE_CLIP", Clip().c_str(), 1) == 0 &&
          setenv("FAKE_LOG", Log().c_str(), 1) == 0;
    for (const char* name : {"FAKE_FAIL", "FAKE_NOREAD", "FAKE_HANG"}) {
      if (unsetenv(name) != 0) ok_ = false;
    }
    const auto tool = DetectClipboardTool({dir_.dir().c_str(), nullptr, ":0"});
    if (tool.ok()) tool_ = tool.value();
    else ok_ = false;
  }
  ~FakeDesktop() {
    for (const char* name : {"FAKE_CLIP", "FAKE_LOG", "FAKE_FAIL", "FAKE_NOREAD", "FAKE_HANG"}) {
      if (unsetenv(name) != 0) {
        // Test cleanup only.
      }
    }
  }
  bool ok() const { return ok_; }
  const ClipboardTool& tool() const { return tool_; }
  std::string Clip() const { return dir_.Path("clip"); }
  std::string Log() const { return dir_.Path("log"); }

 private:
  TempDir dir_;
  ClipboardTool tool_;
  bool ok_ = false;
};

// Polls until the fake clipboard file is empty, for at most `limit_ms`.
bool BecomesEmpty(const std::string& path, int limit_ms) {
  const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(limit_ms);
  while (std::chrono::steady_clock::now() < end) {
    if (ReadText(path).empty()) return true;
    usleep(50 * 1000);
  }
  return ReadText(path).empty();
}

}  // namespace

NILKEY_TEST(wayland_uses_wl_copy_and_wl_paste) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  NILKEY_EXPECT(MakeTools(dir, {"wl-copy", "wl-paste", "xclip"}));

  const auto tool = DetectClipboardTool({dir.dir().c_str(), "wayland-0", ":0"});
  NILKEY_EXPECT(tool.ok());
  NILKEY_EXPECT(EndsWith(tool.value().copy_path, "/wl-copy"));
  NILKEY_EXPECT(EndsWith(tool.value().paste_path, "/wl-paste"));
  NILKEY_EXPECT(Has(tool.value().paste_args, "--no-newline"));
  NILKEY_EXPECT(Has(tool.value().clear_args, "--clear"));
  NILKEY_EXPECT(tool.value().copy_path.front() == '/');  // Absolute.
}

NILKEY_TEST(wayland_without_both_wl_tools_fails_instead_of_using_x11) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  NILKEY_EXPECT(MakeTools(dir, {"wl-copy", "xclip", "xsel"}));  // No wl-paste.
  NILKEY_EXPECT(Fails(DetectClipboardTool({dir.dir().c_str(), "wayland-0", ":0"}),
                      ErrorCode::kNoClipboardTool));
}

NILKEY_TEST(x11_prefers_xclip_and_selects_the_clipboard) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  NILKEY_EXPECT(MakeTools(dir, {"xsel", "xclip"}));

  const auto tool = DetectClipboardTool({dir.dir().c_str(), nullptr, ":0"});
  NILKEY_EXPECT(tool.ok());
  NILKEY_EXPECT(EndsWith(tool.value().copy_path, "/xclip"));
  NILKEY_EXPECT(tool.value().copy_path == tool.value().paste_path);
  for (const auto* args : {&tool.value().copy_args, &tool.value().paste_args}) {
    NILKEY_EXPECT(Has(*args, "-selection") && Has(*args, "clipboard"));
  }
  NILKEY_EXPECT(Has(tool.value().copy_args, "-in"));
  NILKEY_EXPECT(Has(tool.value().paste_args, "-out"));
}

// Without --clipboard, xsel reads PRIMARY: the cleaner would never see the
// copied text and never clear it.
NILKEY_TEST(xsel_is_used_without_xclip_and_always_on_the_clipboard) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  NILKEY_EXPECT(MakeTools(dir, {"xsel"}));

  const auto tool = DetectClipboardTool({dir.dir().c_str(), "", ":0"});
  NILKEY_EXPECT(tool.ok());
  NILKEY_EXPECT(EndsWith(tool.value().copy_path, "/xsel"));
  NILKEY_EXPECT(Has(tool.value().copy_args, "--clipboard"));
  NILKEY_EXPECT(Has(tool.value().paste_args, "--clipboard"));
  NILKEY_EXPECT(Has(tool.value().clear_args, "--clipboard"));
}

NILKEY_TEST(no_display_or_no_tool_or_no_path_is_an_error) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  NILKEY_EXPECT(MakeTools(dir, {"xclip", "xsel", "wl-copy", "wl-paste"}));
  // Neither variable set, or only set to empty text.
  NILKEY_EXPECT(Fails(DetectClipboardTool({dir.dir().c_str(), nullptr, nullptr}),
                      ErrorCode::kNoClipboardTool));
  NILKEY_EXPECT(Fails(DetectClipboardTool({dir.dir().c_str(), "", ""}),
                      ErrorCode::kNoClipboardTool));

  TempDir empty;
  NILKEY_EXPECT(empty.ok());
  NILKEY_EXPECT(Fails(DetectClipboardTool({empty.dir().c_str(), nullptr, ":0"}),
                      ErrorCode::kNoClipboardTool));
  NILKEY_EXPECT(Fails(DetectClipboardTool({nullptr, nullptr, ":0"}), ErrorCode::kNoClipboardTool));
  NILKEY_EXPECT(Fails(DetectClipboardTool({"", nullptr, ":0"}), ErrorCode::kNoClipboardTool));
}

NILKEY_TEST(a_file_that_is_not_executable_or_not_a_file_is_skipped) {
  TempDir plain;
  NILKEY_EXPECT(plain.ok());
  NILKEY_EXPECT(MakeFile(plain, "xclip", 0644));          // Not executable.
  NILKEY_EXPECT(mkdir(plain.Path("xsel").c_str(), 0755) == 0);  // A directory.
  TempDir good;
  NILKEY_EXPECT(good.ok());
  NILKEY_EXPECT(MakeTools(good, {"xclip"}));

  const std::string path = plain.dir() + ":" + good.dir();
  const auto tool = DetectClipboardTool({path.c_str(), nullptr, ":0"});
  NILKEY_EXPECT(tool.ok());
  NILKEY_EXPECT(tool.value().copy_path == good.dir() + "/xclip");

  const auto only_plain = DetectClipboardTool({plain.dir().c_str(), nullptr, ":0"});
  NILKEY_EXPECT(Fails(only_plain, ErrorCode::kNoClipboardTool));
  NILKEY_EXPECT(rmdir(plain.Path("xsel").c_str()) == 0);  // TempDir only unlinks files.
}

// A tool in the current directory must not be run just because PATH has an
// empty or relative entry.
NILKEY_TEST(relative_and_empty_path_entries_are_ignored) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  NILKEY_EXPECT(MakeTools(dir, {"xclip"}));
  char old_cwd[4096];
  NILKEY_EXPECT(getcwd(old_cwd, sizeof old_cwd) != nullptr);
  NILKEY_EXPECT(chdir(dir.dir().c_str()) == 0);

  const bool empty_entry = DetectClipboardTool({":", nullptr, ":0"}).ok();
  const bool dot_entry = DetectClipboardTool({".", nullptr, ":0"}).ok();
  const bool relative_entry = DetectClipboardTool({"./", nullptr, ":0"}).ok();
  const bool trailing_empty = DetectClipboardTool({"/nonexistent:", nullptr, ":0"}).ok();

  NILKEY_EXPECT(chdir(old_cwd) == 0);
  NILKEY_EXPECT(!empty_entry && !dot_entry && !relative_entry && !trailing_empty);
}

// ---- Copy and clear ----

NILKEY_TEST(copy_hands_the_text_over_byte_for_byte) {
  const FakeDesktop desktop;
  NILKEY_EXPECT(desktop.ok());

  const std::string nul_and_utf8("pa\0ss \xC3\xA9 \xF0\x9F\x94\x91", 12);
  const std::string big(64 * 1024, 'x');
  for (const std::string& text : {std::string("hunter2"), nul_and_utf8, big}) {
    const Bytes bytes = ToBytes(text);
    NILKEY_EXPECT(nilkey::CopyToClipboard(desktop.tool(), bytes).ok());
    NILKEY_EXPECT(ReadText(desktop.Clip()) == text);
  }
  // The clipboard, not PRIMARY.
  NILKEY_EXPECT(ReadText(desktop.Log()).find("-selection clipboard -in") != std::string::npos);
}

NILKEY_TEST(clear_empties_the_clipboard) {
  const FakeDesktop desktop;
  NILKEY_EXPECT(desktop.ok());
  NILKEY_EXPECT(nilkey::CopyToClipboard(desktop.tool(), ToBytes("something")).ok());
  NILKEY_EXPECT(nilkey::ClearClipboard(desktop.tool()).ok());
  NILKEY_EXPECT(ReadText(desktop.Clip()).empty());
}

NILKEY_TEST(a_failing_or_missing_tool_is_reported) {
  const FakeDesktop desktop;
  NILKEY_EXPECT(desktop.ok());
  NILKEY_EXPECT(WriteText(desktop.Clip(), "before"));

  NILKEY_EXPECT(setenv("FAKE_FAIL", "1", 1) == 0);
  const auto failed = nilkey::CopyToClipboard(desktop.tool(), ToBytes("new"));
  NILKEY_EXPECT(!failed.ok() && failed.error().code == ErrorCode::kClipboardFailed);
  NILKEY_EXPECT(ReadText(desktop.Clip()) == "before");

  ClipboardTool missing = desktop.tool();
  missing.copy_path = "/nonexistent/xclip";
  const auto absent = nilkey::CopyToClipboard(missing, ToBytes("new"));
  NILKEY_EXPECT(!absent.ok() && absent.error().code == ErrorCode::kClipboardFailed);
}

// A tool that quits without reading makes write() fail with EPIPE; the default
// SIGPIPE action would kill the whole process. Enough data that the write
// cannot just sit in the pipe buffer.
NILKEY_TEST(a_tool_that_does_not_read_fails_the_copy_but_not_the_process) {
  const FakeDesktop desktop;
  NILKEY_EXPECT(desktop.ok());
  NILKEY_EXPECT(setenv("FAKE_NOREAD", "1", 1) == 0);

  struct sigaction before = {};
  NILKEY_EXPECT(sigaction(SIGPIPE, nullptr, &before) == 0);
  const auto result = nilkey::CopyToClipboard(desktop.tool(), ToBytes(std::string(1 << 20, 'z')));
  NILKEY_EXPECT(!result.ok() && result.error().code == ErrorCode::kClipboardFailed);

  struct sigaction after = {};
  NILKEY_EXPECT(sigaction(SIGPIPE, nullptr, &after) == 0);
  NILKEY_EXPECT(after.sa_handler == before.sa_handler);  // The old action is back.
}

NILKEY_TEST(a_tool_that_hangs_is_killed_after_a_few_seconds) {
  const FakeDesktop desktop;
  NILKEY_EXPECT(desktop.ok());
  NILKEY_EXPECT(setenv("FAKE_HANG", "1", 1) == 0);

  const auto start = std::chrono::steady_clock::now();
  const auto result = nilkey::CopyToClipboard(desktop.tool(), ToBytes("x"));
  const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::steady_clock::now() - start)
                           .count();
  NILKEY_EXPECT(!result.ok() && result.error().code == ErrorCode::kClipboardFailed);
  NILKEY_EXPECT(seconds >= 4 && seconds < 30);
}

// ---- The cleaner ----

NILKEY_TEST(fingerprints_tell_texts_apart) {
  const auto a = nilkey::FingerprintOf(ToBytes("password"));
  const auto b = nilkey::FingerprintOf(ToBytes("password"));
  const auto c = nilkey::FingerprintOf(ToBytes("passwore"));
  NILKEY_EXPECT(a.ok() && b.ok() && c.ok());
  NILKEY_EXPECT(a.value().digest == b.value().digest);
  NILKEY_EXPECT(a.value().digest != c.value().digest);
  NILKEY_EXPECT(a.value().length == 8);
}

NILKEY_TEST(the_cleaner_clears_the_clipboard_if_it_still_holds_the_text) {
  const FakeDesktop desktop;
  NILKEY_EXPECT(desktop.ok());
  const Bytes text = ToBytes("s3cret value");
  NILKEY_EXPECT(nilkey::CopyToClipboard(desktop.tool(), text).ok());
  const auto fingerprint = nilkey::FingerprintOf(text);
  NILKEY_EXPECT(fingerprint.ok());

  const auto cleared = nilkey::RunCleaner(desktop.tool(), fingerprint.value(), 0,
                                          MemlockPolicy::kRequire);
  NILKEY_EXPECT(cleared.ok() && cleared.value());
  NILKEY_EXPECT(ReadText(desktop.Clip()).empty());
}

NILKEY_TEST(the_cleaner_leaves_other_clipboard_content_alone) {
  const FakeDesktop desktop;
  NILKEY_EXPECT(desktop.ok());
  const auto fingerprint = nilkey::FingerprintOf(ToBytes("s3cret value"));
  NILKEY_EXPECT(fingerprint.ok());

  // Different text of the same length, a prefix, something longer, empty: all
  // are "not ours", and none may be cleared.
  for (const char* other : {"s3cret valuf", "s3cret", "s3cret value and more", ""}) {
    NILKEY_EXPECT(WriteText(desktop.Clip(), other));
    const auto cleared = nilkey::RunCleaner(desktop.tool(), fingerprint.value(), 0,
                                            MemlockPolicy::kRequire);
    NILKEY_EXPECT(!cleared.ok() || !cleared.value());
    NILKEY_EXPECT(ReadText(desktop.Clip()) == other);
  }
}

NILKEY_TEST(the_cleaner_does_nothing_if_the_clipboard_cannot_be_read) {
  const FakeDesktop desktop;
  NILKEY_EXPECT(desktop.ok());
  const Bytes text = ToBytes("s3cret value");
  NILKEY_EXPECT(nilkey::CopyToClipboard(desktop.tool(), text).ok());
  const auto fingerprint = nilkey::FingerprintOf(text);
  NILKEY_EXPECT(fingerprint.ok());

  NILKEY_EXPECT(setenv("FAKE_FAIL", "1", 1) == 0);
  const auto result = nilkey::RunCleaner(desktop.tool(), fingerprint.value(), 0,
                                         MemlockPolicy::kRequire);
  NILKEY_EXPECT(!result.ok());
  NILKEY_EXPECT(ReadText(desktop.Clip()) == "s3cret value");
}

NILKEY_TEST(the_cleaner_waits_for_the_given_time) {
  const FakeDesktop desktop;
  NILKEY_EXPECT(desktop.ok());
  const Bytes text = ToBytes("s3cret value");
  NILKEY_EXPECT(nilkey::CopyToClipboard(desktop.tool(), text).ok());
  const auto fingerprint = nilkey::FingerprintOf(text);
  NILKEY_EXPECT(fingerprint.ok());

  const auto start = std::chrono::steady_clock::now();
  const auto cleared = nilkey::RunCleaner(desktop.tool(), fingerprint.value(), 2,
                                          MemlockPolicy::kRequire);
  const auto elapsed = std::chrono::steady_clock::now() - start;
  NILKEY_EXPECT(cleared.ok() && cleared.value());
  NILKEY_EXPECT(elapsed >= std::chrono::milliseconds(1900));
}

// ---- The detached cleaner ----

// What matters is the order: StartCleaner() comes back while the text is still
// on the clipboard, and the clearing happens afterwards, in another process.
NILKEY_TEST(the_detached_cleaner_clears_after_the_call_has_returned) {
  const FakeDesktop desktop;
  NILKEY_EXPECT(desktop.ok());
  const Bytes text = ToBytes("s3cret value");
  NILKEY_EXPECT(nilkey::CopyToClipboard(desktop.tool(), text).ok());
  const auto fingerprint = nilkey::FingerprintOf(text);
  NILKEY_EXPECT(fingerprint.ok());

  NILKEY_EXPECT(nilkey::StartCleaner(desktop.tool(), fingerprint.value(), 3,
                                     MemlockPolicy::kRequire)
                    .ok());
  NILKEY_EXPECT(ReadText(desktop.Clip()) == "s3cret value");  // Not cleared yet.
  NILKEY_EXPECT(BecomesEmpty(desktop.Clip(), 20000));
}

NILKEY_TEST(the_detached_cleaner_leaves_changed_content_alone) {
  const FakeDesktop desktop;
  NILKEY_EXPECT(desktop.ok());
  const Bytes text = ToBytes("s3cret value");
  NILKEY_EXPECT(nilkey::CopyToClipboard(desktop.tool(), text).ok());
  const auto fingerprint = nilkey::FingerprintOf(text);
  NILKEY_EXPECT(fingerprint.ok());

  NILKEY_EXPECT(nilkey::StartCleaner(desktop.tool(), fingerprint.value(), 1,
                                     MemlockPolicy::kRequire)
                    .ok());
  NILKEY_EXPECT(WriteText(desktop.Clip(), "something else"));
  usleep(3500 * 1000);  // Well past the time the cleaner was given.
  NILKEY_EXPECT(ReadText(desktop.Clip()) == "something else");
}

NILKEY_TEST_MAIN()

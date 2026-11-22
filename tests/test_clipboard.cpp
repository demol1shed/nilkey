// Clipboard tool detection (SPEC.md 9.3) against directories of fake tools.
// Nothing here starts a tool or touches the real clipboard.

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>
#include <string_view>
#include <vector>

#include "nilkey/clipboard.hpp"
#include "temp_dir.hpp"
#include "test_framework.hpp"

using nilkey::ClipboardEnv;
using nilkey::ClipboardTool;
using nilkey::DetectClipboardTool;
using nilkey::ErrorCode;
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

NILKEY_TEST_MAIN()

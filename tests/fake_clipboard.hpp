#ifndef NILKEY_TEST_FAKE_CLIPBOARD_HPP
#define NILKEY_TEST_FAKE_CLIPBOARD_HPP

// A stand-in for xclip, so that clipboard code is tested without a display and
// without touching the real clipboard. The "clipboard" is the file $FAKE_CLIP:
// "-in" stores stdin there, "-out" prints it. The arguments of every call are
// appended to $FAKE_LOG. $FAKE_FAIL makes the tool fail, $FAKE_NOREAD makes it
// quit without reading its input, $FAKE_HANG makes it hang.

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string_view>

#include "temp_dir.hpp"

namespace nilkey::test {

inline constexpr const char* kFakeXclip =
    "#!/bin/sh\n"
    "echo \"$*\" >> \"$FAKE_LOG\"\n"
    "[ -n \"$FAKE_FAIL\" ] && exit 3\n"
    "[ -n \"$FAKE_NOREAD\" ] && exit 0\n"
    "[ -n \"$FAKE_HANG\" ] && exec sleep 60\n"
    "case \"$*\" in\n"
    "  *-in*) cat > \"$FAKE_CLIP\" ;;\n"
    "  *-out*) cat \"$FAKE_CLIP\" ;;\n"
    "esac\n";

// Writes `text` to `path` (mode 0600, or `mode`).
inline bool WriteTextFile(const std::string& path, std::string_view text, mode_t mode = 0600) {
  const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
  if (fd < 0) return false;
  const bool wrote = write(fd, text.data(), text.size()) == static_cast<ssize_t>(text.size());
  return fchmod(fd, mode) == 0 && close(fd) == 0 && wrote;
}

// Puts the fake `xclip` into `dir`, with an empty "clip" and "log" next to it.
inline bool InstallFakeXclip(const TempDir& dir) {
  return dir.ok() && WriteTextFile(dir.Path("xclip"), kFakeXclip, 0755) &&
         WriteTextFile(dir.Path("clip"), "") && WriteTextFile(dir.Path("log"), "");
}

}  // namespace nilkey::test

#endif  // NILKEY_TEST_FAKE_CLIPBOARD_HPP

#ifndef NILKEY_CLIPBOARD_HPP
#define NILKEY_CLIPBOARD_HPP

// Talking to the system clipboard through an external tool (SPEC.md 9.3):
// wl-copy and wl-paste under Wayland, xclip or xsel under X11. nilkey never
// links a display library and never runs a shell; a tool is started with
// posix_spawn() from an absolute path.
//
// Only the CLIPBOARD selection is used, never PRIMARY.

#include <string>
#include <vector>

#include "nilkey/result.hpp"

namespace nilkey {

// A clipboard tool found on this system: plain data, no secrets. Arguments
// exclude argv[0].
struct ClipboardTool {
  std::string copy_path;   // Reads the text from stdin.
  std::string paste_path;  // Prints the clipboard text on stdout.
  std::vector<std::string> copy_args;
  std::vector<std::string> paste_args;
  // Run with copy_path to empty the clipboard; `clear_input` goes to its stdin.
  std::vector<std::string> clear_args;
  std::string clear_input;
};

// The three environment variables the choice depends on, passed in so that
// tests do not have to change the real environment. Null or empty means unset.
struct ClipboardEnv {
  const char* path;
  const char* wayland_display;
  const char* display;
};

// SPEC.md 9.3: if WAYLAND_DISPLAY is set, wl-copy and wl-paste (both needed);
// otherwise, if DISPLAY is set, xclip, then xsel. There is no fallback from one
// to the other: a Wayland session without wl-clipboard fails instead of
// quietly going through XWayland. A tool is looked up in the PATH entries that
// are absolute paths; a relative or empty entry is ignored, so a command run in
// the current directory is never picked up. kNoClipboardTool if nothing fits.
[[nodiscard]] Result<ClipboardTool> DetectClipboardTool(const ClipboardEnv& env);

}  // namespace nilkey

#endif  // NILKEY_CLIPBOARD_HPP

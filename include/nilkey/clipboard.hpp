#ifndef NILKEY_CLIPBOARD_HPP
#define NILKEY_CLIPBOARD_HPP

// Talking to the system clipboard through an external tool (SPEC.md 9.3):
// wl-copy and wl-paste under Wayland, xclip or xsel under X11. nilkey never
// links a display library and never runs a shell; a tool is started with
// posix_spawn() from an absolute path.
//
// Only the CLIPBOARD selection is used, never PRIMARY.

#include <array>
#include <cstddef>
#include <span>
#include <string>
#include <vector>

#include "nilkey/result.hpp"
#include "nilkey/secure_buffer.hpp"

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

// What the cleaner remembers about the copied text: a BLAKE2b-256 digest and
// the length, never the text itself (SPEC.md 9.3). The digest of a password is
// still treated as secret: it is not printed or logged and is zeroed when done.
struct ClipboardFingerprint {
  std::array<unsigned char, 32> digest;
  std::size_t length;
};

[[nodiscard]] Result<ClipboardFingerprint> FingerprintOf(std::span<const std::byte> text);

// Puts `text` on the clipboard through the tool's stdin: no shell, no argument
// and no temporary file ever holds it. The tool's own output is discarded, so
// nothing it prints can leak. kClipboardFailed if it cannot be started, exits
// with an error, or does not finish within a few seconds (then it is killed).
[[nodiscard]] Status CopyToClipboard(const ClipboardTool& tool, std::span<const std::byte> text);

// Empties the clipboard with the tool's clear command.
[[nodiscard]] Status ClearClipboard(const ClipboardTool& tool);

// The cleaner's job (it runs in a detached process, see StartCleaner): wait
// `seconds`, read the clipboard back, and clear it only if what is there still
// has the fingerprint of the copied text. Whatever else was copied meanwhile
// is left alone, as is a clipboard that cannot be read. Returns whether it
// cleared. `policy` is for the buffer the clipboard text is read into.
[[nodiscard]] Result<bool> RunCleaner(const ClipboardTool& tool,
                                      const ClipboardFingerprint& fingerprint, unsigned seconds,
                                      MemlockPolicy policy);

}  // namespace nilkey

#endif  // NILKEY_CLIPBOARD_HPP

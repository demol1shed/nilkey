#include "nilkey/clipboard.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <optional>
#include <string_view>

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

}  // namespace nilkey

#ifndef NILKEY_DOCTOR_HPP
#define NILKEY_DOCTOR_HPP

// The judgements behind `nilkey doctor` (SPEC.md 9.2), kept apart from the
// system calls that gather the facts, so each rule can be tested on its own.
// Nothing here touches a secret, a file or the process: the command in
// commands.cpp reads the mode, the owner, the limits and /proc/swaps and asks
// these functions what they mean.

#include <sys/types.h>

#include <cstdint>
#include <string>
#include <string_view>

namespace nilkey {

// How serious a finding is. A problem breaks an assumption nilkey's protection
// rests on and makes `doctor` exit with 1; a note is something about this
// machine the user should know and may accept; ok needs no action.
enum class Finding : std::uint8_t { kOk, kNote, kProblem };

// A finding and the sentence that explains it. `text` is static.
struct Check {
  Finding level;
  const char* text;
};

// A vault or lock file must have mode 0600 exactly (setuid, setgid and sticky
// bits count too) and belong to the user who runs nilkey: another owner could
// replace the content, and a looser mode lets others read the ciphertext for
// an offline attack (SPEC.md 2.1).
[[nodiscard]] Check ClassifyFileMode(mode_t mode, uid_t owner, uid_t user);

// The directory that holds the vault. If group or others can write to it they
// can delete the vault and put another in its place (a problem). If they can
// only read or enter it they can see that a vault exists (a note). Only the
// user, or root, may own it.
[[nodiscard]] Check ClassifyDirectoryMode(mode_t mode, uid_t owner, uid_t user);

// The number of swap areas in the text of /proc/swaps: the lines after the
// header that are not blank.
[[nodiscard]] unsigned CountSwapAreas(std::string_view proc_swaps);

// The memory nilkey may have to lock at once for a vault whose encrypted
// payload is `payload_len` bytes: the payload is held twice while a command
// changes it (SPEC.md 6.4), each copy rounded up to whole pages, plus a fixed
// allowance for the keys, passwords and input buffers. An estimate, not a
// promise.
[[nodiscard]] std::uint64_t LockedBytesNeeded(std::uint32_t payload_len, std::uint64_t page_size);

// The directory part of `path`: "." if it has none, "/" for a file in the root.
[[nodiscard]] std::string ParentDirectory(const std::string& path);

}  // namespace nilkey

#endif  // NILKEY_DOCTOR_HPP

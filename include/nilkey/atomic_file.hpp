#ifndef NILKEY_ATOMIC_FILE_HPP
#define NILKEY_ATOMIC_FILE_HPP

// Vault file I/O (SPEC.md 8). The bytes handled here are the encrypted vault
// file, which is public data, so a plain std::vector is fine. Paths are
// NUL-terminated strings; they never hold secrets.
//
// Symlinks are rejected (kSymlinkRejected) instead of followed, so a vault
// path can never silently redirect a write or a read.
//
// There is no file lock: two processes that read-modify-write the same vault
// at once are last-writer-wins. The layer that owns the read-modify-write
// cycle (SPEC.md 8, "Eşzamanlı yazma") is responsible for that.

#include <cstddef>
#include <span>
#include <vector>

#include "nilkey/result.hpp"

namespace nilkey {

// Replaces `path` with `data` atomically and durably, with mode 0600:
// temp file in the same directory, write, fsync, rename, fsync of the
// directory. If anything fails before the rename, the temp file is removed
// and the existing vault is untouched. If only the final directory fsync
// fails, kIoError is returned although the new file is already in place.
[[nodiscard]] Status WriteFileAtomic(const char* path, std::span<const std::byte> data);

// Reads a whole vault file. Fails with kSymlinkRejected for a symlink,
// kIoError for open/read errors, and kInvalidFormat for anything that is not a
// regular file, is larger than kHeaderSize + kMaxPayloadSize (checked before
// any memory is allocated), or changes size while being read. Header and
// size consistency are checked later by OpenWithPassword, not here.
[[nodiscard]] Result<std::vector<std::byte>> ReadVaultFile(const char* path);

}  // namespace nilkey

#endif  // NILKEY_ATOMIC_FILE_HPP

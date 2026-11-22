#include "nilkey/doctor.hpp"

#include <sys/stat.h>

namespace nilkey {

namespace {

constexpr mode_t kGroupOtherWrite = S_IWGRP | S_IWOTH;
constexpr mode_t kGroupOtherAny = S_IRWXG | S_IRWXO;

// Keys, record passwords and the 64 KiB notes input buffer.
constexpr std::uint64_t kSmallBuffersAllowance = 256 * 1024;

}  // namespace

Check ClassifyFileMode(mode_t mode, uid_t owner, uid_t user) {
  if (owner != user) {
    return {Finding::kProblem, "owned by another user, who could replace it"};
  }
  if ((mode & 07777) != 0600) {
    return {Finding::kProblem, "expected 0600; others may be able to read or change it"};
  }
  return {Finding::kOk, "readable and writable only by you"};
}

Check ClassifyDirectoryMode(mode_t mode, uid_t owner, uid_t user) {
  if (owner != user && owner != 0) {
    return {Finding::kProblem, "owned by another user, who could replace the vault"};
  }
  if ((mode & kGroupOtherWrite) != 0) {
    return {Finding::kProblem, "group or others can write to it and replace the vault"};
  }
  if ((mode & kGroupOtherAny) != 0) {
    return {Finding::kNote, "group or others can see that a vault is there; 0700 is stricter"};
  }
  return {Finding::kOk, "accessible only by you"};
}

unsigned CountSwapAreas(std::string_view proc_swaps) {
  unsigned areas = 0;
  bool header = true;
  while (!proc_swaps.empty()) {
    const std::size_t end = proc_swaps.find('\n');
    const std::string_view line = proc_swaps.substr(0, end);
    proc_swaps = end == std::string_view::npos ? std::string_view() : proc_swaps.substr(end + 1);
    if (header) {
      header = false;
      continue;
    }
    if (line.find_first_not_of(" \t\r") != std::string_view::npos) ++areas;
  }
  return areas;
}

std::uint64_t LockedBytesNeeded(std::uint32_t payload_len, std::uint64_t page_size) {
  if (page_size == 0) page_size = 4096;
  const std::uint64_t pages = (std::uint64_t{payload_len} + page_size - 1) / page_size;
  return 2 * pages * page_size + kSmallBuffersAllowance;
}

std::string ParentDirectory(const std::string& path) {
  const std::size_t slash = path.rfind('/');
  if (slash == std::string::npos) return ".";
  if (slash == 0) return "/";
  return path.substr(0, slash);
}

}  // namespace nilkey

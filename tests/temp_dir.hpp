#ifndef NILKEY_TEST_TEMP_DIR_HPP
#define NILKEY_TEST_TEMP_DIR_HPP

// File helpers shared by the tests that touch the file system. They use plain
// POSIX calls, independent of the code under test.

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <string>
#include <vector>

namespace nilkey::test {

// A private directory under /tmp, removed (best effort, files first) when the
// test ends, including when a check returns early.
class TempDir {
 public:
  TempDir() {
    char tmpl[] = "/tmp/nilkey-test-XXXXXX";
    if (mkdtemp(tmpl) != nullptr) path_ = tmpl;
  }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  ~TempDir() {
    if (path_.empty()) return;
    if (DIR* d = opendir(path_.c_str()); d != nullptr) {
      while (const dirent* e = readdir(d)) {
        const std::string name = e->d_name;
        if (name == "." || name == "..") continue;
        const std::string full = path_ + "/" + name;
        // Test cleanup: a leftover in /tmp is harmless, so results are not checked.
        if (unlink(full.c_str()) != 0) (void)rmdir(full.c_str());
      }
      (void)closedir(d);
    }
    (void)rmdir(path_.c_str());
  }

  bool ok() const { return !path_.empty(); }
  std::string Path(const char* name) const { return path_ + "/" + name; }
  const std::string& dir() const { return path_; }

  std::size_t EntryCount() const {
    std::size_t count = 0;
    DIR* d = opendir(path_.c_str());
    if (d == nullptr) return 0;
    while (const dirent* e = readdir(d)) {
      const std::string name = e->d_name;
      if (name != "." && name != "..") ++count;
    }
    (void)closedir(d);
    return count;
  }

 private:
  std::string path_;
};

// Reads a whole file with plain POSIX calls, independent of the code under
// test. Returns false if the file cannot be read.
inline bool Slurp(const std::string& path, std::vector<std::byte>& out) {
  const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) return false;
  out.clear();
  std::byte buf[4096];
  for (;;) {
    const ssize_t n = read(fd, buf, sizeof buf);
    if (n < 0) {
      if (errno == EINTR) continue;
      (void)close(fd);
      return false;
    }
    if (n == 0) break;
    out.insert(out.end(), buf, buf + n);
  }
  return close(fd) == 0;
}

// st_mode permission bits of `path`, or -1 if it cannot be stat'ed.
inline int ModeOf(const std::string& path) {
  struct stat st;
  if (stat(path.c_str(), &st) != 0) return -1;
  return static_cast<int>(st.st_mode & 07777);
}

}  // namespace nilkey::test

#endif  // NILKEY_TEST_TEMP_DIR_HPP

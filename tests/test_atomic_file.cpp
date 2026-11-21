// Built against nilkey_core_test: the round trip tests derive keys with the
// fast test-only KDF limits.

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <string>
#include <vector>

#include <array>
#include <span>

#include "nilkey/atomic_file.hpp"
#include "nilkey/crypto.hpp"
#include "nilkey/vault_format.hpp"
#include "test_framework.hpp"

using nilkey::ErrorCode;
using nilkey::MemlockPolicy;
using nilkey::ReadVaultFile;
using nilkey::ScopedReadGuard;
using nilkey::Status;
using nilkey::WriteFileAtomic;

namespace {

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

std::vector<std::byte> Bytes(std::size_t n, unsigned char fill) {
  return std::vector<std::byte>(n, static_cast<std::byte>(fill));
}

// Reads a whole file with plain POSIX calls, independent of the code under
// test. Returns false if the file cannot be read.
bool Slurp(const std::string& path, std::vector<std::byte>& out) {
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
int ModeOf(const std::string& path) {
  struct stat st;
  if (stat(path.c_str(), &st) != 0) return -1;
  return static_cast<int>(st.st_mode & 07777);
}

bool CreateWithMode(const std::string& path, const std::vector<std::byte>& data, mode_t mode) {
  const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd < 0) return false;
  const bool wrote = write(fd, data.data(), data.size()) == static_cast<ssize_t>(data.size());
  const bool chmoded = fchmod(fd, mode) == 0;
  return close(fd) == 0 && wrote && chmoded;
}

// Restores the process umask when a test ends, even on an early return.
class ScopedUmask {
 public:
  explicit ScopedUmask(mode_t mask) : old_(umask(mask)) {}
  ScopedUmask(const ScopedUmask&) = delete;
  ScopedUmask& operator=(const ScopedUmask&) = delete;
  ~ScopedUmask() { umask(old_); }

 private:
  mode_t old_;
};

}  // namespace

NILKEY_TEST(write_creates_file_with_exact_mode_0600) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const auto data = Bytes(100, 0xAB);
  // Mode must be 0600 whatever the umask is: open() can only remove bits from
  // 0600, so the widest umask (0) is the one that could reveal a wrong mode.
  for (const mode_t mask : {mode_t{0}, mode_t{0022}, mode_t{0077}}) {
    const ScopedUmask scoped(mask);
    const std::string path = dir.Path("vault.bin");
    NILKEY_EXPECT(WriteFileAtomic(path.c_str(), data).ok());
    NILKEY_EXPECT(ModeOf(path) == 0600);
    NILKEY_EXPECT(unlink(path.c_str()) == 0);
  }
}

NILKEY_TEST(write_round_trips_content) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string path = dir.Path("vault.bin");
  const auto data = Bytes(1234, 0x5A);
  NILKEY_EXPECT(WriteFileAtomic(path.c_str(), data).ok());
  std::vector<std::byte> back;
  NILKEY_EXPECT(Slurp(path, back));
  NILKEY_EXPECT_SECRET_EQ(back, data);
}

NILKEY_TEST(write_round_trips_one_mebibyte) {
  // Larger than a pipe buffer, so a broken partial-write loop would show.
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string path = dir.Path("vault.bin");
  std::vector<std::byte> data(1U << 20);
  for (std::size_t i = 0; i < data.size(); ++i) data[i] = static_cast<std::byte>(i * 31U);
  NILKEY_EXPECT(WriteFileAtomic(path.c_str(), data).ok());
  std::vector<std::byte> back;
  NILKEY_EXPECT(Slurp(path, back));
  NILKEY_EXPECT_SECRET_EQ(back, data);
}

NILKEY_TEST(write_accepts_empty_data) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string path = dir.Path("vault.bin");
  NILKEY_EXPECT(WriteFileAtomic(path.c_str(), {}).ok());
  std::vector<std::byte> back;
  NILKEY_EXPECT(Slurp(path, back));
  NILKEY_EXPECT(back.empty());
}

NILKEY_TEST(overwrite_replaces_content_and_tightens_mode) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string path = dir.Path("vault.bin");
  NILKEY_EXPECT(CreateWithMode(path, Bytes(10, 0x11), 0644));
  const auto fresh = Bytes(20, 0x22);
  NILKEY_EXPECT(WriteFileAtomic(path.c_str(), fresh).ok());
  std::vector<std::byte> back;
  NILKEY_EXPECT(Slurp(path, back));
  NILKEY_EXPECT_SECRET_EQ(back, fresh);
  NILKEY_EXPECT(ModeOf(path) == 0600);
}

NILKEY_TEST(write_leaves_no_temp_file_behind) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string path = dir.Path("vault.bin");
  NILKEY_EXPECT(WriteFileAtomic(path.c_str(), Bytes(8, 1)).ok());
  NILKEY_EXPECT(WriteFileAtomic(path.c_str(), Bytes(8, 2)).ok());
  NILKEY_EXPECT(dir.EntryCount() == 1);
}

NILKEY_TEST(write_works_with_a_relative_path) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  char cwd[4096];
  NILKEY_EXPECT(getcwd(cwd, sizeof cwd) != nullptr);
  NILKEY_EXPECT(chdir(dir.dir().c_str()) == 0);
  const Status written = WriteFileAtomic("vault.bin", Bytes(16, 7));
  NILKEY_EXPECT(chdir(cwd) == 0);  // Restore before any check can return.
  NILKEY_EXPECT(written.ok());
  NILKEY_EXPECT(ModeOf(dir.Path("vault.bin")) == 0600);
  NILKEY_EXPECT(dir.EntryCount() == 1);
}

NILKEY_TEST(write_rejects_symlink_and_leaves_target_untouched) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string target = dir.Path("real.bin");
  const std::string link = dir.Path("link.bin");
  const auto original = Bytes(10, 0x33);
  NILKEY_EXPECT(CreateWithMode(target, original, 0600));
  NILKEY_EXPECT(symlink("real.bin", link.c_str()) == 0);

  const auto result = WriteFileAtomic(link.c_str(), Bytes(10, 0x44));
  NILKEY_EXPECT(!result.ok());
  NILKEY_EXPECT(result.error().code == ErrorCode::kSymlinkRejected);

  std::vector<std::byte> back;
  NILKEY_EXPECT(Slurp(target, back));
  NILKEY_EXPECT_SECRET_EQ(back, original);
  struct stat st;
  NILKEY_EXPECT(lstat(link.c_str(), &st) == 0 && S_ISLNK(st.st_mode));
  NILKEY_EXPECT(dir.EntryCount() == 2);  // No temp file.
}

NILKEY_TEST(write_rejects_dangling_symlink) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string link = dir.Path("link.bin");
  NILKEY_EXPECT(symlink("missing.bin", link.c_str()) == 0);
  const auto result = WriteFileAtomic(link.c_str(), Bytes(4, 1));
  NILKEY_EXPECT(!result.ok());
  NILKEY_EXPECT(result.error().code == ErrorCode::kSymlinkRejected);
  NILKEY_EXPECT(dir.EntryCount() == 1);
}

NILKEY_TEST(write_fails_in_missing_directory) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string path = dir.Path("no-such-dir/vault.bin");
  const auto result = WriteFileAtomic(path.c_str(), Bytes(4, 1));
  NILKEY_EXPECT(!result.ok());
  NILKEY_EXPECT(result.error().code == ErrorCode::kIoError);
  NILKEY_EXPECT(dir.EntryCount() == 0);
}

NILKEY_TEST(failed_rename_removes_temp_file_and_keeps_target) {
  // rename(file, directory) fails, which is the failure after the temp file is
  // fully written: the cleanup path must remove it.
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string path = dir.Path("vault.bin");
  NILKEY_EXPECT(mkdir(path.c_str(), 0700) == 0);
  const auto result = WriteFileAtomic(path.c_str(), Bytes(32, 9));
  NILKEY_EXPECT(!result.ok());
  NILKEY_EXPECT(result.error().code == ErrorCode::kIoError);
  struct stat st;
  NILKEY_EXPECT(stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode));
  NILKEY_EXPECT(dir.EntryCount() == 1);
}

NILKEY_TEST(write_rejects_null_and_empty_path) {
  const auto null_result = WriteFileAtomic(nullptr, Bytes(1, 1));
  NILKEY_EXPECT(!null_result.ok());
  NILKEY_EXPECT(null_result.error().code == ErrorCode::kInvalidArgument);
  const auto empty_result = WriteFileAtomic("", Bytes(1, 1));
  NILKEY_EXPECT(!empty_result.ok());
  NILKEY_EXPECT(empty_result.error().code == ErrorCode::kInvalidArgument);
}

NILKEY_TEST(read_returns_file_content) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string path = dir.Path("vault.bin");
  const auto data = Bytes(5000, 0x6B);
  NILKEY_EXPECT(CreateWithMode(path, data, 0600));
  auto read = ReadVaultFile(path.c_str());
  NILKEY_EXPECT(read.ok());
  NILKEY_EXPECT_SECRET_EQ(read.value(), data);
}

NILKEY_TEST(read_returns_empty_file_as_empty) {
  // Rejecting a file that is too short is the header parser's job.
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string path = dir.Path("vault.bin");
  NILKEY_EXPECT(CreateWithMode(path, {}, 0600));
  auto read = ReadVaultFile(path.c_str());
  NILKEY_EXPECT(read.ok());
  NILKEY_EXPECT(read.value().empty());
}

NILKEY_TEST(read_missing_file_is_io_error) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string path = dir.Path("missing.bin");
  const auto read = ReadVaultFile(path.c_str());
  NILKEY_EXPECT(!read.ok());
  NILKEY_EXPECT(read.error().code == ErrorCode::kIoError);
}

NILKEY_TEST(read_rejects_symlink) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  NILKEY_EXPECT(CreateWithMode(dir.Path("real.bin"), Bytes(10, 1), 0600));
  const std::string link = dir.Path("link.bin");
  NILKEY_EXPECT(symlink("real.bin", link.c_str()) == 0);
  const auto read = ReadVaultFile(link.c_str());
  NILKEY_EXPECT(!read.ok());
  NILKEY_EXPECT(read.error().code == ErrorCode::kSymlinkRejected);
}

NILKEY_TEST(read_rejects_directory_and_fifo) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string sub = dir.Path("subdir");
  NILKEY_EXPECT(mkdir(sub.c_str(), 0700) == 0);
  const auto from_dir = ReadVaultFile(sub.c_str());
  NILKEY_EXPECT(!from_dir.ok());
  NILKEY_EXPECT(from_dir.error().code == ErrorCode::kInvalidFormat);

  // Must return at once: a blocking open of a FIFO with no writer would hang.
  const std::string fifo = dir.Path("fifo");
  NILKEY_EXPECT(mkfifo(fifo.c_str(), 0600) == 0);
  const auto from_fifo = ReadVaultFile(fifo.c_str());
  NILKEY_EXPECT(!from_fifo.ok());
  NILKEY_EXPECT(from_fifo.error().code == ErrorCode::kInvalidFormat);
}

NILKEY_TEST(read_rejects_oversized_file_without_reading_it) {
  // A sparse file one byte over the limit: no data is stored and none may be
  // allocated or read.
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string path = dir.Path("big.bin");
  const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  NILKEY_EXPECT(fd >= 0);
  const off_t limit = static_cast<off_t>(nilkey::kHeaderSize + nilkey::kMaxPayloadSize);
  NILKEY_EXPECT(ftruncate(fd, limit + 1) == 0);
  NILKEY_EXPECT(close(fd) == 0);
  const auto too_big = ReadVaultFile(path.c_str());
  NILKEY_EXPECT(!too_big.ok());
  NILKEY_EXPECT(too_big.error().code == ErrorCode::kInvalidFormat);

  // Exactly at the limit is accepted (the header parser decides after that).
  NILKEY_EXPECT(truncate(path.c_str(), limit) == 0);
  const auto at_limit = ReadVaultFile(path.c_str());
  NILKEY_EXPECT(at_limit.ok());
  NILKEY_EXPECT(at_limit.value().size() == static_cast<std::size_t>(limit));
}

NILKEY_TEST(read_rejects_null_and_empty_path) {
  const auto null_result = ReadVaultFile(nullptr);
  NILKEY_EXPECT(!null_result.ok());
  NILKEY_EXPECT(null_result.error().code == ErrorCode::kInvalidArgument);
  const auto empty_result = ReadVaultFile("");
  NILKEY_EXPECT(!empty_result.ok());
  NILKEY_EXPECT(empty_result.error().code == ErrorCode::kInvalidArgument);
}

// SPEC.md 10 item 5, end to end: Seal -> disk -> read -> open.
namespace {

constexpr nilkey::KdfParams kFast = {8, 1};
constexpr MemlockPolicy kRequire = MemlockPolicy::kRequire;
constexpr std::array<std::byte, 6> kPassword = {std::byte{'s'}, std::byte{0x00}, std::byte{'e'},
                                                std::byte{'c'}, std::byte{0xC3}, std::byte{0xA9}};
constexpr std::array<std::byte, 5> kPlain = {std::byte{'v'}, std::byte{0x00}, std::byte{'a'},
                                             std::byte{'u'}, std::byte{'l'}};

bool PlaintextIs(const nilkey::SecureBuffer& buf, std::span<const std::byte> expected) {
  auto guard = ScopedReadGuard::Open(buf);
  if (!guard.ok()) return false;
  return nilkey::test::secret_equal(guard.value().bytes(), expected);
}

}  // namespace

NILKEY_TEST(vault_round_trips_through_disk) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string path = dir.Path("vault.bin");
  auto key = nilkey::NewVaultKey(kPassword, kFast, kRequire);
  NILKEY_EXPECT(key.ok());
  auto sealed = nilkey::Seal(key.value(), kPlain);
  NILKEY_EXPECT(sealed.ok());
  NILKEY_EXPECT(WriteFileAtomic(path.c_str(), sealed.value()).ok());
  NILKEY_EXPECT(ModeOf(path) == 0600);

  auto read = ReadVaultFile(path.c_str());
  NILKEY_EXPECT(read.ok());
  auto opened = nilkey::OpenWithPassword(read.value(), kPassword, kRequire);
  NILKEY_EXPECT(opened.ok());
  NILKEY_EXPECT(PlaintextIs(opened.value().plaintext, kPlain));
}

NILKEY_TEST(truncated_and_padded_vault_files_are_rejected) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  auto key = nilkey::NewVaultKey(kPassword, kFast, kRequire);
  NILKEY_EXPECT(key.ok());
  auto sealed = nilkey::Seal(key.value(), kPlain);
  NILKEY_EXPECT(sealed.ok());

  std::vector<std::byte> truncated = sealed.value();
  truncated.pop_back();
  std::vector<std::byte> padded = sealed.value();
  padded.push_back(std::byte{0});
  const std::vector<std::byte>* const variants[] = {&truncated, &padded};
  for (const std::vector<std::byte>* bytes : variants) {
    const std::string path = dir.Path("bad.bin");
    NILKEY_EXPECT(WriteFileAtomic(path.c_str(), *bytes).ok());
    auto read = ReadVaultFile(path.c_str());
    NILKEY_EXPECT(read.ok());  // The read layer is size-agnostic below the limit.
    NILKEY_EXPECT(!nilkey::OpenWithPassword(read.value(), kPassword, kRequire).ok());
    NILKEY_EXPECT(unlink(path.c_str()) == 0);
  }
}

NILKEY_TEST(each_save_writes_a_fresh_nonce) {
  // Nonce lives at header offset 38 (SPEC.md 5.1).
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string path = dir.Path("vault.bin");
  auto key = nilkey::NewVaultKey(kPassword, kFast, kRequire);
  NILKEY_EXPECT(key.ok());
  std::array<std::byte, nilkey::kNonceSize> previous{};
  for (int save = 0; save < 3; ++save) {
    auto sealed = nilkey::Seal(key.value(), kPlain);
    NILKEY_EXPECT(sealed.ok());
    NILKEY_EXPECT(WriteFileAtomic(path.c_str(), sealed.value()).ok());
    auto read = ReadVaultFile(path.c_str());
    NILKEY_EXPECT(read.ok());
    NILKEY_EXPECT(read.value().size() >= nilkey::kHeaderSize);
    std::array<std::byte, nilkey::kNonceSize> nonce{};
    for (std::size_t i = 0; i < nonce.size(); ++i) nonce[i] = read.value()[38 + i];
    if (save > 0) NILKEY_EXPECT(!nilkey::test::secret_equal(nonce, previous));
    previous = nonce;
  }
}

NILKEY_TEST_MAIN()

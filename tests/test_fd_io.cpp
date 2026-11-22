// ReadAllSecret: reading a descriptor to its end into a SecureBuffer. The data
// here is test data, not a secret.

#include <fcntl.h>
#include <unistd.h>

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include "nilkey/fd_io.hpp"
#include "temp_dir.hpp"
#include "test_framework.hpp"

using nilkey::ErrorCode;
using nilkey::MemlockPolicy;
using nilkey::ReadAllSecret;
using nilkey::ScopedReadGuard;
using nilkey::test::TempDir;

namespace {

constexpr MemlockPolicy kRequire = MemlockPolicy::kRequire;

std::vector<std::byte> B(std::string_view s) {
  std::vector<std::byte> b;
  for (const char c : s) b.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
  return b;
}

// The read end of a pipe that already holds `data` and has no writer left.
int PipeWith(std::string_view data) {
  int fds[2];
  if (pipe(fds) != 0) std::abort();
  const std::vector<std::byte> bytes = B(data);
  if (!nilkey::WriteAll(fds[1], bytes).ok()) std::abort();
  if (close(fds[1]) != 0) std::abort();
  return fds[0];
}

}  // namespace

NILKEY_TEST(reads_everything_until_the_end) {
  const int fd = PipeWith("hello notes");
  auto secret = ReadAllSecret(fd, 64, kRequire);
  NILKEY_EXPECT(close(fd) == 0);
  NILKEY_EXPECT(secret.ok());
  NILKEY_EXPECT(secret.value().size() == 11);
  auto guard = ScopedReadGuard::Open(secret.value());
  NILKEY_EXPECT(guard.ok());
  NILKEY_EXPECT_SECRET_EQ(guard.value().bytes(), std::span<const std::byte>(B("hello notes")));
}

NILKEY_TEST(empty_input_gives_an_empty_buffer) {
  const int fd = PipeWith("");
  auto secret = ReadAllSecret(fd, 64, kRequire);
  NILKEY_EXPECT(close(fd) == 0);
  NILKEY_EXPECT(secret.ok());
  NILKEY_EXPECT(secret.value().size() == 0);
}

NILKEY_TEST(accepts_exactly_the_limit_and_rejects_one_more) {
  const int exact = PipeWith(std::string(16, 'a'));
  auto at_limit = ReadAllSecret(exact, 16, kRequire);
  NILKEY_EXPECT(close(exact) == 0);
  NILKEY_EXPECT(at_limit.ok());
  NILKEY_EXPECT(at_limit.value().size() == 16);

  const int over = PipeWith(std::string(17, 'a'));
  auto too_long = ReadAllSecret(over, 16, kRequire);
  NILKEY_EXPECT(close(over) == 0);
  NILKEY_EXPECT(!too_long.ok());
  NILKEY_EXPECT(too_long.error().code == ErrorCode::kInputTooLong);
}

NILKEY_TEST(keeps_nul_and_bytes_that_are_not_utf8) {
  const std::string_view data("a\0b\xFF\xC3\xA9", 6);
  const int fd = PipeWith(data);
  auto secret = ReadAllSecret(fd, 64, kRequire);
  NILKEY_EXPECT(close(fd) == 0);
  NILKEY_EXPECT(secret.ok());
  auto guard = ScopedReadGuard::Open(secret.value());
  NILKEY_EXPECT(guard.ok());
  NILKEY_EXPECT_SECRET_EQ(guard.value().bytes(), std::span<const std::byte>(B(data)));
}

// A regular file larger than one read() hands back at most `max_size + 1` bytes.
NILKEY_TEST(reads_a_file_and_stops_at_the_limit) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string path = dir.Path("notes.txt");
  const int out = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  NILKEY_EXPECT(out >= 0);
  NILKEY_EXPECT(nilkey::WriteAll(out, B(std::string(1000, 'n'))).ok());
  NILKEY_EXPECT(close(out) == 0);

  const int in = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  NILKEY_EXPECT(in >= 0);
  auto whole = ReadAllSecret(in, 1000, kRequire);
  NILKEY_EXPECT(whole.ok() && whole.value().size() == 1000);
  NILKEY_EXPECT(close(in) == 0);

  const int again = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  NILKEY_EXPECT(again >= 0);
  auto cut = ReadAllSecret(again, 999, kRequire);
  NILKEY_EXPECT(!cut.ok() && cut.error().code == ErrorCode::kInputTooLong);
  NILKEY_EXPECT(close(again) == 0);
}

NILKEY_TEST(a_bad_descriptor_is_an_io_error) {
  auto secret = ReadAllSecret(-1, 16, kRequire);
  NILKEY_EXPECT(!secret.ok());
  NILKEY_EXPECT(secret.error().code == ErrorCode::kIoError);
}

NILKEY_TEST_MAIN()

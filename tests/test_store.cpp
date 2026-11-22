// Vault store: load and save, the lock, and the helpers around the path.
// Built against nilkey_core_test, so ParamsForNewVault() is the cheap KDF.

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "nilkey/atomic_file.hpp"
#include "nilkey/store.hpp"
#include "temp_dir.hpp"
#include "test_framework.hpp"

using nilkey::ErrorCode;
using nilkey::LoadVault;
using nilkey::MemlockPolicy;
using nilkey::NewVaultKey;
using nilkey::ParamsForNewVault;
using nilkey::RecordInput;
using nilkey::SaveVault;
using nilkey::Vault;
using nilkey::VaultKey;
using nilkey::VaultLock;
using nilkey::test::ModeOf;
using nilkey::test::Slurp;
using nilkey::test::TempDir;

namespace {

constexpr MemlockPolicy kRequire = MemlockPolicy::kRequire;
constexpr std::size_t kSaltOffset = 22;
constexpr std::size_t kNonceOffset = 38;

using Bytes = std::vector<std::byte>;

Bytes B(std::string_view s) {
  Bytes b;
  for (const char c : s) b.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
  return b;
}

std::span<const std::byte> View(const Bytes& b) { return b; }

bool Same(std::span<const std::byte> a, std::span<const std::byte> b) {
  return nilkey::test::secret_equal(a, b);
}

// A key for `password` with the cheap test costs.
VaultKey KeyFor(std::string_view password) {
  const Bytes pw = B(password);
  auto key = NewVaultKey(pw, ParamsForNewVault(), kRequire);
  if (!key.ok()) std::abort();
  return std::move(key).value();
}

// A vault with one record, `alpha` with password `p1`.
Vault VaultWithAlpha() {
  auto vault = Vault::CreateEmpty(kRequire);
  if (!vault.ok()) std::abort();
  const Bytes name = B("alpha");
  const Bytes password = B("p1");
  const RecordInput input{name, {}, password, {}, {}};
  if (!vault.value().Add(input, 100).ok()) std::abort();
  return std::move(vault).value();
}

std::span<const std::byte> Slice(const Bytes& file, std::size_t offset, std::size_t n) {
  return std::span<const std::byte>(file).subspan(offset, n);
}

}  // namespace

NILKEY_TEST(new_vaults_use_the_cheap_costs_in_the_test_build) {
  NILKEY_EXPECT(ParamsForNewVault().mem_kib == 8);
  NILKEY_EXPECT(ParamsForNewVault().iterations == 1);
}

NILKEY_TEST(save_then_load_round_trip) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string path = dir.Path("v.vault");
  const VaultKey key = KeyFor("master");
  const Vault vault = VaultWithAlpha();
  NILKEY_EXPECT(SaveVault(path, key, vault).ok());
  NILKEY_EXPECT(ModeOf(path) == 0600);

  auto loaded = LoadVault(path, B("master"), kRequire);
  NILKEY_EXPECT(loaded.ok());
  NILKEY_EXPECT(loaded.value().vault.size() == 1);
  auto reader = loaded.value().vault.Open();
  NILKEY_EXPECT(reader.ok());
  const Bytes name = B("alpha");
  const auto found = reader.value().Find(name);
  NILKEY_EXPECT(found.has_value());
  const auto record = reader.value().Get(*found);
  NILKEY_EXPECT(record.ok());
  NILKEY_EXPECT_SECRET_EQ(record.value().password, View(B("p1")));
  NILKEY_EXPECT(record.value().created_at == 100);
}

NILKEY_TEST(every_save_has_a_new_nonce_and_the_same_salt) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string path = dir.Path("v.vault");
  const VaultKey key = KeyFor("master");
  const Vault vault = VaultWithAlpha();

  Bytes first;
  Bytes second;
  NILKEY_EXPECT(SaveVault(path, key, vault).ok());
  NILKEY_EXPECT(Slurp(path, first));
  NILKEY_EXPECT(SaveVault(path, key, vault).ok());
  NILKEY_EXPECT(Slurp(path, second));

  NILKEY_EXPECT(!Same(Slice(first, kNonceOffset, 24), Slice(second, kNonceOffset, 24)));
  NILKEY_EXPECT(Same(Slice(first, kSaltOffset, 16), Slice(second, kSaltOffset, 16)));
  NILKEY_EXPECT(dir.EntryCount() == 1);  // No temp file left behind.
}

NILKEY_TEST(a_wrong_password_is_an_authentication_failure) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string path = dir.Path("v.vault");
  NILKEY_EXPECT(SaveVault(path, KeyFor("master"), VaultWithAlpha()).ok());

  auto loaded = LoadVault(path, B("wrong"), kRequire);
  NILKEY_EXPECT(!loaded.ok());
  NILKEY_EXPECT(loaded.error().code == ErrorCode::kAuthenticationFailed);
}

NILKEY_TEST(a_missing_vault_is_reported_as_such) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string path = dir.Path("none.vault");

  const auto exists = nilkey::RequireVaultExists(path);
  NILKEY_EXPECT(!exists.ok());
  NILKEY_EXPECT(exists.error().code == ErrorCode::kVaultNotFound);
  NILKEY_EXPECT(nilkey::RequireVaultAbsent(path).ok());

  const auto loaded = LoadVault(path, B("master"), kRequire);
  NILKEY_EXPECT(!loaded.ok());
  NILKEY_EXPECT(loaded.error().code == ErrorCode::kVaultNotFound);
}

NILKEY_TEST(an_existing_vault_is_reported_as_such) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string path = dir.Path("v.vault");
  NILKEY_EXPECT(SaveVault(path, KeyFor("master"), VaultWithAlpha()).ok());

  NILKEY_EXPECT(nilkey::RequireVaultExists(path).ok());
  const auto absent = nilkey::RequireVaultAbsent(path);
  NILKEY_EXPECT(!absent.ok());
  NILKEY_EXPECT(absent.error().code == ErrorCode::kVaultExists);
}

NILKEY_TEST(a_symbolic_link_counts_as_existing_and_is_not_followed) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string real = dir.Path("real.vault");
  const std::string link = dir.Path("link.vault");
  NILKEY_EXPECT(SaveVault(real, KeyFor("master"), VaultWithAlpha()).ok());
  NILKEY_EXPECT(symlink(real.c_str(), link.c_str()) == 0);

  NILKEY_EXPECT(nilkey::RequireVaultExists(link).ok());
  NILKEY_EXPECT(nilkey::RequireVaultAbsent(link).error().code == ErrorCode::kVaultExists);
  const auto loaded = LoadVault(link, B("master"), kRequire);
  NILKEY_EXPECT(!loaded.ok());
  NILKEY_EXPECT(loaded.error().code == ErrorCode::kSymlinkRejected);

  // A link to nothing is still something at that path.
  const std::string dangling = dir.Path("dangling.vault");
  NILKEY_EXPECT(symlink(dir.Path("nowhere").c_str(), dangling.c_str()) == 0);
  NILKEY_EXPECT(nilkey::RequireVaultAbsent(dangling).error().code == ErrorCode::kVaultExists);
}

NILKEY_TEST(creates_missing_parent_directories_with_mode_0700) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string path = dir.Path("a/b/c/v.vault");
  NILKEY_EXPECT(nilkey::EnsureParentDirectory(path).ok());
  NILKEY_EXPECT(ModeOf(dir.Path("a")) == 0700);
  NILKEY_EXPECT(ModeOf(dir.Path("a/b")) == 0700);
  NILKEY_EXPECT(ModeOf(dir.Path("a/b/c")) == 0700);
  // Running it again changes nothing.
  NILKEY_EXPECT(nilkey::EnsureParentDirectory(path).ok());
}

NILKEY_TEST(leaves_an_existing_directory_alone) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string shared = dir.Path("shared");
  NILKEY_EXPECT(mkdir(shared.c_str(), 0755) == 0);
  NILKEY_EXPECT(chmod(shared.c_str(), 0755) == 0);
  NILKEY_EXPECT(nilkey::EnsureParentDirectory(shared + "/v.vault").ok());
  NILKEY_EXPECT(ModeOf(shared) == 0755);
}

NILKEY_TEST(needs_no_directory_for_a_bare_file_name_or_the_root) {
  NILKEY_EXPECT(nilkey::EnsureParentDirectory("v.vault").ok());
  NILKEY_EXPECT(nilkey::EnsureParentDirectory("/v.vault").ok());
}

NILKEY_TEST(a_file_in_the_way_of_a_directory_is_an_error) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string blocker = dir.Path("blocker");
  const int fd = open(blocker.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  NILKEY_EXPECT(fd >= 0);
  NILKEY_EXPECT(close(fd) == 0);
  const auto s = nilkey::EnsureParentDirectory(blocker + "/sub/v.vault");
  NILKEY_EXPECT(!s.ok());
  NILKEY_EXPECT(s.error().code == ErrorCode::kIoError);
}

NILKEY_TEST(the_lock_file_is_private_and_next_to_the_vault) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string path = dir.Path("v.vault");
  auto lock = VaultLock::Acquire(path);
  NILKEY_EXPECT(lock.ok());
  NILKEY_EXPECT(ModeOf(path + ".lock") == 0600);
}

NILKEY_TEST(a_symbolic_link_as_lock_file_is_rejected) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string path = dir.Path("v.vault");
  NILKEY_EXPECT(symlink(dir.Path("elsewhere").c_str(), (path + ".lock").c_str()) == 0);
  const auto lock = VaultLock::Acquire(path);
  NILKEY_EXPECT(!lock.ok());
  NILKEY_EXPECT(lock.error().code == ErrorCode::kSymlinkRejected);
}

// The child is forked before the lock is taken. A flock() belongs to the open
// file description, so a child forked while the parent holds the lock would
// inherit a copy of it and keep the lock after the parent lets go.
NILKEY_TEST(a_second_holder_waits_until_the_first_lets_go) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string path = dir.Path("v.vault");

  int go[2];     // Parent to child: "try now".
  int ready[2];  // Child to parent: "I hold the lock".
  NILKEY_EXPECT(pipe(go) == 0);
  NILKEY_EXPECT(pipe(ready) == 0);
  const pid_t child = fork();
  NILKEY_EXPECT(child >= 0);
  if (child == 0) {
    char c = 0;
    if (read(go[0], &c, 1) != 1) _exit(1);
    auto second = VaultLock::Acquire(path);  // Blocks while the parent holds it.
    if (!second.ok()) _exit(2);
    if (write(ready[1], "x", 1) != 1) _exit(3);
    _exit(0);
  }
  NILKEY_EXPECT(close(go[0]) == 0);
  NILKEY_EXPECT(close(ready[1]) == 0);

  std::optional<VaultLock> held;
  {
    auto first = VaultLock::Acquire(path);
    NILKEY_EXPECT(first.ok());
    held.emplace(std::move(first).value());
  }
  NILKEY_EXPECT(write(go[1], "g", 1) == 1);

  // While the lock is held the child cannot get it, so nothing arrives. (A
  // working lock cannot make this check fail; a missing one makes it fail at
  // once, because the child then writes within milliseconds.)
  struct pollfd waiting = {ready[0], POLLIN, 0};
  NILKEY_EXPECT(poll(&waiting, 1, 300) == 0);

  held.reset();  // Release.
  waiting.revents = 0;
  NILKEY_EXPECT(poll(&waiting, 1, 10000) == 1);

  int status = 0;
  NILKEY_EXPECT(waitpid(child, &status, 0) == child);
  NILKEY_EXPECT(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  NILKEY_EXPECT(close(go[1]) == 0);
  NILKEY_EXPECT(close(ready[0]) == 0);
}

NILKEY_TEST_MAIN()

// `nilkey doctor` against the real command line (nilkey_e2e), on a vault in a
// temporary directory. Every run states the lock limit and the clipboard
// environment itself, so the result does not depend on the machine it runs on.
// The vaults hold no secret worth the name; the master password is test data.

#include <sys/stat.h>
#include <unistd.h>

#include <string>
#include <string_view>

#include "e2e_support.hpp"
#include "fake_clipboard.hpp"
#include "test_framework.hpp"

using namespace nilkey::test::e2e;  // NOLINT(build/namespaces)
using nilkey::test::InstallFakeXclip;
using nilkey::test::TempDir;

namespace {

constexpr rlim_t kEnoughKiB = 4096;  // Covers the test vault and its 8 KiB key derivation.

struct Doctor {
  int status = -1;
  std::string out;
  std::string terminal;
};

// Starts `doctor` with the lock limit `memlock_kib` and a clipboard tool that is
// found (the fake xclip in `dir`) or not.
Doctor RunDoctor(const TempDir& dir, const std::string& vault, rlim_t memlock_kib, bool tool,
                 const std::vector<std::string>& extra_args = {}) {
  CliEnv env;
  env.unset = {"WAYLAND_DISPLAY"};
  env.set = {{"DISPLAY", ":fake"},
             {"PATH", tool ? dir.dir() + ":/usr/bin:/bin" : "/nonexistent-nilkey-test"}};
  env.memlock_kib = memlock_kib;
  std::vector<std::string> args = {"doctor"};
  args.insert(args.end(), extra_args.begin(), extra_args.end());
  const Run run = RunCli(dir, vault, args, {}, nullptr, &env);
  return Doctor{run.status, run.out, run.terminal};
}

// Whether some line of `out` starts with `level` and contains `phrase`.
bool LineHas(const std::string& out, std::string_view level, std::string_view phrase) {
  std::size_t start = 0;
  while (start < out.size()) {
    std::size_t end = out.find('\n', start);
    if (end == std::string::npos) end = out.size();
    const std::string_view line(out.data() + start, end - start);
    if (line.substr(0, level.size()) == level && line.find(phrase) != std::string_view::npos) {
      return true;
    }
    start = end + 1;
  }
  return false;
}

bool MakeHealthyVault(const TempDir& dir, const std::string& vault) {
  return InstallFakeXclip(dir) && MakeVault(dir, vault, "a master password");
}

}  // namespace

NILKEY_TEST(a_healthy_setup_passes_and_never_asks_for_the_master_password) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  NILKEY_EXPECT(MakeHealthyVault(dir, vault));

  const Doctor d = RunDoctor(dir, vault, kEnoughKiB, true);
  NILKEY_EXPECT(d.status == 0);
  NILKEY_EXPECT(LineHas(d.out, "ok", "vault file: mode 0600"));
  NILKEY_EXPECT(LineHas(d.out, "ok", "directory: mode 0700"));
  NILKEY_EXPECT(LineHas(d.out, "ok", "memory lock limit"));
  NILKEY_EXPECT(LineHas(d.out, "ok", "key derivation memory"));
  NILKEY_EXPECT(LineHas(d.out, "ok", "core dumps"));
  NILKEY_EXPECT(LineHas(d.out, "ok", "core file size"));
  NILKEY_EXPECT(LineHas(d.out, "ok", "clipboard: X11 session"));
  NILKEY_EXPECT(!Has(d.out, "problem"));
  NILKEY_EXPECT(!Has(d.terminal, "password"));
}

NILKEY_TEST(the_vault_path_is_printed_once_and_the_lock_file_is_checked) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  NILKEY_EXPECT(MakeHealthyVault(dir, vault));
  NILKEY_EXPECT(WriteFile(vault + ".lock", ""));

  const Doctor d = RunDoctor(dir, vault, kEnoughKiB, true);
  NILKEY_EXPECT(d.status == 0);
  NILKEY_EXPECT(d.out.rfind("vault: " + vault + "\n", 0) == 0);
  NILKEY_EXPECT(LineHas(d.out, "ok", "lock file: mode 0600"));
}

NILKEY_TEST(a_vault_file_with_a_loose_mode_is_a_problem) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  NILKEY_EXPECT(MakeHealthyVault(dir, vault));
  NILKEY_EXPECT(chmod(vault.c_str(), 0644) == 0);

  const Doctor d = RunDoctor(dir, vault, kEnoughKiB, true);
  NILKEY_EXPECT(d.status == 1);
  NILKEY_EXPECT(LineHas(d.out, "problem", "vault file: mode 0644"));
}

NILKEY_TEST(a_lock_file_with_a_loose_mode_is_a_problem) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  NILKEY_EXPECT(MakeHealthyVault(dir, vault));
  NILKEY_EXPECT(WriteFile(vault + ".lock", ""));
  NILKEY_EXPECT(chmod((vault + ".lock").c_str(), 0666) == 0);

  const Doctor d = RunDoctor(dir, vault, kEnoughKiB, true);
  NILKEY_EXPECT(d.status == 1);
  NILKEY_EXPECT(LineHas(d.out, "problem", "lock file: mode 0666"));
}

NILKEY_TEST(a_symbolic_link_in_place_of_the_vault_is_a_problem) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string real = dir.Path("real.vault");
  const std::string link = dir.Path("link.vault");
  NILKEY_EXPECT(MakeHealthyVault(dir, real));
  NILKEY_EXPECT(symlink(real.c_str(), link.c_str()) == 0);

  const Doctor d = RunDoctor(dir, link, kEnoughKiB, true);
  NILKEY_EXPECT(d.status == 1);
  NILKEY_EXPECT(LineHas(d.out, "problem", "vault file: is a symbolic link"));
}

NILKEY_TEST(a_directory_others_can_write_is_a_problem) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  NILKEY_EXPECT(MakeHealthyVault(dir, vault));
  NILKEY_EXPECT(chmod(dir.dir().c_str(), 0777) == 0);

  const Doctor d = RunDoctor(dir, vault, kEnoughKiB, true);
  NILKEY_EXPECT(d.status == 1);
  NILKEY_EXPECT(LineHas(d.out, "problem", "directory: mode 0777"));
}

NILKEY_TEST(a_directory_others_can_only_read_is_a_note_and_not_a_failure) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  NILKEY_EXPECT(MakeHealthyVault(dir, vault));
  NILKEY_EXPECT(chmod(dir.dir().c_str(), 0755) == 0);

  const Doctor d = RunDoctor(dir, vault, kEnoughKiB, true);
  NILKEY_EXPECT(d.status == 0);
  NILKEY_EXPECT(LineHas(d.out, "note", "directory: mode 0755"));
}

NILKEY_TEST(no_vault_yet_is_a_note_and_a_small_lock_limit_for_argon2_is_only_a_note) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  NILKEY_EXPECT(InstallFakeXclip(dir));

  // The production Argon2id memory (64 MiB) does not fit in 4 MiB; that warns at
  // run time and must not fail `doctor`.
  const Doctor d = RunDoctor(dir, dir.Path("none.vault"), kEnoughKiB, true);
  NILKEY_EXPECT(d.status == 0);
  NILKEY_EXPECT(LineHas(d.out, "note", "vault file: not found"));
  NILKEY_EXPECT(LineHas(d.out, "note", "key derivation memory"));
  NILKEY_EXPECT(!Has(d.out, "problem"));
}

NILKEY_TEST(a_lock_limit_the_vault_does_not_fit_in_is_a_problem) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  NILKEY_EXPECT(MakeHealthyVault(dir, vault));

  const Doctor d = RunDoctor(dir, vault, 0, true);
  NILKEY_EXPECT(d.status == 1);
  NILKEY_EXPECT(LineHas(d.out, "problem", "memory lock limit: 0 KiB"));
  NILKEY_EXPECT(Has(d.out, "ulimit -l"));
}

NILKEY_TEST(a_damaged_header_is_a_problem) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  NILKEY_EXPECT(InstallFakeXclip(dir));
  NILKEY_EXPECT(WriteFile(vault, std::string(100, 'x')));

  const Doctor d = RunDoctor(dir, vault, kEnoughKiB, true);
  NILKEY_EXPECT(d.status == 1);
  NILKEY_EXPECT(LineHas(d.out, "problem", "vault header"));
}

NILKEY_TEST(a_missing_clipboard_tool_is_a_note_that_points_to_print) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  NILKEY_EXPECT(MakeHealthyVault(dir, vault));

  const Doctor d = RunDoctor(dir, vault, kEnoughKiB, false);
  NILKEY_EXPECT(d.status == 0);
  NILKEY_EXPECT(LineHas(d.out, "note", "clipboard: no tool found"));
  NILKEY_EXPECT(Has(d.out, "--print"));
}

NILKEY_TEST(the_clipboard_line_names_the_tool_that_get_would_use) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  NILKEY_EXPECT(MakeHealthyVault(dir, vault));

  const Doctor d = RunDoctor(dir, vault, kEnoughKiB, true);
  NILKEY_EXPECT(LineHas(d.out, "ok", "using " + dir.dir() + "/xclip"));
}

NILKEY_TEST(a_path_with_control_characters_cannot_act_on_the_terminal) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  NILKEY_EXPECT(InstallFakeXclip(dir));

  const Doctor d = RunDoctor(dir, dir.dir() + "/v\x1b[2J.vault", kEnoughKiB, true);
  NILKEY_EXPECT(d.status == 0);
  NILKEY_EXPECT(!Has(d.out, "\x1b"));
  NILKEY_EXPECT(Has(d.out, "v?[2J.vault"));
}

NILKEY_TEST(doctor_takes_no_arguments) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const Doctor d = RunDoctor(dir, dir.Path("v.vault"), kEnoughKiB, true, {"extra"});
  NILKEY_EXPECT(d.status == 2);
  NILKEY_EXPECT(d.out.empty());
}

NILKEY_TEST_MAIN()

// The commands update, delete and passwd, end to end: the real command line,
// in a child process on a pseudo-terminal, against a vault file on disk. The
// child is nilkey_e2e, the CLI built with the cheap test-only KDF costs. The
// helpers are shared with test_cli_e2e.cpp (e2e_support.hpp).
//
// Every check about what was stored reads the vault back through the library
// in this process. The passwords and notes here are test data.

#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include "e2e_support.hpp"
#include "nilkey/store.hpp"
#include "pty_harness.hpp"
#include "temp_dir.hpp"
#include "test_framework.hpp"

using nilkey::test::ModeOf;
using nilkey::test::PtyChild;
using nilkey::test::TempDir;

using namespace nilkey::test::e2e;

namespace {

constexpr const char* kCurrentPrompt = "Current master password: ";
constexpr const char* kConfirmPrompt = "Delete this record? [y/N] ";
constexpr const char* kAlphaNotes = "alpha notes\nsecond line\n";

// A vault with three records. Only `alpha` has a user name, url and notes.
bool Seed(const TempDir& dir, const std::string& vault, const std::string& master) {
  if (!MakeVault(dir, vault, master)) return false;

  const std::string notes_path = dir.Path("seed-notes.txt");
  if (!WriteFile(notes_path, kAlphaNotes)) return false;
  PtyChild child = StartCli(dir, vault,
                            {"add", "alpha", "--username", "alice", "--url",
                             "https://alpha.example", "--notes-stdin"},
                            notes_path.c_str());
  if (!Reply(child, {{kMasterPrompt, master},
                     {kRecordPrompt, "pw-alpha"},
                     {kRepeatRecordPrompt, "pw-alpha"}})) {
    return false;
  }
  if (child.Wait(kWaitMs) != 0) return false;
  return AddRecord(dir, vault, master, "beta", "pw-beta").status == 0 &&
         AddRecord(dir, vault, master, "gamma", "pw-gamma").status == 0;
}

Run Update(const TempDir& dir, const std::string& vault, const std::vector<std::string>& options,
           const std::vector<Answer>& answers, const char* stdin_path = nullptr) {
  std::vector<std::string> args = {"update"};
  args.insert(args.end(), options.begin(), options.end());
  return RunCli(dir, vault, args, answers, stdin_path);
}

Run Delete(const TempDir& dir, const std::string& vault, const std::vector<std::string>& options,
           const std::vector<Answer>& answers) {
  std::vector<std::string> args = {"delete"};
  args.insert(args.end(), options.begin(), options.end());
  return RunCli(dir, vault, args, answers);
}

std::vector<Answer> Passwd(const std::string& current, const std::string& next,
                           const std::string& again) {
  return {{kCurrentPrompt, current}, {kNewMasterPrompt, next}, {kRepeatNewMasterPrompt, again}};
}

// The record names in the order `list` shows them (first column).
std::vector<std::string> ListedNames(const TempDir& dir, const std::string& vault,
                                     const std::string& master) {
  const Run run = RunCli(dir, vault, {"list"}, {{kMasterPrompt, master}});
  std::vector<std::string> names;
  if (run.status != 0) return names;
  std::size_t start = 0;
  while (start < run.out.size()) {
    const std::size_t end = run.out.find('\n', start);
    const std::string line = run.out.substr(start, end - start);
    names.push_back(line.substr(0, line.find('\t')));
    if (end == std::string::npos) break;
    start = end + 1;
  }
  return names;
}

bool NonceChanged(const Bytes& before, const Bytes& after) {
  const Bytes a = Slice(before, kNonceOffset, 24);
  const Bytes b = Slice(after, kNonceOffset, 24);
  return !a.empty() && !b.empty() && a != b;
}

bool SaltKept(const Bytes& before, const Bytes& after) {
  const Bytes a = Slice(before, kSaltOffset, 16);
  return !a.empty() && a == Slice(after, kSaltOffset, 16);
}

// How many files in `dir` are left over from an interrupted atomic write.
int LeftoverTempFiles(const std::string& dir) {
  DIR* const handle = opendir(dir.c_str());
  if (handle == nullptr) return -1;
  int count = 0;
  while (const dirent* entry = readdir(handle)) {
    if (std::string_view(entry->d_name).find(".tmp.") != std::string_view::npos) ++count;
  }
  if (closedir(handle) != 0) return -1;
  return count;
}

// The test holds the lock itself, so the result does not depend on timing: the
// command must wait, change nothing, and finish once the lock is let go.
bool WaitsForTheLock(const TempDir& dir, const std::string& vault,
                     const std::vector<std::string>& args, const std::vector<Answer>& answers) {
  const Bytes before = ReadFile(vault);
  const int lock_fd = open((vault + ".lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  if (lock_fd < 0 || flock(lock_fd, LOCK_EX) != 0) return false;

  PtyChild child = StartCli(dir, vault, args);
  const bool answered = Reply(child, answers);
  child.Pump(400);
  const bool waiting = child.Running() && SameBytes(ReadFile(vault), before);

  if (close(lock_fd) != 0) return false;  // Releases the lock.
  return answered && waiting && child.Wait(kWaitMs) == 0 && !SameBytes(ReadFile(vault), before);
}

}  // namespace

// ---- update ----

NILKEY_TEST(update_changes_only_the_fields_that_are_given) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass m1";
  NILKEY_EXPECT(Seed(dir, vault, master));
  const Stored before = Lookup(vault, master, "alpha");
  const Bytes file_before = ReadFile(vault);
  NILKEY_EXPECT(before.found);

  const Run run = Update(dir, vault, {"alpha", "--username", "bob"}, {{kMasterPrompt, master}});
  NILKEY_EXPECT(run.answered);
  NILKEY_EXPECT(run.status == 0);
  NILKEY_EXPECT(run.out.empty());
  NILKEY_EXPECT(Has(run.terminal, "Updated \"alpha\"."));

  const Stored after = Lookup(vault, master, "alpha");
  NILKEY_EXPECT(after.found);
  NILKEY_EXPECT(after.username == "bob");
  NILKEY_EXPECT(after.password == "pw-alpha");
  NILKEY_EXPECT(after.url == "https://alpha.example");
  NILKEY_EXPECT(after.notes == kAlphaNotes);
  NILKEY_EXPECT(after.created_at == before.created_at);
  NILKEY_EXPECT(after.updated_at >= before.updated_at);
  // The other records are untouched, and nothing moved.
  NILKEY_EXPECT(Lookup(vault, master, "beta").password == "pw-beta");
  NILKEY_EXPECT((ListedNames(dir, vault, master) ==
                 std::vector<std::string>{"alpha", "beta", "gamma"}));

  NILKEY_EXPECT(NonceChanged(file_before, ReadFile(vault)));
  NILKEY_EXPECT(SaltKept(file_before, ReadFile(vault)));
  NILKEY_EXPECT(ModeOf(vault) == 0600);
}

NILKEY_TEST(update_can_rename_but_not_onto_another_record) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass m2";
  NILKEY_EXPECT(Seed(dir, vault, master));

  const Run taken = Update(dir, vault, {"alpha", "--rename", "beta"}, {{kMasterPrompt, master}});
  NILKEY_EXPECT(taken.status == 1);
  NILKEY_EXPECT(Has(taken.terminal, "a record with this name already exists"));
  const Bytes unchanged = ReadFile(vault);

  const Run same = Update(dir, vault, {"alpha", "--rename", "alpha"}, {{kMasterPrompt, master}});
  NILKEY_EXPECT(same.status == 0);

  const Run renamed =
      Update(dir, vault, {"alpha", "--rename", "alpha two"}, {{kMasterPrompt, master}});
  NILKEY_EXPECT(renamed.status == 0);
  NILKEY_EXPECT(!Lookup(vault, master, "alpha").found);
  const Stored moved = Lookup(vault, master, "alpha two");
  NILKEY_EXPECT(moved.found);
  NILKEY_EXPECT(moved.password == "pw-alpha");
  NILKEY_EXPECT(moved.username == "alice");
  NILKEY_EXPECT((ListedNames(dir, vault, master) ==
                 std::vector<std::string>{"alpha two", "beta", "gamma"}));
  NILKEY_EXPECT(!SameBytes(ReadFile(vault), unchanged));
}

NILKEY_TEST(update_asks_for_a_new_password_twice_and_checks_it) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass m3";
  NILKEY_EXPECT(Seed(dir, vault, master));
  const Bytes before = ReadFile(vault);

  const Run mismatch = Update(dir, vault, {"alpha", "--prompt-password"},
                              {{kMasterPrompt, master},
                               {kRecordPrompt, "first try"},
                               {kRepeatRecordPrompt, "second try"}});
  NILKEY_EXPECT(mismatch.status == 1);
  NILKEY_EXPECT(Has(mismatch.terminal, "the two entries do not match"));
  NILKEY_EXPECT(SameBytes(ReadFile(vault), before));

  const std::string fresh = "n\xC3\xAF" "w-secret";
  const Run run = Update(dir, vault, {"alpha", "--prompt-password"},
                         {{kMasterPrompt, master},
                          {kRecordPrompt, fresh},
                          {kRepeatRecordPrompt, fresh}});
  NILKEY_EXPECT(run.status == 0);
  NILKEY_EXPECT(!Has(run.terminal, fresh));  // Echo is off.
  const Stored after = Lookup(vault, master, "alpha");
  NILKEY_EXPECT(after.password == fresh);
  NILKEY_EXPECT(after.username == "alice");
  NILKEY_EXPECT(after.notes == kAlphaNotes);
}

NILKEY_TEST(update_generate_asks_no_password_and_keeps_the_other_fields) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass m4";
  NILKEY_EXPECT(Seed(dir, vault, master));

  // Only the master password is asked; a record password prompt would hang.
  const Run run = Update(dir, vault, {"alpha", "--generate"}, {{kMasterPrompt, master}});
  NILKEY_EXPECT(run.answered);
  NILKEY_EXPECT(run.status == 0);
  NILKEY_EXPECT(!Has(run.terminal, kRecordPrompt));

  const Stored after = Lookup(vault, master, "alpha");
  NILKEY_EXPECT(after.password.size() == 20);
  NILKEY_EXPECT(after.password != "pw-alpha");
  NILKEY_EXPECT(after.password.find_first_not_of(kAlphabet) == std::string::npos);
  NILKEY_EXPECT(after.username == "alice");
  NILKEY_EXPECT(after.url == "https://alpha.example");
}

NILKEY_TEST(update_can_clear_and_replace_optional_fields) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass m5";
  NILKEY_EXPECT(Seed(dir, vault, master));

  // An empty value, given either way, clears the field.
  const Run cleared = Update(dir, vault, {"alpha", "--username", "", "--url="},
                             {{kMasterPrompt, master}});
  NILKEY_EXPECT(cleared.status == 0);
  Stored stored = Lookup(vault, master, "alpha");
  NILKEY_EXPECT(stored.username.empty() && stored.url.empty());
  NILKEY_EXPECT(stored.notes == kAlphaNotes);
  NILKEY_EXPECT(stored.password == "pw-alpha");

  const std::string notes_path = dir.Path("new-notes.txt");
  NILKEY_EXPECT(WriteFile(notes_path, "replaced \xC3\xA9"));
  const Run replaced = Update(dir, vault, {"alpha", "--notes-stdin"}, {{kMasterPrompt, master}},
                              notes_path.c_str());
  NILKEY_EXPECT(replaced.status == 0);
  stored = Lookup(vault, master, "alpha");
  NILKEY_EXPECT(stored.notes == "replaced \xC3\xA9");

  // Empty stdin clears the notes.
  NILKEY_EXPECT(WriteFile(notes_path, ""));
  const Run emptied = Update(dir, vault, {"alpha", "--notes-stdin"}, {{kMasterPrompt, master}},
                             notes_path.c_str());
  NILKEY_EXPECT(emptied.status == 0);
  NILKEY_EXPECT(Lookup(vault, master, "alpha").notes.empty());
}

NILKEY_TEST(update_refuses_bad_command_lines_before_any_prompt) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  NILKEY_EXPECT(Seed(dir, vault, "master pass m6"));
  const Bytes before = ReadFile(vault);

  const std::vector<std::vector<std::string>> bad = {
      {"alpha"},                                                // nothing to change
      {"alpha", "--prompt-password", "--generate"},             // two ways to set it
      {"alpha", "--rename", ""},                                // empty new name
      {"alpha", "--rename", std::string(1025, 'n')},            // new name too long
      {"alpha", "--rename", "\xFF"},                            // new name not UTF-8
      {"alpha", "--username", "\xFF"},
      {"alpha", "--url", "\xC3"},
      {"", "--username", "x"},                                  // empty name
      {"\xFF", "--username", "x"},
      {"alpha", "--rename", "a\x1b[31mb"},                      // control characters
      {"alpha", "--rename", "a\tb"},
      {"alpha", "--rename", "a\nb"},
      {"alpha", "--rename", "a\xC2\x85" "b"},                    // C1 control
      {"alpha", "--rename", "a\xE2\x80\xAE" "b"},               // U+202E
      {"alpha", "--username", "a\x1b[2Jb"},
      {"alpha", "--username", "a\tb"},
      {"alpha", "--url", "http://x/\n"},
      {"alpha", "--url", "a\xE2\x80\xAE" "b"},
  };
  for (const std::vector<std::string>& options : bad) {
    const Run run = Update(dir, vault, options, {});
    NILKEY_EXPECT(run.status == 2);
    NILKEY_EXPECT(!Has(run.terminal, kMasterPrompt));
  }
  NILKEY_EXPECT(SameBytes(ReadFile(vault), before));
}

NILKEY_TEST(update_names_the_option_that_holds_a_control_character) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  NILKEY_EXPECT(Seed(dir, vault, "master pass m6"));

  const struct {
    std::vector<std::string> options;
    const char* message;
  } cases[] = {
      {{"alpha", "--rename", "a\x1b" "b"}, "--rename must not contain control characters"},
      {{"alpha", "--username", "a\tb"}, "--username must not contain control characters"},
      {{"alpha", "--url", "a\nb"}, "--url must not contain control characters"},
  };
  for (const auto& c : cases) {
    const Run run = Update(dir, vault, c.options, {});
    NILKEY_EXPECT(run.status == 2);
    NILKEY_EXPECT(Has(run.terminal, c.message));
  }
}

// A record that an older version or another writer made, with a control
// character in its name, can still be found, changed, renamed and deleted: only
// text that is being written is checked.
NILKEY_TEST(a_record_with_a_control_character_in_its_name_can_still_be_changed_and_removed) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass m7";
  NILKEY_EXPECT(Seed(dir, vault, master));
  const std::string legacy = "old\x1b[31m name";
  NILKEY_EXPECT(SeedRecord(vault, master, legacy, "", "pw-old", ""));

  const Run changed = Update(dir, vault, {legacy, "--username", "carol"}, {{kMasterPrompt, master}});
  NILKEY_EXPECT(changed.status == 0);
  NILKEY_EXPECT(Lookup(vault, master, legacy).username == "carol");

  const Run renamed = Update(dir, vault, {legacy, "--rename", "old name"}, {{kMasterPrompt, master}});
  NILKEY_EXPECT(renamed.status == 0);
  NILKEY_EXPECT(!Lookup(vault, master, legacy).found);
  NILKEY_EXPECT(Lookup(vault, master, "old name").found);

  NILKEY_EXPECT(SeedRecord(vault, master, "other\tname", "", "pw-other", ""));
  const Run removed = Delete(dir, vault, {"other\tname", "--yes"}, {{kMasterPrompt, master}});
  NILKEY_EXPECT(removed.status == 0);
  NILKEY_EXPECT(!Lookup(vault, master, "other\tname").found);
}

NILKEY_TEST(update_reports_a_missing_record_and_a_wrong_master_password) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass m7";
  NILKEY_EXPECT(Seed(dir, vault, master));
  const Bytes before = ReadFile(vault);

  const Run missing = Update(dir, vault, {"nope", "--username", "x"}, {{kMasterPrompt, master}});
  NILKEY_EXPECT(missing.status == 1);
  NILKEY_EXPECT(Has(missing.terminal, "record not found"));
  NILKEY_EXPECT(SameBytes(ReadFile(vault), before));

  const std::string secret = "must-not-appear";
  const Run wrong = Update(dir, vault, {"alpha", "--prompt-password"},
                           {{kMasterPrompt, "not the master"},
                            {kRecordPrompt, secret},
                            {kRepeatRecordPrompt, secret}});
  NILKEY_EXPECT(wrong.status == 1);
  NILKEY_EXPECT(Has(wrong.terminal, "wrong password or corrupted vault file"));
  NILKEY_EXPECT(!Has(wrong.terminal, secret));
  NILKEY_EXPECT(SameBytes(ReadFile(vault), before));

  const Run no_vault = Update(dir, dir.Path("none.vault"), {"alpha", "--username", "x"}, {});
  NILKEY_EXPECT(no_vault.status == 1);
  NILKEY_EXPECT(Has(no_vault.terminal, "vault file not found"));
  NILKEY_EXPECT(!Has(no_vault.terminal, kMasterPrompt));
}

// ---- delete ----

NILKEY_TEST(delete_asks_first_and_only_yes_removes_the_record) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass d1";
  NILKEY_EXPECT(Seed(dir, vault, master));
  const Bytes before = ReadFile(vault);

  // Anything but y or yes is a no, and the master password is never asked.
  for (const char* answer : {"n", "", "maybe", "yep"}) {
    const Run declined = Delete(dir, vault, {"beta"}, {{kConfirmPrompt, answer}});
    NILKEY_EXPECT(declined.status == 1);
    NILKEY_EXPECT(Has(declined.terminal, "not deleted"));
    NILKEY_EXPECT(!Has(declined.terminal, kMasterPrompt));
    NILKEY_EXPECT(SameBytes(ReadFile(vault), before));
  }

  const Run run = Delete(dir, vault, {"beta"}, {{kConfirmPrompt, "y"}, {kMasterPrompt, master}});
  NILKEY_EXPECT(run.answered);
  NILKEY_EXPECT(run.status == 0);
  NILKEY_EXPECT(run.out.empty());
  NILKEY_EXPECT(Has(run.terminal, "Deleted \"beta\"."));

  NILKEY_EXPECT(!Lookup(vault, master, "beta").found);
  NILKEY_EXPECT(Lookup(vault, master, "alpha").password == "pw-alpha");
  NILKEY_EXPECT(Lookup(vault, master, "gamma").password == "pw-gamma");
  NILKEY_EXPECT((ListedNames(dir, vault, master) == std::vector<std::string>{"alpha", "gamma"}));

  const Bytes after = ReadFile(vault);
  NILKEY_EXPECT(NonceChanged(before, after));
  NILKEY_EXPECT(SaltKept(before, after));
  NILKEY_EXPECT(ModeOf(vault) == 0600);
}

NILKEY_TEST(delete_with_yes_asks_no_confirmation) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass d2";
  NILKEY_EXPECT(Seed(dir, vault, master));

  const Run run = Delete(dir, vault, {"gamma", "--yes"}, {{kMasterPrompt, master}});
  NILKEY_EXPECT(run.answered);
  NILKEY_EXPECT(run.status == 0);
  NILKEY_EXPECT(!Has(run.terminal, kConfirmPrompt));
  NILKEY_EXPECT(!Lookup(vault, master, "gamma").found);
  NILKEY_EXPECT(Lookup(vault, master, "alpha").found);
}

NILKEY_TEST(delete_reports_a_missing_record_and_a_wrong_master_password) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass d3";
  NILKEY_EXPECT(Seed(dir, vault, master));
  const Bytes before = ReadFile(vault);

  const Run missing = Delete(dir, vault, {"nope", "--yes"}, {{kMasterPrompt, master}});
  NILKEY_EXPECT(missing.status == 1);
  NILKEY_EXPECT(Has(missing.terminal, "record not found"));
  NILKEY_EXPECT(SameBytes(ReadFile(vault), before));

  const Run wrong = Delete(dir, vault, {"alpha", "--yes"}, {{kMasterPrompt, "not the master"}});
  NILKEY_EXPECT(wrong.status == 1);
  NILKEY_EXPECT(Has(wrong.terminal, "wrong password or corrupted vault file"));
  NILKEY_EXPECT(SameBytes(ReadFile(vault), before));

  for (const std::vector<std::string>& options : {std::vector<std::string>{""},
                                                  std::vector<std::string>{"\xFF"}}) {
    const Run bad = Delete(dir, vault, options, {});
    NILKEY_EXPECT(bad.status == 2);
    NILKEY_EXPECT(!Has(bad.terminal, kConfirmPrompt));
  }
}

NILKEY_TEST(delete_can_be_aborted_at_the_confirmation) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  NILKEY_EXPECT(Seed(dir, vault, "master pass d4"));
  const Bytes before = ReadFile(vault);

  PtyChild child = StartCli(dir, vault, {"delete", "alpha"});
  NILKEY_EXPECT(child.WaitFor(kConfirmPrompt, kWaitMs));
  child.Send("\x03");
  NILKEY_EXPECT(child.Wait(kWaitMs) == 130);
  NILKEY_EXPECT(Has(child.output(), "aborted"));
  NILKEY_EXPECT(SameBytes(ReadFile(vault), before));
}

// ---- passwd ----

NILKEY_TEST(passwd_re_keys_the_vault_and_keeps_every_record) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string old_master = "old master 1";
  const std::string new_master = "new m\xC3\xA4ster 2";
  NILKEY_EXPECT(Seed(dir, vault, old_master));
  const Bytes before = ReadFile(vault);
  const Stored alpha = Lookup(vault, old_master, "alpha");
  const Stored beta = Lookup(vault, old_master, "beta");
  const Stored gamma = Lookup(vault, old_master, "gamma");
  NILKEY_EXPECT(alpha.found && beta.found && gamma.found);

  const Run run = RunCli(dir, vault, {"passwd"}, Passwd(old_master, new_master, new_master));
  NILKEY_EXPECT(run.answered);
  NILKEY_EXPECT(run.status == 0);
  NILKEY_EXPECT(run.out.empty());
  NILKEY_EXPECT(Has(run.terminal, "Master password changed."));
  NILKEY_EXPECT(!Has(run.terminal, old_master) && !Has(run.terminal, new_master));

  // SPEC 10.4: a new salt and a new nonce ...
  const Bytes after = ReadFile(vault);
  NILKEY_EXPECT(NonceChanged(before, after));
  const Bytes old_salt = Slice(before, kSaltOffset, 16);
  const Bytes new_salt = Slice(after, kSaltOffset, 16);
  NILKEY_EXPECT(!old_salt.empty() && !new_salt.empty() && old_salt != new_salt);
  NILKEY_EXPECT(ModeOf(vault) == 0600);
  NILKEY_EXPECT(LeftoverTempFiles(dir.Path(".")) == 0);

  // ... the old password is refused, the new one opens everything.
  NILKEY_EXPECT(!Lookup(vault, old_master, "alpha").found);
  const Run old_list = RunCli(dir, vault, {"list"}, {{kMasterPrompt, old_master}});
  NILKEY_EXPECT(old_list.status == 1);
  NILKEY_EXPECT(old_list.out.empty());
  NILKEY_EXPECT(Has(old_list.terminal, "wrong password or corrupted vault file"));

  const Stored alpha2 = Lookup(vault, new_master, "alpha");
  const Stored beta2 = Lookup(vault, new_master, "beta");
  const Stored gamma2 = Lookup(vault, new_master, "gamma");
  NILKEY_EXPECT(alpha2.found && beta2.found && gamma2.found);
  NILKEY_EXPECT(alpha2.password == alpha.password && alpha2.username == alpha.username);
  NILKEY_EXPECT(alpha2.url == alpha.url && alpha2.notes == alpha.notes);
  NILKEY_EXPECT(alpha2.created_at == alpha.created_at && alpha2.updated_at == alpha.updated_at);
  NILKEY_EXPECT(beta2.password == beta.password && gamma2.password == gamma.password);
  NILKEY_EXPECT((ListedNames(dir, vault, new_master) ==
                 std::vector<std::string>{"alpha", "beta", "gamma"}));
}

NILKEY_TEST(passwd_refuses_a_wrong_current_password_and_a_bad_new_one) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass p2";
  NILKEY_EXPECT(Seed(dir, vault, master));
  const Bytes before = ReadFile(vault);

  const std::string secret = "must-not-appear-1";
  const Run wrong = RunCli(dir, vault, {"passwd"}, Passwd("not the master", secret, secret));
  NILKEY_EXPECT(wrong.status == 1);
  NILKEY_EXPECT(Has(wrong.terminal, "wrong password or corrupted vault file"));
  NILKEY_EXPECT(!Has(wrong.terminal, secret));
  NILKEY_EXPECT(SameBytes(ReadFile(vault), before));

  const Run mismatch = RunCli(dir, vault, {"passwd"}, Passwd(master, "one", "two"));
  NILKEY_EXPECT(mismatch.status == 1);
  NILKEY_EXPECT(Has(mismatch.terminal, "the two entries do not match"));
  NILKEY_EXPECT(SameBytes(ReadFile(vault), before));

  const Run empty = RunCli(dir, vault, {"passwd"},
                           {{kCurrentPrompt, master}, {kNewMasterPrompt, ""}});
  NILKEY_EXPECT(empty.status == 1);
  NILKEY_EXPECT(Has(empty.terminal, "input is empty"));
  NILKEY_EXPECT(SameBytes(ReadFile(vault), before));

  // The old password still works.
  NILKEY_EXPECT(Lookup(vault, master, "alpha").found);
}

NILKEY_TEST(passwd_can_be_aborted_and_needs_a_vault) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  NILKEY_EXPECT(Seed(dir, vault, "master pass p3"));
  const Bytes before = ReadFile(vault);

  PtyChild child = StartCli(dir, vault, {"passwd"});
  NILKEY_EXPECT(child.WaitFor(kCurrentPrompt, kWaitMs));
  child.Send("\x03");
  NILKEY_EXPECT(child.Wait(kWaitMs) == 130);
  NILKEY_EXPECT(SameBytes(ReadFile(vault), before));

  const Run none = RunCli(dir, dir.Path("none.vault"), {"passwd"}, {});
  NILKEY_EXPECT(none.status == 1);
  NILKEY_EXPECT(Has(none.terminal, "vault file not found"));
  NILKEY_EXPECT(!Has(none.terminal, kCurrentPrompt));
}

// ---- the lock ----

NILKEY_TEST(update_delete_and_passwd_wait_for_the_vault_lock) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass l1";
  NILKEY_EXPECT(Seed(dir, vault, master));

  NILKEY_EXPECT(WaitsForTheLock(dir, vault, {"update", "alpha", "--generate"},
                                {{kMasterPrompt, master}}));
  NILKEY_EXPECT(WaitsForTheLock(dir, vault, {"delete", "beta"},
                                {{kConfirmPrompt, "y"}, {kMasterPrompt, master}}));
  NILKEY_EXPECT(WaitsForTheLock(dir, vault, {"passwd"}, Passwd(master, "other master", "other master")));
}

NILKEY_TEST_MAIN()

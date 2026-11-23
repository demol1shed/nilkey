// The commands init, add and list, end to end: the real command line, in a
// child process on a pseudo-terminal, against a vault file on disk. The child
// is nilkey_e2e, the CLI built with the cheap test-only KDF costs.
//
// Every check about what was stored reads the vault back through the library in
// this process, so "written" and "read" are proven independently. The
// passwords and notes here are test data.

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstddef>
#include <ctime>
#include <string>
#include <string_view>
#include <vector>

#include "e2e_support.hpp"
#include "nilkey/store.hpp"
#include "pty_harness.hpp"
#include "temp_dir.hpp"
#include "test_framework.hpp"

using nilkey::MemlockPolicy;
using nilkey::test::ModeOf;
using nilkey::test::PtyChild;
using nilkey::test::Slurp;
using nilkey::test::TempDir;

using namespace nilkey::test::e2e;

NILKEY_TEST(init_creates_a_private_vault_and_directories) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("sub/deeper/v.vault");
  const std::string master = "correct horse battery 1";

  const Run run = RunCli(dir, vault, {"init"},
                         {{kNewMasterPrompt, master}, {kRepeatNewMasterPrompt, master}});
  NILKEY_EXPECT(run.answered);
  NILKEY_EXPECT(run.status == 0);
  NILKEY_EXPECT(run.out.empty());
  NILKEY_EXPECT(Has(run.terminal, "Created vault: "));
  NILKEY_EXPECT(!Has(run.terminal, master));  // Echo is off.

  NILKEY_EXPECT(ModeOf(vault) == 0600);
  NILKEY_EXPECT(ModeOf(dir.Path("sub")) == 0700);
  NILKEY_EXPECT(ModeOf(dir.Path("sub/deeper")) == 0700);
  const Bytes file = ReadFile(vault);
  NILKEY_EXPECT(file.size() > 66);
  NILKEY_EXPECT(TextOf(Slice(file, 0, 8)) == std::string("NILKEY1\0", 8));
}

NILKEY_TEST(init_refuses_an_existing_vault_before_asking_anything) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  NILKEY_EXPECT(MakeVault(dir, vault, "first master"));
  const Bytes before = ReadFile(vault);

  const Run run = RunCli(dir, vault, {"init"}, {});
  NILKEY_EXPECT(run.status == 1);
  NILKEY_EXPECT(Has(run.terminal, "vault file already exists"));
  NILKEY_EXPECT(!Has(run.terminal, kNewMasterPrompt));
  NILKEY_EXPECT(SameBytes(ReadFile(vault), before));
}

NILKEY_TEST(init_rejects_two_different_or_an_empty_password) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");

  const Run differ = RunCli(dir, vault, {"init"},
                            {{kNewMasterPrompt, "one"}, {kRepeatNewMasterPrompt, "two"}});
  NILKEY_EXPECT(differ.status == 1);
  NILKEY_EXPECT(Has(differ.terminal, "the two entries do not match"));
  NILKEY_EXPECT(!Exists(vault));

  const Run empty = RunCli(dir, vault, {"init"}, {{kNewMasterPrompt, ""}});
  NILKEY_EXPECT(empty.status == 1);
  NILKEY_EXPECT(Has(empty.terminal, "input is empty"));
  NILKEY_EXPECT(!Exists(vault));
}

NILKEY_TEST(init_can_be_aborted_with_ctrl_c) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  PtyChild child = StartCli(dir, vault, {"init"});
  NILKEY_EXPECT(child.WaitFor(kNewMasterPrompt, kWaitMs));
  child.Send("\x03");
  NILKEY_EXPECT(child.Wait(kWaitMs) == 130);
  NILKEY_EXPECT(Has(child.output(), "aborted"));
  NILKEY_EXPECT(!Exists(vault));
}

NILKEY_TEST(add_stores_exactly_what_was_given) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass 1";
  NILKEY_EXPECT(MakeVault(dir, vault, master));

  const std::string notes = "line1\nline2 \xC3\xA9\n";
  NILKEY_EXPECT(WriteFile(dir.Path("notes.txt"), notes));
  const std::string password = "p\xC3\xA4ssw\xC3\xB6rd-s3cret";

  const auto before = std::time(nullptr);
  const std::string stdin_path = dir.Path("notes.txt");
  PtyChild child = StartCli(dir, vault,
                            {"add", "site", "--username", "bob", "--url", "https://example.org",
                             "--notes-stdin"},
                            stdin_path.c_str());
  NILKEY_EXPECT(Reply(child, {{kMasterPrompt, master},
                              {kRecordPrompt, password},
                              {kRepeatRecordPrompt, password}}));
  NILKEY_EXPECT(child.Wait(kWaitMs) == 0);
  const auto after = std::time(nullptr);
  NILKEY_EXPECT(Has(child.output(), "Added \"site\"."));
  NILKEY_EXPECT(!Has(child.output(), password));  // Echo is off.
  NILKEY_EXPECT(!Has(child.output(), "line1"));
  NILKEY_EXPECT(ModeOf(vault) == 0600);

  const Stored stored = Lookup(vault, master, "site");
  NILKEY_EXPECT(stored.found);
  NILKEY_EXPECT(stored.password == password);
  NILKEY_EXPECT(stored.username == "bob");
  NILKEY_EXPECT(stored.url == "https://example.org");
  NILKEY_EXPECT(stored.notes == notes);
  NILKEY_EXPECT(stored.created_at == stored.updated_at);
  NILKEY_EXPECT(stored.created_at >= before && stored.created_at <= after);
}

NILKEY_TEST(add_generate_asks_no_record_password) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass 2";
  NILKEY_EXPECT(MakeVault(dir, vault, master));

  // Only the master password is asked; a record password prompt would hang.
  const Run run = RunCli(dir, vault, {"add", "gen", "--generate"}, {{kMasterPrompt, master}});
  NILKEY_EXPECT(run.answered);
  NILKEY_EXPECT(run.status == 0);
  NILKEY_EXPECT(!Has(run.terminal, kRecordPrompt));

  const Stored stored = Lookup(vault, master, "gen");
  NILKEY_EXPECT(stored.found);
  NILKEY_EXPECT(stored.password.size() == 20);
  NILKEY_EXPECT(stored.password.find_first_not_of(kAlphabet) == std::string::npos);
}

NILKEY_TEST(every_write_has_a_new_nonce_and_keeps_the_salt) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass 3";
  NILKEY_EXPECT(MakeVault(dir, vault, master));
  const Bytes created = ReadFile(vault);

  NILKEY_EXPECT(AddRecord(dir, vault, master, "a", "pw-a").status == 0);
  const Bytes after_a = ReadFile(vault);
  NILKEY_EXPECT(AddRecord(dir, vault, master, "b", "pw-b").status == 0);
  const Bytes after_b = ReadFile(vault);

  const Bytes n0 = Slice(created, kNonceOffset, 24);
  const Bytes n1 = Slice(after_a, kNonceOffset, 24);
  const Bytes n2 = Slice(after_b, kNonceOffset, 24);
  NILKEY_EXPECT(!n0.empty() && !n1.empty() && !n2.empty());
  NILKEY_EXPECT(n0 != n1 && n1 != n2 && n0 != n2);
  const Bytes salt = Slice(created, kSaltOffset, 16);
  NILKEY_EXPECT(Slice(after_a, kSaltOffset, 16) == salt);
  NILKEY_EXPECT(Slice(after_b, kSaltOffset, 16) == salt);
  NILKEY_EXPECT(ModeOf(vault) == 0600);
}

NILKEY_TEST(a_duplicate_name_is_refused_and_changes_nothing) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass 4";
  NILKEY_EXPECT(MakeVault(dir, vault, master));
  NILKEY_EXPECT(AddRecord(dir, vault, master, "site", "first").status == 0);
  const Bytes before = ReadFile(vault);

  const Run again = AddRecord(dir, vault, master, "site", "second");
  NILKEY_EXPECT(again.status == 1);
  NILKEY_EXPECT(Has(again.terminal, "a record with this name already exists"));
  NILKEY_EXPECT(SameBytes(ReadFile(vault), before));
  NILKEY_EXPECT(Lookup(vault, master, "site").password == "first");
}

NILKEY_TEST(a_wrong_master_password_shows_nothing_and_changes_nothing) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass 5";
  NILKEY_EXPECT(MakeVault(dir, vault, master));
  NILKEY_EXPECT(AddRecord(dir, vault, master, "site", "pw-site", {"--username", "carol"}).status == 0);
  const Bytes before = ReadFile(vault);

  const Run list = RunCli(dir, vault, {"list"}, {{kMasterPrompt, "not the master"}});
  NILKEY_EXPECT(list.status == 1);
  NILKEY_EXPECT(list.out.empty());
  NILKEY_EXPECT(Has(list.terminal, "wrong password or corrupted vault file"));
  NILKEY_EXPECT(!Has(list.terminal, "site"));
  NILKEY_EXPECT(!Has(list.terminal, "carol"));

  const Run add = RunCli(dir, vault, {"add", "x", "--generate"}, {{kMasterPrompt, "not the master"}});
  NILKEY_EXPECT(add.status == 1);
  NILKEY_EXPECT(Has(add.terminal, "wrong password or corrupted vault file"));
  NILKEY_EXPECT(SameBytes(ReadFile(vault), before));

  // Typing the record password is not requested: the master is checked first.
  const Run typed = RunCli(dir, vault, {"add", "y"}, {{kMasterPrompt, "not the master"}});
  NILKEY_EXPECT(typed.answered);
  NILKEY_EXPECT(typed.status == 1);
  NILKEY_EXPECT(Has(typed.terminal, "wrong password or corrupted vault file"));
  NILKEY_EXPECT(!Has(typed.terminal, kRecordPrompt));
  NILKEY_EXPECT(SameBytes(ReadFile(vault), before));
}

NILKEY_TEST(a_missing_vault_is_reported_before_any_prompt) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("none.vault");
  for (const std::vector<std::string>& args :
       {std::vector<std::string>{"list"}, std::vector<std::string>{"add", "x"}}) {
    const Run run = RunCli(dir, vault, args, {});
    NILKEY_EXPECT(run.status == 1);
    NILKEY_EXPECT(Has(run.terminal, "vault file not found"));
    NILKEY_EXPECT(Has(run.terminal, "nilkey init"));
    NILKEY_EXPECT(!Has(run.terminal, kMasterPrompt));
  }
  NILKEY_EXPECT(!Exists(vault));
}

NILKEY_TEST(damaged_vault_files_and_links_are_refused) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass 6";
  NILKEY_EXPECT(MakeVault(dir, vault, master));

  // A symbolic link in place of the vault.
  const std::string link = dir.Path("link.vault");
  NILKEY_EXPECT(symlink(vault.c_str(), link.c_str()) == 0);
  const Run linked = RunCli(dir, link, {"list"}, {{kMasterPrompt, master}});
  NILKEY_EXPECT(linked.status == 1);
  NILKEY_EXPECT(Has(linked.terminal, "vault path is a symbolic link"));

  // A truncated file.
  const std::string cut = dir.Path("cut.vault");
  Bytes file = ReadFile(vault);
  file.resize(file.size() - 10);
  NILKEY_EXPECT(WriteFile(cut, std::string_view(reinterpret_cast<const char*>(file.data()), file.size())));
  const Run truncated = RunCli(dir, cut, {"list"}, {{kMasterPrompt, master}});
  NILKEY_EXPECT(truncated.status == 1);
  NILKEY_EXPECT(Has(truncated.terminal, "invalid vault file format"));

  // A file with a byte too many.
  const std::string longer = dir.Path("long.vault");
  file = ReadFile(vault);
  file.push_back(std::byte{0});
  NILKEY_EXPECT(WriteFile(longer, std::string_view(reinterpret_cast<const char*>(file.data()), file.size())));
  const Run trailing = RunCli(dir, longer, {"list"}, {{kMasterPrompt, master}});
  NILKEY_EXPECT(trailing.status == 1);
  NILKEY_EXPECT(Has(trailing.terminal, "invalid vault file format"));
}

NILKEY_TEST(bad_arguments_are_refused_before_any_prompt_and_change_nothing) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  NILKEY_EXPECT(MakeVault(dir, vault, "master pass 7"));
  const Bytes before = ReadFile(vault);

  const std::vector<std::vector<std::string>> bad = {
      {"add", ""},                                // empty name
      {"add", std::string(1025, 'n')},            // name too long
      {"add", "\xFF"},                            // not UTF-8
      {"add", "n", "--username", "\xFF"},
      {"add", "n", "--url", "\xC3"},
      {"add", "\x1b[31mred"},                      // control characters
      {"add", "a\tb"},
      {"add", "a\nb"},
      {"add", "a\xC2\x85" "b"},                     // C1 control
      {"add", "a\xE2\x80\xAE" "b"},                // U+202E
      {"add", "n", "--username", "a\x1b[2Jb"},
      {"add", "n", "--username", "a\tb"},
      {"add", "n", "--url", "http://x/\n"},
      {"add", "n", "--url", "a\xE2\x80\xAE" "b"},
  };
  for (const std::vector<std::string>& args : bad) {
    const Run run = RunCli(dir, vault, args, {});
    NILKEY_EXPECT(run.status == 2);
    NILKEY_EXPECT(!Has(run.terminal, kMasterPrompt));
  }
  NILKEY_EXPECT(SameBytes(ReadFile(vault), before));
}

NILKEY_TEST(control_characters_are_refused_with_a_message_naming_the_option) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  NILKEY_EXPECT(MakeVault(dir, vault, "master pass 7"));

  const struct {
    std::vector<std::string> args;
    const char* message;
  } cases[] = {
      {{"add", "a\x1b" "b"}, "the name must not contain control characters"},
      {{"add", "n", "--username", "a\tb"}, "--username must not contain control characters"},
      {{"add", "n", "--url", "a\nb"}, "--url must not contain control characters"},
  };
  for (const auto& c : cases) {
    const Run run = RunCli(dir, vault, c.args, {});
    NILKEY_EXPECT(run.status == 2);
    NILKEY_EXPECT(Has(run.terminal, c.message));
  }
}

NILKEY_TEST(notes_may_hold_control_characters_and_text_that_only_looks_unusual_is_accepted) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass 7";
  NILKEY_EXPECT(MakeVault(dir, vault, master));
  const std::string notes_path = dir.Path("notes.txt");
  NILKEY_EXPECT(WriteFile(notes_path, "line\tone\x1b[0m\nline two\n"));
  const std::string name = "t\xC3\xBCrk\xC3\xA7" "e \xF0\x9F\x94\x91";  // Turkish letters and an emoji
  const Run run = RunCli(dir, vault, {"add", name, "--username", "\xC4\xB1\xC5\x9F\xC4\x9F", "--notes-stdin"},
                         {{kMasterPrompt, master}, {kRecordPrompt, "pw"}, {kRepeatRecordPrompt, "pw"}},
                         notes_path.c_str());
  NILKEY_EXPECT(run.status == 0);
  const Stored stored = Lookup(vault, master, name);
  NILKEY_EXPECT(stored.found);
  NILKEY_EXPECT(stored.notes == "line\tone\x1b[0m\nline two\n");
}

NILKEY_TEST(notes_must_be_utf8_and_at_most_64_kib) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass 8";
  NILKEY_EXPECT(MakeVault(dir, vault, master));
  const Bytes before = ReadFile(vault);
  const std::string notes_path = dir.Path("notes.txt");

  NILKEY_EXPECT(WriteFile(notes_path, "bad \xFF notes"));
  const Run invalid = RunCli(dir, vault, {"add", "n", "--generate", "--notes-stdin"}, {},
                             notes_path.c_str());
  NILKEY_EXPECT(invalid.status == 2);
  NILKEY_EXPECT(Has(invalid.terminal, "the notes are not valid UTF-8"));
  NILKEY_EXPECT(!Has(invalid.terminal, kMasterPrompt));

  NILKEY_EXPECT(WriteFile(notes_path, std::string(65537, 'a')));
  const Run too_long = RunCli(dir, vault, {"add", "n", "--generate", "--notes-stdin"}, {},
                              notes_path.c_str());
  NILKEY_EXPECT(too_long.status == 2);
  NILKEY_EXPECT(Has(too_long.terminal, "the notes are longer than 64 KiB"));
  NILKEY_EXPECT(SameBytes(ReadFile(vault), before));

  // Exactly 64 KiB is fine.
  NILKEY_EXPECT(WriteFile(notes_path, std::string(65536, 'b')));
  const Run exact = RunCli(dir, vault, {"add", "n", "--generate", "--notes-stdin"},
                           {{kMasterPrompt, master}}, notes_path.c_str());
  NILKEY_EXPECT(exact.status == 0);
  NILKEY_EXPECT(Lookup(vault, master, "n").notes.size() == 65536);
}

NILKEY_TEST(list_shows_names_users_and_times_with_controls_defused) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass 9";
  NILKEY_EXPECT(MakeVault(dir, vault, master));
  NILKEY_EXPECT(AddRecord(dir, vault, master, "plain", "pw1", {"--username", "alice"}).status == 0);
  // The CLI refuses such names, so they are written through the library, as an
  // older version or another writer could have.
  NILKEY_EXPECT(SeedRecord(vault, master, "\x1b[31mred", "bob", "pw2", ""));
  NILKEY_EXPECT(SeedRecord(vault, master, "tab\there", "", "pw3", ""));

  const Run run = RunCli(dir, vault, {"list"}, {{kMasterPrompt, master}});
  NILKEY_EXPECT(run.status == 0);
  NILKEY_EXPECT(run.out.find('\x1b') == std::string::npos);
  NILKEY_EXPECT(!Has(run.out, "pw1") && !Has(run.out, "pw2") && !Has(run.out, "pw3"));

  std::vector<std::string> lines;
  std::size_t start = 0;
  while (start < run.out.size()) {
    const std::size_t end = run.out.find('\n', start);
    lines.push_back(run.out.substr(start, end - start));
    if (end == std::string::npos) break;
    start = end + 1;
  }
  NILKEY_EXPECT(lines.size() == 3);

  const char* names[] = {"plain", "?[31mred", "tab?here"};
  const char* users[] = {"alice", "bob", ""};
  for (std::size_t i = 0; i < 3 && i < lines.size(); ++i) {
    const std::size_t first = lines[i].find('\t');
    const std::size_t second = lines[i].find('\t', first + 1);
    NILKEY_EXPECT(first != std::string::npos && second != std::string::npos);
    NILKEY_EXPECT(lines[i].find('\t', second + 1) == std::string::npos);  // Exactly 3 columns.
    NILKEY_EXPECT(lines[i].substr(0, first) == names[i]);
    NILKEY_EXPECT(lines[i].substr(first + 1, second - first - 1) == users[i]);
    const std::string when = lines[i].substr(second + 1);
    NILKEY_EXPECT(when.size() == 20 && when[10] == 'T' && when[19] == 'Z');
  }
}

// The lines `list` printed after the master password prompt, without the
// terminal's carriage returns. The line break that the terminal shows when the
// password is entered is not one of them.
std::vector<std::string> LinesAfterPrompt(const std::string& terminal) {
  const std::size_t prompt = terminal.find(kMasterPrompt);
  if (prompt == std::string::npos) return {"<no prompt>"};
  const std::size_t entered = terminal.find('\n', prompt);
  if (entered == std::string::npos) return {"<no line break after the prompt>"};
  const std::string text = terminal.substr(entered + 1);
  std::vector<std::string> lines;
  std::size_t start = 0;
  while (start < text.size()) {
    const std::size_t end = text.find('\n', start);
    std::string line = text.substr(start, end - start);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    lines.push_back(line);
    if (end == std::string::npos) break;
    start = end + 1;
  }
  return lines;
}

NILKEY_TEST(list_on_a_terminal_lines_up_the_columns) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass 9";
  NILKEY_EXPECT(MakeVault(dir, vault, master));
  const std::string key_name = "\xF0\x9F\x94\x91 key";            // 6 cells: the emoji takes two
  const std::string turkish = "t\xC3\xBCrk\xC3\xA7" "e \xC4\xB1";  // 8 cells
  NILKEY_EXPECT(AddRecord(dir, vault, master, "plain", "pw1", {"--username", "alice"}).status == 0);
  NILKEY_EXPECT(AddRecord(dir, vault, master, key_name, "pw2", {"--username", "a-rather-long-user-name"}).status == 0);
  NILKEY_EXPECT(AddRecord(dir, vault, master, turkish, "pw3").status == 0);
  NILKEY_EXPECT(SeedRecord(vault, master, "\x1b[31mred", "bob", "pw4", ""));  // Refused by the CLI.

  CliEnv env;
  env.stdout_on_terminal = true;
  const Run run = RunCli(dir, vault, {"list"}, {{kMasterPrompt, master}}, nullptr, &env);
  NILKEY_EXPECT(run.status == 0);
  NILKEY_EXPECT(run.out.empty());
  NILKEY_EXPECT(run.terminal.find('\t') == std::string::npos);
  NILKEY_EXPECT(!Has(run.terminal, "pw1") && !Has(run.terminal, "pw2") && !Has(run.terminal, "pw3") &&
                !Has(run.terminal, "pw4"));

  // The name column is 8 cells wide and the user name column 23, each followed
  // by two spaces. The expected text is written out, not computed.
  const std::string long_user = "a-rather-long-user-name";
  const std::string expected_prefix[] = {
      "NAME" + std::string(6, ' ') + "USERNAME" + std::string(17, ' ') + "UPDATED",
      "plain" + std::string(5, ' ') + "alice" + std::string(20, ' '),
      key_name + std::string(4, ' ') + long_user + std::string(2, ' '),
      turkish + std::string(2, ' ') + std::string(25, ' '),
      "?[31mred" + std::string(2, ' ') + "bob" + std::string(22, ' '),
  };
  const std::vector<std::string> lines = LinesAfterPrompt(run.terminal);
  NILKEY_EXPECT(lines.size() == 5);
  NILKEY_EXPECT(lines.size() == 5 && lines[0] == expected_prefix[0]);
  for (std::size_t i = 1; i < 5 && i < lines.size(); ++i) {
    NILKEY_EXPECT(lines[i].rfind(expected_prefix[i], 0) == 0);
    const std::string when = lines[i].substr(expected_prefix[i].size());
    NILKEY_EXPECT(when.size() == 20 && when[10] == 'T' && when[19] == 'Z');
  }
}

NILKEY_TEST(list_on_a_terminal_prints_nothing_for_an_empty_vault) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass 9";
  NILKEY_EXPECT(MakeVault(dir, vault, master));

  CliEnv env;
  env.stdout_on_terminal = true;
  const Run run = RunCli(dir, vault, {"list"}, {{kMasterPrompt, master}}, nullptr, &env);
  NILKEY_EXPECT(run.status == 0);
  NILKEY_EXPECT(LinesAfterPrompt(run.terminal).empty());
  NILKEY_EXPECT(!Has(run.terminal, "NAME"));
}

NILKEY_TEST(an_empty_vault_lists_nothing) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  NILKEY_EXPECT(MakeVault(dir, vault, "master pass 10"));
  const Run run = RunCli(dir, vault, {"list"}, {{kMasterPrompt, "master pass 10"}});
  NILKEY_EXPECT(run.status == 0);
  NILKEY_EXPECT(run.out.empty());
}

// The test holds the lock itself, so the result does not depend on timing: the
// command must wait, change nothing, and finish once the lock is let go.
NILKEY_TEST(add_waits_for_the_vault_lock) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "master pass 11";
  NILKEY_EXPECT(MakeVault(dir, vault, master));
  const Bytes before = ReadFile(vault);

  const int lock_fd = open((vault + ".lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  NILKEY_EXPECT(lock_fd >= 0);
  NILKEY_EXPECT(flock(lock_fd, LOCK_EX) == 0);

  PtyChild child = StartCli(dir, vault, {"add", "locked", "--generate"});
  NILKEY_EXPECT(Reply(child, {{kMasterPrompt, master}}));
  child.Pump(400);
  NILKEY_EXPECT(child.Running());
  NILKEY_EXPECT(SameBytes(ReadFile(vault), before));

  NILKEY_EXPECT(close(lock_fd) == 0);  // Releases the lock.
  NILKEY_EXPECT(child.Wait(kWaitMs) == 0);
  NILKEY_EXPECT(Lookup(vault, master, "locked").found);
}

NILKEY_TEST_MAIN()

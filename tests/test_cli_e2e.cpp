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

#include "nilkey/store.hpp"
#include "pty_harness.hpp"
#include "temp_dir.hpp"
#include "test_framework.hpp"

using nilkey::MemlockPolicy;
using nilkey::test::ModeOf;
using nilkey::test::PtyChild;
using nilkey::test::Slurp;
using nilkey::test::TempDir;

namespace {

constexpr MemlockPolicy kRequire = MemlockPolicy::kRequire;
constexpr int kWaitMs = 30000;  // Generous: the children run under the sanitizers.

constexpr const char* kMasterPrompt = "Master password: ";
constexpr const char* kNewMasterPrompt = "New master password: ";
constexpr const char* kRepeatNewMasterPrompt = "Repeat the new master password: ";
constexpr const char* kRecordPrompt = "Password for the record: ";
constexpr const char* kRepeatRecordPrompt = "Repeat the password: ";

constexpr std::size_t kSaltOffset = 22;
constexpr std::size_t kNonceOffset = 38;

using Bytes = std::vector<std::byte>;

struct Answer {
  const char* prompt;
  std::string reply;
};

struct Run {
  int status = -1;
  bool answered = false;  // Every prompt in the list appeared.
  std::string terminal;   // Prompts and messages, as shown on the terminal.
  std::string out;        // What went to stdout.
};

PtyChild StartCli(const TempDir& dir, const std::string& vault, const std::vector<std::string>& args,
                  const char* stdin_path = nullptr) {
  std::vector<std::string> full = {"nilkey", "--vault", vault};
  full.insert(full.end(), args.begin(), args.end());
  const std::string stdout_path = dir.Path("stdout.txt");
  PtyChild::ExecOptions options;
  options.stdin_path = stdin_path;
  options.stdout_path = stdout_path.c_str();
  return PtyChild::StartExec(NILKEY_E2E_BINARY, full, options);
}

// Types each reply once its prompt has shown. False if a prompt never comes.
bool Reply(PtyChild& child, const std::vector<Answer>& answers) {
  for (const Answer& a : answers) {
    if (!child.WaitFor(a.prompt, kWaitMs)) return false;
    child.Send(a.reply + "\n");
  }
  return true;
}

std::string TextOf(const Bytes& bytes) {
  return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

Run RunCli(const TempDir& dir, const std::string& vault, const std::vector<std::string>& args,
           const std::vector<Answer>& answers, const char* stdin_path = nullptr) {
  PtyChild child = StartCli(dir, vault, args, stdin_path);
  Run run;
  run.answered = Reply(child, answers);
  if (!run.answered) child.Kill(SIGKILL);
  run.status = child.Wait(kWaitMs);
  run.terminal = child.output();
  Bytes out;
  if (Slurp(dir.Path("stdout.txt"), out)) run.out = TextOf(out);
  return run;
}

Bytes ReadFile(const std::string& path) {
  Bytes bytes;
  if (!Slurp(path, bytes)) bytes.clear();
  return bytes;
}

bool WriteFile(const std::string& path, std::string_view data) {
  const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) return false;
  const bool wrote = write(fd, data.data(), data.size()) == static_cast<ssize_t>(data.size());
  return close(fd) == 0 && wrote;
}

bool Exists(const std::string& path) { return access(path.c_str(), F_OK) == 0; }

bool Has(const std::string& text, std::string_view part) {
  return text.find(part) != std::string::npos;
}

bool SameBytes(const Bytes& a, const Bytes& b) { return a == b; }

// Bytes [offset, offset + n) of a vault file.
Bytes Slice(const Bytes& file, std::size_t offset, std::size_t n) {
  if (file.size() < offset + n) return {};
  return Bytes(file.begin() + static_cast<std::ptrdiff_t>(offset),
               file.begin() + static_cast<std::ptrdiff_t>(offset + n));
}

bool MakeVault(const TempDir& dir, const std::string& vault, const std::string& master) {
  const Run run = RunCli(dir, vault, {"init"},
                         {{kNewMasterPrompt, master}, {kRepeatNewMasterPrompt, master}});
  return run.status == 0 && run.answered;
}

// Adds a record with a typed password.
Run AddRecord(const TempDir& dir, const std::string& vault, const std::string& master,
              const std::string& name, const std::string& password,
              std::vector<std::string> options = {}) {
  std::vector<std::string> args = {"add", name};
  args.insert(args.end(), options.begin(), options.end());
  return RunCli(dir, vault, args,
                {{kMasterPrompt, master}, {kRecordPrompt, password}, {kRepeatRecordPrompt, password}});
}

struct Stored {
  bool found = false;
  std::string password;
  std::string username;
  std::string url;
  std::string notes;
  std::int64_t created_at = 0;
  std::int64_t updated_at = 0;
};

// Reads a record back through the library.
Stored Lookup(const std::string& vault, const std::string& master, std::string_view name) {
  Stored stored;
  const Bytes pw(reinterpret_cast<const std::byte*>(master.data()),
                 reinterpret_cast<const std::byte*>(master.data()) + master.size());
  auto loaded = nilkey::LoadVault(vault, pw, kRequire);
  if (!loaded.ok()) return stored;
  auto reader = loaded.value().vault.Open();
  if (!reader.ok()) return stored;
  const std::span<const std::byte> wanted(reinterpret_cast<const std::byte*>(name.data()),
                                          name.size());
  const auto index = reader.value().Find(wanted);
  if (!index.has_value()) return stored;
  const auto record = reader.value().Get(*index);
  if (!record.ok()) return stored;
  const auto text = [](std::span<const std::byte> b) {
    return std::string(reinterpret_cast<const char*>(b.data()), b.size());
  };
  stored.found = true;
  stored.password = text(record.value().password);
  stored.username = text(record.value().username);
  stored.url = text(record.value().url);
  stored.notes = text(record.value().notes);
  stored.created_at = record.value().created_at;
  stored.updated_at = record.value().updated_at;
  return stored;
}

constexpr std::string_view kAlphabet =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>/?";

}  // namespace

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
  };
  for (const std::vector<std::string>& args : bad) {
    const Run run = RunCli(dir, vault, args, {});
    NILKEY_EXPECT(run.status == 2);
    NILKEY_EXPECT(!Has(run.terminal, kMasterPrompt));
  }
  NILKEY_EXPECT(SameBytes(ReadFile(vault), before));
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
  NILKEY_EXPECT(AddRecord(dir, vault, master, "\x1b[31mred", "pw2", {"--username", "bob"}).status == 0);
  NILKEY_EXPECT(AddRecord(dir, vault, master, "tab\there", "pw3").status == 0);

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

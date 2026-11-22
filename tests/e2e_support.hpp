#ifndef NILKEY_TEST_E2E_SUPPORT_HPP
#define NILKEY_TEST_E2E_SUPPORT_HPP

// What the end-to-end tests of the command line share: starting nilkey_e2e on
// a pseudo-terminal, typing the answers to its prompts, and reading a vault
// back through the library. The passwords and notes in these tests are test
// data.

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "nilkey/store.hpp"
#include "pty_harness.hpp"
#include "temp_dir.hpp"

namespace nilkey::test::e2e {

using nilkey::MemlockPolicy;


inline constexpr MemlockPolicy kRequire = MemlockPolicy::kRequire;
inline constexpr int kWaitMs = 30000;  // Generous: the children run under the sanitizers.

inline constexpr const char* kMasterPrompt = "Master password: ";
inline constexpr const char* kNewMasterPrompt = "New master password: ";
inline constexpr const char* kRepeatNewMasterPrompt = "Repeat the new master password: ";
inline constexpr const char* kRecordPrompt = "Password for the record: ";
inline constexpr const char* kRepeatRecordPrompt = "Repeat the password: ";

inline constexpr std::size_t kSaltOffset = 22;
inline constexpr std::size_t kNonceOffset = 38;

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

inline PtyChild StartCli(const TempDir& dir, const std::string& vault, const std::vector<std::string>& args,
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
inline bool Reply(PtyChild& child, const std::vector<Answer>& answers) {
  for (const Answer& a : answers) {
    if (!child.WaitFor(a.prompt, kWaitMs)) return false;
    child.Send(a.reply + "\n");
  }
  return true;
}

inline std::string TextOf(const Bytes& bytes) {
  return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

inline Run RunCli(const TempDir& dir, const std::string& vault, const std::vector<std::string>& args,
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

inline Bytes ReadFile(const std::string& path) {
  Bytes bytes;
  if (!Slurp(path, bytes)) bytes.clear();
  return bytes;
}

inline bool WriteFile(const std::string& path, std::string_view data) {
  const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) return false;
  const bool wrote = write(fd, data.data(), data.size()) == static_cast<ssize_t>(data.size());
  return close(fd) == 0 && wrote;
}

inline bool Exists(const std::string& path) { return access(path.c_str(), F_OK) == 0; }

inline bool Has(const std::string& text, std::string_view part) {
  return text.find(part) != std::string::npos;
}

inline bool SameBytes(const Bytes& a, const Bytes& b) { return a == b; }

// Bytes [offset, offset + n) of a vault file.
inline Bytes Slice(const Bytes& file, std::size_t offset, std::size_t n) {
  if (file.size() < offset + n) return {};
  return Bytes(file.begin() + static_cast<std::ptrdiff_t>(offset),
               file.begin() + static_cast<std::ptrdiff_t>(offset + n));
}

inline bool MakeVault(const TempDir& dir, const std::string& vault, const std::string& master) {
  const Run run = RunCli(dir, vault, {"init"},
                         {{kNewMasterPrompt, master}, {kRepeatNewMasterPrompt, master}});
  return run.status == 0 && run.answered;
}

// Adds a record with a typed password.
inline Run AddRecord(const TempDir& dir, const std::string& vault, const std::string& master,
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
inline Stored Lookup(const std::string& vault, const std::string& master, std::string_view name) {
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

inline constexpr std::string_view kAlphabet =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>/?";

}  // namespace nilkey::test::e2e

#endif  // NILKEY_TEST_E2E_SUPPORT_HPP

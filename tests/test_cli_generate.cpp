// The `generate` command through the real Run(): the password goes to a pipe
// (or, for the terminal case, to a pty), the diagnostics to memory streams.
// Generated passwords are random test data, not secrets.

#include <signal.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "nilkey/cli.hpp"
#include "pty_harness.hpp"
#include "test_framework.hpp"

using nilkey::Io;
using nilkey::test::PtyChild;

namespace {

constexpr std::string_view kLower = "abcdefghijklmnopqrstuvwxyz";
constexpr std::string_view kUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
constexpr std::string_view kDigits = "0123456789";
constexpr std::string_view kSymbols = "!@#$%^&*()-_=+[]{};:,.<>/?";

struct Captured {
  int status;
  std::string password;  // What reached the output descriptor.
  std::string out;       // What went to the stdio stream.
  std::string err;
};

std::string Drain(std::FILE* stream, char*& buffer, std::size_t& size) {
  std::fclose(stream);  // Fills `buffer` and `size`.
  std::string text(buffer == nullptr ? "" : buffer, size);
  std::free(buffer);
  buffer = nullptr;
  return text;
}

// Ignores SIGPIPE for the lifetime of the object. NILKEY_EXPECT returns early
// on a failed check, so the old action is restored by the destructor.
class IgnoreSigpipe {
 public:
  IgnoreSigpipe() {
    struct sigaction ignore = {};
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    if (sigaction(SIGPIPE, &ignore, &old_) != 0) std::abort();
  }
  IgnoreSigpipe(const IgnoreSigpipe&) = delete;
  IgnoreSigpipe& operator=(const IgnoreSigpipe&) = delete;
  ~IgnoreSigpipe() {
    if (sigaction(SIGPIPE, &old_, nullptr) != 0) std::abort();
  }

 private:
  struct sigaction old_ = {};
};

// Runs with the output descriptor being a pipe. With `reader_open` false the
// read end is closed first, so writing to it fails.
Captured RunGenerate(std::initializer_list<const char*> args, bool reader_open = true) {
  int fds[2];
  if (pipe(fds) != 0) std::abort();
  if (!reader_open && close(fds[0]) != 0) std::abort();

  char* out_buffer = nullptr;
  std::size_t out_size = 0;
  char* err_buffer = nullptr;
  std::size_t err_size = 0;
  std::FILE* out = open_memstream(&out_buffer, &out_size);
  std::FILE* err = open_memstream(&err_buffer, &err_size);
  if (out == nullptr || err == nullptr) std::abort();

  const std::vector<const char*> v(args);
  Captured result;
  result.status = nilkey::Run(std::span<const char* const>(v), Io{out, err, fds[1]});
  if (close(fds[1]) != 0) std::abort();

  if (reader_open) {
    char chunk[256];
    for (;;) {
      const ssize_t n = read(fds[0], chunk, sizeof chunk);
      if (n <= 0) break;
      result.password.append(chunk, static_cast<std::size_t>(n));
    }
    if (close(fds[0]) != 0) std::abort();
  }
  result.out = Drain(out, out_buffer, out_size);
  result.err = Drain(err, err_buffer, err_size);
  return result;
}

bool AllFrom(const std::string& text, std::initializer_list<std::string_view> sets) {
  for (const char c : text) {
    bool found = false;
    for (const std::string_view set : sets) found = found || set.find(c) != std::string_view::npos;
    if (!found) return false;
  }
  return true;
}

bool HasAnyOf(const std::string& text, std::string_view set) {
  return text.find_first_of(set) != std::string::npos;
}

int BodyGenerateOnTerminal() {
  const char* args[] = {"generate", "--length", "16"};
  return nilkey::Run(std::span<const char* const>(args), Io{stdout, stderr, STDOUT_FILENO}) == 0
             ? 0
             : 10;
}

}  // namespace

NILKEY_TEST(default_password_is_twenty_characters_without_a_line_break) {
  const Captured r = RunGenerate({"generate"});
  NILKEY_EXPECT(r.status == nilkey::kExitOk);
  NILKEY_EXPECT(r.password.size() == 20);  // No '\n': a pipe is not a terminal.
  NILKEY_EXPECT(AllFrom(r.password, {kLower, kUpper, kDigits, kSymbols}));
  NILKEY_EXPECT(HasAnyOf(r.password, kLower) && HasAnyOf(r.password, kUpper));
  NILKEY_EXPECT(HasAnyOf(r.password, kDigits) && HasAnyOf(r.password, kSymbols));
  NILKEY_EXPECT(r.out.empty());
  NILKEY_EXPECT(r.err.empty());
}

NILKEY_TEST(length_option_in_both_forms_and_at_the_limits) {
  NILKEY_EXPECT(RunGenerate({"generate", "--length", "32"}).password.size() == 32);
  NILKEY_EXPECT(RunGenerate({"generate", "--length=12"}).password.size() == 12);
  NILKEY_EXPECT(RunGenerate({"generate", "--length=8"}).password.size() == 8);
  NILKEY_EXPECT(RunGenerate({"generate", "--length=1024"}).password.size() == 1024);
  NILKEY_EXPECT(RunGenerate({"--length=9", "generate"}).status == nilkey::kExitUsage);
}

NILKEY_TEST(character_class_flags) {
  const Captured no_symbols = RunGenerate({"generate", "--no-symbols"});
  NILKEY_EXPECT(no_symbols.status == nilkey::kExitOk);
  NILKEY_EXPECT(AllFrom(no_symbols.password, {kLower, kUpper, kDigits}));

  const Captured digits_only = RunGenerate({"generate", "--no-lower", "--no-upper", "--no-symbols"});
  NILKEY_EXPECT(digits_only.status == nilkey::kExitOk);
  NILKEY_EXPECT(digits_only.password.size() == 20);
  NILKEY_EXPECT(AllFrom(digits_only.password, {kDigits}));

  const Captured letters = RunGenerate({"generate", "--no-digits", "--no-symbols"});
  NILKEY_EXPECT(AllFrom(letters.password, {kLower, kUpper}));
  NILKEY_EXPECT(HasAnyOf(letters.password, kLower) && HasAnyOf(letters.password, kUpper));
}

NILKEY_TEST(rejects_a_bad_length_and_prints_nothing_to_stdout) {
  for (const char* bad : {"7", "1025", "abc", "20x", "-5", "+20", "", "99999999999999999999999"}) {
    const Captured r = RunGenerate({"generate", "--length", bad});
    NILKEY_EXPECT(r.status == nilkey::kExitUsage);
    NILKEY_EXPECT(r.password.empty());
    NILKEY_EXPECT(r.err.find("--length must be a number from 8 to 1024") != std::string::npos);
    NILKEY_EXPECT(r.err.find("Try 'nilkey --help'.") != std::string::npos);
  }
  // The offending value is never echoed.
  NILKEY_EXPECT(RunGenerate({"generate", "--length", "abc"}).err.find("abc") == std::string::npos);
  NILKEY_EXPECT(RunGenerate({"generate", "--length", "20x"}).err.find("20x") == std::string::npos);
}

NILKEY_TEST(rejects_turning_every_class_off) {
  const Captured r = RunGenerate(
      {"generate", "--no-lower", "--no-upper", "--no-digits", "--no-symbols"});
  NILKEY_EXPECT(r.status == nilkey::kExitUsage);
  NILKEY_EXPECT(r.password.empty());
  NILKEY_EXPECT(r.err.find("at least one character class") != std::string::npos);
}

NILKEY_TEST(rejects_extra_arguments_and_a_password_option) {
  NILKEY_EXPECT(RunGenerate({"generate", "extra"}).status == nilkey::kExitUsage);
  const Captured r = RunGenerate({"generate", "--password=hunter2"});
  NILKEY_EXPECT(r.status == nilkey::kExitUsage);
  NILKEY_EXPECT(r.password.empty());
  NILKEY_EXPECT(r.err.find("hunter2") == std::string::npos);
}

NILKEY_TEST(allow_unlocked_memory_is_accepted) {
  const Captured r = RunGenerate({"--allow-unlocked-memory", "generate"});
  NILKEY_EXPECT(r.status == nilkey::kExitOk);
  NILKEY_EXPECT(r.password.size() == 20);
}

NILKEY_TEST(two_runs_give_different_passwords) {
  NILKEY_EXPECT(RunGenerate({"generate"}).password != RunGenerate({"generate"}).password);
}

// On a terminal the password is followed by a line break (the pty turns "\n"
// into "\r\n").
NILKEY_TEST(a_terminal_gets_a_line_break) {
  PtyChild child = PtyChild::Start(BodyGenerateOnTerminal);
  NILKEY_EXPECT(child.Wait(10000) == 0);
  const std::string& shown = child.output();
  NILKEY_EXPECT(shown.size() == 18);
  NILKEY_EXPECT(shown.compare(16, 2, "\r\n") == 0);
  NILKEY_EXPECT(AllFrom(shown.substr(0, 16), {kLower, kUpper, kDigits, kSymbols}));
}

NILKEY_TEST(a_failed_write_is_an_error_and_leaks_nothing) {
  const IgnoreSigpipe ignore;
  const Captured r = RunGenerate({"generate"}, /*reader_open=*/false);
  NILKEY_EXPECT(r.status == nilkey::kExitError);
  NILKEY_EXPECT(r.out.empty());
  NILKEY_EXPECT(r.err == "nilkey: file operation failed\n");
}

NILKEY_TEST_MAIN()

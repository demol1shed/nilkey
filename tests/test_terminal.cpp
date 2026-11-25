// Terminal input (SPEC.md 9.3), tested against a real pseudo-terminal. Each
// test runs the code under test in a child process whose controlling terminal
// the test drives; the child reports through its exit status (0 = all checks
// passed, other values identify the failed check) and never prints values.

#include <poll.h>
#include <signal.h>
#include <sodium.h>
#include <termios.h>
#include <unistd.h>

#include <cstddef>
#include <cstring>
#include <span>
#include <string>
#include <string_view>

#include "nilkey/terminal.hpp"
#include "pty_harness.hpp"
#include "test_framework.hpp"

using nilkey::Confirm;
using nilkey::CountCharacters;
using nilkey::ErrorCode;
using nilkey::MemlockPolicy;
using nilkey::ReadNewSecret;
using nilkey::ReadSecret;
using nilkey::ScopedReadGuard;
using nilkey::SecureBuffer;
using nilkey::test::PtyChild;

namespace {

constexpr int kWaitMs = 10000;
constexpr MemlockPolicy kRequire = MemlockPolicy::kRequire;

// ---- Child side -----------------------------------------------------------

bool Holds(const SecureBuffer& buffer, std::string_view expected) {
  const auto guard = ScopedReadGuard::Open(buffer);
  if (!guard.ok()) return false;
  const auto bytes = guard.value().bytes();
  return bytes.size() == expected.size() &&
         (bytes.empty() || sodium_memcmp(bytes.data(), expected.data(), bytes.size()) == 0);
}

// The terminal as the child sees it (stdin is the pty slave).
bool EchoIsOn() {
  struct termios t;
  return tcgetattr(0, &t) == 0 && (t.c_lflag & ECHO) != 0;
}

constexpr int kHandledSignals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGTSTP};

// The signal dispositions and mask a process had at some moment. The test's
// own environment decides what they are (a shell may start it with SIGINT
// ignored), so "restored" means "the same as before", not "the default".
struct SignalState {
  void (*handlers[5])(int);
  sigset_t blocked;
};

bool CaptureSignalState(SignalState& state) {
  for (std::size_t i = 0; i < 5; ++i) {
    struct sigaction current;
    if (sigaction(kHandledSignals[i], nullptr, &current) != 0) return false;
    state.handlers[i] = current.sa_handler;
  }
  return sigprocmask(SIG_BLOCK, nullptr, &state.blocked) == 0;
}

bool SameSignalState(const SignalState& a, const SignalState& b) {
  for (std::size_t i = 0; i < 5; ++i) {
    if (a.handlers[i] != b.handlers[i]) return false;
    if (sigismember(&a.blocked, kHandledSignals[i]) != sigismember(&b.blocked, kHandledSignals[i])) {
      return false;
    }
  }
  return true;
}

int BodyReadsHunter2() {
  const auto secret = ReadSecret("Password: ", kRequire);
  if (!secret.ok()) return 10;
  if (!Holds(secret.value(), "hunter2")) return 11;
  if (!EchoIsOn()) return 12;
  return 0;
}

int BodyReadsUtf8AndNul() {
  const auto secret = ReadSecret("Password: ", kRequire);
  if (!secret.ok()) return 10;
  return Holds(secret.value(), std::string_view("p\0ss\xE2\x82\xAC", 7)) ? 0 : 11;
}

int BodyEmptyLine() {
  const auto secret = ReadSecret("Password: ", kRequire);
  if (secret.ok() || secret.error().code != ErrorCode::kEmptyInput) return 10;
  return EchoIsOn() ? 0 : 11;
}

// True if the terminal still holds unread input. Prompting again would flush
// it, so only this check shows whether a too-long line was read to its end.
bool InputIsPending() {
  struct pollfd waiting = {0, POLLIN, 0};
  return poll(&waiting, 1, 0) != 0;
}

int BodyLengthLimit() {
  const auto at_limit = ReadSecret("P1: ", kRequire);
  if (!at_limit.ok() || at_limit.value().size() != nilkey::kMaxSecretSize) return 10;
  // One byte over the limit, then a line several buffers long.
  const auto one_over = ReadSecret("P2: ", kRequire);
  if (one_over.ok() || one_over.error().code != ErrorCode::kInputTooLong) return 11;
  if (InputIsPending()) return 12;
  const auto far_over = ReadSecret("P3: ", kRequire);
  if (far_over.ok() || far_over.error().code != ErrorCode::kInputTooLong) return 13;
  if (InputIsPending()) return 14;
  const auto after = ReadSecret("P4: ", kRequire);
  if (!after.ok() || !Holds(after.value(), "ok")) return 15;
  return 0;
}

int BodyEndOfFile() {
  const auto secret = ReadSecret("Password: ", kRequire);
  if (secret.ok() || secret.error().code != ErrorCode::kAborted) return 10;
  return EchoIsOn() ? 0 : 11;
}

int BodyAborted() {
  SignalState before;
  if (!CaptureSignalState(before)) return 9;
  const auto secret = ReadSecret("Password: ", kRequire);
  if (secret.ok() || secret.error().code != ErrorCode::kAborted) return 10;
  if (!EchoIsOn()) return 11;
  SignalState after;
  if (!CaptureSignalState(after) || !SameSignalState(before, after)) return 12;
  return 0;
}

int BodyConfirm() {
  const struct {
    const char* prompt;
    bool expected;
  } cases[] = {{"Q1? ", true},  {"Q2? ", true},  {"Q3? ", false},
               {"Q4? ", false}, {"Q5? ", false}, {"Q6? ", false}};
  int bad = 0;
  for (int i = 0; i < 6; ++i) {
    const auto answer = Confirm(cases[i].prompt);
    if (!answer.ok() || answer.value() != cases[i].expected) bad |= 1 << i;
  }
  return bad;
}

int BodyConfirmAborted() {
  const auto answer = Confirm("Sure? ");
  return !answer.ok() && answer.error().code == ErrorCode::kAborted ? 0 : 10;
}

int BodyNewSecret() {
  const auto same = ReadNewSecret("n1> ", "n1c> ", kRequire);
  if (!same.ok() || !Holds(same.value(), "same")) return 10;
  const auto differ = ReadNewSecret("n2> ", "n2c> ", kRequire);
  if (differ.ok() || differ.error().code != ErrorCode::kInputMismatch) return 11;
  const auto empty_second = ReadNewSecret("n3> ", "n3c> ", kRequire);
  if (empty_second.ok() || empty_second.error().code != ErrorCode::kEmptyInput) return 12;
  return 0;
}

int BodyNewSecretNotUtf8() {
  const auto secret = ReadNewSecret("l1> ", "l1c> ", kRequire);
  if (!secret.ok()) return 10;
  return Holds(secret.value(), "\xB1\xB1") ? 0 : 11;
}

int BodyNoTerminal() {
  const auto secret = ReadSecret("Password: ", kRequire);
  if (secret.ok() || secret.error().code != ErrorCode::kNoTerminal) return 10;
  const auto answer = Confirm("Sure? ");
  if (answer.ok() || answer.error().code != ErrorCode::kNoTerminal) return 11;
  return 0;
}

}  // namespace

// ---- Parent side ----------------------------------------------------------

NILKEY_TEST(reads_a_secret_with_echo_off) {
  PtyChild child = PtyChild::Start(BodyReadsHunter2);
  NILKEY_EXPECT(child.WaitFor("Password: ", kWaitMs));
  NILKEY_EXPECT(!child.EchoEnabled());
  child.Send("hunter2\n");
  NILKEY_EXPECT(child.Wait(kWaitMs) == 0);  // Also: echo is back on afterwards.
  NILKEY_EXPECT(child.output().find("hunter2") == std::string::npos);
}

NILKEY_TEST(keeps_utf8_and_embedded_nul) {
  PtyChild child = PtyChild::Start(BodyReadsUtf8AndNul);
  NILKEY_EXPECT(child.WaitFor("Password: ", kWaitMs));
  child.Send(std::string_view("p\0ss\xE2\x82\xAC\n", 8));
  NILKEY_EXPECT(child.Wait(kWaitMs) == 0);
}

NILKEY_TEST(rejects_an_empty_line) {
  PtyChild child = PtyChild::Start(BodyEmptyLine);
  NILKEY_EXPECT(child.WaitFor("Password: ", kWaitMs));
  child.Send("\n");
  NILKEY_EXPECT(child.Wait(kWaitMs) == 0);
}

NILKEY_TEST(accepts_the_limit_and_discards_a_longer_line) {
  PtyChild child = PtyChild::Start(BodyLengthLimit);
  NILKEY_EXPECT(child.WaitFor("P1: ", kWaitMs));
  child.Send(std::string(nilkey::kMaxSecretSize, 'a') + "\n");
  NILKEY_EXPECT(child.WaitFor("P2: ", kWaitMs));
  child.Send(std::string(nilkey::kMaxSecretSize + 1, 'b') + "\n");
  NILKEY_EXPECT(child.WaitFor("P3: ", kWaitMs));
  child.Send(std::string(3000, 'c') + "\n");
  NILKEY_EXPECT(child.WaitFor("P4: ", kWaitMs));
  child.Send("ok\n");
  NILKEY_EXPECT(child.Wait(kWaitMs) == 0);
}

NILKEY_TEST(ctrl_d_on_an_empty_line_aborts) {
  PtyChild child = PtyChild::Start(BodyEndOfFile);
  NILKEY_EXPECT(child.WaitFor("Password: ", kWaitMs));
  child.Send("\x04");
  NILKEY_EXPECT(child.Wait(kWaitMs) == 0);
}

// ^C makes the terminal itself send SIGINT to the foreground process group.
NILKEY_TEST(ctrl_c_aborts_and_restores_the_terminal) {
  PtyChild child = PtyChild::Start(BodyAborted);
  NILKEY_EXPECT(child.WaitFor("Password: ", kWaitMs));
  child.Send("\x03");
  NILKEY_EXPECT(child.Wait(kWaitMs) == 0);
}

NILKEY_TEST(sigterm_aborts_and_restores_the_terminal) {
  PtyChild child = PtyChild::Start(BodyAborted);
  NILKEY_EXPECT(child.WaitFor("Password: ", kWaitMs));
  child.Kill(SIGTERM);
  NILKEY_EXPECT(child.Wait(kWaitMs) == 0);
}

NILKEY_TEST(an_abort_ends_the_prompt_line) {
  PtyChild child = PtyChild::Start(BodyAborted);
  NILKEY_EXPECT(child.WaitFor("Password: ", kWaitMs));
  child.Send("\x03");
  NILKEY_EXPECT(child.Wait(kWaitMs) == 0);
  // The prompt is followed by a line break, so the shell prompt starts fresh.
  NILKEY_EXPECT(child.output().find("Password: \r\n") != std::string::npos);
}

NILKEY_TEST(confirm_accepts_only_yes) {
  PtyChild child = PtyChild::Start(BodyConfirm);
  const char* answers[] = {"y\n", "YES\n", "n\n", "\n", "yes please\n", nullptr};
  const char* prompts[] = {"Q1? ", "Q2? ", "Q3? ", "Q4? ", "Q5? ", "Q6? "};
  const std::string long_answer(100, 'a');
  for (int i = 0; i < 6; ++i) {
    NILKEY_EXPECT(child.WaitFor(prompts[i], kWaitMs));
    child.Send(answers[i] != nullptr ? std::string(answers[i]) : long_answer + "\n");
  }
  NILKEY_EXPECT(child.Wait(kWaitMs) == 0);
}

NILKEY_TEST(confirm_reports_an_abort) {
  PtyChild child = PtyChild::Start(BodyConfirmAborted);
  NILKEY_EXPECT(child.WaitFor("Sure? ", kWaitMs));
  child.Send("\x04");
  NILKEY_EXPECT(child.Wait(kWaitMs) == 0);
}

NILKEY_TEST(new_secret_needs_two_equal_entries) {
  PtyChild child = PtyChild::Start(BodyNewSecret);
  NILKEY_EXPECT(child.WaitFor("n1> ", kWaitMs));
  child.Send("same\n");
  NILKEY_EXPECT(child.WaitFor("n1c> ", kWaitMs));
  child.Send("same\n");
  NILKEY_EXPECT(child.WaitFor("n2> ", kWaitMs));
  child.Send("one\n");
  NILKEY_EXPECT(child.WaitFor("n2c> ", kWaitMs));
  child.Send("two\n");
  NILKEY_EXPECT(child.WaitFor("n3> ", kWaitMs));
  child.Send("third\n");
  NILKEY_EXPECT(child.WaitFor("n3c> ", kWaitMs));
  child.Send("\n");
  NILKEY_EXPECT(child.Wait(kWaitMs) == 0);
}

NILKEY_TEST(counts_characters_not_bytes) {
  const auto count = [](std::string_view text) {
    return CountCharacters(std::as_bytes(std::span(text.data(), text.size())));
  };
  NILKEY_EXPECT(count("") == 0);
  NILKEY_EXPECT(count("abc") == 3);
  NILKEY_EXPECT(count("çüğışö") == 6);          // 2 bytes each
  NILKEY_EXPECT(count("\xE2\x82\xAC") == 1);    // 3-byte euro sign
  NILKEY_EXPECT(count("\xF0\x9F\x98\x80") == 1);  // 4-byte emoji
  NILKEY_EXPECT(count(std::string_view("a\0b", 3)) == 3);
  NILKEY_EXPECT(count("\xFF\xFE") == 2);        // invalid bytes count one each
  NILKEY_EXPECT(count("\xFF" "abc") == 4);
  NILKEY_EXPECT(count("\x80\x80") == 2);        // stray continuation bytes
  NILKEY_EXPECT(count("\xC3") == 1);            // lead byte alone
  NILKEY_EXPECT(count("\xE2\x82") == 2);        // cut-off sequence
  NILKEY_EXPECT(count("\xC3\xA7\x80") == 2);    // valid, then stray
  NILKEY_EXPECT(count("\xE0\x80\x80") == 3);    // overlong form
}

// A record password has no minimum, so one made only of bytes from 0x80 to 0xBF
// (a Latin-1 terminal) must be accepted.
NILKEY_TEST(new_secret_accepts_bytes_that_are_not_utf8) {
  PtyChild child = PtyChild::Start(BodyNewSecretNotUtf8);
  NILKEY_EXPECT(child.WaitFor("l1> ", kWaitMs));
  child.Send("\xB1\xB1\n");
  NILKEY_EXPECT(child.WaitFor("l1c> ", kWaitMs));
  child.Send("\xB1\xB1\n");
  NILKEY_EXPECT(child.Wait(kWaitMs) == 0);
}

NILKEY_TEST(fails_without_a_controlling_terminal) {
  PtyChild child = PtyChild::Start(BodyNoTerminal, /*controlling_tty=*/false);
  NILKEY_EXPECT(child.Wait(kWaitMs) == 0);
}

NILKEY_TEST_MAIN()

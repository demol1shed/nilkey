// The memory lock policy through the real command line (SPEC.md 10, item 7):
// with RLIMIT_MEMLOCK at 0, `init` fails closed unless --allow-unlocked-memory
// is given, in which case it warns and carries on.
//
// Not built with the sanitizers: their runtimes intercept mlock() and always
// report success, so a lock failure cannot be provoked (SPEC.md 7.4). With
// root or CAP_IPC_LOCK the limit is ignored; the test then skips itself.

#include <signal.h>
#include <unistd.h>

#include <cstdio>
#include <string>
#include <vector>

#include "pty_harness.hpp"
#include "temp_dir.hpp"
#include "test_framework.hpp"

using nilkey::test::ModeOf;
using nilkey::test::PtyChild;
using nilkey::test::TempDir;

namespace {

constexpr int kWaitMs = 30000;

PtyChild StartInit(const TempDir& dir, const std::vector<std::string>& extra) {
  std::vector<std::string> args = {"nilkey", "--vault", dir.Path("v.vault")};
  args.insert(args.end(), extra.begin(), extra.end());
  args.push_back("init");
  const std::string stdout_path = dir.Path("stdout.txt");
  PtyChild::ExecOptions options;
  options.stdout_path = stdout_path.c_str();
  options.no_memlock = true;
  return PtyChild::StartExec(NILKEY_E2E_BINARY, args, options);
}

bool Has(const std::string& text, const char* part) { return text.find(part) != std::string::npos; }

int CountOf(const std::string& text, const std::string& part) {
  int count = 0;
  for (std::size_t at = text.find(part); at != std::string::npos; at = text.find(part, at + 1)) {
    ++count;
  }
  return count;
}

}  // namespace

NILKEY_TEST(init_fails_closed_when_memory_cannot_be_locked) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  PtyChild child = StartInit(dir, {});
  // The first secure buffer is allocated before any prompt, so a working limit
  // makes the command fail at once. If the prompt shows up instead, locking is
  // not limited for this process.
  if (child.WaitFor("New master password", 3000)) {
    std::fputs("SKIP: memory locking is not limited here (root or CAP_IPC_LOCK)\n", stderr);
    return;
  }
  const int status = child.Wait(kWaitMs);
  NILKEY_EXPECT(status == 1);
  NILKEY_EXPECT(Has(child.output(), "cannot lock memory"));
  NILKEY_EXPECT(Has(child.output(), "nilkey doctor"));
  NILKEY_EXPECT(access(dir.Path("v.vault").c_str(), F_OK) != 0);
}

NILKEY_TEST(allow_unlocked_memory_warns_and_carries_on) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  PtyChild child = StartInit(dir, {"--allow-unlocked-memory"});
  NILKEY_EXPECT(child.WaitFor("New master password: ", kWaitMs));
  child.Send("a master password\n");
  NILKEY_EXPECT(child.WaitFor("Repeat the new master password: ", kWaitMs));
  child.Send("a master password\n");
  NILKEY_EXPECT(child.Wait(kWaitMs) == 0);
  NILKEY_EXPECT(Has(child.output(), "secure memory could not be locked"));
  NILKEY_EXPECT(ModeOf(dir.Path("v.vault")) == 0600);
}

// A run allocates several secure buffers (both password prompts, the key, the
// vault); the warning would be repeated for each of them.
NILKEY_TEST(the_lock_warning_is_printed_once_per_run) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  PtyChild child = StartInit(dir, {"--allow-unlocked-memory"});
  NILKEY_EXPECT(child.WaitFor("New master password: ", kWaitMs));
  child.Send("a master password\n");
  NILKEY_EXPECT(child.WaitFor("Repeat the new master password: ", kWaitMs));
  child.Send("a master password\n");
  NILKEY_EXPECT(child.Wait(kWaitMs) == 0);
  NILKEY_EXPECT(CountOf(child.output(), "secure memory could not be locked") == 1);
}

NILKEY_TEST_MAIN()

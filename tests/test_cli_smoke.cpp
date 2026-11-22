// Smoke test of the real nilkey binary, with the production Argon2id costs
// (64 MiB, 3 passes), so it is slow and labelled `slow`. The end-to-end tests
// use a build with the cheapest costs; this one shows that the shipped binary
// does not, and that the commands work with the real KDF.

#include <signal.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "pty_harness.hpp"
#include "temp_dir.hpp"
#include "test_framework.hpp"

using nilkey::test::PtyChild;
using nilkey::test::Slurp;
using nilkey::test::TempDir;

namespace {

constexpr int kWaitMs = 90000;  // Each key derivation is slow under the sanitizers.

struct Result {
  int status = -1;
  std::string terminal;
  std::string out;
};

struct Answer {
  const char* prompt;
  std::string reply;
};

Result RunBinary(const TempDir& dir, const std::string& vault, const std::vector<std::string>& args,
                 const std::vector<Answer>& answers) {
  std::vector<std::string> full = {"nilkey", "--vault", vault};
  full.insert(full.end(), args.begin(), args.end());
  const std::string stdout_path = dir.Path("stdout.txt");
  PtyChild::ExecOptions options;
  options.stdout_path = stdout_path.c_str();
  PtyChild child = PtyChild::StartExec(NILKEY_BINARY, full, options);

  bool answered = true;
  for (const Answer& a : answers) {
    if (!child.WaitFor(a.prompt, kWaitMs)) {
      answered = false;
      break;
    }
    child.Send(a.reply + "\n");
  }
  if (!answered) child.Kill(SIGKILL);

  Result result;
  result.status = child.Wait(kWaitMs);
  result.terminal = child.output();
  std::vector<std::byte> out;
  if (Slurp(stdout_path, out)) {
    result.out.assign(reinterpret_cast<const char*>(out.data()), out.size());
  }
  return result;
}

std::uint32_t Le32(const std::vector<std::byte>& file, std::size_t offset) {
  std::uint32_t value = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(file[offset + i]) << (8 * i);
  }
  return value;
}

bool Has(const std::string& text, const char* part) { return text.find(part) != std::string::npos; }

}  // namespace

NILKEY_TEST(the_real_binary_uses_the_production_costs_and_works) {
  TempDir dir;
  NILKEY_EXPECT(dir.ok());
  const std::string vault = dir.Path("v.vault");
  const std::string master = "a real master password";

  const Result init = RunBinary(dir, vault, {"init"},
                                {{"New master password: ", master},
                                 {"Repeat the new master password: ", master}});
  NILKEY_EXPECT(init.status == 0);

  // SPEC.md 4.1: 64 MiB, 3 passes, parallelism 1 (header offsets 10, 14, 18).
  std::vector<std::byte> file;
  NILKEY_EXPECT(Slurp(vault, file));
  NILKEY_EXPECT(file.size() > 66);
  NILKEY_EXPECT(Le32(file, 10) == 65536);
  NILKEY_EXPECT(Le32(file, 14) == 3);
  NILKEY_EXPECT(Le32(file, 18) == 1);

  const Result add = RunBinary(dir, vault, {"add", "smoke", "--username", "u", "--generate"},
                               {{"Master password: ", master}});
  NILKEY_EXPECT(add.status == 0);

  const Result list = RunBinary(dir, vault, {"list"}, {{"Master password: ", master}});
  NILKEY_EXPECT(list.status == 0);
  NILKEY_EXPECT(list.out.rfind("smoke\tu\t", 0) == 0);

  // A low RLIMIT_MEMLOCK makes the binary warn on stderr, so stderr is not
  // expected to be empty here.
  const Result wrong = RunBinary(dir, vault, {"list"}, {{"Master password: ", "not it"}});
  NILKEY_EXPECT(wrong.status == 1);
  NILKEY_EXPECT(wrong.out.empty());
  NILKEY_EXPECT(Has(wrong.terminal, "wrong password or corrupted vault file"));
}

NILKEY_TEST_MAIN()

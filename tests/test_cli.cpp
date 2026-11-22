// Command router and vault path resolution (SPEC.md 9.1). Run() writes to
// FILE* streams, which the tests point at memory streams.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <span>
#include <string>
#include <vector>

#include "nilkey/cli.hpp"
#include "nilkey/commands.hpp"
#include "test_framework.hpp"

using nilkey::ErrorCode;
using nilkey::ResolveVaultPath;

namespace {

struct Captured {
  int status;
  std::string out;
  std::string err;
};

Captured RunCaptured(std::initializer_list<const char*> args) {
  char* out_buffer = nullptr;
  std::size_t out_size = 0;
  char* err_buffer = nullptr;
  std::size_t err_size = 0;
  std::FILE* out = open_memstream(&out_buffer, &out_size);
  std::FILE* err = open_memstream(&err_buffer, &err_size);
  if (out == nullptr || err == nullptr) std::abort();

  const std::vector<const char*> v(args);
  Captured result;
  // No command tested here writes a secret, so there is no descriptor for them.
  result.status = nilkey::Run(std::span<const char* const>(v), nilkey::Io{out, err, -1});
  // fclose() updates the size variables, so read them only afterwards.
  std::fclose(out);
  std::fclose(err);
  result.out.assign(out_buffer == nullptr ? "" : out_buffer, out_size);
  result.err.assign(err_buffer == nullptr ? "" : err_buffer, err_size);
  std::free(out_buffer);
  std::free(err_buffer);
  return result;
}

constexpr const char* kCommandNames[] = {"init", "add",    "get",    "list",  "update",
                                         "delete", "generate", "passwd", "doctor"};

}  // namespace

NILKEY_TEST(help_lists_every_command_and_global_option) {
  const Captured r = RunCaptured({"--help"});
  NILKEY_EXPECT(r.status == nilkey::kExitOk);
  NILKEY_EXPECT(r.err.empty());
  for (const char* name : kCommandNames) {
    NILKEY_EXPECT(r.out.find(std::string("  ") + name) != std::string::npos);
  }
  NILKEY_EXPECT(r.out.find("--vault") != std::string::npos);
  NILKEY_EXPECT(r.out.find("--allow-unlocked-memory") != std::string::npos);
  NILKEY_EXPECT(r.out.find("--version") != std::string::npos);
}

NILKEY_TEST(help_works_after_a_command) {
  const Captured r = RunCaptured({"add", "--help"});
  NILKEY_EXPECT(r.status == nilkey::kExitOk);
  NILKEY_EXPECT(!r.out.empty());
}

NILKEY_TEST(version_prints_name_and_number) {
  const Captured r = RunCaptured({"--version"});
  NILKEY_EXPECT(r.status == nilkey::kExitOk);
  NILKEY_EXPECT(r.out.rfind("nilkey ", 0) == 0);
  NILKEY_EXPECT(r.out.size() > std::strlen("nilkey \n"));
  NILKEY_EXPECT(r.err.empty());
}

NILKEY_TEST(usage_errors_exit_2_with_a_hint_and_no_stdout) {
  const Captured none = RunCaptured({});
  NILKEY_EXPECT(none.status == nilkey::kExitUsage);
  NILKEY_EXPECT(none.out.empty());
  NILKEY_EXPECT(none.err.find("no command given") != std::string::npos);
  NILKEY_EXPECT(none.err.find("--help") != std::string::npos);

  const Captured unknown = RunCaptured({"frobnicate"});
  NILKEY_EXPECT(unknown.status == nilkey::kExitUsage);
  NILKEY_EXPECT(unknown.out.empty());
  NILKEY_EXPECT(unknown.err.find("frobnicate") == std::string::npos);
}

// SPEC.md 9.3: no command may take a password as an argument, and a password
// typed there by mistake must not be echoed back.
NILKEY_TEST(no_command_accepts_a_password_option) {
  for (const char* name : kCommandNames) {
    for (const char* option : {"--password=hunter2", "--master-password=hunter2"}) {
      const Captured r = RunCaptured({name, "entry", option});
      NILKEY_EXPECT(r.status == nilkey::kExitUsage);
      NILKEY_EXPECT(r.out.find("hunter2") == std::string::npos);
      NILKEY_EXPECT(r.err.find("hunter2") == std::string::npos);
    }
  }
}

NILKEY_TEST(vault_flag_wins_over_environment) {
  const auto r = ResolveVaultPath("/flag.vault", "/env.vault", "/home/u");
  NILKEY_EXPECT(r.ok());
  NILKEY_EXPECT(r.value() == "/flag.vault");
}

NILKEY_TEST(nilkey_path_wins_over_home) {
  const auto r = ResolveVaultPath(std::nullopt, "/env.vault", "/home/u");
  NILKEY_EXPECT(r.ok());
  NILKEY_EXPECT(r.value() == "/env.vault");
}

NILKEY_TEST(default_vault_lives_under_home) {
  const auto r = ResolveVaultPath(std::nullopt, nullptr, "/home/u");
  NILKEY_EXPECT(r.ok());
  NILKEY_EXPECT(r.value() == "/home/u/.local/share/nilkey/default.vault");

  // An empty NILKEY_PATH counts as unset.
  const auto empty = ResolveVaultPath(std::nullopt, "", "/home/u");
  NILKEY_EXPECT(empty.ok());
  NILKEY_EXPECT(empty.value() == "/home/u/.local/share/nilkey/default.vault");
}

NILKEY_TEST(vault_path_errors) {
  const auto empty_flag = ResolveVaultPath("", "/env.vault", "/home/u");
  NILKEY_EXPECT(!empty_flag.ok());
  NILKEY_EXPECT(empty_flag.error().code == ErrorCode::kUsage);

  const auto nothing = ResolveVaultPath(std::nullopt, nullptr, nullptr);
  NILKEY_EXPECT(!nothing.ok());
  NILKEY_EXPECT(nothing.error().code == ErrorCode::kInvalidArgument);

  const auto empty_home = ResolveVaultPath(std::nullopt, "", "");
  NILKEY_EXPECT(!empty_home.ok());
}

namespace {

// What an error turns into: the exit status and the one thing printed.
struct Reported {
  int status;
  std::string err;
};

Reported ReportCaptured(nilkey::ErrorCode code) {
  char* buffer = nullptr;
  std::size_t size = 0;
  std::FILE* err = open_memstream(&buffer, &size);
  if (err == nullptr) std::abort();
  Reported result;
  result.status = nilkey::ReportError(nilkey::make_error(code), err);
  std::fclose(err);
  result.err.assign(buffer == nullptr ? "" : buffer, size);
  std::free(buffer);
  return result;
}

}  // namespace

NILKEY_TEST(a_wrong_command_line_exits_2_with_a_hint) {
  const Reported r = ReportCaptured(ErrorCode::kUsage);
  NILKEY_EXPECT(r.status == nilkey::kExitUsage);
  NILKEY_EXPECT(r.err.find("Try 'nilkey --help'.") != std::string::npos);
}

NILKEY_TEST(an_abort_exits_130_and_says_so_once) {
  const Reported r = ReportCaptured(ErrorCode::kAborted);
  NILKEY_EXPECT(r.status == 130);
  NILKEY_EXPECT(r.err == "nilkey: aborted\n");
}

NILKEY_TEST(any_other_error_exits_1_with_its_static_message) {
  for (const ErrorCode code : {ErrorCode::kIoError, ErrorCode::kAuthenticationFailed,
                               ErrorCode::kVaultNotFound, ErrorCode::kMemoryLockFailed}) {
    const Reported r = ReportCaptured(code);
    NILKEY_EXPECT(r.status == nilkey::kExitError);
    NILKEY_EXPECT(r.err == std::string("nilkey: ") + nilkey::describe(code) + "\n");
  }
}

NILKEY_TEST_MAIN()

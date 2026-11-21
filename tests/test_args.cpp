// Command line parser (SPEC.md 9). Uses its own small command table so the
// grammar is tested independently of the real commands.

#include <array>
#include <cstring>
#include <initializer_list>
#include <span>
#include <vector>

#include "nilkey/args.hpp"
#include "test_framework.hpp"

using nilkey::CommandSpec;
using nilkey::ErrorCode;
using nilkey::OptionSpec;
using nilkey::ParsedArgs;
using nilkey::Result;

namespace {

constexpr std::array<OptionSpec, 3> kPutOptions = {{
    {"username", true},
    {"generate", false},
    {"yes", false},
}};

constexpr std::array<CommandSpec, 3> kCommands = {{
    {"ping", "ping", "No arguments", {}, 0, 0},
    {"put", "put <name>", "One argument and options", kPutOptions, 1, 1},
    {"many", "many [name...]", "Zero to three arguments", {}, 0, 3},
}};

Result<ParsedArgs> Parse(std::initializer_list<const char*> args) {
  const std::vector<const char*> v(args);
  return nilkey::ParseArgs(std::span<const char* const>(v), kCommands);
}

// The parsed views point into the literals, which outlive the call.
bool IsUsageError(const Result<ParsedArgs>& r) {
  return !r.ok() && r.error().code == ErrorCode::kUsage;
}

}  // namespace

NILKEY_TEST(parses_command_and_positional) {
  const auto r = Parse({"put", "github"});
  NILKEY_EXPECT(r.ok());
  NILKEY_EXPECT(r.value().command != nullptr);
  NILKEY_EXPECT(r.value().command->name == "put");
  NILKEY_EXPECT(r.value().positionals.size() == 1);
  NILKEY_EXPECT(r.value().positionals[0] == "github");
  NILKEY_EXPECT(!r.value().globals.vault.has_value());
  NILKEY_EXPECT(!r.value().globals.allow_unlocked_memory);
}

NILKEY_TEST(global_options_before_and_after_command) {
  const auto before = Parse({"--vault", "/a", "--allow-unlocked-memory", "ping"});
  NILKEY_EXPECT(before.ok());
  NILKEY_EXPECT(before.value().globals.vault.has_value());
  NILKEY_EXPECT(*before.value().globals.vault == "/a");
  NILKEY_EXPECT(before.value().globals.allow_unlocked_memory);

  const auto after = Parse({"ping", "--allow-unlocked-memory", "--vault=/b"});
  NILKEY_EXPECT(after.ok());
  NILKEY_EXPECT(*after.value().globals.vault == "/b");
  NILKEY_EXPECT(after.value().globals.allow_unlocked_memory);
}

NILKEY_TEST(command_options_in_both_value_forms) {
  const auto r = Parse({"put", "--username", "bob", "name", "--generate", "--yes"});
  NILKEY_EXPECT(r.ok());
  NILKEY_EXPECT(r.value().Has("generate"));
  NILKEY_EXPECT(r.value().Has("yes"));
  NILKEY_EXPECT(r.value().Value("username").has_value());
  NILKEY_EXPECT(*r.value().Value("username") == "bob");
  NILKEY_EXPECT(r.value().positionals.size() == 1);

  const auto eq = Parse({"put", "name", "--username=alice"});
  NILKEY_EXPECT(eq.ok());
  NILKEY_EXPECT(*eq.value().Value("username") == "alice");
  NILKEY_EXPECT(!eq.value().Has("generate"));
  NILKEY_EXPECT(!eq.value().Value("generate").has_value());
}

NILKEY_TEST(empty_option_value_is_allowed) {
  const auto r = Parse({"put", "name", "--username="});
  NILKEY_EXPECT(r.ok());
  NILKEY_EXPECT(r.value().Value("username").has_value());
  NILKEY_EXPECT(r.value().Value("username")->empty());
}

NILKEY_TEST(a_value_may_look_like_an_option) {
  const auto r = Parse({"put", "name", "--username", "--yes"});
  NILKEY_EXPECT(r.ok());
  NILKEY_EXPECT(*r.value().Value("username") == "--yes");
  NILKEY_EXPECT(!r.value().Has("yes"));
}

NILKEY_TEST(double_dash_ends_options) {
  const auto r = Parse({"put", "--", "--odd-name"});
  NILKEY_EXPECT(r.ok());
  NILKEY_EXPECT(r.value().positionals.size() == 1);
  NILKEY_EXPECT(r.value().positionals[0] == "--odd-name");

  const auto single = Parse({"put", "--", "-x"});
  NILKEY_EXPECT(single.ok());
  NILKEY_EXPECT(single.value().positionals[0] == "-x");
}

NILKEY_TEST(lone_dash_is_a_positional) {
  const auto r = Parse({"put", "-"});
  NILKEY_EXPECT(r.ok());
  NILKEY_EXPECT(r.value().positionals[0] == "-");
}

NILKEY_TEST(empty_string_is_a_positional) {
  const auto r = Parse({"put", ""});
  NILKEY_EXPECT(r.ok());
  NILKEY_EXPECT(r.value().positionals.size() == 1);
  NILKEY_EXPECT(r.value().positionals[0].empty());
  NILKEY_EXPECT(IsUsageError(Parse({""})));
}

NILKEY_TEST(rejects_unknown_command) {
  NILKEY_EXPECT(IsUsageError(Parse({"nope"})));
  NILKEY_EXPECT(IsUsageError(Parse({"--vault", "/a", "nope"})));
}

NILKEY_TEST(rejects_missing_command) {
  NILKEY_EXPECT(IsUsageError(Parse({})));
  NILKEY_EXPECT(IsUsageError(Parse({"--allow-unlocked-memory"})));
}

NILKEY_TEST(rejects_unknown_and_misplaced_options) {
  NILKEY_EXPECT(IsUsageError(Parse({"put", "name", "--nope"})));
  NILKEY_EXPECT(IsUsageError(Parse({"put", "name", "-u"})));
  // A command's own options are not known before the command.
  NILKEY_EXPECT(IsUsageError(Parse({"--generate", "put", "name"})));
  // ...nor for another command.
  NILKEY_EXPECT(IsUsageError(Parse({"ping", "--generate"})));
}

NILKEY_TEST(rejects_missing_or_unexpected_option_value) {
  NILKEY_EXPECT(IsUsageError(Parse({"put", "name", "--username"})));
  NILKEY_EXPECT(IsUsageError(Parse({"ping", "--vault"})));
  NILKEY_EXPECT(IsUsageError(Parse({"put", "name", "--generate=yes"})));
  NILKEY_EXPECT(IsUsageError(Parse({"ping", "--help=1"})));
}

NILKEY_TEST(rejects_repeated_options) {
  NILKEY_EXPECT(IsUsageError(Parse({"put", "name", "--yes", "--yes"})));
  NILKEY_EXPECT(IsUsageError(Parse({"put", "name", "--username=a", "--username=b"})));
  NILKEY_EXPECT(IsUsageError(Parse({"--vault=/a", "ping", "--vault=/b"})));
  NILKEY_EXPECT(IsUsageError(Parse({"--help", "--help"})));
}

NILKEY_TEST(enforces_positional_count) {
  NILKEY_EXPECT(IsUsageError(Parse({"put"})));
  NILKEY_EXPECT(IsUsageError(Parse({"put", "a", "b"})));
  NILKEY_EXPECT(IsUsageError(Parse({"ping", "a"})));
  NILKEY_EXPECT(Parse({"many"}).ok());
  NILKEY_EXPECT(Parse({"many", "a", "b", "c"}).ok());
  NILKEY_EXPECT(IsUsageError(Parse({"many", "a", "b", "c", "d"})));
}

NILKEY_TEST(help_and_version_need_no_command) {
  const auto help = Parse({"--help"});
  NILKEY_EXPECT(help.ok());
  NILKEY_EXPECT(help.value().globals.help);
  NILKEY_EXPECT(help.value().command == nullptr);

  const auto version = Parse({"--version"});
  NILKEY_EXPECT(version.ok());
  NILKEY_EXPECT(version.value().globals.version);

  // The positional count is not enforced either, so `put --help` works.
  const auto put_help = Parse({"put", "--help"});
  NILKEY_EXPECT(put_help.ok());
  NILKEY_EXPECT(put_help.value().globals.help);

  // An unknown command is still an error.
  NILKEY_EXPECT(IsUsageError(Parse({"nope", "--help"})));
}

NILKEY_TEST(errors_never_echo_the_offending_argument) {
  const auto r = Parse({"put", "name", "--password=hunter2"});
  NILKEY_EXPECT(IsUsageError(r));
  NILKEY_EXPECT(std::strstr(r.error().message, "hunter2") == nullptr);
  NILKEY_EXPECT(std::strstr(r.error().message, "password") == nullptr);

  const auto bad_command = Parse({"hunter2"});
  NILKEY_EXPECT(IsUsageError(bad_command));
  NILKEY_EXPECT(std::strstr(bad_command.error().message, "hunter2") == nullptr);
}

NILKEY_TEST_MAIN()

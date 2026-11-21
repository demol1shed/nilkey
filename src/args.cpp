#include "nilkey/args.hpp"

#include <array>
#include <cstddef>

namespace nilkey {

namespace {

constexpr std::array<OptionSpec, 4> kGlobalSpecs = {{
    {"vault", true},
    {"allow-unlocked-memory", false},
    {"help", false},
    {"version", false},
}};

// Indexes into kGlobalSpecs, in the same order.
constexpr std::size_t kVault = 0;
constexpr std::size_t kAllowUnlocked = 1;
constexpr std::size_t kHelp = 2;
constexpr std::size_t kVersion = 3;

Error Usage(const char* message) { return Error{ErrorCode::kUsage, message}; }

const CommandSpec* FindCommand(std::span<const CommandSpec> commands, std::string_view name) {
  for (const CommandSpec& command : commands) {
    if (command.name == name) return &command;
  }
  return nullptr;
}

std::optional<std::size_t> FindGlobal(std::string_view name) {
  for (std::size_t i = 0; i < kGlobalSpecs.size(); ++i) {
    if (kGlobalSpecs[i].name == name) return i;
  }
  return std::nullopt;
}

const OptionSpec* FindCommandOption(const CommandSpec& command, std::string_view name) {
  for (const OptionSpec& option : command.options) {
    if (option.name == name) return &option;
  }
  return nullptr;
}

}  // namespace

bool ParsedArgs::Has(std::string_view name) const {
  for (const ParsedOption& option : options) {
    if (option.name == name) return true;
  }
  return false;
}

std::optional<std::string_view> ParsedArgs::Value(std::string_view name) const {
  for (const ParsedOption& option : options) {
    if (option.name == name) return option.value;
  }
  return std::nullopt;
}

Result<ParsedArgs> ParseArgs(std::span<const char* const> args,
                             std::span<const CommandSpec> commands) {
  ParsedArgs parsed;
  std::array<bool, kGlobalSpecs.size()> seen_global{};
  bool only_positionals = false;

  for (std::size_t i = 0; i < args.size(); ++i) {
    std::string_view token = args[i];

    if (only_positionals || token.size() < 2 || token[0] != '-') {
      if (parsed.command == nullptr) {
        parsed.command = FindCommand(commands, token);
        if (parsed.command == nullptr) return Usage("unknown command");
      } else {
        parsed.positionals.push_back(token);
      }
      continue;
    }
    if (token == "--") {
      only_positionals = true;
      continue;
    }
    // Short options do not exist; `-x` is not a positional either.
    if (token[1] != '-') return Usage("unknown option");

    token.remove_prefix(2);
    std::string_view name = token;
    std::optional<std::string_view> inline_value;
    const std::size_t equals = token.find('=');
    if (equals != std::string_view::npos) {
      name = token.substr(0, equals);
      inline_value = token.substr(equals + 1);
    }

    const std::optional<std::size_t> global = FindGlobal(name);
    const OptionSpec* command_option = nullptr;
    if (!global.has_value() && parsed.command != nullptr) {
      command_option = FindCommandOption(*parsed.command, name);
    }
    if (!global.has_value() && command_option == nullptr) return Usage("unknown option");

    const bool takes_value = global.has_value() ? kGlobalSpecs[*global].takes_value
                                                : command_option->takes_value;
    std::string_view value;
    if (takes_value) {
      if (inline_value.has_value()) {
        value = *inline_value;
      } else if (i + 1 < args.size()) {
        value = args[++i];
      } else {
        return Usage("option requires a value");
      }
    } else if (inline_value.has_value()) {
      return Usage("option does not take a value");
    }

    if (global.has_value()) {
      if (seen_global[*global]) return Usage("repeated option");
      seen_global[*global] = true;
      switch (*global) {
        case kVault:
          parsed.globals.vault = value;
          break;
        case kAllowUnlocked:
          parsed.globals.allow_unlocked_memory = true;
          break;
        case kHelp:
          parsed.globals.help = true;
          break;
        case kVersion:
          parsed.globals.version = true;
          break;
      }
    } else {
      if (parsed.Has(name)) return Usage("repeated option");
      parsed.options.push_back(ParsedOption{command_option->name, value});
    }
  }

  if (parsed.globals.help || parsed.globals.version) return parsed;
  if (parsed.command == nullptr) return Usage("no command given");
  if (parsed.positionals.size() < parsed.command->min_positionals ||
      parsed.positionals.size() > parsed.command->max_positionals) {
    return Usage("wrong number of arguments");
  }
  return parsed;
}

}  // namespace nilkey

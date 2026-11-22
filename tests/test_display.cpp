// WritePrintable: what a terminal may be shown from a vault. Output is
// captured with a memory stream.

#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#include "nilkey/display.hpp"
#include "test_framework.hpp"

using nilkey::ErrorCode;
using nilkey::WritePrintable;

namespace {

std::vector<std::byte> B(std::string_view s) {
  std::vector<std::byte> b;
  for (const char c : s) b.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
  return b;
}

std::string Shown(std::string_view input) {
  char* buffer = nullptr;
  std::size_t size = 0;
  std::FILE* out = open_memstream(&buffer, &size);
  if (out == nullptr) std::abort();
  const bool ok = WritePrintable(out, B(input)).ok();
  std::fclose(out);  // Fills `buffer` and `size`.
  std::string text(buffer == nullptr ? "" : buffer, size);
  std::free(buffer);
  return ok ? text : "<write failed>";
}

}  // namespace

NILKEY_TEST(plain_text_is_unchanged) {
  NILKEY_EXPECT(Shown("github.com/user name-1_2") == "github.com/user name-1_2");
  NILKEY_EXPECT(Shown("").empty());
}

NILKEY_TEST(other_languages_and_emoji_are_unchanged) {
  const std::string text = "\xC3\xA7\xC4\x9F\xC4\xB1\xC3\xB6\xC5\x9F\xC3\xBC \xE6\x97\xA5\xE6\x9C\xAC "
                           "\xF0\x9F\x94\x91";
  NILKEY_EXPECT(Shown(text) == text);
  NILKEY_EXPECT(Shown("\xC2\xA0") == "\xC2\xA0");  // U+00A0 is not a C1 control.
}

NILKEY_TEST(terminal_escape_sequences_are_defused) {
  NILKEY_EXPECT(Shown("\x1b[31mred\x1b[0m") == "?[31mred?[0m");
  NILKEY_EXPECT(Shown("\x1b]0;title\x07") == "?]0;title?");
}

NILKEY_TEST(c0_controls_and_del_become_a_question_mark) {
  NILKEY_EXPECT(Shown(std::string_view("a\tb\nc\rd\0e\x7f", 10)) == "a?b?c?d?e?");
  NILKEY_EXPECT(Shown("\x01\x08\x1f") == "???");
}

NILKEY_TEST(c1_controls_become_one_question_mark_each) {
  NILKEY_EXPECT(Shown("a\xC2\x85z") == "a?z");  // U+0085 NEL
  NILKEY_EXPECT(Shown("\xC2\x9B") == "?");      // U+009B CSI
  NILKEY_EXPECT(Shown("\xC2\x80\xC2\x9F") == "??");
}

NILKEY_TEST(direction_and_line_controls_are_replaced) {
  NILKEY_EXPECT(Shown("a\xE2\x80\xAE" "b") == "a?b");   // U+202E right-to-left override
  NILKEY_EXPECT(Shown("\xE2\x80\xAA\xE2\x80\xAD") == "??");  // U+202A, U+202D
  NILKEY_EXPECT(Shown("\xE2\x81\xA6\xE2\x81\xA9") == "??");  // U+2066, U+2069
  NILKEY_EXPECT(Shown("\xE2\x80\x8E\xE2\x80\x8F") == "??");  // U+200E, U+200F
  NILKEY_EXPECT(Shown("\xE2\x80\xA8\xE2\x80\xA9") == "??");  // U+2028, U+2029
  NILKEY_EXPECT(Shown("\xD8\x9C") == "?");                   // U+061C
  // The neighbours of those ranges are ordinary characters.
  NILKEY_EXPECT(Shown("\xE2\x80\xAF") == "\xE2\x80\xAF");    // U+202F
  NILKEY_EXPECT(Shown("\xE2\x81\xA5") == "\xE2\x81\xA5");    // U+2065
  NILKEY_EXPECT(Shown("\xE2\x81\xAA") == "\xE2\x81\xAA");    // U+206A
}

NILKEY_TEST(bytes_that_are_not_valid_utf8_are_replaced_one_by_one) {
  NILKEY_EXPECT(Shown("a\x80z") == "a?z");             // stray continuation byte
  NILKEY_EXPECT(Shown("\xFF\xFE") == "??");            // never valid
  NILKEY_EXPECT(Shown("\xC0\xAF") == "??");            // overlong "/"
  NILKEY_EXPECT(Shown("\xED\xA0\x80") == "???");       // a surrogate
  NILKEY_EXPECT(Shown("ab\xE2\x82") == "ab??");        // truncated at the end
  NILKEY_EXPECT(Shown("\xF4\x90\x80\x80") == "????");  // above U+10FFFF
}

NILKEY_TEST(a_failed_write_is_an_error) {
  // A stream opened for reading cannot be written to.
  std::FILE* read_only = std::fopen("/dev/null", "r");
  NILKEY_EXPECT(read_only != nullptr);
  const auto status = WritePrintable(read_only, B("name"));
  NILKEY_EXPECT(std::fclose(read_only) == 0);
  NILKEY_EXPECT(!status.ok());
  NILKEY_EXPECT(status.error().code == ErrorCode::kIoError);
}

NILKEY_TEST_MAIN()

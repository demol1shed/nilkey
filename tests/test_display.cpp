// WritePrintable: what a terminal may be shown from a vault. Output is
// captured with a memory stream. PrintableWidth: how many terminal cells that
// output fills.

#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#include "nilkey/display.hpp"
#include "test_framework.hpp"

using nilkey::ErrorCode;
using nilkey::PrintableWidth;
using nilkey::ShowsAsWritten;
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

bool Written(std::string_view input) { return ShowsAsWritten(B(input)); }

std::size_t Cells(std::string_view input) { return PrintableWidth(B(input)); }

// The characters in `text`: every byte except UTF-8 continuation bytes.
std::size_t CodePoints(const std::string& text) {
  std::size_t count = 0;
  for (const char c : text) {
    if ((static_cast<unsigned char>(c) & 0xC0U) != 0x80U) ++count;
  }
  return count;
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

NILKEY_TEST(text_that_shows_as_written_is_accepted) {
  NILKEY_EXPECT(Written(""));
  NILKEY_EXPECT(Written("github.com/user name-1_2"));
  NILKEY_EXPECT(Written("\xC3\xA7\xC4\x9F\xC4\xB1\xC3\xB6\xC5\x9F\xC3\xBC"));  // Turkish
  NILKEY_EXPECT(Written("\xF0\x9F\x94\x91 \xE6\x97\xA5"));                      // emoji, CJK
  NILKEY_EXPECT(Written("\xC2\xA0"));                                            // U+00A0
  NILKEY_EXPECT(Written("\xE2\x80\xAF\xE2\x81\xA5\xE2\x81\xAA"));  // neighbours of the ranges
}

NILKEY_TEST(text_that_would_be_replaced_does_not_show_as_written) {
  NILKEY_EXPECT(!Written("\x1b[31mred"));                     // ESC
  NILKEY_EXPECT(!Written("a\tb"));                            // tab
  NILKEY_EXPECT(!Written("a\nb"));                            // newline
  NILKEY_EXPECT(!Written(std::string_view("a\0b", 3)));       // NUL
  NILKEY_EXPECT(!Written("a\x7f"));                           // DEL
  NILKEY_EXPECT(!Written("a\xC2\x85"));                      // C1: NEL
  NILKEY_EXPECT(!Written("a\xC2\x9B"));                      // C1: CSI
  NILKEY_EXPECT(!Written("a\xE2\x80\xAE" "b"));               // U+202E
  NILKEY_EXPECT(!Written("\xE2\x80\x8E"));                    // U+200E
  NILKEY_EXPECT(!Written("a\x80z"));                          // invalid UTF-8
  NILKEY_EXPECT(!Written("ab\xE2\x82"));                     // truncated at the end
  NILKEY_EXPECT(!Written("\xF0\x9F\x94\x91\x01"));            // one bad character after a good one
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

NILKEY_TEST(width_of_ascii_and_one_cell_letters) {
  NILKEY_EXPECT(Cells("") == 0);
  NILKEY_EXPECT(Cells("github.com/user name-1_2") == 24);
  NILKEY_EXPECT(Cells("\xC4\xB1\xC4\xB0\xC5\x9F\xC4\x9F\xC3\xBC\xC3\xB6\xC3\xA7") == 7);  // Turkish letters
  NILKEY_EXPECT(Cells("\xE2\x86\x92\xE2\x98\x85") == 2);  // U+2192, U+2605: narrow symbols
  NILKEY_EXPECT(Cells("\xE2\x9D\xA4") == 1);                 // U+2764 without a selector
}

NILKEY_TEST(width_of_a_replaced_character_is_one_cell) {
  NILKEY_EXPECT(Cells("a\x1b[0m") == 5);               // ESC, '[', '0', 'm' and 'a'
  NILKEY_EXPECT(Cells(std::string_view("a\tb\0c", 5)) == 5);
  NILKEY_EXPECT(Cells("\x7f") == 1);
  NILKEY_EXPECT(Cells("\xC2\x85") == 1);               // C1 control
  NILKEY_EXPECT(Cells("\xE2\x80\xAE") == 1);           // direction override
  NILKEY_EXPECT(Cells("\xFF\xFE") == 2);               // two invalid bytes
  NILKEY_EXPECT(Cells("ab\xE2\x82") == 4);             // truncated sequence
}

NILKEY_TEST(width_of_east_asian_and_emoji_characters_is_two_cells) {
  NILKEY_EXPECT(Cells("\xF0\x9F\x94\x91") == 2);                  // U+1F511
  NILKEY_EXPECT(Cells("\xE6\x97\xA5\xE6\x9C\xAC") == 4);        // two CJK characters
  NILKEY_EXPECT(Cells("\xEA\xB0\x80") == 2);                       // U+AC00 Hangul
  // Emoji from the Miscellaneous Symbols blocks, drawn wide by terminals.
  NILKEY_EXPECT(Cells("\xE2\x9C\x85") == 2);  // U+2705
  NILKEY_EXPECT(Cells("\xE2\xAD\x90") == 2);  // U+2B50
  NILKEY_EXPECT(Cells("\xE2\x8C\x9A") == 2);  // U+231A
  NILKEY_EXPECT(Cells("\xE2\x98\x95") == 2);  // U+2615
  NILKEY_EXPECT(Cells("\xE2\x9A\xA1") == 2);  // U+26A1
  NILKEY_EXPECT(Cells("\xE2\x9D\x8C") == 2);  // U+274C
  NILKEY_EXPECT(Cells("\xF0\x9F\x8F\xBB") == 2);  // U+1F3FB skin tone
  NILKEY_EXPECT(Cells("\xF0\xA0\x80\x80") == 2);  // U+20000 CJK extension B
}

NILKEY_TEST(width_of_combining_marks_and_joiners_is_zero) {
  NILKEY_EXPECT(Cells("e\xCC\x81") == 1);              // e + U+0301
  NILKEY_EXPECT(Cells("\xE2\x80\x8B") == 0);           // U+200B zero width space
  NILKEY_EXPECT(Cells("\xE2\x80\x8D") == 0);           // U+200D zero width joiner
  NILKEY_EXPECT(Cells("\xEF\xB8\x8F") == 0);           // U+FE0F variation selector
  NILKEY_EXPECT(Cells("\xE2\x9D\xA4\xEF\xB8\x8F") == 1);  // U+2764 U+FE0F
  NILKEY_EXPECT(Cells("\xF3\xA0\x84\x80") == 0);      // U+E0100 variation selector
}

NILKEY_TEST(width_changes_exactly_at_the_edges_of_the_ranges) {
  NILKEY_EXPECT(Cells("\xE1\x83\xBF") == 1);  // U+10FF just below U+1100
  NILKEY_EXPECT(Cells("\xE1\x84\x80") == 2);  // U+1100
  NILKEY_EXPECT(Cells("\xE1\x85\x9F") == 2);  // U+115F
  NILKEY_EXPECT(Cells("\xE1\x85\xA0") == 0);  // U+1160 Hangul filler vowels
  NILKEY_EXPECT(Cells("\xED\x9E\xA3") == 2);  // U+D7A3, the last Hangul syllable
  NILKEY_EXPECT(Cells("\xED\x9E\xA4") == 1);  // U+D7A4
  NILKEY_EXPECT(Cells("\xCC\xBF") == 0);       // U+033F inside U+0300..U+036F
  NILKEY_EXPECT(Cells("\xCD\xB0") == 1);       // U+0370 just above it
  NILKEY_EXPECT(Cells("\xF4\x8F\xBF\xBF") == 1);  // U+10FFFF
}

NILKEY_TEST(width_matches_what_write_printable_writes) {
  // Text with only one-cell characters and replaced ones: the cells are the
  // characters of what is written.
  const std::string text = std::string("plain \x1b[31m t\xC3\xBCrk\xC3\xA7" "e\xFF\x01 \xC2\x85 \xE2\x80\xAE end");
  NILKEY_EXPECT(Cells(text) == CodePoints(Shown(text)));
}

NILKEY_TEST_MAIN()

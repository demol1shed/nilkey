#ifndef NILKEY_DISPLAY_HPP
#define NILKEY_DISPLAY_HPP

// Text from a vault that is shown on a terminal (record names, user names).
// A vault may come from another writer, and a terminal obeys control
// characters, so raw output could rewrite the screen or reorder what the user
// reads. WritePrintable() writes such text with everything that acts on the
// terminal replaced by '?'.
//
// This is display data (SPEC.md 9.2 lists names), not a secret, but it is still
// part of the decrypted payload, so it is written straight from the caller's
// view of the vault to the stream, with no copy into a std::string. Passwords
// and notes never go through here.

#include <cstddef>
#include <cstdio>
#include <span>

#include "nilkey/result.hpp"

namespace nilkey {

// Replaced by one '?' each:
//   * C0 controls (including tab, newline and ESC) and DEL;
//   * C1 controls (U+0080..U+009F), which some terminals treat like ESC;
//   * text direction and line controls: U+061C, U+200E, U+200F, U+2028,
//     U+2029, U+202A..U+202E, U+2066..U+2069;
//   * every byte that is not part of a valid UTF-8 sequence.
// Everything else, including other languages and emoji, is written unchanged.
// kIoError if writing to `out` fails.
[[nodiscard]] Status WritePrintable(std::FILE* out, std::span<const std::byte> text);

// How many terminal cells WritePrintable() fills for `text`, so that columns
// can be lined up. A replaced character is one cell (the '?'); other
// characters are one cell, two (East Asian and emoji) or none (combining marks
// and joiners). The width of the common characters is right; a sequence that a
// terminal draws as one picture (a flag, a family) is counted code point by
// code point and may be off by a few cells.
[[nodiscard]] std::size_t PrintableWidth(std::span<const std::byte> text);

}  // namespace nilkey

#endif  // NILKEY_DISPLAY_HPP

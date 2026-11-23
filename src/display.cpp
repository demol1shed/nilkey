#include "nilkey/display.hpp"

#include <cstdint>

#include "nilkey/tlv.hpp"

namespace nilkey {

namespace {

// Length of the UTF-8 sequence a lead byte announces, or 0 if it cannot lead.
std::size_t SequenceLength(std::uint8_t lead) {
  if (lead >= 0xC2 && lead <= 0xDF) return 2;
  if (lead >= 0xE0 && lead <= 0xEF) return 3;
  if (lead >= 0xF0 && lead <= 0xF4) return 4;
  return 0;
}

// The code point of a sequence that IsValidUtf8() has already accepted.
std::uint32_t Decode(std::span<const std::byte> sequence) {
  const auto lead = static_cast<std::uint32_t>(sequence[0]);
  std::uint32_t code = 0;
  switch (sequence.size()) {
    case 2:
      code = lead & 0x1FU;
      break;
    case 3:
      code = lead & 0x0FU;
      break;
    default:
      code = lead & 0x07U;
      break;
  }
  for (std::size_t i = 1; i < sequence.size(); ++i) {
    code = (code << 6) | (static_cast<std::uint32_t>(sequence[i]) & 0x3FU);
  }
  return code;
}

bool ActsOnTheTerminal(std::uint32_t code) {
  return (code >= 0x80 && code <= 0x9F) ||  // C1 controls
         code == 0x061C || code == 0x200E || code == 0x200F ||  // direction marks
         code == 0x2028 || code == 0x2029 ||                    // line and paragraph
         (code >= 0x202A && code <= 0x202E) ||                  // embeddings, overrides
         (code >= 0x2066 && code <= 0x2069);                    // isolates
}

Status Put(std::FILE* out, std::span<const std::byte> bytes) {
  if (std::fwrite(bytes.data(), 1, bytes.size(), out) != bytes.size()) {
    return make_error(ErrorCode::kIoError);
  }
  return Ok();
}

// The first character of `text` as it is shown: the bytes to write (the
// character itself, or one '?' if it is replaced), how many input bytes it
// used, and its code point. One byte that is not valid UTF-8 counts as one
// replaced character; `code` is 0 for it and for a replaced ASCII character.
struct Piece {
  std::span<const std::byte> shown;
  std::size_t step;
  std::uint32_t code;
  bool replaced;
};

Piece NextPiece(std::span<const std::byte> text) {
  static constexpr std::byte kPlaceholder{'?'};
  const std::span<const std::byte> placeholder(&kPlaceholder, 1);

  const auto c = static_cast<std::uint8_t>(text[0]);
  if (c < 0x80) {
    const bool show = c >= 0x20 && c != 0x7F;
    return {show ? text.first(1) : placeholder, 1, show ? c : 0U, !show};
  }
  const std::size_t length = SequenceLength(c);
  if (length != 0 && text.size() >= length && IsValidUtf8(text.first(length))) {
    const std::span<const std::byte> character = text.first(length);
    const std::uint32_t code = Decode(character);
    const bool replaced = ActsOnTheTerminal(code);
    return {replaced ? placeholder : character, length, replaced ? 0U : code, replaced};
  }
  return {placeholder, 1, 0, true};
}

}  // namespace

Status WritePrintable(std::FILE* out, std::span<const std::byte> text) {
  while (!text.empty()) {
    const Piece piece = NextPiece(text);
    if (const Status s = Put(out, piece.shown); !s.ok()) return s;
    text = text.subspan(piece.step);
  }
  return Ok();
}

}  // namespace nilkey

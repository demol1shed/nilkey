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

}  // namespace

Status WritePrintable(std::FILE* out, std::span<const std::byte> text) {
  static constexpr std::byte kPlaceholder{'?'};
  const std::span<const std::byte> placeholder(&kPlaceholder, 1);

  std::size_t i = 0;
  while (i < text.size()) {
    const auto c = static_cast<std::uint8_t>(text[i]);
    std::span<const std::byte> piece = text.subspan(i, 1);
    bool show = false;
    std::size_t step = 1;

    if (c < 0x80) {
      show = c >= 0x20 && c != 0x7F;
    } else {
      const std::size_t length = SequenceLength(c);
      if (length != 0 && text.size() - i >= length && IsValidUtf8(text.subspan(i, length))) {
        piece = text.subspan(i, length);
        step = length;
        show = !ActsOnTheTerminal(Decode(piece));
      }
    }

    if (const Status s = Put(out, show ? piece : placeholder); !s.ok()) return s;
    i += step;
  }
  return Ok();
}

}  // namespace nilkey

#include "nilkey/tlv.hpp"

#include <algorithm>
#include <array>
#include <limits>

#include "nilkey/vault_format.hpp"

namespace nilkey {

namespace {

constexpr std::size_t kRecordLenSize = 4;
constexpr std::size_t kTimestampSize = 8;

std::uint32_t ReadLe32(std::span<const std::byte> bytes, std::size_t off) {
  std::uint32_t v = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    v |= static_cast<std::uint32_t>(bytes[off + i]) << (8 * i);
  }
  return v;
}

std::int64_t ReadLe64(std::span<const std::byte> bytes) {
  std::uint64_t v = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    v |= static_cast<std::uint64_t>(bytes[i]) << (8 * i);
  }
  return static_cast<std::int64_t>(v);  // Defined (two's complement) since C++20.
}

bool ByteLess(std::span<const std::byte> a, std::span<const std::byte> b) {
  return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
}

// The checks WriteRecord and RecordSize share with ParseRecord, so anything
// that is written parses back.
Status ValidateRecord(const Record& r) {
  if (r.name.empty()) return make_error(ErrorCode::kInvalidArgument);
  if (r.name.size() > kMaxNameSize) return make_error(ErrorCode::kOutOfRange);
  const std::array<std::span<const std::byte>, 4> text = {r.name, r.username, r.url, r.notes};
  for (const auto& field : text) {
    if (field.size() > kMaxPlaintextSize) return make_error(ErrorCode::kOutOfRange);
    if (!IsValidUtf8(field)) return make_error(ErrorCode::kInvalidArgument);
  }
  if (r.password.size() > kMaxPlaintextSize) return make_error(ErrorCode::kOutOfRange);
  return Ok();
}

}  // namespace

bool IsValidUtf8(std::span<const std::byte> bytes) {
  const std::size_t n = bytes.size();
  std::size_t i = 0;
  while (i < n) {
    const auto c = static_cast<std::uint8_t>(bytes[i]);
    if (c < 0x80) {
      ++i;
      continue;
    }
    // Number of continuation bytes, and the allowed range of the first one
    // (it excludes overlong forms, surrogates and values above U+10FFFF).
    std::size_t extra = 0;
    std::uint8_t lo = 0x80;
    std::uint8_t hi = 0xBF;
    if (c >= 0xC2 && c <= 0xDF) {
      extra = 1;
    } else if (c == 0xE0) {
      extra = 2;
      lo = 0xA0;
    } else if (c == 0xED) {
      extra = 2;
      hi = 0x9F;
    } else if (c >= 0xE1 && c <= 0xEF) {
      extra = 2;
    } else if (c == 0xF0) {
      extra = 3;
      lo = 0x90;
    } else if (c == 0xF4) {
      extra = 3;
      hi = 0x8F;
    } else if (c >= 0xF1 && c <= 0xF3) {
      extra = 3;
    } else {
      return false;  // 0x80..0xC1 and 0xF5..0xFF never start a sequence.
    }
    if (n - i - 1 < extra) return false;
    const auto first = static_cast<std::uint8_t>(bytes[i + 1]);
    if (first < lo || first > hi) return false;
    for (std::size_t k = 2; k <= extra; ++k) {
      const auto cont = static_cast<std::uint8_t>(bytes[i + k]);
      if (cont < 0x80 || cont > 0xBF) return false;
    }
    i += extra + 1;
  }
  return true;
}

Result<Field> NextField(std::span<const std::byte>& rest) {
  if (rest.size() < kFieldHeaderSize) return make_error(ErrorCode::kInvalidFormat);
  const std::uint32_t length = ReadLe32(rest, 1);
  // Compare against the remaining size, never add to it: no overflow possible.
  if (rest.size() - kFieldHeaderSize < length) return make_error(ErrorCode::kInvalidFormat);
  const Field field{static_cast<std::uint8_t>(rest[0]), rest.subspan(kFieldHeaderSize, length)};
  rest = rest.subspan(kFieldHeaderSize + length);
  return field;
}

Result<Record> ParseRecord(std::span<const std::byte> bytes) {
  std::array<bool, 256> seen{};
  Record record{};
  std::uint32_t field_count = 0;

  std::span<const std::byte> rest = bytes;
  while (!rest.empty()) {
    if (++field_count > kMaxFieldsPerRecord) return make_error(ErrorCode::kInvalidFormat);
    Result<Field> next = NextField(rest);
    if (!next.ok()) return next.error();
    const Field field = next.value();

    if (seen[field.type]) return make_error(ErrorCode::kInvalidFormat);
    seen[field.type] = true;

    switch (field.type) {
      case kFieldName:
        if (field.value.empty() || field.value.size() > kMaxNameSize ||
            !IsValidUtf8(field.value)) {
          return make_error(ErrorCode::kInvalidFormat);
        }
        record.name = field.value;
        break;
      case kFieldUsername:
        if (!IsValidUtf8(field.value)) return make_error(ErrorCode::kInvalidFormat);
        record.username = field.value;
        break;
      case kFieldPassword:
        record.password = field.value;
        break;
      case kFieldUrl:
        if (!IsValidUtf8(field.value)) return make_error(ErrorCode::kInvalidFormat);
        record.url = field.value;
        break;
      case kFieldNotes:
        if (!IsValidUtf8(field.value)) return make_error(ErrorCode::kInvalidFormat);
        record.notes = field.value;
        break;
      case kFieldCreatedAt:
        if (field.value.size() != kTimestampSize) return make_error(ErrorCode::kInvalidFormat);
        record.created_at = ReadLe64(field.value);
        break;
      case kFieldUpdatedAt:
        if (field.value.size() != kTimestampSize) return make_error(ErrorCode::kInvalidFormat);
        record.updated_at = ReadLe64(field.value);
        break;
      default:
        break;  // Unknown type: skipped for forward compatibility (SPEC.md 6.3).
    }
  }

  if (!seen[kFieldName] || !seen[kFieldPassword] || !seen[kFieldCreatedAt] ||
      !seen[kFieldUpdatedAt]) {
    return make_error(ErrorCode::kInvalidFormat);
  }
  return record;
}

Result<std::vector<RecordLocation>> ParseEnvelope(std::span<const std::byte> bytes) {
  if (bytes.size() < kRecordLenSize) return make_error(ErrorCode::kInvalidFormat);
  const std::uint32_t count = ReadLe32(bytes, 0);
  if (count > kMaxRecords) return make_error(ErrorCode::kInvalidFormat);
  // Each record needs at least its 4 byte length prefix, so a count that
  // cannot fit is rejected before anything is reserved.
  if (std::uint64_t{count} * kRecordLenSize > bytes.size() - kRecordLenSize) {
    return make_error(ErrorCode::kInvalidFormat);
  }

  std::vector<RecordLocation> locations;
  locations.reserve(count);
  std::vector<std::span<const std::byte>> names;
  names.reserve(count);

  std::size_t pos = kRecordLenSize;
  for (std::uint32_t i = 0; i < count; ++i) {
    if (bytes.size() - pos < kRecordLenSize) return make_error(ErrorCode::kInvalidFormat);
    const std::uint32_t length = ReadLe32(bytes, pos);
    pos += kRecordLenSize;
    if (bytes.size() - pos < length) return make_error(ErrorCode::kInvalidFormat);

    Result<Record> record = ParseRecord(bytes.subspan(pos, length));
    if (!record.ok()) return record.error();
    names.push_back(record.value().name);
    locations.push_back(RecordLocation{pos, length});
    pos += length;
  }
  if (pos != bytes.size()) return make_error(ErrorCode::kInvalidFormat);  // Trailing bytes.

  // Sorted, equal names are neighbours. Names are not compared as secrets.
  std::sort(names.begin(), names.end(), ByteLess);
  for (std::size_t i = 1; i < names.size(); ++i) {
    if (std::equal(names[i - 1].begin(), names[i - 1].end(), names[i].begin(), names[i].end())) {
      return make_error(ErrorCode::kInvalidFormat);
    }
  }
  return locations;
}

Result<std::size_t> RecordSize(const Record& record) {
  Status valid = ValidateRecord(record);
  if (!valid.ok()) return valid.error();

  // Every length is <= kMaxPlaintextSize (checked above), so this cannot
  // overflow a uint64.
  std::uint64_t total = 2 * (kFieldHeaderSize + kTimestampSize);
  total += kFieldHeaderSize + record.name.size();
  total += kFieldHeaderSize + record.password.size();
  for (const auto& optional : {record.username, record.url, record.notes}) {
    if (!optional.empty()) total += kFieldHeaderSize + optional.size();
  }
  if (total > kMaxPlaintextSize) return make_error(ErrorCode::kOutOfRange);
  return static_cast<std::size_t>(total);
}

Status TlvWriter::PutU32(std::uint32_t value) {
  if (out_.size() - pos_ < 4) return make_error(ErrorCode::kOutOfRange);
  for (std::size_t i = 0; i < 4; ++i) {
    out_[pos_ + i] = static_cast<std::byte>((value >> (8 * i)) & 0xFFU);
  }
  pos_ += 4;
  return Ok();
}

Status TlvWriter::PutField(std::uint8_t type, std::span<const std::byte> value) {
  if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
    return make_error(ErrorCode::kOutOfRange);
  }
  if (out_.size() - pos_ < kFieldHeaderSize ||
      out_.size() - pos_ - kFieldHeaderSize < value.size()) {
    return make_error(ErrorCode::kOutOfRange);
  }
  out_[pos_] = static_cast<std::byte>(type);
  ++pos_;
  // Cannot fail: the space for the length and the value was checked above.
  Status length_ok = PutU32(static_cast<std::uint32_t>(value.size()));
  if (!length_ok.ok()) return length_ok.error();
  std::copy(value.begin(), value.end(), out_.begin() + static_cast<std::ptrdiff_t>(pos_));
  pos_ += value.size();
  return Ok();
}

Status TlvWriter::PutRaw(std::span<const std::byte> bytes) {
  if (out_.size() - pos_ < bytes.size()) return make_error(ErrorCode::kOutOfRange);
  std::copy(bytes.begin(), bytes.end(), out_.begin() + static_cast<std::ptrdiff_t>(pos_));
  pos_ += bytes.size();
  return Ok();
}

Status TlvWriter::PutInt64Field(std::uint8_t type, std::int64_t value) {
  std::array<std::byte, kTimestampSize> raw{};
  const auto bits = static_cast<std::uint64_t>(value);
  for (std::size_t i = 0; i < raw.size(); ++i) {
    raw[i] = static_cast<std::byte>((bits >> (8 * i)) & 0xFFU);
  }
  return PutField(type, raw);
}

Status WriteRecord(TlvWriter& writer, const Record& record) {
  Status valid = ValidateRecord(record);
  if (!valid.ok()) return valid;

  struct Entry {
    std::uint8_t type;
    std::span<const std::byte> value;
    bool required;
  };
  // Ascending type order; empty optional fields are left out (SPEC.md 6.4).
  const std::array<Entry, 5> entries = {{{kFieldName, record.name, true},
                                         {kFieldUsername, record.username, false},
                                         {kFieldPassword, record.password, true},
                                         {kFieldUrl, record.url, false},
                                         {kFieldNotes, record.notes, false}}};
  for (const Entry& e : entries) {
    if (!e.required && e.value.empty()) continue;
    Status put = writer.PutField(e.type, e.value);
    if (!put.ok()) return put;
  }
  Status created = writer.PutInt64Field(kFieldCreatedAt, record.created_at);
  if (!created.ok()) return created;
  return writer.PutInt64Field(kFieldUpdatedAt, record.updated_at);
}

}  // namespace nilkey

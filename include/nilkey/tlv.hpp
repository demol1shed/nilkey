#ifndef NILKEY_TLV_HPP
#define NILKEY_TLV_HPP

// Binary TLV envelope of the decrypted vault payload (SPEC.md 6). All
// multi-byte integers are little-endian. Everything here works on spans: the
// caller owns the memory and, for secrets, keeps it in a SecureBuffer with a
// guard open while these views are in use.

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "nilkey/result.hpp"

namespace nilkey {

// Field type codes (SPEC.md 6.2).
inline constexpr std::uint8_t kFieldName = 0x01;
inline constexpr std::uint8_t kFieldUsername = 0x02;
inline constexpr std::uint8_t kFieldPassword = 0x03;
inline constexpr std::uint8_t kFieldUrl = 0x04;
inline constexpr std::uint8_t kFieldNotes = 0x05;
inline constexpr std::uint8_t kFieldCreatedAt = 0x06;
inline constexpr std::uint8_t kFieldUpdatedAt = 0x07;

// Parser limits (SPEC.md 6.3 asks for "reasonable" bounds; values in 6.4).
inline constexpr std::uint32_t kMaxRecords = 100000;
inline constexpr std::uint32_t kMaxFieldsPerRecord = 64;
inline constexpr std::uint32_t kMaxNameSize = 1024;

inline constexpr std::size_t kFieldHeaderSize = 5;  // type (1) + length (4)

// One decoded record. The spans point into the buffer that was parsed. An
// absent optional field and an empty one are the same: an empty span.
struct Record {
  std::span<const std::byte> name;
  std::span<const std::byte> username;
  std::span<const std::byte> password;
  std::span<const std::byte> url;
  std::span<const std::byte> notes;
  std::int64_t created_at;
  std::int64_t updated_at;
};

// Where one record's TLV bytes sit inside the envelope (after its length
// prefix). Plain offsets, so it holds no secrets.
struct RecordLocation {
  std::size_t offset;
  std::uint32_t length;
};

// One raw field. Used to walk a record, including fields of unknown type.
struct Field {
  std::uint8_t type;
  std::span<const std::byte> value;
};

// Strict UTF-8 (RFC 3629): rejects overlong forms, surrogates, > U+10FFFF and
// truncated sequences. An embedded NUL is valid UTF-8 and is accepted.
[[nodiscard]] bool IsValidUtf8(std::span<const std::byte> bytes);

// Reads the field at the front of `rest` and advances `rest` past it. Fails
// with kInvalidFormat if the header or the value does not fit in `rest`.
[[nodiscard]] Result<Field> NextField(std::span<const std::byte>& rest);

// Parses the TLV fields of one record (without its length prefix). Unknown
// field types are skipped; a repeated type (known or not), a missing required
// field, a bad length or invalid UTF-8 in a text field is kInvalidFormat.
[[nodiscard]] Result<Record> ParseRecord(std::span<const std::byte> bytes);

// Validates a whole envelope: record count, every record (via ParseRecord),
// that the buffer is consumed exactly, and that no `name` repeats. Names are
// compared byte for byte; there is no Unicode normalization. Returns the
// location of each record in order.
[[nodiscard]] Result<std::vector<RecordLocation>> ParseEnvelope(std::span<const std::byte> bytes);

// Size of the known fields of `record` as ParseRecord expects them, i.e. what
// WriteRecord() will write. Optional fields that are empty are not counted.
[[nodiscard]] Result<std::size_t> RecordSize(const Record& record);

// Appends little-endian values and TLV fields to a caller-provided buffer.
// Every Put checks the remaining space and returns kOutOfRange instead of
// writing past the end.
class TlvWriter {
 public:
  explicit TlvWriter(std::span<std::byte> out) : out_(out) {}

  [[nodiscard]] Status PutU32(std::uint32_t value);
  [[nodiscard]] Status PutField(std::uint8_t type, std::span<const std::byte> value);
  [[nodiscard]] Status PutInt64Field(std::uint8_t type, std::int64_t value);
  // Appends bytes verbatim, e.g. a record that is copied unchanged.
  [[nodiscard]] Status PutRaw(std::span<const std::byte> bytes);

  std::size_t written() const { return pos_; }

 private:
  std::span<std::byte> out_;
  std::size_t pos_ = 0;
};

// Writes the known fields of `record` in ascending type order. Validates the
// same rules ParseRecord enforces (non-empty name within kMaxNameSize, UTF-8
// text fields), so a record that was written always parses back.
[[nodiscard]] Status WriteRecord(TlvWriter& writer, const Record& record);

}  // namespace nilkey

#endif  // NILKEY_TLV_HPP

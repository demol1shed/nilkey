#include "nilkey/vault.hpp"

#include <algorithm>
#include <utility>

#include "nilkey/vault_format.hpp"

namespace nilkey {

namespace {

constexpr std::size_t kEnvelopeHeaderSize = 4;  // record_count
constexpr std::size_t kRecordLenSize = 4;

bool IsKnownType(std::uint8_t type) { return type >= kFieldName && type <= kFieldUpdatedAt; }

bool SameBytes(std::span<const std::byte> a, std::span<const std::byte> b) {
  return std::equal(a.begin(), a.end(), b.begin(), b.end());
}

std::span<const std::byte> RecordBytes(std::span<const std::byte> payload,
                                       const RecordLocation& loc) {
  return payload.subspan(loc.offset, loc.length);
}

Record ToRecord(const RecordInput& in, std::int64_t created_at, std::int64_t updated_at) {
  return Record{in.name, in.username, in.password, in.url, in.notes, created_at, updated_at};
}

// The name of an already validated record, without decoding the other fields.
std::span<const std::byte> NameOf(std::span<const std::byte> record) {
  std::span<const std::byte> rest = record;
  while (!rest.empty()) {
    Result<Field> field = NextField(rest);
    if (!field.ok()) break;
    if (field.value().type == kFieldName) return field.value().value;
  }
  return {};
}

// The fields of `record` whose type this version does not know.
Result<std::vector<Field>> UnknownFields(std::span<const std::byte> record) {
  std::vector<Field> unknown;
  std::span<const std::byte> rest = record;
  while (!rest.empty()) {
    Result<Field> field = NextField(rest);
    if (!field.ok()) return field.error();
    if (!IsKnownType(field.value().type)) unknown.push_back(field.value());
  }
  return unknown;
}

// One record of a new payload: an old record copied byte for byte, or a new
// one that is encoded (plus the unknown fields of an old record, if `carry` is
// set). Offsets and pointers only, never secrets.
struct Entry {
  std::optional<RecordLocation> copy;
  const Record* write = nullptr;
  std::optional<RecordLocation> carry;
};

Entry CopyOf(const RecordLocation& loc) { return Entry{loc, nullptr, std::nullopt}; }

struct BuiltPayload {
  SecureBuffer payload;
  std::vector<RecordLocation> index;
};

// Parses `buffer` as a payload and returns its index.
Result<std::vector<RecordLocation>> IndexOf(const SecureBuffer& buffer) {
  Result<ScopedReadGuard> guard = ScopedReadGuard::Open(buffer);
  if (!guard.ok()) return guard.error();
  return ParseEnvelope(guard.value().bytes());
}

// Writes the new payload. `lengths` holds the record_len of every entry.
Status Fill(SecureBuffer& buffer, std::span<const std::byte> old, std::span<const Entry> entries,
            const std::vector<std::size_t>& lengths) {
  Result<ScopedWriteGuard> guard = ScopedWriteGuard::Open(buffer);
  if (!guard.ok()) return guard.error();
  TlvWriter writer(guard.value().bytes());

  Status put = writer.PutU32(static_cast<std::uint32_t>(entries.size()));
  if (!put.ok()) return put;
  for (std::size_t i = 0; i < entries.size(); ++i) {
    const Entry& entry = entries[i];
    put = writer.PutU32(static_cast<std::uint32_t>(lengths[i]));
    if (!put.ok()) return put;
    if (entry.copy.has_value()) {
      put = writer.PutRaw(RecordBytes(old, *entry.copy));
      if (!put.ok()) return put;
      continue;
    }
    put = WriteRecord(writer, *entry.write);
    if (!put.ok()) return put;
    if (entry.carry.has_value()) {
      Result<std::vector<Field>> unknown = UnknownFields(RecordBytes(old, *entry.carry));
      if (!unknown.ok()) return unknown.error();
      for (const Field& field : unknown.value()) {
        put = writer.PutField(field.type, field.value);
        if (!put.ok()) return put;
      }
    }
  }
  // The size pass and the write pass must agree, or the payload is wrong.
  if (writer.written() != buffer.size()) return make_error(ErrorCode::kInternal);
  return Ok();
}

// Sizes the new payload (rejecting anything over the limits before memory is
// allocated), writes it into a fresh SecureBuffer and re-parses the result.
// `old` is the payload that the locations in `entries` refer to.
Result<BuiltPayload> BuildPayload(std::span<const std::byte> old, std::span<const Entry> entries,
                                  MemlockPolicy policy) {
  if (entries.size() > kMaxRecords) return make_error(ErrorCode::kOutOfRange);

  std::vector<std::size_t> lengths;
  lengths.reserve(entries.size());
  // uint64 so the sum cannot wrap; it is checked against the limit every step.
  std::uint64_t total = kEnvelopeHeaderSize;
  for (const Entry& entry : entries) {
    std::uint64_t length = 0;
    if (entry.copy.has_value()) {
      length = entry.copy->length;
    } else {
      Result<std::size_t> known = RecordSize(*entry.write);
      if (!known.ok()) return known.error();
      length = known.value();

      std::uint64_t field_count = 4;  // name, password, created_at, updated_at
      field_count += entry.write->username.empty() ? 0U : 1U;
      field_count += entry.write->url.empty() ? 0U : 1U;
      field_count += entry.write->notes.empty() ? 0U : 1U;
      if (entry.carry.has_value()) {
        Result<std::vector<Field>> unknown = UnknownFields(RecordBytes(old, *entry.carry));
        if (!unknown.ok()) return unknown.error();
        for (const Field& field : unknown.value()) length += kFieldHeaderSize + field.value.size();
        field_count += unknown.value().size();
      }
      // A record with more fields would be written but would not parse back.
      if (field_count > kMaxFieldsPerRecord) return make_error(ErrorCode::kOutOfRange);
    }
    total += kRecordLenSize + length;
    if (total > kMaxPlaintextSize) return make_error(ErrorCode::kOutOfRange);
    lengths.push_back(static_cast<std::size_t>(length));
  }

  Result<SecureBuffer> buffer = SecureBuffer::Create(static_cast<std::size_t>(total), policy);
  if (!buffer.ok()) return buffer.error();
  Status filled = Fill(buffer.value(), old, entries, lengths);
  if (!filled.ok()) return filled.error();

  // Never hold a payload that does not parse. Fill() and IndexOf() have closed
  // their guards, so the buffer can be moved into the result.
  Result<std::vector<RecordLocation>> index = IndexOf(buffer.value());
  if (!index.ok()) return index.error();
  return BuiltPayload{std::move(buffer).value(), std::move(index).value()};
}

}  // namespace

Result<Record> VaultReader::Get(std::size_t index) const {
  if (index >= index_->size()) return make_error(ErrorCode::kOutOfRange);
  return ParseRecord(RecordBytes(payload(), (*index_)[index]));
}

// shortcut: linear scan, index by name if kMaxRecords grows.
std::optional<std::size_t> VaultReader::Find(std::span<const std::byte> name) const {
  for (std::size_t i = 0; i < index_->size(); ++i) {
    if (SameBytes(NameOf(RecordBytes(payload(), (*index_)[i])), name)) return i;
  }
  return std::nullopt;
}

Result<Vault> Vault::CreateEmpty(MemlockPolicy policy) {
  // SecureBuffer::Create zero-fills, and four zero bytes are the envelope of a
  // vault with record_count = 0.
  Result<SecureBuffer> buffer = SecureBuffer::Create(kEnvelopeHeaderSize, policy);
  if (!buffer.ok()) return buffer.error();
  return Vault(std::move(buffer).value(), {}, policy);
}

Result<Vault> Vault::FromPlaintext(SecureBuffer plaintext, MemlockPolicy policy) {
  Result<std::vector<RecordLocation>> index = IndexOf(plaintext);
  if (!index.ok()) return index.error();
  return Vault(std::move(plaintext), std::move(index).value(), policy);
}

Result<VaultReader> Vault::Open() const {
  Result<ScopedReadGuard> guard = ScopedReadGuard::Open(payload_);
  if (!guard.ok()) return guard.error();
  return VaultReader(std::move(guard).value(), &index_);
}

// In each mutation the lambda owns the reader, so its guard is closed before
// the new payload is moved in: moving a buffer with a guard open aborts.

Status Vault::Add(const RecordInput& input, std::int64_t now) {
  const Record record = ToRecord(input, now, now);
  Result<BuiltPayload> built = [&]() -> Result<BuiltPayload> {
    Result<VaultReader> reader = Open();
    if (!reader.ok()) return reader.error();
    if (reader.value().Find(input.name).has_value()) {
      return make_error(ErrorCode::kAlreadyExists);
    }
    std::vector<Entry> entries;
    entries.reserve(index_.size() + 1);
    for (const RecordLocation& loc : index_) entries.push_back(CopyOf(loc));
    entries.push_back(Entry{std::nullopt, &record, std::nullopt});
    return BuildPayload(reader.value().payload(), entries, policy_);
  }();
  if (!built.ok()) return built.error();
  payload_ = std::move(built.value().payload);
  index_ = std::move(built.value().index);
  return Ok();
}

Status Vault::Update(std::span<const std::byte> name, const RecordInput& input,
                     std::int64_t now) {
  Result<BuiltPayload> built = [&]() -> Result<BuiltPayload> {
    Result<VaultReader> reader = Open();
    if (!reader.ok()) return reader.error();
    const std::optional<std::size_t> target = reader.value().Find(name);
    if (!target.has_value()) return make_error(ErrorCode::kNotFound);
    // Renaming onto another record's name is refused; keeping the name is fine.
    const std::optional<std::size_t> owner = reader.value().Find(input.name);
    if (owner.has_value() && *owner != *target) return make_error(ErrorCode::kAlreadyExists);

    Result<Record> old = reader.value().Get(*target);
    if (!old.ok()) return old.error();
    const Record record = ToRecord(input, old.value().created_at, now);

    std::vector<Entry> entries;
    entries.reserve(index_.size());
    for (std::size_t i = 0; i < index_.size(); ++i) {
      if (i == *target) {
        entries.push_back(Entry{std::nullopt, &record, index_[i]});
      } else {
        entries.push_back(CopyOf(index_[i]));
      }
    }
    return BuildPayload(reader.value().payload(), entries, policy_);
  }();
  if (!built.ok()) return built.error();
  payload_ = std::move(built.value().payload);
  index_ = std::move(built.value().index);
  return Ok();
}

Status Vault::Remove(std::span<const std::byte> name) {
  Result<BuiltPayload> built = [&]() -> Result<BuiltPayload> {
    Result<VaultReader> reader = Open();
    if (!reader.ok()) return reader.error();
    const std::optional<std::size_t> target = reader.value().Find(name);
    if (!target.has_value()) return make_error(ErrorCode::kNotFound);

    std::vector<Entry> entries;
    entries.reserve(index_.size());
    for (std::size_t i = 0; i < index_.size(); ++i) {
      if (i != *target) entries.push_back(CopyOf(index_[i]));
    }
    return BuildPayload(reader.value().payload(), entries, policy_);
  }();
  if (!built.ok()) return built.error();
  payload_ = std::move(built.value().payload);
  index_ = std::move(built.value().index);
  return Ok();
}

}  // namespace nilkey

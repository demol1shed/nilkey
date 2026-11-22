// Vault data model: record CRUD on one SecureBuffer, and the round trip
// through Seal() and OpenWithPassword(). Built against nilkey_core_test so the
// Argon2id costs are small.
//
// Test payloads are written by hand with the SPEC.md 6 encoding, independent
// of the code under test.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <initializer_list>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "nilkey/crypto.hpp"
#include "nilkey/tlv.hpp"
#include "nilkey/vault.hpp"
#include "test_framework.hpp"

using nilkey::ErrorCode;
using nilkey::KdfParams;
using nilkey::MemlockPolicy;
using nilkey::NextField;
using nilkey::OpenWithPassword;
using nilkey::ParseEnvelope;
using nilkey::RecordInput;
using nilkey::RecordPatch;
using nilkey::ScopedWriteGuard;
using nilkey::SecureBuffer;
using nilkey::Seal;
using nilkey::Status;
using nilkey::Vault;

namespace {

using Bytes = std::vector<std::byte>;

constexpr MemlockPolicy kRequire = MemlockPolicy::kRequire;
constexpr KdfParams kFast = {8, 1};

Bytes Str(std::string_view s) {
  Bytes b;
  for (char c : s) b.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
  return b;
}

Bytes Raw(std::initializer_list<unsigned> values) {
  Bytes b;
  for (unsigned v : values) b.push_back(static_cast<std::byte>(v));
  return b;
}

void Cat(Bytes& dst, const Bytes& src) { dst.insert(dst.end(), src.begin(), src.end()); }

void PutLe(Bytes& dst, std::uint64_t v, std::size_t n) {
  for (std::size_t i = 0; i < n; ++i) dst.push_back(static_cast<std::byte>((v >> (8 * i)) & 0xFFU));
}

Bytes Fld(unsigned type, const Bytes& value) {
  Bytes b;
  b.push_back(static_cast<std::byte>(type));
  PutLe(b, value.size(), 4);
  Cat(b, value);
  return b;
}

Bytes Ts(unsigned type, std::uint64_t v) {
  Bytes value;
  PutLe(value, v, 8);
  return Fld(type, value);
}

// A record with name, password, created_at and updated_at.
Bytes Rec(std::string_view name, std::string_view password, std::uint64_t created,
          std::uint64_t updated) {
  Bytes b = Fld(0x01, Str(name));
  Cat(b, Fld(0x03, Str(password)));
  Cat(b, Ts(0x06, created));
  Cat(b, Ts(0x07, updated));
  return b;
}

Bytes Env(const std::vector<Bytes>& records) {
  Bytes b;
  PutLe(b, records.size(), 4);
  for (const Bytes& r : records) {
    PutLe(b, r.size(), 4);
    Cat(b, r);
  }
  return b;
}

std::span<const std::byte> S(const Bytes& b) { return b; }

bool Is(std::span<const std::byte> a, std::string_view s) {
  const Bytes expected = Str(s);
  return std::equal(a.begin(), a.end(), expected.begin(), expected.end());
}

bool Fails(const Status& s, ErrorCode code) { return !s.ok() && s.error().code == code; }

// Setup helper: a SecureBuffer holding `bytes`. Aborts if allocation fails.
SecureBuffer Secure(const Bytes& bytes, MemlockPolicy policy = kRequire) {
  SecureBuffer buffer = SecureBuffer::Create(bytes.size(), policy).value();
  auto guard = ScopedWriteGuard::Open(buffer).value();
  std::copy(bytes.begin(), bytes.end(), guard.bytes().begin());
  return buffer;
}

Vault FromBytes(const Bytes& payload, MemlockPolicy policy = kRequire) {
  return Vault::FromPlaintext(Secure(payload, policy), policy).value();
}

// A copy of the serialized payload, for comparing before and after.
Bytes Payload(const Vault& vault) {
  auto reader = vault.Open().value();
  return Bytes(reader.payload().begin(), reader.payload().end());
}

// The user fields of a record, owning their bytes.
struct Fields {
  Bytes name, username, password, url, notes;
  RecordInput View() const { return RecordInput{name, username, password, url, notes}; }
};

Fields F(std::string_view name, std::string_view password) {
  Fields f;
  f.name = Str(name);
  f.password = Str(password);
  return f;
}

// The bytes of record `index` of a serialized payload.
Bytes RecordAt(const Bytes& payload, std::size_t index) {
  auto locations = ParseEnvelope(S(payload)).value();
  const auto& loc = locations[index];
  return Bytes(payload.begin() + static_cast<std::ptrdiff_t>(loc.offset),
               payload.begin() + static_cast<std::ptrdiff_t>(loc.offset + loc.length));
}

bool HasField(const Bytes& record, unsigned type, const Bytes& value) {
  std::span<const std::byte> rest = S(record);
  while (!rest.empty()) {
    auto field = NextField(rest);
    if (!field.ok()) return false;
    if (field.value().type == type) {
      return std::equal(field.value().value.begin(), field.value().value.end(), value.begin(),
                        value.end());
    }
  }
  return false;
}

const Bytes kEmptyPayload = Raw({0, 0, 0, 0});

}  // namespace

// ---- Creating and loading ----

NILKEY_TEST(empty_vault_is_a_valid_empty_envelope) {
  Vault vault = Vault::CreateEmpty(kRequire).value();
  NILKEY_EXPECT(vault.size() == 0);
  NILKEY_EXPECT(Payload(vault) == kEmptyPayload);

  auto reloaded = Vault::FromPlaintext(Secure(kEmptyPayload), kRequire);
  NILKEY_EXPECT(reloaded.ok());
  NILKEY_EXPECT(reloaded.value().size() == 0);
}

NILKEY_TEST(from_plaintext_rejects_invalid_payloads) {
  auto empty = Vault::FromPlaintext(Secure({}), kRequire);
  NILKEY_EXPECT(!empty.ok() && empty.error().code == ErrorCode::kInvalidFormat);

  Bytes trailing = kEmptyPayload;
  trailing.push_back(std::byte{0});
  auto extra = Vault::FromPlaintext(Secure(trailing), kRequire);
  NILKEY_EXPECT(!extra.ok() && extra.error().code == ErrorCode::kInvalidFormat);

  auto duplicate = Vault::FromPlaintext(
      Secure(Env({Rec("a", "p", 1, 2), Rec("a", "q", 3, 4)})), kRequire);
  NILKEY_EXPECT(!duplicate.ok() && duplicate.error().code == ErrorCode::kInvalidFormat);
}

// ---- Add ----

NILKEY_TEST(add_then_find_and_get_round_trips_every_field) {
  Vault vault = Vault::CreateEmpty(kRequire).value();
  Fields f;
  f.name = Str("caf\xC3\xA9");
  f.username = Str("alice");
  // "pa\0ss é" + emoji: an embedded NUL and non-ASCII text.
  f.password = Raw({'p', 'a', 0x00, 's', 's', ' ', 0xC3, 0xA9, ' ', 0xF0, 0x9F, 0x94, 0x91});
  f.url = Str("https://example.org");
  f.notes = Str("line one\nline two");
  NILKEY_EXPECT(vault.Add(f.View(), 1700000000).ok());
  NILKEY_EXPECT(vault.size() == 1);

  auto reader = vault.Open();
  NILKEY_EXPECT(reader.ok());
  NILKEY_EXPECT(reader.value().size() == 1);
  NILKEY_EXPECT(reader.value().Find(f.name) == std::optional<std::size_t>(0));
  NILKEY_EXPECT(!reader.value().Find(Str("other")).has_value());
  NILKEY_EXPECT(!reader.value().Find({}).has_value());

  auto rec = reader.value().Get(0);
  NILKEY_EXPECT(rec.ok());
  NILKEY_EXPECT(Is(rec.value().name, "caf\xC3\xA9"));
  NILKEY_EXPECT(Is(rec.value().username, "alice"));
  NILKEY_EXPECT_SECRET_EQ(rec.value().password, S(f.password));
  NILKEY_EXPECT(Is(rec.value().url, "https://example.org"));
  NILKEY_EXPECT(Is(rec.value().notes, "line one\nline two"));
  NILKEY_EXPECT(rec.value().created_at == 1700000000);
  NILKEY_EXPECT(rec.value().updated_at == 1700000000);

  auto missing = reader.value().Get(1);
  NILKEY_EXPECT(!missing.ok() && missing.error().code == ErrorCode::kOutOfRange);
}

NILKEY_TEST(add_appends_and_keeps_existing_records_byte_for_byte) {
  Vault vault = Vault::CreateEmpty(kRequire).value();
  NILKEY_EXPECT(vault.Add(F("first", "p1").View(), 10).ok());
  const Bytes before = Payload(vault);

  NILKEY_EXPECT(vault.Add(F("second", "p2").View(), 20).ok());
  const Bytes after = Payload(vault);
  NILKEY_EXPECT(vault.size() == 2);
  // Everything after the 4 byte count is the old payload, then the new record.
  NILKEY_EXPECT(after.size() > before.size());
  NILKEY_EXPECT(std::equal(before.begin() + 4, before.end(), after.begin() + 4));
  NILKEY_EXPECT(after[0] == std::byte{2});

  auto reader = vault.Open().value();
  NILKEY_EXPECT(reader.Find(Str("first")) == std::optional<std::size_t>(0));
  NILKEY_EXPECT(reader.Find(Str("second")) == std::optional<std::size_t>(1));
}

NILKEY_TEST(add_rejects_duplicate_name_and_changes_nothing) {
  Vault vault = Vault::CreateEmpty(kRequire).value();
  NILKEY_EXPECT(vault.Add(F("a", "p1").View(), 1).ok());
  const Bytes before = Payload(vault);

  NILKEY_EXPECT(Fails(vault.Add(F("a", "p2").View(), 2), ErrorCode::kAlreadyExists));
  NILKEY_EXPECT(vault.size() == 1);
  NILKEY_EXPECT(Payload(vault) == before);
}

NILKEY_TEST(add_rejects_invalid_input_and_changes_nothing) {
  Vault vault = Vault::CreateEmpty(kRequire).value();
  NILKEY_EXPECT(Fails(vault.Add(F("", "p").View(), 1), ErrorCode::kInvalidArgument));

  Fields bad_utf8 = F("a", "p");
  bad_utf8.notes = Raw({0xC3, 0x28});
  NILKEY_EXPECT(Fails(vault.Add(bad_utf8.View(), 1), ErrorCode::kInvalidArgument));

  NILKEY_EXPECT(vault.size() == 0);
  NILKEY_EXPECT(Payload(vault) == kEmptyPayload);
}

NILKEY_TEST(add_over_the_size_limit_is_rejected_before_allocating) {
  Vault vault = Vault::CreateEmpty(kRequire).value();
  // This record is 7 bytes under the limit on its own; with the 4 byte count
  // and its 4 byte length prefix the payload would be 1 byte over.
  Fields f = F("a", "");
  f.password = Bytes(nilkey::kMaxPlaintextSize - 44, std::byte{'x'});
  NILKEY_EXPECT(Fails(vault.Add(f.View(), 1), ErrorCode::kOutOfRange));
  NILKEY_EXPECT(vault.size() == 0);
  NILKEY_EXPECT(Payload(vault) == kEmptyPayload);
}

NILKEY_TEST(add_stops_at_the_record_limit) {
  // 100000 minimal records, names "00000".."99999". Only this test needs a
  // buffer of ~4.5 MiB, so it does not insist on locking it (a low
  // RLIMIT_MEMLOCK must not make it fail).
  std::vector<Bytes> records;
  records.reserve(nilkey::kMaxRecords);
  for (std::uint32_t i = 0; i < nilkey::kMaxRecords; ++i) {
    std::string name = std::to_string(i);
    name.insert(0, 5 - name.size(), '0');
    records.push_back(Rec(name, "", 1, 1));
  }
  const MemlockPolicy policy = MemlockPolicy::kAllowUnlocked;
  Vault vault = FromBytes(Env(records), policy);
  NILKEY_EXPECT(vault.size() == nilkey::kMaxRecords);
  NILKEY_EXPECT(Fails(vault.Add(F("extra", "p").View(), 2), ErrorCode::kOutOfRange));
  NILKEY_EXPECT(vault.size() == nilkey::kMaxRecords);
}

// ---- Update ----

NILKEY_TEST(update_replaces_fields_and_keeps_created_at_and_position) {
  Vault vault = Vault::CreateEmpty(kRequire).value();
  NILKEY_EXPECT(vault.Add(F("a", "old").View(), 100).ok());
  NILKEY_EXPECT(vault.Add(F("b", "pb").View(), 100).ok());
  const Bytes before = Payload(vault);

  Fields f = F("a", "new");
  f.username = Str("bob");
  NILKEY_EXPECT(vault.Update(Str("a"), f.View(), 200).ok());
  NILKEY_EXPECT(vault.size() == 2);

  {
    auto reader = vault.Open().value();
    auto rec = reader.Get(0);
    NILKEY_EXPECT(rec.ok());
    NILKEY_EXPECT(Is(rec.value().name, "a"));
    NILKEY_EXPECT(Is(rec.value().username, "bob"));
    NILKEY_EXPECT_SECRET_EQ(rec.value().password, S(Str("new")));
    NILKEY_EXPECT(rec.value().created_at == 100);
    NILKEY_EXPECT(rec.value().updated_at == 200);
  }
  // The record that was not touched is identical, byte for byte.
  NILKEY_EXPECT(RecordAt(Payload(vault), 1) == RecordAt(before, 1));
}

NILKEY_TEST(update_can_rename_but_not_onto_another_record) {
  Vault vault = Vault::CreateEmpty(kRequire).value();
  NILKEY_EXPECT(vault.Add(F("a", "pa").View(), 1).ok());
  NILKEY_EXPECT(vault.Add(F("b", "pb").View(), 1).ok());

  NILKEY_EXPECT(vault.Update(Str("a"), F("c", "pa").View(), 2).ok());
  {
    auto reader = vault.Open().value();
    NILKEY_EXPECT(!reader.Find(Str("a")).has_value());
    NILKEY_EXPECT(reader.Find(Str("c")) == std::optional<std::size_t>(0));
  }

  const Bytes before = Payload(vault);
  NILKEY_EXPECT(Fails(vault.Update(Str("c"), F("b", "pa").View(), 3), ErrorCode::kAlreadyExists));
  NILKEY_EXPECT(Payload(vault) == before);
}

NILKEY_TEST(update_and_remove_report_a_missing_record) {
  Vault vault = Vault::CreateEmpty(kRequire).value();
  NILKEY_EXPECT(vault.Add(F("a", "p").View(), 1).ok());
  const Bytes before = Payload(vault);

  NILKEY_EXPECT(Fails(vault.Update(Str("nope"), F("x", "p").View(), 2), ErrorCode::kNotFound));
  NILKEY_EXPECT(Fails(vault.Remove(Str("nope")), ErrorCode::kNotFound));
  NILKEY_EXPECT(Payload(vault) == before);
}

NILKEY_TEST(update_rejects_invalid_input_and_changes_nothing) {
  Vault vault = Vault::CreateEmpty(kRequire).value();
  NILKEY_EXPECT(vault.Add(F("a", "p").View(), 1).ok());
  const Bytes before = Payload(vault);

  NILKEY_EXPECT(Fails(vault.Update(Str("a"), F("", "p").View(), 2), ErrorCode::kInvalidArgument));
  NILKEY_EXPECT(Payload(vault) == before);
}

NILKEY_TEST(update_and_remove_keep_fields_of_unknown_type) {
  // Written by a newer version: record a has a field of type 0x7F, record b one
  // of type 0x08. This version does not know either.
  Bytes rec_a = Rec("a", "pa", 1, 2);
  Cat(rec_a, Fld(0x7F, Str("future")));
  Bytes rec_b = Rec("b", "pb", 3, 4);
  Cat(rec_b, Fld(0x08, Raw({1, 2, 3})));
  Vault vault = FromBytes(Env({rec_a, rec_b}));

  // Update: the new record keeps the unknown field; the other record is
  // copied unchanged.
  NILKEY_EXPECT(vault.Update(Str("a"), F("a2", "new").View(), 10).ok());
  Bytes payload = Payload(vault);
  NILKEY_EXPECT(HasField(RecordAt(payload, 0), 0x7F, Str("future")));
  NILKEY_EXPECT(RecordAt(payload, 1) == rec_b);
  {
    auto reader = vault.Open().value();
    auto rec = reader.Get(0);
    NILKEY_EXPECT(rec.ok());
    NILKEY_EXPECT(Is(rec.value().name, "a2"));
    NILKEY_EXPECT(rec.value().created_at == 1);
    NILKEY_EXPECT(rec.value().updated_at == 10);
  }

  // Remove the other record: what is left still has its unknown field.
  NILKEY_EXPECT(vault.Remove(Str("b")).ok());
  payload = Payload(vault);
  NILKEY_EXPECT(vault.size() == 1);
  NILKEY_EXPECT(HasField(RecordAt(payload, 0), 0x7F, Str("future")));
}

NILKEY_TEST(update_that_would_exceed_the_field_limit_is_rejected) {
  // 4 required fields + 60 unknown ones = 64, the limit.
  Bytes rec = Rec("a", "pw", 1, 2);
  for (unsigned t = 0x10; t < 0x10 + 60; ++t) Cat(rec, Fld(t, {}));
  const Bytes payload = Env({rec});

  Vault vault = FromBytes(payload);
  Fields more = F("a", "pw2");
  more.username = Str("u");
  more.url = Str("x");
  more.notes = Str("n");  // 7 known + 60 unknown = 67: written, but would not parse back
  NILKEY_EXPECT(Fails(vault.Update(Str("a"), more.View(), 5), ErrorCode::kOutOfRange));
  NILKEY_EXPECT(Payload(vault) == payload);

  // Without the optional fields it is exactly 64 and works.
  NILKEY_EXPECT(vault.Update(Str("a"), F("a", "pw2").View(), 5).ok());
  NILKEY_EXPECT(HasField(RecordAt(Payload(vault), 0), 0x10, {}));
}

// ---- Patch ----

namespace {

// A patch that sets one field, given by its TLV type.
RecordPatch Only(unsigned type, const Bytes& value) {
  RecordPatch patch;
  const std::span<const std::byte> view(value);
  if (type == 0x01) patch.name = view;
  if (type == 0x02) patch.username = view;
  if (type == 0x03) patch.password = view;
  if (type == 0x04) patch.url = view;
  if (type == 0x05) patch.notes = view;
  return patch;
}

Vault FullRecordVault() {
  Vault vault = Vault::CreateEmpty(kRequire).value();
  Fields a = F("a", "pa");
  a.username = Str("alice");
  a.url = Str("https://a.example");
  a.notes = Str("note a");
  // Setup: a failure here is a broken test, not a result.
  if (!vault.Add(a.View(), 100).ok() || !vault.Add(F("b", "pb").View(), 100).ok()) std::abort();
  return vault;
}

}  // namespace

NILKEY_TEST(patch_changes_only_the_fields_that_are_set) {
  Vault vault = FullRecordVault();
  const Bytes before = Payload(vault);

  const Bytes password = Str("new password");
  NILKEY_EXPECT(vault.Patch(Str("a"), Only(0x03, password), 200).ok());

  {
    auto reader = vault.Open().value();
    auto rec = reader.Get(0);
    NILKEY_EXPECT(rec.ok());
    NILKEY_EXPECT(Is(rec.value().name, "a"));
    NILKEY_EXPECT(Is(rec.value().username, "alice"));
    NILKEY_EXPECT(Is(rec.value().url, "https://a.example"));
    NILKEY_EXPECT(Is(rec.value().notes, "note a"));
    NILKEY_EXPECT_SECRET_EQ(rec.value().password, S(password));
    NILKEY_EXPECT(rec.value().created_at == 100);
    NILKEY_EXPECT(rec.value().updated_at == 200);
  }
  // The other record is copied unchanged.
  NILKEY_EXPECT(RecordAt(Payload(vault), 1) == RecordAt(before, 1));
}

NILKEY_TEST(patch_keeps_each_untouched_field_whichever_one_is_set) {
  for (const unsigned type : {0x02U, 0x03U, 0x04U, 0x05U}) {
    Vault vault = FullRecordVault();
    const Bytes value = Str("changed");
    NILKEY_EXPECT(vault.Patch(Str("a"), Only(type, value), 200).ok());

    auto reader = vault.Open().value();
    auto rec = reader.Get(0);
    NILKEY_EXPECT(rec.ok());
    NILKEY_EXPECT(Is(rec.value().username, type == 0x02 ? "changed" : "alice"));
    NILKEY_EXPECT(Is(rec.value().password, type == 0x03 ? "changed" : "pa"));
    NILKEY_EXPECT(Is(rec.value().url, type == 0x04 ? "changed" : "https://a.example"));
    NILKEY_EXPECT(Is(rec.value().notes, type == 0x05 ? "changed" : "note a"));
  }
}

NILKEY_TEST(patch_with_an_empty_value_clears_an_optional_field) {
  Vault vault = FullRecordVault();
  NILKEY_EXPECT(vault.Patch(Str("a"), Only(0x02, {}), 200).ok());
  NILKEY_EXPECT(vault.Patch(Str("a"), Only(0x05, {}), 201).ok());

  auto reader = vault.Open().value();
  auto rec = reader.Get(0);
  NILKEY_EXPECT(rec.ok());
  NILKEY_EXPECT(rec.value().username.empty());
  NILKEY_EXPECT(rec.value().notes.empty());
  NILKEY_EXPECT(Is(rec.value().url, "https://a.example"));
  NILKEY_EXPECT(Is(rec.value().password, "pa"));
}

NILKEY_TEST(a_patch_that_sets_nothing_only_moves_updated_at) {
  Vault vault = FullRecordVault();
  NILKEY_EXPECT(vault.Patch(Str("a"), RecordPatch{}, 300).ok());

  auto reader = vault.Open().value();
  auto rec = reader.Get(0);
  NILKEY_EXPECT(rec.ok());
  NILKEY_EXPECT(Is(rec.value().username, "alice"));
  NILKEY_EXPECT(Is(rec.value().password, "pa"));
  NILKEY_EXPECT(rec.value().created_at == 100);
  NILKEY_EXPECT(rec.value().updated_at == 300);
}

NILKEY_TEST(patch_can_rename_keeping_the_other_fields_but_not_onto_another_record) {
  Vault vault = FullRecordVault();

  NILKEY_EXPECT(vault.Patch(Str("a"), Only(0x01, Str("a2")), 200).ok());
  {
    auto reader = vault.Open().value();
    NILKEY_EXPECT(!reader.Find(Str("a")).has_value());
    NILKEY_EXPECT(reader.Find(Str("a2")) == std::optional<std::size_t>(0));
    NILKEY_EXPECT(Is(reader.Get(0).value().username, "alice"));
  }
  // Naming it what it already is does not collide with itself.
  NILKEY_EXPECT(vault.Patch(Str("a2"), Only(0x01, Str("a2")), 201).ok());

  const Bytes before = Payload(vault);
  NILKEY_EXPECT(Fails(vault.Patch(Str("a2"), Only(0x01, Str("b")), 202),
                      ErrorCode::kAlreadyExists));
  NILKEY_EXPECT(Fails(vault.Patch(Str("a2"), Only(0x01, {}), 202), ErrorCode::kInvalidArgument));
  NILKEY_EXPECT(Payload(vault) == before);
}

NILKEY_TEST(patch_reports_a_missing_record_and_respects_an_open_reader) {
  Vault vault = FullRecordVault();
  const Bytes before = Payload(vault);
  NILKEY_EXPECT(Fails(vault.Patch(Str("nope"), Only(0x03, Str("x")), 2), ErrorCode::kNotFound));
  {
    auto reader = vault.Open();
    NILKEY_EXPECT(reader.ok());
    NILKEY_EXPECT(Fails(vault.Patch(Str("a"), Only(0x03, Str("x")), 2),
                        ErrorCode::kInvalidArgument));
  }
  NILKEY_EXPECT(Payload(vault) == before);
}

NILKEY_TEST(patch_keeps_fields_of_unknown_type) {
  Bytes rec_a = Rec("a", "pa", 1, 2);
  Cat(rec_a, Fld(0x7F, Str("future")));
  Vault vault = FromBytes(Env({rec_a}));

  NILKEY_EXPECT(vault.Patch(Str("a"), Only(0x03, Str("new")), 10).ok());
  const Bytes payload = Payload(vault);
  NILKEY_EXPECT(HasField(RecordAt(payload, 0), 0x7F, Str("future")));
  NILKEY_EXPECT(HasField(RecordAt(payload, 0), 0x03, Str("new")));
}

// ---- Remove ----

NILKEY_TEST(remove_deletes_one_record_and_keeps_the_order) {
  Vault vault = Vault::CreateEmpty(kRequire).value();
  NILKEY_EXPECT(vault.Add(F("a", "pa").View(), 1).ok());
  NILKEY_EXPECT(vault.Add(F("b", "pb").View(), 1).ok());
  NILKEY_EXPECT(vault.Add(F("c", "pc").View(), 1).ok());
  const Bytes before = Payload(vault);

  NILKEY_EXPECT(vault.Remove(Str("b")).ok());
  NILKEY_EXPECT(vault.size() == 2);
  const Bytes after = Payload(vault);
  NILKEY_EXPECT(RecordAt(after, 0) == RecordAt(before, 0));
  NILKEY_EXPECT(RecordAt(after, 1) == RecordAt(before, 2));
  {
    auto reader = vault.Open().value();
    NILKEY_EXPECT(!reader.Find(Str("b")).has_value());
    NILKEY_EXPECT(reader.Find(Str("c")) == std::optional<std::size_t>(1));
  }

  NILKEY_EXPECT(vault.Remove(Str("a")).ok());
  NILKEY_EXPECT(vault.Remove(Str("c")).ok());
  NILKEY_EXPECT(vault.size() == 0);
  NILKEY_EXPECT(Payload(vault) == kEmptyPayload);
}

// ---- Reader guard ----

NILKEY_TEST(an_open_reader_blocks_changes_without_damaging_the_vault) {
  Vault vault = Vault::CreateEmpty(kRequire).value();
  NILKEY_EXPECT(vault.Add(F("a", "pa").View(), 1).ok());
  const Bytes before = Payload(vault);

  {
    auto reader = vault.Open();
    NILKEY_EXPECT(reader.ok());
    auto second = vault.Open();
    NILKEY_EXPECT(!second.ok() && second.error().code == ErrorCode::kInvalidArgument);
    NILKEY_EXPECT(Fails(vault.Add(F("b", "p").View(), 2), ErrorCode::kInvalidArgument));
    NILKEY_EXPECT(Fails(vault.Update(Str("a"), F("a", "q").View(), 2), ErrorCode::kInvalidArgument));
    NILKEY_EXPECT(Fails(vault.Remove(Str("a")), ErrorCode::kInvalidArgument));
    // The reader still sees the unchanged data.
    NILKEY_EXPECT(Is(reader.value().Get(0).value().name, "a"));
  }

  NILKEY_EXPECT(Payload(vault) == before);
  NILKEY_EXPECT(vault.Add(F("b", "p").View(), 2).ok());
}

// ---- With the crypto layer ----

NILKEY_TEST(vault_survives_seal_and_open_with_password) {
  const Bytes password = Raw({'m', 'a', 0x00, 's', 't', 'e', 'r', 0xC3, 0xA9});

  Vault vault = Vault::CreateEmpty(kRequire).value();
  Fields a = F("a", "");
  a.password = Raw({'p', 0x00, 'q', 0xF0, 0x9F, 0x94, 0x91});
  a.username = Str("alice");
  NILKEY_EXPECT(vault.Add(a.View(), 1700000000).ok());
  NILKEY_EXPECT(vault.Add(F("b", "pb").View(), 1700000001).ok());

  auto key = nilkey::NewVaultKey(S(password), kFast, kRequire);
  NILKEY_EXPECT(key.ok());

  Bytes file_one;
  Bytes file_two;
  {
    auto reader = vault.Open().value();
    auto sealed_one = Seal(key.value(), reader.payload());
    auto sealed_two = Seal(key.value(), reader.payload());
    NILKEY_EXPECT(sealed_one.ok() && sealed_two.ok());
    file_one = sealed_one.value();
    file_two = sealed_two.value();
  }
  // Sealing the same payload twice gives a fresh nonce (header bytes 38..61).
  NILKEY_EXPECT(!std::equal(file_one.begin() + 38, file_one.begin() + 62, file_two.begin() + 38));

  auto opened = OpenWithPassword(S(file_one), S(password), kRequire);
  NILKEY_EXPECT(opened.ok());
  auto reloaded = Vault::FromPlaintext(std::move(opened.value().plaintext), kRequire);
  NILKEY_EXPECT(reloaded.ok());
  NILKEY_EXPECT(reloaded.value().size() == 2);
  NILKEY_EXPECT(Payload(reloaded.value()) == Payload(vault));

  auto reader = reloaded.value().Open().value();
  auto rec = reader.Get(0);
  NILKEY_EXPECT(rec.ok());
  NILKEY_EXPECT_SECRET_EQ(rec.value().password, S(a.password));
  NILKEY_EXPECT(Is(rec.value().username, "alice"));
}

NILKEY_TEST_MAIN()

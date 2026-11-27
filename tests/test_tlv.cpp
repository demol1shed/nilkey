// TLV envelope parser and writer (SPEC.md 6, test matrix item 6). The inputs
// are written out by hand from the SPEC.md 6 tables, not by the code under
// test, so the encoding itself is checked.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "nilkey/tlv.hpp"
#include "test_framework.hpp"

using nilkey::ErrorCode;
using nilkey::IsValidUtf8;
using nilkey::ParseEnvelope;
using nilkey::ParseRecord;
using nilkey::Record;
using nilkey::RecordSize;
using nilkey::TlvWriter;
using nilkey::WriteRecord;

namespace {

using Bytes = std::vector<std::byte>;

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

// One field: type, 4 byte little-endian length, value.
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

// A valid record: name, password, created_at = 1, updated_at = 2.
Bytes Rec(std::string_view name, std::string_view password) {
  Bytes b = Fld(0x01, Str(name));
  Cat(b, Fld(0x03, Str(password)));
  Cat(b, Ts(0x06, 1));
  Cat(b, Ts(0x07, 2));
  return b;
}

// Envelope: record_count, then each record behind its length.
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

bool RecordRejected(const Bytes& record) {
  auto r = ParseRecord(S(record));
  return !r.ok() && r.error().code == ErrorCode::kInvalidFormat;
}

bool EnvelopeRejected(const Bytes& envelope) {
  auto r = ParseEnvelope(S(envelope));
  return !r.ok() && r.error().code == ErrorCode::kInvalidFormat;
}

bool Utf8(std::initializer_list<unsigned> v) { return IsValidUtf8(S(Raw(v))); }

// The golden record: name "ab", username "u", password "p\0q", no url,
// notes "n", created_at -1, updated_at 0x1122334455667788.
Bytes GoldenRecord() {
  return Raw({0x01, 0x02, 0x00, 0x00, 0x00, 0x61, 0x62,                // name
              0x02, 0x01, 0x00, 0x00, 0x00, 0x75,                      // username
              0x03, 0x03, 0x00, 0x00, 0x00, 0x70, 0x00, 0x71,          // password
              0x05, 0x01, 0x00, 0x00, 0x00, 0x6E,                      // notes
              0x06, 0x08, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,    // created_at
              0xFF, 0xFF, 0xFF, 0xFF,                                  //
              0x07, 0x08, 0x00, 0x00, 0x00, 0x88, 0x77, 0x66, 0x55,    // updated_at
              0x44, 0x33, 0x22, 0x11});
}

Record GoldenFields(const Bytes& name, const Bytes& username, const Bytes& password,
                    const Bytes& notes) {
  Record r{};
  r.name = name;
  r.username = username;
  r.password = password;
  r.notes = notes;
  r.created_at = -1;
  r.updated_at = 0x1122334455667788;
  return r;
}

}  // namespace

// ---- UTF-8 ----

NILKEY_TEST(utf8_accepts_valid_text) {
  NILKEY_EXPECT(IsValidUtf8({}));
  NILKEY_EXPECT(Utf8({0x41}));                    // ASCII
  NILKEY_EXPECT(Utf8({0x00}));                    // NUL is valid UTF-8
  NILKEY_EXPECT(Utf8({0xC3, 0xA9}));              // U+00E9
  NILKEY_EXPECT(Utf8({0xE2, 0x82, 0xAC}));        // U+20AC
  NILKEY_EXPECT(Utf8({0xF0, 0x9F, 0x94, 0x91}));  // U+1F511
  NILKEY_EXPECT(Utf8({0xED, 0x9F, 0xBF}));        // U+D7FF, last before surrogates
  NILKEY_EXPECT(Utf8({0xEE, 0x80, 0x80}));        // U+E000, first after surrogates
  NILKEY_EXPECT(Utf8({0xF4, 0x8F, 0xBF, 0xBF}));  // U+10FFFF, the maximum
}

NILKEY_TEST(utf8_rejects_malformed_text) {
  NILKEY_EXPECT(!Utf8({0x80}));                    // lone continuation byte
  NILKEY_EXPECT(!Utf8({0xC0, 0x80}));              // overlong NUL
  NILKEY_EXPECT(!Utf8({0xC1, 0xBF}));              // overlong
  NILKEY_EXPECT(!Utf8({0xE0, 0x80, 0x80}));        // overlong 3 byte
  NILKEY_EXPECT(!Utf8({0xE0, 0x9F, 0xBF}));        // overlong 3 byte
  NILKEY_EXPECT(!Utf8({0xED, 0xA0, 0x80}));        // surrogate U+D800
  NILKEY_EXPECT(!Utf8({0xF0, 0x80, 0x80, 0x80}));  // overlong 4 byte
  NILKEY_EXPECT(!Utf8({0xF4, 0x90, 0x80, 0x80}));  // above U+10FFFF
  NILKEY_EXPECT(!Utf8({0xF5, 0x80, 0x80, 0x80}));  // invalid lead byte
  NILKEY_EXPECT(!Utf8({0xFF}));
  NILKEY_EXPECT(!Utf8({0xC3}));                    // truncated
  NILKEY_EXPECT(!Utf8({0xE2, 0x82}));              // truncated
  NILKEY_EXPECT(!Utf8({0xF0, 0x9F, 0x94}));        // truncated
  NILKEY_EXPECT(!Utf8({0xC3, 0x41}));              // bad continuation byte
  NILKEY_EXPECT(!Utf8({0xE2, 0x82, 0x41}));        // bad continuation byte
  NILKEY_EXPECT(!Utf8({0x41, 0xFF, 0x41}));        // bad byte in the middle
}

// ---- ParseRecord ----

NILKEY_TEST(parse_record_matches_golden_bytes) {
  const Bytes golden = GoldenRecord();
  auto r = ParseRecord(S(golden));
  NILKEY_EXPECT(r.ok());
  const Record& rec = r.value();
  NILKEY_EXPECT(Is(rec.name, "ab"));
  NILKEY_EXPECT(Is(rec.username, "u"));
  NILKEY_EXPECT_SECRET_EQ(rec.password, S(Raw({0x70, 0x00, 0x71})));  // "p\0q"
  NILKEY_EXPECT(rec.url.empty());
  NILKEY_EXPECT(Is(rec.notes, "n"));
  NILKEY_EXPECT(rec.created_at == -1);
  NILKEY_EXPECT(rec.updated_at == 0x1122334455667788);
}

NILKEY_TEST(parse_record_accepts_empty_password) {
  Bytes b = Fld(0x01, Str("a"));
  Cat(b, Fld(0x03, {}));
  Cat(b, Ts(0x06, 1));
  Cat(b, Ts(0x07, 2));
  auto r = ParseRecord(S(b));
  NILKEY_EXPECT(r.ok());
  NILKEY_EXPECT(r.value().password.empty());
}

NILKEY_TEST(parse_record_skips_unknown_types) {
  // Unknown types in front, in the middle and at the end, in any order.
  Bytes b = Fld(0x7F, Str("future"));
  Cat(b, Fld(0x01, Str("a")));
  Cat(b, Fld(0x08, Raw({1, 2, 3})));
  Cat(b, Fld(0x03, Str("pw")));
  Cat(b, Ts(0x06, 1));
  Cat(b, Fld(0x00, {}));
  Cat(b, Ts(0x07, 2));
  Cat(b, Fld(0xFF, Str("x")));
  auto r = ParseRecord(S(b));
  NILKEY_EXPECT(r.ok());
  NILKEY_EXPECT(Is(r.value().name, "a"));
  NILKEY_EXPECT(r.value().created_at == 1);
  NILKEY_EXPECT(r.value().updated_at == 2);
}

NILKEY_TEST(parse_record_rejects_repeated_field_types) {
  Bytes known = Rec("a", "pw");
  Cat(known, Fld(0x02, Str("u1")));
  Cat(known, Fld(0x02, Str("u2")));
  NILKEY_EXPECT(RecordRejected(known));

  Bytes unknown = Rec("a", "pw");
  Cat(unknown, Fld(0x7F, Str("x")));
  Cat(unknown, Fld(0x7F, Str("y")));
  NILKEY_EXPECT(RecordRejected(unknown));

  Bytes name_twice = Rec("a", "pw");
  Cat(name_twice, Fld(0x01, Str("b")));
  NILKEY_EXPECT(RecordRejected(name_twice));
}

NILKEY_TEST(parse_record_requires_name_password_and_timestamps) {
  Bytes no_name = Fld(0x03, Str("pw"));
  Cat(no_name, Ts(0x06, 1));
  Cat(no_name, Ts(0x07, 2));
  NILKEY_EXPECT(RecordRejected(no_name));

  Bytes no_password = Fld(0x01, Str("a"));
  Cat(no_password, Ts(0x06, 1));
  Cat(no_password, Ts(0x07, 2));
  NILKEY_EXPECT(RecordRejected(no_password));

  Bytes no_created = Fld(0x01, Str("a"));
  Cat(no_created, Fld(0x03, Str("pw")));
  Cat(no_created, Ts(0x07, 2));
  NILKEY_EXPECT(RecordRejected(no_created));

  Bytes no_updated = Fld(0x01, Str("a"));
  Cat(no_updated, Fld(0x03, Str("pw")));
  Cat(no_updated, Ts(0x06, 1));
  NILKEY_EXPECT(RecordRejected(no_updated));

  NILKEY_EXPECT(RecordRejected({}));  // an empty record has none of them
}

NILKEY_TEST(parse_record_enforces_name_rules) {
  Bytes empty_name = Fld(0x01, {});
  Cat(empty_name, Fld(0x03, Str("pw")));
  Cat(empty_name, Ts(0x06, 1));
  Cat(empty_name, Ts(0x07, 2));
  NILKEY_EXPECT(RecordRejected(empty_name));

  NILKEY_EXPECT(ParseRecord(S(Rec(std::string(nilkey::kMaxNameSize, 'n'), "pw"))).ok());
  NILKEY_EXPECT(RecordRejected(Rec(std::string(nilkey::kMaxNameSize + 1, 'n'), "pw")));
}

NILKEY_TEST(parse_record_rejects_bad_timestamp_length) {
  for (std::size_t len : {std::size_t{0}, std::size_t{7}, std::size_t{9}}) {
    Bytes b = Fld(0x01, Str("a"));
    Cat(b, Fld(0x03, Str("pw")));
    Cat(b, Fld(0x06, Bytes(len, std::byte{1})));
    Cat(b, Ts(0x07, 2));
    NILKEY_EXPECT(RecordRejected(b));
  }
}

NILKEY_TEST(parse_record_rejects_bad_field_lengths) {
  // Length runs past the end of the record.
  Bytes past_end = Rec("a", "pw");
  Cat(past_end, Raw({0x7F, 0x05, 0x00, 0x00, 0x00, 0x01}));
  NILKEY_EXPECT(RecordRejected(past_end));

  // Length 0xFFFFFFFF: adding it to an offset would wrap a 32 bit counter.
  Bytes huge = Rec("a", "pw");
  Cat(huge, Raw({0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0x01}));
  NILKEY_EXPECT(RecordRejected(huge));

  // Truncated field header: 1 to 4 trailing bytes.
  for (std::size_t n = 1; n <= 4; ++n) {
    Bytes b = Rec("a", "pw");
    b.insert(b.end(), n, std::byte{0x7F});
    NILKEY_EXPECT(RecordRejected(b));
  }
}

NILKEY_TEST(parse_record_limits_field_count) {
  // 4 required fields plus 60 unknown ones is exactly 64.
  Bytes at_limit = Rec("a", "pw");
  for (unsigned t = 0x10; t < 0x10 + 60; ++t) Cat(at_limit, Fld(t, {}));
  NILKEY_EXPECT(ParseRecord(S(at_limit)).ok());

  Bytes over = at_limit;
  Cat(over, Fld(0x10 + 60, {}));
  NILKEY_EXPECT(RecordRejected(over));
}

NILKEY_TEST(parse_record_rejects_invalid_utf8_in_text_fields) {
  for (unsigned type : {0x01U, 0x02U, 0x04U, 0x05U}) {
    Bytes b = Rec("a", "pw");
    // Replace/add the text field with an invalid sequence. For the name,
    // build the record without the valid one.
    if (type == 0x01) {
      b = Fld(0x01, Raw({0xC3, 0x28}));
      Cat(b, Fld(0x03, Str("pw")));
      Cat(b, Ts(0x06, 1));
      Cat(b, Ts(0x07, 2));
    } else {
      Cat(b, Fld(type, Raw({0xC3, 0x28})));
    }
    NILKEY_EXPECT(RecordRejected(b));
  }
}

NILKEY_TEST(parse_record_leaves_password_as_raw_bytes) {
  Bytes b = Fld(0x01, Str("a"));
  Cat(b, Fld(0x03, Raw({0xFF, 0xFE, 0x00, 0xC3})));  // not valid UTF-8
  Cat(b, Ts(0x06, 1));
  Cat(b, Ts(0x07, 2));
  auto r = ParseRecord(S(b));
  NILKEY_EXPECT(r.ok());
  NILKEY_EXPECT_SECRET_EQ(r.value().password, S(Raw({0xFF, 0xFE, 0x00, 0xC3})));
}

// ---- ParseEnvelope ----

NILKEY_TEST(parse_envelope_accepts_empty_vault) {
  auto r = ParseEnvelope(S(Raw({0, 0, 0, 0})));
  NILKEY_EXPECT(r.ok());
  NILKEY_EXPECT(r.value().empty());
}

NILKEY_TEST(parse_envelope_locates_each_record) {
  const Bytes first = Rec("one", "p1");
  const Bytes second = GoldenRecord();
  const Bytes env = Env({first, second});

  auto r = ParseEnvelope(S(env));
  NILKEY_EXPECT(r.ok());
  const auto& loc = r.value();
  NILKEY_EXPECT(loc.size() == 2);
  NILKEY_EXPECT(loc[0].offset == 8);  // count (4) + first record_len (4)
  NILKEY_EXPECT(loc[0].length == first.size());
  NILKEY_EXPECT(loc[1].offset == 8 + first.size() + 4);
  NILKEY_EXPECT(loc[1].length == second.size());

  auto rec = ParseRecord(S(env).subspan(loc[1].offset, loc[1].length));
  NILKEY_EXPECT(rec.ok());
  NILKEY_EXPECT(Is(rec.value().name, "ab"));
}

NILKEY_TEST(parse_envelope_rejects_bad_framing) {
  NILKEY_EXPECT(EnvelopeRejected({}));
  NILKEY_EXPECT(EnvelopeRejected(Raw({0, 0, 0})));  // shorter than the count

  // Count says 2, only one record present.
  Bytes short_count = Env({Rec("a", "p")});
  short_count[0] = std::byte{2};
  NILKEY_EXPECT(EnvelopeRejected(short_count));

  // Count says 1, but 2 records follow: trailing bytes.
  Bytes trailing_record = Env({Rec("a", "p"), Rec("b", "p")});
  trailing_record[0] = std::byte{1};
  NILKEY_EXPECT(EnvelopeRejected(trailing_record));

  // Trailing garbage after the last record.
  Bytes trailing = Env({Rec("a", "p")});
  trailing.push_back(std::byte{0});
  NILKEY_EXPECT(EnvelopeRejected(trailing));

  // record_len longer than the remaining bytes, and the 0xFFFFFFFF wrap case.
  Bytes long_len = Env({Rec("a", "p")});
  long_len[4] = static_cast<std::byte>(static_cast<std::uint8_t>(long_len[4]) + 1);
  NILKEY_EXPECT(EnvelopeRejected(long_len));
  Bytes max_len = Env({Rec("a", "p")});
  for (std::size_t i = 4; i < 8; ++i) max_len[i] = std::byte{0xFF};
  NILKEY_EXPECT(EnvelopeRejected(max_len));

  // A record_len prefix cut short.
  Bytes cut = Raw({1, 0, 0, 0, 5, 0});
  NILKEY_EXPECT(EnvelopeRejected(cut));

  // A zero length record has no name.
  NILKEY_EXPECT(EnvelopeRejected(Raw({1, 0, 0, 0, 0, 0, 0, 0})));
}

NILKEY_TEST(parse_envelope_rejects_oversized_record_count) {
  // Rejected from the count alone, before anything is reserved.
  NILKEY_EXPECT(EnvelopeRejected(Raw({0xFF, 0xFF, 0xFF, 0xFF})));
  NILKEY_EXPECT(EnvelopeRejected(Raw({0xA1, 0x86, 0x01, 0x00})));  // 100001
  // Within kMaxRecords but far more records than the bytes could hold.
  NILKEY_EXPECT(EnvelopeRejected(Raw({0xA0, 0x86, 0x01, 0x00, 0, 0, 0, 0})));  // 100000
}

NILKEY_TEST(parse_envelope_stops_at_the_record_limit) {
  // Real records, so that only the limit itself can reject the larger envelope.
  std::vector<Bytes> records;
  records.reserve(nilkey::kMaxRecords + 1);
  for (std::uint32_t i = 0; i < nilkey::kMaxRecords; ++i) {
    records.push_back(Rec(std::to_string(i), ""));
  }
  NILKEY_EXPECT(ParseEnvelope(S(Env(records))).ok());

  records.push_back(Rec("extra", ""));
  NILKEY_EXPECT(EnvelopeRejected(Env(records)));
}

NILKEY_TEST(parse_envelope_rejects_duplicate_names) {
  NILKEY_EXPECT(EnvelopeRejected(Env({Rec("a", "p1"), Rec("a", "p2")})));
  // Not adjacent in file order.
  NILKEY_EXPECT(EnvelopeRejected(Env({Rec("a", "p"), Rec("b", "p"), Rec("a", "p")})));
}

NILKEY_TEST(parse_envelope_compares_names_byte_for_byte) {
  // Case differs, a prefix of another name, and NFC vs NFD "é": all distinct.
  const Bytes env = Env({Rec("a", "p"), Rec("A", "p"), Rec("ab", "p"),
                         Rec("\xC3\xA9", "p"), Rec("e\xCC\x81", "p")});
  auto r = ParseEnvelope(S(env));
  NILKEY_EXPECT(r.ok());
  NILKEY_EXPECT(r.value().size() == 5);
}

// ---- TlvWriter / WriteRecord ----

NILKEY_TEST(write_record_matches_golden_bytes) {
  const Bytes name = Str("ab");
  const Bytes username = Str("u");
  const Bytes password = Raw({0x70, 0x00, 0x71});
  const Bytes notes = Str("n");
  const Record rec = GoldenFields(name, username, password, notes);

  const Bytes expected = GoldenRecord();
  auto size = RecordSize(rec);
  NILKEY_EXPECT(size.ok());
  NILKEY_EXPECT(size.value() == expected.size());

  Bytes out(size.value());
  TlvWriter writer(out);
  NILKEY_EXPECT(WriteRecord(writer, rec).ok());
  NILKEY_EXPECT(writer.written() == out.size());
  NILKEY_EXPECT(out == expected);
}

NILKEY_TEST(write_record_round_trips_utf8_and_nul_password) {
  // Password "pa\0ss é" + emoji, with an embedded NUL, and a UTF-8 name.
  const Bytes name = Str("caf\xC3\xA9 \xF0\x9F\x94\x91");
  const Bytes password = Raw({'p', 'a', 0x00, 's', 's', ' ', 0xC3, 0xA9, ' ', 0xF0, 0x9F, 0x94, 0x91});
  Record rec{};
  rec.name = name;
  rec.password = password;
  rec.created_at = 1700000000;
  rec.updated_at = 1700000001;

  Bytes out(RecordSize(rec).value());
  TlvWriter writer(out);
  NILKEY_EXPECT(WriteRecord(writer, rec).ok());

  auto parsed = ParseRecord(S(out));
  NILKEY_EXPECT(parsed.ok());
  NILKEY_EXPECT_SECRET_EQ(parsed.value().password, S(password));
  NILKEY_EXPECT(std::equal(parsed.value().name.begin(), parsed.value().name.end(), name.begin(),
                           name.end()));
  NILKEY_EXPECT(parsed.value().created_at == 1700000000);
  NILKEY_EXPECT(parsed.value().updated_at == 1700000001);
}

NILKEY_TEST(write_record_omits_empty_optional_fields) {
  const Bytes name = Str("a");
  Record rec{};
  rec.name = name;
  rec.created_at = 0;
  rec.updated_at = 0;

  Bytes out(RecordSize(rec).value());
  TlvWriter writer(out);
  NILKEY_EXPECT(WriteRecord(writer, rec).ok());
  // name (6) + empty password (5) + two timestamps (26): no username/url/notes.
  NILKEY_EXPECT(out.size() == 6 + 5 + 26);
  auto parsed = ParseRecord(S(out));
  NILKEY_EXPECT(parsed.ok());
  NILKEY_EXPECT(parsed.value().username.empty());
  NILKEY_EXPECT(parsed.value().url.empty());
  NILKEY_EXPECT(parsed.value().notes.empty());
}

NILKEY_TEST(write_record_never_writes_past_the_buffer) {
  const Bytes name = Str("ab");
  const Bytes username = Str("u");
  const Bytes password = Raw({0x70, 0x00, 0x71});
  const Bytes notes = Str("n");
  const Record rec = GoldenFields(name, username, password, notes);
  const std::size_t size = RecordSize(rec).value();

  // One byte too small fails cleanly; the guard bytes after the buffer stay.
  Bytes guarded(size + 8, std::byte{0xAA});
  TlvWriter small(std::span<std::byte>(guarded).first(size - 1));
  auto r = WriteRecord(small, rec);
  NILKEY_EXPECT(!r.ok());
  NILKEY_EXPECT(r.error().code == ErrorCode::kOutOfRange);
  for (std::size_t i = size - 1; i < guarded.size(); ++i) {
    NILKEY_EXPECT(guarded[i] == std::byte{0xAA});
  }

  Bytes exact(size);
  TlvWriter fits(exact);
  NILKEY_EXPECT(WriteRecord(fits, rec).ok());
}

NILKEY_TEST(write_record_rejects_invalid_records) {
  Bytes out(256);
  const Bytes empty;
  const Bytes name = Str("a");
  const Bytes bad_utf8 = Raw({0xC3, 0x28});

  Record no_name{};
  no_name.name = empty;
  TlvWriter w1(out);
  auto r1 = WriteRecord(w1, no_name);
  NILKEY_EXPECT(!r1.ok() && r1.error().code == ErrorCode::kInvalidArgument);
  NILKEY_EXPECT(!RecordSize(no_name).ok());

  Record bad_user{};
  bad_user.name = name;
  bad_user.username = bad_utf8;
  TlvWriter w2(out);
  auto r2 = WriteRecord(w2, bad_user);
  NILKEY_EXPECT(!r2.ok() && r2.error().code == ErrorCode::kInvalidArgument);

  const Bytes long_name(nilkey::kMaxNameSize + 1, std::byte{'n'});
  Record too_long{};
  too_long.name = long_name;
  TlvWriter w3(out);
  auto r3 = WriteRecord(w3, too_long);
  NILKEY_EXPECT(!r3.ok() && r3.error().code == ErrorCode::kOutOfRange);
}

NILKEY_TEST(writer_put_u32_is_little_endian_and_bounded) {
  Bytes out(4);
  TlvWriter writer(out);
  NILKEY_EXPECT(writer.PutU32(0x01020304).ok());
  NILKEY_EXPECT(out == Raw({0x04, 0x03, 0x02, 0x01}));
  auto full = writer.PutU32(1);
  NILKEY_EXPECT(!full.ok() && full.error().code == ErrorCode::kOutOfRange);
  NILKEY_EXPECT(writer.written() == 4);
}

NILKEY_TEST(writer_put_raw_appends_verbatim_and_is_bounded) {
  Bytes guarded(8, std::byte{0xAA});
  TlvWriter writer(std::span<std::byte>(guarded).first(5));
  NILKEY_EXPECT(writer.PutRaw(S(Raw({1, 2, 3}))).ok());
  NILKEY_EXPECT(writer.PutRaw({}).ok());  // nothing to append is fine
  NILKEY_EXPECT(writer.written() == 3);

  auto too_big = writer.PutRaw(S(Raw({4, 5, 6})));  // 2 bytes left
  NILKEY_EXPECT(!too_big.ok() && too_big.error().code == ErrorCode::kOutOfRange);
  NILKEY_EXPECT(writer.written() == 3);

  NILKEY_EXPECT(writer.PutRaw(S(Raw({4, 5}))).ok());
  NILKEY_EXPECT(guarded == Raw({1, 2, 3, 4, 5, 0xAA, 0xAA, 0xAA}));  // nothing past 5
}

NILKEY_TEST(writer_builds_an_envelope_that_parses) {
  const Bytes name_a = Str("a");
  const Bytes name_b = Str("b");
  const Bytes pw = Str("pw");
  Record a{};
  a.name = name_a;
  a.password = pw;
  a.created_at = 5;
  a.updated_at = 6;
  Record b = a;
  b.name = name_b;

  const std::size_t size_a = RecordSize(a).value();
  const std::size_t size_b = RecordSize(b).value();
  Bytes out(4 + 4 + size_a + 4 + size_b);
  TlvWriter writer(out);
  NILKEY_EXPECT(writer.PutU32(2).ok());
  NILKEY_EXPECT(writer.PutU32(static_cast<std::uint32_t>(size_a)).ok());
  NILKEY_EXPECT(WriteRecord(writer, a).ok());
  NILKEY_EXPECT(writer.PutU32(static_cast<std::uint32_t>(size_b)).ok());
  NILKEY_EXPECT(WriteRecord(writer, b).ok());
  NILKEY_EXPECT(writer.written() == out.size());

  auto r = ParseEnvelope(S(out));
  NILKEY_EXPECT(r.ok());
  NILKEY_EXPECT(r.value().size() == 2);
}

NILKEY_TEST_MAIN()

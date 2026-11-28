// Fuzz harness for the TLV envelope and record parsers (SPEC.md 6). Whatever
// ParseEnvelope accepts must have a consistent layout and unique names, and its
// known fields must survive being written again.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <set>
#include <span>
#include <string_view>
#include <vector>

#include "fuzz_harness.hpp"
#include "nilkey/tlv.hpp"
#include "nilkey/vault_format.hpp"

namespace {

using Bytes = std::vector<std::byte>;

bool Equal(std::span<const std::byte> a, std::span<const std::byte> b) {
  return std::equal(a.begin(), a.end(), b.begin(), b.end());
}

std::uint32_t Le32(std::span<const std::byte> bytes, std::size_t off) {
  std::uint32_t v = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    v |= static_cast<std::uint32_t>(bytes[off + i]) << (8 * i);
  }
  return v;
}

// The records of an accepted envelope, after checking that they lie back to back
// behind their length prefixes, fill it exactly, have different names and stay
// within the field limit.
std::vector<nilkey::Record> CheckedRecords(
    std::span<const std::byte> envelope, const std::vector<nilkey::RecordLocation>& locations) {
  NILKEY_FUZZ_CHECK(envelope.size() >= 4 && Le32(envelope, 0) == locations.size());

  std::vector<nilkey::Record> records;
  std::set<Bytes> names;
  std::size_t end = 4;
  for (const nilkey::RecordLocation& location : locations) {
    NILKEY_FUZZ_CHECK(envelope.size() - end >= 4);
    NILKEY_FUZZ_CHECK(location.offset == end + 4);
    NILKEY_FUZZ_CHECK(location.length == Le32(envelope, end));
    NILKEY_FUZZ_CHECK(location.length <= envelope.size() - location.offset);
    end = location.offset + location.length;

    const auto bytes = envelope.subspan(location.offset, location.length);
    const auto record = nilkey::ParseRecord(bytes);
    NILKEY_FUZZ_CHECK(record.ok());
    std::size_t fields = 0;
    for (std::span<const std::byte> rest = bytes; !rest.empty(); ++fields) {
      NILKEY_FUZZ_CHECK(nilkey::NextField(rest).ok());
    }
    NILKEY_FUZZ_CHECK(fields <= 64);  // SPEC.md 6.4.
    const nilkey::Record& r = record.value();
    NILKEY_FUZZ_CHECK(!r.name.empty() && r.name.size() <= nilkey::kMaxNameSize);
    NILKEY_FUZZ_CHECK(names.insert(Bytes(r.name.begin(), r.name.end())).second);
    for (const auto& text : {r.name, r.username, r.url, r.notes}) {
      NILKEY_FUZZ_CHECK(nilkey::IsValidUtf8(text));
    }
    records.push_back(r);
  }
  NILKEY_FUZZ_CHECK(end == envelope.size());
  return records;
}

// Writes the known fields of `records` as a new envelope.
Bytes Rebuild(const std::vector<nilkey::Record>& records) {
  std::vector<std::size_t> sizes;
  std::size_t total = 4;
  for (const nilkey::Record& record : records) {
    const auto size = nilkey::RecordSize(record);
    NILKEY_FUZZ_CHECK(size.ok());
    sizes.push_back(size.value());
    total += 4 + size.value();
  }

  // Exactly as large as predicted, so ASan sees a write past the end.
  Bytes out(total);
  nilkey::TlvWriter writer(out);
  NILKEY_FUZZ_CHECK(writer.PutU32(static_cast<std::uint32_t>(records.size())).ok());
  for (std::size_t i = 0; i < records.size(); ++i) {
    NILKEY_FUZZ_CHECK(writer.PutU32(static_cast<std::uint32_t>(sizes[i])).ok());
    const std::size_t before = writer.written();
    NILKEY_FUZZ_CHECK(nilkey::WriteRecord(writer, records[i]).ok());
    NILKEY_FUZZ_CHECK(writer.written() - before == sizes[i]);
  }
  NILKEY_FUZZ_CHECK(writer.written() == out.size());
  return out;
}

std::span<const std::byte> Text(std::string_view s) {
  return std::as_bytes(std::span<const char>(s.data(), s.size()));
}

// One encoded record, followed by `unknown_fields` fields of types this version
// does not know.
Bytes SeedRecord(const nilkey::Record& record, unsigned unknown_fields) {
  Bytes out(256 + std::size_t{unknown_fields} * 10);
  nilkey::TlvWriter writer(out);
  NILKEY_FUZZ_CHECK(nilkey::WriteRecord(writer, record).ok());
  for (unsigned i = 0; i < unknown_fields; ++i) {
    const auto type = static_cast<std::uint8_t>(0x10 + i);
    NILKEY_FUZZ_CHECK(writer.PutField(type, Text("later")).ok());
  }
  out.resize(writer.written());
  return out;
}

Bytes Envelope(const std::vector<Bytes>& records) {
  std::size_t size = 4;
  for (const Bytes& record : records) size += 4 + record.size();
  Bytes out(size);
  nilkey::TlvWriter writer(out);
  NILKEY_FUZZ_CHECK(writer.PutU32(static_cast<std::uint32_t>(records.size())).ok());
  for (const Bytes& record : records) {
    NILKEY_FUZZ_CHECK(writer.PutU32(static_cast<std::uint32_t>(record.size())).ok());
    NILKEY_FUZZ_CHECK(writer.PutRaw(record).ok());
  }
  return out;
}

// An envelope the parser must accept; a rejected one would leave the checks
// above unused.
Bytes SeedEnvelope(const std::vector<Bytes>& records) {
  Bytes out = Envelope(records);
  NILKEY_FUZZ_CHECK(nilkey::ParseEnvelope(out).ok());
  return out;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const auto input = std::as_bytes(std::span<const std::uint8_t>(data, size));
  // A real payload is never larger, and RecordSize() relies on that.
  if (input.size() > nilkey::kMaxPlaintextSize) return 0;

  const auto parsed = nilkey::ParseEnvelope(input);
  if (!parsed.ok()) return 0;
  const std::vector<nilkey::Record> records = CheckedRecords(input, parsed.value());

  // Unknown fields and empty optional ones are dropped, so the new envelope can
  // be smaller, and only the known fields are compared.
  const Bytes rebuilt = Rebuild(records);
  NILKEY_FUZZ_CHECK(rebuilt.size() <= input.size());
  const auto reparsed = nilkey::ParseEnvelope(rebuilt);
  NILKEY_FUZZ_CHECK(reparsed.ok());
  const std::vector<nilkey::Record> again = CheckedRecords(rebuilt, reparsed.value());
  NILKEY_FUZZ_CHECK(again.size() == records.size());
  for (std::size_t i = 0; i < records.size(); ++i) {
    const nilkey::Record& a = records[i];
    const nilkey::Record& b = again[i];
    NILKEY_FUZZ_CHECK(Equal(a.name, b.name));
    NILKEY_FUZZ_CHECK(Equal(a.username, b.username));
    NILKEY_FUZZ_CHECK(Equal(a.password, b.password));
    NILKEY_FUZZ_CHECK(Equal(a.url, b.url));
    NILKEY_FUZZ_CHECK(Equal(a.notes, b.notes));
    NILKEY_FUZZ_CHECK(a.created_at == b.created_at && a.updated_at == b.updated_at);
  }
  return 0;
}

std::vector<std::vector<std::byte>> FuzzSeeds() {
  using namespace std::string_view_literals;
  // Every field set; the password holds a NUL and multi-byte characters.
  const nilkey::Record full{Text("github"),
                            Text("me"),
                            Text("p\0ss \xC3\xA9 \xE2\x82\xAC \xF0\x9F\x94\x91"sv),
                            Text("https://example.com"),
                            Text("line 1\nline 2"),
                            1,
                            2};
  const nilkey::Record minimal{Text("mail"), {}, Text(""), {}, {}, -1, 0};
  // One byte away from `minimal`, so that a single mutation repeats a name.
  const nilkey::Record twin{Text("maim"), {}, Text(""), {}, {}, -1, 0};

  // `minimal` has 4 fields: 60 more reach the limit of 64, and 61 pass it. That
  // last seed has to be rejected; if it is not, the field count check fails.
  return {SeedEnvelope({}),
          SeedEnvelope({SeedRecord(full, 0)}),
          SeedEnvelope({SeedRecord(full, 1)}),
          SeedEnvelope({SeedRecord(full, 0), SeedRecord(minimal, 0)}),
          SeedEnvelope({SeedRecord(minimal, 0), SeedRecord(twin, 0)}),
          SeedEnvelope({SeedRecord(minimal, 60)}),
          Envelope({SeedRecord(minimal, 61)})};
}

// Fuzz harness for the 66 byte vault header (SPEC.md 5). The limits are written
// out from SPEC.md 4.1 and 5, not taken from the code under test.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "fuzz_harness.hpp"
#include "nilkey/vault_format.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const auto input = std::as_bytes(std::span<const std::uint8_t>(data, size));
  const auto parsed = nilkey::ParseHeader(input);

  if (size != 66) {
    NILKEY_FUZZ_CHECK(!parsed.ok());
    return 0;
  }
  if (!parsed.ok()) return 0;
  const nilkey::VaultHeader& header = parsed.value();

  NILKEY_FUZZ_CHECK(header.kdf.mem_kib >= 19456 && header.kdf.mem_kib <= 2097152);
  NILKEY_FUZZ_CHECK(header.kdf.iterations >= 2 && header.kdf.iterations <= 20);
  NILKEY_FUZZ_CHECK(header.payload_len >= 16 && header.payload_len <= 16 * 1024 * 1024 + 16);

  // Every byte of an accepted header is either fixed or kept in `header`.
  const auto again = nilkey::SerializeHeader(header);
  NILKEY_FUZZ_CHECK(std::equal(again.begin(), again.end(), input.begin(), input.end()));

  const std::uint64_t file_size = std::uint64_t{66} + header.payload_len;
  NILKEY_FUZZ_CHECK(nilkey::ValidateFileSize(file_size, header).ok());
  NILKEY_FUZZ_CHECK(!nilkey::ValidateFileSize(file_size - 1, header).ok());
  NILKEY_FUZZ_CHECK(!nilkey::ValidateFileSize(file_size + 1, header).ok());
  return 0;
}

std::vector<std::vector<std::byte>> FuzzSeeds() {
  // The default costs, then both ends of the accepted ranges.
  const std::array<nilkey::VaultHeader, 3> headers = {
      {{nilkey::kDefaultKdfParams, {}, {}, 20},
       {{19456, 2}, {}, {}, 16},
       {{2097152, 20}, {}, {}, 16 * 1024 * 1024 + 16}}};

  std::vector<std::vector<std::byte>> seeds;
  for (const nilkey::VaultHeader& header : headers) {
    const auto bytes = nilkey::SerializeHeader(header);
    // A seed the parser rejects would leave the checks above unused.
    NILKEY_FUZZ_CHECK(nilkey::ParseHeader(bytes).ok());
    seeds.emplace_back(bytes.begin(), bytes.end());
  }
  return seeds;
}

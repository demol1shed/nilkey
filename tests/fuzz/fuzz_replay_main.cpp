// Runs a fuzz harness without libFuzzer, so every compiler builds it and CTest
// exercises it:
//
//   fuzz_x_replay                     runs the seeds
//   fuzz_x_replay FILE...             also runs these inputs, e.g. a crash file
//   fuzz_x_replay --write-seeds DIR   writes the seeds into the existing DIR as
//                                     the starting corpus for libFuzzer

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

#include "fuzz_harness.hpp"

namespace {

void Run(const std::vector<std::byte>& input) {
  // A copy with no spare capacity, so ASan sees a read past the end.
  const std::vector<std::byte> exact(input.begin(), input.end());
  // The harness always returns 0; it reports a failure by trapping.
  LLVMFuzzerTestOneInput(reinterpret_cast<const std::uint8_t*>(exact.data()), exact.size());
}

bool ReadFile(const char* path, std::vector<std::byte>& out) {
  std::FILE* file = std::fopen(path, "rb");
  if (file == nullptr) return false;
  std::array<std::byte, 4096> chunk{};
  std::size_t n = 0;
  while ((n = std::fread(chunk.data(), 1, chunk.size(), file)) > 0) {
    out.insert(out.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(n));
  }
  const bool read_ok = std::ferror(file) == 0;
  const bool close_ok = std::fclose(file) == 0;
  return read_ok && close_ok;
}

bool WriteFile(const std::string& path, const std::vector<std::byte>& bytes) {
  std::FILE* file = std::fopen(path.c_str(), "wb");
  if (file == nullptr) return false;
  const bool write_ok = std::fwrite(bytes.data(), 1, bytes.size(), file) == bytes.size();
  const bool close_ok = std::fclose(file) == 0;
  return write_ok && close_ok;
}

}  // namespace

int main(int argc, char** argv) {
  const std::vector<std::vector<std::byte>> seeds = FuzzSeeds();
  if (seeds.empty()) {
    std::fprintf(stderr, "no seeds\n");
    return 1;
  }

  if (argc > 1 && std::string_view(argv[1]) == "--write-seeds") {
    if (argc != 3) {
      std::fprintf(stderr, "--write-seeds needs one directory\n");
      return 1;
    }
    for (std::size_t i = 0; i < seeds.size(); ++i) {
      const std::string path = std::string(argv[2]) + "/seed-" + std::to_string(i);
      if (!WriteFile(path, seeds[i])) {
        std::fprintf(stderr, "cannot write %s\n", path.c_str());
        return 1;
      }
    }
    return 0;
  }

  for (const auto& seed : seeds) Run(seed);
  for (int i = 1; i < argc; ++i) {
    std::vector<std::byte> input;
    if (!ReadFile(argv[i], input)) {
      std::fprintf(stderr, "cannot read %s\n", argv[i]);
      return 1;
    }
    Run(input);
  }
  std::printf("replayed %zu input(s)\n", seeds.size() + static_cast<std::size_t>(argc - 1));
  return 0;
}

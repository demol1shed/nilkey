// The rules behind `nilkey doctor` (SPEC.md 9.2): what a file mode, a
// directory mode, the swap list and a lock limit mean. The system calls that
// gather these facts are covered end to end in test_cli_doctor_e2e.

#include <sys/stat.h>

#include <cstdint>
#include <initializer_list>
#include <string>

#include "nilkey/doctor.hpp"
#include "test_framework.hpp"

using nilkey::Check;
using nilkey::ClassifyDirectoryMode;
using nilkey::ClassifyFileMode;
using nilkey::CountSwapAreas;
using nilkey::Finding;
using nilkey::LockedBytesNeeded;
using nilkey::ParentDirectory;

namespace {

constexpr uid_t kMe = 1000;
constexpr uid_t kOther = 1001;

// What the kernel reports for a regular file or a directory: the type bits come
// along with the permission bits.
constexpr mode_t File(mode_t permissions) { return S_IFREG | permissions; }
constexpr mode_t Directory(mode_t permissions) { return S_IFDIR | permissions; }

}  // namespace

NILKEY_TEST(a_file_of_mode_0600_that_you_own_is_fine) {
  NILKEY_EXPECT(ClassifyFileMode(File(0600), kMe, kMe).level == Finding::kOk);
}

NILKEY_TEST(any_other_file_mode_is_a_problem) {
  for (const mode_t permissions : std::initializer_list<mode_t>{
           0644, 0640, 0604, 0700, 0400, 0660, 0666, 0777, 04600, 02600, 01600}) {
    NILKEY_EXPECT(ClassifyFileMode(File(permissions), kMe, kMe).level == Finding::kProblem);
  }
}

NILKEY_TEST(a_file_of_another_owner_is_a_problem_even_at_0600) {
  NILKEY_EXPECT(ClassifyFileMode(File(0600), kOther, kMe).level == Finding::kProblem);
  NILKEY_EXPECT(ClassifyFileMode(File(0600), 0, kMe).level == Finding::kProblem);
}

NILKEY_TEST(a_directory_of_mode_0700_that_you_own_is_fine) {
  NILKEY_EXPECT(ClassifyDirectoryMode(Directory(0700), kMe, kMe).level == Finding::kOk);
}

NILKEY_TEST(a_directory_that_group_or_others_can_write_is_a_problem) {
  for (const mode_t permissions :
       std::initializer_list<mode_t>{0770, 0707, 0775, 0757, 0777, 01777, 0720, 0702}) {
    NILKEY_EXPECT(ClassifyDirectoryMode(Directory(permissions), kMe, kMe).level ==
                  Finding::kProblem);
  }
}

NILKEY_TEST(a_directory_that_others_can_only_read_or_enter_is_a_note) {
  for (const mode_t permissions :
       std::initializer_list<mode_t>{0755, 0750, 0701, 0710, 0705, 0711}) {
    NILKEY_EXPECT(ClassifyDirectoryMode(Directory(permissions), kMe, kMe).level ==
                  Finding::kNote);
  }
}

NILKEY_TEST(a_directory_may_belong_to_you_or_to_root_and_to_nobody_else) {
  NILKEY_EXPECT(ClassifyDirectoryMode(Directory(0755), 0, kMe).level == Finding::kNote);
  NILKEY_EXPECT(ClassifyDirectoryMode(Directory(0700), kOther, kMe).level == Finding::kProblem);
  NILKEY_EXPECT(ClassifyDirectoryMode(Directory(0755), kOther, kMe).level == Finding::kProblem);
}

NILKEY_TEST(every_check_carries_an_explanation) {
  const Check checks[] = {ClassifyFileMode(File(0600), kMe, kMe),
                          ClassifyFileMode(File(0644), kMe, kMe),
                          ClassifyFileMode(File(0600), kOther, kMe),
                          ClassifyDirectoryMode(Directory(0700), kMe, kMe),
                          ClassifyDirectoryMode(Directory(0755), kMe, kMe),
                          ClassifyDirectoryMode(Directory(0777), kMe, kMe),
                          ClassifyDirectoryMode(Directory(0700), kOther, kMe)};
  for (const Check& check : checks) {
    NILKEY_EXPECT(check.text != nullptr && check.text[0] != '\0');
  }
}

NILKEY_TEST(swap_areas_are_the_lines_after_the_header) {
  const std::string header = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n";
  NILKEY_EXPECT(CountSwapAreas("") == 0);
  NILKEY_EXPECT(CountSwapAreas(header) == 0);
  NILKEY_EXPECT(CountSwapAreas(header + "/swap.img file 4194300 0 -2\n") == 1);
  NILKEY_EXPECT(CountSwapAreas(header + "/swap.img file 4194300 0 -2\n/dev/zram0 partition 262140 0 100\n") == 2);
}

NILKEY_TEST(swap_counting_ignores_blank_lines_and_a_missing_final_newline) {
  const std::string header = "Filename Type Size Used Priority\n";
  NILKEY_EXPECT(CountSwapAreas(header + "/swap.img file 1 0 -2") == 1);
  NILKEY_EXPECT(CountSwapAreas(header + "\n  \n\t\n") == 0);
  NILKEY_EXPECT(CountSwapAreas(header + "/a file 1 0 -2\n\n/b file 1 0 -3\n") == 2);
  NILKEY_EXPECT(CountSwapAreas("Filename Type Size Used Priority") == 0);
}

NILKEY_TEST(locked_bytes_hold_the_payload_twice_in_whole_pages_plus_an_allowance) {
  constexpr std::uint64_t kAllowance = 256 * 1024;
  NILKEY_EXPECT(LockedBytesNeeded(0, 4096) == kAllowance);
  NILKEY_EXPECT(LockedBytesNeeded(1, 4096) == 2 * 4096 + kAllowance);
  NILKEY_EXPECT(LockedBytesNeeded(4096, 4096) == 2 * 4096 + kAllowance);
  NILKEY_EXPECT(LockedBytesNeeded(4097, 4096) == 2 * 8192 + kAllowance);
  NILKEY_EXPECT(LockedBytesNeeded(100, 65536) == 2 * 65536 + kAllowance);
}

NILKEY_TEST(locked_bytes_for_the_largest_vault_do_not_overflow) {
  const std::uint64_t largest = 16U * 1024U * 1024U + 16U;
  NILKEY_EXPECT(LockedBytesNeeded(static_cast<std::uint32_t>(largest), 4096) >= 2 * largest);
  NILKEY_EXPECT(LockedBytesNeeded(UINT32_MAX, 4096) > std::uint64_t{UINT32_MAX} * 2);
}

NILKEY_TEST(a_zero_page_size_does_not_divide_by_zero) {
  NILKEY_EXPECT(LockedBytesNeeded(10, 0) == LockedBytesNeeded(10, 4096));
}

NILKEY_TEST(the_parent_directory_of_a_path) {
  NILKEY_EXPECT(ParentDirectory("/a/b/v.vault") == "/a/b");
  NILKEY_EXPECT(ParentDirectory("a/v.vault") == "a");
  NILKEY_EXPECT(ParentDirectory("v.vault") == ".");
  NILKEY_EXPECT(ParentDirectory("/v.vault") == "/");
}

NILKEY_TEST_MAIN()

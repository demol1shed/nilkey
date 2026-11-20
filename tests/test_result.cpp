#include <array>
#include <cstddef>
#include <cstring>
#include <memory>
#include <span>
#include <utility>

#include "nilkey/error.hpp"
#include "nilkey/result.hpp"
#include "test_framework.hpp"

using nilkey::Error;
using nilkey::ErrorCode;
using nilkey::Ok;
using nilkey::Result;
using nilkey::Status;
using nilkey::make_error;

NILKEY_TEST(result_holds_value) {
  Result<int> r(42);
  NILKEY_EXPECT(r.ok());
  NILKEY_EXPECT(r.value() == 42);
}

NILKEY_TEST(result_holds_error) {
  Result<int> r(make_error(ErrorCode::kOutOfRange));
  NILKEY_EXPECT(!r.ok());
  NILKEY_EXPECT(r.error().code == ErrorCode::kOutOfRange);
}

NILKEY_TEST(result_supports_move_only_values) {
  Result<std::unique_ptr<int>> r(std::make_unique<int>(7));
  NILKEY_EXPECT(r.ok());
  std::unique_ptr<int> p = std::move(r).value();
  NILKEY_EXPECT(p != nullptr);
  NILKEY_EXPECT(*p == 7);
}

NILKEY_TEST(status_ok_and_error) {
  Status good = Ok();
  NILKEY_EXPECT(good.ok());
  Status bad(make_error(ErrorCode::kInternal));
  NILKEY_EXPECT(!bad.ok());
  NILKEY_EXPECT(bad.error().code == ErrorCode::kInternal);
}

NILKEY_TEST(make_error_uses_static_messages) {
  const ErrorCode codes[] = {ErrorCode::kInvalidArgument, ErrorCode::kOutOfRange,
                             ErrorCode::kInternal};
  for (ErrorCode code : codes) {
    Error e = make_error(code);
    NILKEY_EXPECT(e.code == code);
    NILKEY_EXPECT(e.message != nullptr);
    NILKEY_EXPECT(std::strlen(e.message) > 0);
    NILKEY_EXPECT(std::strcmp(e.message, nilkey::describe(code)) == 0);
  }
}

NILKEY_TEST(secret_equal_compares_content_and_length) {
  const std::array<std::byte, 3> a{std::byte{1}, std::byte{2}, std::byte{3}};
  const std::array<std::byte, 3> same{std::byte{1}, std::byte{2}, std::byte{3}};
  const std::array<std::byte, 3> other{std::byte{1}, std::byte{2}, std::byte{4}};
  const std::span<const std::byte> a_span(a);
  NILKEY_EXPECT_SECRET_EQ(a_span, std::span<const std::byte>(same));
  NILKEY_EXPECT(!nilkey::test::secret_equal(a_span, std::span<const std::byte>(other)));
  NILKEY_EXPECT(!nilkey::test::secret_equal(a_span, a_span.first(2)));
  NILKEY_EXPECT(nilkey::test::secret_equal({}, {}));
}

NILKEY_TEST_MAIN()

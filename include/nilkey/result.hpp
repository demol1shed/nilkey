#ifndef NILKEY_RESULT_HPP
#define NILKEY_RESULT_HPP

#include <cstdlib>
#include <utility>
#include <variant>

#include "nilkey/error.hpp"

namespace nilkey {

// Either a value of type T or an error of type E. Exceptions are disabled in
// this project, so a wrong access calls std::abort() instead of throwing.
// Access goes through std::get_if on purpose: std::get would abort silently
// under -fno-exceptions.
template <typename T, typename E = Error>
class [[nodiscard]] Result {
 public:
  Result(T val) : data_(std::in_place_index<0>, std::move(val)) {}
  Result(E err) : data_(std::in_place_index<1>, std::move(err)) {}

  bool ok() const { return data_.index() == 0; }

  T& value() & {
    T* v = std::get_if<0>(&data_);
    if (v == nullptr) std::abort();
    return *v;
  }
  const T& value() const& {
    const T* v = std::get_if<0>(&data_);
    if (v == nullptr) std::abort();
    return *v;
  }
  T&& value() && {
    T* v = std::get_if<0>(&data_);
    if (v == nullptr) std::abort();
    return std::move(*v);
  }

  const E& error() const {
    const E* e = std::get_if<1>(&data_);
    if (e == nullptr) std::abort();
    return *e;
  }

 private:
  std::variant<T, E> data_;
};

// Result of an operation that returns no value.
using Status = Result<std::monostate>;

inline Status Ok() { return Status(std::monostate{}); }

}  // namespace nilkey

#endif  // NILKEY_RESULT_HPP

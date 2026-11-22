#include "nilkey/secure_buffer.hpp"

#include <sodium.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <utility>

namespace nilkey {

Result<SecureBuffer> SecureBuffer::Create(std::size_t size, MemlockPolicy policy) {
  if (size == 0) return SecureBuffer(nullptr, 0);

  void* data = sodium_malloc(size);
  if (data == nullptr) return make_error(ErrorCode::kAllocationFailed);

  // sodium_malloc() tries to lock the pages itself but ignores failure, so the
  // result of an explicit sodium_mlock() is the only reliable signal.
  if (sodium_mlock(data, size) != 0) {
    if (policy == MemlockPolicy::kRequire) {
      sodium_free(data);
      return make_error(ErrorCode::kMemoryLockFailed);
    }
    std::fputs(
        "warning: secure memory could not be locked; it may be written to swap "
        "(see `ulimit -l`)\n",
        stderr);
  }

  sodium_memzero(data, size);  // sodium_malloc fills new memory with 0xdb.
  if (sodium_mprotect_noaccess(data) != 0) {
    sodium_free(data);
    return make_error(ErrorCode::kMemoryProtectFailed);
  }
  return SecureBuffer(data, size);
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept : data_(other.data_), size_(other.size_) {
  // A live guard points at `other`; moving it would leave the guard dangling.
  if (other.guard_open_) std::abort();
  other.data_ = nullptr;
  other.size_ = 0;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
  if (this == &other) return *this;
  if (guard_open_ || other.guard_open_) std::abort();
  Release();
  data_ = other.data_;
  size_ = other.size_;
  other.data_ = nullptr;
  other.size_ = 0;
  return *this;
}

SecureBuffer::~SecureBuffer() { Release(); }

void SecureBuffer::Release() {
  if (data_ != nullptr) sodium_free(data_);  // Checks canary, zeroes, unlocks.
  data_ = nullptr;
  size_ = 0;
}

namespace {

// Opens `buffer` with the given protection call. An empty buffer owns no
// memory, so there is nothing to unprotect.
template <typename Protect>
Status OpenBuffer(void* data, bool& guard_open, Protect protect) {
  if (guard_open) return make_error(ErrorCode::kInvalidArgument);
  if (data != nullptr && protect(data) != 0) return make_error(ErrorCode::kMemoryProtectFailed);
  guard_open = true;
  return Ok();
}

// A buffer that cannot be re-locked would leave a secret readable, so the
// destructors abort instead of continuing.
void CloseBuffer(void* data, bool& guard_open) {
  if (data != nullptr && sodium_mprotect_noaccess(data) != 0) std::abort();
  guard_open = false;
}

}  // namespace

Result<ScopedReadGuard> ScopedReadGuard::Open(const SecureBuffer& buffer) {
  Status s = OpenBuffer(buffer.data_, buffer.guard_open_, sodium_mprotect_readonly);
  if (!s.ok()) return s.error();
  return ScopedReadGuard(&buffer);
}

ScopedReadGuard::ScopedReadGuard(ScopedReadGuard&& other) noexcept : buffer_(other.buffer_) {
  other.buffer_ = nullptr;
}

ScopedReadGuard::~ScopedReadGuard() {
  if (buffer_ != nullptr) CloseBuffer(buffer_->data_, buffer_->guard_open_);
}

std::span<const std::byte> ScopedReadGuard::bytes() const {
  if (buffer_->data_ == nullptr) return {};
  return {static_cast<const std::byte*>(buffer_->data_), buffer_->size_};
}

Result<ScopedWriteGuard> ScopedWriteGuard::Open(SecureBuffer& buffer) {
  Status s = OpenBuffer(buffer.data_, buffer.guard_open_, sodium_mprotect_readwrite);
  if (!s.ok()) return s.error();
  return ScopedWriteGuard(&buffer);
}

ScopedWriteGuard::ScopedWriteGuard(ScopedWriteGuard&& other) noexcept : buffer_(other.buffer_) {
  other.buffer_ = nullptr;
}

ScopedWriteGuard::~ScopedWriteGuard() {
  if (buffer_ != nullptr) CloseBuffer(buffer_->data_, buffer_->guard_open_);
}

std::span<std::byte> ScopedWriteGuard::bytes() const {
  if (buffer_->data_ == nullptr) return {};
  return {static_cast<std::byte*>(buffer_->data_), buffer_->size_};
}

Result<SecureBuffer> CopyToSecureBuffer(std::span<const std::byte> source, MemlockPolicy policy) {
  Result<SecureBuffer> made = SecureBuffer::Create(source.size(), policy);
  if (!made.ok()) return made;
  if (source.empty()) return made;
  {
    // The guard must be closed before the buffer is moved out.
    Result<ScopedWriteGuard> guard = ScopedWriteGuard::Open(made.value());
    if (!guard.ok()) return guard.error();
    std::memcpy(guard.value().bytes().data(), source.data(), source.size());
  }
  return made;
}

}  // namespace nilkey

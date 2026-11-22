#ifndef NILKEY_SECURE_BUFFER_HPP
#define NILKEY_SECURE_BUFFER_HPP

#include <cstddef>
#include <span>

#include "nilkey/result.hpp"

namespace nilkey {

// What to do when the allocation cannot be locked into RAM (SPEC.md 7.3).
enum class MemlockPolicy {
  kRequire,        // Fail with kMemoryLockFailed (default behaviour).
  kAllowUnlocked,  // Print a warning to stderr and continue.
};

class ScopedReadGuard;
class ScopedWriteGuard;

// Fixed-size, non-copyable block of sodium_malloc'd memory. The contents are
// inaccessible (PROT_NONE) except while a guard is alive. Callers keep secrets
// in one buffer and slice it with std::span::subspan instead of allocating
// many small buffers (each sodium_malloc costs several guard pages).
//
// Not thread-safe. sodium_init() must have been called first.
class SecureBuffer {
 public:
  // The returned buffer is zero-filled. A size of 0 yields an empty buffer
  // that owns no memory.
  [[nodiscard]] static Result<SecureBuffer> Create(std::size_t size, MemlockPolicy policy);

  SecureBuffer(const SecureBuffer&) = delete;
  SecureBuffer& operator=(const SecureBuffer&) = delete;
  SecureBuffer(SecureBuffer&& other) noexcept;
  SecureBuffer& operator=(SecureBuffer&& other) noexcept;
  ~SecureBuffer();

  std::size_t size() const { return size_; }

 private:
  friend class ScopedReadGuard;
  friend class ScopedWriteGuard;

  SecureBuffer(void* data, std::size_t size) : data_(data), size_(size) {}
  void Release();

  void* data_ = nullptr;
  std::size_t size_ = 0;
  // Mutable so a read guard can be opened on a const buffer.
  mutable bool guard_open_ = false;
};

// Makes the buffer readable for the lifetime of the guard. Only one guard may
// be open on a buffer at a time; a second Open() fails.
class [[nodiscard]] ScopedReadGuard {
 public:
  [[nodiscard]] static Result<ScopedReadGuard> Open(const SecureBuffer& buffer);

  ScopedReadGuard(const ScopedReadGuard&) = delete;
  ScopedReadGuard& operator=(const ScopedReadGuard&) = delete;
  ScopedReadGuard(ScopedReadGuard&& other) noexcept;
  ScopedReadGuard& operator=(ScopedReadGuard&&) = delete;
  ~ScopedReadGuard();

  std::span<const std::byte> bytes() const;

 private:
  explicit ScopedReadGuard(const SecureBuffer* buffer) : buffer_(buffer) {}
  const SecureBuffer* buffer_;
};

// Makes the buffer readable and writable for the lifetime of the guard.
class [[nodiscard]] ScopedWriteGuard {
 public:
  [[nodiscard]] static Result<ScopedWriteGuard> Open(SecureBuffer& buffer);

  ScopedWriteGuard(const ScopedWriteGuard&) = delete;
  ScopedWriteGuard& operator=(const ScopedWriteGuard&) = delete;
  ScopedWriteGuard(ScopedWriteGuard&& other) noexcept;
  ScopedWriteGuard& operator=(ScopedWriteGuard&&) = delete;
  ~ScopedWriteGuard();

  std::span<std::byte> bytes() const;

 private:
  explicit ScopedWriteGuard(SecureBuffer* buffer) : buffer_(buffer) {}
  SecureBuffer* buffer_;
};

// A SecureBuffer of exactly `source.size()` bytes holding a copy of `source`.
// For sizing a secret that was first read into a larger buffer. An empty source
// yields an empty buffer.
[[nodiscard]] Result<SecureBuffer> CopyToSecureBuffer(std::span<const std::byte> source,
                                                      MemlockPolicy policy);

}  // namespace nilkey

#endif  // NILKEY_SECURE_BUFFER_HPP

#ifndef NILKEY_VAULT_HPP
#define NILKEY_VAULT_HPP

// In-memory vault: the decrypted TLV payload (SPEC.md 6) held in one
// SecureBuffer, plus a plain index of where each record sits. Records are
// views into that buffer, so reading one needs a VaultReader, which keeps the
// buffer readable (a ScopedReadGuard) for as long as it lives.
//
// Every change builds a complete new payload and swaps it in only once it has
// been written and re-parsed, so a failed Add/Update/Remove leaves the vault
// exactly as it was. Not thread-safe.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "nilkey/result.hpp"
#include "nilkey/secure_buffer.hpp"
#include "nilkey/tlv.hpp"

namespace nilkey {

// The user-editable fields of a record. Timestamps are not part of it: the
// vault sets them, from the `now` the caller passes in.
struct RecordInput {
  std::span<const std::byte> name;
  std::span<const std::byte> username;
  std::span<const std::byte> password;
  std::span<const std::byte> url;
  std::span<const std::byte> notes;
};

// A change to some fields of one record: a field that is set replaces the old
// value (an empty span clears an optional field), a field that is not set keeps
// it. The old values never leave the vault's own buffer.
struct RecordPatch {
  std::optional<std::span<const std::byte>> name;
  std::optional<std::span<const std::byte>> username;
  std::optional<std::span<const std::byte>> password;
  std::optional<std::span<const std::byte>> url;
  std::optional<std::span<const std::byte>> notes;
};

// Read access to a vault. Spans returned by Get() and payload() are valid only
// while the reader is alive. Only one reader (or any other guard) can be open
// on a vault at a time, so Add/Update/Remove fail with kInvalidArgument while
// one is open. Moving the Vault while a reader is open aborts (see
// SecureBuffer).
class [[nodiscard]] VaultReader {
 public:
  VaultReader(const VaultReader&) = delete;
  VaultReader& operator=(const VaultReader&) = delete;
  VaultReader(VaultReader&&) = default;
  VaultReader& operator=(VaultReader&&) = delete;

  std::size_t size() const { return index_->size(); }

  // kOutOfRange if `index >= size()`.
  [[nodiscard]] Result<Record> Get(std::size_t index) const;

  // Index of the record with exactly this name (byte for byte), if any.
  std::optional<std::size_t> Find(std::span<const std::byte> name) const;

  // The whole serialized payload, ready for Seal().
  std::span<const std::byte> payload() const { return guard_.bytes(); }

 private:
  friend class Vault;
  VaultReader(ScopedReadGuard guard, const std::vector<RecordLocation>* index)
      : guard_(std::move(guard)), index_(index) {}

  ScopedReadGuard guard_;
  const std::vector<RecordLocation>* index_;
};

class Vault {
 public:
  // A vault with no records (for `init`). `policy` is used for every buffer
  // the vault allocates later.
  [[nodiscard]] static Result<Vault> CreateEmpty(MemlockPolicy policy);

  // Takes over a decrypted payload (the plaintext of Open() or
  // OpenWithPassword()) and validates it with ParseEnvelope.
  [[nodiscard]] static Result<Vault> FromPlaintext(SecureBuffer plaintext, MemlockPolicy policy);

  std::size_t size() const { return index_.size(); }

  [[nodiscard]] Result<VaultReader> Open() const;

  // Appends a record; created_at = updated_at = now. kAlreadyExists if the
  // name is taken; kOutOfRange if the vault would pass kMaxRecords or
  // kMaxPlaintextSize.
  [[nodiscard]] Status Add(const RecordInput& input, std::int64_t now);

  // Replaces every user field of the record called `name` (the name too, so
  // this renames). created_at and the position are kept, updated_at = now.
  // Fields of a type this version does not know are carried over. kNotFound if
  // there is no such record; kAlreadyExists if the new name belongs to a
  // different record.
  [[nodiscard]] Status Update(std::span<const std::byte> name, const RecordInput& input,
                              std::int64_t now);

  // Like Update(), but only the fields set in `patch` change; the others keep
  // their old value without being copied out of the vault. The errors are the
  // same as for Update().
  [[nodiscard]] Status Patch(std::span<const std::byte> name, const RecordPatch& patch,
                             std::int64_t now);

  // kNotFound if there is no record called `name`.
  [[nodiscard]] Status Remove(std::span<const std::byte> name);

 private:
  Vault(SecureBuffer payload, std::vector<RecordLocation> index, MemlockPolicy policy)
      : payload_(std::move(payload)), index_(std::move(index)), policy_(policy) {}

  SecureBuffer payload_;
  std::vector<RecordLocation> index_;
  MemlockPolicy policy_;
};

}  // namespace nilkey

#endif  // NILKEY_VAULT_HPP

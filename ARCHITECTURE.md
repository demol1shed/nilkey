# Architecture notes

Design decisions and known limitations that the code alone does not explain.
`SPEC.md` stays the source of truth for formats and parameters; this file
records what was learned while implementing it. Add a section per phase.

## Phase 1: secure memory and process hardening

Code: `include/nilkey/secure_buffer.hpp`, `include/nilkey/hardening.hpp`.

### Design decisions

- **Lock policy is a parameter.** `SecureBuffer::Create(size, MemlockPolicy)`
  takes the policy instead of reading a global, so the future
  `--allow-unlocked-memory` flag is wired in by the CLI.
- **`sodium_mlock()` is checked explicitly.** `sodium_malloc()` tries to lock
  the pages but ignores failure, so its result cannot be trusted.
- **One guard per buffer at a time.** A second `Open()` fails with
  `kInvalidArgument`. There is no reference counting.
- **Moving a buffer while a guard is open calls `abort()`.** The guard would
  otherwise point at a moved-from buffer.
- **A guard that cannot re-lock its buffer calls `abort()`.** Continuing
  would leave a secret readable.
- **Secrets live in few, large buffers.** Callers slice them with
  `std::span::subspan`; every `sodium_malloc` costs several guard pages.

### Known limitations

- **Sanitizers hide lock failures.** ASan and UBSan intercept `mlock()` and
  always report success, so the lock-failure policy test
  (`tests/test_memlock_policy.cpp`) is registered only when sanitizers are
  off. It runs in the CI release profile. This is a deliberate exception to
  "all tests run under sanitizers".
- **Root and `CAP_IPC_LOCK` ignore `RLIMIT_MEMLOCK`.** The same test then
  prints `SKIP` and still reports success.
- **Not tested:** `mprotect` violations (SIGSEGV) and canary corruption.
  Signal behaviour under ASan is fragile.
- **Not tested:** failure paths of `prctl` and `setrlimit` in
  `HardenProcess()`. They cannot be forced to fail.

### Deferred to later phases

- `sodium_stackzero` calls belong to the KDF, decrypt and password-read flows
  (Phase 2 and 4).
- Locking Argon2's internal working memory is decided in Phase 2
  (`SPEC.md` 7.3).
- The error branch in `main()` is reworked with the real CLI in Phase 4.

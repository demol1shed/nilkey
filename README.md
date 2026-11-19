# nilkey

A zero-knowledge command-line password vault written in C++20 on top of
[libsodium](https://libsodium.org). Secrets live in a single encrypted `.vault`
file; the master password (or any hash of it) is never stored.

> **Status: pre-alpha (Phase 0 of 4 — project skeleton).**
> There is no usable functionality yet, and the design has not been
> independently audited. Do not store real secrets with it.

## Design goals

- Argon2id key derivation and XChaCha20-Poly1305 authenticated encryption,
  both taken from libsodium; no hand-written cryptography.
- Whole 66-byte file header authenticated as AAD, atomic and crash-safe saves.
- Sensitive data kept in guarded, locked memory (`sodium_malloc`/`sodium_mlock`).
- Auditable code: no exceptions, no RTTI, no third-party dependency other than
  libsodium.

The full technical specification (in Turkish) is in [`SPEC.md`](SPEC.md).

## Requirements

- Linux
- g++ >= 13 or clang++ >= 18 (C++20)
- CMake >= 3.20 and `pkg-config`
- libsodium >= 1.0.18 with development files (`libsodium-dev` on Debian/Ubuntu)

## Build and test

Debug build with AddressSanitizer and UndefinedBehaviorSanitizer:

```bash
cmake -B build-debug -DCMAKE_BUILD_TYPE=Debug -DNILKEY_ENABLE_SANITIZERS=ON
cmake --build build-debug -j
ctest --test-dir build-debug --output-on-failure
```

Hardened release build:

```bash
cmake -B build-release -DCMAKE_BUILD_TYPE=Release -DNILKEY_ENABLE_SANITIZERS=OFF
cmake --build build-release -j
```

Warnings are errors by default. Pass `-DNILKEY_WERROR=OFF` to turn that off,
for example when packaging with a newer compiler.

## License

[MIT](LICENSE)

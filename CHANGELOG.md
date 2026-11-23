# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The version of the vault file format (the `version` field in its header) is
independent of the version of the program.

## [Unreleased]

### Changed

- **No control characters in new names and options.** `add` (the name,
  `--username`, `--url`) and `update` (`--rename`, `--username`, `--url`) now
  refuse text that would not show as written: control characters such as ESC,
  tab and newline, and direction marks such as U+202E. Before, they were
  accepted and `list` showed them as `?`. The command fails with exit
  code 2 before any password is asked. Notes and passwords are not affected, and
  records that already have such a name can still be found, renamed and deleted.
- **`list` on a terminal.** When the output goes to a terminal, `list` prints a
  header and lines up the columns: names, user names and times each start at the
  same place, and each column is as wide as its longest entry (measured in
  terminal cells, so most emoji and East Asian characters line up too). When the
  output goes to a pipe or a file, the rows are still `name`, `username` and
  `updated_at` separated by tabs.

## [0.1.0] - 2026-11-23

First release. nilkey is pre-alpha: its design has not been independently
audited, so do not store real secrets with it. What it does not protect against
and what rests on design and review rather than on a test is listed in
[`SPEC.md`](SPEC.md) section 9.4.

### Added

- **Vault file format.** A 66-byte header that is authenticated in full as
  additional data (magic, format version, Argon2id costs, salt, nonce, payload
  length). The key comes from the master password with Argon2id (64 MiB, 3
  passes by default); the payload is sealed with XChaCha20-Poly1305. Costs
  below a floor or above a ceiling are rejected before any memory is allocated,
  so a tampered header can neither weaken the key derivation nor make it ask for
  an unreasonable amount of memory.
  Every save uses a fresh nonce; `passwd` also uses a fresh salt. All
  cryptography comes from libsodium.
- **Records.** A dependency-free binary TLV payload: strict UTF-8 for names, user
  names, URLs and notes; passwords are raw bytes (embedded NUL bytes are fine);
  limits of 100,000 records, 64 fields per record and 16 MiB in all. Fields that
  a newer version wrote are kept when a record is updated.
- **Memory and process hardening.** `SecureBuffer` (guard pages, `mlock`,
  `mprotect`, zeroed on release) holds every password, key and decrypted
  payload. Locking memory fails closed, with a pointer to `nilkey doctor`;
  `--allow-unlocked-memory` continues with a warning. At start-up the process
  turns off core dumps and ptrace (`PR_SET_DUMPABLE`, `RLIMIT_CORE`) and sets
  `umask` to 0077. The stack is scrubbed after key derivation, decryption and
  password input, on failure paths too.
- **Files.** Saves are atomic and durable (temporary file, `fsync`, `rename`,
  directory `fsync`) with mode `0600`. Symbolic links are refused. Commands that
  change the vault hold an `flock` on `<vault>.lock` for the whole
  read-modify-write cycle; `list` and `get` need no lock.
- **Commands.** `init`, `add`, `get`, `list`, `update`, `delete`, `generate`,
  `passwd` and `doctor`. Master and record passwords are read from the terminal
  with echo off and never from the command line; `--notes-stdin` reads notes from
  stdin. `generate` draws unbiased characters with `randombytes_uniform`.
  Exit status is 0 for success, 1 for a failed command, 2 for a wrong command
  line and 130 when the user aborts.
- **Clipboard.** `get` copies a field with `wl-copy` (Wayland), `xclip` or `xsel`
  (X11) and starts a detached process that clears the clipboard after 15 seconds
  (`--timeout`, 1 to 3600), but only if it still holds the copied text; it
  compares a BLAKE2b digest and never holds the text itself. `get --print` writes
  the field to stdout instead.
- **`doctor`.** Reports the mode and owner of the vault, its lock file and its
  directory, the memory lock limit against what the vault needs, core dump
  settings, active swap areas and the clipboard tool. It asks for no password.
- **Tests and CI.** A single-header test framework, a pseudo-terminal harness, a
  fake clipboard tool and end-to-end suites for every command; the production
  binary is smoke tested with the production Argon2id costs. GitHub Actions
  builds with g++-13 and clang++-18, with and without AddressSanitizer and
  UndefinedBehaviorSanitizer, treats warnings as errors and checks that the
  release binary is position independent with full RELRO and immediate binding.
- **Build.** C++20 with `-fno-exceptions` and `-fno-rtti`; libsodium (1.0.18 or
  newer) is the only dependency. Linux only.

[Unreleased]: https://github.com/demol1shed/nilkey/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/demol1shed/nilkey/releases/tag/v0.1.0

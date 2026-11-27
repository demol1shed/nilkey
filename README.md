# nilkey

A zero-knowledge command-line password vault written in C++20 on top of
[libsodium](https://libsodium.org). Secrets live in a single encrypted `.vault`
file; the master password (or any hash of it) is never stored.

> **Status: pre-alpha (all four planned phases are done: secure memory, crypto
> core, vault file layer, vault data model, and the command line).**
> The commands below work, but the design has not been independently audited and
> the known limits are in [`SPEC.md`](SPEC.md) section 9.4. Do not store real
> secrets with it yet.

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

### Fuzzing

The header parser and the TLV parser have libFuzzer targets in `tests/fuzz/`.
Every build replays their seed inputs as part of `ctest`. Fuzzing itself needs
Clang with its libFuzzer runtime (on Ubuntu 24.04, the packages `clang-18` and
`libclang-rt-18-dev`) and runs for as long as you allow it:

```bash
CXX=clang++-18 cmake -B build-fuzz -DCMAKE_BUILD_TYPE=Debug \
  -DNILKEY_ENABLE_SANITIZERS=ON -DNILKEY_ENABLE_FUZZING=ON
cmake --build build-fuzz -j --target \
  fuzz_header fuzz_header_replay fuzz_envelope fuzz_envelope_replay

mkdir -p build-fuzz/corpus/header build-fuzz/corpus/envelope build-fuzz/artifacts
build-fuzz/tests/fuzz_header_replay --write-seeds build-fuzz/corpus/header
build-fuzz/tests/fuzz_envelope_replay --write-seeds build-fuzz/corpus/envelope

build-fuzz/tests/fuzz_header -max_total_time=60 -max_len=128 \
  -artifact_prefix=build-fuzz/artifacts/ build-fuzz/corpus/header
build-fuzz/tests/fuzz_envelope -max_total_time=60 \
  -artifact_prefix=build-fuzz/artifacts/ build-fuzz/corpus/envelope
```

When a target fails, libFuzzer saves the input under `build-fuzz/artifacts/`.
Run it again with the replay binary of the same target, for example
`build-fuzz/tests/fuzz_envelope_replay build-fuzz/artifacts/crash-...`. After
the fix, add those bytes to `FuzzSeeds()` in the harness, so that every later
build tests them.

## Usage

```bash
nilkey init                                   # create the vault, asks for a master password (12+ characters)
nilkey add github --username me --generate    # add a record with a generated password
nilkey list                                   # names, user names, last change
nilkey get github                             # copy the password; cleared after 15 seconds
nilkey get github --field url --print         # write a field to stdout instead
nilkey doctor                                 # check this machine's security settings
```

| Command | What it does |
| :--- | :--- |
| `init` | Create a new vault |
| `add <name>` | Add a record (`--username`, `--url`, `--notes-stdin`, `--generate`) |
| `get <name>` | Copy a field to the clipboard (`--field`, `--timeout <seconds>`), or print it (`--print`) |
| `list` | List record names |
| `update <name>` | Change a record (`--rename`, `--username`, `--url`, `--notes-stdin`, `--prompt-password`, `--generate`) |
| `delete <name>` | Delete a record (asks first; `--yes` skips the question) |
| `generate` | Print a random password (`--length`, `--no-lower`, `--no-upper`, `--no-digits`, `--no-symbols`) |
| `passwd` | Change the master password (new salt, new nonce) |
| `doctor` | Report file modes, memory lock limit, core dumps, swap and the clipboard tool |

`nilkey --help` lists every option.

- **Passwords never go through the command line.** The master password and
  record passwords are read from the terminal with echo off; `--notes-stdin`
  reads notes from stdin.
- **The vault file** is `--vault <path>`, else `$NILKEY_PATH`, else
  `~/.local/share/nilkey/default.vault`. It is saved atomically with mode `0600`.
- **The clipboard** needs `wl-clipboard` (Wayland), or `xclip` or `xsel` (X11).
  Without one, `get` fails and `get --print` still works. A background process
  clears the clipboard after the timeout, but only if it still holds the copied
  text. Clipboard history managers on your desktop may keep a copy.
- **Locked memory:** secrets live in memory that is locked against swap. If
  `ulimit -l` is too low, nilkey stops and points to `nilkey doctor`;
  `--allow-unlocked-memory` continues with a warning.
- **Exit status:** 0 success, 1 the command failed, 2 a wrong command line,
  130 the user aborted.

## License

[MIT](LICENSE)

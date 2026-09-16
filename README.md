# pwsafe

`pwsafe` is a Windows-only command-line password safe. Passwords are generated
with a CSPRNG or imported, stored in a single vault file encrypted with the
Windows Data Protection API (DPAPI), and retrieved straight to the clipboard
without ever being printed to the terminal.

## Requirements

- Windows (DPAPI is Windows-specific)
- Rust 1.98 or newer (edition 2024)

## Build

```
cargo build --release
```

The binary is `target\release\pwsafe.exe`. Add that directory to `PATH` (or
copy the exe somewhere on it) to use `pwsafe` from any shell.

## Usage

```powershell
pwsafe add github -l 24            # generate, store, copy to the clipboard
pwsafe set github                  # store an existing password (hidden prompt)
$secret | pwsafe set github        # ...or pipe one line in
pwsafe get github                  # copy to the clipboard
pwsafe get github --clear-secs 0   # copy and leave it on the clipboard
pwsafe list                        # list stored keys (values are never printed)
pwsafe rm github                   # delete an entry
pwsafe set github --force          # overwrite an existing entry
```

- `add` generates a password containing at least one lowercase, uppercase,
  digit, and symbol character, stores it, and copies it to the clipboard.
- `set` stores a password you already have. It is never taken from the
  command line: at a terminal you get a hidden prompt with a confirmation
  entry, otherwise one line is read from stdin. A trailing `\r\n`, `\n`, or
  `\r` and a UTF-8 BOM are stripped; empty input, NUL characters, more than
  one line, invalid UTF-8, and secrets longer than 4096 characters are
  rejected. `set` does not touch the clipboard.
- `add` and `get` copy the secret with clipboard history and cloud sync
  disabled, and wipe the clipboard after `--clear-secs` seconds (default 15,
  maximum 86400) only if it still holds the secret. Ctrl+C during the wait
  keeps it.
- No command ever writes a password to stdout or stderr.

On PowerShell 5.1, piped output is ASCII-encoded; non-ASCII secrets should be
entered at the hidden prompt instead.

The vault lives at `%APPDATA%\pwsafe-rs\vault.dat`. Set the `PWSAFE_VAULT`
environment variable to use a different location; it must be an absolute path
on a local drive (UNC and device paths are rejected).

## Security model

What `pwsafe` does:

- Generates passwords with a CSPRNG, guaranteeing character class coverage.
- Encrypts the vault with DPAPI under the current Windows user, with
  app-specific optional entropy and `CRYPTPROTECT_UI_FORBIDDEN`.
- Never writes plaintext to disk: only the DPAPI ciphertext is stored.
- Zeroizes plaintext vault data held in process memory on clean exit.
- Writes atomically: unique temp file created with create-new, flushed to
  disk, then `ReplaceFileW` (which preserves the vault's ACLs);
  read-modify-write cycles are serialized with an exclusive lock, so
  concurrent invocations cannot lose entries.
- Refuses to overwrite a vault that fails to decrypt, instead of treating it
  as an empty vault.
- Marks copied secrets as excluded from Windows clipboard history (Win+V) and
  cloud clipboard, and wipes them after the configured delay when the
  clipboard is unchanged, verified through the clipboard sequence number.
- Restores the console input mode if Ctrl+C interrupts the hidden prompt.
- Restricts entry names to 1-128 printable ASCII characters, preventing ANSI
  and Unicode bidi spoofing in `pwsafe list`.
- Never accepts a secret as a command-line argument (argv is visible to other
  processes and lands in shell history).
- Bounds rejected input: a piped secret larger than 16 KiB is refused before
  it is buffered, and the vault path must be an absolute local file.

What it does **not** protect against:

- Other processes running as the same Windows user (malware, or anything that
  reads the clipboard while the secret is on it), administrators, SYSTEM, or
  domain DPAPI recovery keys.
- Clipboard entries created before history exclusion was in place, or by other
  tools; cloud clipboard settings on managed devices are outside our control.
- Offline attacks by someone who can extract your Windows credentials.
- Loss of the Windows profile: the vault is bound to this user and machine and
  cannot be decrypted elsewhere. There is no recovery path and no backup.

There is no master password. Your Windows account is the root of trust.

## Development

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check                                  # advisories, licenses, bans, sources
semgrep scan --config .semgrep.yml src --error    # custom security rules
```

`deny.toml` pins the target graph to `x86_64-pc-windows-msvc`, denies yanked,
unmaintained, and unsound crates, unknown registries/git sources, wildcard
dependencies, and duplicate crate versions (with a documented exception for
`windows-sys` 0.60, which arboard pins). `.semgrep.yml` blocks debug/abort
macros, process spawning, environment mutation, and direct printing, and
requires review of any file write outside `src/vault.rs`.

A GitHub Actions workflow (`.github/workflows/ci.yml`) runs all five gates on
every push and pull request.

## License

MIT

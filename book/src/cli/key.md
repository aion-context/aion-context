# `key` — keystore management

Generate, list, export, import, and delete Ed25519 signing
keys held by the local keystore. The CLI uses the OS keyring
where available (Linux Secret Service / GNOME Keyring, macOS
Keychain, Windows Credential Manager) and falls back to a
file-based keystore otherwise.

```bash
aion key <SUBCOMMAND>

Subcommands:
  generate    Create a fresh Ed25519 keypair under a key ID
  list        List every stored key (when the backend supports enumeration)
  export      Export a key to a password-protected file
  import      Import a key from a password-protected file
  delete      Delete a key from the keystore
```

## `aion key generate`

```bash
aion key generate --id <KEY_ID> [--description <STRING>]
```

`KEY_ID` is a numeric string (parsed as `u64`). The same value
is used as the AuthorId when this key signs versions.

Output prints the public bytes — operators copy these into
the registry JSON when pinning.

## `aion key list`

Prints every key the backend knows about. On keyring backends
that don't support enumeration (most), the CLI scans common
ID ranges to find what's there. File-based keystores enumerate
directly.

## `aion key export` / `aion key import`

Round-trip a key through a password-protected file (Argon2 +
ChaCha20-Poly1305). Useful for moving keys between machines or
backing them up offline.

```bash
aion key export <KEY_ID> --output backup.key
aion key import backup.key --id <NEW_KEY_ID>
```

The export format is documented in `src/keystore.rs`. The
password is read interactively unless `AION_KEY_PASSWORD` is
set in the environment.

## `aion key delete`

```bash
aion key delete <KEY_ID> [--force]
```

Without `--force`, the CLI prompts for confirmation. Deletion
is permanent at the keystore level — the only recovery is
re-import from a previously exported backup file.

## Key conventions

The crate has no convention enforced at the type level for how
operators name their keys, but the worked examples in this
book use:

| Range | Purpose |
|---|---|
| `100_001`–`499_999` | Operational keys (sign versions) |
| `1_000_000` + above | Master keys (authorize rotations) |

So a CCO operational key might be `250_001`, paired with a
master key `1_250_001`. The book examples follow this pattern;
tests use `40xxxx` / `50xxxx` ranges to stay out of the way.

## Where the keys live

- **Linux** with libsecret: `secret-tool list` shows the
  aion-context entries.
- **macOS**: Keychain Access app, search "aion".
- **Windows**: Credential Manager, "Web Credentials" panel.
- **Fallback file-based keystore**: under `~/.aion/keys/` (path
  configurable via `AION_KEYSTORE_DIR`).

The file-based fallback is encrypted with Argon2-derived keys
from a master password set at first use.

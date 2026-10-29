# credstore

Cross-platform credential storage — OS keyring with AES-encrypted file backup.

A standalone secret manager. It was originally extracted from [Slife](https://github.com/juzcn/slife), which uses it as its credential store, but credstore has **no dependency on Slife**. Declares four runtime dependencies: `keyring`, `keyrings-cryptfile`, `jaraco.classes`, and `pywin32-ctypes` (Windows only).

Supports **Windows**, **macOS** (GUI + headless), **Linux** (desktop + headless), and **WSL** (Windows Credential Manager via a PowerShell bridge).

## Install

Requires **Python ≥ 3.13**.

```bash
pip install credstore
# or, in an isolated environment:
uv tool install --force --python '>=3.13' credstore
```

> `--python '>=3.13'` is not optional. Without it `uv` builds the tool
> environment on whichever interpreter it prefers and then installs the newest
> release compatible with *that* Python — which on a 3.12 environment is the
> long-superseded 0.9.0, not the current release. With the constraint, uv
> fetches a suitable interpreter or fails loudly.

One-click installers (install `uv` if needed, then `uv tool install --force
--python '>=3.13' credstore`):

```bash
# macOS / Linux / WSL
curl -fsSL https://raw.githubusercontent.com/juzcn/credstore/main/install.sh | bash

# Windows PowerShell
powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/juzcn/credstore/main/install.ps1 | iex"
```

The installers and the `--force` form are **idempotent** — the first run
installs, re-running **updates** to the latest PyPI release.  A plain
`uv tool install credstore` no-ops when the tool is already installed.
Uninstall with `uninstall.sh` / `uninstall.ps1` (user data under
`~/.credstore/` is left in place).

Verify: `credstore status`

No configuration needed. Run `credstore set-password` to enable encrypted backup.

## CLI

All secret entry uses masked input — each keystroke echoes `*`, paste works, the actual value is never displayed or logged.

> **Interactive terminal required.** Every command except `status`, `remove`, and `uninject` reads from an interactive TTY (`@requires_tty`); run them from a real terminal, not a piped shell or CI step. `remove` runs headless: the primary-store copy is deleted, and only the backup cleanup waits for a terminal (see note ²).

### Setup

```bash
credstore set-password    # creates ~/.credstore/credentials.crypt (or change the master key)
```

Path overridable via the `CREDSTORE_FILE` env var.

Changing the master key writes a **new** file and moves the old one to
`credentials.crypt.bak` (alongside it, same `CREDSTORE_FILE` override). The
backup is kept deliberately: it is the only copy of your credentials if
re-encrypting under the new key fails part-way, and it still opens with the
old password.

### Key names in the backup

Keys are matched case-sensitively in both stores. Inside the encrypted file
they are not: `keyrings.cryptfile` escapes a key into an INI option name and
configparser folds that name to lower case (`gh/cli-token` →
`gh_2fcli_2dtoken`), while the original spelling is bound into the entry's
AEAD associated data. The file alone therefore cannot tell `myapp/api_key`
from `MYAPP/API_KEY` — and a lookup with the wrong spelling fails its MAC
check rather than returning the wrong secret. Reads of the backup handle this
by trying the spellings that could have produced the stored name:

- `reset-keyring` and a `set-password` change ask the system keyring for each
  entry's spelling where the platform can enumerate it (Windows, WSL — the
  only source that can recover a mixed-case key like `myApp/ApiKey`); on macOS
  and Linux they try the upper- and lower-case forms of the recovered name.
- An entry that decrypts under none of those spellings is **reported**, not
  silently dropped. Re-set it with `credstore set KEY` using the spelling it
  was stored under; where the keyring can be listed, `credstore reset-backup`
  rewrites it from there.
- In the listing, a credential the keyring holds but the backup cannot read
  back under that name shows as `MISMATCH ⚠`.

### Commands

| Command | Master key | Description |
|---------|-----------|-------------|
| `set-password` | sets it | Create or change the master key (≥8 chars) |
| `status` | — | Show backend health |
| `set KEY` | required¹ | Atomic dual-write: cryptfile → primary store (keyring, or environment fallback). Rolls back on primary-store failure |
| `get KEY` | — | Primary store only, masked output (`sk-…b722`) |
| `get KEY -p` | prompted | Dual-query primary store + cryptfile, plaintext. Fails on mismatch |
| `remove KEY` | prompted² | Remove from both stores (best-effort) |
| `copy SOURCE DEST` | required¹ | Idempotent copy (primary store + cryptfile; both must already match). Re-injects dest to env if previously injected |
| *(no command)* | prompted³ | Triple-read: primary store + cryptfile + env. Shows sync status per key |
| `inject KEY… [--shell]` | — ³ | Persist to system env: registry (Win) or shell profile (Unix). Reads the primary store; falls back to the backup only when the key is missing there (prompts master pw) |
| `uninject KEY… [--shell]` | — | Remove from system env (in fallback mode, from the environment store too) |
| `reset-keyring` | prompted | Restore all from cryptfile → system keyring (disaster recovery) |
| `reset-env` | prompted | Restore all from cryptfile → environment fallback (no keyring available) |
| `reset-backup` | required¹ | Sync primary store → cryptfile |

¹ `set`, `copy`, and `reset-backup` are gated up front — they refuse to run until the master key has been set (`credstore set-password`).
² `remove` prompts for the master key to clean the cryptfile copy; the primary-store copy is removed regardless, including from a non-interactive shell, where the backup copy is skipped with a notice. With no backup yet (no `set-password` run) it prompts for nothing — there is nothing to clean up.
³ Master password prompted only if the primary store has no copy and the backup must be read.

`--shell` accepts `auto` (default), `bash`, `powershell`, or `cmd`.

### `get` Modes

| Mode | Reads from | Output | Use case |
|------|-----------|--------|----------|
| `get KEY` | Primary store only | Masked | Quick check, safe for screen sharing |
| `get KEY -p` | Primary store + cryptfile | Plaintext | Verify consistency, pipe to another tool |

`-p` mode performs a dual-query consistency check:

- Both stores have the value AND they match → prints plaintext
- One store missing → error with recovery instructions (in environment-fallback
  mode a missing environment copy still prints the backup's value, so the old
  cryptfile-only workflow keeps working)
- Values differ → error, tells you which tool to run

**Environment fallback** (no usable system keyring — e.g. Linux where keyctl is
blocked by policy): the environment takes the keyring's place. `set`/`copy`
dual-write the environment and the AES cryptfile; `get KEY`, `inject`, and the
Python API read the environment and need **no master password**; `status`
reports "environment fallback". The master password is only needed to unlock
the encrypted backup (`get -p`, `reset-env`, `remove`'s backup cleanup).

| Platform | Environment persistence |
|----------|-------------------------|
| Windows | `HKCU\Environment` (the `inject` store), plus the live process env |
| Unix | `~/.credstore/env` (mode 0600, `CREDSTORE_ENV_FILE` override), sourced from `~/.bashrc`, plus the live process env |

A key that is a valid environment variable name (`DEEPSEEK_API_KEY`) is stored
under its own name, so child processes see it directly. Any other key
(`myapp/provider/deepseek`) is stored under `CREDSTORE_KEY_` plus a reversible
escape (`/` → `_2F`, `_` → `__`). `CREDSTORE_`-prefixed keys are always escaped,
so a credential can never overwrite credstore's own `CREDSTORE_FILE` /
`CREDSTORE_KEYCHAIN` settings. Reads prefer the live environment: a value
supplied by the container runtime, CI, or a parent shell wins over the
persisted copy.

> ⚠️ **Plaintext at rest.** Unlike the keyring, environment variables are not
> encrypted. The cryptfile remains the encrypted copy; the fallback trades
> confidentiality at rest for password-free reads. `credstore status` warns
> when the fallback is active.

> **Python API in fallback mode.** `get_credential`, `exists_credential`, and
> `resolve_uri` read the environment fallback without prompting, so
> password-free startup resolution keeps working with no keyring. Only the
> encrypted backup is unavailable to them: with no environment copy (and no
> keyring), they return `None` / raise `KeyError`; reading the backup itself
> still requires the CLI and the master password.

### `inject` / `uninject`

`inject` reads a secret from the primary store (keyring, or the environment fallback) and persists it to the system environment:

| Platform | Persistence | Activation |
|----------|-------------|------------|
| Windows | Registry (`HKCU\Environment`) + broadcast | Restart shell, or `Invoke-Expression (credstore inject KEY)` |
| Unix | Shell profile (`~/.bashrc`) | New shell, or `eval "$(credstore inject KEY)"` |

When stdout is a TTY, `inject` prints an activation hint instead of the secret. The actual export command only flows through a pipe.

```bash
eval "$(credstore inject DEEPSEEK_API_KEY)"           # Bash/Zsh — activate now
Invoke-Expression (credstore inject DEEPSEEK_API_KEY)  # PowerShell — activate now
```

`uninject` reverses the operation — removes from registry or profile and prints the unset command. In environment-fallback mode it removes the variable from the environment store itself (the primary copy); the encrypted backup is left for `reset-env` to restore from.

### Default (bare) Output

```
  KEY                  SYSTEM KEYRING   CRYPTFILE        ENV    STATUS
  ────────             ──────────────   ──────────────   ────   ──────
  ANTHROPIC_API_KEY    ✔                ✔                —      synced
  DEEPSEEK_API_KEY     ✔                ✔                ✔      synced
  OPENAI_API_KEY       —                ✔                —      cryptfile only
  ────────             ──────────────   ──────────────   ────   ──────
  3 credential(s) — synced: 2, cryptfile only: 1, env: 1
```

| Column | Meaning |
|--------|---------|
| `SYSTEM KEYRING` | ✔ = stored in OS keyring; `?` = this platform cannot list the keyring |
| `CRYPTFILE` | ✔ = stored in encrypted backup |
| `ENV` | ✔ = currently set as environment variable |
| `STATUS` | `synced`, `keyring only`, `cryptfile only`, `MISMATCH ⚠`, or `in backup` (`?` keyring — nothing can be compared) |

In **environment-fallback** mode the first column is labelled `ENV FALLBACK`
and lists the environment copies; statuses and tips refer to it instead of the
keyring.

> On **macOS** and **Linux** the system keyring cannot be listed at all (no enumeration API), so the table shows `?` in that column, reports each credential as `in backup`, and gives no per-key sync verdict or tip — whether the keyring holds the credential cannot be checked there. Key names appear in their canonical (upper-case) form, since the file does not preserve the original case (see [Key names in the backup](#key-names-in-the-backup)). Only **Windows** and **WSL** enumerate Credential Manager directly.

## Memory Safety

Secrets are immutable Python `str` objects — they cannot be zeroed in place. Mitigations:

1. **Never batch-load** — `list` collects only key names. Sync comparison fetches one value at a time and immediately `del`s it.
2. **Prefer existence checks** — `exists_credential()` / `list_credential_keys()` never return secret content.
3. **Explicit cleanup** — every CLI handler `del`s secret references on all exit paths including error branches.

| Operation | Cleanup |
|-----------|---------|
| `get` / `get_credential()` | Caller must `del` the returned value |
| `set` | `del secret` + `del master_pw` after dual-write |
| `copy` | Same as `set`. Idempotent: skips if dest matches source. Re-injects dest to env if previously persisted |
| `list` | Values fetched one-at-a-time, compared, `del`ed immediately |
| `inject` | Value read → persisted → `del`ed. TTY: no secret on stdout |
| `reset-keyring` | Each value `del`ed after writing to the system keyring |
| `reset-env` | Each value `del`ed after writing to the environment store |
| `reset-backup` | Keyring path batch-loads (unavoidable); environment path reads one at a time |

`masked_input()` echoes `*` per keystroke — paste works, actual value never displayed.

## Python API

```python
import credstore

# Read / check / delete (primary store only, no prompt)
credstore.get_credential("myapp/api_key")      # → str | None
credstore.exists_credential("myapp/api_key")   # → bool  (NEVER returns secret)
credstore.list_credential_keys()               # → list[str]  (NEVER returns values)
credstore.set_credential("myapp/api_key", "sk-…")
credstore.delete_credential("myapp/api_key")   # → bool

# keyring: URI resolution
credstore.is_keyring_uri("keyring:myapp/k")    # → True
credstore.resolve_uri("keyring:myapp/k")       # → the secret value (or KeyError)
credstore.parse_keyring_uri("keyring:srv/k")   # → ("srv", "k") | None

# Shell formatting
credstore.format_export("KEY", "secret", "bash")   # → "export KEY='secret'"
credstore.format_unset("KEY", "bash")              # → "unset KEY"

# Environment persistence (programmatic form of `inject` / `uninject`)
credstore.persist_key("KEY", "secret", "bash")     # registry (Win) / profile (Unix)
credstore.unpersist_key("KEY", "bash")             # remove from system environment

# Diagnostics
credstore.init_store()              # → CredentialStore (explicit lazy init)
credstore.check_backend()           # → {"available": True, "backend": "…", …}
credstore.get_backend_name()        # → "system keyring + cryptfile (dual-write)"
```

**Python API talks to the primary store only** — no master password, no prompt. That is the system keyring, or the environment fallback when no keyring is available (in which case reads and writes work without the master password). Dual-write (primary store + cryptfile) is handled by the CLI. Two exceptions worth noting:

- `set_credential()` writes only to the primary store, but it still **requires the master key to have been set** (`credstore set-password` run once — the cryptfile must exist) and raises `RuntimeError` otherwise. This is deliberate: a secret is never written to the primary store without an encrypted backup to survive OS password changes. It never prompts.
- `get_credential()` and `resolve_uri()` return `None` / raise `KeyError` when the primary store has no copy — the API never unlocks the cryptfile. Only the CLI can read the encrypted backup, which requires the master password.

Callers of `get_credential()` and `resolve_uri()` must `del` the returned value after use. Prefer `exists_credential()` when you only need to know if a credential exists. `reset_credentials()` (for `reset-keyring`) and `reset_environment_credentials()` (for `reset-env`) exist internally for the CLI but are not part of the public package API.

## Configuration

The encrypted credential file's path is resolved by precedence:

1. `CREDSTORE_FILE=<path>` (env var)
2. `~/.credstore/credentials.crypt` (default)

The environment-fallback file (used only when no system keyring is available)
is resolved separately:

1. `CREDSTORE_ENV_FILE=<path>` (env var)
2. `~/.credstore/env` (default; mode 0600, sourced from `~/.bashrc`)

Resolution never depends on the current directory — not even credstore's own
source tree: the system keyring is shared between a checkout and a production
install, so a checkout-local cryptfile forked the backup rather than isolating
anything.

## Architecture

### Backend Matrix

Backend selection is **deterministic by platform** — no keyring auto-discovery. Exactly five platform configurations are supported; anything else is rejected with a clear error.

| Platform | Backend | Mechanism |
|----------|---------|-----------|
| **Windows** | `WinVaultKeyring` | Windows Credential Manager (Vault API, via keyring) |
| **WSL** | `WslBackend` | PowerShell → advapi32.dll CredReadW/CredWriteW (C# P/Invoke) — same CredMan store as Windows |
| **macOS** (GUI) | `macOS.Keyring` | macOS login keychain |
| **macOS** (headless) | `macOS.Keyring` + isolated keychain | `CREDSTORE_KEYCHAIN` (or `~/.credstore/credentials.keychain-db`); auto-created via `security create-keychain` |
| **Linux** | `KeyutilsBackend` | Kernel persistent keyring (`@p`) via `add_key`/`keyctl` syscalls (ctypes, zero extra deps) |

`WslBackend` (priority 9.5) and `KeyutilsBackend` (priority 1.5) are also registered as standard `keyring.backends` entry points, so they participate correctly in keyring's own priority chain for external consumers — but credstore's own dispatch selects them directly, never by discovery.

### Dual-Write Flow

```
┌──────────────────────────────────────────────────┐
│  CLI (__main__.py)                               │
│  Interactive: masked_input(), master password     │
│  Atomic dual-write: cryptfile → primary store     │
│  Rollback on primary-store failure                │
├──────────────────────────────────────────────────┤
│  Python API (__init__.py)                        │
│  Programmatic: no prompt, primary store only      │
├────────────────────┬─────────────────────────────┤
│  Primary Store     │  Cryptfile Backup           │
│  keyring or env    │  (encrypted)                │
│  ────────────────  │  ───────────────────────    │
│  Win CredMan       │  keyrings.cryptfile         │
│  WSL (PowerShell)  │  AES-encrypted INI          │
│  macOS Keychain    │  Survives OS pw changes     │
│  Linux keyutils    │                             │
│  environment *     │                             │
└────────────────────┴─────────────────────────────┘

* Environment fallback: used only where no keyring backend is usable.
```

### WSL Backend

On WSL, no Linux desktop keyring is available. `WslBackend` bridges to Windows Credential Manager by calling `powershell.exe` with embedded C# that P/Invokes `advapi32.dll` (`CredReadW`, `CredWriteW`, `CredDeleteW`). Because it targets CredMan directly, WSL and native Windows share the same credential store — `credstore set` on either side is visible on the other. It also reads the native-Windows layout (`TargetName = service`, key in the `UserName` field) so credentials written by `WinVaultKeyring` resolve correctly on WSL. Unlike platform auto-discovery, `WslBackend` is selected deterministically (no priority roulette).

### Keyutils Backend

On Linux (desktop and headless alike), `KeyutilsBackend` stores credentials in the Linux kernel's persistent keyring (`@p`). Calls `add_key` and `keyctl` syscalls directly through `ctypes` — zero Python dependencies beyond stdlib. Each credential is a `"user"` key with description `"credstore:<service>/<key>"`. Syscall numbers are hard-coded per architecture — `x86_64`, `i686`, `aarch64`, `armv7l`, `ppc64le`, `s390x`, `riscv64` — and taken from the kernel's own syscall tables; a machine outside that list is rejected rather than guessed at. If the kernel keyring is unavailable (e.g. keyctl blocked by seccomp on an HPC login node), credstore degrades to **environment-fallback** mode: `set` dual-writes the environment and the AES backup, `get`/`inject`/the Python API read the environment with no master password, `get -p`/`set-password`/`status`/`remove` keep working, and the reason is visible in `credstore status`. A fully unsupported platform still raises rather than picking a wrong backend.

### Environment Fallback

Used when a supported platform has no usable keyring backend (Linux with
keyctl blocked, a Windows host whose Credential Manager is unreachable).
`_envstore.py` gives the environment the keyring's role:

- `set` dual-writes: encrypted backup first, then the environment; a failed
  environment write rolls the backup entry back, exactly like a failed keyring
  write.
- `get`, `inject`, and `get_credential()`/`resolve_uri()` read the environment
  and never prompt. `get -p` still compares the environment copy with the
  backup and reports drift.
- `reset-keyring` refuses without a keyring and points at `reset-env`, which
  restores the backup into the environment.
- `reset-backup` syncs the environment back into the encrypted backup: escaped
  (`CREDSTORE_KEY_*`) entries plus every key the backup already knows, matched
  case-insensitively so the original spelling is kept. A bare-name variable
  the backup does not know cannot be enumerated and is reported as skipped.
- Windows persists to `HKCU\Environment`; Unix persists to
  `~/.credstore/env` (0600, sourced from `~/.bashrc`) and also reads it
  directly, so non-interactive processes work even when no profile is loaded.
- Reads prefer the live process environment, so a container runtime or CI can
  supply the value without `credstore set` at all.

Environment variables are plaintext. This is the deliberate trade-off of the
fallback; the cryptfile stays the encrypted copy.

### macOS Backend

macOS uses `keyring.backends.macOS.Keyring` (the login keychain) in GUI sessions. For headless macOS (CI, servers) — where login-keychain interaction would fail with `errSecInteractionNotAllowed` — set `CREDSTORE_KEYCHAIN` to an isolated keychain path, or let credstore use `~/.credstore/credentials.keychain-db`; the file is created automatically via `security create-keychain` on first use.

### Credential Enumeration

`credstore` (the default, no-command view) reads keys from the OS credential store using platform-specific APIs:

| Platform | API |
|----------|-----|
| **Windows** | `win32cred.CredEnumerate` |
| **WSL** | `powershell.exe` + inline C# `CredEnumerateW` via `advapi32.dll` |
| **Other** | Unsupported — the listing uses the environment fallback and the cryptfile's key names |

Enumeration retrieves key names only — secret values are never batch-loaded. On WSL the PowerShell bridge is told not to read the credential blobs at all unless values are actually wanted, so a listing never moves secrets out of Credential Manager. Sync comparison fetches one value at a time and immediately discards it.

## Development

Requires [uv](https://docs.astral.sh/uv/).

```bash
uv sync --locked     # create .venv with runtime + dev dependencies
uv run pytest        # run the test suite
uv run ruff check    # lint
uv run ruff format   # format
uv run pyright       # type-check
```

CI runs the suite on Windows, macOS, and Linux (`.github/workflows/ci.yml`), plus lint and type-check jobs.

### Releasing

Bump `version` in `pyproject.toml`, commit, then push a tag with the same
version:

```bash
git tag -a v0.10.8 -m "credstore 0.10.8" && git push origin v0.10.8
```

`.github/workflows/publish.yml` fails unless the tag matches the package
version exactly, then uploads to PyPI via trusted publishing.

## License

MIT

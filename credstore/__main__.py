"""credstore CLI — terminal commands for credential management.

All secret input uses masked_input() — each keystroke echoes ``*``,
paste works, but the actual value is never visible or logged.

Commands::

    credstore set-password        Set/change cryptfile master password
    credstore status              Show backend status
    credstore set <key>           Store a credential (primary store + cryptfile)
    credstore get <key>           Retrieve (primary store only, masked)
    credstore remove <key>        Remove a credential
    credstore copy <src> <dst>    Copy a credential to a new key
    credstore (no command)       List credentials (primary store + cryptfile + env)
    credstore reset-keyring       Restore keyring from cryptfile backup
    credstore reset-env           Restore the environment fallback from cryptfile
    credstore reset-backup        Sync primary store → cryptfile backup
    credstore inject KEY...       Print shell export commands (for eval)
    credstore uninject KEY...     Print shell unset commands (cleanup)

Module layout::

    _store.py        CredentialStore + module-level API
    _shell.py        Shell formatting (format_export / format_unset)
    _backend.py      Dual-write backends + unlocked_cryptfile
    _envstore.py     Environment fallback (no OS keyring)
    _enumerate.py    Platform-specific credential enumeration
    _config.py       Config file loading + cryptfile path resolution
    _resolver.py     keyring: URI resolution
    _tty.py          Masked terminal input (cross-platform)
"""

from __future__ import annotations

import argparse
import functools
import os
import sys

from credstore import _backend as backend_mod
from credstore import _config as config_mod
from credstore import _envstore
from credstore import _store as store_mod
from credstore._enumerate import enumerate_system_keyring as _enumerate_system_keyring
from credstore._enumerate import enumeration_supported
from credstore._shell import (
    format_export,
    format_unset,
    is_injected,
    persist_key,
    resolve_shell,
    unpersist_key,
)
from credstore._tty import masked_input

# ── Helpers ────────────────────────────────────────────────────────────


def _err(msg: str) -> None:
    """Print an error message to stderr."""
    print(f"Error: {msg}", file=sys.stderr)


def requires_tty(func):
    """Decorator: require an interactive terminal for CLI commands."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not sys.stdin.isatty():
            # Subcommand names are dashed on the command line ("set-password"),
            # but the handler's suffix is underscored ("_cmd_set_password") —
            # without the second replace the user was told to run the
            # non-existent "credstore set_password".
            cmd = func.__name__.replace("_cmd_", "").replace("_", "-")
            # _cmd_list is the bare-command default — no subcommand to name.
            shown = "credstore" if cmd == "list" else f"credstore {cmd}"
            _err(f"'{shown}' requires an interactive terminal.")
            return 1
        return func(*args, **kwargs)

    return wrapper


# ── Command dispatch table ─────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for credstore CLI."""
    parser = argparse.ArgumentParser(
        prog="credstore",
        description="Secure credential storage: OS keyring, encrypted backup, "
        "environment fallback.",
        epilog="Run 'credstore' with no subcommand to list credentials from "
        "the primary store (keyring or environment fallback), the encrypted "
        "backup, and environment variables.",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser(
        "set-password",
        help="Set or change the cryptfile master password (interactive)",
        description="Create or change the master password that encrypts the "
        "cryptfile backup. Requires an interactive terminal.",
    )
    sub.add_parser(
        "status",
        help="Show backend status",
        description="Show the active primary store, whether the encrypted "
        "backup is ready, and where the environment fallback is kept.",
    )

    set_p = sub.add_parser(
        "set",
        help="Store a credential (primary store + encrypted backup)",
        description="Store a secret in the primary store (system keyring, or "
        "the environment fallback) and in the encrypted backup. Prompts for "
        "the secret and the master password.",
    )
    set_p.add_argument("key", help="Credential key, e.g. 'myapp/provider/deepseek'")

    get_p = sub.add_parser(
        "get",
        help="Retrieve a credential from the primary store (masked output)",
        description="Retrieve a credential from the primary store. The output "
        "is masked by default; --password prints the plaintext after checking "
        "it against the encrypted backup.",
    )
    get_p.add_argument("key", help="Credential key to retrieve")
    get_p.add_argument(
        "--password",
        "-p",
        action="store_true",
        help="Dual-query the primary store + cryptfile, output plaintext; "
        "fail on mismatch",
    )

    del_p = sub.add_parser(
        "remove",
        help="Remove a credential from the primary store and backup",
        description="Remove a credential from the primary store and the "
        "encrypted backup. Both removals are best effort.",
    )
    del_p.add_argument("key", help="Credential key to delete")

    copy_p = sub.add_parser(
        "copy",
        help="Copy a credential to a new key (primary store + encrypted backup)",
        description="Copy a credential to a new key in both stores. "
        "Idempotent: a destination that already matches in both stores is a "
        "no-op.",
    )
    copy_p.add_argument("source", help="Source credential key")
    copy_p.add_argument("dest", help="Destination credential key")

    sub.add_parser(
        "reset-keyring",
        help="Restore all credentials from cryptfile backup to the system keyring",
        description="Restore every credential from the encrypted backup into "
        "the system keyring. Requires the master password.",
    )
    sub.add_parser(
        "reset-env",
        help="Restore all credentials from cryptfile backup to the environment fallback",
        description="Restore every credential from the encrypted backup into "
        "the environment fallback, used when no system keyring is available. "
        "Requires the master password and writes plaintext environment values.",
    )
    sub.add_parser(
        "reset-backup",
        help="Sync credentials from the primary store to the cryptfile backup",
        description="Overwrite the encrypted backup with the credentials in "
        "the primary store (system keyring, or the environment fallback). "
        "Requires the master password.",
    )

    inject_p = sub.add_parser(
        "inject",
        help="Persist credentials to system environment",
        description="Read credentials from the primary store and persist them "
        "to the system environment (registry on Windows, shell profile on "
        "Unix). Prints the shell export command for the current session.",
    )
    inject_p.add_argument(
        "keys", nargs="+", metavar="KEY", help="Credential keys to export as env vars"
    )
    inject_p.add_argument(
        "--shell",
        choices=["auto", "bash", "powershell", "cmd"],
        default="auto",
        help="Shell format (default: auto-detect)",
    )

    uninject_p = sub.add_parser(
        "uninject",
        help="Remove credentials from system environment",
        description="Remove credentials from the system environment and, in "
        "environment-fallback mode, from the persisted environment store.",
    )
    uninject_p.add_argument(
        "keys",
        nargs="+",
        metavar="KEY",
        help="Credential keys to remove from the environment",
    )
    uninject_p.add_argument(
        "--shell",
        choices=["auto", "bash", "powershell", "cmd"],
        default="auto",
        help="Shell format (default: auto-detect)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns exit code."""
    if argv is None:
        argv = sys.argv[1:]

    parser = _build_parser()
    args = parser.parse_args(argv)

    # Gate: 'set' / 'reset-backup' require cryptfile to exist
    if args.command in ("set", "copy", "reset-backup"):
        store_mod.init_store()
        if not backend_mod.has_master_key():
            _err("master key not set.")
            print("Run 'credstore set-password' first.", file=sys.stderr)
            return 1

    # Dispatch via explicit routing (clearer than dict for argument-passing)
    try:
        if args.command is None:
            return _cmd_list()
        elif args.command == "set-password":
            return _cmd_set_password()
        elif args.command == "status":
            return _cmd_status()
        elif args.command == "set":
            return _cmd_set(args.key)
        elif args.command == "get":
            return _cmd_get(args.key, password_mode=args.password)
        elif args.command == "remove":
            return _cmd_remove(args.key)
        elif args.command == "copy":
            return _cmd_copy(args.source, args.dest)
        elif args.command == "reset-keyring":
            return _cmd_reset_keyring()
        elif args.command == "reset-env":
            return _cmd_reset_env()
        elif args.command == "reset-backup":
            return _cmd_reset_backup()
        elif args.command == "inject":
            return _cmd_inject(args.keys, args.shell)
        elif args.command == "uninject":
            return _cmd_uninject(args.keys, args.shell)
        else:
            parser.print_help()
            return 1
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 130
    except Exception as exc:  # noqa: BLE001 — top-level guard: report, not traceback
        _err(str(exc))
        return 1


# ── Command implementations ──────────────────────────────────────


# ── set-password helpers ──────────────────────────────────────────


def _read_old_cryptfile_data() -> dict[str, str]:
    """Unlock existing cryptfile with the user's old password.

    Reads all stored credentials into a dict, keyed by the spelling each
    entry is sealed with (so re-encrypting under the new password keeps
    them readable).  Returns empty dict if the cryptfile exists but has no
    entries.  Raises ``ValueError`` on wrong password; raises
    ``RuntimeError`` if the cryptfile backend is not available.

    An entry that cannot be read back is reported on stderr as it is
    skipped — dropping it silently would quietly shrink the backup.
    """
    backend_mod.init_backend()
    cf = backend_mod.get_cryptfile()
    if cf is None:
        raise RuntimeError("cryptfile backend not available")

    spellings = store_mod.keyring_key_spellings(store_mod.DEFAULT_SERVICE)
    old_pw = masked_input("Current master password: ")
    skipped: list[str] = []
    try:
        with backend_mod.unlocked_cryptfile(old_pw) as cf_ctx:
            keys = store_mod._read_cryptfile_keys(cf_ctx)
            data: dict[str, str] = {}
            for key in keys:
                try:
                    entry = store_mod.resolve_cryptfile_entry(
                        cf_ctx, key, store_mod.DEFAULT_SERVICE, spellings
                    )
                except Exception:  # noqa: BLE001 — unreadable key, skip it
                    # Any failure reading one key means it simply is not
                    # carried over; the rest of the store still is.
                    skipped.append(key)
                    continue
                if entry is not None:
                    name, value = entry
                    data[name] = value
    except Exception:  # noqa: BLE001 — normalize any failure to "bad password"
        del old_pw
        raise ValueError("incorrect password or corrupted file")
    del old_pw

    if skipped:
        print(
            f"Warning: {len(skipped)} credential(s) could not be read back "
            f"from the existing backup: {', '.join(skipped)}",
            file=sys.stderr,
        )
        print(
            "  The file folds key names to lower case, so an entry that does "
            "not decrypt under the spellings that could have produced it "
            "cannot be read back — it is NOT carried into the new backup.",
            file=sys.stderr,
        )
        print(
            f"  The old file is kept as {config_mod.get_cryptfile_path()}.bak — "
            + (
                "run 'credstore reset-backup' once the new password is set to "
                "put them back from the system keyring."
                if enumeration_supported()
                else "it still opens with the old password, so re-run "
                "'credstore set <KEY>' for these keys under the spelling they "
                "were stored with."
            ),
            file=sys.stderr,
        )
    return data


def _re_encrypt_old_data(cf_new, old_data: dict[str, str]) -> int:
    """Re-encrypt old credentials into the new cryptfile.

    Returns the number of successfully re-encrypted credentials.
    Cleans up *old_data* after processing.
    """
    synced = 0
    for key, value in old_data.items():
        try:
            cf_new.set_password(store_mod.DEFAULT_SERVICE, key, value)
            synced += 1
        except Exception:  # noqa: BLE001, S112 — unwritable key, skip it
            # One key that cannot be written must not abort re-encryption
            # of all the others; ``synced`` reports what made it across.
            continue
    del old_data
    return synced


@requires_tty
def _cmd_set_password() -> int:
    """Interactively set or change the cryptfile master password."""
    print("Set master password for encrypted credential backup.")
    print()

    crypt_path = config_mod.get_cryptfile_path()
    is_change = os.path.exists(crypt_path)

    # ── Read existing data (change mode only) ──
    old_data: dict[str, str] = {}
    if is_change:
        print("Changing existing master password.")
        try:
            old_data = _read_old_cryptfile_data()
        except RuntimeError as exc:
            _err(str(exc))
            return 1
        except ValueError as exc:
            del old_data
            _err(str(exc))
            return 1
        print(f"  Read {len(old_data)} credential(s) from existing backup.")
        print()

    # ── Prompt for new password ──
    pw1 = masked_input("New master password: ")
    if len(pw1) < 8:
        del pw1
        _err("password must be at least 8 characters.")
        return 1

    pw2 = masked_input("Confirm password: ")
    if pw1 != pw2:
        del pw2
        del pw1
        _err("passwords do not match.")
        return 1
    del pw2

    # ── Write new cryptfile ──
    # ``replace_existing`` on the change path: the current file is encrypted
    # with the OLD password, and the keyring key setter only unlocks — a new
    # password needs a new file.
    backend_mod.reinit_cryptfile(pw1, replace_existing=is_change)
    del pw1

    if not backend_mod.has_master_key():
        _err("could not initialize cryptfile backend.")
        return 1

    cf_new = backend_mod.get_cryptfile()
    if cf_new is None:
        _err("cryptfile backend lost after init — aborting.")
        return 1

    if is_change and old_data:
        synced = _re_encrypt_old_data(cf_new, old_data)
        print(f"Master password changed. {synced} credential(s) re-encrypted.")
    else:
        print("Master password set.")

    return 0


def _cmd_status() -> int:
    """Show backend diagnostic info."""
    info = store_mod.check_backend()
    print(f"Backend: {info.get('backend', 'unknown')}")
    print(f"Available: {info.get('available', False)}")

    if info.get("cryptfile_ready"):
        if info.get("env_fallback"):
            print("Cryptfile: ready (environment fallback, dual-write active)")
            if "cryptfile_path" in info:
                print(f"  File: {info['cryptfile_path']}")
            if "env_file" in info:
                print(f"  Env:  {info['env_file']}")
            print()
            print("No system keyring available — the environment is the primary store.")
            print("Secrets are written to the environment and the AES cryptfile;")
            print("'credstore get KEY' needs no master password.")
            print("WARNING: environment variables are plaintext. The cryptfile is the")
            print("encrypted copy; keep its master password safe.")
        else:
            print("Cryptfile: ready (dual-write active)")
            if "cryptfile_path" in info:
                print(f"  File: {info['cryptfile_path']}")
            print()
            print("Dual-write: system keyring + cryptfile encrypted backup.")
            print("Safe from OS password changes — data auto-restores from cryptfile.")
    elif info.get("cryptfile_locked") is not None:
        print("Cryptfile: LOCKED (master password not set)")
        if "cryptfile_path" in info:
            print(f"  File: {info['cryptfile_path']}")
        print()
        if info.get("env_fallback"):
            print("No system keyring available — the environment is the primary store.")
            print("Run 'credstore set-password' to enable the encrypted backup.")
        else:
            print("Secrets are stored in system keyring only.")
            print("WARNING: Changing your OS login password may erase all secrets.")
            print("Run 'credstore set-password' to enable cryptfile backup.")
    else:
        print("Cryptfile: not installed")
        print()
        if info.get("env_fallback"):
            print("No system keyring available — the environment is the primary store.")
        else:
            print("Secrets are stored in system keyring only.")
        print(
            "Install keyrings.cryptfile for encrypted backup: pip install keyrings.cryptfile"
        )
    return 0


@requires_tty
def _cmd_set(key: str) -> int:
    """Store a credential: cryptfile + primary store (atomic dual-write).

    The primary store is the system keyring, or the environment fallback when
    the OS has no usable keyring.  Writes to cryptfile FIRST, then the primary
    store.  If the primary write fails, rolls back the cryptfile entry so both
    stores stay consistent.
    """
    cf = backend_mod.get_cryptfile()
    if cf is None:
        _err("cryptfile backend not available.")
        print("Install: pip install keyrings.cryptfile", file=sys.stderr)
        return 1

    print(f"Enter secret for '{key}' (paste then press Enter):")
    try:
        secret = masked_input("")
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 130

    if not secret.strip():
        del secret
        _err("secret cannot be empty.")
        return 1

    master_pw = masked_input("Master password (for encrypted backup): ")

    # 1. Write cryptfile first (backup)
    try:
        with backend_mod.unlocked_cryptfile(master_pw) as cf:
            cf.set_password(store_mod.DEFAULT_SERVICE, key, secret)
    except ValueError as exc:
        del secret
        del master_pw
        _err(str(exc))
        return 1

    # 2. Write the primary store — system keyring, or the environment
    #    fallback when the OS has no usable keyring.
    keyring_available = backend_mod.get_system_keyring() is not None
    try:
        store_mod.set_credential(key, secret)
    except Exception as exc:  # noqa: BLE001 — report any write failure to the user
        # Rollback: remove from cryptfile
        try:
            with backend_mod.unlocked_cryptfile(master_pw) as cf:
                cf.delete_password(store_mod.DEFAULT_SERVICE, key)
        except Exception:  # noqa: BLE001, S110 — rollback is best effort
            # The original write error is what gets reported; a failed
            # rollback must not mask it.
            pass
        del secret
        del master_pw
        _err(str(exc))
        return 1

    del secret
    del master_pw
    print(f"Stored: {key}")
    if not keyring_available:
        print(
            "  (no system keyring — stored in the environment fallback"
            " and the encrypted backup)",
            file=sys.stderr,
        )
        _print_inject_activation("auto", key)
    return 0


@requires_tty
def _cmd_get(key: str, password_mode: bool = False) -> int:
    """Retrieve a credential.

    Default mode: primary store only (keyring, or the environment fallback),
    masked output.
    --password mode: dual-query the primary store + cryptfile, plaintext,
    fail on mismatch.
    """
    # -- Default mode: primary store only, masked --
    if not password_mode:
        value = store_mod.get_credential(key)
        if value is None:
            where = (
                "system keyring"
                if backend_mod.get_system_keyring() is not None
                else "environment fallback"
            )
            _err(f"Not found in {where}: {key}")
            return 1
        print(f"{key}: {store_mod.CredentialStore.mask(value)}")
        del value
        return 0

    # -- Password mode: dual-query with consistency check --
    # **Initialise before asking the backend whether a backup exists.**
    # `has_master_key()` reads `_cryptfile`, which is None until
    # `init_backend()` has run.  Initialising on module import is deliberately
    # not done (the platform probe is expensive), and the default `get` path
    # reached here without it — so a store whose `credentials.crypt` was
    # present still answered "no encrypted backup yet" and refused to read it.
    backend_mod.init_backend()
    # No backup to compare against.  Checked before prompting: the master
    # password would be asked for nothing, and unlocking a missing cryptfile
    # creates it (see _backend.unlocked_cryptfile).
    if not backend_mod.has_master_key():
        _err("no encrypted backup yet — there is nothing to compare against.")
        print("Run 'credstore set-password' first.", file=sys.stderr)
        return 1

    master_pw = masked_input("Master password: ")
    if not master_pw.strip():
        del master_pw
        _err("master password is required in --password mode.")
        return 1

    value_primary = store_mod.get_credential(key)

    value_cf = None
    cf_error: str | None = None
    try:
        value_cf = backend_mod.read_cryptfile_entry(
            key, master_pw, store_mod.DEFAULT_SERVICE
        )
    except Exception as exc:  # noqa: BLE001 — surfaced to the user as cf_error
        cf_error = str(exc)

    # Environment-fallback mode: the environment takes the keyring's place as
    # the primary store, so the same consistency check applies.  The backup is
    # still authoritative when the environment copy is missing (the profile
    # may not have been loaded yet) — that preserves the old cryptfile-only
    # behaviour of printing the backup's value.
    fallback = backend_mod.get_system_keyring() is None
    where = "environment fallback" if fallback else "system keyring"

    if fallback and value_primary is None and value_cf is not None:
        del master_pw
        print(
            f"{key} — found in cryptfile but missing from the environment "
            "fallback. Run 'credstore reset-env' to restore it.",
            file=sys.stderr,
        )
        print(value_cf)
        del value_cf
        return 0

    # Guard clauses — each branch returns early
    if value_primary is None and value_cf is None:
        del master_pw
        detail = f" ({cf_error})" if cf_error else ""
        _err(f"Not found in either store: {key}{detail}")
        return 1

    if value_primary is None:
        del value_cf
        del master_pw
        _err(f"{key} — found in cryptfile but missing from {where}.")
        print(
            "Run 'credstore reset-keyring' to restore all credentials from backup.",
            file=sys.stderr,
        )
        return 1

    if value_cf is None:
        del value_primary
        del master_pw
        msg = (
            f"cryptfile read failed: {cf_error}"
            if cf_error
            else f"{key} — found in {where} but missing from cryptfile backup."
        )
        _err(msg)
        print(
            "Run 'credstore reset-backup' to sync the primary store → cryptfile."
            if not fallback and enumeration_supported()
            else "Re-run 'credstore set' to write the credential into the backup.",
            file=sys.stderr,
        )
        return 1

    if value_primary != value_cf:
        del value_cf
        del value_primary
        del master_pw
        _err(f"{key} — value mismatch between {where} and cryptfile.")
        print(
            "The two stores have diverged. Determine the correct value, then:",
            file=sys.stderr,
        )
        if fallback:
            print(
                "  credstore reset-env       to take the backup's value",
                file=sys.stderr,
            )
            print(
                f"  credstore set {key}       to write the current value to both",
                file=sys.stderr,
            )
        else:
            print(
                "  credstore reset-backup   if keyring is authoritative",
                file=sys.stderr,
            )
            print(
                "  credstore reset-keyring  if cryptfile is authoritative",
                file=sys.stderr,
            )
        return 1

    # Match — output plaintext
    del value_cf
    del master_pw
    print(value_primary)
    del value_primary
    return 0


# ── inject / uninject ──────────────────────────────────────────


def _cmd_inject(keys: list[str], shell: str) -> int:
    """Persist credentials to system environment + print export for current shell.

    For each KEY:
      1. Read the secret from the primary store — the system keyring, or the
         environment fallback when no keyring is available.  If the primary
         store has no copy but the encrypted backup does (backup-only
         recovery), read the backup, prompting once for the master password.
      2. Persist: registry (Windows) or shell profile (Unix) — in fallback
         mode the environment store itself gains the value.
      3. Print the export command for immediate eval.
      4. ``del`` the secret immediately.

    Not gated on a TTY: keyring and environment-fallback modes need no input,
    so injection works from scripts and shell profiles. Only the cryptfile
    recovery path (which prompts for the master password) needs a terminal.
    """
    for key in keys:
        value = store_mod.get_credential(key)
        if value is None and backend_mod.get_system_keyring() is None:
            # No keyring and no environment copy: read from the encrypted
            # backup. Needs the master password, which can only be read
            # interactively.
            if not sys.stdin.isatty():
                _err(
                    f"'{key}' is only in the encrypted backup; reading it "
                    "requires an interactive terminal."
                )
                return 1
            master_pw = masked_input("Master password (for encrypted backup): ")
            try:
                value = backend_mod.read_cryptfile_entry(
                    key, master_pw, store_mod.DEFAULT_SERVICE
                )
            except Exception as exc:  # noqa: BLE001 — reported as "not found"
                del master_pw
                _err(f"'{key}' not found in the environment or cryptfile: {exc}")
                return 1
            del master_pw
        if value is None:
            where = (
                "system keyring"
                if backend_mod.get_system_keyring() is not None
                else "environment fallback"
            )
            _err(
                f"'{key}' is not stored in the {where}.\n"
                f"Store it first: credstore set {key}"
            )
            return 1

        if backend_mod.get_system_keyring() is None:
            # The environment is the store here.  Persisting the value makes
            # the next read password-free; the profile-source line that
            # `persist_key` would add is already managed by _envstore.
            _envstore.store_secret(key, value)
        else:
            persist_key(key, value, shell)

        if sys.stdout.isatty():
            _print_inject_activation(shell, key)
        else:
            print(format_export(key, value, shell))
        del value

    return 0


def _cmd_uninject(keys: list[str], shell: str) -> int:
    """Remove from system environment + print unset for current shell."""
    fallback = backend_mod.get_system_keyring() is None
    for key in keys:
        if fallback:
            # In environment-fallback mode the variable is the credential's
            # primary copy; remove it from the persisted store too, not just
            # from the shell profile reference.
            _envstore.delete_secret(key)
        else:
            unpersist_key(key, shell)
        print(format_unset(key, shell))

    return 0


def _print_inject_activation(shell: str, key: str) -> None:
    """Tell the user how to activate the key in their current shell."""
    fmt = resolve_shell(shell)
    if os.name == "nt":
        if fmt == "powershell":
            print(
                f"# Restart PowerShell, or: Invoke-Expression (credstore inject {key})",
                file=sys.stderr,
            )
        else:
            print(
                f"# Restart cmd, or:"
                f" FOR /F \"delims=\" %i IN ('credstore inject {key}') DO %i",
                file=sys.stderr,
            )
    else:
        # Unix: _detect_shell() always returns "bash"
        print(f'# Run: eval "$(credstore inject {key})"', file=sys.stderr)


# ── cryptfile helpers (CLI layer — master key is only typed here) ───


def _cryptfile_holds(cf, key: str, secret: str) -> bool:
    """Whether an unlocked cryptfile already stores *secret* under *key*.

    An entry sealed under a different spelling of the key cannot be read back
    under this one — the AEAD associated data binds the original name — and
    that counts as "no usable copy", so the caller rewrites it instead of
    skipping the write.
    """
    try:
        stored = cf.get_password(store_mod.DEFAULT_SERVICE, key)
    except ValueError:
        return False
    matched = stored is not None and stored == secret
    del stored
    return matched


def _delete_from_cryptfile(key: str) -> str:
    """Remove a single credential from the cryptfile.

    Prompts for the master password, then verifies the backup no longer
    contains *key* — deleting it if present.  Returns ``"removed"`` when a
    copy was deleted, ``"absent"`` when the backup had no copy (nothing to
    do), ``"unavailable"`` when there is no cryptfile to clean up (none
    configured, or no master password set yet), ``"skipped"`` when the
    terminal is non-interactive (so the master password cannot be read), and
    ``"failed"`` when the master password was wrong or the cryptfile could
    not be read.
    """
    cf = backend_mod.get_cryptfile()
    if cf is None:
        return "unavailable"

    # Nothing to clean up — and asking for a master password here would be
    # worse than pointless: unlocking a missing cryptfile creates it (see
    # _backend.unlocked_cryptfile), keyed to whatever the user typed.
    if not backend_mod.has_master_key():
        return "unavailable"

    if not sys.stdin.isatty():
        print(
            "(non-interactive — cryptfile cleanup skipped,"
            " re-run 'credstore remove' in a terminal to clean up)",
            file=sys.stderr,
        )
        return "skipped"

    master_pw = masked_input("Master password (to remove from encrypted backup): ")

    try:
        try:
            result = "absent"  # nothing found to remove — a no-op, not an error
            with backend_mod.unlocked_cryptfile(master_pw) as cf:
                if cf.get_password(store_mod.DEFAULT_SERVICE, key) is not None:
                    cf.delete_password(store_mod.DEFAULT_SERVICE, key)
                    result = "removed"
            return result
        except ValueError as exc:
            print(f"Warning: {exc}", file=sys.stderr)
            print(
                "Cryptfile cleanup skipped (incorrect master password).",
                file=sys.stderr,
            )
            return "failed"
        except Exception:  # noqa: BLE001 — cleanup is best effort, never fatal
            return "failed"
    finally:
        # Scrub the master password from memory on every exit path.
        del master_pw


def _cmd_remove(key: str) -> int:
    """Remove a credential from the primary store + cryptfile.

    Not gated on a TTY: the primary copy (keyring, or the environment
    fallback) is removed regardless, and the cryptfile copy only needs the
    master password — a piped shell gets the primary removal plus a notice
    that the backup copy still needs a terminal.  Both removals are
    best-effort and independent; when only one copy could be removed the
    remaining copy is reported explicitly so the user is not left believing
    the credential is fully gone.
    """
    keyring_available = backend_mod.get_system_keyring() is not None
    primary = "system keyring" if keyring_available else "environment fallback"
    deleted_sk = store_mod.delete_credential(key)
    # removed|absent|unavailable|skipped|failed
    cf_state = _delete_from_cryptfile(key)

    if deleted_sk:
        if cf_state in ("removed", "absent"):
            print(f"Deleted: {key}")
        elif cf_state == "unavailable":
            print(f"Deleted from {primary}: {key}")
            print(
                "  (no encrypted backup to clean up — run 'credstore "
                "set-password' to create one)",
                file=sys.stderr,
            )
        else:
            print(f"Deleted from {primary}: {key}")
            reason = (
                "cryptfile cleanup needs an interactive terminal"
                if cf_state == "skipped"
                else "missing or incorrect master password"
            )
            print(
                f"Warning: '{key}' remains in the encrypted backup ({reason}). "
                "Re-run 'credstore remove' in a terminal to finish.",
                file=sys.stderr,
            )
        return 0
    if cf_state == "removed":
        print(f"Deleted from encrypted backup: {key}")
        # Only warn about a leftover keyring copy when there IS a keyring.
        # In environment-fallback mode (no system keyring at all) the warning
        # was false twice over: the primary copy was already removed, and
        # 'reset-backup' cannot enumerate one to sync back.
        if keyring_available:
            print(
                f"Warning: '{key}' remains in the system keyring and could "
                "not be removed. It will be re-synced back into the backup "
                "by 'credstore reset-backup'.",
                file=sys.stderr,
            )
        return 0
    print(f"Not found: {key}")
    return 1


@requires_tty
def _cmd_copy(source: str, dest: str) -> int:
    """Copy a credential from *source* to *dest* (dual-write, idempotent).

    Idempotent: if *dest* already holds the same value as *source* in
    **both** stores, the operation is a no-op and returns success — the
    master password is still needed to establish that, since only the
    cryptfile can say whether the backup has a usable copy.

    If *dest* was previously injected into the system environment
    (``credstore inject``), the new value is re-injected so all three
    stores stay consistent: keyring == cryptfile == env.
    """
    if source == dest:
        _err("source and destination are the same.")
        return 1

    cf = backend_mod.get_cryptfile()
    if cf is None:
        _err("cryptfile backend not available.")
        print("Install: pip install keyrings.cryptfile", file=sys.stderr)
        return 1

    # 1. Read source (primary store first; cryptfile recovery without one)
    secret = store_mod.get_credential(source)
    fallback = backend_mod.get_system_keyring() is None
    where = "environment fallback" if fallback else "system keyring"
    if secret is None:
        if not fallback:
            _err(f"source credential '{source}' not found in {where}.")
            return 1
        master_pw_probe = masked_input("Master password (for encrypted backup): ")
        try:
            secret = backend_mod.read_cryptfile_entry(
                source, master_pw_probe, store_mod.DEFAULT_SERVICE
            )
        except Exception as exc:  # noqa: BLE001 — reported as "not found"
            del master_pw_probe
            _err(
                f"source credential '{source}' not found in {where} or cryptfile: {exc}"
            )
            return 1
        del master_pw_probe
        if secret is None:
            _err(f"source credential '{source}' not found in {where} or cryptfile.")
            return 1

    print(f"Copying '{source}' → '{dest}'")
    master_pw = masked_input("Master password (for encrypted backup): ")

    # 2 + 3. Write the cryptfile first (backup), and decide idempotency from
    # BOTH stores.  The keyring alone is not enough: a credential can be
    # present in the keyring and absent from the backup (a `set` whose
    # cryptfile entry was later lost, or one the backup cannot read back), and
    # answering "Already synced" then would silently skip the encrypted copy
    # this command exists to create.
    already_synced = False
    try:
        with backend_mod.unlocked_cryptfile(master_pw) as cf:
            dest_in_keyring = store_mod.get_credential(dest)
            if dest_in_keyring is not None and dest_in_keyring == secret:
                already_synced = _cryptfile_holds(cf, dest, secret)
            del dest_in_keyring

            if not already_synced:
                cf.set_password(store_mod.DEFAULT_SERVICE, dest, secret)
    except ValueError as exc:
        del secret
        del master_pw
        _err(str(exc))
        return 1

    if already_synced:
        del secret
        del master_pw
        print(f"Already synced: '{dest}' matches '{source}' in both stores.")
        return 0

    # 4. Write the primary store — system keyring, or the environment
    #    fallback when the OS has no usable keyring.
    try:
        store_mod.set_credential(dest, secret)
    except Exception as exc:  # noqa: BLE001 — report any write failure to the user
        try:
            with backend_mod.unlocked_cryptfile(master_pw) as cf:
                cf.delete_password(store_mod.DEFAULT_SERVICE, dest)
        except Exception:  # noqa: BLE001, S110 — rollback is best effort
            # The original write error is what gets reported; a failed
            # rollback must not mask it.
            pass
        del secret
        del master_pw
        _err(str(exc))
        return 1

    # 5. Re-inject to env if dest was previously injected (keep 3 stores
    #    equal).  In environment-fallback mode step 4 already persisted it,
    #    and `is_injected` would just read the value back out of our own store.
    was_injected = not fallback and is_injected(dest)
    if was_injected:
        persist_key(dest, secret)

    del secret
    del master_pw

    if fallback:
        print(f"Copied to: {dest} (environment fallback + encrypted backup).")
    elif was_injected:
        print(f"Copied to: {dest} (re-injected to environment).")
    else:
        print(f"Copied to: {dest}")
    return 0


@requires_tty
def _cmd_list() -> int:
    """List credentials from the primary store, cryptfile backup, and env vars.

    Triple-read: checks the primary store (system keyring, or the environment
    fallback when no keyring is available), the cryptfile, and ``os.environ``
    for each known credential key.  The ENV column shows whether the key is
    currently set as an environment variable.

    Where the keyring cannot be enumerated (macOS, Linux) the keyring column
    is reported as unknown — the keys then come from the backup and the env,
    and no verdict about the pair of stores is possible.  In environment
    fallback mode the environment IS the primary store, so it is enumerated
    (``CREDSTORE_KEY_*`` entries) and the table compares it with the backup.

    Memory-safe: collects only KEY names, never batch-loads secret
    values.  For sync comparison, retrieves values one at a time
    and immediately ``del``-s each after comparison.
    """
    backend_mod.init_backend()
    env_fallback = backend_mod.get_system_keyring() is None
    enumerable = True if env_fallback else enumeration_supported()

    # ── 1. Cryptfile keys only (no values) ─────────────────────
    cryptfile_keys: set[str] = set()
    cryptfile_path = config_mod.get_cryptfile_path()
    cryptfile_exists = os.path.exists(cryptfile_path)

    master_pw: str | None = None
    if cryptfile_exists and backend_mod.has_master_key():
        master_pw = masked_input("Master password: ")
        if not master_pw.strip():
            del master_pw
            _err("master password is required.")
            return 1

        try:
            backend_mod.init_backend(password=master_pw)
            cf = backend_mod.get_cryptfile()
            if cf is not None:
                with backend_mod.unlocked_cryptfile(master_pw) as cf_ctx:
                    cryptfile_keys = set(store_mod._read_cryptfile_keys(cf_ctx))
        except Exception as exc:  # noqa: BLE001 — reported to the user
            del master_pw
            _err(f"cannot read cryptfile — {exc}")
            return 1

    # ── 2. Primary-store keys only (no values) ─────────────────
    primary_keys: set[str] = set()
    if env_fallback:
        # Escaped entries (``CREDSTORE_KEY_*``) are recoverable on their own.
        primary_keys.update(_envstore.list_keys())
        # Bare-name variables are indistinguishable from ordinary environment
        # variables, so only the ones whose name matches a key the backup
        # knows about are claimed.  Their spelling is preferred for display:
        # the cryptfile folds option names to upper case, the environment
        # keeps the original, and `get` needs the original.
        known_upper = {k.upper() for k in cryptfile_keys}
        known_upper.update(k.upper() for k in primary_keys)
        for name in _envstore.names():
            key = _envstore.key_from_env_var(name) or name
            if key.upper() in known_upper:
                primary_keys.add(key)
    else:
        entries = _enumerate_system_keyring(
            store_mod.DEFAULT_SERVICE, with_values=False
        )
        for k, _ in entries:
            primary_keys.add(k)
        del entries

    # ── 3. Env vars (keys only — never decode secret values) ────
    env_keys: set[str] = {
        k for k in primary_keys | cryptfile_keys if _envstore.has_secret(k)
    }

    # ── 4. Merge & display (values retrieved one-at-a-time) ────
    # Cross-store matching is case-insensitive: _read_cryptfile_keys()
    # normalizes cryptfile keys to UPPER (configparser folds option case),
    # while keyring enumeration returns the raw UserName.  Dedup by
    # canonical case, preferring the keyring name for display — otherwise
    # a lowercase key (e.g. mcp_oauth_*) synced into the cryptfile shows
    # up as two rows, one "keyring only" and one "cryptfile only".
    by_upper: dict[str, str] = {}
    for k in primary_keys:
        by_upper[k.upper()] = k
    for k in cryptfile_keys:
        by_upper.setdefault(k.upper(), k)
    all_keys = sorted(by_upper.values())

    if not all_keys:
        _print_empty_list(primary_keys, cryptfile_exists, cryptfile_keys, env_fallback)
        # Clean up master password reference
        if master_pw is not None:
            del master_pw
        return 0

    # Unlock cryptfile once for comparison pass, or pass None
    cf = backend_mod.get_cryptfile()
    try:
        if cf is not None and master_pw is not None:
            with backend_mod.unlocked_cryptfile(master_pw) as cf_ctx:
                _print_credential_table_safe(
                    all_keys,
                    primary_keys,
                    cryptfile_keys,
                    env_keys,
                    cryptfile_exists,
                    cf_ctx,
                    enumerable,
                    env_fallback,
                )
        else:
            _print_credential_table_safe(
                all_keys,
                primary_keys,
                cryptfile_keys,
                env_keys,
                cryptfile_exists,
                None,
                enumerable,
                env_fallback,
            )
    finally:
        if master_pw is not None:
            del master_pw

    return 0


def _print_empty_list(
    keyring_keys: set[str],
    cryptfile_exists: bool,
    cryptfile_keys: set[str],
    env_fallback: bool = False,
) -> None:
    """Print the empty-credential message with appropriate guidance."""
    print("No credentials stored.")
    print()
    if not keyring_keys and not cryptfile_exists:
        print("Run 'credstore set <KEY>' to store a credential.")
    elif not keyring_keys and not cryptfile_keys:
        if env_fallback:
            print("Cryptfile exists but is empty.")
        else:
            print("Cryptfile exists but is empty.  Credentials in the")
            print("system keyring cannot be enumerated on this platform.")
        print("Run 'credstore set <KEY>' to populate both stores.")


def _classify_credential_row(
    key: str,
    in_ring: bool,
    in_crypt: bool,
    cf_ctx,  # unlocked cryptfile or None
    enumerable: bool = True,
    env_primary: bool = False,
):
    """Compare a single credential across stores and classify its sync status.

    Returns ``(ring_mark, crypt_mark, status, delta)`` where *delta* is
    one of ``("synced", "ring_only", "crypt_only", "mismatched", "unknown")``.
    Caller updates aggregate counters from *delta*.

    *enumerable* is False on platforms whose keyring has no list API (macOS,
    Linux): membership there is unknowable, so no verdict about the pair can
    be given.

    *env_primary* relabels the primary-store side: in environment-fallback
    mode the first column is the environment, not the keyring.

    Memory-safe: retrieves at most one value per store, compares,
    and ``del``-s immediately.
    """
    primary_only = "env only" if env_primary else "keyring only"
    if not enumerable:
        # Nothing can be said about the keyring's side: it cannot be listed,
        # so "cryptfile only" — which is what every row used to say there —
        # would be a claim about a store nobody looked at, and it sent the
        # user to `reset-keyring` for credentials that were never missing.
        return (
            ("?", "✔", "in backup", "unknown")
            if in_crypt
            else ("?", "—", "unknown", "unknown")
        )

    if not (in_ring and in_crypt):
        # Present in only one store — no comparison needed.  Neither can be
        # "synced" here: that verdict needs a value from both stores.
        return (
            ("✔", "—", primary_only, "ring_only")
            if in_ring
            else ("—", "✔", "cryptfile only", "crypt_only")
        )

    ring_val = store_mod.get_credential(key)
    try:
        crypt_val = (
            cf_ctx.get_password(store_mod.DEFAULT_SERVICE, key)
            if cf_ctx is not None
            else None
        )
    except ValueError:
        # The key IS in cryptfile_keys, so the entry exists — but it is sealed
        # under a different spelling of the key, and the value cannot be read
        # back under this one.  That is a divergence between the two stores,
        # which is what MISMATCH reports; "reset-backup" resolves it by
        # rewriting the entry under the keyring's spelling.  Return instead of
        # raising so one such entry cannot abort the whole listing.
        del ring_val
        return ("✔", "✔", "MISMATCH ⚠", "mismatched")

    if ring_val is not None and crypt_val is not None:
        if ring_val == crypt_val:
            result = ("✔", "✔", "synced", "synced")
        else:
            result = ("✔", "✔", "MISMATCH ⚠", "mismatched")
        del crypt_val
    elif ring_val is not None:
        result = ("✔", "—", primary_only, "ring_only")
    else:
        result = ("—", "✔", "cryptfile only", "crypt_only")

    del ring_val
    return result


def _print_credential_table_safe(
    all_keys: list[str],
    keyring_keys: set[str],
    cryptfile_keys: set[str],
    env_keys: set[str],
    cryptfile_exists: bool,
    cf_ctx,  # unlocked cryptfile or None
    enumerable: bool = True,
    env_primary: bool = False,
) -> None:
    """Print a formatted table of credentials with sync status.

    Shows four columns: KEY, primary store (SYSTEM KEYRING, or ENV FALLBACK),
    CRYPTFILE, ENV, STATUS.  *enumerable* False (macOS, Linux) leaves the
    keyring column unknown — see ``_classify_credential_row``.
    Memory-safe: retrieves values ONE at a time for comparison.
    """
    key_width = max(len(k) for k in all_keys) + 2
    primary_header = "ENV FALLBACK    " if env_primary else "SYSTEM KEYRING  "

    print()
    header = f"  {'KEY':<{key_width}} {primary_header} CRYPTFILE        ENV    STATUS"
    sep = f"  {'─' * (key_width - 2):─<{key_width}} ──────────────   ──────────────   ────   ──────"
    print(header)
    print(sep)

    counts = {
        "synced": 0,
        "ring_only": 0,
        "crypt_only": 0,
        "mismatched": 0,
        "unknown": 0,
        "env_set": 0,
    }

    # Canonical-case matching: cryptfile keys are stored uppercased
    # (_read_cryptfile_keys), keyring keys keep their raw case.
    crypt_upper = {k.upper() for k in cryptfile_keys}

    for key in all_keys:
        in_ring = key in keyring_keys
        in_crypt = key.upper() in crypt_upper
        in_env = key in env_keys
        env_mark = "✔" if in_env else "—"
        if in_env:
            counts["env_set"] += 1

        ring_mark, crypt_mark, status, delta = _classify_credential_row(
            key,
            in_ring,
            in_crypt,
            cf_ctx,
            enumerable,
            env_primary,
        )
        if delta in counts:
            counts[delta] += 1

        print(
            f"  {key:<{key_width}} {ring_mark:<13}   {crypt_mark:<14}   {env_mark:<4}   {status}"
        )

    print(sep)
    parts = []
    if counts["synced"]:
        parts.append(f"synced: {counts['synced']}")
    if counts["ring_only"]:
        label = "env only" if env_primary else "system only"
        parts.append(f"{label}: {counts['ring_only']}")
    if counts["crypt_only"]:
        parts.append(f"cryptfile only: {counts['crypt_only']}")
    if counts["mismatched"]:
        parts.append(f"mismatched: {counts['mismatched']}")
    if counts["unknown"]:
        parts.append(f"in backup: {counts['unknown']}")
    if counts["env_set"]:
        parts.append(f"env: {counts['env_set']}")
    print(f"  {len(all_keys)} credential(s) — {', '.join(parts)}")

    if not enumerable:
        print()
        print("  The system keyring cannot be listed on this platform, so '?' means")
        print("  its contents are unknown here — credentials are shown from the")
        print("  encrypted backup. Only Windows and WSL enumerate the keyring.")

    _print_list_tips(
        counts["ring_only"], counts["crypt_only"], cryptfile_exists, env_primary
    )
    print()


def _print_list_tips(
    ring_only: int,
    crypt_only: int,
    cryptfile_exists: bool,
    env_primary: bool = False,
) -> None:
    """Print context-sensitive sync tips."""
    if ring_only > 0:
        if env_primary:
            print()
            print(f"  Tip: run 'credstore reset-backup' to sync {ring_only}")
            print("  credential(s) from the environment into the cryptfile.")
        elif cryptfile_exists:
            print()
            print(f"  Tip: run 'credstore reset-backup' to sync {ring_only} missing")
            print("  credential(s) from system keyring into the cryptfile.")
        else:
            print()
            print("  Tip: run 'credstore set-password' to enable encrypted backup,")
            print(f"  then 'credstore reset-backup' to sync {ring_only} credential(s).")
    elif crypt_only > 0:
        if env_primary:
            print()
            print(f"  Tip: run 'credstore reset-env' to restore {crypt_only}")
            print("  credential(s) from cryptfile to the environment fallback.")
        else:
            print()
            print(f"  Tip: run 'credstore reset-keyring' to restore {crypt_only}")
            print("  credential(s) from cryptfile back to the system keyring.")


@requires_tty
def _cmd_reset_keyring() -> int:
    """Restore all credentials from cryptfile to the system keyring."""
    backend_mod.init_backend()
    if backend_mod.get_system_keyring() is None:
        _err("no system keyring available.")
        print(
            "Run 'credstore reset-env' to restore into the environment fallback.",
            file=sys.stderr,
        )
        return 1
    print("Restore credentials from encrypted backup to the system keyring.")
    print()

    master_pw = masked_input("Master password: ")

    try:
        count = store_mod.reset_credentials(master_pw)
    except Exception as exc:  # noqa: BLE001 — reported to the user
        del master_pw
        _err(str(exc))
        return 1

    del master_pw
    print(f"Restored {count} credential(s) to the system keyring.")
    return 0


@requires_tty
def _cmd_reset_env() -> int:
    """Restore all credentials from cryptfile into the environment fallback."""
    backend_mod.init_backend()
    if backend_mod.get_system_keyring() is not None:
        _err("a system keyring is available — the environment fallback is not in use.")
        print(
            "Use 'credstore inject KEY…' to export credentials to the environment.",
            file=sys.stderr,
        )
        return 1
    print("Restore credentials from encrypted backup to the environment fallback.")
    print()

    master_pw = masked_input("Master password: ")

    try:
        count = store_mod.reset_environment_credentials(master_pw)
    except Exception as exc:  # noqa: BLE001 — reported to the user
        del master_pw
        _err(str(exc))
        return 1

    del master_pw
    print(f"Restored {count} credential(s) to the environment fallback.")
    return 0


@requires_tty
def _cmd_reset_backup() -> int:
    """Reset cryptfile backup: sync all credentials from the primary store.

    Keyring mode enumerates the keyring and loads all values at once (they are
    needed to write the backup).  Environment-fallback mode reads one value at
    a time from the environment store.  Values are ``del``-ed as soon as the
    sync is done.
    """
    backend_mod.init_backend()
    keyring_available = backend_mod.get_system_keyring() is not None
    source = "system keyring" if keyring_available else "environment fallback"
    print(f"Reset cryptfile backup from {source}.")
    print()

    if keyring_available:
        return _reset_backup_from_keyring()
    return _reset_backup_from_environment()


def _reset_backup_from_keyring() -> int:
    """Keyring → cryptfile: the original reset-backup path."""
    # with_values=True is required here — we genuinely need the secrets
    # to write them into the cryptfile backup
    entries = _enumerate_system_keyring(
        store_mod.DEFAULT_SERVICE,
        with_values=True,
    )
    if not entries:
        print("No credentials found in system keyring.")
        return 0

    print(f"Found {len(entries)} credential(s) in system keyring:")
    print()
    master_pw = masked_input("Master password: ")

    cf = backend_mod.get_cryptfile()
    if cf is None:
        del entries
        del master_pw
        _err("cryptfile backend not available.")
        return 1

    synced = 0
    try:
        with backend_mod.unlocked_cryptfile(master_pw) as cf:
            for key, value in entries:
                try:
                    cf.set_password(store_mod.DEFAULT_SERVICE, key, value)
                    print(f"  {key}")
                    synced += 1
                except Exception as exc:  # noqa: BLE001 — one bad key must not abort the sync
                    # The cryptfile layer raises from several families
                    # (KeyringError, OSError, RuntimeError on a decrypt
                    # failure), so this deliberately catches broadly.
                    print(f"  {key} — skipped: {exc}", file=sys.stderr)
    except ValueError:
        del entries
        del master_pw
        _err("incorrect master password.")
        return 1

    # Explicit cleanup — batch of secrets no longer needed
    del entries
    del master_pw

    print()
    print(f"Reset {synced} credential(s) in cryptfile backup.")
    return 0


def _reset_backup_from_environment() -> int:
    """Environment fallback → cryptfile: reset-backup without a keyring."""
    keys = store_mod.environment_backup_keys()
    if not keys:
        print("No credentials found in the environment fallback.")
        return 0

    print(f"Found {len(keys)} credential(s) in the environment fallback:")
    print()
    master_pw = masked_input("Master password: ")

    try:
        synced, skipped = store_mod.sync_backup_from_environment(master_pw)
    except ValueError:
        del master_pw
        _err("incorrect master password.")
        return 1
    except Exception as exc:  # noqa: BLE001 — reported to the user
        del master_pw
        _err(str(exc))
        return 1

    del master_pw
    print(f"Reset {synced} credential(s) in cryptfile backup.")
    for key in skipped:
        print(
            f"  {key} — skipped: not in the environment fallback",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())

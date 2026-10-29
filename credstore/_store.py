"""Credential store — system keyring with cryptfile backup.

The primary store is the OS keyring.  Where no usable keyring backend exists,
the environment takes its place (see ``_envstore``): secrets are dual-written
to the environment and the encrypted cryptfile, and reads need no master
password.

- get():      primary store only (keyring, or environment fallback) — fast,
              no master key
- list_keys(): primary store keys only — NEVER returns secret values
- set():      primary store only — requires the master key to already be set
- delete():   primary store only (cryptfile cleanup handled by CLI layer)
- reset():    cryptfile → system keyring (explicit recovery, needs master key)
- reset_environment(): cryptfile → environment fallback (no keyring needed)

Memory safety: secrets are Python ``str`` objects (immutable).  Callers MUST
``del`` references after use to release them for garbage collection.  Never
batch-load all values into a single collection — compare inline, one at a time.
"""

from __future__ import annotations

import logging

import credstore._backend as _be
from credstore import _envstore

logger = logging.getLogger("credstore")

DEFAULT_SERVICE = "credstore"

_store: CredentialStore | None = None


class CredentialStore:
    """Dual-write credential storage."""

    def __init__(self, service: str = DEFAULT_SERVICE):
        self._service = service

    # ── get: primary store only ────────────────────────────────

    def get(self, key: str) -> str | None:
        """Retrieve from the primary store — fast, no master key.

        The primary store is the system keyring, or the environment fallback
        when no keyring backend is available.

        Prefer ``exists()`` when you only need to know whether a
        credential is stored — it returns a bool instead of the secret.
        """
        sk = _be.get_system_keyring()
        if sk is not None:
            return sk.get_password(self._service, key)  # type: ignore[return-value]
        return _envstore.get_secret(key)

    def exists(self, key: str) -> bool:
        """Check whether a credential exists.

        Returns True/False — the value is fetched only to test existence,
        discarded immediately, and never returned.
        """
        return self.get(key) is not None

    def list_keys(self) -> list[str]:
        """List credential keys from the primary store — NEVER returns values.

        Returns key names only.  Keyring mode delegates to platform-specific
        enumeration (win32cred on Windows, PowerShell CredEnumerate on WSL).
        In environment-fallback mode the keys come from the persisted
        environment (``CREDSTORE_KEY_*`` entries) plus the backup's own key
        names, which are readable without decrypting the file.  Use
        ``exists()`` to check individual credentials without returning the
        secret.
        """
        if _be.get_system_keyring() is None:
            return self._env_fallback_keys()

        from credstore._enumerate import enumerate_system_keyring

        return [
            key
            for key, _value in enumerate_system_keyring(
                self._service, with_values=False
            )
        ]

    def _env_fallback_keys(self) -> list[str]:
        """Keys retrievable in environment-fallback mode.

        The environment can only enumerate its escaped (``CREDSTORE_KEY_*``)
        entries — a bare-name credential is indistinguishable from an ordinary
        environment variable.  The cryptfile's option names need no decryption
        to list, so they fill the gap for keys the backup knows about; where
        the environment holds one of those keys, its original spelling is
        preferred (the file folds names to upper case, and ``get`` needs the
        original).
        """
        keys = list(_envstore.list_keys())
        seen = {key.upper() for key in keys}

        # Original spellings, case-insensitively indexed — bare names are only
        # claimed when a key the backup knows about matches them.
        spellings: dict[str, str] = {}
        for name in _envstore.names():
            key = _envstore.key_from_env_var(name) or name
            spellings.setdefault(key.upper(), key)

        cf = _be.get_cryptfile()
        if cf is None:
            return keys
        try:
            cryptfile_keys = _read_cryptfile_keys(cf, self._service)
        except Exception:
            # A malformed or half-written backup must not break the listing;
            # the env-store keys above are still answers.
            logger.debug("could not read backup keys", exc_info=True)
            return keys

        for key in cryptfile_keys:
            if key.upper() in seen:
                continue
            seen.add(key.upper())
            keys.append(spellings.get(key.upper(), key))
        return keys

    # ── set ───────────────────────────────────────────────────

    def set(self, key: str, secret: str) -> None:
        """Store to the primary store.

        Writes the system keyring, or — when no keyring backend is
        available — the environment fallback (persisted for new processes).
        The encrypted cryptfile backup is written separately by the CLI
        layer (``credstore set``), which dual-writes both stores.

        Requires the master key to already be set (``credstore set-password``
        run once, so the cryptfile exists) and raises ``RuntimeError``
        otherwise. This is deliberate: a secret is never written to the
        primary store alone without an encrypted backup to recover from OS
        password changes.
        """
        if not _be.has_master_key():
            raise RuntimeError(
                "Master key not set.\nRun 'credstore set-password' first."
            )

        sk = _be.get_system_keyring()
        if sk is None:
            _envstore.store_secret(key, secret)
            logger.info("credential_stored_env key=%s", key)
            return
        sk.set_password(self._service, key, secret)
        logger.info("credential_stored key=%s", key)

    # ── delete ─────────────────────────────────────────────────

    def delete(self, key: str) -> bool:
        """Delete from the primary store.

        Cryptfile cleanup is handled by the CLI layer (needs master key)."""
        existed = False

        sk = _be.get_system_keyring()
        if sk is not None:
            try:
                sk.delete_password(self._service, key)
                existed = True
            except Exception:  # noqa: BLE001, S110 — best-effort delete
                # A missing or unreachable entry in the system keyring must
                # not fail the delete: ``existed`` stays False and the
                # caller carries on to the cryptfile cleanup.
                pass
        else:
            existed = _envstore.delete_secret(key)

        if existed:
            logger.info("credential_deleted key=%s", key)
        return existed

    # ── reset: cryptfile → primary store ──────────────────────

    def reset(self, master_password: str) -> int:
        """Restore all credentials from cryptfile to the system keyring.

        Reads every credential from the encrypted cryptfile using
        *master_password*, then writes each one to the system keyring under
        the spelling the entry is sealed with, which is also the spelling to
        restore it under.  Returns the count of restored credentials; an entry
        that cannot be read is skipped with a warning rather than silently
        dropped.

        Raises ``RuntimeError`` when no system keyring is available — the
        environment store is a different, plaintext target with its own entry
        point, ``reset_environment``.
        """
        sk = _be.get_system_keyring()
        if sk is None:
            raise RuntimeError(
                "No system keyring available.\n"
                "Run 'credstore reset-env' to restore into the environment fallback."
            )
        return self._restore_from_cryptfile(master_password, sk)

    def reset_environment(self, master_password: str) -> int:
        """Restore all credentials from cryptfile into the environment fallback.

        The environment counterpart of ``reset``: no keyring is involved, and
        each credential is written to the environment store (persisted for new
        processes) under the spelling the entry is sealed with.  Used by
        ``credstore reset-env`` when no keyring backend is available.
        """
        return self._restore_from_cryptfile(master_password, None)

    def _restore_from_cryptfile(self, master_password: str, sk) -> int:
        """Shared restore loop; *sk* is a keyring backend or None for env."""
        fallback = sk is None

        # Where the primary store can be read back, a skipped entry can be
        # repaired by re-syncing it; where it cannot (macOS, Linux, the
        # environment fallback), the only way out is to re-set the credential
        # under the spelling it was stored with.
        from credstore._enumerate import enumeration_supported

        readable_primary = not fallback and enumeration_supported()
        unreadable_hint = (
            "run 'credstore reset-backup' to rewrite it from the keyring"
            if readable_primary
            else "the file cannot show its original spelling — re-set it with "
            "'credstore set <KEY>'"
        )

        spellings = keyring_key_spellings(self._service)
        with _be.unlocked_cryptfile(master_password) as cf:
            keys = _read_cryptfile_keys(cf, self._service)
            count = 0
            for key in keys:
                try:
                    entry = resolve_cryptfile_entry(cf, key, self._service, spellings)
                    if entry is not None:
                        name, value = entry
                        if fallback:
                            _envstore.store_secret(name, value)
                        else:
                            sk.set_password(self._service, name, value)
                        count += 1
                        logger.info("reset_restored key=%s", name)
                        del value  # release secret after write
                except Exception as exc:  # noqa: BLE001 — one bad key must not abort the restore
                    # Keyrings and the cryptfile layer raise from several
                    # families (KeyringError, OSError, RuntimeError on a
                    # decrypt failure), so this deliberately catches broadly.
                    logger.warning(
                        "reset_skip key=%s err=%s — not restored: %s",
                        key,
                        exc,
                        unreadable_hint,
                    )

            logger.info("reset_complete count=%d", count)
            return count

    # ── backup: environment fallback → cryptfile ──────────────

    def environment_backup_keys(self) -> list[str]:
        """Keys the environment fallback can contribute to the backup.

        Covers every credential the environment can name: its escaped
        (``CREDSTORE_KEY_*``) entries, plus the original spelling of every key
        the backup already knows about (the file's option names are readable
        without decrypting it).  A bare-name variable that neither source
        names cannot be distinguished from an ordinary environment variable
        and is not guessed at.
        """
        cf = _be.get_cryptfile()
        if cf is None:
            return _envstore.list_keys()

        keys: list[str] = []
        seen: set[str] = set()

        def add(key: str) -> None:
            if key.upper() not in seen:
                seen.add(key.upper())
                keys.append(key)

        for key in _envstore.list_keys():
            add(key)

        # Original spellings, case-insensitively indexed — the cryptfile folds
        # names to upper case, and writing back needs the spelling it was
        # sealed with.
        spellings: dict[str, str] = {}
        for name in _envstore.names():
            key = _envstore.key_from_env_var(name) or name
            spellings.setdefault(key.upper(), key)

        try:
            backup_keys = _read_cryptfile_keys(cf, self._service)
        except Exception:
            # A malformed backup must not hide the environment-only keys
            # above; it just cannot contribute its own names.
            logger.debug("could not read backup keys", exc_info=True)
            backup_keys = []
        for key in backup_keys:
            add(spellings.get(key.upper(), key))
        return keys

    def sync_backup_from_environment(
        self, master_password: str
    ) -> tuple[int, list[str]]:
        """Rewrite cryptfile entries from the environment fallback.

        The ``reset-backup`` direction when no keyring is available: the
        environment is the primary store, so its values are authoritative.
        One value is read, written, and released at a time.  Returns
        ``(synced_count, skipped_keys)``; a named key the environment does not
        hold (or the backup refuses) is reported rather than silently
        dropped.
        """
        skipped: list[str] = []
        synced = 0
        with _be.unlocked_cryptfile(master_password) as cf:
            for key in self.environment_backup_keys():
                value = _envstore.get_secret(key)
                if value is None:
                    skipped.append(key)
                    continue
                try:
                    cf.set_password(self._service, key, value)
                    synced += 1
                    logger.info("backup_synced key=%s", key)
                except Exception as exc:  # noqa: BLE001 — one bad key must not abort the sync
                    logger.warning("backup_skip key=%s err=%s", key, exc)
                    skipped.append(key)
                finally:
                    del value

        logger.info("backup_sync_complete count=%d skipped=%d", synced, len(skipped))
        return synced, skipped

    # ── mask ──────────────────────────────────────────────────

    @staticmethod
    def mask(value: str) -> str:
        """Return the conventional masked form of a credential.

        Shows the first four and last four characters, or ``***`` when the
        value is short enough that four characters would be most of it.  This
        is the form a consumer shows when the credential would otherwise reach
        a model or a log.
        """
        if not value:
            return "(empty)"
        if len(value) <= 8:
            return "***"
        return f"{value[:4]}…{value[-4:]}"


# ── helpers ──────────────────────────────────────────────────


def _read_cryptfile_keys(cf, service: str = DEFAULT_SERVICE) -> list[str]:
    """Read all credential keys from a cryptfile INI file.

    Names come back canonically cased (upper).  The file cannot do better:
    ``keyrings.cryptfile`` escapes a key into the INI option name (``/`` →
    ``_2F``) and configparser then folds that name to lower case, while the
    key's *original* spelling is sealed into the entry's AEAD associated data.
    ``myapp/api_key`` and ``MYAPP/API_KEY`` are therefore indistinguishable
    here — pass these canonical names to ``resolve_cryptfile_entry``, which
    recovers the sealed spelling, never straight to ``get_password``.
    """
    import configparser

    from keyrings.cryptfile.escape import escape, unescape

    cfg = configparser.ConfigParser()
    cfg.read(cf.file_path)
    keys = []
    for section in cfg.sections():
        if section.startswith(("keyring", "DEFAULT")):
            continue
        # Sections are escaped as well — but, unlike option names, not folded.
        if section == escape(service):
            for raw_key in cfg.options(section):
                keys.append(unescape(raw_key).upper())
    return keys


def keyring_key_spellings(service: str = DEFAULT_SERVICE) -> dict[str, str]:
    """Map canonical key names to the spelling the system keyring holds.

    This is the only way to recover a *mixed-case* key (``myApp/ApiKey``): the
    cryptfile stores a lower-cased option name, so the original spelling is
    nowhere in the file.  Only Windows and WSL can enumerate Credential
    Manager (see ``_enumerate.enumeration_supported``), so this is empty on
    macOS and Linux, where callers fall back to plain case variants.
    """
    from credstore._enumerate import enumerate_system_keyring, enumeration_supported

    if not enumeration_supported():
        return {}

    try:
        entries = enumerate_system_keyring(service, with_values=False)
    except Exception:
        # A failed enumeration is not fatal — it only means the exact spelling
        # of a mixed-case key is unknown, and the case variants are tried.
        logger.debug("could not enumerate keyring for key spellings", exc_info=True)
        return {}
    return {name.upper(): name for name, _value in entries}


def resolve_cryptfile_entry(
    cf,
    key: str,
    service: str = DEFAULT_SERVICE,
    spellings: dict[str, str] | None = None,
) -> tuple[str, str] | None:
    """Read one cryptfile entry by its canonical *key*.

    Returns ``(name, value)``, where *name* is the spelling the entry is
    actually sealed under, or ``None`` when the entry is absent.  Raises
    ``ValueError`` when the entry exists but none of the candidate spellings
    match its associated data — the caller must report that, and must NOT read
    it as "no such credential": the value is still there, just not reachable
    under the name recovered from the file.

    *spellings* is the optional map from ``keyring_key_spellings``; when the
    keyring's own spelling is known it is tried first and is authoritative.
    Every candidate resolves to the same INI option name, so a candidate can
    only fail by MAC check (wrong spelling), never by returning a wrong secret.
    """
    candidates: list[str] = []
    exact = (spellings or {}).get(key)
    if exact:
        candidates.append(exact)
    for candidate in (key, key.lower()):
        if candidate not in candidates:
            candidates.append(candidate)

    error: ValueError | None = None
    for name in candidates:
        try:
            value = cf.get_password(service, name)
        except ValueError as exc:  # sealed under a different spelling
            error = exc
            continue
        if value is not None:
            return name, value

    if error is not None:
        raise error
    return None


# ── module-level API ─────────────────────────────────────────


def init_store(password: str | None = None) -> CredentialStore:
    global _store
    _be.init_backend(password=password)
    if _store is None:
        _store = CredentialStore()
    return _store


def _get_store() -> CredentialStore:
    if _store is None:
        init_store()
    assert _store is not None  # init_store() guarantees this
    return _store


def get_credential(key: str) -> str | None:
    """Retrieve a credential from the primary store.

    The primary store is the system keyring, or the environment fallback
    when no keyring backend is available.

    Callers MUST ``del`` the returned value after use to release the
    secret from memory as soon as possible.  Python strings are
    immutable — only the reference can be cleaned up.

    Prefer ``exists_credential()`` when you only need to check existence.
    """
    return _get_store().get(key)


def exists_credential(key: str) -> bool:
    """Check whether a credential exists.

    Returns True/False — the value is fetched only to test existence,
    discarded immediately, and never returned. Prefer this over
    ``get_credential()`` when you only need to know if a key is stored.
    """
    return _get_store().exists(key)


def list_credential_keys() -> list[str]:
    """List credential keys WITHOUT retrieving any secret values.

    Returns key names only — NEVER the secret content.
    Use this for enumeration; call ``get_credential()`` individually
    for the specific keys you need, and ``del`` the result after use.
    """
    return _get_store().list_keys()


def set_credential(key: str, secret: str) -> None:
    """Store a credential to the primary store.

    Writes the system keyring, or the environment fallback when no keyring
    is available; the cryptfile backup is handled by the CLI.  Requires the
    master key to already be set (``credstore set-password``) and raises
    ``RuntimeError`` otherwise. See ``CredentialStore.set``.
    """
    _get_store().set(key, secret)


def delete_credential(key: str) -> bool:
    return _get_store().delete(key)


def reset_credentials(master_password: str) -> int:
    return _get_store().reset(master_password)


def reset_environment_credentials(master_password: str) -> int:
    return _get_store().reset_environment(master_password)


def environment_backup_keys() -> list[str]:
    return _get_store().environment_backup_keys()


def sync_backup_from_environment(master_password: str) -> tuple[int, list[str]]:
    return _get_store().sync_backup_from_environment(master_password)


def get_backend_name() -> str:
    return _be.get_active_backend_name()


def check_backend() -> dict:
    return _be.get_backend_info()

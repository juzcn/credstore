"""Credential store — system keyring with cryptfile backup.

- get():      system keyring only (fast, no master key)
- list_keys(): system keyring keys only — NEVER returns secret values
- set():      system keyring only — requires the master key to already be set
- delete():   system keyring only (cryptfile cleanup handled by CLI layer)
- reset():    cryptfile → system keyring (explicit recovery, needs master key)

Memory safety: secrets are Python ``str`` objects (immutable).  Callers MUST
``del`` references after use to release them for garbage collection.  Never
batch-load all values into a single collection — compare inline, one at a time.
"""

from __future__ import annotations

import logging

import credstore._backend as _be

logger = logging.getLogger("credstore")

DEFAULT_SERVICE = "credstore"

_store: CredentialStore | None = None


class CredentialStore:
    """Dual-write credential storage."""

    def __init__(self, service: str = DEFAULT_SERVICE):
        self._service = service

    # ── get: system keyring only ───────────────────────────────

    def get(self, key: str) -> str | None:
        """Retrieve from system keyring only — fast, no master key.

        Prefer ``exists()`` when you only need to know whether a
        credential is stored — it returns a bool instead of the secret.
        """
        sk = _be.get_system_keyring()
        if sk is not None:
            return sk.get_password(self._service, key)  # type: ignore[return-value]
        return None

    def exists(self, key: str) -> bool:
        """Check whether a credential exists.

        Returns True/False — the value is fetched only to test existence,
        discarded immediately, and never returned.
        """
        return self.get(key) is not None

    def list_keys(self) -> list[str]:
        """List credential keys from system keyring — NEVER returns values.

        Returns key names only.  Delegates to platform-specific
        enumeration (win32cred on Windows, PowerShell CredEnumerate
        on WSL).  Use ``exists()`` to check individual credentials
        without returning the secret.
        """
        from credstore._enumerate import enumerate_system_keyring

        return [
            key
            for key, _value in enumerate_system_keyring(
                self._service, with_values=False
            )
        ]

    # ── set ───────────────────────────────────────────────────

    def set(self, key: str, secret: str) -> None:
        """Store to system keyring only.

        The encrypted cryptfile backup is written separately by the CLI
        layer (``credstore set``), which dual-writes both stores.

        Requires the master key to already be set (``credstore set-password``
        run once, so the cryptfile exists) and raises ``RuntimeError``
        otherwise. This is deliberate: a secret is never written to the
        keyring alone without an encrypted backup to recover from OS
        password changes.
        """
        if not _be.has_master_key():
            raise RuntimeError(
                "Master key not set.\nRun 'credstore set-password' first."
            )

        sk = _be.get_system_keyring()
        if sk is None:
            raise RuntimeError("No system keyring available")
        sk.set_password(self._service, key, secret)
        logger.info("credential_stored key=%s", key)

    # ── delete ─────────────────────────────────────────────────

    def delete(self, key: str) -> bool:
        """Delete from system keyring only.

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

        if existed:
            logger.info("credential_deleted key=%s", key)
        return existed

    # ── reset: cryptfile → system keyring ────────────────────

    def reset(self, master_password: str) -> int:
        """Restore all credentials from cryptfile to system keyring.

        Reads every credential from the encrypted cryptfile using
        *master_password*, then writes each one to the system keyring —
        under the spelling the entry is sealed with, which is also the
        spelling to restore it under.  Returns the count of restored
        credentials; an entry that cannot be read is skipped with a warning
        rather than silently dropped.
        """
        sk = _be.get_system_keyring()
        if sk is None:
            raise RuntimeError("No system keyring available")

        # Where the keyring can be read back, a skipped entry can be repaired
        # by re-syncing it; where it cannot (macOS, Linux), the only way out is
        # to re-set the credential under the spelling it was stored with.
        from credstore._enumerate import enumeration_supported

        unreadable_hint = (
            "run 'credstore reset-backup' to rewrite it from the keyring"
            if enumeration_supported()
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

    # ── mask ──────────────────────────────────────────────────

    @staticmethod
    def mask(value: str) -> str:
        """Return a masked representation for CLI display.

        Shows first 4 + last 4 characters for human verification
        in the terminal.  Agent tools must use ``exists()`` instead
        — never expose partial credential data to an LLM.
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
    """Retrieve a credential from system keyring.

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
    """Store a credential to the system keyring.

    Writes the keyring only; the cryptfile backup is handled by the CLI.
    Requires the master key to already be set (``credstore set-password``)
    and raises ``RuntimeError`` otherwise. See ``CredentialStore.set``.
    """
    _get_store().set(key, secret)


def delete_credential(key: str) -> bool:
    return _get_store().delete(key)


def reset_credentials(master_password: str) -> int:
    return _get_store().reset(master_password)


def get_backend_name() -> str:
    return _be.get_active_backend_name()


def check_backend() -> dict:
    return _be.get_backend_info()

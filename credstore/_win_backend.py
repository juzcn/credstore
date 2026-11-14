"""Windows keyring backend — Credential Manager, one target per credential.

``TargetName`` is ``{service}:{username}`` (see ``credstore._target``) and
``UserName`` carries the username as metadata.  Credential Manager keys a
generic credential by TargetName alone, so this layout gives every credential
its own entry; there is no main/overflow pair and no displacement step.

This backend deliberately does not reuse ``keyring.backends.Windows``: its
``WinVaultKeyring`` writes the bare service name and moves colliding usernames
to ``{username}@{service}``, a backward-compatibility workaround for stores
written before usernames were composed into the target.  credstore has one
format on both Windows and WSL.
"""

from __future__ import annotations

import logging
import os

from jaraco.classes import properties
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError, PasswordSetError

from credstore._target import target_name

logger = logging.getLogger("credstore.win_backend")

_ERROR_NOT_FOUND = 1168  # ERROR_NOT_FOUND from CredRead/CredDelete
_COMMENT = "Stored using credstore"


def _load_win32():
    """Import pywin32-ctypes (or pywin32) — the Windows bindings.

    Imported lazily so this module can be imported (and the rest of credstore
    used in environment-fallback mode) on a host without the bindings.
    """
    try:
        from win32ctypes.pywin32 import pywintypes, win32cred
    except ImportError:
        import pywintypes  # type: ignore[import-not-found, no-redef]
        import win32cred  # type: ignore[import-not-found, no-redef]
    return pywintypes, win32cred


def _read_credential(target: str) -> str | None:
    """Read a credential blob, or return None when it does not exist."""
    pywintypes, win32cred = _load_win32()
    try:
        cred = win32cred.CredRead(Type=win32cred.CRED_TYPE_GENERIC, TargetName=target)
    except pywintypes.error as exc:
        if getattr(exc, "winerror", None) == _ERROR_NOT_FOUND:
            return None
        raise

    blob = cred.get("CredentialBlob") or b""
    try:
        return blob.decode("utf-16-le")
    except UnicodeDecodeError:
        try:
            return blob.decode("utf-8")
        except UnicodeDecodeError:
            logger.debug("Failed to decode credential blob for %s", target)
            return None


def _set_credential(target: str, username: str, password: str) -> bool:
    """Write a credential; return True on success."""
    _, win32cred = _load_win32()
    credential = {
        "Type": win32cred.CRED_TYPE_GENERIC,
        "TargetName": target,
        "UserName": username,
        "CredentialBlob": password,
        "Comment": _COMMENT,
        "Persist": win32cred.CRED_PERSIST_LOCAL_MACHINE,
    }
    try:
        win32cred.CredWrite(credential, 0)
    except Exception as exc:  # noqa: BLE001 — any failure is a failed store
        logger.warning("CredWrite failed for %s: %s", target, exc)
        return False
    return True


def _delete_credential(target: str) -> bool:
    """Delete a credential; return True when an entry was removed."""
    _, win32cred = _load_win32()
    try:
        win32cred.CredDelete(Type=win32cred.CRED_TYPE_GENERIC, TargetName=target)
    except Exception as exc:  # noqa: BLE001 — any failure is a failed delete
        if getattr(exc, "winerror", None) != _ERROR_NOT_FOUND:
            logger.warning("CredDelete failed for %s: %s", target, exc)
        return False
    return True


class WinBackend(KeyringBackend):
    """Windows system keyring backed by Credential Manager.

    Selected deterministically by ``credstore._backend``; it is not registered
    as a keyring entry point, so installing credstore does not silently change
    the storage format used by unrelated keyring consumers.
    """

    def __init__(self) -> None:
        super().__init__()
        # Fail construction when the Windows bindings are missing, letting
        # the caller fall back to the environment store.
        _load_win32()

    @properties.classproperty
    def priority(cls) -> float:
        """Return 9.5 on Windows; raise RuntimeError otherwise."""
        if os.name != "nt":
            raise RuntimeError("WinBackend requires Windows")
        return 9.5

    def get_password(self, service: str, username: str) -> str | None:
        return _read_credential(target_name(service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        if not _set_credential(target_name(service, username), username, password):
            raise PasswordSetError(
                f"Failed to store credential for {service}/{username}"
            )

    def delete_password(self, service: str, username: str) -> None:
        if not _delete_credential(target_name(service, username)):
            raise PasswordDeleteError(
                f"Failed to delete credential for {service}/{username}"
            )

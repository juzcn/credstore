"""The one Credential Manager target-name format credstore writes.

Windows identifies a generic credential by ``TargetName`` alone — the
``UserName`` field is ignored by Credential Manager.  A separate target is
therefore required for every ``(service, username)`` pair.  credstore composes
them as ``{service}:{username}``, the convention ``keyring_wincred`` and
``go-keyring`` use; no other target name is written or read.

Keeping the composition in one module is deliberate: Windows and the WSL
bridge must never drift into two layouts again.
"""

from __future__ import annotations

SEPARATOR = ":"


def target_name(service: str, username: str) -> str:
    """Return the Credential Manager TargetName for a service/username pair."""
    return f"{service}{SEPARATOR}{username}"


def key_from_target(service: str, target: str) -> str | None:
    """Return the key encoded in *target*, or None for a foreign target.

    Matching is case-insensitive because Credential Manager target names are;
    the returned key keeps the spelling stored in *target*.
    """
    prefix = f"{service}{SEPARATOR}"
    if target[: len(prefix)].lower() != prefix.lower():
        return None
    key = target[len(prefix) :]
    return key or None

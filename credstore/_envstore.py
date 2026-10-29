"""Environment-variable fallback store.

credstore's primary store is the OS keyring and its backup is the encrypted
cryptfile.  When no usable keyring backend exists (a locked-down Linux
container, a headless host whose Credential Manager is unreachable, keyctl
blocked by seccomp), the environment takes the keyring's place: ``set`` writes
the secret to both the environment and the cryptfile, and every read that
would consult the keyring consults the environment instead — no master
password needed.

Naming
------
An environment-safe key (``[A-Za-z_][A-Za-z0-9_]*``) is stored under its own
name, so ``credstore set DEEPSEEK_API_KEY`` makes ``DEEPSEEK_API_KEY``
available to child processes.  Any other key (``myapp/provider/deepseek``) is
stored under ``CREDSTORE_KEY_`` plus a reversible escape — ``/`` becomes
``_2F``, ``_`` becomes ``__`` — because POSIX environments cannot hold such a
name.  ``CREDSTORE_``-prefixed keys are always escaped so a credential can
never overwrite credstore's own configuration variables (``CREDSTORE_FILE``,
``CREDSTORE_KEYCHAIN``, …).

Persistence
-----------
Windows: ``HKCU\\Environment`` — the same registry store ``inject`` uses — so
new processes inherit the value.  POSIX: ``~/.credstore/env`` (mode 0600), a
shell-sourceable file, plus one marked ``source`` line in ``~/.bashrc`` so new
shells export the values.  credstore itself also reads that file, which is
what makes the fallback work in non-interactive processes where no profile is
ever sourced.

Reads prefer ``os.environ``: a value provided by the caller's environment
(container runtime, CI, a parent shell) wins over the persisted copy.

Security: environment variables are plaintext.  That is the deliberate
trade-off of the fallback; the cryptfile remains the encrypted copy, and
``credstore status`` reports the mode.
"""

from __future__ import annotations

import logging
import os
import re
import shlex
from pathlib import Path

from credstore._config import get_env_file_path
from credstore._shell import _setx, _setx_delete, format_export, get_profile_path

logger = logging.getLogger("credstore")

__all__ = [
    "ENV_NAME_PREFIX",
    "delete_secret",
    "env_var_name",
    "get_secret",
    "has_secret",
    "key_from_env_var",
    "list_keys",
    "names",
    "store_secret",
]

#: Prefix for keys the environment cannot hold verbatim.  Also what makes the
#: stored entries enumerable again; bare-name entries are indistinguishable
#: from ordinary environment variables, which is exactly how they are read.
ENV_NAME_PREFIX = "CREDSTORE_KEY_"

_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

#: Marker for the one line ``store_secret`` adds to the shell profile.
_SOURCE_MARKER = "# credstore: environment fallback"


# ── naming ───────────────────────────────────────────────────


def env_var_name(key: str) -> str:
    """Return the environment variable that holds *key*.

    >>> env_var_name("DEEPSEEK_API_KEY")
    'DEEPSEEK_API_KEY'
    >>> env_var_name("myapp/provider/deepseek")
    'CREDSTORE_KEY_myapp_2Fprovider_2Fdeepseek'
    """
    if key and _ENV_NAME_RE.fullmatch(key) and not key.upper().startswith("CREDSTORE_"):
        return key
    return ENV_NAME_PREFIX + _encode(key)


def key_from_env_var(name: str) -> str | None:
    """Recover a credential key from a ``CREDSTORE_KEY_`` variable name.

    Returns ``None`` for names this store did not produce (including bare-name
    credentials, which cannot be told apart from ordinary environment
    variables).
    """
    if not name.startswith(ENV_NAME_PREFIX):
        return None
    body = name[len(ENV_NAME_PREFIX) :]
    if not body:
        return None
    return _decode(body)


def _encode(key: str) -> str:
    """Escape *key* into ``[A-Za-z0-9_]``, reversibly.

    ``_`` becomes ``__``; every other byte outside ``[A-Za-z0-9]`` becomes
    ``_HH``.  UTF-8 bytes keep non-ASCII keys representable in an ASCII-only
    variable name.
    """
    parts: list[str] = []
    for byte in key.encode("utf-8"):
        if 0x30 <= byte <= 0x39 or 0x41 <= byte <= 0x5A or 0x61 <= byte <= 0x7A:
            parts.append(chr(byte))
        elif byte == 0x5F:  # "_"
            parts.append("__")
        else:
            parts.append(f"_{byte:02X}")
    return "".join(parts)


def _decode(text: str) -> str | None:
    """Inverse of :func:`_encode`; ``None`` when *text* is malformed."""
    data = bytearray()
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "_":
            if i + 1 < len(text) and text[i + 1] == "_":
                data.append(0x5F)
                i += 2
                continue
            hex_pair = text[i + 1 : i + 3]
            if len(hex_pair) != 2:
                return None
            try:
                data.append(int(hex_pair, 16))
            except ValueError:
                return None
            i += 3
            continue
        if not (ch.isascii() and ch.isalnum()):
            return None
        data.extend(ch.encode("ascii"))
        i += 1
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


# ── public API ───────────────────────────────────────────────


def get_secret(key: str) -> str | None:
    """Read *key* from the live environment, then from the persisted copy.

    The caller owns the returned secret and must ``del`` it after use.
    """
    name = env_var_name(key)
    value = os.environ.get(name)
    if value is not None:
        return value
    return _persisted_get(name)


def has_secret(key: str) -> bool:
    """Whether *key* is present in the environment fallback."""
    return get_secret(key) is not None


def store_secret(key: str, value: str) -> None:
    """Store *key* in the live environment and persist it for new processes.

    Persistence comes first: a failed write must not leave the value live in
    this process while the store has nothing.
    """
    name = env_var_name(key)
    _persist(name, value)
    os.environ[name] = value


def delete_secret(key: str) -> bool:
    """Remove *key* from both the live environment and the persisted copy.

    Returns whether anything was removed.
    """
    name = env_var_name(key)
    persisted = _unpersist(name)
    live = os.environ.pop(name, None) is not None
    return persisted or live


def list_keys() -> list[str]:
    """List credential keys recoverable from the persistent environment.

    Only ``CREDSTORE_KEY_``-escaped entries can be recovered: a bare-name
    credential (``DEEPSEEK_API_KEY``) is indistinguishable from an ordinary
    environment variable, so it is never guessed at.  Callers that know the
    key they want should use :func:`get_secret`.
    """
    keys: list[str] = []
    seen: set[str] = set()
    for name in names():
        key = key_from_env_var(name)
        if key is None or key.upper() in seen:
            continue
        seen.add(key.upper())
        keys.append(key)
    return keys


def names() -> list[str]:
    """Every variable name the store can see, live and persisted.

    Used by the listing to recover the *original spelling* of a bare-name
    credential (the environment keeps it; the cryptfile folds it to upper
    case).  Only names are returned — the listing must not batch-load secret
    values.  Callers must not treat every name as a credential: ordinary
    environment variables are in here too.
    """
    all_names = set(_persisted_names())
    all_names.update(os.environ)
    return sorted(all_names)


# ── persistence: Windows registry ────────────────────────────


def _registry_get(name: str) -> str | None:
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ
        ) as handle:
            value, _kind = winreg.QueryValueEx(handle, name)
    except OSError:
        return None
    return value if isinstance(value, str) else None


def _registry_names() -> list[str]:
    import winreg

    names: list[str] = []
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ
        ) as handle:
            index = 0
            while True:
                try:
                    name, _value, _kind = winreg.EnumValue(handle, index)
                except OSError:
                    break
                names.append(name)
                index += 1
    except OSError:
        return []
    return names


# ── persistence: POSIX env file ──────────────────────────────


def _read_env_entry(name: str) -> str | None:
    """Read one entry, parsing no other value than the one requested."""
    marker = f"export {name}="
    path = Path(get_env_file_path())
    try:
        with path.open(encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line.startswith(marker):
                    continue
                try:
                    parts = shlex.split(line)
                except ValueError:
                    continue
                if len(parts) != 2 or parts[0] != "export":
                    continue
                entry_name, sep, value = parts[1].partition("=")
                if sep and entry_name == name:
                    return value
    except OSError:
        return None
    return None


def _env_file_names() -> list[str]:
    """Variable names in the env file, without parsing their values.

    The listing must not batch-load secrets; :func:`_read_env_entry` is for
    reads and the rewrite helpers only ever touch one entry's value.
    """
    path = Path(get_env_file_path())
    try:
        with path.open(encoding="utf-8") as handle:
            names = []
            for raw_line in handle:
                line = raw_line.strip()
                if not line.startswith("export "):
                    continue
                name = line[len("export ") :].split("=", 1)[0].strip()
                if name:
                    names.append(name)
    except OSError:
        return []
    return names


def _lines_without(lines: list[str], name: str) -> list[str]:
    marker = f"export {name}="
    return [line for line in lines if not line.strip().startswith(marker)]


def _write_env_entry(name: str, value: str) -> None:
    """Insert or replace one line, leaving every other line untouched."""
    path = Path(get_env_file_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass

    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        content = ""
    lines = _lines_without(content.splitlines(), name)
    lines.append(format_export(name, value, "bash"))

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _remove_env_entry(name: str) -> bool:
    path = Path(get_env_file_path())
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return False

    lines = content.splitlines()
    kept = _lines_without(lines, name)
    if len(kept) == len(lines):
        return False
    path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
    return True


def _ensure_profile_source(env_path: str) -> None:
    """Add a single marked ``source`` line to the shell profile, once."""
    profile = get_profile_path("bash")
    if profile is None:
        return

    try:
        content = profile.read_text(encoding="utf-8")
    except OSError:
        content = ""
    if _SOURCE_MARKER in content:
        return

    quoted = shlex.quote(env_path)
    line = f"[ -f {quoted} ] && . {quoted}"
    content = content.rstrip("\n")
    if content:
        content += "\n"
    content += f"{_SOURCE_MARKER}\n{line}\n"

    profile.parent.mkdir(parents=True, exist_ok=True)
    profile.write_text(content, encoding="utf-8")


# ── persistence dispatch ─────────────────────────────────────


def _persisted_get(name: str) -> str | None:
    if os.name == "nt":
        return _registry_get(name)
    return _read_env_entry(name)


def _persisted_names() -> list[str]:
    if os.name == "nt":
        return _registry_names()
    return _env_file_names()


def _persist(name: str, value: str) -> None:
    if os.name == "nt":
        _setx(name, value)
        return
    _write_env_entry(name, value)
    # The value is stored; a profile that cannot be updated only means new
    # login shells will not export it automatically.  Never fail the write
    # for that.
    try:
        _ensure_profile_source(get_env_file_path())
    except OSError as exc:
        logger.warning("could not add env fallback source line: %s", exc)


def _unpersist(name: str) -> bool:
    if os.name == "nt":
        existed = _registry_get(name) is not None
        _setx_delete(name)
        return existed
    return _remove_env_entry(name)

"""credstore — secure credential storage via OS keyring.

Cross-platform API for retrieving secrets stored in the OS keyring
with keyrings.cryptfile encrypted backup.  The CLI (``credstore set``)
reads secrets from masked stdin and dual-writes both stores; the Python
API's ``set_credential()`` writes the system keyring only.

Modules::

    _store.py        CredentialStore + module-level API
    _shell.py        Shell formatting helpers
    _backend.py      Dual-write backends (system keyring + cryptfile)
    _enumerate.py    Platform-specific credential enumeration
    _config.py       Config file loading
    _resolver.py     keyring: URI resolution
    _tty.py          Masked terminal input
    __main__.py      CLI (entry point)

Usage::

    import credstore

    # Retrieve a secret
    value = credstore.get_credential("myapp/api_key")

    # Resolve keyring: URIs in config values
    resolved = credstore.resolve_uri("keyring:myapp/api_key")

    # Delete
    credstore.delete_credential("myapp/api_key")

    # Shell formatting
    credstore.format_export("KEY", "value", "bash")  # → export statement

    # Persist to the system environment (registry on Windows / shell
    # profile on Unix) — the programmatic form of ``credstore inject``.
    credstore.persist_key("KEY", "value", "bash")
    credstore.unpersist_key("KEY", "bash")

    # Check backend
    info = credstore.check_backend()
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version

from credstore._resolver import (
    is_keyring_uri,
    parse_keyring_uri,
    resolve_uri,
)
from credstore._shell import (
    format_export,
    format_unset,
    persist_key,
    unpersist_key,
)
from credstore._store import (
    check_backend,
    delete_credential,
    exists_credential,
    get_backend_name,
    get_credential,
    init_store,
    list_credential_keys,
    set_credential,
)

try:
    __version__ = _version("credstore")
except PackageNotFoundError:
    # Running from a source tree that was never installed.
    __version__ = "0.0.0"

__all__ = [  # noqa: RUF022 — grouped by purpose, not alphabetically
    # Read / write / delete
    "get_credential",
    "exists_credential",
    "list_credential_keys",
    "set_credential",
    "delete_credential",
    # URI resolution
    "is_keyring_uri",
    "parse_keyring_uri",
    "resolve_uri",
    # Shell formatting / environment persistence
    "format_export",
    "format_unset",
    "persist_key",
    "unpersist_key",
    # Diagnostics
    "get_backend_name",
    "check_backend",
    "init_store",
]

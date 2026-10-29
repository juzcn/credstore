"""Shared fixtures and mocks for credstore tests."""

from __future__ import annotations

import pytest

from credstore._store import DEFAULT_SERVICE

from ._mocks import MockCryptfileBackend, MockKeyringBackend

# ═══════════════════════════════════════════════════════════════════════
# Shared data fixtures
# ═══════════════════════════════════════════════════════════════════════


@pytest.fixture
def in_mem_store() -> dict:
    """Empty in-memory dict for system keyring mock."""
    return {}


@pytest.fixture
def in_mem_cryptfile() -> dict:
    """Empty in-memory dict for cryptfile mock."""
    return {}


@pytest.fixture
def in_mem_env() -> dict:
    """Empty in-memory dict for the environment fallback."""
    return {}


# ═══════════════════════════════════════════════════════════════════════
# Backend-state cleanup (prevents cross-test leakage)
# ═══════════════════════════════════════════════════════════════════════


@pytest.fixture
def clean_backend_state(monkeypatch):
    """Reset credstore._backend module globals before each test.

    The _backend module uses module-level singletons for system_keyring
    and _cryptfile.  Tests that patch these directly can leave stale
    state.  This fixture guarantees a clean slate.
    """
    import credstore._backend as be

    monkeypatch.setattr(be, "_system_keyring", None)
    monkeypatch.setattr(be, "_cryptfile", None)


# ═══════════════════════════════════════════════════════════════════════
# Composable backend foundation
# ═══════════════════════════════════════════════════════════════════════


@pytest.fixture
def base_backend(monkeypatch, in_mem_store, in_mem_cryptfile):
    """Minimal composable backend foundation.

    Patches the core backend module with mock backends backed by
    ``in_mem_store`` and ``in_mem_cryptfile``.  Test files layer
    additional monkeypatches on top for their specific needs.

    Returns the mock cryptfile instance.
    """
    import credstore._backend as backend
    import credstore._store as sm

    # -- Prevent real init from running --
    monkeypatch.setattr(backend, "init_backend", lambda **kw: None)

    # -- System keyring mock --
    sk = MockKeyringBackend(in_mem_store)
    monkeypatch.setattr(backend, "get_system_keyring", lambda: sk)
    monkeypatch.setattr(backend, "_system_keyring", sk)

    # -- Cryptfile mock (only patch _cryptfile; get_cryptfile() reads it via global) --
    cf = MockCryptfileBackend(in_mem_cryptfile, keyring_key="mock-master-key")
    monkeypatch.setattr(backend, "_cryptfile", cf)

    # -- has_master_key: cryptfile file always "exists" --
    monkeypatch.setattr(backend, "has_master_key", lambda: True)

    # -- keyring_key_spellings: the real one enumerates Credential Manager on
    #    Windows/WSL; unit tests must not reach the host's real store.
    monkeypatch.setattr(sm, "keyring_key_spellings", lambda service=DEFAULT_SERVICE: {})

    # -- reinit_cryptfile: keep the mock, never build a real CryptFileKeyring.
    #    set-password calls reinit_cryptfile(), which normally re-runs
    #    _init_cryptfile() and constructs a real backend; on POSIX CI that
    #    construction fails and clobbers _cryptfile to None, breaking the
    #    first-time/change password tests.  The CLI then sees the mock
    #    cryptfile via get_cryptfile().
    monkeypatch.setattr(backend, "reinit_cryptfile", lambda password, **kw: None)

    # -- Backend names / info --
    monkeypatch.setattr(backend, "get_active_backend_name", lambda: "MockBackend")
    monkeypatch.setattr(
        backend,
        "get_backend_info",
        lambda: {
            "available": True,
            "backend": "MockBackend",
            "cryptfile_ready": True,
            "cryptfile_path": "/mock/credentials.crypt",
        },
    )

    # -- Config path (avoid CWD dependency) --
    import credstore._config as cfg

    monkeypatch.setattr(cfg, "get_cryptfile_path", lambda: "/mock/credentials.crypt")

    # -- Store module init --
    monkeypatch.setattr(sm, "init_store", lambda **kw: None)
    monkeypatch.setattr(sm, "get_backend_name", lambda: "MockBackend")
    monkeypatch.setattr(
        sm,
        "check_backend",
        lambda: {
            "available": True,
            "backend": "MockBackend",
            "cryptfile_ready": True,
            "cryptfile_path": "/mock/credentials.crypt",
        },
    )

    return cf


# ═══════════════════════════════════════════════════════════════════════
# CLI store wiring
# ═══════════════════════════════════════════════════════════════════════


@pytest.fixture
def cli_store(monkeypatch, in_mem_store, in_mem_cryptfile):
    """Wire credstore._store module-level API to in-memory dicts.

    Used by both test_cli.py and test_store.py.  Patching the module-level
    wrappers lets CLI tests call ``main()`` and have their ops land in
    the shared in-memory stores.
    """
    import credstore
    import credstore._store as sm

    store = sm.CredentialStore()
    store.get = in_mem_store.get
    store.set = in_mem_store.__setitem__
    store.delete = lambda key: in_mem_store.pop(key, None) is not None
    monkeypatch.setattr(sm, "_store", store)
    monkeypatch.setattr(sm, "_get_store", lambda: store)
    monkeypatch.setattr(sm, "get_credential", in_mem_store.get)
    monkeypatch.setattr(sm, "set_credential", in_mem_store.__setitem__)
    monkeypatch.setattr(
        sm, "delete_credential", lambda k: in_mem_store.pop(k, None) is not None
    )

    # Also patch the credstore package-level references
    monkeypatch.setattr(credstore, "get_credential", in_mem_store.get)
    monkeypatch.setattr(credstore, "set_credential", in_mem_store.__setitem__)
    monkeypatch.setattr(
        credstore, "delete_credential", lambda k: in_mem_store.pop(k, None) is not None
    )

    # Mock _read_cryptfile_keys
    monkeypatch.setattr(
        "credstore._store._read_cryptfile_keys",
        lambda cf, service=DEFAULT_SERVICE: list(in_mem_cryptfile.keys()),
    )

    # Mock keyring_key_spellings — the real one enumerates Credential Manager
    # on Windows/WSL, which a unit test must never touch.
    monkeypatch.setattr(
        "credstore._store.keyring_key_spellings",
        lambda service=DEFAULT_SERVICE: {},
    )

    # Mock _enumerate_system_keyring (never touch real Credential Manager)
    monkeypatch.setattr(
        "credstore.__main__._enumerate_system_keyring",
        lambda service, with_values=False: [],
    )

    # The environment fallback must never touch the host's registry / env file
    # from a unit test.  The no-keyring fixture overrides these to route at
    # its own in-memory dict.
    monkeypatch.setattr("credstore._envstore.has_secret", lambda k: False)
    monkeypatch.setattr("credstore._envstore.names", list)
    monkeypatch.setattr("credstore._envstore.list_keys", list)

    # Mock enumeration_supported: its real answer depends on the host OS (True
    # on Windows/WSL, False on macOS/Linux), and the list command branches on
    # it — pinning it keeps every listing test identical across platforms.
    monkeypatch.setattr("credstore.__main__.enumeration_supported", lambda: True)

    # os.path.exists — default to True (cryptfile exists)
    import os as _os

    monkeypatch.setattr(_os.path, "exists", lambda p: True)

    return store

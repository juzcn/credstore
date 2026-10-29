"""Tests for credential store operations."""

import logging
from contextlib import contextmanager
from typing import ClassVar

import pytest

pytestmark = pytest.mark.unit

import credstore._backend as be
import credstore._store as sm
from credstore._store import DEFAULT_SERVICE, CredentialStore, _read_cryptfile_keys

from ._mocks import MockCryptfileBackend, MockKeyringBackend


class _SealedCryptfile:
    """A cryptfile stand-in that enforces the spelling its entries are sealed with.

    Mirrors the real ``keyrings.cryptfile``: the key's original spelling is
    bound into the entry's AEAD associated data, so a lookup under any other
    case fails its MAC check — ``ValueError`` — instead of returning a value
    (or a wrong one).  Absent keys return None.
    """

    def __init__(self, entries: dict[str, str]):
        self._entries = entries

    def get_password(self, service: str, username: str) -> str | None:
        if username in self._entries:
            return self._entries[username]
        folded = username.lower()
        if any(k.lower() == folded for k in self._entries):
            raise ValueError("MAC check failed")
        return None


def _already_unlocked(cf):
    """Build a stand-in for ``unlocked_cryptfile`` that yields *cf* as-is."""

    @contextmanager
    def _unlock(password):
        yield cf

    return _unlock


class TestCredentialStore:
    def test_set_and_get(self, dual_store):
        store, data = dual_store
        store.set("test-key", "secret-value")
        assert store.get("test-key") == "secret-value"
        assert "system:test-key" in data

    def test_get_not_found(self, dual_store):
        store, _ = dual_store
        assert store.get("nonexistent") is None

    def test_delete_existing(self, dual_store):
        store, data = dual_store
        store.set("test-key", "secret-value")
        assert store.delete("test-key") is True
        assert store.get("test-key") is None
        assert "system:test-key" not in data

    def test_delete_not_found(self, dual_store):
        store, _ = dual_store
        assert store.delete("nonexistent") is False

    def test_overwrite(self, dual_store):
        store, _ = dual_store
        store.set("test-key", "first")
        store.set("test-key", "second")
        assert store.get("test-key") == "second"

    def test_keys_with_slashes(self, dual_store):
        store, _ = dual_store
        store.set("myapp/provider/deepseek", "sk-key")
        assert store.get("myapp/provider/deepseek") == "sk-key"

    def test_reset_restores_to_system(self, dual_store, monkeypatch):
        """reset() reads from cryptfile and writes to system keyring."""
        store, data = dual_store
        data["cryptfile:key1"] = "val1"
        data["cryptfile:key2"] = "val2"

        monkeypatch.setattr(
            "credstore._store._read_cryptfile_keys",
            lambda cf, service=DEFAULT_SERVICE: [
                k.split(":", 1)[1] for k in data if k.startswith("cryptfile:")
            ],
        )

        assert store.get("key1") is None
        count = store.reset("mock-password")
        assert count == 2
        assert data["system:key1"] == "val1"
        assert data["system:key2"] == "val2"

    def test_get_system_only(self, dual_store):
        """get() only reads from system keyring, not cryptfile."""
        store, data = dual_store
        data["cryptfile:only-cf"] = "from-cf"
        assert store.get("only-cf") is None


class TestResolveCryptfileEntry:
    """The cryptfile cannot say how a key was spelled — lookups must recover it.

    ``keyrings.cryptfile`` folds the INI option name to lower case but binds
    the key's original spelling into the entry's AEAD associated data, so a
    lookup with the wrong case fails its MAC check (ValueError) rather than
    returning a wrong value.  Reading a key out of the file therefore means
    trying the spellings that could have produced the stored option name.
    """

    def test_resolves_lowercase_sealed_entry(self):
        """Canonical 'MYAPP/API_KEY' is found as the sealed 'myapp/api_key'."""
        entry = sm.resolve_cryptfile_entry(
            _SealedCryptfile({"myapp/api_key": "s3cret"}), "MYAPP/API_KEY"
        )
        assert entry == ("myapp/api_key", "s3cret")

    def test_resolves_uppercase_sealed_entry(self):
        """...and an upper-case entry is found from the same canonical name."""
        entry = sm.resolve_cryptfile_entry(
            _SealedCryptfile({"MCP_OAUTH_TOKEN": "tok"}), "MCP_OAUTH_TOKEN"
        )
        assert entry == ("MCP_OAUTH_TOKEN", "tok")

    def test_keyring_spelling_wins(self):
        """A mixed-case key is recoverable only from the keyring's spelling."""
        cf = _SealedCryptfile({"myApp/ApiKey": "mixed"})
        with pytest.raises(ValueError):
            sm.resolve_cryptfile_entry(cf, "MYAPP/APIKEY")
        entry = sm.resolve_cryptfile_entry(
            cf, "MYAPP/APIKEY", spellings={"MYAPP/APIKEY": "myApp/ApiKey"}
        )
        assert entry == ("myApp/ApiKey", "mixed")

    def test_absent_entry_returns_none(self):
        assert sm.resolve_cryptfile_entry(_SealedCryptfile({}), "NOPE") is None

    def test_unrecoverable_spelling_raises(self):
        """An entry that exists but decrypts under no candidate must raise.

        Reporting it as "absent" is what let `reset-keyring` and the
        `set-password` change path drop credentials without a word.
        """
        cf = _SealedCryptfile({"myApp/ApiKey": "mixed"})
        with pytest.raises(ValueError):
            sm.resolve_cryptfile_entry(cf, "MYAPP/APIKEY")


class TestResetKeepsSealedSpelling:
    """reset() must restore under the spelling the cryptfile sealed."""

    def test_reset_restores_lowercase_entry(self, dual_store, monkeypatch):
        store, data = dual_store
        monkeypatch.setattr(
            be,
            "unlocked_cryptfile",
            _already_unlocked(_SealedCryptfile({"myapp/api_key": "s3cret"})),
        )
        monkeypatch.setattr(
            sm,
            "_read_cryptfile_keys",
            lambda cf, service=DEFAULT_SERVICE: ["MYAPP/API_KEY"],
        )
        monkeypatch.setattr(
            sm, "keyring_key_spellings", lambda service=DEFAULT_SERVICE: {}
        )

        assert store.reset("pw") == 1
        # Restored under the sealed spelling — writing the canonical form into
        # the keyring would leave the backup entry unreachable by that name.
        assert data["system:myapp/api_key"] == "s3cret"
        assert "system:MYAPP/API_KEY" not in data

    def test_reset_uses_keyring_spelling_for_mixed_case(self, dual_store, monkeypatch):
        store, data = dual_store
        monkeypatch.setattr(
            be,
            "unlocked_cryptfile",
            _already_unlocked(_SealedCryptfile({"myApp/ApiKey": "v"})),
        )
        monkeypatch.setattr(
            sm,
            "_read_cryptfile_keys",
            lambda cf, service=DEFAULT_SERVICE: ["MYAPP/APIKEY"],
        )
        monkeypatch.setattr(
            sm,
            "keyring_key_spellings",
            lambda service=DEFAULT_SERVICE: {"MYAPP/APIKEY": "myApp/ApiKey"},
        )

        assert store.reset("pw") == 1
        assert data["system:myApp/ApiKey"] == "v"

    @pytest.mark.parametrize(
        "enumerable,advertises",
        [
            # Where the keyring can be listed, re-syncing repairs the entry.
            (True, "reset-backup"),
            # Where it cannot (macOS, Linux), reset-backup would enumerate
            # nothing and sync nothing — pointing at it is a dead end.
            (False, "credstore set"),
        ],
    )
    def test_reset_reports_unreadable_entry(
        self, dual_store, monkeypatch, caplog, enumerable, advertises
    ):
        """A key that cannot be read back is skipped *loudly* and with a
        remedy that works on this platform."""
        store, _data = dual_store
        monkeypatch.setattr(
            be,
            "unlocked_cryptfile",
            _already_unlocked(_SealedCryptfile({"myApp/ApiKey": "v"})),
        )
        monkeypatch.setattr(
            sm,
            "_read_cryptfile_keys",
            lambda cf, service=DEFAULT_SERVICE: ["MYAPP/APIKEY"],
        )
        monkeypatch.setattr(
            sm, "keyring_key_spellings", lambda service=DEFAULT_SERVICE: {}
        )
        monkeypatch.setattr(
            "credstore._enumerate.enumeration_supported", lambda: enumerable
        )

        with caplog.at_level(logging.WARNING, logger="credstore"):
            assert store.reset("pw") == 0
        assert "reset_skip" in caplog.text
        assert advertises in caplog.text


@pytest.mark.integration
class TestResetAgainstRealCryptfile:
    """The real encrypted file is what loses the key's case — test against it.

    ``reset-keyring`` is the disaster-recovery command (the system keyring
    was wiped, the backup is all that is left), so the file's case handling
    has to hold for the library that actually writes it, not just a mock.
    """

    KEYS: ClassVar[dict[str, str]] = {
        "myapp/api_key": "secret-lower",
        "MCP_OAUTH_TOKEN": "secret-upper",
        "gh/cli-token": "secret-slash",
    }

    def _sealed_cryptfile(self, tmp_path):
        from keyrings.cryptfile.cryptfile import CryptFileKeyring

        cf = CryptFileKeyring()
        # file_path is a read-only NonDataProperty on the class; an instance
        # attribute shadows it (same assignment as _backend._init_cryptfile).
        cf.file_path = str(tmp_path / "credentials.crypt")  # type: ignore[assignment]
        cf.keyring_key = "master-password"
        for key, secret in self.KEYS.items():
            cf.set_password(DEFAULT_SERVICE, key, secret)
        return cf

    def test_reset_restores_every_key_under_its_own_spelling(
        self, tmp_path, monkeypatch
    ):
        cf = self._sealed_cryptfile(tmp_path)

        restored: dict[str, str] = {}

        class _WipedKeyring:
            """A keyring that lost its values — the case reset-keyring exists for."""

            def get_password(self, service, username):
                return None

            def set_password(self, service, username, password):
                restored[username] = password

        monkeypatch.setattr(be, "get_system_keyring", lambda: _WipedKeyring())
        monkeypatch.setattr(be, "unlocked_cryptfile", _already_unlocked(cf))
        monkeypatch.setattr(
            sm, "keyring_key_spellings", lambda service=DEFAULT_SERVICE: {}
        )

        store = CredentialStore()
        monkeypatch.setattr(sm, "_get_store", lambda: store)

        # Every credential comes back — a name read out of the file is
        # canonicalised, so a lookup has to recover the sealed spelling.
        assert store.reset("master-password") == len(self.KEYS)
        assert restored == self.KEYS


class TestMask:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("", "(empty)"),
            ("short", "***"),
            ("12345678", "***"),
            ("123456789", "1234…6789"),
            ("sk-5f55bd925bc84372917a77e282bdb722", "sk-5…b722"),
        ],
    )
    def test_mask(self, value, expected):
        assert CredentialStore.mask(value) == expected


class TestCredentialStoreEdgeCases:
    """Tests for error paths and edge cases in CredentialStore."""

    def test_get_without_keyring(self, monkeypatch):
        """No keyring → get() reads the environment fallback."""
        store = CredentialStore()
        monkeypatch.setattr(be, "get_system_keyring", lambda: None)
        monkeypatch.setattr(
            "credstore._envstore.get_secret", lambda key: "env-fallback-value"
        )
        assert store.get("any-key") == "env-fallback-value"

    def test_exists_returns_false_for_missing(self, dual_store):
        store, _data = dual_store
        assert store.exists("nonexistent-key") is False

    def test_exists_returns_true_for_stored(self, dual_store):
        store, _data = dual_store
        store.set("exists-test", "secret")
        assert store.exists("exists-test") is True

    def test_list_keys_returns_list(self, dual_store):
        store, _data = dual_store
        result = store.list_keys()
        assert isinstance(result, list)

    def test_list_keys_without_keyring(self, monkeypatch):
        """No keyring → list_keys() lists the environment fallback."""
        store = CredentialStore()
        monkeypatch.setattr(be, "get_system_keyring", lambda: None)
        monkeypatch.setattr(be, "get_cryptfile", lambda: None)
        monkeypatch.setattr("credstore._envstore.list_keys", lambda: ["ENV_KEY"])
        assert store.list_keys() == ["ENV_KEY"]

    def test_list_keys_env_fallback_prefers_env_spelling(self, monkeypatch, tmp_path):
        """The backup folds names to upper case; the environment keeps them.

        A lowercase key (``mcp_oauth_token``) must be listed with the spelling
        ``get_credential`` can actually read back.
        """
        store = CredentialStore()
        monkeypatch.setattr(be, "get_system_keyring", lambda: None)

        backup = tmp_path / "test.crypt"
        backup.write_text(
            f"[{DEFAULT_SERVICE}]\nmcp_oauth_token = tok\n", encoding="utf-8"
        )

        class _CF:
            file_path = str(backup)

        monkeypatch.setattr(be, "get_cryptfile", lambda: _CF())
        monkeypatch.setattr("credstore._envstore.list_keys", list)
        monkeypatch.setattr("credstore._envstore.names", lambda: ["mcp_oauth_token"])

        assert store.list_keys() == ["mcp_oauth_token"]

    def test_list_keys_env_fallback_includes_backup_only_keys(
        self, monkeypatch, tmp_path
    ):
        """A key the backup knows and the environment does not is still listed."""
        store = CredentialStore()
        monkeypatch.setattr(be, "get_system_keyring", lambda: None)

        backup = tmp_path / "test.crypt"
        backup.write_text(f"[{DEFAULT_SERVICE}]\nBACKUP_ONLY = v\n", encoding="utf-8")

        class _CF:
            file_path = str(backup)

        monkeypatch.setattr(be, "get_cryptfile", lambda: _CF())
        monkeypatch.setattr("credstore._envstore.list_keys", list)
        monkeypatch.setattr("credstore._envstore.names", list)

        assert store.list_keys() == ["BACKUP_ONLY"]

    def test_set_requires_master_key(self, dual_store, monkeypatch):
        """set() raises RuntimeError when master key not set."""
        store, _data = dual_store
        monkeypatch.setattr(be, "has_master_key", lambda: False)
        with pytest.raises(RuntimeError, match="Master key not set"):
            store.set("key", "secret")

    def test_set_without_keyring_uses_env_fallback(self, dual_store, monkeypatch):
        """set() writes the environment fallback when no keyring is available."""
        store, _data = dual_store
        monkeypatch.setattr(be, "get_system_keyring", lambda: None)
        written: dict[str, str] = {}
        monkeypatch.setattr(
            "credstore._envstore.store_secret",
            lambda key, value: written.__setitem__(key, value),
        )
        store.set("key", "secret")
        assert written == {"key": "secret"}

    def test_delete_without_keyring_uses_env_fallback(self, dual_store, monkeypatch):
        """delete() removes the environment copy when no keyring is available."""
        store, _data = dual_store
        monkeypatch.setattr(be, "get_system_keyring", lambda: None)
        deleted: list[str] = []
        monkeypatch.setattr(
            "credstore._envstore.delete_secret",
            lambda key: deleted.append(key) or True,
        )
        assert store.delete("key") is True
        assert deleted == ["key"]

    def test_reset_no_keyring(self, monkeypatch):
        """reset() refuses without a keyring and points at reset-env."""
        store = CredentialStore()
        monkeypatch.setattr(be, "get_system_keyring", lambda: None)
        with pytest.raises(RuntimeError, match="reset-env"):
            store.reset("master-pw")

    def test_reset_environment_no_keyring(self, monkeypatch, tmp_path):
        """reset_environment() restores into the environment fallback."""
        store = CredentialStore()
        monkeypatch.setattr(be, "get_system_keyring", lambda: None)
        monkeypatch.setattr(
            "credstore._store.keyring_key_spellings",
            lambda service=DEFAULT_SERVICE: {},
        )

        cf_path = tmp_path / "test.crypt"
        cf_path.write_text(f"[{DEFAULT_SERVICE}]\ngood-key = good-val\n")

        @contextmanager
        def _unlock_with_env(pw):
            class _CF:
                file_path = str(cf_path)

                def get_password(self, service, key):
                    return "good-val" if key == "GOOD-KEY" else None

            yield _CF()

        monkeypatch.setattr(be, "unlocked_cryptfile", _unlock_with_env)
        written: dict[str, str] = {}
        monkeypatch.setattr(
            "credstore._envstore.store_secret",
            lambda key, value: written.__setitem__(key, value),
        )

        assert store.reset_environment("pw") == 1
        assert written == {"GOOD-KEY": "good-val"}

    def test_reset_skip_on_get_error(self, dual_store, monkeypatch, tmp_path):
        """reset() skips keys that fail during get_password."""
        store, data = dual_store

        cf_path = tmp_path / "test.crypt"
        cf_path.write_text(
            f"[{DEFAULT_SERVICE}]\ngood-key = good-val\nbad-key = bad-val\n"
        )

        @contextmanager
        def _unlock_with_bad_key(pw):
            class _BadCF:
                file_path = str(cf_path)

                def get_password(self, service, key):
                    if key == "BAD-KEY":
                        raise RuntimeError("decrypt error")
                    return data.get(key)

            yield _BadCF()

        monkeypatch.setattr(be, "unlocked_cryptfile", _unlock_with_bad_key)
        data["GOOD-KEY"] = "good-val"
        data["BAD-KEY"] = "bad-val"
        count = store.reset("pw")
        assert count == 1


class TestStoreModuleApi:
    """Tests for the module-level convenience functions."""

    def test_init_store_with_password(self, monkeypatch):
        """init_store(password=...) passes password to init_backend."""
        monkeypatch.setattr(be, "init_backend", lambda password=None: None)
        monkeypatch.setattr(sm, "_store", None)
        monkeypatch.setattr(be, "has_master_key", lambda: True)
        store = sm.init_store(password="test-pw")
        assert isinstance(store, CredentialStore)

    def test_get_store_lazy_init(self, monkeypatch):
        """_get_store() lazy-inits when _store is None."""
        monkeypatch.setattr(sm, "_store", None)
        monkeypatch.setattr(be, "init_backend", lambda password=None: None)
        monkeypatch.setattr(be, "has_master_key", lambda: True)
        store = sm._get_store()
        assert isinstance(store, CredentialStore)

    def test_list_credential_keys_module(self):
        """list_credential_keys() returns list without values."""
        result = sm.list_credential_keys()
        assert isinstance(result, list)

    def test_get_credential_returns_none(self, monkeypatch):
        """get_credential returns None for missing key."""
        monkeypatch.setattr(sm, "_store", None)
        monkeypatch.setattr(be, "init_backend", lambda password=None: None)
        monkeypatch.setattr(be, "get_system_keyring", lambda: None)
        monkeypatch.setattr(be, "has_master_key", lambda: True)
        assert sm.get_credential("nonexistent") is None

    def test_read_cryptfile_keys_parses_ini(self, tmp_path):
        """_read_cryptfile_keys parses cryptfile INI format."""
        ini_content = (
            "[DEFAULT]\n"
            "keyring = cryptfile\n"
            f"[{DEFAULT_SERVICE}]\n"
            "test_key = escaped-value\n"
        )
        cf_path = tmp_path / "test.crypt"
        cf_path.write_text(ini_content)

        class _MockCF:
            file_path = str(cf_path)

        keys = _read_cryptfile_keys(_MockCF())
        assert isinstance(keys, list)

    def test_read_cryptfile_keys_skips_other_sections(self, tmp_path):
        """_read_cryptfile_keys ignores non-credstore sections."""
        ini_content = (
            "[keyring]\n"
            "something = ignored\n"
            "[other-app]\n"
            "their_key = their-val\n"
            f"[{DEFAULT_SERVICE}]\n"
            "my_key = my-val\n"
        )
        cf_path = tmp_path / "test2.crypt"
        cf_path.write_text(ini_content)

        class _MockCF:
            file_path = str(cf_path)

        keys = _read_cryptfile_keys(_MockCF())
        assert len(keys) == 1

    def test_set_credential_module_wrapper(self, dual_store, monkeypatch):
        """set_credential() delegates to store.set()."""
        store, data = dual_store
        monkeypatch.setattr("credstore._store._store", store)
        sm.set_credential("my-key", "my-secret")
        assert data.get("system:my-key") == "my-secret"

    def test_delete_credential_module_wrapper(self, dual_store, monkeypatch):
        """delete_credential() delegates to store.delete()."""
        store, data = dual_store
        data["system:my-key"] = "my-secret"
        monkeypatch.setattr("credstore._store._store", store)
        assert sm.delete_credential("my-key") is True
        assert "system:my-key" not in data

    def test_exists_credential_module_wrapper(self, monkeypatch):
        """exists_credential() returns bool without retrieving value."""
        store = CredentialStore()
        monkeypatch.setattr("credstore._store._store", store)
        monkeypatch.setattr(be, "get_system_keyring", lambda: None)
        monkeypatch.setattr(be, "has_master_key", lambda: True)
        monkeypatch.setattr("credstore._envstore.get_secret", lambda key: None)
        assert sm.exists_credential("anything") is False

    def test_get_backend_name_module(self, monkeypatch):
        """get_backend_name() returns a string."""
        monkeypatch.setattr(be, "get_active_backend_name", lambda: "test-backend")
        assert sm.get_backend_name() == "test-backend"

    def test_check_backend_module(self, monkeypatch):
        """check_backend() returns a dict."""
        monkeypatch.setattr(be, "get_backend_info", lambda: {"available": True})
        result = sm.check_backend()
        assert result["available"] is True


# ── fixtures ───────────────────────────────────────────────────


@pytest.fixture
def dual_store(monkeypatch):
    """A CredentialStore with mocked dual-write backends."""
    data = {}

    system = MockKeyringBackend(data, prefix="system")
    cryptfile = MockCryptfileBackend(
        data, prefix="cryptfile", keyring_key="mock-password"
    )

    monkeypatch.setattr(be, "get_system_keyring", lambda: system)
    monkeypatch.setattr(be, "get_cryptfile", lambda: cryptfile)
    monkeypatch.setattr(be, "has_master_key", lambda: True)
    monkeypatch.setattr(be, "_system_keyring", system)
    monkeypatch.setattr(be, "_cryptfile", cryptfile)
    monkeypatch.setattr(be, "init_backend", lambda **kw: None)

    store = CredentialStore()
    monkeypatch.setattr(sm, "_store", store)
    monkeypatch.setattr(sm, "_get_store", lambda: store)

    return store, data

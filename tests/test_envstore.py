"""Tests for the environment-variable fallback store."""

from __future__ import annotations

import os

import pytest

from credstore import _envstore


@pytest.fixture
def clean_environ(monkeypatch):
    """Isolate the live environment from the host's variables."""
    fresh: dict[str, str] = {}
    monkeypatch.setattr(os, "environ", fresh)
    return fresh


# ═══════════════════════════════════════════════════════════════
# naming
# ═══════════════════════════════════════════════════════════════


class TestEnvVarName:
    def test_env_safe_key_is_its_own_name(self):
        assert _envstore.env_var_name("DEEPSEEK_API_KEY") == "DEEPSEEK_API_KEY"
        assert _envstore.env_var_name("mcp_oauth-token") != "mcp_oauth-token"

    def test_namespaced_key_is_escaped(self):
        assert (
            _envstore.env_var_name("myapp/provider/deepseek")
            == "CREDSTORE_KEY_myapp_2Fprovider_2Fdeepseek"
        )

    def test_credstore_prefixed_key_is_escaped(self):
        """A credential must never overwrite credstore's own config vars."""
        assert _envstore.env_var_name("CREDSTORE_FILE") == (
            "CREDSTORE_KEY_CREDSTORE__FILE"
        )
        assert _envstore.env_var_name("CREDSTORE_KEY_X") == (
            "CREDSTORE_KEY_CREDSTORE__KEY__X"
        )

    @pytest.mark.parametrize(
        "key",
        [
            "myapp/provider/deepseek",
            "a_b/c-d",
            "CREDSTORE_FILE",
            "CREDSTORE_KEY_X",
            "ключ/名称",
        ],
    )
    def test_escaped_name_round_trips(self, key):
        name = _envstore.env_var_name(key)
        assert name.startswith(_envstore.ENV_NAME_PREFIX)
        assert _envstore.key_from_env_var(name) == key

    def test_bare_name_is_not_recoverable(self):
        """A bare variable cannot be told apart from a user's own variable."""
        assert _envstore.key_from_env_var("DEEPSEEK_API_KEY") is None

    def test_malformed_escape_is_rejected(self):
        assert _envstore.key_from_env_var("CREDSTORE_KEY_a_") is None


# ═══════════════════════════════════════════════════════════════
# reads (platform-independent, persistence mocked)
# ═══════════════════════════════════════════════════════════════


class TestReads:
    def test_live_environment_wins(self, clean_environ, monkeypatch):
        clean_environ["MY_KEY"] = "live"
        monkeypatch.setattr(_envstore, "_persisted_get", lambda name: "persisted")
        assert _envstore.get_secret("MY_KEY") == "live"

    def test_persisted_copy_is_the_fallback(self, clean_environ, monkeypatch):
        monkeypatch.setattr(_envstore, "_persisted_get", lambda name: "persisted")
        assert _envstore.get_secret("MY_KEY") == "persisted"

    def test_missing_key_is_none(self, clean_environ, monkeypatch):
        monkeypatch.setattr(_envstore, "_persisted_get", lambda name: None)
        assert _envstore.get_secret("MY_KEY") is None


# ═══════════════════════════════════════════════════════════════
# POSIX persistence: ~/.credstore/env + profile source line
# ═══════════════════════════════════════════════════════════════


@pytest.mark.skipif(os.name == "nt", reason="POSIX env-file persistence")
class TestPosixEnvFile:
    @pytest.fixture
    def env_file(self, tmp_path, monkeypatch, clean_environ):
        path = tmp_path / "credstore" / "env"
        profile = tmp_path / "home" / ".bashrc"
        monkeypatch.setattr(_envstore, "get_env_file_path", lambda: str(path))
        monkeypatch.setattr(_envstore, "get_profile_path", lambda shell="auto": profile)
        return path, profile

    def test_store_persists_value_and_is_private(self, env_file):
        path, profile = env_file
        _envstore.store_secret("myapp/api_key", "s3cret-v4lue")

        name = "CREDSTORE_KEY_myapp_2Fapi__key"
        assert os.environ[name] == "s3cret-v4lue"
        assert f"export {name}='s3cret-v4lue'" in path.read_text(encoding="utf-8")
        assert path.stat().st_mode & 0o777 == 0o600
        assert "# credstore: environment fallback" in profile.read_text(
            encoding="utf-8"
        )
        assert str(path) in profile.read_text(encoding="utf-8")

    def test_profile_source_line_is_added_once(self, env_file):
        _, profile = env_file
        _envstore.store_secret("A_KEY", "1")
        _envstore.store_secret("B_KEY", "2")
        content = profile.read_text(encoding="utf-8")
        assert content.count("# credstore: environment fallback") == 1

    def test_get_reads_file_for_a_new_process(self, env_file):
        path, _ = env_file
        path.parent.mkdir(parents=True)
        path.write_text("export MY_KEY='from-file'\n", encoding="utf-8")
        assert _envstore.get_secret("MY_KEY") == "from-file"

    def test_get_parses_shell_quoted_values(self, env_file):
        path, _ = env_file
        path.parent.mkdir(parents=True)
        path.write_text("export MY_KEY='a'\\''b c'\n", encoding="utf-8")
        assert _envstore.get_secret("MY_KEY") == "a'b c"

    def test_delete_removes_live_and_persisted(self, env_file):
        path, _ = env_file
        _envstore.store_secret("MY_KEY", "v")
        assert _envstore.delete_secret("MY_KEY") is True
        assert "MY_KEY" not in os.environ
        assert "MY_KEY" not in path.read_text(encoding="utf-8")
        assert _envstore.delete_secret("MY_KEY") is False

    def test_list_keys_recovers_escaped_names_only(self, env_file):
        _envstore.store_secret("myapp/api_key", "v1")
        _envstore.store_secret("PLAIN_KEY", "v2")
        # PLAIN_KEY is stored under its own name and cannot be recovered;
        # it is still readable by name.
        assert _envstore.list_keys() == ["myapp/api_key"]
        assert _envstore.get_secret("PLAIN_KEY") == "v2"

    def test_profile_failure_does_not_fail_the_store(self, env_file, monkeypatch):
        """An unwritable profile must not lose the value."""
        path, _ = env_file

        def _fail(env_path):
            raise OSError("read-only profile")

        monkeypatch.setattr(_envstore, "_ensure_profile_source", _fail)
        _envstore.store_secret("MY_KEY", "v")

        assert _envstore.get_secret("MY_KEY") == "v"
        assert "MY_KEY" in path.read_text(encoding="utf-8")

    def test_rewrite_preserves_other_entries(self, env_file):
        path, _ = env_file
        _envstore.store_secret("A_KEY", "1")
        _envstore.store_secret("B_KEY", "2")
        _envstore.store_secret("A_KEY", "3")
        assert _envstore.get_secret("A_KEY") == "3"
        assert _envstore.get_secret("B_KEY") == "2"
        assert path.read_text(encoding="utf-8").count("export A_KEY=") == 1


# ═══════════════════════════════════════════════════════════════
# Windows persistence: HKCU\Environment
# ═══════════════════════════════════════════════════════════════


@pytest.mark.skipif(os.name != "nt", reason="Windows registry persistence")
class TestWindowsRegistry:
    @pytest.fixture
    def registry(self, monkeypatch, clean_environ):
        data: dict[str, str] = {}
        monkeypatch.setattr(
            _envstore, "_setx", lambda name, value: data.__setitem__(name, value)
        )
        monkeypatch.setattr(
            _envstore, "_setx_delete", lambda name: data.pop(name, None)
        )
        monkeypatch.setattr(_envstore, "_registry_get", data.get)
        monkeypatch.setattr(_envstore, "_registry_names", lambda: list(data))
        return data

    def test_store_persists_to_registry_and_live_env(self, registry):
        _envstore.store_secret("myapp/api_key", "s3cret")
        name = "CREDSTORE_KEY_myapp_2Fapi__key"
        assert registry[name] == "s3cret"
        assert os.environ[name] == "s3cret"

    def test_get_reads_registry_for_a_new_process(self, registry, monkeypatch):
        _envstore.store_secret("MY_KEY", "from-registry")
        monkeypatch.delitem(os.environ, "MY_KEY")
        assert _envstore.get_secret("MY_KEY") == "from-registry"

    def test_delete_removes_live_and_registry(self, registry):
        _envstore.store_secret("MY_KEY", "v")
        assert _envstore.delete_secret("MY_KEY") is True
        assert "MY_KEY" not in os.environ
        assert "MY_KEY" not in registry
        assert _envstore.delete_secret("MY_KEY") is False

    def test_list_keys_recovers_escaped_names_only(self, registry):
        _envstore.store_secret("myapp/api_key", "v1")
        _envstore.store_secret("PLAIN_KEY", "v2")
        assert _envstore.list_keys() == ["myapp/api_key"]

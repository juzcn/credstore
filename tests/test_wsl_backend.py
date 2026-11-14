"""Tests for credstore._wsl_backend — WSL system-keyring bridge."""

from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest
from keyring.errors import PasswordDeleteError, PasswordSetError


def _fake_result(out="", err="", rc=0):
    return SimpleNamespace(returncode=rc, stdout=out, stderr=err)


def _b64(password: str) -> str:
    return base64.b64encode(password.encode("utf-16-le")).decode("ascii")


# ═══════════════════════════════════════════════════════════════════════
# WslBackend.priority
# ═══════════════════════════════════════════════════════════════════════


class TestWslBackendPriority:
    def test_returns_9_5_on_wsl(self, monkeypatch):
        monkeypatch.setattr("credstore._wsl_backend.is_wsl", lambda: True)
        monkeypatch.setattr("platform.system", lambda: "Linux")
        monkeypatch.setattr(
            "credstore._wsl_backend.subprocess.run",
            lambda cmd, **kw: _fake_result(out="ok"),
        )
        from credstore._wsl_backend import WslBackend

        assert WslBackend.priority == 9.5

    def test_raises_on_non_linux(self, monkeypatch):
        monkeypatch.setattr("platform.system", lambda: "Windows")
        from credstore._wsl_backend import WslBackend

        with pytest.raises(RuntimeError, match="requires Linux"):
            _ = WslBackend.priority

    def test_raises_on_non_wsl_linux(self, monkeypatch):
        monkeypatch.setattr("platform.system", lambda: "Linux")
        monkeypatch.setattr("credstore._wsl_backend.is_wsl", lambda: False)
        from credstore._wsl_backend import WslBackend

        with pytest.raises(RuntimeError, match="requires WSL"):
            _ = WslBackend.priority

    def test_raises_when_powershell_unavailable(self, monkeypatch):
        """powershell.exe missing → RuntimeError on first operation.

        The priority property only checks platform + WSL status;
        the actual powershell probe happens lazily on first use.
        """
        monkeypatch.setattr("platform.system", lambda: "Linux")
        monkeypatch.setattr("credstore._wsl_backend.is_wsl", lambda: True)
        monkeypatch.setattr(
            "credstore._wsl_backend.subprocess.run",
            lambda cmd, **kw: _fake_result(out="ok"),
        )

        from credstore._wsl_backend import WslBackend

        assert WslBackend.priority == 9.5

        # Now break powershell and verify the backend raises on use
        def _fail(cmd, **kw):
            raise FileNotFoundError("powershell.exe")

        monkeypatch.setattr("credstore._wsl_backend.subprocess.run", _fail)
        backend = WslBackend()
        with pytest.raises(FileNotFoundError, match="powershell.exe"):
            backend.get_password("svc", "usr")


# ═══════════════════════════════════════════════════════════════════════
# _run_powershell
# ═══════════════════════════════════════════════════════════════════════


class TestRunPowershell:
    def test_success(self, monkeypatch):
        monkeypatch.setattr(
            "credstore._wsl_backend.subprocess.run",
            lambda cmd, **kw: _fake_result(out="  hello  ", err="warn"),
        )
        from credstore._wsl_backend import _run_powershell

        rc, out, err = _run_powershell("Write-Output test")
        assert rc == 0
        assert out == "hello"
        assert err == "warn"

    def test_encoding_is_utf8_with_replace(self, monkeypatch):
        captured = {}

        def _capture(cmd, **kw):
            captured.update(kw)
            return _fake_result()

        monkeypatch.setattr("credstore._wsl_backend.subprocess.run", _capture)
        from credstore._wsl_backend import _run_powershell

        _run_powershell("Write-Output ok")
        assert captured["encoding"] == "utf-8"
        assert captured["errors"] == "replace"

    def test_nonzero_exit_code(self, monkeypatch):
        monkeypatch.setattr(
            "credstore._wsl_backend.subprocess.run",
            lambda cmd, **kw: _fake_result(rc=5),
        )
        from credstore._wsl_backend import _run_powershell

        rc, _, _ = _run_powershell("exit 5")
        assert rc == 5


# ═══════════════════════════════════════════════════════════════════════
# _read_credential
# ═══════════════════════════════════════════════════════════════════════


class TestReadCredential:
    def test_success(self, monkeypatch):
        monkeypatch.setattr(
            "credstore._wsl_backend._run_powershell",
            lambda script: (0, _b64("my-secret") + "|juzcn", ""),
        )
        from credstore._wsl_backend import _read_credential

        assert _read_credential("svc") == ("my-secret", "juzcn")

    def test_not_found(self, monkeypatch):
        monkeypatch.setattr(
            "credstore._wsl_backend._run_powershell",
            lambda script: (1, "", ""),
        )
        from credstore._wsl_backend import _read_credential

        assert _read_credential("svc") is None

    def test_empty_stdout(self, monkeypatch):
        monkeypatch.setattr(
            "credstore._wsl_backend._run_powershell",
            lambda script: (0, "", ""),
        )
        from credstore._wsl_backend import _read_credential

        assert _read_credential("svc") is None

    def test_empty_blob_preserves_username(self, monkeypatch):
        monkeypatch.setattr(
            "credstore._wsl_backend._run_powershell",
            lambda script: (0, "|juzcn", ""),
        )
        from credstore._wsl_backend import _read_credential

        assert _read_credential("svc") == ("", "juzcn")

    def test_decode_failure(self, monkeypatch):
        monkeypatch.setattr(
            "credstore._wsl_backend._run_powershell",
            lambda script: (0, "!!!not-base64!!!|juzcn", ""),
        )
        from credstore._wsl_backend import _read_credential

        assert _read_credential("svc") == (None, "juzcn")

    def test_utf16_decode_failure(self, monkeypatch):
        # unpaired surrogate → invalid UTF-16-LE
        bad = base64.b64encode(b"\x00\xd8\x00\x00").decode("ascii")
        monkeypatch.setattr(
            "credstore._wsl_backend._run_powershell",
            lambda script: (0, bad + "|juzcn", ""),
        )
        from credstore._wsl_backend import _read_credential

        assert _read_credential("svc") == (None, "juzcn")


# ═══════════════════════════════════════════════════════════════════════
# _set_credential / _delete_credential
# ═══════════════════════════════════════════════════════════════════════


class TestSetCredential:
    def test_success(self, monkeypatch):
        monkeypatch.setattr(
            "credstore._wsl_backend._run_powershell",
            lambda script, stdin_data=None: (0, "", ""),
        )
        from credstore._wsl_backend import _set_credential

        assert _set_credential("t@svc", "u", "pwd") is True

    def test_failure(self, monkeypatch):
        monkeypatch.setattr(
            "credstore._wsl_backend._run_powershell",
            lambda script, stdin_data=None: (1, "", "error"),
        )
        from credstore._wsl_backend import _set_credential

        assert _set_credential("t@svc", "u", "pwd") is False

    def test_the_secret_goes_over_stdin_not_the_command_line(self, monkeypatch):
        """The script rides in ``powershell.exe``'s command line.

        Anything that can enumerate command lines can decode ``-EncodedCommand``
        back to plaintext, so interpolating the credential into the script
        published it — the base64 value must travel on stdin instead.
        """
        seen = {}

        def _fake(script, stdin_data=None):
            seen["script"] = script
            seen["stdin"] = stdin_data
            return 0, "", ""

        monkeypatch.setattr("credstore._wsl_backend._run_powershell", _fake)
        from credstore._wsl_backend import _set_credential

        assert _set_credential("t@svc", "u", "hunter2") is True

        expected = base64.b64encode("hunter2".encode("utf-16-le")).decode("ascii")
        assert seen["stdin"] == expected
        assert expected not in seen["script"]
        assert "hunter2" not in seen["script"]


class TestDeleteCredential:
    def test_success(self, monkeypatch):
        monkeypatch.setattr(
            "credstore._wsl_backend._run_powershell",
            lambda script: (0, "", ""),
        )
        from credstore._wsl_backend import _delete_credential

        assert _delete_credential("t@svc") is True

    def test_failure(self, monkeypatch):
        monkeypatch.setattr(
            "credstore._wsl_backend._run_powershell",
            lambda script: (1, "", "error"),
        )
        from credstore._wsl_backend import _delete_credential

        assert _delete_credential("t@svc") is False


# ═══════════════════════════════════════════════════════════════════════
# WslBackend ops
# ═══════════════════════════════════════════════════════════════════════


class _FakeCredMan:
    """In-memory Credential Manager keyed by TargetName, as Windows does."""

    def __init__(self):
        self.creds: dict[str, tuple[str | None, str]] = {}
        self.delete_calls: list[str] = []

    def read(self, target):
        return self.creds.get(target)

    def set(self, target, username, password):
        self.creds[target] = (password, username)
        return True

    def delete(self, target):
        self.delete_calls.append(target)
        if target not in self.creds:
            return False
        del self.creds[target]
        return True


class TestWslBackendOps:
    @pytest.fixture(autouse=True)
    def _setup(self, monkeypatch):
        monkeypatch.setattr("platform.system", lambda: "Linux")
        monkeypatch.setattr("credstore._wsl_backend.is_wsl", lambda: True)

    @pytest.fixture
    def credman(self, monkeypatch):
        fake = _FakeCredMan()
        monkeypatch.setattr("credstore._wsl_backend._read_credential", fake.read)
        monkeypatch.setattr("credstore._wsl_backend._set_credential", fake.set)
        monkeypatch.setattr("credstore._wsl_backend._delete_credential", fake.delete)
        return fake

    def _backend(self):
        from credstore._wsl_backend import WslBackend

        return WslBackend()

    def test_compound_name_matches_winvault(self):
        from credstore._wsl_backend import WslBackend

        assert WslBackend._compound_name("credstore", "MY_KEY") == "MY_KEY@credstore"

    def test_get_reads_service_target_first(self, credman):
        """Same order as WinVaultKeyring: service, then {username}@service."""
        credman.creds["svc"] = ("current", "usr")
        credman.creds["usr@svc"] = ("stale", "usr")

        assert self._backend().get_password("svc", "usr") == "current"

    def test_get_falls_back_to_compound_target(self, credman):
        credman.creds["usr@svc"] = ("mine", "usr")

        assert self._backend().get_password("svc", "usr") == "mine"

    def test_get_ignores_service_target_for_another_username(self, credman):
        credman.creds["svc"] = ("theirs", "other")

        assert self._backend().get_password("svc", "usr") is None

    def test_get_ignores_compound_target_for_another_username(self, credman):
        credman.creds["usr@svc"] = ("theirs", "other")

        assert self._backend().get_password("svc", "usr") is None

    def test_set_writes_service_target_with_username(self, credman):
        self._backend().set_password("svc", "usr", "secret")

        assert credman.creds == {"svc": ("secret", "usr")}

    def test_set_displaces_the_existing_service_entry(self, credman):
        """WinVault moves the current owner to its compound target first."""
        credman.creds["svc"] = ("old", "other")

        self._backend().set_password("svc", "usr", "new")

        assert credman.creds == {
            "svc": ("new", "usr"),
            "other@svc": ("old", "other"),
        }

    def test_update_round_trips_through_the_service_target(self, credman):
        backend = self._backend()
        backend.set_password("svc", "usr", "first")
        backend.set_password("svc", "usr", "second")

        assert credman.creds == {
            "svc": ("second", "usr"),
            "usr@svc": ("first", "usr"),
        }
        assert backend.get_password("svc", "usr") == "second"

    def test_set_refuses_to_discard_an_undecodable_entry(self, credman):
        credman.creds["svc"] = (None, "other")

        with pytest.raises(PasswordSetError, match="not valid UTF-16"):
            self._backend().set_password("svc", "usr", "new")
        assert credman.creds == {"svc": (None, "other")}

    def test_set_failure_raises(self, credman, monkeypatch):
        monkeypatch.setattr("credstore._wsl_backend._set_credential", lambda *a: False)

        with pytest.raises(PasswordSetError, match="Failed to store"):
            self._backend().set_password("svc", "usr", "secret")

    def test_delete_removes_both_of_this_usernames_entries(self, credman):
        credman.creds = {
            "svc": ("mine", "usr"),
            "usr@svc": ("old", "usr"),
            "other@svc": ("theirs", "other"),
        }

        self._backend().delete_password("svc", "usr")

        assert credman.creds == {"other@svc": ("theirs", "other")}

    def test_delete_does_not_touch_another_usernames_service_entry(self, credman):
        credman.creds["svc"] = ("theirs", "other")

        with pytest.raises(PasswordDeleteError, match="Failed to delete"):
            self._backend().delete_password("svc", "usr")
        assert credman.creds == {"svc": ("theirs", "other")}

    def test_delete_missing_raises(self, credman):
        with pytest.raises(PasswordDeleteError, match="Failed to delete"):
            self._backend().delete_password("svc", "usr")

    def test_delete_failure_raises(self, credman, monkeypatch):
        credman.creds["svc"] = ("mine", "usr")
        monkeypatch.setattr(
            "credstore._wsl_backend._delete_credential", lambda target: False
        )

        with pytest.raises(PasswordDeleteError, match="Failed to delete"):
            self._backend().delete_password("svc", "usr")

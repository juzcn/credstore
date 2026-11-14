"""Tests for credstore._win_backend — native Windows Credential Manager."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from keyring.errors import PasswordDeleteError, PasswordSetError

from credstore import _win_backend

pytestmark = pytest.mark.unit


class _FakeError(Exception):
    """Stand-in for win32ctypes.pywin32.pywintypes.error."""

    def __init__(self, winerror):
        super().__init__(f"winerror {winerror}")
        self.winerror = winerror


class _FakeWin32Cred:
    CRED_TYPE_GENERIC = 1
    CRED_PERSIST_LOCAL_MACHINE = 2

    def __init__(self):
        self.store: dict[str, dict] = {}
        self.writes: list[dict] = []
        self.read_error: Exception | None = None
        self.write_error: Exception | None = None
        self.delete_error: Exception | None = None

    def CredRead(self, Type, TargetName):
        if self.read_error is not None:
            raise self.read_error
        if TargetName not in self.store:
            raise _FakeError(1168)
        return self.store[TargetName]

    def CredWrite(self, credential, flags):
        if self.write_error is not None:
            raise self.write_error
        self.writes.append(dict(credential))
        stored = dict(credential)
        # pywin32-ctypes turns the str blob into UTF-16LE wchar_t bytes.
        stored["CredentialBlob"] = stored["CredentialBlob"].encode("utf-16-le")
        self.store[stored["TargetName"]] = stored

    def CredDelete(self, Type, TargetName):
        if self.delete_error is not None:
            raise self.delete_error
        if TargetName not in self.store:
            raise _FakeError(1168)
        del self.store[TargetName]


@pytest.fixture
def win32(monkeypatch):
    fake = _FakeWin32Cred()
    monkeypatch.setattr(
        _win_backend,
        "_load_win32",
        lambda: (SimpleNamespace(error=_FakeError), fake),
    )
    return fake


class TestPriority:
    def test_raises_on_non_windows(self, monkeypatch):
        monkeypatch.setattr(_win_backend.os, "name", "posix")

        with pytest.raises(RuntimeError, match="requires Windows"):
            _ = _win_backend.WinBackend.priority

    def test_returns_9_5_on_windows(self, monkeypatch):
        monkeypatch.setattr(_win_backend.os, "name", "nt")

        assert _win_backend.WinBackend.priority == 9.5


class TestTargetFormat:
    def test_colon_separated(self):
        from credstore._target import target_name

        assert target_name("credstore", "DEEPSEEK_API_KEY") == (
            "credstore:DEEPSEEK_API_KEY"
        )

    def test_key_with_separator_is_still_extracted(self):
        from credstore._target import key_from_target

        assert key_from_target("credstore", "credstore:my:key") == "my:key"

    def test_foreign_target(self):
        from credstore._target import key_from_target

        assert key_from_target("credstore", "KEY@credstore") is None
        assert key_from_target("credstore", "credstore") is None

    def test_prefix_match_is_case_insensitive(self):
        from credstore._target import key_from_target

        assert key_from_target("credstore", "CredStore:KEY") == "KEY"


class TestBackendOps:
    def _backend(self):
        return _win_backend.WinBackend()

    def test_set_writes_exactly_one_target(self, win32):
        self._backend().set_password("credstore", "KEY", "secret")

        assert list(win32.store) == ["credstore:KEY"]
        credential = win32.writes[-1]
        assert credential["UserName"] == "KEY"
        assert credential["CredentialBlob"] == "secret"

    def test_get_roundtrip(self, win32):
        backend = self._backend()
        backend.set_password("credstore", "KEY", "secret")

        assert backend.get_password("credstore", "KEY") == "secret"

    def test_get_missing(self, win32):
        assert self._backend().get_password("credstore", "KEY") is None

    def test_get_decodes_utf16le(self, win32):
        win32.store["credstore:KEY"] = {"CredentialBlob": "秘密".encode("utf-16-le")}

        assert self._backend().get_password("credstore", "KEY") == "秘密"

    def test_get_propagates_unexpected_errors(self, win32):
        win32.read_error = OSError("access denied")

        with pytest.raises(OSError, match="access denied"):
            self._backend().get_password("credstore", "KEY")

    def test_set_failure_raises(self, win32):
        win32.write_error = OSError("denied")

        with pytest.raises(PasswordSetError, match="Failed to store"):
            self._backend().set_password("credstore", "KEY", "secret")

    def test_delete_removes_the_target(self, win32):
        backend = self._backend()
        backend.set_password("credstore", "KEY", "secret")

        backend.delete_password("credstore", "KEY")

        assert win32.store == {}

    def test_delete_missing_raises(self, win32):
        with pytest.raises(PasswordDeleteError, match="Failed to delete"):
            self._backend().delete_password("credstore", "KEY")

    def test_delete_failure_raises(self, win32):
        win32.store["credstore:KEY"] = {"CredentialBlob": b""}
        win32.delete_error = OSError("denied")

        with pytest.raises(PasswordDeleteError, match="Failed to delete"):
            self._backend().delete_password("credstore", "KEY")

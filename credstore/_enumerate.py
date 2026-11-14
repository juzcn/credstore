"""Platform-specific credential enumeration.

Reads credential keys from the OS credential store.  On Windows this
uses ``win32cred.CredEnumerate``; on WSL it uses ``powershell.exe``
with inline C# P/Invoke to ``advapi32.dll CredEnumerateW``.  Other
platforms return an empty list.

Memory safety: pass ``with_values=False`` (the default) to enumerate
keys only — secret values are never decoded or stored, and on WSL the
PowerShell bridge is told not to read the credential blobs at all, so
they never leave Credential Manager.  Only set ``with_values=True``
when you genuinely need all values (e.g. syncing to cryptfile backup).
"""

from __future__ import annotations

import base64
import os
import subprocess
import sys

from credstore._platform import is_wsl
from credstore._target import key_from_target

__all__ = ["enumerate_system_keyring", "enumeration_supported"]


# ── WSL detection ───────────────────────────────────────────────────

_CRED_ENUM_SCRIPT = r"""
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class CredEnum {
    public const int CRED_TYPE_GENERIC = 1;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL {
        public int Flags;
        public int Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public long LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredEnumerateW(string filter, int flags, out int count, out IntPtr credentials);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern void CredFree(IntPtr buffer);

    public static string EnumerateCredentials(string serviceSuffix, bool withValues) {
        int count;
        IntPtr buf;
        if (!CredEnumerateW(null, 0, out count, out buf)) {
            return "[]";
        }
        // credstore writes exactly one target per credential:
        // {service}:{key}.  Anything else under Credential Manager belongs to
        // another application and is ignored.
        string prefix = serviceSuffix + ":";
        var results = new System.Collections.Generic.List<string>();
        // CredEnumerateW returns an array of POINTERS to CREDENTIAL structs,
        // not a contiguous array of CREDENTIAL structs.
        for (int i = 0; i < count; i++) {
            IntPtr credPtr = Marshal.ReadIntPtr(buf, i * IntPtr.Size);
            CREDENTIAL cred = (CREDENTIAL)Marshal.PtrToStructure(credPtr, typeof(CREDENTIAL));
            if (cred.Type != CRED_TYPE_GENERIC) continue;
            string target = Marshal.PtrToStringUni(cred.TargetName) ?? "";
            if (!target.StartsWith(prefix, System.StringComparison.OrdinalIgnoreCase)) continue;
            string key = target.Substring(prefix.Length);
            if (key.Length == 0) continue;
            // withValues is false for a plain listing: the blob is left where
            // it is, so no secret is ever copied into this process, encoded,
            // or piped back to the caller.
            string blobStr = "";
            if (withValues && cred.CredentialBlobSize > 0) {
                byte[] bytes = new byte[cred.CredentialBlobSize];
                Marshal.Copy(cred.CredentialBlob, bytes, 0, cred.CredentialBlobSize);
                blobStr = Convert.ToBase64String(bytes);
            }
            results.Add(key + "|" + blobStr);
        }
        CredFree(buf);
        return "[" + string.Join(",", results.ConvertAll(s => "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"")) + "]";
    }
}
"@

$svc = [Console]::In.ReadLine()
$flag = [Console]::In.ReadLine()
$json = [CredEnum]::EnumerateCredentials($svc, ($flag -eq "1"))
Write-Output $json
"""


def _enumerate_wsl(service: str, with_values: bool = False) -> list[tuple[str, str]]:
    """Enumerate credstore credentials via PowerShell CredEnumerate on WSL.

    With *with_values* False (the default) the bridge returns key names only:
    the script is told not to read the credential blobs at all, so the secrets
    are never encoded into the child's stdout — and therefore never enter this
    process's memory — just to be discarded here.
    """
    import json

    try:
        script_bytes = _CRED_ENUM_SCRIPT.encode("utf-16-le")
        encoded_script = base64.b64encode(script_bytes).decode("ascii")

        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                encoded_script,
            ],
            input=f"{service}\n{1 if with_values else 0}\n",
            check=False,  # nonzero exit is handled below, not raised
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        print(f"Cannot enumerate credentials: {exc}", file=sys.stderr)
        return []

    if result.returncode != 0:
        return []

    raw_stdout = result.stdout.strip()

    try:
        raw_entries = json.loads(raw_stdout or "[]")
    except json.JSONDecodeError:
        return []

    entries: list[tuple[str, str]] = []
    seen: set[str] = set()
    for entry in raw_entries:
        if "|" in entry:
            key, b64_blob = entry.split("|", 1)
        else:
            key, b64_blob = entry, ""

        if key in seen:
            continue
        seen.add(key)

        if with_values and b64_blob:
            try:
                blob = base64.b64decode(b64_blob)
            except (ValueError, TypeError):
                # Malformed base64 blob from the bridge — skip this entry.
                continue
            value = _decode_blob(blob)
            if value is None:
                continue
            entries.append((key, value))
        else:
            entries.append((key, ""))

    return entries


# ── blob decoding ───────────────────────────────────────────────────


def _decode_blob(blob: bytes) -> str | None:
    """Decode a credential blob: UTF-16LE (credstore's write format), then UTF-8.

    Returns None when neither decoding works (the blob is not text) —
    such an entry is skipped rather than syncing opaque bytes into the
    backup.  Mirrors ``_enumerate_windows``' decode chain.
    """
    try:
        return blob.decode("utf-16-le")
    except UnicodeDecodeError:
        pass
    try:
        return blob.decode("utf-8")
    except UnicodeDecodeError:
        return None


# ── public API ──────────────────────────────────────────────────────


def enumeration_supported() -> bool:
    """Whether the system keyring can be enumerated on this platform.

    Windows and WSL read Credential Manager directly; the macOS Keychain and
    the Linux kernel keyring expose no list API at all, so there callers must
    distinguish "the keyring is empty" from "the keyring cannot be listed" —
    e.g. a recovery message that suggests rebuilding from the keyring is only
    actionable where the keyring can be read back.
    """
    return os.name == "nt" or is_wsl()


def enumerate_system_keyring(
    service: str, with_values: bool = False
) -> list[tuple[str, str]]:
    """Enumerate credentials for *service* from the system keyring.

    Uses platform-specific APIs.  On Windows, reads from Credential
    Manager via ``win32cred.CredEnumerate``.  On WSL, uses
    ``powershell.exe`` with ``advapi32.dll CredEnumerateW``.
    Returns a list of (key, value) tuples when *with_values* is True,
    otherwise (key, "") tuples.

    IMPORTANT: Pass ``with_values=False`` unless you genuinely need
    the secret values.  Batch-loading all secrets into memory is a
    leak risk — prefer ``with_values=False`` for enumeration and
    retrieve individual values only on demand, ``del``-ing each
    after use.
    """
    if os.name == "nt":
        return _enumerate_windows(service, with_values=with_values)

    if is_wsl():
        return _enumerate_wsl(service, with_values=with_values)

    # Other platforms: keyring backends don't support enumeration.
    print(
        "Credential enumeration is not supported on this platform.\n"
        "Re-run 'credstore set <KEY>' for each credential to populate\n"
        "the cryptfile backup.",
        file=sys.stderr,
    )
    return []


def _enumerate_windows(
    service: str, with_values: bool = False
) -> list[tuple[str, str]]:
    """Enumerate credstore credentials from Windows Credential Manager.

    When *with_values* is False (default), returns (key, "") tuples
    and discards decoded secrets immediately — safe for enumeration.
    Only set *with_values=True* when you genuinely need all values
    (e.g. reset-backup).
    """
    try:
        from win32ctypes.pywin32 import win32cred
    except ImportError:
        try:
            import win32cred
        except ImportError:
            print(
                "win32cred not available — install pywin32 or pywin32-ctypes.",
                file=sys.stderr,
            )
            return []

    try:
        all_creds = win32cred.CredEnumerate(None, 0)
    except Exception as exc:  # noqa: BLE001 — pywin32-ctypes error types vary
        print(f"Cannot enumerate credentials: {exc}", file=sys.stderr)
        return []

    if all_creds is None:
        return []

    entries: list[tuple[str, str]] = []
    for cred in all_creds:
        target = cred.get("TargetName", "")
        cred_type = cred.get("Type", 0)

        # CRED_TYPE_GENERIC = 1
        if cred_type != 1:
            continue

        # credstore writes exactly one target per credential:
        # {service}:{key}.  Anything else belongs to another application.
        key = key_from_target(service, target)
        if key is None:
            continue

        if with_values:
            # Decode the credential blob (UTF-16LE as written by credstore)
            blob = cred.get("CredentialBlob", b"")
            try:
                value = blob.decode("utf-16")
            except (UnicodeDecodeError, UnicodeError):
                try:
                    value = blob.decode("utf-8")
                except (UnicodeDecodeError, UnicodeError):
                    continue
            entries.append((key, value))
        else:
            # Keys only — never decode secret values for enumeration
            entries.append((key, ""))

    # Discard raw credential structures from memory
    del all_creds

    return entries

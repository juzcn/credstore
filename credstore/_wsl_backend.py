"""WSL keyring backend — bridges to Windows Credential Manager.

On WSL, no Linux desktop keyring (SecretService / GNOME Keyring /
kernel keyutils) is available.  This backend calls ``powershell.exe``
with inline C# P/Invoke to access the native Windows credential store
via ``advapi32.dll``.

A proper ``KeyringBackend`` subclass, registered via the standard
``keyring.backends`` entry point.  Priority 9.5 beats
``keyring_wincred.WinCredKeyring`` (9.0) when both are installed.  The
storage layout is ``WinVaultKeyring``'s, so WSL and native Windows share one
store with one read order.
"""

from __future__ import annotations

import base64
import logging
import platform
import subprocess

from jaraco.classes import properties
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError, PasswordSetError

from credstore._platform import is_wsl

logger = logging.getLogger("credstore.wsl_backend")

# ── Embedded PowerShell + C# bridge ─────────────────────────────────
# Inline C# calls advapi32.dll CredReadW / CredWriteW / CredDeleteW.
# Uses -EncodedCommand (base64 UTF-16LE) to avoid quoting issues.


_CRED_MANAGER_CS = r"""
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class CredManager {
    public const int CRED_TYPE_GENERIC = 1;
    public const int CRED_PERSIST_LOCAL_MACHINE = 2;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL {
        public int Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredRead(string target, int type, int reservedFlag, out IntPtr credentialPtr);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredWrite([In] ref CREDENTIAL userCredential, [In] uint flags);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool CredDelete(string target, int type, int flags);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern void CredFree([In] IntPtr cred);

    public static string GetCredentialWithUser(string target) {
        string blobB64, user;
        if (!ReadCredential(target, out blobB64, out user)) {
            return null;
        }
        return blobB64 + "|" + user;
    }

    private static bool ReadCredential(string target, out string blobB64, out string user) {
        blobB64 = null;
        user = null;
        IntPtr credPtr;
        if (!CredRead(target, CRED_TYPE_GENERIC, 0, out credPtr)) {
            return false;
        }
        try {
            CREDENTIAL cred = (CREDENTIAL)Marshal.PtrToStructure(credPtr, typeof(CREDENTIAL));
            user = cred.UserName;
            if (cred.CredentialBlobSize > 0) {
                byte[] passwordBytes = new byte[cred.CredentialBlobSize];
                Marshal.Copy(cred.CredentialBlob, passwordBytes, 0, cred.CredentialBlobSize);
                blobB64 = Convert.ToBase64String(passwordBytes);
            } else {
                blobB64 = "";
            }
            return true;
        } finally {
            CredFree(credPtr);
        }
    }

    public static bool SetCredential(string target, string username, string base64Password) {
        byte[] passwordBytes = Convert.FromBase64String(base64Password);

        CREDENTIAL cred = new CREDENTIAL();
        cred.Type = CRED_TYPE_GENERIC;
        cred.TargetName = target;
        cred.UserName = username;
        cred.CredentialBlobSize = passwordBytes.Length;
        cred.CredentialBlob = Marshal.AllocHGlobal(passwordBytes.Length);
        cred.Persist = CRED_PERSIST_LOCAL_MACHINE;

        try {
            Marshal.Copy(passwordBytes, 0, cred.CredentialBlob, passwordBytes.Length);
            return CredWrite(ref cred, 0);
        } finally {
            Marshal.FreeHGlobal(cred.CredentialBlob);
        }
    }

    public static bool DeleteCredential(string target) {
        return CredDelete(target, CRED_TYPE_GENERIC, 0);
    }
}
"@
"""


# ── PowerShell bridge helpers ───────────────────────────────────────


def _run_powershell(
    script: str,
    stdin_data: str | None = None,
) -> tuple[int, str, str]:
    """Execute a PowerShell snippet, returning (rc, stdout, stderr).

    ``stdin_data`` is delivered on the child's standard input.  Secret
    material goes THERE, never interpolated into *script*: the script travels
    as ``-EncodedCommand``, i.e. in the ``powershell.exe`` command line, where
    anything that can enumerate command lines (Task Manager,
    ``Get-CimInstance Win32_Process``, an EDR agent) can decode it back to
    plaintext — base64 is an encoding, not encryption.  The Linux side's
    ``_shell._setx`` avoids the same leak by design.

    Uses ``encoding='utf-8', errors='replace'`` because PowerShell
    outputs in the Windows OEM code page but the WSL Linux locale
    is UTF-8 — ``text=True`` (which uses the locale encoding) would
    crash on non-ASCII bytes.
    """
    full_script = _CRED_MANAGER_CS + "\n" + script
    script_bytes = full_script.encode("utf-16-le")
    encoded_script = base64.b64encode(script_bytes).decode("ascii")

    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            encoded_script,
        ],
        input=stdin_data,
        check=False,  # returncode is returned to the caller, not raised
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def _read_credential(target: str) -> tuple[str | None, str] | None:
    """Read a credential's blob and UserName from Credential Manager.

    Returns ``(value, username)`` for an existing entry, or ``None`` when no
    credential is stored under *target*.  *value* is ``""`` for an empty blob
    and ``None`` when the stored blob is not valid UTF-16 — the entry exists,
    but its bytes are not ours to interpret.  *username* is the CREDENTIAL
    struct's UserName field.
    """
    escaped_target = target.replace("'", "''")
    script = f"""
$result = [CredManager]::GetCredentialWithUser('{escaped_target}')
if ($result -eq $null) {{
    exit 1
}}
Write-Output $result
"""
    returncode, stdout, _ = _run_powershell(script)

    if returncode != 0 or not stdout:
        return None

    blob_b64, _, username = stdout.partition("|")
    if not blob_b64:
        # Empty blob — the entry exists with an empty value.
        return ("", username)
    try:
        password_bytes = base64.b64decode(blob_b64)
        return (password_bytes.decode("utf-16-le"), username)
    except ValueError:
        # binascii.Error (bad base64) or UnicodeDecodeError (bad UTF-16).
        logger.debug("Failed to decode credential blob for %s", target)
        return (None, username)


def _set_credential(target: str, username: str, password: str) -> bool:
    """Store a credential into Windows Credential Manager.

    Returns ``True`` on success.
    """
    password_bytes = password.encode("utf-16-le")
    b64_password = base64.b64encode(password_bytes).decode("ascii")

    escaped_target = target.replace("'", "''")
    escaped_username = username.replace("'", "''")

    # The blob comes in on stdin, NOT in the script: the script rides in the
    # command line, so interpolating it here published the credential to every
    # process that can read one. The target and user name stay inline — they
    # are names, not secrets.
    script = f"""
$b64 = [Console]::In.ReadLine()
$result = [CredManager]::SetCredential('{escaped_target}', '{escaped_username}', $b64)
if (-not $result) {{
    exit 1
}}
"""
    returncode, _, _ = _run_powershell(script, stdin_data=b64_password)
    return returncode == 0


def _delete_credential(target: str) -> bool:
    """Delete a credential from Windows Credential Manager.

    Returns ``True`` on success.
    """
    escaped_target = target.replace("'", "''")
    script = f"""
$result = [CredManager]::DeleteCredential('{escaped_target}')
if (-not $result) {{
    exit 1
}}
"""
    returncode, _, _ = _run_powershell(script)
    return returncode == 0


# ── Keyring backend ─────────────────────────────────────────────────


class WslBackend(KeyringBackend):
    """WSL system-keyring backend backed by Windows Credential Manager.

    Storage layout is exactly ``keyring.backends.Windows.WinVaultKeyring``'s:
    a credential's UserName is its key, the entry that owns the ``{service}``
    target is the one written last, and every displaced username is moved to
    the compound target ``{username}@{service}``.  Reads check the service
    target first and the compound target second.  Native Windows and WSL
    therefore write the same entries and resolve them in the same order.

    Called ``WslBackend`` (not ``WslCredBackend``) so that keyring's
    ``by_priority`` sorting works correctly — it accesses ``priority``
    as a class attribute, which ``@classproperty`` provides.
    """

    @properties.classproperty
    def priority(cls) -> float:
        """Return 9.5 on WSL; raise RuntimeError otherwise.

        9.5 beats ``keyring_wincred.WinCredKeyring`` (9.0) so this backend,
        with its WinVault-compatible layout and encoding, is always active
        when both packages are installed.
        """
        if platform.system() != "Linux":
            raise RuntimeError("WslBackend requires Linux")
        if not is_wsl():
            raise RuntimeError("WslBackend requires WSL")
        return 9.5

    @staticmethod
    def _compound_name(service: str, username: str) -> str:
        """WinVault's displaced-entry target: ``{username}@{service}``."""
        return f"{username}@{service}"

    # ── KeyringBackend interface ──────────────────────────────────

    def get_password(self, service: str, username: str) -> str | None:
        # WinVault order: the service target holds the most recently written
        # entry; only when it is absent or belongs to someone else does the
        # compound target hold this username's copy.
        entry = _read_credential(service)
        if entry is not None and entry[1] == username:
            return entry[0]
        entry = _read_credential(self._compound_name(service, username))
        if entry is not None and entry[1] == username:
            return entry[0]
        return None

    def set_password(self, service: str, username: str, password: str) -> None:
        # WinVault bookkeeping: Credential Manager keys an entry by TargetName
        # alone, so before taking over the service target, move the entry that
        # currently owns it to its user's compound target.
        existing = _read_credential(service)
        if existing is not None:
            existing_value, existing_username = existing
            if existing_value is None:
                raise PasswordSetError(
                    f"Cannot preserve the existing credential for {service}: "
                    f"its blob is not valid UTF-16"
                )
            if existing_username:
                displaced = self._compound_name(service, existing_username)
                if not _set_credential(displaced, existing_username, existing_value):
                    raise PasswordSetError(
                        f"Failed to move the existing credential for {service} "
                        f"to {displaced}"
                    )
                logger.debug("credential_displaced target=%s", displaced)
            else:
                logger.debug(
                    "overwriting service target without a UserName target=%s", service
                )
        if not _set_credential(service, username, password):
            raise PasswordSetError(
                f"Failed to store credential for {service}/{username}"
            )

    def delete_password(self, service: str, username: str) -> None:
        # WinVault order: both the service target and this username's compound
        # target can hold a copy, and each is deleted only when its UserName
        # matches — another username's entry is never removed.
        deleted = False
        for target in (service, self._compound_name(service, username)):
            entry = _read_credential(target)
            if entry is None or entry[1] != username:
                continue
            if not _delete_credential(target):
                raise PasswordDeleteError(
                    f"Failed to delete credential for {service}/{username}"
                )
            deleted = True
        if not deleted:
            raise PasswordDeleteError(
                f"Failed to delete credential for {service}/{username}"
            )

"""credstore — resolve the encrypted credential file path.

Priority:
  1. ``CREDSTORE_FILE`` env var
  2. ``~/.credstore/credentials.crypt``

The environment fallback (used when no system keyring is available) keeps its
plaintext values in a separate file:

  1. ``CREDSTORE_ENV_FILE`` env var
  2. ``~/.credstore/env``

Deliberately independent of the CWD — there is no dev-mode override.  The
system keyring, credstore's source of truth, is shared between a source
checkout and a production install, so a checkout-local cryptfile forked
only the *backup* (``credstore set`` run from the source tree wrote a
different file than everywhere else, and the two drifted), and it
scattered credential files into the source tree.
"""

from __future__ import annotations

import os
from pathlib import Path

__all__ = ["get_cryptfile_path", "get_env_file_path"]


def get_cryptfile_path() -> str:
    """Resolve the cryptfile path.

    Priority:
      1. ``CREDSTORE_FILE`` env var
      2. ``~/.credstore/credentials.crypt``
    """
    env_path = os.environ.get("CREDSTORE_FILE")
    if env_path:
        return env_path
    return str(Path.home() / ".credstore" / "credentials.crypt")


def get_env_file_path() -> str:
    """Resolve the environment-fallback file path.

    This file holds plaintext ``export`` lines and is sourced from the shell
    profile; it exists only where no system keyring is available.

    Priority:
      1. ``CREDSTORE_ENV_FILE`` env var
      2. ``~/.credstore/env``
    """
    env_path = os.environ.get("CREDSTORE_ENV_FILE")
    if env_path:
        return env_path
    return str(Path.home() / ".credstore" / "env")

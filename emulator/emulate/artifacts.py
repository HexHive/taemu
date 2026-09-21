"""Filesystem permissions for fuzzing artifacts.

The emulator runs as root inside the container while the repo is bind-mounted
from the host, so anything it creates is root-owned on the host and the
ordinary user cannot prune it -- `eval/deduplicate.py --enable-del` used to
abort with PermissionError on `in/suspicious_inputs`. Create these artifacts
world-writable instead.

Kept free of intra-package imports: `common` imports from `fuzz_record`, so
putting these there would form a cycle.
"""

import os


def shared_makedirs(path):
    """makedirs() an artifact directory the host user can also write.

    umask masks the mode argument of makedirs, so the chmod must be explicit.
    """
    os.makedirs(path, exist_ok=True)
    try:
        os.chmod(path, 0o777)
    except OSError:
        pass
    return path


def shared_chmod(path):
    """Make a written artifact file writable by the host user."""
    try:
        os.chmod(path, 0o666)
    except OSError:
        pass
    return path

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Test support (1.11.0), not part of the package: what the tests need from the system, by its equivalent where a system
has no such thing (as cryptovalid-opencore's test_platforms_20261124).

full_sink(): a path whose writes fail with ENOSPC. Linux has /dev/full. macOS and Windows have no such device; there the equivalent is an empty file `sink` on a full
volume named by AP2_FULL_DIR, which the CI's macOS and Windows cells make (hdiutil, diskpart) and fill to the last byte.
None where neither exists: the caller skips with the reason."""
import os
import sys


def full_sink():
    if sys.platform.startswith("linux") and os.path.exists("/dev/full"):
        return "/dev/full"
    d = os.environ.get("AP2_FULL_DIR")
    if d and os.path.isfile(os.path.join(d, "sink")):
        return os.path.join(d, "sink")
    return None


NO_FULL = "no full device here: Linux has /dev/full; elsewhere AP2_FULL_DIR names a full volume with an empty file `sink`"


# the device a reader must refuse at once: /dev/zero on Linux and macOS, NUL (\\.\NUL, a character device) on Windows
DEVICE = "\\\\.\\NUL" if os.name == "nt" else "/dev/zero"


def fifo(tc, path):
    """A pipe a reader is given by name, to be refused without waiting: a FIFO at `path` on POSIX; on Windows, which has no
    FIFO in a directory, its equivalent, a named pipe \\\\.\\pipe\\ap2-<random> with 64 listening instances (each reader
    that opens it takes one). Returns the name to give the reader."""
    if hasattr(os, "mkfifo"):
        os.mkfifo(path)
        return path
    import _winapi
    import secrets
    name = "\\\\.\\pipe\\ap2-" + secrets.token_hex(8)
    for _ in range(64):
        # PIPE_ACCESS_DUPLEX 3, PIPE_TYPE_BYTE 0, PIPE_WAIT 0 (winbase.h): _winapi does not export the last two
        h = _winapi.CreateNamedPipe(name, 3, 0, 255, 65536, 65536, 0, 0)   # PIPE_UNLIMITED_INSTANCES 255, no security attributes
        tc.addCleanup(_winapi.CloseHandle, h)
    return name


def device_link(path):
    """A name that leads to DEVICE: a symlink at `path` on POSIX; on Windows, where a link to NUL cannot be made, NUL itself."""
    if os.name == "nt":
        return DEVICE
    os.symlink(DEVICE, path)
    return path


def fake_tool(directory, name, code):
    """A program `name` in `directory` that runs the Python `code` (sys.argv as the program's arguments), found by
    shutil.which once `directory` leads PATH. POSIX: an executable script with this interpreter in its #! line. Windows,
    where a file without an extension in PATHEXT is not a program: name.cmd, which runs name.py with this interpreter
    (CreateProcess starts a .cmd through cmd.exe)."""
    import sys
    os.makedirs(directory, exist_ok=True)
    if os.name == "nt":
        py = os.path.join(directory, name + ".py")
        with open(py, "w", encoding="utf-8", newline="\n") as f:
            f.write(code)
        with open(os.path.join(directory, name + ".cmd"), "w", encoding="ascii", newline="\r\n") as f:
            f.write('@"%s" "%s" %%*\n@exit /b %%ERRORLEVEL%%\n' % (sys.executable, py))
        return directory
    p = os.path.join(directory, name)
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write("#!%s\n%s" % (sys.executable, code))
    os.chmod(p, 0o755)
    return directory

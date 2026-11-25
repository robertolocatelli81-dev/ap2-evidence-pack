# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Test support (1.11.0), not part of the package: what the tests need from the system, by its equivalent where a system
has no such thing (as cryptovalid-opencore's test_platforms_20261124).

full_sink(): a path whose writes fail with ENOSPC. Linux has /dev/full. macOS and Windows have no such device; there the equivalent is an empty file `sink` on a full
volume named by AP2_FULL_DIR, which the CI's macOS and Windows cells make (hdiutil, diskpart) and fill to the last byte.
None where neither exists: the caller skips with the reason."""
import os
import subprocess
import sys


def full_sink():
    if sys.platform.startswith("linux") and os.path.exists("/dev/full"):
        return "/dev/full"
    d = os.environ.get("AP2_FULL_DIR")
    if d and os.path.isfile(os.path.join(d, "sink")):
        fill_volume(d)
        return os.path.join(d, "sink")
    return None


def fill_volume(d):
    """Fill the volume of directory `d` to its last byte with files ap2-fill-<n> (blocks of 64 KiB, then down to 1 byte;
    a write that does not fit raises ENOSPC). Idempotent: a full volume takes nothing more."""
    n = len([x for x in os.listdir(d) if x.startswith("ap2-fill-")])
    for size in (65536, 4096, 512, 1):
        try:
            with open(os.path.join(d, "ap2-fill-%d-%d" % (n, size)), "wb", buffering=0) as f:
                b = b"\0" * size
                while True:
                    f.write(b)
        except OSError:
            pass


def full_volume_with(tc, name, data=b""):
    """A file `name` holding `data` on the full volume (AP2_FULL_DIR), the volume full again around it: the equivalent,
    where no per-process file-size limit exists (Windows), of a file this process cannot make grow. The filler files are
    removed first to make room, and the volume is filled again after; the file is removed at the test's end."""
    d = os.environ.get("AP2_FULL_DIR")
    if not d or not os.path.isdir(d):
        tc.skipTest(NO_FULL)
    for x in os.listdir(d):
        if x.startswith("ap2-fill-"):
            os.remove(os.path.join(d, x))
    p = os.path.join(d, name)
    with open(p, "wb") as f:
        f.write(data)
    tc.addCleanup(lambda: os.path.exists(p) and os.remove(p))
    fill_volume(d)
    return p


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


# ---- processes: what POSIX does in a preexec_fn, and the equivalent where there is no fork (1.11.0) ----

def _win_job(active_process_limit=None):
    """A Job Object (Windows): ActiveProcessLimit is the equivalent of RLIMIT_NPROC — a process inside the job that starts
    another one beyond the limit fails (CreateProcess: ERROR_NOT_ENOUGH_QUOTA)."""
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
    job = k32.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())

    class BASIC(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]
    info = BASIC()
    if active_process_limit is not None:
        info.LimitFlags = 0x00000008   # JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        info.ActiveProcessLimit = active_process_limit
    k32.SetInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
    if not k32.SetInformationJobObject(job, 2, ctypes.byref(info), ctypes.sizeof(info)):   # JobObjectBasicLimitInformation
        raise ctypes.WinError(ctypes.get_last_error())
    return k32, job


def popen(cmd, close=(), fsize=None, nproc=None, **kw):
    """subprocess.Popen with, at the child's start: the descriptors in `close` (1, 2) closed; RLIMIT_FSIZE `fsize`;
    RLIMIT_NPROC `nproc`. POSIX: a preexec_fn. Windows, which has no fork: descriptors closed by Git's bash before it
    starts the program (`exec "$@" 1>&-`: the program starts with no handle there); `nproc` by a Job Object with
    ActiveProcessLimit, the child created suspended, put in the job, then resumed; `fsize` has no equivalent per process
    there (Windows limits no file size per process: the callers use a file on a full volume instead, full_sink)."""
    if os.name != "nt":
        def pre():
            for fd in close:
                os.close(fd)
            if fsize is not None or nproc is not None:
                import resource
                import signal
                if fsize is not None:
                    signal.signal(signal.SIGXFSZ, signal.SIG_DFL)   # as from a plain shell
                    resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
                if nproc is not None:
                    resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
        return subprocess.Popen(cmd, preexec_fn=pre, **kw)
    if fsize is not None:
        raise ValueError("no per-process file size limit on Windows: write to full_sink() instead")
    import shutil
    if close:
        bash = shutil.which("bash")   # PATH's bash (Git's): System32's bash.exe is the WSL launcher
        redir = " ".join("%d>&-" % fd for fd in close)
        cmd = [bash, "-c", 'exec "$@" ' + redir, "_"] + [c.replace("\\", "/") for c in cmd]
    if nproc is None:
        return subprocess.Popen(cmd, **kw)
    k32, job = _win_job(active_process_limit=nproc)
    p = subprocess.Popen(cmd, creationflags=kw.pop("creationflags", 0) | 0x4, **kw)   # CREATE_SUSPENDED
    import ctypes
    from ctypes import wintypes
    k32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    ok = k32.AssignProcessToJobObject(job, int(p._handle))
    nt = ctypes.WinDLL("ntdll")
    nt.NtResumeProcess.argtypes = (wintypes.HANDLE,)
    nt.NtResumeProcess(int(p._handle))
    if not ok:
        p.kill()
        raise ctypes.WinError(ctypes.get_last_error())
    p._ap2_job = job   # the job lives as long as the Popen object
    return p


def run(cmd, close=(), fsize=None, nproc=None, timeout=300, input=None, **kw):
    """subprocess.run on top of popen(): a CompletedProcess."""
    with popen(cmd, close=close, fsize=fsize, nproc=nproc, **kw) as p:
        try:
            out, err = p.communicate(input, timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            raise
    return subprocess.CompletedProcess(p.args, p.returncode, out, err)


def cpu_seconds(pid):
    """User + system CPU time of a live process, all its threads: /proc on Linux; `ps -o time=` on macOS (to 1/100 s);
    GetProcessTimes on Windows. OSError when the process is gone."""
    if os.path.exists("/proc/self/stat"):
        with open(f"/proc/{pid}/stat", "rb") as f:
            fields = f.read().rsplit(b")", 1)[1].split()
        return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.restype = wintypes.HANDLE
        h = k32.OpenProcess(0x1000, False, pid)   # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            raise OSError("process gone")
        try:
            t = [wintypes.FILETIME() for _ in range(4)]
            if not k32.GetProcessTimes(h, *[ctypes.byref(x) for x in t]):
                raise OSError("GetProcessTimes failed")
            return sum((x.dwHighDateTime << 32 | x.dwLowDateTime) for x in t[2:]) / 1e7
        finally:
            k32.CloseHandle(h)
    out = subprocess.run(["ps", "-o", "time=", "-p", str(pid)], capture_output=True, text=True, encoding="utf-8")
    v = out.stdout.strip()
    if out.returncode != 0 or not v:
        raise OSError("process gone")
    days, _, rest = v.rpartition("-")
    parts = [float(x) for x in rest.split(":")]
    secs = 0.0
    for x in parts:
        secs = secs * 60 + x
    return secs + (int(days) * 86400 if days else 0)


def set_nonblocking(fd):
    """O_NONBLOCK on a pipe's write end: fcntl on POSIX; on Windows PIPE_NOWAIT through SetNamedPipeHandleState (an
    anonymous pipe is a named pipe there; os.set_blocking does it only from Python 3.12)."""
    if os.name != "nt":
        os.set_blocking(fd, False)
        return
    import ctypes
    import msvcrt
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.SetNamedPipeHandleState.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, ctypes.c_void_p)
    mode = wintypes.DWORD(0x00000001)   # PIPE_NOWAIT (PIPE_READMODE_BYTE)
    if not k32.SetNamedPipeHandleState(msvcrt.get_osfhandle(fd), ctypes.byref(mode), None, None):
        raise ctypes.WinError(ctypes.get_last_error())


def deny_writes_in(tc, d):
    """No new file in directory `d` for this user until the test ends: mode 0555 on POSIX (root ignores it: skipped with
    that reason), on Windows a deny ACE for this user on adding files and subdirectories (icacls), the equivalent there
    (a mode does not stop a write into a directory)."""
    if os.name == "nt":
        who = os.environ["USERNAME"]
        subprocess.run(["icacls", d, "/deny", "%s:(AD,WD)" % who], check=True, capture_output=True)
        tc.addCleanup(subprocess.run, ["icacls", d, "/remove:d", who], capture_output=True)
        return
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        tc.skipTest("root writes into a directory of mode 0555 (and Windows' deny ACE has no POSIX equivalent for root)")
    os.chmod(d, 0o555)
    tc.addCleanup(os.chmod, d, 0o755)


def read_only(tc, path):
    """A file this user cannot write until the test ends: mode 0444 (on Windows it sets the read-only attribute, which
    refuses a write there too). Root ignores the mode on POSIX: skipped with that reason."""
    import stat
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0:
        tc.skipTest("root writes a read-only file")
    os.chmod(path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
    tc.addCleanup(lambda: os.path.exists(path) and os.chmod(path, stat.S_IREAD | stat.S_IWRITE))


def volume_dir(tc):
    """A new directory on the full volume (AP2_FULL_DIR) with room in it: the filler files are removed; the caller writes
    what it needs and then calls fill_volume(volume_root()) so that nothing more fits. Removed at the test's end."""
    import shutil
    d = os.environ.get("AP2_FULL_DIR")
    if not d or not os.path.isdir(d):
        tc.skipTest(NO_FULL)
    for x in os.listdir(d):
        if x.startswith("ap2-fill-"):
            os.remove(os.path.join(d, x))
    import secrets
    sub = os.path.join(d, "t" + secrets.token_hex(4))
    os.mkdir(sub)
    tc.addCleanup(shutil.rmtree, sub, True)
    return sub


def volume_root():
    return os.environ.get("AP2_FULL_DIR")


def acl(path):
    """The access list of `path` as icacls prints it, the path itself left out (Windows)."""
    out = subprocess.run(["icacls", path], capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
    return out.replace(path, "<p>").strip()


def unfill_volume(d):
    """Remove the filler files of fill_volume: room again on the volume of `d`."""
    for x in os.listdir(d):
        if x.startswith("ap2-fill-"):
            os.remove(os.path.join(d, x))


NO_TEMP_LIMIT = ("no per-process file-size limit on Windows, and tempfile there falls back from an unwritable TEMP to "
                 "%SYSTEMROOT%\\Temp, c:\\temp and the working directory, so no setting of this process makes every "
                 "temporary directory unwritable for the child alone")

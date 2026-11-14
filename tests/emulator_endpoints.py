"""Exact loopback UDP endpoints leased by test-owned emulator processes."""

from contextlib import contextmanager

_owned = set()


def is_owned_endpoint(endpoint):
    return endpoint in _owned


@contextmanager
def owned_emulator_pair(port):
    if not isinstance(port, int) or isinstance(port, bool) or not 0 < port < 65535:
        raise ValueError("emulator port must leave room for its debug port")
    endpoints = {("127.0.0.1", port), ("127.0.0.1", port + 1)}
    if endpoints & _owned:
        raise RuntimeError("emulator endpoints already leased")
    _owned.update(endpoints)
    try:
        yield
    finally:
        _owned.difference_update(endpoints)


def boot_owned_emulator(test):
    """Boot a kkemu `test` owns, over a flash image in a fresh temp dir, so it
    can power-cycle it (halt + boot keeps the image: a reboot, not a wipe).

    The shared CI emulator is a separate container no test can restart, so
    tests that cross a reboot must bring their own. CI mounts the exact variant
    binary at KK_EMULATOR_BIN; there a missing binary FAILS, because a skipped
    reboot test reads as a pass. Elsewhere None means "no binary found".
    """
    import os
    import shutil
    import tempfile
    from test_storage_version_gate import Emulator, _EMULATOR_BIN

    if _EMULATOR_BIN is None:
        if os.environ.get("KK_EMULATOR_BIN"):
            test.fail("KK_EMULATOR_BIN=%s is not an executable kkemu"
                      % os.environ["KK_EMULATOR_BIN"])
        return None
    workdir = tempfile.mkdtemp(prefix="kk-reboot-")
    test.addCleanup(shutil.rmtree, workdir, True)
    emu = Emulator(workdir)
    emu.boot()
    test.addCleanup(emu.halt)
    return emu

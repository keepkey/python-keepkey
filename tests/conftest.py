"""
conftest.py -- pytest plugin for per-test OLED screenshot directories.

When KEEPKEY_SCREENSHOT=1, patches KeepKeyTest.setUp to set per-test
screenshot directories BEFORE setUp runs (so wipe_device captures go
to the right place).

FAIL-FAST: If KEEPKEY_SCREENSHOT=1 and zero PNGs are captured after
all tests complete, the session exits non-zero. This prevents silent
screenshot pipeline failures from going unnoticed.
"""
import pytest
import os
import glob
import sys

if os.environ.get('KEEPKEY_SCREENSHOT') == '1':
    import common

    _orig_setUp = common.KeepKeyTest.setUp

    def _patched_setUp(self):
        # Derive per-test screenshot directory BEFORE setUp runs,
        # so captures during wipe_device/load_device go to the right place.
        test_id = self.id()
        # pytest: "tests.test_msg_wipedevice.TestDeviceWipe.test_wipe_device"
        # unittest: "test_msg_wipedevice.TestDeviceWipe.test_wipe_device"
        # Extract module basename and test method name
        parts = test_id.split('.')
        test_name = parts[-1] if parts else 'unknown'
        # Find the module part (starts with test_msg_)
        module = 'unknown'
        for p in parts:
            if p.startswith('test_msg_') or p.startswith('test_sign_') or p.startswith('test_verify_'):
                module = p.replace('test_', '', 1)  # strip first test_ only
                break
        screenshot_dir = os.path.join(
            os.environ.get('SCREENSHOT_DIR', 'screenshots'),
            module, test_name
        )
        os.makedirs(screenshot_dir, exist_ok=True)

        # Now run original setUp (creates client, calls wipe_device)
        _orig_setUp(self)

        # Set screenshot dir on the client that setUp just created
        if hasattr(self, 'client') and self.client:
            self.client.screenshot_dir = screenshot_dir
            self.client.screenshot_id = 0

    common.KeepKeyTest.setUp = _patched_setUp


def pytest_sessionfinish(session, exitstatus):
    """Fail-fast: if screenshots were requested but none captured, fail the session."""
    if os.environ.get('KEEPKEY_SCREENSHOT') != '1':
        return
    screenshot_dir = os.environ.get('SCREENSHOT_DIR', 'screenshots')
    pngs = glob.glob(os.path.join(screenshot_dir, '**', '*.png'), recursive=True)
    count = len(pngs)
    if count == 0:
        print("FATAL: KEEPKEY_SCREENSHOT=1 but 0 PNGs captured. Screenshot pipeline is broken.", file=sys.stderr)
        session.exitstatus = 1
    else:
        print("[SCREENSHOT] Session complete: %d PNGs captured" % count, file=sys.stderr)

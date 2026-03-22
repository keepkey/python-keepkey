"""
conftest.py -- pytest plugin for per-test OLED screenshot directories.

When KEEPKEY_SCREENSHOT=1, patches KeepKeyTest.setUp to set per-test
screenshot directories: screenshots/{module_name}/{test_name}/scr*.png
"""
import pytest
import os

if os.environ.get('KEEPKEY_SCREENSHOT') == '1':
    import common

    _orig_setUp = common.KeepKeyTest.setUp

    def _patched_setUp(self):
        _orig_setUp(self)
        # Client now exists -- set its screenshot dir for this test
        test_id = self.id()  # e.g. "test_msg_getaddress_show.TestMsgGetaddress.test_show"
        parts = test_id.rsplit('.', 2)
        module = parts[0].replace('test_', '') if len(parts) >= 2 else 'unknown'
        test_name = parts[-1] if parts else 'unknown'
        screenshot_dir = os.path.join(
            os.environ.get('SCREENSHOT_DIR', 'screenshots'),
            module, test_name
        )
        os.makedirs(screenshot_dir, exist_ok=True)
        if hasattr(self, 'client') and self.client:
            self.client.screenshot_dir = screenshot_dir
            self.client.screenshot_id = 0

    common.KeepKeyTest.setUp = _patched_setUp

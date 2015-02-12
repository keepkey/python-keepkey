import time
import unittest
import common

from trezorlib import messages_pb2 as proto
from trezorlib import types_pb2 as types
from trezorlib.client import PinException, CallException

class TestStor(common.TrezorTest):

    def test_stor_increment(self):
        self.client.wipe_device()

        self.assertEqual(self.client.debug.read_config_stor_count(), 1)

        self.setup_mnemonic_nopin_nopassphrase()
			
        self.assertEqual(self.client.debug.read_config_stor_count(), 2)

        self.client.apply_settings(label='new label')
        
        self.assertEqual(self.client.debug.read_config_stor_count(), 3)

    def test_stor_reset(self):
        self.client.wipe_device()

        self.assertEqual(self.client.debug.read_config_stor_count(), 1)

        self.setup_mnemonic_nopin_nopassphrase()
			
        self.assertEqual(self.client.debug.read_config_stor_count(), 2)

        self.client.apply_settings(language='english')
        
        self.assertEqual(self.client.debug.read_config_stor_count(), 3)
        
        self.client.wipe_device()

        self.assertEqual(self.client.debug.read_config_stor_count(), 1)
    
    def test_stor_curruption(self):
        self.client.wipe_device()

        self.setup_mnemonic_pin_passphrase()
        
        self.client.apply_settings(label='initial label')

        initial_stor = self.client.debug.read_config_stor()

        for attempt in range (1, 1000):
          self.client.apply_settings(label='new label attempt %d' % (attempt))

        self.client.apply_settings(label='initial label')
        self.assertEqual(initial_stor, self.client.debug.read_config_stor())
    
    def test_stor_loops(self):
        self.client.wipe_device()

        self.setup_mnemonic_pin_passphrase()

        for attempt in range (1, 206 - self.client.debug.read_config_stor_count()):
          self.client.apply_settings(label='new label attempt %d' % (attempt))

        self.assertEqual(self.client.debug.read_config_stor_count(), 1)

if __name__ == '__main__':
    unittest.main()

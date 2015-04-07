import unittest
import common

from trezorlib import messages_pb2 as proto

class TestDeviceRecovery(common.TrezorTest):
    def test_pin_passphrase(self):
        mnemonic = self.mnemonic12
        ret = self.client.call_raw(proto.RecoveryDevice(word_count=12,
                                   passphrase_protection=True,
                                   pin_protection=True,
                                   label='label',
                                   language='english',
                                   enforce_wordlist=True,
                                   use_character_cypher=True))

        self.assertIsInstance(ret, proto.PinMatrixRequest)

        # Enter PIN for first time
        pin_encoded = self.client.debug.encode_pin(self.pin6)
        ret = self.client.call_raw(proto.PinMatrixAck(pin=pin_encoded))
        self.assertIsInstance(ret, proto.PinMatrixRequest)

        # Enter PIN for second time
        pin_encoded = self.client.debug.encode_pin(self.pin6)
        ret = self.client.call_raw(proto.PinMatrixAck(pin=pin_encoded))

        for character in mnemonic:
            self.assertIsInstance(ret, proto.CharacterRequest)
            cypher = self.client.debug.read_recovery_cypher()

            if character == ' ':
                ret = self.client.call_raw(proto.CharacterAck(character=character))
            else:
                encoded_character = cypher[ord(character) - 97]
                ret = self.client.call_raw(proto.CharacterAck(character=encoded_character))

            print character

        # Send final ack
        self.assertIsInstance(ret, proto.CharacterRequest)
        ret = self.client.call_raw(proto.CharacterFinalAck())

        # Workflow succesfully ended
        self.assertIsInstance(ret, proto.Success)

        # Mnemonic is the same
        self.client.init_device()
        self.assertEqual(self.client.debug.read_mnemonic(), self.mnemonic12)

        self.assertTrue(self.client.features.pin_protection)
        self.assertTrue(self.client.features.passphrase_protection)
        
        # Do passphrase-protected action, PassphraseRequest should be raised
        resp = self.client.call_raw(proto.Ping(passphrase_protection=True))
        self.assertIsInstance(resp, proto.PassphraseRequest)
        self.client.call_raw(proto.Cancel())

        # Do PIN-protected action, PinRequest should be raised
        resp = self.client.call_raw(proto.Ping(pin_protection=True))
        self.assertIsInstance(resp, proto.PinMatrixRequest)
        self.client.call_raw(proto.Cancel())

    def test_nopin_nopassphrase(self):
        mnemonic = self.mnemonic12
        ret = self.client.call_raw(proto.RecoveryDevice(word_count=12,
                                   passphrase_protection=False,
                                   pin_protection=False,
                                   label='label',
                                   language='english',
                                   enforce_wordlist=True,
                                   use_character_cypher=True))

        for character in mnemonic:
            self.assertIsInstance(ret, proto.CharacterRequest)
            cypher = self.client.debug.read_recovery_cypher()

            if character == ' ':
                ret = self.client.call_raw(proto.CharacterAck(character=character))
            else:
                encoded_character = cypher[ord(character) - 97]
                ret = self.client.call_raw(proto.CharacterAck(character=encoded_character))

            print character

        # Send final ack
        self.assertIsInstance(ret, proto.CharacterRequest)
        ret = self.client.call_raw(proto.CharacterFinalAck())

        # Workflow succesfully ended
        self.assertIsInstance(ret, proto.Success)

        # Mnemonic is the same
        self.client.init_device()
        self.assertEqual(self.client.debug.read_mnemonic(), self.mnemonic12)

        self.assertFalse(self.client.features.pin_protection)
        self.assertFalse(self.client.features.passphrase_protection)

        # Do passphrase-protected action, PassphraseRequest should NOT be raised
        resp = self.client.call_raw(proto.Ping(passphrase_protection=True))
        self.assertIsInstance(resp, proto.Success)

        # Do PIN-protected action, PinRequest should NOT be raised
        resp = self.client.call_raw(proto.Ping(pin_protection=True))
        self.assertIsInstance(resp, proto.Success)
    
    def test_character_fail(self):
        ret = self.client.call_raw(proto.RecoveryDevice(word_count=12,
                                   passphrase_protection=False,
                                   pin_protection=False,
                                   label='label',
                                   language='english',
                                   enforce_wordlist=True,
                                   use_character_cypher=True))

        self.assertIsInstance(ret, proto.CharacterRequest)
        ret = self.client.call_raw(proto.CharacterAck(character='1'))
        self.assertIsInstance(ret, proto.Failure)

    def test_backspace(self):
        mnemonic = self.mnemonic12
        ret = self.client.call_raw(proto.RecoveryDevice(word_count=12,
                                   passphrase_protection=False,
                                   pin_protection=False,
                                   label='label',
                                   language='english',
                                   enforce_wordlist=True,
                                   use_character_cypher=True))

        for character in mnemonic:
            self.assertIsInstance(ret, proto.CharacterRequest)
            cypher = self.client.debug.read_recovery_cypher()

            if character == ' ':
                ret = self.client.call_raw(proto.CharacterAck(character=character))
            else:
                encoded_character = cypher[ord(character) - 97]
                ret = self.client.call_raw(proto.CharacterAck(character=encoded_character))

            print character


        for character in mnemonic:
            self.assertIsInstance(ret, proto.CharacterRequest)
            ret = self.client.call_raw(proto.CharacterDeleteAck())

        for character in mnemonic:
            self.assertIsInstance(ret, proto.CharacterRequest)
            cypher = self.client.debug.read_recovery_cypher()

            if character == ' ':
                ret = self.client.call_raw(proto.CharacterAck(character=character))
            else:
                encoded_character = cypher[ord(character) - 97]
                ret = self.client.call_raw(proto.CharacterAck(character=encoded_character))

            print character

        # Send final ack
        self.assertIsInstance(ret, proto.CharacterRequest)
        ret = self.client.call_raw(proto.CharacterFinalAck())

        # Workflow succesfully ended
        self.assertIsInstance(ret, proto.Success)

        # Mnemonic is the same
        self.client.init_device()
        self.assertEqual(self.client.debug.read_mnemonic(), self.mnemonic12)

        self.assertFalse(self.client.features.pin_protection)
        self.assertFalse(self.client.features.passphrase_protection)

        # Do passphrase-protected action, PassphraseRequest should NOT be raised
        resp = self.client.call_raw(proto.Ping(passphrase_protection=True))
        self.assertIsInstance(resp, proto.Success)

        # Do PIN-protected action, PinRequest should NOT be raised
        resp = self.client.call_raw(proto.Ping(pin_protection=True))
        self.assertIsInstance(resp, proto.Success)
    
if __name__ == '__main__':
    unittest.main()

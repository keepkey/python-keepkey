import time
import unittest
import common
import hashlib
import binascii

from trezorlib import messages_pb2 as proto
from trezorlib import types_pb2 as proto_types

class TestBootloader(common.TrezorBootloaderTest):

    def test_firmware_update_mode(self):

        self.client.init_device()        
        self.assertEquals(self.client.features.bootloader_mode, True)

    def test_signed_firmware_upload(self):

        # get storage fingerprint so we can compare it after upload
        app_fingerprint_before, storage_fingerprint = self.client.debug.read_fingerprints()

        data = open('firmware_images/signed_firmware_correct.bin', 'r').read()
        fingerprint = hashlib.sha256(data[256:]).hexdigest()

        # erase firmware
        ret = self.client.call(proto.FirmwareErase())
        self.assertIsInstance(ret, proto.Success)

        # upload firmware
        ret = self.client.call_raw(proto.FirmwareUpload(payload=data))
        self.assertIsInstance(ret, proto.ButtonRequest)

        # get fingerprints
        app_fingerprint, storage_fingerprint_after = self.client.debug.read_fingerprints()

        # check that app fingerprint written to flash is the same as we calculated client side
        self.assertEquals(fingerprint, binascii.hexlify(app_fingerprint))

        # finish upload so device resets
        self.client.debug.press_yes()
        ret = self.client.call_raw(proto.ButtonAck())

        # make sure config flash got copied over
        self.assertEquals(storage_fingerprint, storage_fingerprint_after)

    def test_signed_wrong_firmware_upload(self):

        # get storage fingerprint so we can compare it after upload
        app_fingerprint_before, storage_fingerprint = self.client.debug.read_fingerprints()

        data = open('firmware_images/signed_firmware_wrong.bin', 'r').read()
        fingerprint = hashlib.sha256(data[256:]).hexdigest()

        # erase firmware
        ret = self.client.call(proto.FirmwareErase())
        self.assertIsInstance(ret, proto.Success)

        # upload firmware
        ret = self.client.call_raw(proto.FirmwareUpload(payload=data))
        self.assertIsInstance(ret, proto.ButtonRequest)

        # get fingerprints
        app_fingerprint, storage_fingerprint_after = self.client.debug.read_fingerprints()

        # check that app fingerprint written to flash is the same as we calculated client side
        self.assertEquals(fingerprint, binascii.hexlify(app_fingerprint))

        # finish upload so device resets
        self.client.debug.press_yes()
        ret = self.client.call_raw(proto.ButtonAck())

        # make sure config flash got copied over
        self.assertNotEquals(storage_fingerprint, storage_fingerprint_after)

    def test_unsigned_firmware_upload(self):

        # get storage fingerprint so we can compare it after upload
        app_fingerprint_before, storage_fingerprint = self.client.debug.read_fingerprints()

        data = open('firmware_images/firmware_no_magic.bin', 'r').read()
        fingerprint = hashlib.sha256(data[256:]).hexdigest()

        # erase firmware
        ret = self.client.call(proto.FirmwareErase())
        self.assertIsInstance(ret, proto.Success)

        # upload firmware
        ret = self.client.call_raw(proto.FirmwareUpload(payload=data))
        self.assertIsInstance(ret, proto.Failure)
        self.assertEquals(ret.message, 'Not valid firmware')

    def test_signed_firmware_too_large_upload(self):

        # get storage fingerprint so we can compare it after upload
        app_fingerprint_before, storage_fingerprint = self.client.debug.read_fingerprints()

        data = open('firmware_images/signed_firmware_correct_too_large.bin', 'r').read()
        fingerprint = hashlib.sha256(data[256:]).hexdigest()

        # erase firmware
        ret = self.client.call(proto.FirmwareErase())
        self.assertIsInstance(ret, proto.Success)

        # upload firmware
        ret = self.client.call_raw(proto.FirmwareUpload(payload=data))
        self.assertIsInstance(ret, proto.Failure)
        self.assertEquals(ret.message, 'Firmware too large')

    def test_signed_firmware_corrupted_upload(self):

        # get storage fingerprint so we can compare it after upload
        app_fingerprint_before, storage_fingerprint = self.client.debug.read_fingerprints()

        data = open('firmware_images/signed_firmware_correct_corrupted.bin', 'r').read()
        fingerprint = hashlib.sha256(data[256:]).hexdigest()

        # erase firmware
        ret = self.client.call(proto.FirmwareErase())
        self.assertIsInstance(ret, proto.Success)

        # upload firmware
        ret = self.client.call_raw(proto.FirmwareUpload(payload=data))
        self.assertIsInstance(ret, proto.ButtonRequest)

        # get fingerprints
        app_fingerprint, storage_fingerprint_after = self.client.debug.read_fingerprints()

        # check that app fingerprint written to flash is the same as we calculated client side
        self.assertEquals(fingerprint, binascii.hexlify(app_fingerprint))

        # finish upload so device resets
        self.client.debug.press_yes()
        ret = self.client.call_raw(proto.ButtonAck())

        # make sure config flash got copied over
        self.assertNotEquals(storage_fingerprint, storage_fingerprint_after)

if __name__ == '__main__':
    unittest.main()

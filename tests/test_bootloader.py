import time
import unittest
import common
import hashlib
import binascii
import struct

from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as proto_types

class TestBootloader(common.KeepKeyBootloaderTest):

    def test_firmware_update_mode(self):

        self.client.init_device()        
        self.assertEquals(self.client.features.bootloader_mode, True)

    def test_signed_firmware_upload(self):

        self.client.debug.fill_config()

        # get storage hash so we can compare it after upload
        original_flashed_firmware_hash, storage_hash = self.client.debug.read_memory_hashes()

        data = open('firmware_images/signed_firmware_correct.bin', 'r').read()
        firmware_hash = hashlib.sha256(data)

        # erase firmware
        ret = self.client.call(proto.FirmwareErase())
        self.assertIsInstance(ret, proto.Success)

        # upload firmware
        ret = self.client.call_raw(proto.FirmwareUpload(payload_hash=firmware_hash.digest(), payload=data))
        self.assertIsInstance(ret, proto.Success)

        self.reconnect()

        # get flashed hashes
        flashed_firmware_hash, storage_hash_after = self.client.debug.read_memory_hashes()

        # check that firmware hash is the same as we calculated client side
        self.assertEquals(firmware_hash.hexdigest(), binascii.hexlify(flashed_firmware_hash))

        # make sure config flash got copied over
        self.assertEquals(storage_hash, storage_hash_after)

    def test_signed_wrong_firmware_upload(self):
        
        self.client.debug.fill_config()

        # get storage hash so we can compare it after upload
        original_flashed_firmware_hash, storage_hash = self.client.debug.read_memory_hashes()

        data = open('firmware_images/signed_firmware_wrong.bin', 'r').read()
        firmware_hash = hashlib.sha256(data)

        # erase firmware
        ret = self.client.call(proto.FirmwareErase())
        self.assertIsInstance(ret, proto.Success)

        # upload firmware
        ret = self.client.call_raw(proto.FirmwareUpload(payload_hash=firmware_hash.digest(), payload=data))
        self.assertIsInstance(ret, proto.Success)

        self.reconnect()

        # get flased hashes
        flashed_firmware_hash, storage_hash_after = self.client.debug.read_memory_hashes()

        # check that the flashed hash is the same as we calculated client side
        self.assertEquals(firmware_hash.hexdigest(), binascii.hexlify(flashed_firmware_hash))

        # make sure config flash did not get copied over
        self.assertNotEquals(storage_hash, storage_hash_after)

    def test_unsigned_firmware_upload(self):

        # get storage hash so we can compare it after upload
        original_flashed_firmware_hash, storage_hash = self.client.debug.read_memory_hashes()

        data = open('firmware_images/firmware_no_magic.bin', 'r').read()
        firmware_hash = hashlib.sha256(data)

        # erase firmware
        ret = self.client.call(proto.FirmwareErase())
        self.assertIsInstance(ret, proto.Success)

        # upload firmware
        ret = self.client.call_raw(proto.FirmwareUpload(payload_hash=firmware_hash.digest(), payload=data))
        self.assertIsInstance(ret, proto.Failure)
        self.assertEquals(ret.message, 'Not valid firmware')

    def test_signed_firmware_too_large_upload(self):

        # get storage hash so we can compare it after upload
        original_flashed_firmware_hash, storage_hash = self.client.debug.read_memory_hashes()

        data = open('firmware_images/signed_firmware_correct_too_large.bin', 'r').read()
        firmware_hash = hashlib.sha256(data)

        # erase firmware
        ret = self.client.call(proto.FirmwareErase())
        self.assertIsInstance(ret, proto.Success)

        # upload firmware
        ret = self.client.call_raw(proto.FirmwareUpload(payload_hash=firmware_hash.digest(), payload=data))
        self.assertIsInstance(ret, proto.Failure)
        self.assertEquals(ret.message, 'Firmware too large')

    def test_signed_firmware_corrupted_upload(self):

        self.client.debug.fill_config()

        # get storage hash so we can compare it after upload
        original_flashed_firmware_hash, storage_hash = self.client.debug.read_memory_hashes()

        data = open('firmware_images/signed_firmware_correct_corrupted.bin', 'r').read()
        firmware_hash = hashlib.sha256(data)

        # erase firmware
        ret = self.client.call(proto.FirmwareErase())
        self.assertIsInstance(ret, proto.Success)

        # upload firmware
        ret = self.client.call_raw(proto.FirmwareUpload(payload_hash=firmware_hash.digest(), payload=data))
        self.assertIsInstance(ret, proto.Success)

        self.reconnect()

        # get flashed hashes
        flashed_firmware_hash, storage_hash_after = self.client.debug.read_memory_hashes()

        # check firmware hash written to flash is the same as we calculated client side
        self.assertEquals(firmware_hash.hexdigest(), binascii.hexlify(flashed_firmware_hash))

        # make sure config flash did not get copied over
        self.assertNotEquals(storage_hash, storage_hash_after)

if __name__ == '__main__':
    unittest.main()

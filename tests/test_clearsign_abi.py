import unittest

from keepkeylib.clearsign_abi import encode_static_args


class TestClearsignAbiSignedIntegers(unittest.TestCase):

    def test_negative_int8_is_sign_extended(self):
        self.assertEqual(encode_static_args(['int8'], [-1]), b'\xff' * 32)
        self.assertEqual(
            encode_static_args(['int8'], [-128]),
            b'\xff' * 31 + b'\x80',
        )

    def test_int8_bounds_are_enforced(self):
        self.assertEqual(
            encode_static_args(['int8'], [127]),
            b'\x00' * 31 + b'\x7f',
        )
        for value in (-129, 128):
            with self.assertRaises(AssertionError):
                encode_static_args(['int8'], [value])

    def test_uint8_keeps_unsigned_bounds(self):
        self.assertEqual(
            encode_static_args(['uint8'], [255]),
            b'\x00' * 31 + b'\xff',
        )
        for value in (-1, 256):
            with self.assertRaises(AssertionError):
                encode_static_args(['uint8'], [value])


if __name__ == '__main__':
    unittest.main()

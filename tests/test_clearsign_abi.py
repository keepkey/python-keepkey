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


class TestClearsignAbiTypeValidation(unittest.TestCase):
    """The encoder must refuse types Solidity does not have.

    Emitting a plausible 32-byte word for `uint7` or `int264` makes a fixture
    read as a real ABI encoding while encoding a type no compiler can produce.
    """

    def test_non_multiple_of_eight_widths_are_rejected(self):
        for typ in ('uint7', 'int7', 'uint255', 'int13'):
            with self.assertRaises(ValueError):
                encode_static_args([typ], [1])

    def test_zero_and_oversized_widths_are_rejected(self):
        for typ in ('uint0', 'int0', 'uint264', 'int264', 'uint512'):
            with self.assertRaises(ValueError):
                encode_static_args([typ], [0])

    def test_valid_widths_still_encode(self):
        for typ in ('uint8', 'uint16', 'uint256', 'uint', 'int8', 'int256', 'int'):
            self.assertEqual(len(encode_static_args([typ], [1])), 32)

    def test_bool_requires_an_actual_bool(self):
        # 1 and 'false' would both have become ABI true.
        for val in (1, 0, 'false', 'true', 2, None):
            with self.assertRaises(ValueError):
                encode_static_args(['bool'], [val])
        self.assertEqual(encode_static_args(['bool'], [True]),
                         b'\x00' * 31 + b'\x01')
        self.assertEqual(encode_static_args(['bool'], [False]), b'\x00' * 32)

    def test_fixed_bytes_width_is_bounded(self):
        for typ in ('bytes0', 'bytes33', 'bytes64'):
            with self.assertRaises(ValueError):
                encode_static_args([typ], [b'\x11' * 32])

    def test_oversized_fixed_bytes_cannot_shift_later_arguments(self):
        """bytes33 used to emit 33 bytes -- ljust does not truncate -- which
        pushed every following argument one byte to the right."""
        with self.assertRaises(ValueError):
            encode_static_args(['bytes33', 'uint256'], [b'\x11' * 33, 1])

    def test_valid_fixed_bytes_still_encode_left_aligned(self):
        self.assertEqual(encode_static_args(['bytes1'], [b'\xab']),
                         b'\xab' + b'\x00' * 31)
        self.assertEqual(len(encode_static_args(['bytes32'], [b'\x11' * 32])), 32)

    def test_arrays_report_the_dynamic_type_error(self):
        for typ in ('uint256[]', 'address[]', 'uint256[2]'):
            with self.assertRaisesRegex(ValueError, 'dynamic/unsupported type'):
                encode_static_args([typ], [[1]])


if __name__ == '__main__':
    unittest.main()

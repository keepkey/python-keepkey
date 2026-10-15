import os
import subprocess
import sys
import unittest
from decimal import Decimal
from fractions import Fraction

import pytest

from keepkeylib.clearsign_abi import canonical_signature, encode_static_args, selector


@pytest.mark.parametrize('typ', ['uint8', 'int8'])
@pytest.mark.parametrize('value', [1.9, -0.9, -1.9, Decimal('1.9'),
                                  Decimal('-0.9'), Fraction(19, 10),
                                  Fraction(-9, 10)])
def test_integer_arguments_reject_fractional_values(typ, value):
    with pytest.raises(ValueError):
        encode_static_args([typ], [value])


@pytest.mark.parametrize('typ,value,expected', [
    ('uint8', '255', 255), ('int8', '-128', -128),
    ('uint8', 1.0, 1), ('int8', -1.0, -1),
    ('uint256', str(2**256 - 1), 2**256 - 1),
    ('int256', str(-(2**255)), -(2**255)),
    ('uint8', Decimal('2'), 2), ('int8', Fraction(-2, 1), -2),
])
def test_integer_arguments_preserve_exact_values(typ, value, expected):
    assert encode_static_args([typ], [value]) == expected.to_bytes(
        32, 'big', signed=typ.startswith('int'))


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
            with self.assertRaises(ValueError):
                encode_static_args(['int8'], [value])

    def test_uint8_keeps_unsigned_bounds(self):
        self.assertEqual(
            encode_static_args(['uint8'], [255]),
            b'\x00' * 31 + b'\xff',
        )
        for value in (-1, 256):
            with self.assertRaises(ValueError):
                encode_static_args(['uint8'], [value])

    def test_validation_survives_optimized_python(self):
        """Interpreter optimization must not remove calldata validation."""
        script = r'''
from keepkeylib.clearsign_abi import canonical_signature, encode_static_args, selector

invalid = (
    (['address'], [b'\x11' * 19]),
    (['uint8'], []),
    (['uint8'], [256]),
    (['int8'], [128]),
    (['uint8'], [-0.9]),
    (['int8'], [-1.9]),
    (['bytes2'], [b'\x11']),
)
for types, values in invalid:
    try:
        encode_static_args(types, values)
    except ValueError:
        continue
    raise SystemExit('accepted invalid ABI value: %r %r' % (types, values))
'''
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        subprocess.check_call([sys.executable, '-O', '-c', script], cwd=repo_root)


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


class TestClearsignAbiSelectors(unittest.TestCase):
    def test_integer_aliases_inside_composite_types(self):
        for shorthand, canonical in (
            ('f(uint[])', 'f(uint256[])'),
            ('f(int[2][][4])', 'f(int256[2][][4])'),
            ('f((uint,int[]),uint[3])', 'f((uint256,int256[]),uint256[3])'),
            ('f((address,(uint,int)[])[])', 'f((address,(uint256,int256)[])[])'),
        ):
            with self.subTest(signature=shorthand):
                self.assertEqual(canonical_signature(shorthand), canonical)
                self.assertEqual(selector(shorthand), selector(canonical))

    def test_aliases_do_not_rewrite_function_names_or_other_identifiers(self):
        for signature in ('uint(uint8,int32)', 'f(myuint,my_int,uint256)'):
            self.assertEqual(canonical_signature(signature), signature)


if __name__ == '__main__':
    unittest.main()

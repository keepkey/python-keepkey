# This file is part of the KeepKey project.
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

import common
import unittest

from binascii import hexlify, unhexlify

from common import KeepKeyTest
from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as proto_types
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path
from keepkeylib.tx_api import TxApiBitcoin



# Synthetic prev tx paying 100000 sat to the BIP-86 first receiving address of
# the "abandon abandon ... about" mnemonic
# (bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr).
# The fixture lives in tests/txcache and was produced together with the
# expected witness below by an independent Python implementation of
# BIP-340/341, keyed from BIP-86's own published xprv.
PREV_TXID = "6e32033911982f7550ab1d26232adfd08711293e15085f77cd27628be0a6ee37"
IN_AMOUNT = 100000
OUT_AMOUNT = 90000
OUT_ADDRESS = "1BitcoinEaterAddressDontSendf59kuE"

EXPECTED_WITNESS = (
    "afe221b16d648a1ad7329f9765930732380cc67765bd73af7ce13b5991146851"
    "2d9ee77e34af56fe1f59f98372011f7cb400ced614d808c690c5ba907fb62de9"
)

EXPECTED_CHANGE_WITNESS = (
    "e3c44408fe61256ad406733f100f1ee856eb31854335efa59e60a61ea5d41ab"
    "341802f0cccb55f644042a1ab390f0a406b9d3efe3996d05442b4ee43d5355eab"
)
EXPECTED_CHANGE_SCRIPT = (
    "5120882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc"
)

MIXED_PREV_TXID = (
    "3e1fdf082678a8a2f378995ffc0e4f853942c55c4ddbc2771b348413eeeca9a4"
)
EXPECTED_MIXED_WITNESS = (
    "b596e1bbefb855af9852942797075d4f452b2d186cb17a76226892334a497a62"
    "adb9a02f7c1b4573e4d48b92e2307bb0b2282c97e2c5350bb3c21619fab855a2"
)


# Full BIP-144 serializations, captured from the emulator and cross-checked
# against an independent derivation from this file's own inputs and the
# EXPECTED_* witnesses above. These pin the bytes the host would broadcast --
# `signature` alone was populated correctly even while the witness and the
# locktime footer were being dropped on the wire.
EXPECTED_SERIALIZED_TX = (
    "0100000000010137eea6e08b6227cd775f08153e291187d0df2a23261dab50752f98"
    "113903326e0000000000ffffffff01905f0100000000001976a914759d6677091e97"
    "3b9e9d99f19c68fbf43e3f05f988ac0140afe221b16d648a1ad7329f976593073238"
    "0cc67765bd73af7ce13b59911468512d9ee77e34af56fe1f59f98372011f7cb400ce"
    "d614d808c690c5ba907fb62de900000000"
)
EXPECTED_SERIALIZED_TX_CHANGE = (
    "0100000000010137eea6e08b6227cd775f08153e291187d0df2a23261dab50752f98"
    "113903326e0000000000ffffffff0250c30000000000001976a914759d6677091e97"
    "3b9e9d99f19c68fbf43e3f05f988ac409c000000000000225120882d74e5d0572d5a"
    "816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc0140e3c44408fe61256a"
    "d406733f100f1ee856eb31854335efa59e60a61ea5d41ab341802f0cccb55f644042"
    "a1ab390f0a406b9d3efe3996d05442b4ee43d5355eab00000000"
)
EXPECTED_SERIALIZED_TX_MIXED = (
    "01000000000102a4a9ecee1384341b77c2db4d5cc54239854f0efc5f9978f3a2a878"
    "2608df1f3e0000000000ffffffffa4a9ecee1384341b77c2db4d5cc54239854f0efc"
    "5f9978f3a2a8782608df1f3e010000006a47304402205aa50469308c21e9e1ba0299"
    "cd235add026914e4406bcfa6d9c0403c8cc3cf580220764a5832ad1bc36ba6a21020"
    "a253c2272bca5aa1643d9c41b12c318b0a38824e012103aaeb52dd7494c361049de6"
    "7cc680e83ebcbbbdbeb13637d92cd845f70308af5effffffff01e022020000000000"
    "1976a914759d6677091e973b9e9d99f19c68fbf43e3f05f988ac0140b596e1bbefb8"
    "55af9852942797075d4f452b2d186cb17a76226892334a497a62adb9a02f7c1b4573"
    "e4d48b92e2307bb0b2282c97e2c5350bb3c21619fab855a20000000000"
)


class TestMsgSigntxTaproot(KeepKeyTest):

    def assertCompleteSegwitTx(self, raw, signatures, n_in, n_out):
        """Parse the serialized tx strictly; it must consume exactly len(raw).

        `signature` and `serialized_tx` are separate nanopb fields on
        TxRequestSerializedType, each with its own presence flag.  Asserting
        only `signature` passes even when the device never transmits the
        witness stack -- the host then gets a tx that declares the segwit
        marker/flag, carries no witness and no locktime, and every node
        rejects it.  A structural parse catches that: the marker promises
        witnesses, so the stream ends early and the offset check fails.

        Returns the witness stacks, one list per input.
        """
        pos = [0]

        def take(n):
            if len(raw) < pos[0] + n:
                raise AssertionError(
                    "tx truncated at offset %d: wanted %d more byte(s) of %d "
                    "total: %s"
                    % (pos[0], n, len(raw), hexlify(raw).decode()))
            out = raw[pos[0]:pos[0] + n]
            pos[0] += n
            return out

        def varint():
            first = take(1)[0]
            if first < 0xfd:
                return first
            width = {0xfd: 2, 0xfe: 4, 0xff: 8}[first]
            return int.from_bytes(take(width), "little")

        take(4)                                              # nVersion
        marker = take(2)
        if marker != unhexlify("0001"):
            raise AssertionError(
                "missing segwit marker/flag: got %s" % hexlify(marker).decode())
        if varint() != n_in:
            raise AssertionError("unexpected input count")
        for _ in range(n_in):
            take(32); take(4); take(varint()); take(4)       # outpoint, sig, seq
        if varint() != n_out:
            raise AssertionError("unexpected output count")
        for _ in range(n_out):
            take(8); take(varint())                          # value, scriptPubKey
        witnesses = [[take(varint()) for _ in range(varint())]
                     for _ in range(n_in)]
        take(4)                                              # nLockTime footer
        if pos[0] != len(raw):
            raise AssertionError(
                "trailing bytes: parsed %d of %d" % (pos[0], len(raw)))

        # Every BIP-340 signature the device reported must actually appear in
        # the witness data it serialized.
        flat = [item for stack in witnesses for item in stack]
        for sig in signatures:
            if len(sig) == 64 and sig not in flat:
                raise AssertionError(
                    "schnorr signature absent from serialized_tx witnesses")
        return witnesses

    def test_send_p2tr(self):
        """Spend a P2TR input and compare the witness byte for byte.

        BIP-340 signing is deterministic given aux_rand, and the firmware
        signs with an all-zero aux, so this is an equality check against a
        signature computed independently of the firmware -- not a round trip
        through our own verifier, which would pass even if the device
        committed to the wrong transaction.
        """
        self.requires_taproot()
        self.setup_mnemonic_abandon()
        self.client.set_tx_api(TxApiBitcoin)

        inp1 = proto_types.TxInputType(
            address_n=parse_path("86'/0'/0'/0/0"),
            amount=IN_AMOUNT,
            prev_hash=unhexlify(PREV_TXID),
            prev_index=0,
            script_type=proto_types.SPENDTAPROOT,
        )
        out1 = proto_types.TxOutputType(
            address=OUT_ADDRESS,
            amount=OUT_AMOUNT,
            script_type=proto_types.PAYTOADDRESS,
        )

        with self.client:
            self.client.set_expected_responses([
                proto.TxRequest(
                    request_type=proto_types.TXINPUT,
                    details=proto_types.TxRequestDetailsType(
                        request_index=0)),
                proto.TxRequest(
                    request_type=proto_types.TXOUTPUT,
                    details=proto_types.TxRequestDetailsType(
                        request_index=0)),
                proto.ButtonRequest(
                    code=proto_types.ButtonRequest_ConfirmOutput),
                proto.ButtonRequest(
                    code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(
                    request_type=proto_types.TXINPUT,
                    details=proto_types.TxRequestDetailsType(
                        request_index=0)),
                proto.TxRequest(
                    request_type=proto_types.TXOUTPUT,
                    details=proto_types.TxRequestDetailsType(
                        request_index=0)),
                proto.TxRequest(
                    request_type=proto_types.TXINPUT,
                    details=proto_types.TxRequestDetailsType(
                        request_index=0)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),
            ])
            (signatures, serialized) = self.client.sign_tx(
                "Bitcoin", [inp1], [out1])

        self.assertEqual(len(signatures), 1)
        self.assertEqual(hexlify(signatures[0]).decode(), EXPECTED_WITNESS)
        witnesses = self.assertCompleteSegwitTx(serialized, signatures, 1, 1)
        # key-path spend: exactly one stack item, the bare 64-byte signature
        self.assertEqual(witnesses[0], [signatures[0]])
        self.assertEqual(hexlify(serialized).decode(), EXPECTED_SERIALIZED_TX)

    def test_send_p2tr_with_change(self):
        """P2TR change is device-derived and omitted from recipient prompts."""
        self.requires_taproot()
        self.setup_mnemonic_abandon()
        self.client.set_tx_api(TxApiBitcoin)

        inp1 = proto_types.TxInputType(
            address_n=parse_path("86'/0'/0'/0/0"),
            amount=IN_AMOUNT,
            prev_hash=unhexlify(PREV_TXID),
            prev_index=0,
            script_type=proto_types.SPENDTAPROOT,
        )
        recipient = proto_types.TxOutputType(
            address=OUT_ADDRESS,
            amount=50000,
            script_type=proto_types.PAYTOADDRESS,
        )
        change = proto_types.TxOutputType(
            address_n=parse_path("86'/0'/0'/1/0"),
            amount=40000,
            script_type=proto_types.PAYTOTAPROOT,
        )

        (signatures, serialized) = self.client.sign_tx(
            "Bitcoin", [inp1], [recipient, change])

        self.assertEqual(hexlify(signatures[0]).decode(),
                         EXPECTED_CHANGE_WITNESS)
        # EXPECTED_CHANGE_SCRIPT is a phase-1 output byte, which the device
        # transmits regardless of whether the witness ever reaches the host.
        # Assert the whole transaction, not just that prefix.
        self.assertIn(unhexlify(EXPECTED_CHANGE_SCRIPT), serialized)
        witnesses = self.assertCompleteSegwitTx(serialized, signatures, 1, 2)
        self.assertEqual(witnesses[0], [signatures[0]])
        self.assertEqual(hexlify(serialized).decode(),
                         EXPECTED_SERIALIZED_TX_CHANGE)

    def test_send_mixed_p2tr_and_legacy(self):
        """A P2TR signature commits to the legacy input's real prevout."""
        self.requires_taproot()
        self.setup_mnemonic_abandon()
        self.client.set_tx_api(TxApiBitcoin)

        taproot = proto_types.TxInputType(
            address_n=parse_path("86'/0'/0'/0/0"),
            amount=100000,
            prev_hash=unhexlify(MIXED_PREV_TXID),
            prev_index=0,
            script_type=proto_types.SPENDTAPROOT,
        )
        legacy = proto_types.TxInputType(
            address_n=parse_path("44'/0'/0'/0/0"),
            amount=50000,
            prev_hash=unhexlify(MIXED_PREV_TXID),
            prev_index=1,
            script_type=proto_types.SPENDADDRESS,
        )
        recipient = proto_types.TxOutputType(
            address=OUT_ADDRESS,
            amount=140000,
            script_type=proto_types.PAYTOADDRESS,
        )

        (signatures, serialized) = self.client.sign_tx(
            "Bitcoin", [taproot, legacy], [recipient])

        self.assertEqual(len(signatures), 2)
        self.assertEqual(hexlify(signatures[0]).decode(),
                         EXPECTED_MIXED_WITNESS)
        self.assertTrue(signatures[1])
        witnesses = self.assertCompleteSegwitTx(serialized, signatures, 2, 1)
        self.assertEqual(witnesses[0], [signatures[0]])
        # the legacy input must still serialize an EMPTY witness (0x00)
        self.assertEqual(witnesses[1], [])
        self.assertEqual(hexlify(serialized).decode(),
                         EXPECTED_SERIALIZED_TX_MIXED)

    def test_mixed_p2tr_requires_every_input_amount(self):
        """Fail closed instead of signing an incomplete BIP-341 commitment."""
        self.requires_taproot()
        self.setup_mnemonic_abandon()
        self.client.set_tx_api(TxApiBitcoin)

        taproot = proto_types.TxInputType(
            address_n=parse_path("86'/0'/0'/0/0"),
            amount=100000,
            prev_hash=unhexlify(MIXED_PREV_TXID),
            prev_index=0,
            script_type=proto_types.SPENDTAPROOT,
        )
        incomplete_legacy = proto_types.TxInputType(
            address_n=parse_path("44'/0'/0'/0/0"),
            prev_hash=unhexlify(MIXED_PREV_TXID),
            prev_index=1,
            script_type=proto_types.SPENDADDRESS,
        )
        recipient = proto_types.TxOutputType(
            address=OUT_ADDRESS,
            amount=140000,
            script_type=proto_types.PAYTOADDRESS,
        )

        with self.assertRaisesRegex(
                CallException,
                "Taproot transaction input without amount"):
            self.client.sign_tx(
                "Bitcoin", [taproot, incomplete_legacy], [recipient])

    def test_mixed_p2tr_rejects_wrong_legacy_amount(self):
        """Reject a host amount that disagrees with the actual legacy prevout."""
        self.requires_taproot()
        self.setup_mnemonic_abandon()
        self.client.set_tx_api(TxApiBitcoin)

        taproot = proto_types.TxInputType(
            address_n=parse_path("86'/0'/0'/0/0"),
            amount=100000,
            prev_hash=unhexlify(MIXED_PREV_TXID),
            prev_index=0,
            script_type=proto_types.SPENDTAPROOT,
        )
        tampered_legacy = proto_types.TxInputType(
            address_n=parse_path("44'/0'/0'/0/0"),
            amount=50001,
            prev_hash=unhexlify(MIXED_PREV_TXID),
            prev_index=1,
            script_type=proto_types.SPENDADDRESS,
        )
        recipient = proto_types.TxOutputType(
            address=OUT_ADDRESS,
            amount=140000,
            script_type=proto_types.PAYTOADDRESS,
        )

        with self.assertRaisesRegex(
                CallException,
                "Input amount or script does not match prevout"):
            self.client.sign_tx(
                "Bitcoin", [taproot, tampered_legacy], [recipient])


if __name__ == '__main__':
    unittest.main()

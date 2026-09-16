import hashlib
import unittest
import common

from base64 import b64encode
from binascii import hexlify, unhexlify

from ecdsa import VerifyingKey, SECP256k1
from ecdsa.util import sigdecode_string

import keepkeylib.messages_pb2 as proto
import keepkeylib.messages_mayachain_pb2 as mayachain_proto
import keepkeylib.types_pb2 as proto_types
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path
from keepkeylib.signed_metadata import eth_sighash_legacy, keccak256

DEFAULT_BIP32_PATH = "m/44h/931h/0h/0/0"

# Compressed secp256k1 pubkey for the standard test seed at m/44'/931'/0'/0/0.
# Proven by the (green) thorchain frozen-vector test over the same path/curve.
DEVICE_PUBKEY_HEX = b"031519713b8b42bdc367112d33132cf14cedf928ac5771d444ba459b9497117ba3"

def make_send(from_address, to_address, amount):
    return {
        'type': 'mayachain/MsgSend',
        'value': {
            'amount': [{
                'denom': 'cacao',
                'amount': str(amount),
            }],
            'from_address': from_address,
            'to_address': to_address,
        }
    }

def recover_eth_signer(sig_r, sig_s, sig_v, digest, chain_id):
    """Recover the 20-byte Ethereum signer from a legacy (EIP-155) signature.

    Mirrors the helper proven in test_msg_ethereum_clear_signing.py. Verifying
    recovery — rather than asserting r/s lengths — means a wrong digest, wrong
    calldata or wrong key fails the test, and it stays correct across router
    changes without re-freezing vectors.
    """
    from ecdsa import VerifyingKey, SECP256k1, util
    if chain_id:
        rec = sig_v - (35 + 2 * chain_id)
    else:
        rec = sig_v - 27
    keys = VerifyingKey.from_public_key_recovery_with_digest(
        sig_r + sig_s, digest, SECP256k1, hashfunc=None,
        sigdecode=util.sigdecode_string,
    )
    return keccak256(keys[rec].to_string())[-20:]


class TestMsgMayaChainSignTx(common.KeepKeyTest):

    def test_ack_rejects_send_and_deposit_together(self):
        """An unused deposit submessage must not suppress the signed tx memo."""
        self.requires_firmware("7.15.0")
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        response = self.client.call(mayachain_proto.MayachainSignTx(
            address_n=parse_path(DEFAULT_BIP32_PATH), account_number=92,
            chain_id="mayachain", fee_amount=3000, gas=200000,
            memo="SWAP:BTC.BTC:bc1qreviewthismemo", sequence=3,
            msg_count=1, testnet=False))
        self.assertIsInstance(response, mayachain_proto.MayachainMsgRequest)

        with self.assertRaises(CallException):
            self.client.call(mayachain_proto.MayachainMsgAck(
                send=mayachain_proto.MayachainMsgSend(
                    to_address="maya1jvt443rvhq5h8yrna55yjysvhtju0el7mdujp3",
                    amount=10000, denom="cacao"),
                deposit=mayachain_proto.MayachainMsgDeposit(
                    asset="MAYA.CACAO", amount=1, memo="unused",
                    signer="maya1ls33ayg26kmltw7jjy55p32ghjna09zp7z4etj")))

    def _maya_send_digest(self, account_number, chain_id, fee, gas, memo,
                          amount, from_address, to_address, sequence):
        """SHA256 of the amino StdSignDoc exactly as mayachain.c streams it.

        Byte-for-byte mirror of mayachain_signTxInit/UpdateMsgSend/Finalize
        (denom "cacao", type "mayachain/MsgSend", from_address DERIVED BY THE
        DEVICE — the host-supplied from_address is not part of the digest).
        The identical construction for thorchain ("rune"/"thorchain/MsgSend")
        reproduces that suite's green frozen vector, which pins this format.
        """
        doc = ('{"account_number":"%s"'
               ',"chain_id":"%s"'
               ',"fee":{"amount":[{"amount":"%s","denom":"cacao"}],"gas":"%s"}'
               ',"memo":"%s"'
               ',"msgs":[{"type":"mayachain/MsgSend","value":{'
               '"amount":[{"amount":"%s","denom":"cacao"}]'
               ',"from_address":"%s"'
               ',"to_address":"%s"'
               '}}],"sequence":"%s"}') % (
                   account_number, chain_id, fee, gas, memo,
                   amount, from_address, to_address, sequence)
        return hashlib.sha256(doc.encode()).digest()

    def _sign_and_verify_send(self, memo, amount=10000,
                              to_address="maya1jvt443rvhq5h8yrna55yjysvhtju0el7mdujp3"):
        """Sign a single-MsgSend maya tx and verify the signature against the
        host-reconstructed sign-doc digest and the known device pubkey. A wrong
        digest (any field not bound), wrong key, or wrong curve fails here —
        no frozen signature vectors to go stale."""
        # The device derives the sign-doc from_address itself (mainnet "maya"
        # prefix); fetch it so the host digest matches by construction.
        device_address = self.client.mayachain_get_address(
            parse_path(DEFAULT_BIP32_PATH))

        resp = self.client.mayachain_sign_tx(
            address_n=parse_path(DEFAULT_BIP32_PATH),
            account_number=92,
            chain_id="mayachain",
            fee=3000,
            gas=200000,
            msgs=[make_send(device_address, to_address, amount)],
            memo=memo,
            sequence=3,
            testnet=False,
        )

        self.assertEqual(hexlify(resp.public_key), DEVICE_PUBKEY_HEX)
        self.assertEqual(len(resp.signature), 64)
        digest = self._maya_send_digest(
            account_number=92, chain_id="mayachain", fee=3000, gas=200000,
            memo=memo, amount=amount, from_address=device_address,
            to_address=to_address, sequence=3)
        vk = VerifyingKey.from_string(unhexlify(DEVICE_PUBKEY_HEX),
                                      curve=SECP256k1)
        # Raises BadSignatureError if the device signed anything but this doc.
        self.assertTrue(vk.verify_digest(resp.signature, digest,
                                         sigdecode=sigdecode_string))

    def test_mayachain_sign_tx(self):
        """Native CACAO MsgSend with a plain memo; the full raw memo is paged
        on the OLED before signing (thorchain_confirm_full_memo is the sole
        memo gate for native MAYA)."""
        self.requires_firmware("7.9.1")
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        self._sign_and_verify_send(memo="foobar")

    def test_sign_btc_eth_swap(self):
        self.requires_firmware("7.9.1")
        self.setup_mnemonic_nopin_nopassphrase()

        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        out1 = proto_types.TxOutputType(op_return_data=b'SWAP:ETH.ETH:0x41e5560054824ea6b0732e656e3ad64e20e94e45:420',
                              amount=0,
                              script_type=proto_types.PAYTOOPRETURN,
                              )


        (signatures, serialized_tx) = self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
        self.assertEqual(hexlify(serialized_tx), '010000000182488650ef25a58fef6788bd71b8212038d7f2bbe4750bc7bcb44701e85ef6d5000000006b483045022100c1cf12191f0a50398dae21553d14d5c796ff3e2e1c378bce3d0a7d43fa9bdf4402201245f76291db518dd8b496b4406128ca0e07165c64d2fe927161eee17402f9c40121023230848585885f63803a0a8aecdd6538792d5c539215c91698e315bf0253b43dffffffff0100000000000000003d6a3b535741503a4554482e4554483a3078343165353536303035343832346561366230373332653635366533616436346532306539346534353a34323000000000')

    def test_sign_eth_btc_swap(self):
        self.requires_firmware("7.1.0")
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        address_n = [2147483692,2147483708,2147483648,0,0]
        nonce, gas_price, gas_limit, value = 0x0, 0x5FB9ACA00, 0x186A0, 0x00
        to = unhexlify('e3985e6b61b814f7cdb188766562ba71b446b46d')  # Maya router v4 (firmware-pinned)
        data = unhexlify('1fece7b4' +
            '000000000000000000000000345b297ec83add7ff74d2f7933651bffa037d956' +    # asgard vault address
            '0000000000000000000000000000000000000000000000000000000000000000' +    # asset ETH
            '000000000000000000000000000000000000000000000065945acd2b867ef000' +    # amount
            '0000000000000000000000000000000000000000000000000000000000000080' +    # offset of memo string from after func sig
            '000000000000000000000000000000000000000000000000000000000000003b' +    # length of memo string in bytes
            # SWAP:BTC.BTC:0x41e5560054824ea6b0732e656e3ad64e20e94e45:420
            '535741503a4254432e4254433a30783431653535363030353438323465613662' +    # mayachain transaction memo
            '30373332653635366533616436346532306539346534353a3432300000000000')
        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=address_n, nonce=nonce, gas_price=gas_price, gas_limit=gas_limit,
            value=value, to=to, address_type=0, chain_id=1, data=data)
        # Verify the signature is over the EXACT tx above and by THIS device's
        # key, rather than merely checking r/s lengths (which a wrong digest,
        # wrong calldata or wrong key would also pass). Recovery keeps the test
        # correct across router changes without re-freezing r/s vectors.
        self.assertIn(sig_v, [37, 38])  # EIP-155 chain_id=1
        self.assertEqual(len(sig_r), 32)
        self.assertEqual(len(sig_s), 32)
        digest = eth_sighash_legacy(nonce, gas_price, gas_limit, to, value,
                                    data, 1)
        signer = recover_eth_signer(sig_r, sig_s, sig_v, digest, 1)
        # ethereum_get_address returns the raw 20 bytes. NB: KeepKeyTest's
        # assertEqual override takes no msg argument.
        self.assertEqual(signer, self.client.ethereum_get_address(address_n))


    def test_sign_btc_add_liquidity(self):
        self.requires_firmware("7.9.1")
        self.setup_mnemonic_nopin_nopassphrase()

        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        out1 = proto_types.TxOutputType(op_return_data=b'ADD:BTC.BTC:thorpub1addwnpepq2ynqt500fag3wyxsjuv7570qxr8rqtpx93hw3cpqaqxtwxesy76utgtemp:420',
                              amount=0,
                              script_type=proto_types.PAYTOOPRETURN,
                              )


        (signatures, serialized_tx) = self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
        self.assertEqual(hexlify(serialized_tx), '010000000182488650ef25a58fef6788bd71b8212038d7f2bbe4750bc7bcb44701e85ef6d5000000006b483045022100ed9206af5ba7fe82dda17cf20574197924a120be5b415f875f7d9880f4591e4202201081cb688cceadad65dc20e9843d910d895342ce9316f792b748b0e4a0f757870121023230848585885f63803a0a8aecdd6538792d5c539215c91698e315bf0253b43dffffffff0100000000000000005e6a4c5b4144443a4254432e4254433a74686f7270756231616464776e7065707132796e717435303066616733777978736a7576373537307178723872717470783933687733637071617178747778657379373675746774656d703a34323000000000')

    def test_sign_eth_add_liquidity(self):
        self.requires_firmware("7.9.1")
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        address_n = [2147483692,2147483708,2147483648,0,0]
        nonce, gas_price, gas_limit, value = 0x0, 0x5FB9ACA00, 0x186A0, 0x00
        to = unhexlify('e3985e6b61b814f7cdb188766562ba71b446b46d')  # Maya router v4 (firmware-pinned)
        data = unhexlify('1fece7b4' +
            '0000000000000000000000000000000000000000000000000000000000000000' +
            '0000000000000000000000000000000000000000000000000000000000000000' +
            '0000000000000000000000000000000000000000000000000000000000000000' +
            '0000000000000000000000000000000000000000000000000000000000000080' +  # offset of memo string from 4
            '000000000000000000000000000000000000000000000000000000000000003a' +  # length of memo string in bytes (58: ADD:ETH.ETH:<addr>:420; the 59th byte the old 0x3b counted was ABI padding)
            # ADD:ETH.ETH:0xc5b2608927ea95ed43f842f553e3a27b09c050e8:420
            '4144443a4554482e4554483a3078633562323630383932376561393565643433' +
            '663834326635353365336132376230396330353065383a343230000000000000')
        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=address_n, nonce=nonce, gas_price=gas_price, gas_limit=gas_limit,
            value=value, to=to, address_type=0, chain_id=1, data=data)
        # Verify the signature is over the EXACT tx above and by THIS device's
        # key, rather than merely checking r/s lengths (which a wrong digest,
        # wrong calldata or wrong key would also pass). Recovery keeps the test
        # correct across router changes without re-freezing r/s vectors.
        self.assertIn(sig_v, [37, 38])  # EIP-155 chain_id=1
        self.assertEqual(len(sig_r), 32)
        self.assertEqual(len(sig_s), 32)
        digest = eth_sighash_legacy(nonce, gas_price, gas_limit, to, value,
                                    data, 1)
        signer = recover_eth_signer(sig_r, sig_s, sig_v, digest, 1)
        # ethereum_get_address returns the raw 20 bytes. NB: KeepKeyTest's
        # assertEqual override takes no msg argument.
        self.assertEqual(signer, self.client.ethereum_get_address(address_n))

    def test_mayachain_remove_liquidity(self):
        """WITHDRAW memo: pool + basis points paged in full on the OLED."""
        self.requires_firmware("7.9.1")
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        self._sign_and_verify_send(
            memo="WITHDRAW:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7:10000")


    def test_mayachain_sign_tx_memos(self):
        """Every memo shape MAYA routes on (SWAP/s/=/ADD/a/+ and bare-pool)
        signs, and each signature is bound to its exact memo bytes — a memo
        substitution changes the sign-doc digest and fails verification."""
        self.requires_firmware("7.9.1")
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        memos = [
            # full memo
            "SWAP:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7:0x41e5560054824ea6b0732e656e3ad64e20e94e45:420",
            # no limit, 's' for swap token
            "s:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7:0x41e5560054824ea6b0732e656e3ad64e20e94e45:",
            # swap to self, "=" for swap token
            "=:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7::420",
            # swap to self, no limit
            "SWAP:BTC.BTC",
            # full memo
            "ADD:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7:0x41e5560054824ea6b0732e656e3ad64e20e94e45",
            # 'a' for add liquidity
            "a:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7:0x41e5560054824ea6b0732e656e3ad64e20e94e45",
            # "+" for add liquidity
            "+:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7:0x41e5560054824ea6b0732e656e3ad64e20e94e45",
        ]
        for memo in memos:
            self._sign_and_verify_send(memo=memo)

if __name__ == '__main__':
    unittest.main()

import argparse
import importlib.machinery
import importlib.util
import json
import os
import tempfile
import types
import unittest
from unittest import mock

KEEPKEYCTL = os.path.join(os.path.dirname(__file__), '..', '..', 'keepkeyctl')


def load_keepkeyctl():
    loader = importlib.machinery.SourceFileLoader('keepkeyctl', KEEPKEYCTL)
    spec = importlib.util.spec_from_loader('keepkeyctl', loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


keepkeyctl = load_keepkeyctl()


class KeepkeyctlCommandsTestCase(unittest.TestCase):
    """Run the keepkeyctl command handlers against a mocked client."""

    def setUp(self):
        self.client = mock.MagicMock()
        self.client.expand_path.return_value = [44, 60, 0, 0, 0]
        self.cmds = keepkeyctl.Commands(self.client)

    def test_ethereum_get_address(self):
        self.client.ethereum_get_address.return_value = bytes.fromhex('ab' * 20)
        args = argparse.Namespace(n="m/44'/60'/0'/0/0", show_display=False)
        self.assertEqual(self.cmds.ethereum_get_address(args), '0x' + 'ab' * 20)

    def test_ethereum_sign_tx(self):
        fake_rlp = types.SimpleNamespace(encode=mock.Mock(return_value=b'\xf8\x01'))
        fake_ethjsonrpc = types.ModuleType('ethjsonrpc')
        fake_ethjsonrpc.EthJsonRpc = mock.Mock()
        fake_utils = types.ModuleType('ethjsonrpc.utils')
        fake_utils.hex_to_dec = mock.Mock()
        self.client.ethereum_get_address.return_value = bytes.fromhex('cd' * 20)
        self.client.ethereum_sign_tx.return_value = (27, b'r', b's')
        args = argparse.Namespace(
            n="m/44'/60'/0'/0/0", value='1', gas_price='2', gas='21000',
            to='0x' + 'ab' * 20, nonce='5', data='0x1234', chain_id=1,
            publish=False, host='localhost:8545')
        with mock.patch.dict('sys.modules', {
                'rlp': fake_rlp,
                'ethjsonrpc': fake_ethjsonrpc,
                'ethjsonrpc.utils': fake_utils}):
            out = self.cmds.ethereum_sign_tx(args)
        self.assertEqual(out, 'Signed raw transaction: 0xf801')
        kwargs = self.client.ethereum_sign_tx.call_args.kwargs
        self.assertEqual(kwargs['to'], bytes.fromhex('ab' * 20))
        self.assertEqual(kwargs['data'], b'\x12\x34')
        fake_ethjsonrpc.EthJsonRpc.assert_not_called()

        args.to = 'ab' * 20
        with mock.patch.dict('sys.modules', {
                'rlp': fake_rlp,
                'ethjsonrpc': fake_ethjsonrpc,
                'ethjsonrpc.utils': fake_utils}):
            self.cmds.ethereum_sign_tx(args)
        kwargs = self.client.ethereum_sign_tx.call_args.kwargs
        self.assertEqual(kwargs['to'], bytes.fromhex('ab' * 20))

    def test_eos_get_public_key(self):
        self.client.eos_get_public_key.return_value = types.SimpleNamespace(
            wif_public_key='EOS5abc', raw_public_key=b'\x02\x03')
        args = argparse.Namespace(n="m/44'/194'/0'/0/0", show_display=False)
        self.assertEqual(self.cmds.eos_get_public_key(args),
                         'WIF: EOS5abc\nRaw: 0203')

    def test_nano_sign_tx(self):
        self.client.nano_sign_tx.return_value = types.SimpleNamespace(
            block_hash=b'\x01\x02', signature=b'\x03\x04')
        args = argparse.Namespace(
            n="m/44'/165'/0'", coin='Nano', link_recipient_n=None,
            top_parent_hash='aa' * 32, top_link=None,
            top_representative=None, top_balance=None,
            link_hash='bb' * 32, link_recipient=None,
            representative='xrb_1', balance=1)
        out = self.cmds.nano_sign_tx(args)
        self.assertEqual(out, 'Block hash: 0102\nSignature: 0304')
        kwargs = self.client.nano_sign_tx.call_args.kwargs
        self.assertEqual(kwargs['grandparent_hash'], b'\xaa' * 32)
        self.assertIsNone(kwargs['parent_link'])
        self.assertEqual(kwargs['link_hash'], b'\xbb' * 32)

    def test_get_entropy(self):
        self.client.get_entropy.return_value = b'\x00\xff'
        out = self.cmds.get_entropy(argparse.Namespace(size=2))
        self.assertEqual(out, '00ff')
        json.dumps(out)

    def test_sign_message(self):
        self.client.sign_message.return_value = types.SimpleNamespace(
            address='1abc', signature=b'\x01\x02\x03')
        args = argparse.Namespace(n="m/44'/0'/0'/0/0", coin='Bitcoin', message='hi')
        out = self.cmds.sign_message(args)
        self.assertEqual(out['signature'], 'AQID')
        json.dumps(out)

    def test_encrypt_decrypt_keyvalue(self):
        self.client.encrypt_keyvalue.return_value = b'\xde\xad'
        args = argparse.Namespace(n="m/10016'/0", key='k', value='plain')
        self.assertEqual(self.cmds.encrypt_keyvalue(args), 'dead')
        self.assertEqual(self.client.encrypt_keyvalue.call_args.args[2], b'plain')

        self.client.decrypt_keyvalue.return_value = b'plain'
        args = argparse.Namespace(n="m/10016'/0", key='k', value='dead')
        self.assertEqual(self.cmds.decrypt_keyvalue(args), 'plain')
        self.client.decrypt_keyvalue.return_value = b'\xff\xfe'
        self.assertEqual(self.cmds.decrypt_keyvalue(args), 'fffe')
        self.assertEqual(self.client.decrypt_keyvalue.call_args.args[2], b'\xde\xad')

    def test_firmware_update_url(self):
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(b'KPKY' + b'\x00' * 12)
            seen = {}

            def firmware_update(fp):
                seen['data'] = fp.read()
                fp.close()

            self.client.firmware_update.side_effect = firmware_update
            args = argparse.Namespace(file=None, url='https://example.invalid/fw.bin')
            with mock.patch('urllib.request.urlretrieve',
                            return_value=(path, None)) as urlretrieve, \
                    mock.patch('urllib.request.urlcleanup'):
                self.cmds.firmware_update(args)
            urlretrieve.assert_called_once_with(args.url)
            self.assertEqual(seen['data'], b'KPKY' + b'\x00' * 12)
        finally:
            os.remove(path)


if __name__ == '__main__':
    unittest.main()

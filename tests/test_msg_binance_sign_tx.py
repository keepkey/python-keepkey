# This file is part of the Trezor project.
#
# Copyright (C) 2012-2019 SatoshiLabs and contributors
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

import unittest
import common

from base64 import b64encode
import binascii

from keepkeylib.tools import parse_path
import keepkeylib.binance as binance

class TestMsgBinanceSignTx(common.KeepKeyTest):

    def setup_binance(self):
        self.client.load_device_by_mnemonic(
            mnemonic="offer caution gift cross surge pretty orange during eye soldier popular holiday mention east eight office fashion ill parrot vault rent devote earth cousin",
            pin=self.pin4,
            passphrase_protection=False,
            label='test',
            language='english')

    def test_transfer(self):
        self.setup_binance()

        message = {
            "account_number": "34",
            "chain_id": "Binance-Chain-Nile",
            "data": "null",
            "memo": "test",
            "msgs": [
                {
                    "inputs": [
                        {
                            "address": "tbnb1hgm0p7khfk85zpz5v0j8wnej3a90w709zzlffd",
                            "coins": [{"amount": 1000000000, "denom": "BNB"}],
                        }
                    ],
                    "outputs": [
                        {
                            "address": "tbnb1ss57e8sa7xnwq030k2ctr775uac9gjzglqhvpy",
                            "coins": [{"amount": 1000000000, "denom": "BNB"}],
                        }
                    ],
                }
            ],
            "sequence": "31",
            "source": "1",
        }

        response = binance.sign_tx(self.client, parse_path("m/44'/714'/0'/0/0"), message)

        self.assertEqual(binascii.hexlify(response.public_key), b"029729a52e4e3c2b4a4e52aa74033eedaf8ba1df5ab6d1f518fd69e67bbd309b0e")
        self.assertEqual(binascii.hexlify(response.signature), b"faf5b908d6c4ec0c7e2e7d8f7e1b9ca56ac8b1a22b01655813c62ce89bf84a4c7b14f58ce51e85d64c13f47e67d6a9187b8f79f09e0a9b82019f47ae190a4db3")

    def test_transfer_bep2(self):
        self.setup_binance()

        message = {
            "account_number": "34",
            "chain_id": "Binance-Chain-Nile",
            "data": "null",
            "memo": "test",
            "msgs": [
                {
                    "inputs": [
                        {
                            "address": "tbnb1hgm0p7khfk85zpz5v0j8wnej3a90w709zzlffd",
                            "coins": [{"amount": 1000000000, "denom": "RUNE-B1A"}],
                        }
                    ],
                    "outputs": [
                        {
                            "address": "tbnb1ss57e8sa7xnwq030k2ctr775uac9gjzglqhvpy",
                            "coins": [{"amount": 1000000000, "denom": "RUNE-B1A"}],
                        }
                    ],
                }
            ],
            "sequence": "31",
            "source": "1",
        }

        response = binance.sign_tx(self.client, parse_path("m/44'/714'/0'/0/0"), message)

        self.assertEqual(binascii.hexlify(response.public_key), b"029729a52e4e3c2b4a4e52aa74033eedaf8ba1df5ab6d1f518fd69e67bbd309b0e")
        self.assertEqual(binascii.hexlify(response.signature), b"dd79d81887a7e66b90016e92855dd717136ec84da10dba46bf6ef831f11593dc3d07909e74a9f1517f1c710a036f2a72ca2cb152ad9f679f39e390297055cce3")



if __name__ == '__main__':
    unittest.main()

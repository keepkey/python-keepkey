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

from . import messages_binance_pb2 as messages
from .client import expect, session, field

@expect(messages.BinanceAddress)
@field("address")
def get_address(client, address_n, show_display=False):
    return client.call(
        messages.BinanceGetAddress(address_n=address_n, show_display=show_display)
    )


@expect(messages.BinancePublicKey)
@field("public_key")
def get_public_key(client, address_n, show_display=False):
    return client.call(
        messages.BinanceGetPublicKey(address_n=address_n, show_display=show_display)
    )


@session
def sign_tx(client, address_n, tx_json):
    msg = tx_json["msgs"][0]
    envelope = messages.BinanceSignTx(
        account_number=int(tx_json['account_number']),
        chain_id=tx_json['chain_id'],
        sequence=int(tx_json['sequence']),
        source=int(tx_json['source']),
        memo=tx_json['memo'],
        msg_count=1,
        address_n=address_n,
    )

    response = client.call(envelope)

    if not isinstance(response, messages.BinanceTxRequest):
        raise RuntimeError(
            "Invalid response, expected BinanceTxRequest, received "
            + type(response).__name__
        )

    if "inputs" in msg:
        msg = messages.BinanceTransferMsg(
            inputs=[messages.BinanceTransferMsg.BinanceInputOutput(
                address=msg['inputs'][0]['address'],
                coins=[messages.BinanceTransferMsg.BinanceCoin(
                    amount=msg['inputs'][0]['coins'][0]['amount'],
                    denom=msg['inputs'][0]['coins'][0]['denom']
                )]
            )],
            outputs=[messages.BinanceTransferMsg.BinanceInputOutput(
                address=msg['outputs'][0]['address'],
                coins=[messages.BinanceTransferMsg.BinanceCoin(
                    amount=msg['outputs'][0]['coins'][0]['amount'],
                    denom=msg['outputs'][0]['coins'][0]['denom']
                )]
            )]
        )
    else:
        raise ValueError("msg type not supported")

    response = client.call(msg)

    if not isinstance(response, messages.BinanceSignedTx):
        raise RuntimeError(
            "Invalid response, expected BinanceSignedTx, received "
            + type(response).__name__
        )

    return response

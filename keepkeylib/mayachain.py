import base64
import schema
import copy

tx_schema = schema.Schema({
    "tx": schema.Schema({
        "fee": schema.Schema({
            "amount": schema.Schema([{
                "denom": "cacao",
                "amount": str
            }]),
            "gas": str
        }),
        "memo": str,
        # NOTE: this needs to be 'msgs' when signing, but 'msg' when broadcasting.
        "msg": schema.Schema([{
            "type": "mayachain/MsgSend",
            "value": schema.Schema({
                "from_address": str,
                "to_address": str,
                "amount": schema.Schema([{
                    "denom": str,
                    "amount": str
                }])
            })
        }]),
        schema.Optional("signatures"): None,
    }),
    "type": "cosmos-sdk/StdTx",
    "mode": "sync"
})

def mayachain_parse_tx(tx):
    validated = tx_schema.validate(tx)

    stdtx = validated['tx']

    return {
        'fee': stdtx['fee']['amount'][0]['amount'],
        'gas': stdtx['fee']['gas'],
        'msgs': stdtx['msg'],
        'memo': stdtx['memo']
    }


def mayachain_append_sig(tx, public_key, signature):
    tx = copy.deepcopy(tx)

    tx['tx']['signatures'] = [{
        "pub_key": {
            "type": "tendermint/PubKeySecp256k1",
            "value": base64.b64encode(public_key)
        },
        "signature": base64.b64encode(signature)
    }]

    return tx
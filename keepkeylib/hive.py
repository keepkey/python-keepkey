from . import messages_hive_pb2 as proto


def get_public_key(client, address_n, show_display=False, role=None):
    kwargs = dict(address_n=address_n, show_display=show_display)
    if role is not None:
        kwargs['role'] = role
    return client.call(proto.HiveGetPublicKey(**kwargs))


def get_public_keys(client, account_index=0, show_display=False):
    return client.call(
        proto.HiveGetPublicKeys(account_index=account_index, show_display=show_display)
    )


def sign_tx(client, address_n, chain_id, ref_block_num, ref_block_prefix,
            expiration, sender, recipient, amount, decimals, asset_symbol, memo=''):
    # 'from' is a Python keyword so use **-unpacking to set the field
    return client.call(proto.HiveSignTx(**{
        'address_n': address_n,
        'chain_id': chain_id,
        'ref_block_num': ref_block_num,
        'ref_block_prefix': ref_block_prefix,
        'expiration': expiration,
        'from': sender,
        'to': recipient,
        'amount': amount,
        'decimals': decimals,
        'asset_symbol': asset_symbol,
        'memo': memo,
    }))


def sign_message(client, address_n, message):
    """Keychain signBuffer contract: sig over SHA256(raw message bytes) only —
    no chain_id prepend, no message prefix."""
    if isinstance(message, str):
        message = message.encode('utf-8')
    return client.call(proto.HiveSignMessage(address_n=address_n, message=message))


def sign_operations(client, address_n, serialized_tx, chain_id=None):
    """Sign a host-serialized Graphene transaction (HiveSignOperations).
    Firmware parses the bytes and clear-signs the phase-1 op table
    (vote, comment, custom_json); digest = SHA256(chain_id || tx)."""
    kwargs = dict(address_n=address_n, serialized_tx=serialized_tx)
    if chain_id is not None:
        kwargs['chain_id'] = chain_id
    return client.call(proto.HiveSignOperations(**kwargs))


def sign_account_create(client, address_n, chain_id, ref_block_num, ref_block_prefix,
                        expiration, creator, new_account_name, fee_amount=3000,
                        owner_key='', active_key='', posting_key='', memo_key=''):
    return client.call(proto.HiveSignAccountCreate(
        address_n=address_n,
        chain_id=chain_id,
        ref_block_num=ref_block_num,
        ref_block_prefix=ref_block_prefix,
        expiration=expiration,
        creator=creator,
        new_account_name=new_account_name,
        fee_amount=fee_amount,
        owner_key=owner_key,
        active_key=active_key,
        posting_key=posting_key,
        memo_key=memo_key,
    ))


def sign_account_update(client, address_n, chain_id, ref_block_num, ref_block_prefix,
                        expiration, account,
                        new_owner_key='', new_active_key='',
                        new_posting_key='', new_memo_key=''):
    return client.call(proto.HiveSignAccountUpdate(
        address_n=address_n,
        chain_id=chain_id,
        ref_block_num=ref_block_num,
        ref_block_prefix=ref_block_prefix,
        expiration=expiration,
        account=account,
        new_owner_key=new_owner_key,
        new_active_key=new_active_key,
        new_posting_key=new_posting_key,
        new_memo_key=new_memo_key,
    ))

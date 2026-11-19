"""Host half of Monero streamed signing (wire messages 1810-1825).

The DEVICE builds the transaction: it derives every key, proves the range
proof and signs every input. The host supplies an unsigned transfer plan,
stores the public pieces the device hands back (each with a device MAC),
returns them in the order the protocol asks for, and at the end joins them
into the transaction blob a Monero daemon accepts. Nothing secret reaches
the host.

    TxInit -> TxSetInput x n -> TxInputVini x n (key images descending)
    -> TxAllInputsSet -> TxSetOutput x 2 (the second one proves; slow)
    -> TxAllOutSet -> TxSignInput x n (same order) -> TxFinal

A plan is plain data (bytes as hex), as a watch-only Monero wallet exports
an unsigned transfer:

    {"account": 0,                      # subaddress major of the inputs
     "fee": 30720000, "unlock_time": 0,
     "payment_id": "0123456789abcdef",  # only with an integrated output
     "inputs": [{"amount", "mask", "real_index", "tx_public_key",
                 "additional_tx_public_keys": [...], "output_index",
                 "subaddress_major", "subaddress_minor",
                 "ring": [{"global_index", "public_key", "commitment"}]}],
     "outputs": [{"amount", "spend_public_key", "view_public_key",
                  "is_subaddress", "is_integrated"}],   # change included
     "change": {"amount", "spend_public_key", "view_public_key"}}

Firmware 7.17 signs exactly two outputs, one of them the change to the
wallet's own (account, 0) address, with rings of 16. It refuses anything
else at TxInit, before any screen.

A Failure from the device raises (CallException) and ends the session on
the device; start again from sign().

This file is the reference for other hosts: keep ports parallel to it.
"""

import collections
import random
import struct

from Crypto.Cipher import ChaCha20_Poly1305

from . import messages_monero_pb2 as proto
from .signed_metadata import keccak256

RING_SIZE = 16
HARD_FORK = 16
BP_PLUS = 4
RCT_TYPE_CLSAG_BP_PLUS = 6

SignedTx = collections.namedtuple('SignedTx', [
    'blob',        # the transaction, ready for a daemon's send_raw_transaction
    'tx_hash',     # its id
    'key_images',  # of the inputs, in transaction order
    'outputs',     # the plan's outputs in transaction order
    'tx_key',      # r, released at Final for standard payment proofs
    'additional_tx_keys',  # additional keys in output order, when used
])


class StreamError(Exception):
    """The device's replies do not add up to the transaction it signed."""


def varint(value):
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7f) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _keys(item):
    return dict(spend_public_key=bytes.fromhex(item['spend_public_key']),
                view_public_key=bytes.fromhex(item['view_public_key']))


def destination(output):
    return proto.MoneroTxDestination(
        amount=output['amount'], is_subaddress=bool(output['is_subaddress']),
        is_integrated=bool(output['is_integrated']), **_keys(output))


def tx_data(plan, outputs):
    """The MoneroTxData the device reviews, with `outputs` in the order they
    will have in the transaction."""
    data = proto.MoneroTxData(
        outputs=[destination(o) for o in outputs],
        change_dts=proto.MoneroTxChange(
            amount=plan['change']['amount'], major=plan['account'], minor=0,
            **_keys(plan['change'])),
        num_inputs=len(plan['inputs']), ring_size=RING_SIZE, fee=plan['fee'],
        account=plan['account'], unlock_time=plan.get('unlock_time', 0),
        hard_fork=HARD_FORK, bp_version=BP_PLUS)
    if plan.get('payment_id'):
        data.payment_id = bytes.fromhex(plan['payment_id'])
    return data


def source_entry(item):
    """One input: the ring and how the wallet received its real member."""
    src = proto.MoneroTxSourceEntry(
        ring=[proto.MoneroTxRingMember(
            global_index=member['global_index'],
            dest=bytes.fromhex(member['public_key']),
            commitment=bytes.fromhex(member['commitment']))
            for member in item['ring']],
        real_index=item['real_index'],
        real_out_tx_key=bytes.fromhex(item['tx_public_key']),
        real_output_in_tx_index=item['output_index'],
        amount=item['amount'], mask=bytes.fromhex(item['mask']),
        sub_major=item['subaddress_major'],
        sub_minor=item['subaddress_minor'])
    # The device wants only the additional key of the real output, if any.
    additional = item.get('additional_tx_public_keys') or []
    if item['output_index'] < len(additional):
        src.real_out_additional_key = bytes.fromhex(
            additional[item['output_index']])
    return src


def key_image(vini):
    """A vini is a serialized txin_to_key; its last 32 bytes."""
    return vini[-32:]


def open_clsag(opening_key, position, sealed):
    """ChaCha20-Poly1305 under the key TxFinal releases; the nonce is the
    signing position."""
    cipher = ChaCha20_Poly1305.new(
        key=opening_key, nonce=struct.pack('<I', position) + bytes(8))
    return cipher.decrypt_and_verify(sealed[:-16], sealed[-16:])


def assemble(unlock_time, vinis, outs, all_out, clsags, pseudo_outs):
    """(prefix, rctSigBase, prunable) of the transaction, as Monero
    serializes them; the blob is their concatenation."""
    prefix = varint(2) + varint(unlock_time)
    prefix += varint(len(vinis)) + b''.join(vinis)
    prefix += varint(len(outs)) + b''.join(o.tx_out for o in outs)
    prefix += varint(len(all_out.extra)) + all_out.extra
    base = bytes([all_out.rct_type]) + varint(all_out.fee)
    base += b''.join(o.ecdh_info for o in outs)
    base += b''.join(o.out_pk[32:] for o in outs)   # the commitments
    prunable = varint(1) + outs[-1].bp_plus         # one aggregate proof
    prunable += b''.join(clsags) + b''.join(pseudo_outs)
    return prefix, base, prunable


def clsag_message(prefix_hash, base, bp_plus):
    """What every CLSAG signs (Core's get_pre_mlsag_hash): the range proof
    is hashed as its keys alone, without the two length bytes."""
    rounds = bp_plus[192]
    left = bp_plus[193:193 + 32 * rounds]
    right = bp_plus[194 + 32 * rounds:]
    return keccak256(prefix_hash + keccak256(base) +
                     keccak256(bp_plus[:192] + left + right))


def sign(client, address_n, plan, network=None, rng=None):
    """Sign `plan` and return the SignedTx, including payment-proof keys.

    address_n is m/44'/128'/account'. The outputs are shuffled first, as
    Monero Core does, so the change is not always last; pass rng to control
    that (anything with a shuffle method).
    """
    outputs = list(plan['outputs'])
    (rng or random.SystemRandom()).shuffle(outputs)
    unlock_time = plan.get('unlock_time', 0)

    # The device shows the recipient, the change, the fee and the total, and
    # replies only after the user approved.
    init = client.monero_tx_init(address_n, tx_data(plan, outputs), network)

    sources = [source_entry(item) for item in plan['inputs']]
    ins = [client.monero_tx_set_input(src) for src in sources]
    # Consensus order: key images descending.
    order = sorted(range(len(ins)), key=lambda i: key_image(ins[i].vini),
                   reverse=True)
    for i in order:
        client.monero_tx_input_vini(ins[i].vini, ins[i].vini_hmac, i)
    client.monero_tx_all_inputs_set()

    # The last output carries the range proof: an estimated 13-21 s on the
    # device. Send nothing else while it proves or signs: any other message
    # ends the session (Cancel is how a host stops it).
    outs = [client.monero_tx_set_output(destination(o), init.dst_hmacs[j])
            for j, o in enumerate(outputs)]
    all_out = client.monero_tx_all_out_set()

    signed = [client.monero_tx_sign_input(
        sources[i], ins[i].vini, ins[i].vini_hmac, ins[i].pseudo_out,
        ins[i].pseudo_out_hmac, i) for i in order]
    final = client.monero_tx_final()

    clsags = [open_clsag(final.opening_key, position, s.clsag_enc)
              for position, s in enumerate(signed)]
    vinis = [ins[i].vini for i in order]
    # The pseudo-outputs as signed: the last one was adjusted to balance.
    prefix, base, prunable = assemble(
        unlock_time, vinis, outs, all_out, clsags,
        [s.pseudo_out for s in signed])

    # The device hashed its own serialization. If ours differs, the blob
    # would not be the transaction that was signed: never relay it.
    prefix_hash = keccak256(prefix)
    if prefix_hash != all_out.tx_prefix_hash:
        raise StreamError('transaction prefix differs from the signed one')
    if (all_out.rct_type != RCT_TYPE_CLSAG_BP_PLUS or
            all_out.fee != plan['fee']):
        raise StreamError('RingCT type or fee differs from the plan')
    if (clsag_message(prefix_hash, base, outs[-1].bp_plus) !=
            all_out.full_message_hash):
        raise StreamError('RingCT data differs from the signed one')

    return SignedTx(
        blob=prefix + base + prunable,
        tx_hash=keccak256(prefix_hash + keccak256(base) + keccak256(prunable)),
        key_images=[key_image(v) for v in vinis],
        outputs=outputs,
        tx_key=final.tx_key,
        additional_tx_keys=list(final.additional_tx_keys))

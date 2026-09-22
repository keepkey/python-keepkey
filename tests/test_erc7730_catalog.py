import hashlib

import pytest
from ecdsa import SECP256k1, SigningKey, util

from keepkeylib import erc7730
from keepkeylib import messages_ethereum_pb2 as ethereum
from keepkeylib.signed_metadata import TEST_PRIVATE_KEY


ADDRESS = bytes.fromhex("11" * 20)
SELECTOR = bytes.fromhex("1fece7b4")


def minimal_program():
    program = bytearray(179)
    program[:4] = b"C773"
    program[4:8] = bytes((1, 2, 0, 1))
    program[10:18] = (1).to_bytes(8, "big")
    program[18:38] = ADDRESS
    program[38:42] = SELECTOR
    return bytes(program)


def definition(payload=b"signed-envelope"):
    return erc7730.Definition(payload, ethereum.ERC7730_CALLDATA, 1,
                              ADDRESS, SELECTOR)


def request(**kwargs):
    values = dict(kind=ethereum.ERC7730_CALLDATA, chain_id=1,
                  contract_address=ADDRESS,
                  selector_or_type_hash=SELECTOR, offset=0, length=1024,
                  recursion_depth=0)
    values.update(kwargs)
    return ethereum.EthereumClearSignDefinitionRequest(**values)


def test_catalog_serves_exact_lookup_and_id_replays():
    item = definition()
    catalog = erc7730.Catalog((item,))
    first = catalog.chunk(request())
    assert first.definition_id == hashlib.sha256(item.envelope).digest()
    assert first.data == item.envelope
    replay = catalog.chunk(ethereum.EthereumClearSignDefinitionRequest(
        kind=ethereum.ERC7730_CALLDATA, chain_id=1,
        definition_id=item.definition_id, offset=0, length=1024,
        recursion_depth=1))
    assert replay.SerializeToString() == first.SerializeToString()


def test_catalog_refuses_unknown_ambiguous_and_malformed_requests():
    item = definition()
    catalog = erc7730.Catalog((item,))
    with pytest.raises(KeyError):
        catalog.chunk(request(selector_or_type_hash=b"\0" * 4))
    with pytest.raises(ValueError):
        catalog.chunk(request(length=1025))
    with pytest.raises(ValueError):
        catalog.chunk(request(recursion_depth=5))
    with pytest.raises(ValueError):
        catalog.add(definition(b"different-envelope"))


class PreloadClient(object):
    def __init__(self, envelope):
        self.envelope = envelope
        self.offset = 0

    def call(self, message):
        assert isinstance(message, ethereum.EthereumClearSignDefinition)
        assert message.offset == self.offset
        assert message.data == self.envelope[self.offset:self.offset + 1024]
        self.offset += len(message.data)
        return ethereum.EthereumClearSignDefinitionAck(
            definition_id=message.definition_id,
            next_offset=self.offset,
            complete=self.offset == len(self.envelope),
        )


def test_preload_streams_and_checks_every_acknowledgement():
    item = definition(bytes(range(256)) * 9)
    client = PreloadClient(item.envelope)
    erc7730.preload(client, item)
    assert client.offset == len(item.envelope)


def test_signed_catalog_envelope_commits_program_proof_and_certificate():
    program = minimal_program()
    proof = (bytes.fromhex("22" * 32), bytes.fromhex("33" * 32))
    certificate = bytes(range(139))
    envelope = erc7730.sign_envelope(
        program, certificate, TEST_PRIVATE_KEY, proof)
    assert envelope == erc7730.sign_envelope(
        program, certificate, TEST_PRIVATE_KEY, proof)
    assert envelope[:10] == b"K773\x01\x01" + len(program).to_bytes(4, "big")
    cursor = 10 + len(program)
    assert envelope[cursor] == len(proof)
    cursor += 1
    assert envelope[cursor:cursor + 64] == b"".join(proof)
    cursor += 64
    assert envelope[cursor:cursor + 2] == (139).to_bytes(2, "big")
    cursor += 2
    assert envelope[cursor:cursor + 139] == certificate
    cursor += 139
    signature = envelope[cursor:cursor + 64]
    assert envelope[cursor + 64] in (0, 1)
    assert len(envelope) == cursor + 65

    digest = hashlib.sha256(
        erc7730.CATALOG_DOMAIN + erc7730.catalog_root(program, proof)).digest()
    public_key = SigningKey.from_string(
        TEST_PRIVATE_KEY, curve=SECP256k1).get_verifying_key()
    assert public_key.verify_digest(signature, digest,
                                    sigdecode=util.sigdecode_string)
    assert erc7730.catalog_root(program, proof) != erc7730.catalog_root(program)


@pytest.mark.parametrize("program,certificate,private_key,proof", [
    (b"short", bytes(139), TEST_PRIVATE_KEY, ()),
    (minimal_program(), bytes(138), TEST_PRIVATE_KEY, ()),
    (minimal_program(), bytes(139), bytes(31), ()),
    (minimal_program(), bytes(139), TEST_PRIVATE_KEY, (bytes(31),)),
    (minimal_program(), bytes(139), TEST_PRIVATE_KEY,
     tuple(bytes(32) for _ in range(17))),
])
def test_signed_catalog_envelope_rejects_invalid_bounds(
        program, certificate, private_key, proof):
    with pytest.raises(ValueError):
        erc7730.sign_envelope(program, certificate, private_key, proof)

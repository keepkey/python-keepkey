import hashlib

import pytest

from keepkeylib import erc7730
from keepkeylib import messages_ethereum_pb2 as ethereum


ADDRESS = bytes.fromhex("11" * 20)
SELECTOR = bytes.fromhex("1fece7b4")


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

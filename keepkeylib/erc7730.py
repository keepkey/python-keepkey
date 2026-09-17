"""Host-side transport for certified ERC-7730 compiled definitions.

This module deliberately does not interpret or trust descriptor contents.  It
indexes signed envelopes by the lookup facts needed to find them; firmware
recomputes the definition id, authenticates the envelope, and decodes the exact
transaction itself.
"""

from __future__ import absolute_import

import hashlib

from . import messages_ethereum_pb2 as ethereum


MAX_CHUNK = 1024
MAX_RECURSION_DEPTH = 4


class Definition(object):
    def __init__(self, envelope, kind, chain_id, contract_address=None,
                 selector_or_type_hash=None):
        envelope = bytes(envelope)
        if not envelope:
            raise ValueError("ERC-7730 envelope must not be empty")
        if kind not in (ethereum.ERC7730_CALLDATA, ethereum.ERC7730_EIP712,
                        ethereum.ERC7730_TOKEN, ethereum.ERC7730_NETWORK):
            raise ValueError("unknown ERC-7730 definition kind")
        if chain_id <= 0:
            raise ValueError("ERC-7730 chain_id must be positive")
        contract_address = (None if contract_address is None
                            else bytes(contract_address))
        selector_or_type_hash = (
            None if selector_or_type_hash is None
            else bytes(selector_or_type_hash))
        if contract_address is not None and len(contract_address) != 20:
            raise ValueError("ERC-7730 contract address must be 20 bytes")
        expected_selector = 4 if kind == ethereum.ERC7730_CALLDATA else 32
        if kind in (ethereum.ERC7730_CALLDATA, ethereum.ERC7730_EIP712):
            if (selector_or_type_hash is None or
                    len(selector_or_type_hash) != expected_selector):
                raise ValueError("invalid ERC-7730 selector/type hash")
        self.envelope = envelope
        self.kind = kind
        self.chain_id = chain_id
        self.contract_address = contract_address
        self.selector_or_type_hash = selector_or_type_hash
        self.definition_id = hashlib.sha256(envelope).digest()


class Catalog(object):
    def __init__(self, definitions=()):
        self._by_id = {}
        self._by_lookup = {}
        for definition in definitions:
            self.add(definition)

    @staticmethod
    def _lookup_key(kind, chain_id, contract_address,
                    selector_or_type_hash):
        return (kind, chain_id,
                None if contract_address is None else bytes(contract_address),
                None if selector_or_type_hash is None
                else bytes(selector_or_type_hash))

    def add(self, definition):
        if not isinstance(definition, Definition):
            raise TypeError("catalog entries must be ERC-7730 Definition objects")
        existing = self._by_id.get(definition.definition_id)
        if existing is not None and existing.envelope != definition.envelope:
            raise ValueError("ERC-7730 definition id collision")
        key = self._lookup_key(
            definition.kind, definition.chain_id,
            definition.contract_address, definition.selector_or_type_hash)
        lookup_existing = self._by_lookup.get(key)
        if (lookup_existing is not None and
                lookup_existing.definition_id != definition.definition_id):
            raise ValueError("ambiguous ERC-7730 lookup tuple")
        self._by_id[definition.definition_id] = definition
        self._by_lookup[key] = definition
        return definition

    def resolve(self, request):
        if request.HasField("recursion_depth"):
            if request.recursion_depth > MAX_RECURSION_DEPTH:
                raise ValueError("ERC-7730 recursion depth exceeds device limit")
        if request.HasField("definition_id"):
            definition = self._by_id.get(bytes(request.definition_id))
        else:
            definition = self._by_lookup.get(self._lookup_key(
                request.kind, request.chain_id,
                bytes(request.contract_address)
                if request.HasField("contract_address") else None,
                bytes(request.selector_or_type_hash)
                if request.HasField("selector_or_type_hash") else None))
        if definition is None:
            raise KeyError("requested ERC-7730 definition is not in the catalog")
        if (request.kind != definition.kind or
                request.chain_id != definition.chain_id):
            raise ValueError("ERC-7730 request does not match definition")
        return definition

    def chunk(self, request):
        definition = self.resolve(request)
        offset = request.offset
        length = request.length
        if length == 0 or length > MAX_CHUNK or offset >= len(definition.envelope):
            raise ValueError("invalid ERC-7730 chunk request")
        end = min(offset + length, len(definition.envelope))
        return ethereum.EthereumClearSignDefinitionChunk(
            definition_id=definition.definition_id,
            offset=offset,
            total_length=len(definition.envelope),
            data=definition.envelope[offset:end],
        )


def preload(client, definition):
    """Stream one envelope into the device's authenticated preload slot."""
    if not isinstance(definition, Definition):
        raise TypeError("definition must be an ERC-7730 Definition")
    offset = 0
    while offset < len(definition.envelope):
        data = definition.envelope[offset:offset + MAX_CHUNK]
        response = client.call(ethereum.EthereumClearSignDefinition(
            definition_id=definition.definition_id,
            offset=offset,
            total_length=len(definition.envelope),
            data=data,
        ))
        if not isinstance(response, ethereum.EthereumClearSignDefinitionAck):
            raise RuntimeError("unexpected ERC-7730 preload response")
        expected = offset + len(data)
        if (bytes(response.definition_id) != definition.definition_id or
                response.next_offset != expected or
                response.complete != (expected == len(definition.envelope))):
            raise RuntimeError("invalid ERC-7730 preload acknowledgement")
        offset = expected


from keepkeylib import mapping
from keepkeylib import messages_ethereum_pb2 as ethereum
from keepkeylib import messages_pb2 as messages


def test_erc7730_message_ids_and_mapping():
    expected = {
        1709: ethereum.EthereumClearSignDefinition,
        1710: ethereum.EthereumClearSignDefinitionAck,
        1711: ethereum.EthereumClearSignDefinitionRequest,
        1712: ethereum.EthereumClearSignDefinitionChunk,
    }
    for wire_id, message_class in expected.items():
        assert mapping.get_class(wire_id) is message_class
        assert mapping.get_type(message_class()) == wire_id

    assert messages.MessageType_EthereumClearSignDefinition == 1709
    assert messages.MessageType_EthereumClearSignDefinitionChunk == 1712


def test_definition_chunk_round_trip_is_byte_exact():
    definition_id = bytes(range(32))
    payload = bytes((i * 17) & 0xFF for i in range(1024))
    original = ethereum.EthereumClearSignDefinitionChunk(
        definition_id=definition_id,
        offset=2048,
        total_length=4097,
        data=payload,
    )

    decoded = ethereum.EthereumClearSignDefinitionChunk()
    decoded.ParseFromString(original.SerializeToString())
    assert decoded.definition_id == definition_id
    assert decoded.offset == 2048
    assert decoded.total_length == 4097
    assert decoded.data == payload


def test_lookup_kinds_encode_expected_context():
    request = ethereum.EthereumClearSignDefinitionRequest(
        kind=ethereum.ERC7730_CALLDATA,
        chain_id=1,
        contract_address=bytes.fromhex("11" * 20),
        selector_or_type_hash=bytes.fromhex("a9059cbb"),
        offset=0,
        length=1024,
        recursion_depth=0,
    )
    assert request.IsInitialized()

    typed = ethereum.EthereumClearSignDefinitionRequest(
        kind=ethereum.ERC7730_EIP712,
        chain_id=1,
        selector_or_type_hash=bytes.fromhex("22" * 32),
        offset=1024,
        length=512,
    )
    assert typed.IsInitialized()

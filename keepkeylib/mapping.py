from . import messages_pb2 as proto
from . import messages_ethereum_pb2 as eth_proto
from . import messages_eos_pb2 as eos_proto
from . import messages_nano_pb2 as nano_proto
from . import messages_cosmos_pb2 as cosmos_proto
from . import messages_osmosis_pb2 as osmosis_proto
from . import messages_ripple_pb2 as ripple_proto
from . import messages_binance_pb2 as binance_proto
from . import messages_tendermint_pb2 as tendermint_proto
from . import messages_thorchain_pb2 as thorchain_proto
from . import messages_mayachain_pb2 as mayachain_proto

map_type_to_class = {}
map_class_to_type = {}

def build_map():
    for msg_type, i in proto.MessageType.items():
        msg_name = msg_type.replace('MessageType_', '')
        if msg_type.startswith('MessageType_Ethereum'):
            msg_class = getattr(eth_proto, msg_name)
        elif msg_type.startswith('MessageType_Eos'):
            msg_class = getattr(eos_proto, msg_name)
        elif msg_type.startswith('MessageType_Nano'):
            msg_class = getattr(nano_proto, msg_name)
        elif msg_type.startswith('MessageType_Cosmos'):
            msg_class = getattr(cosmos_proto, msg_name)
        elif msg_type.startswith('MessageType_Osmosis'):
            msg_class = getattr(osmosis_proto, msg_name)
        elif msg_type.startswith('MessageType_Ripple'):
            msg_class = getattr(ripple_proto, msg_name)
        elif msg_type.startswith('MessageType_Binance'):
            msg_class = getattr(binance_proto, msg_name)
        elif msg_type.startswith('MessageType_Tendermint'):
            msg_class = getattr(tendermint_proto, msg_name)
        elif msg_type.startswith('MessageType_Thorchain'):
            msg_class = getattr(thorchain_proto, msg_name)
        elif msg_type.startswith('MessageType_Mayachain'):
            msg_class = getattr(mayachain_proto, msg_name)
        else:
            msg_class = getattr(proto, msg_name)

        map_type_to_class[i] = msg_class
        map_class_to_type[msg_class] = i

def get_type(msg):
    return map_class_to_type[msg.__class__]


def get_class(t):
    return map_type_to_class[t]

def check_missing():
    from google.protobuf import reflection

    types = [getattr(proto, item) for item in dir(proto)
             if issubclass(getattr(proto, item).__class__, reflection.GeneratedProtocolMessageType)]

    missing = list(set(types) - set(map_type_to_class.values()))

    if len(missing):
        raise Exception("Following protobuf messages are not defined in mapping: %s" % missing)

build_map()
check_missing()

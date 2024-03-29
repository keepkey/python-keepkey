# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: messages-binance.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from . import types_pb2 as types__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='messages-binance.proto',
  package='',
  syntax='proto2',
  serialized_pb=_b('\n\x16messages-binance.proto\x1a\x0btypes.proto\"<\n\x11\x42inanceGetAddress\x12\x11\n\taddress_n\x18\x01 \x03(\r\x12\x14\n\x0cshow_display\x18\x02 \x01(\x08\"!\n\x0e\x42inanceAddress\x12\x0f\n\x07\x61\x64\x64ress\x18\x01 \x01(\t\">\n\x13\x42inanceGetPublicKey\x12\x11\n\taddress_n\x18\x01 \x03(\r\x12\x14\n\x0cshow_display\x18\x02 \x01(\x08\"&\n\x10\x42inancePublicKey\x12\x12\n\npublic_key\x18\x01 \x01(\x0c\"\x9b\x01\n\rBinanceSignTx\x12\x11\n\taddress_n\x18\x01 \x03(\r\x12\x11\n\tmsg_count\x18\x02 \x01(\r\x12\x1a\n\x0e\x61\x63\x63ount_number\x18\x03 \x01(\x12\x42\x02\x30\x01\x12\x10\n\x08\x63hain_id\x18\x04 \x01(\t\x12\x0c\n\x04memo\x18\x05 \x01(\t\x12\x14\n\x08sequence\x18\x06 \x01(\x12\x42\x02\x30\x01\x12\x12\n\x06source\x18\x07 \x01(\x12\x42\x02\x30\x01\"\x12\n\x10\x42inanceTxRequest\"\xbf\x02\n\x12\x42inanceTransferMsg\x12\x36\n\x06inputs\x18\x01 \x03(\x0b\x32&.BinanceTransferMsg.BinanceInputOutput\x12\x37\n\x07outputs\x18\x02 \x03(\x0b\x32&.BinanceTransferMsg.BinanceInputOutput\x1a\x85\x01\n\x12\x42inanceInputOutput\x12\x0f\n\x07\x61\x64\x64ress\x18\x01 \x01(\t\x12.\n\x05\x63oins\x18\x02 \x03(\x0b\x32\x1f.BinanceTransferMsg.BinanceCoin\x12(\n\x0c\x61\x64\x64ress_type\x18\x03 \x01(\x0e\x32\x12.OutputAddressTypeJ\x04\x08\x04\x10\x05\x1a\x30\n\x0b\x42inanceCoin\x12\x12\n\x06\x61mount\x18\x01 \x01(\x12\x42\x02\x30\x01\x12\r\n\x05\x64\x65nom\x18\x02 \x01(\t\"\xd7\x03\n\x0f\x42inanceOrderMsg\x12\n\n\x02id\x18\x01 \x01(\t\x12\x34\n\tordertype\x18\x02 \x01(\x0e\x32!.BinanceOrderMsg.BinanceOrderType\x12\x11\n\x05price\x18\x03 \x01(\x12\x42\x02\x30\x01\x12\x14\n\x08quantity\x18\x04 \x01(\x12\x42\x02\x30\x01\x12\x0e\n\x06sender\x18\x05 \x01(\t\x12/\n\x04side\x18\x06 \x01(\x0e\x32!.BinanceOrderMsg.BinanceOrderSide\x12\x0e\n\x06symbol\x18\x07 \x01(\t\x12\x38\n\x0btimeinforce\x18\x08 \x01(\x0e\x32#.BinanceOrderMsg.BinanceTimeInForce\"J\n\x10\x42inanceOrderType\x12\x0e\n\nOT_UNKNOWN\x10\x00\x12\n\n\x06MARKET\x10\x01\x12\t\n\x05LIMIT\x10\x02\x12\x0f\n\x0bOT_RESERVED\x10\x03\"7\n\x10\x42inanceOrderSide\x12\x10\n\x0cSIDE_UNKNOWN\x10\x00\x12\x07\n\x03\x42UY\x10\x01\x12\x08\n\x04SELL\x10\x02\"I\n\x12\x42inanceTimeInForce\x12\x0f\n\x0bTIF_UNKNOWN\x10\x00\x12\x07\n\x03GTE\x10\x01\x12\x10\n\x0cTIF_RESERVED\x10\x02\x12\x07\n\x03IOC\x10\x03\"A\n\x10\x42inanceCancelMsg\x12\r\n\x05refid\x18\x01 \x01(\t\x12\x0e\n\x06sender\x18\x02 \x01(\t\x12\x0e\n\x06symbol\x18\x03 \x01(\t\"8\n\x0f\x42inanceSignedTx\x12\x11\n\tsignature\x18\x01 \x01(\x0c\x12\x12\n\npublic_key\x18\x02 \x01(\x0c\x42\x33\n\x1a\x63om.keepkey.deviceprotocolB\x15KeepKeyMessageBinance')
  ,
  dependencies=[types__pb2.DESCRIPTOR,])



_BINANCEORDERMSG_BINANCEORDERTYPE = _descriptor.EnumDescriptor(
  name='BinanceOrderType',
  full_name='BinanceOrderMsg.BinanceOrderType',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='OT_UNKNOWN', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='MARKET', index=1, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='LIMIT', index=2, number=2,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='OT_RESERVED', index=3, number=3,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=1006,
  serialized_end=1080,
)
_sym_db.RegisterEnumDescriptor(_BINANCEORDERMSG_BINANCEORDERTYPE)

_BINANCEORDERMSG_BINANCEORDERSIDE = _descriptor.EnumDescriptor(
  name='BinanceOrderSide',
  full_name='BinanceOrderMsg.BinanceOrderSide',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='SIDE_UNKNOWN', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='BUY', index=1, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SELL', index=2, number=2,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=1082,
  serialized_end=1137,
)
_sym_db.RegisterEnumDescriptor(_BINANCEORDERMSG_BINANCEORDERSIDE)

_BINANCEORDERMSG_BINANCETIMEINFORCE = _descriptor.EnumDescriptor(
  name='BinanceTimeInForce',
  full_name='BinanceOrderMsg.BinanceTimeInForce',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='TIF_UNKNOWN', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='GTE', index=1, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='TIF_RESERVED', index=2, number=2,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='IOC', index=3, number=3,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=1139,
  serialized_end=1212,
)
_sym_db.RegisterEnumDescriptor(_BINANCEORDERMSG_BINANCETIMEINFORCE)


_BINANCEGETADDRESS = _descriptor.Descriptor(
  name='BinanceGetAddress',
  full_name='BinanceGetAddress',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='address_n', full_name='BinanceGetAddress.address_n', index=0,
      number=1, type=13, cpp_type=3, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='show_display', full_name='BinanceGetAddress.show_display', index=1,
      number=2, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=39,
  serialized_end=99,
)


_BINANCEADDRESS = _descriptor.Descriptor(
  name='BinanceAddress',
  full_name='BinanceAddress',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='address', full_name='BinanceAddress.address', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=101,
  serialized_end=134,
)


_BINANCEGETPUBLICKEY = _descriptor.Descriptor(
  name='BinanceGetPublicKey',
  full_name='BinanceGetPublicKey',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='address_n', full_name='BinanceGetPublicKey.address_n', index=0,
      number=1, type=13, cpp_type=3, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='show_display', full_name='BinanceGetPublicKey.show_display', index=1,
      number=2, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=136,
  serialized_end=198,
)


_BINANCEPUBLICKEY = _descriptor.Descriptor(
  name='BinancePublicKey',
  full_name='BinancePublicKey',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='public_key', full_name='BinancePublicKey.public_key', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=200,
  serialized_end=238,
)


_BINANCESIGNTX = _descriptor.Descriptor(
  name='BinanceSignTx',
  full_name='BinanceSignTx',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='address_n', full_name='BinanceSignTx.address_n', index=0,
      number=1, type=13, cpp_type=3, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='msg_count', full_name='BinanceSignTx.msg_count', index=1,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='account_number', full_name='BinanceSignTx.account_number', index=2,
      number=3, type=18, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('0\001')), file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='chain_id', full_name='BinanceSignTx.chain_id', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='memo', full_name='BinanceSignTx.memo', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='sequence', full_name='BinanceSignTx.sequence', index=5,
      number=6, type=18, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('0\001')), file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='source', full_name='BinanceSignTx.source', index=6,
      number=7, type=18, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('0\001')), file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=241,
  serialized_end=396,
)


_BINANCETXREQUEST = _descriptor.Descriptor(
  name='BinanceTxRequest',
  full_name='BinanceTxRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=398,
  serialized_end=416,
)


_BINANCETRANSFERMSG_BINANCEINPUTOUTPUT = _descriptor.Descriptor(
  name='BinanceInputOutput',
  full_name='BinanceTransferMsg.BinanceInputOutput',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='address', full_name='BinanceTransferMsg.BinanceInputOutput.address', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='coins', full_name='BinanceTransferMsg.BinanceInputOutput.coins', index=1,
      number=2, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='address_type', full_name='BinanceTransferMsg.BinanceInputOutput.address_type', index=2,
      number=3, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=555,
  serialized_end=688,
)

_BINANCETRANSFERMSG_BINANCECOIN = _descriptor.Descriptor(
  name='BinanceCoin',
  full_name='BinanceTransferMsg.BinanceCoin',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='amount', full_name='BinanceTransferMsg.BinanceCoin.amount', index=0,
      number=1, type=18, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('0\001')), file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='denom', full_name='BinanceTransferMsg.BinanceCoin.denom', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=690,
  serialized_end=738,
)

_BINANCETRANSFERMSG = _descriptor.Descriptor(
  name='BinanceTransferMsg',
  full_name='BinanceTransferMsg',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='inputs', full_name='BinanceTransferMsg.inputs', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='outputs', full_name='BinanceTransferMsg.outputs', index=1,
      number=2, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[_BINANCETRANSFERMSG_BINANCEINPUTOUTPUT, _BINANCETRANSFERMSG_BINANCECOIN, ],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=419,
  serialized_end=738,
)


_BINANCEORDERMSG = _descriptor.Descriptor(
  name='BinanceOrderMsg',
  full_name='BinanceOrderMsg',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='id', full_name='BinanceOrderMsg.id', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='ordertype', full_name='BinanceOrderMsg.ordertype', index=1,
      number=2, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='price', full_name='BinanceOrderMsg.price', index=2,
      number=3, type=18, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('0\001')), file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='quantity', full_name='BinanceOrderMsg.quantity', index=3,
      number=4, type=18, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('0\001')), file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='sender', full_name='BinanceOrderMsg.sender', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='side', full_name='BinanceOrderMsg.side', index=5,
      number=6, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='symbol', full_name='BinanceOrderMsg.symbol', index=6,
      number=7, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='timeinforce', full_name='BinanceOrderMsg.timeinforce', index=7,
      number=8, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _BINANCEORDERMSG_BINANCEORDERTYPE,
    _BINANCEORDERMSG_BINANCEORDERSIDE,
    _BINANCEORDERMSG_BINANCETIMEINFORCE,
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=741,
  serialized_end=1212,
)


_BINANCECANCELMSG = _descriptor.Descriptor(
  name='BinanceCancelMsg',
  full_name='BinanceCancelMsg',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='refid', full_name='BinanceCancelMsg.refid', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='sender', full_name='BinanceCancelMsg.sender', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='symbol', full_name='BinanceCancelMsg.symbol', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1214,
  serialized_end=1279,
)


_BINANCESIGNEDTX = _descriptor.Descriptor(
  name='BinanceSignedTx',
  full_name='BinanceSignedTx',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='signature', full_name='BinanceSignedTx.signature', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='public_key', full_name='BinanceSignedTx.public_key', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1281,
  serialized_end=1337,
)

_BINANCETRANSFERMSG_BINANCEINPUTOUTPUT.fields_by_name['coins'].message_type = _BINANCETRANSFERMSG_BINANCECOIN
_BINANCETRANSFERMSG_BINANCEINPUTOUTPUT.fields_by_name['address_type'].enum_type = types__pb2._OUTPUTADDRESSTYPE
_BINANCETRANSFERMSG_BINANCEINPUTOUTPUT.containing_type = _BINANCETRANSFERMSG
_BINANCETRANSFERMSG_BINANCECOIN.containing_type = _BINANCETRANSFERMSG
_BINANCETRANSFERMSG.fields_by_name['inputs'].message_type = _BINANCETRANSFERMSG_BINANCEINPUTOUTPUT
_BINANCETRANSFERMSG.fields_by_name['outputs'].message_type = _BINANCETRANSFERMSG_BINANCEINPUTOUTPUT
_BINANCEORDERMSG.fields_by_name['ordertype'].enum_type = _BINANCEORDERMSG_BINANCEORDERTYPE
_BINANCEORDERMSG.fields_by_name['side'].enum_type = _BINANCEORDERMSG_BINANCEORDERSIDE
_BINANCEORDERMSG.fields_by_name['timeinforce'].enum_type = _BINANCEORDERMSG_BINANCETIMEINFORCE
_BINANCEORDERMSG_BINANCEORDERTYPE.containing_type = _BINANCEORDERMSG
_BINANCEORDERMSG_BINANCEORDERSIDE.containing_type = _BINANCEORDERMSG
_BINANCEORDERMSG_BINANCETIMEINFORCE.containing_type = _BINANCEORDERMSG
DESCRIPTOR.message_types_by_name['BinanceGetAddress'] = _BINANCEGETADDRESS
DESCRIPTOR.message_types_by_name['BinanceAddress'] = _BINANCEADDRESS
DESCRIPTOR.message_types_by_name['BinanceGetPublicKey'] = _BINANCEGETPUBLICKEY
DESCRIPTOR.message_types_by_name['BinancePublicKey'] = _BINANCEPUBLICKEY
DESCRIPTOR.message_types_by_name['BinanceSignTx'] = _BINANCESIGNTX
DESCRIPTOR.message_types_by_name['BinanceTxRequest'] = _BINANCETXREQUEST
DESCRIPTOR.message_types_by_name['BinanceTransferMsg'] = _BINANCETRANSFERMSG
DESCRIPTOR.message_types_by_name['BinanceOrderMsg'] = _BINANCEORDERMSG
DESCRIPTOR.message_types_by_name['BinanceCancelMsg'] = _BINANCECANCELMSG
DESCRIPTOR.message_types_by_name['BinanceSignedTx'] = _BINANCESIGNEDTX
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

BinanceGetAddress = _reflection.GeneratedProtocolMessageType('BinanceGetAddress', (_message.Message,), dict(
  DESCRIPTOR = _BINANCEGETADDRESS,
  __module__ = 'messages_binance_pb2'
  # @@protoc_insertion_point(class_scope:BinanceGetAddress)
  ))
_sym_db.RegisterMessage(BinanceGetAddress)

BinanceAddress = _reflection.GeneratedProtocolMessageType('BinanceAddress', (_message.Message,), dict(
  DESCRIPTOR = _BINANCEADDRESS,
  __module__ = 'messages_binance_pb2'
  # @@protoc_insertion_point(class_scope:BinanceAddress)
  ))
_sym_db.RegisterMessage(BinanceAddress)

BinanceGetPublicKey = _reflection.GeneratedProtocolMessageType('BinanceGetPublicKey', (_message.Message,), dict(
  DESCRIPTOR = _BINANCEGETPUBLICKEY,
  __module__ = 'messages_binance_pb2'
  # @@protoc_insertion_point(class_scope:BinanceGetPublicKey)
  ))
_sym_db.RegisterMessage(BinanceGetPublicKey)

BinancePublicKey = _reflection.GeneratedProtocolMessageType('BinancePublicKey', (_message.Message,), dict(
  DESCRIPTOR = _BINANCEPUBLICKEY,
  __module__ = 'messages_binance_pb2'
  # @@protoc_insertion_point(class_scope:BinancePublicKey)
  ))
_sym_db.RegisterMessage(BinancePublicKey)

BinanceSignTx = _reflection.GeneratedProtocolMessageType('BinanceSignTx', (_message.Message,), dict(
  DESCRIPTOR = _BINANCESIGNTX,
  __module__ = 'messages_binance_pb2'
  # @@protoc_insertion_point(class_scope:BinanceSignTx)
  ))
_sym_db.RegisterMessage(BinanceSignTx)

BinanceTxRequest = _reflection.GeneratedProtocolMessageType('BinanceTxRequest', (_message.Message,), dict(
  DESCRIPTOR = _BINANCETXREQUEST,
  __module__ = 'messages_binance_pb2'
  # @@protoc_insertion_point(class_scope:BinanceTxRequest)
  ))
_sym_db.RegisterMessage(BinanceTxRequest)

BinanceTransferMsg = _reflection.GeneratedProtocolMessageType('BinanceTransferMsg', (_message.Message,), dict(

  BinanceInputOutput = _reflection.GeneratedProtocolMessageType('BinanceInputOutput', (_message.Message,), dict(
    DESCRIPTOR = _BINANCETRANSFERMSG_BINANCEINPUTOUTPUT,
    __module__ = 'messages_binance_pb2'
    # @@protoc_insertion_point(class_scope:BinanceTransferMsg.BinanceInputOutput)
    ))
  ,

  BinanceCoin = _reflection.GeneratedProtocolMessageType('BinanceCoin', (_message.Message,), dict(
    DESCRIPTOR = _BINANCETRANSFERMSG_BINANCECOIN,
    __module__ = 'messages_binance_pb2'
    # @@protoc_insertion_point(class_scope:BinanceTransferMsg.BinanceCoin)
    ))
  ,
  DESCRIPTOR = _BINANCETRANSFERMSG,
  __module__ = 'messages_binance_pb2'
  # @@protoc_insertion_point(class_scope:BinanceTransferMsg)
  ))
_sym_db.RegisterMessage(BinanceTransferMsg)
_sym_db.RegisterMessage(BinanceTransferMsg.BinanceInputOutput)
_sym_db.RegisterMessage(BinanceTransferMsg.BinanceCoin)

BinanceOrderMsg = _reflection.GeneratedProtocolMessageType('BinanceOrderMsg', (_message.Message,), dict(
  DESCRIPTOR = _BINANCEORDERMSG,
  __module__ = 'messages_binance_pb2'
  # @@protoc_insertion_point(class_scope:BinanceOrderMsg)
  ))
_sym_db.RegisterMessage(BinanceOrderMsg)

BinanceCancelMsg = _reflection.GeneratedProtocolMessageType('BinanceCancelMsg', (_message.Message,), dict(
  DESCRIPTOR = _BINANCECANCELMSG,
  __module__ = 'messages_binance_pb2'
  # @@protoc_insertion_point(class_scope:BinanceCancelMsg)
  ))
_sym_db.RegisterMessage(BinanceCancelMsg)

BinanceSignedTx = _reflection.GeneratedProtocolMessageType('BinanceSignedTx', (_message.Message,), dict(
  DESCRIPTOR = _BINANCESIGNEDTX,
  __module__ = 'messages_binance_pb2'
  # @@protoc_insertion_point(class_scope:BinanceSignedTx)
  ))
_sym_db.RegisterMessage(BinanceSignedTx)


DESCRIPTOR.has_options = True
DESCRIPTOR._options = _descriptor._ParseOptions(descriptor_pb2.FileOptions(), _b('\n\032com.keepkey.deviceprotocolB\025KeepKeyMessageBinance'))
_BINANCESIGNTX.fields_by_name['account_number'].has_options = True
_BINANCESIGNTX.fields_by_name['account_number']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('0\001'))
_BINANCESIGNTX.fields_by_name['sequence'].has_options = True
_BINANCESIGNTX.fields_by_name['sequence']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('0\001'))
_BINANCESIGNTX.fields_by_name['source'].has_options = True
_BINANCESIGNTX.fields_by_name['source']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('0\001'))
_BINANCETRANSFERMSG_BINANCECOIN.fields_by_name['amount'].has_options = True
_BINANCETRANSFERMSG_BINANCECOIN.fields_by_name['amount']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('0\001'))
_BINANCEORDERMSG.fields_by_name['price'].has_options = True
_BINANCEORDERMSG.fields_by_name['price']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('0\001'))
_BINANCEORDERMSG.fields_by_name['quantity'].has_options = True
_BINANCEORDERMSG.fields_by_name['quantity']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('0\001'))
# @@protoc_insertion_point(module_scope)

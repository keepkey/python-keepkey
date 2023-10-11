#!/bin/bash
CURDIR=$(pwd)
cd "device-protocol"

echo "Building with protoc version: $(protoc --version)"
for i in messages messages-ethereum messages-eos messages-nano messages-cosmos messages-ripple messages-binance messages-tendermint messages-thorchain messages-mayachain messages-osmosis types ; do
    protoc --python_out=$CURDIR/keepkeylib/ -I/usr/include -I. $i.proto
    i=${i/-/_}
    sed -i -Ee 's/^import ([^.]+_pb2)/from . import \1/' $CURDIR/keepkeylib/"$i"_pb2.py
done

sed -i 's/5000\([2-5]\)/6000\1/g' $CURDIR/keepkeylib/types_pb2.py

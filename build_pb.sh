#!/bin/bash
CURDIR=$(pwd)
DEVICE_PROTO="device-protocol"
DEVICE_PROTO_VERSION="v4.0.1"

# Create a clean directory for the protobuf files
if [ -d $DEVICE_PROTO ]
then
    rm -rf $DEVICE_PROTO
fi

git clone --branch $DEVICE_PROTO_VERSION --depth 1 https://github.com/keepkey/$DEVICE_PROTO.git $DEVICE_PROTO
cd $DEVICE_PROTO

echo "Building with protoc version: $(protoc --version)"
for i in messages types exchange ; do
    protoc --python_out=$CURDIR/keepkeylib/ -I/usr/include -I. $i.proto
    sed -Ee 's/^import ([^.]+_pb2)/from . import \1/' -i "" $CURDIR/keepkeylib/"$i"_pb2.py
done

cd $CURDIR/keepkeylib
sed -i "" 's/5000\([2-5]\)/6000\1/g' types_pb2.py

#!/bin/bash
CURDIR=$(pwd)

DEVICE_PROTO="device-protocol"

if [ ! -d ../$DEVICE_PROTO ]
then
    git clone git@github.com:keepkey/$DEVICE_PROTO.git ../$DEVICE_PROTO
fi

cd $CURDIR/../$DEVICE_PROTO

for i in messages types exchange ; do
    protoc --python_out=$CURDIR/keepkeylib/ -I/usr/include -I. $i.proto
done

cd $CURDIR/keepkeylib
sed -i -- 's/5000\([2-5]\)/6000\1/g' types_pb2.py

#!/bin/bash
CURDIR=$(pwd)

cd $CURDIR/../device-protocol

for i in messages types ; do
    protoc --python_out=$CURDIR/keepkeylib/ -I/usr/include -I. $i.proto
done

cd $CURDIR/keepkeylib
sed -i -- 's/5000\([2-5]\)/6000\1/g' types_pb2.py

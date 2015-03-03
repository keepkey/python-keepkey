#!/bin/bash
CURDIR=$(pwd)

cd $CURDIR/../keepkey-firmware/interface/public

for i in messages types ; do
    protoc --python_out=$CURDIR/trezorlib/ -I/usr/include -I. $i.proto
done

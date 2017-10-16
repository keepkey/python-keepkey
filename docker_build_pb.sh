#!/bin/bash

# expects this repo and `device-protocol` to be cloned at the same filesystem level
TEMPDIR="../device-protocol"
IMAGETAG=keepkey/firmware

docker run -it --rm \
    -v $(pwd):/root/python-keepkey \
    -v $(pwd)/$TEMPDIR:/root/device-protocol \
    -w /root/python-keepkey \
    $IMAGETAG \
    ./build_pb.sh

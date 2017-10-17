#!/bin/bash

IMAGETAG=keepkey/firmware

docker run -it --rm \
    -v $(pwd):/root/python-keepkey \
    -w /root/python-keepkey \
    $IMAGETAG \
    ./build_pb.sh

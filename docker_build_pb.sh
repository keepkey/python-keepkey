#!/bin/bash

IMAGETAG=kktech/firmware:v1

docker pull $IMAGETAG

docker run -it \
    -v $(pwd):/root/python-keepkey \
    -w /root/python-keepkey \
    $IMAGETAG \
    ./build_pb.sh

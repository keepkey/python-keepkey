#!/bin/bash

IMAGETAG=kktech/firmware:v8

docker pull $IMAGETAG

docker run -it \
    -v $(pwd):/root/python-keepkey \
    -w /root/python-keepkey \
    $IMAGETAG \
    /bin/sh -c "source /root/python-keepkey/build_pb.sh"

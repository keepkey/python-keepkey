#!/bin/bash

TEMPDIR="../device-protocol"
IMAGETAG=keepkey/firmware

docker build -t $IMAGETAG .

docker run -t -v $(pwd):/root/python-keepkey -v $(pwd)/$TEMPDIR:/root/device-protocol --rm $IMAGETAG /bin/sh -c "\
	cd /root/python-keepkey && \
	./build_pb.sh"
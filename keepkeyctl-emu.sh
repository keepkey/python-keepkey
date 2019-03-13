#!/bin/sh
./keepkeyctl -t udp -p 127.0.0.1:21324 -Dt udp -Dp 127.0.0.1:21325 --auto-button "$@"

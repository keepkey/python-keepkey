#!/bin/sh
./keepkeyctl -t udp -p 127.0.0.1:11044 -Dt udp -Dp 127.0.0.1:11045 --auto-button "$@"

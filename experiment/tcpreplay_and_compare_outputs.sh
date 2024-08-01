#!/bin/bash

set -e 

tmux new-session -d -s tmuxtcpreplaysession "$1 > 0.stats" 
ip link
tcpreplay -i tap0 -t --loop 100000 $3 ; ifconfig tap0
ping 192.168.1.200 -c 1
tmux kill-session -t tmuxtcpreplaysession
tmux new-session -d -s tmuxtcpreplaysession "$2 > 1.stats"
tcpreplay -i tap0 -t --loop 100000 $3 ; ifconfig tap0
ping 192.168.1.200 -c 1
tmux kill-session -t tmuxtcpreplaysession
diff -urN 0.stats 1.stats


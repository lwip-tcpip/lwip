# UDP iPerf2 Test Tool for Raspberry Pi

## Overview

Standalone iPerf2-compatible UDP test tool that implements the **exact same 
protocol** as our `lwiperf.c` UDP implementation. Use it on a Raspberry Pi 
(or any Linux machine) to validate the embedded board's UDP iPerf.

## Build

### On the Raspberry Pi directly:
```bash
# Copy this folder to Pi, then:
cd pi_test
make
```

### Cross-compile from x86 (needs arm-linux-gnueabihf-gcc):
```bash
# Install cross-compiler (Ubuntu/Debian):
sudo apt install gcc-arm-linux-gnueabihf

# Build:
make pi

# Copy to Pi:
scp udp_iperf_test_pi pi@<pi_ip>:~/
```

## Test Setup

```
┌──────────────┐      1 Gbps Ethernet      ┌──────────────┐
│ Raspberry Pi │ ◄─────────────────────────► │  x86 Machine │
│  (test tool) │                             │  (iperf/board)│
└──────────────┘                             └──────────────┘
```

## Usage

```bash
# Server mode (listen for UDP iPerf connections):
./udp_iperf_test -s
./udp_iperf_test -s -p 5001

# Client mode (send UDP traffic):
./udp_iperf_test -c 192.168.1.1 -b 100M -t 10
./udp_iperf_test -c 192.168.1.1 -b 1M -t 5 -p 5001
```

### Bandwidth examples:
- `-b 1M` = 1 Mbps
- `-b 100M` = 100 Mbps
- `-b 500K` = 500 Kbps
- `-b 1G` = 1 Gbps (will be limited by NIC)

## Test Scenarios

### Scenario 1: Pi as Server, Board as Client
```
Board (lwiperf_start_udp_client) ──UDP──► Pi (./udp_iperf_test -s)
```
- Board config: `IPERF_PROTOCOL = IPERF_PROTOCOL_UDP`, `IPERF_MODE = CLIENT`
- Pi: `./udp_iperf_test -s`

### Scenario 2: Pi as Client, Board as Server
```
Pi (./udp_iperf_test -c <board_ip>) ──UDP──► Board (lwiperf_start_udp_server)
```
- Board config: `IPERF_PROTOCOL = IPERF_PROTOCOL_UDP`, `IPERF_MODE = SERVER`
- Pi: `./udp_iperf_test -c 192.168.1.100 -b 1M -t 10`

### Scenario 3: Pi vs standard iperf2 (x86)
```
Pi (./udp_iperf_test -s) ◄──UDP── x86 (iperf -u -c <pi_ip> -b 100M)
Pi (./udp_iperf_test -c <x86_ip>) ──UDP──► x86 (iperf -u -s)
```

### Scenario 4: Bidirectional (Pi ↔ x86)
```
Terminal 1 (Pi): ./udp_iperf_test -s
Terminal 2 (Pi): ./udp_iperf_test -c <x86_ip> -b 100M -t 10
Terminal 1 (x86): iperf -u -s
Terminal 2 (x86): iperf -u -c <pi_ip> -b 100M -t 10
```

## Protocol Details

This tool implements iPerf2 UDP protocol:
- **12-byte header** per datagram: `{id (int32), tv_sec (uint32), tv_usec (uint32)}`
- **Positive id** = sequence number (1, 2, 3, ...)
- **Negative id** = final packet (signals end of test)
- **Server report** = 40-byte response after receiving final packet

This is the same protocol used by:
- Standard `iperf` (version 2.x) with `-u` flag
- Our `lwiperf.c` UDP implementation in the SDK

## Expected Output

### Server:
```
============================================================
 UDP iPerf2 Test Tool (lwiperf-compatible)
============================================================
UDP iPerf2 Server listening on port 5001
------------------------------------------------------------
[Server] Waiting for client...
[Server] Session from 192.168.1.1:54321
[Server] 1.0s: 0.12 MB, 0.99 Mbps, 85 pkts
[Server] 2.0s: 0.24 MB, 0.99 Mbps, 170 pkts
...
[Server] Test complete:
  Duration:    10.01 sec
  Transferred: 1.19 MB
  Bandwidth:   0.99 Mbps
  Datagrams:   850
  Out-of-order: 0
  Lost:        0 (0.00%)
```

### Client:
```
============================================================
 UDP iPerf2 Test Tool (lwiperf-compatible)
============================================================
UDP iPerf2 Client sending to 192.168.1.100:5001
  Duration:  10 sec
  Bandwidth: 1 Mbps
  Pkt size:  1470 bytes
------------------------------------------------------------
[Client] Sending ~85 pkts/sec (11764.7 us delay)
[Client] 1.0s: 0.12 MB sent, 0.99 Mbps, 85 pkts
...
[Client] Server report received:
  Duration:    10.01 sec
  Transferred: 1.19 MB
  Bandwidth:   0.99 Mbps
  Datagrams:   850
  Lost:        0 (0.00%)
  Out-of-order: 0
```

## Troubleshooting

1. **No response from server**: Check firewall (`sudo ufw allow 5001/udp`)
2. **High packet loss**: Reduce bandwidth (`-b 10M` instead of `-b 100M`)
3. **Permission denied**: `chmod +x udp_iperf_test`
4. **Cross-compile fails**: `sudo apt install gcc-arm-linux-gnueabihf`

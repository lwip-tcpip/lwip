# Partial ACK recovery experiment

Run `python3 test/partial_ack/run.py` from the repository root with Python 3
and a C compiler supporting UBSan. Set `CC` to select a compiler. The runner
compiles the real IPv4 TCP core serially with the option disabled and enabled;
it needs no network access, device, or third-party Python packages.

To reproduce existing behavior against an unmodified checkout:

```sh
python3 test/partial_ack/run.py --baseline-only --source /path/to/lwip/src
```

The harness creates an established PCB, sends six segments, and injects valid
IPv4/TCP ACK packets through `ip4_input()`. It checks partial ACKs after fast
retransmit, including sequence wrap. With the option disabled the final gap
requires an RTO; with it enabled successive partial ACKs schedule the next
unacknowledged segment without advancing the timer.

Additional checks cover normal ACKs, duplicate ACKs below the fast-retransmit
threshold, output failure, a referenced pbuf that prevents retransmission,
RTO abandoning fast recovery, the first versus subsequent partial ACK timer
behavior, and new data sent after the recovery boundary was recorded.

This is a deterministic sender-state test. The injected ACK sequence is not a
full receiver/network simulation and makes no claim about RF performance or
end-to-end loss rates. It is separate from the Check-based unit suite, which
has not been run for this experiment.

`LWIP_TCP_PARTIAL_ACK_RECOVERY` defaults to zero. The candidate preserves the
entry sequence boundary, deflates the window on partial ACKs, retransmits the
next outstanding segment, and resets the timer only on the first partial ACK.
It is not a complete RFC 6582 NewReno implementation. Recovery re-entry after
timeouts, full-ACK window handling, congestion-window behavior across varied
flight sizes, IPv6, window scaling, and integration into the existing TCP unit
suite need review before enabling or proposing this as a complete algorithm.

# Performance log

This file records reproducible `easytier-go` data-plane optimizations.
Each round must describe the change, the benchmark conditions, the before and
after result, and any profile evidence used to choose the next change.

## Benchmark setup

- Host CPU: Intel Core i7-14700KF.
- Go host CPUs: P-core logical CPUs `8,10,12,14`.
- Native peer and iperf CPUs: P-core logical CPUs `0,2,4,6`.
- Underlay: UDP over the local Docker bridge.
- Native peer: `10.15.15.1`, listening on underlay UDP port `12012`.
- Go host: `10.15.15.2`, forwarding local port `5202` through
  `Instance.Dial` to `10.15.15.1:5201`.
- Go forwarder: `go run ./cmd/dial-forward-bench`; it intentionally keeps
  forwarding outside the Core so measurements include the public data-plane
  ABI.
- MTU: 1380; encryption enabled with the default algorithm.
- TCP tests use one stream unless noted otherwise.
- UDP tests use 1200-byte datagrams.
- Reported results exclude the first two seconds of each iperf run.

The native comparison uses EasyTier's built-in port forward on the same
machine, CPU groups, peer, network, and iperf server. It isolates the overhead
of the Go/WASM data-plane interface from EasyTier's virtual TCP/UDP stack and
transport.

## Round 0: Dial baseline

Go host commit: `a73f2bac`

EasyTier commit: `30764897`

### Throughput

| Path | Direction | Offered load | Result |
| --- | --- | ---: | ---: |
| Go `DialTCP` | Go to native | unlimited | 14.0 Mbit/s |
| Go `DialTCP` | native to Go | unlimited | 1.56 Gbit/s |
| Go `DialTCP`, 4 streams | Go to native | unlimited | 56.6 Mbit/s |
| Native TCP port forward | forward | unlimited | 1.35 Gbit/s |
| Native TCP port forward | reverse | unlimited | 3.65 Gbit/s |
| Go `DialUDP` | Go to native | 10 Mbit/s | 10.0 Mbit/s, 0% loss |
| Go `DialUDP` | Go to native | 100 Mbit/s | tail stalled after 4 seconds |
| Go `DialUDP` | native to Go | 100 Mbit/s | 61.6 Mbit/s, 38% loss |
| Go `DialUDP` | native to Go | 1 Gbit/s | 86.5 Mbit/s, 91% loss |
| Native UDP port forward | forward | 1 Gbit/s | 999 Mbit/s |

At a 100 Mbit/s forward UDP load, the receiver averaged 40.9 Mbit/s over the
full test because traffic stopped after four measured seconds. This is not a
stable throughput result.

### TCP forward profile

`perf stat` attached to the Go host during a 10-second single-stream test:

| Counter | Value |
| --- | ---: |
| elapsed time | 12.014 s |
| task clock | 1.186 s |
| context switches | 89,072 |
| CPU migrations | 12,015 |
| core cycles | 5.98 billion |
| core instructions | 4.09 billion |
| core cache misses | 23.0 million |

The Go process consumed only 0.099 CPU equivalents while forwarding at
14 Mbit/s. Four TCP streams scaled almost exactly linearly, showing a
per-stream serialization limit rather than CPU or transport saturation.

The Go `streamConn.Write` waits for every guest TCP-write operation. The guest
operation currently calls `AsyncWriteExt::write`, which may complete after a
partial write. Each partial result therefore incurs another complete
submit/drive/complete/take host-to-WASM cycle. The native port-forward result
shows that EasyTier's underlying data plane is not the limiting component.

## Round 1: finish each guest TCP write

Go host commit: `a73f2bac`

EasyTier commit: `73612470`

The guest TCP operation now uses `write_all` semantics instead of completing
after the first partial virtual-socket write.

| Path | Before | After | Change |
| --- | ---: | ---: | ---: |
| TCP forward | 14.0 Mbit/s | 15.9 Mbit/s | +13.6% |

This removed redundant operation completion cycles, but CPU utilization
remained low. The result showed that partial completion was real overhead but
was not the main serialization point.

## Round 2: repoll immediately when smoltcp has ready egress

EasyTier commit: `824e01a3`

The smoltcp reactor reported a zero poll delay when more egress was ready, but
the portable runtime crossed the host timer boundary before polling again.
The reactor now polls again in the same drive turn for a zero delay.

| Path | Before | After | Change |
| --- | ---: | ---: | ---: |
| TCP forward | 15.9 Mbit/s | 1.17 Gbit/s | 73.6x |
| Median packet gap | 891 us | 8.41 us | -99.1% |

The packet-gap distribution was captured in
`/tmp/easytier-dial-forward-immediate-repoll.pcap`. Extending every WASI drive
turn by a fixed 50 us did not improve throughput and was later reverted; the
zero-delay signal was the correct condition for immediate work.

## Round 3: preserve pending UDP operations

Go host commit: `cf53f92`

The example refreshed `SetDeadline` before every datagram. Each refresh
cancelled the currently pending read operation, causing forwarding to stall
under sustained load. Deadline refreshes are now limited to half of the idle
timeout, retaining idle-session cleanup without repeatedly cancelling active
operations.

| UDP forward offered load | Before | After |
| --- | ---: | ---: |
| 300 Mbit/s | 45.3 Mbit/s average, tail stalled | 298 Mbit/s, 0.8% loss |

Logging added while diagnosing this behavior showed successful writes until
the receive operation was cancelled; the stall was not a transport write
failure.

## Round 4: reduce per-datagram host/guest overhead

The following measurements use a 1 Gbit/s offered UDP load. Each row is
measured against the immediately preceding retained state.

| Change | Commit | Before | After | Change |
| --- | --- | ---: | ---: | ---: |
| Reuse operation deadline contexts | `3d7b622` | 525 Mbit/s | 558 Mbit/s | +6.3% |
| Reuse separate UDP address and payload inputs | `f9092c9` | 558 Mbit/s | 587 Mbit/s | +5.2% |
| Reuse data-plane output storage | `f469a34` | 587 Mbit/s | 652 Mbit/s | +11.1% |
| Restore a zero-duration WASI drive budget | `a5ea9b6` | 652 Mbit/s | 672 Mbit/s | +3.1% |
| Cache hot guest function handles | `47f0809` | 672 Mbit/s | 677 Mbit/s | +0.7% |
| Reuse the instance deadline timer | `657022b` | 677 Mbit/s | 677 Mbit/s | neutral |
| Coalesce immediately completed outcomes | `9d1ec76` | 677 Mbit/s | 688 Mbit/s | +1.6% |

The reusable input experiment initially used an interior pointer into one
larger guest allocation. The ABI only accepts allocation base pointers, so
the final implementation keeps the remote address and payload in distinct
reusable allocations.

Restoring the zero-duration drive budget also raised TCP forward throughput
from 1.17 to approximately 1.30 Gbit/s. Reusing the deadline timer was kept
despite neutral throughput because it removes a timer allocation from every
operation without adding synchronization.

The final rebuilt artifact and host measured 693 Mbit/s UDP forward, within
the variation of the 688 Mbit/s retained baseline.

### Profile evidence

The final-stage profile is stored at
`/tmp/easytier-dial-udp-zero-budget.perf.data`. Approximately 49% of samples
were in the WASM JIT and 31% in the Go executable, with the remainder
primarily in the kernel. Before function caching, `NextDeadline` accounted
for 2.25% and Go map hashing for 1.48%. After removing these lookup costs, no
remaining individual host-side helper accounted for enough time to explain
the gap to TCP; guest drive execution and one-operation-per-datagram boundary
crossings dominate.

## Round 5: enlarge data-plane UDP receive queues

EasyTier commit: `1df439d`

The data-plane TCP buffers were already 128 KiB, while UDP inherited the
smoltcp default receive queue of about 8 KiB, enough for only a few 1200-byte
datagrams. The data-plane-only UDP receive buffer is now 128 KiB with 128
packet metadata entries.

| UDP reverse offered load | Before | After |
| --- | ---: | ---: |
| 100 Mbit/s | 61.6 Mbit/s, 38% loss | 100 Mbit/s, 0% loss |
| 300 Mbit/s | not stable | 300 Mbit/s, 0.15% loss |
| 500 Mbit/s | not stable | 495 Mbit/s, 0.95% loss |
| 800 Mbit/s | 558 Mbit/s saturated | about 570 Mbit/s saturated |

Removing the redundant receive-result-size ABI query in `104223c` raised the
800 Mbit/s saturated result from 558 to 563 Mbit/s. Subsequent retained
changes brought it to about 570 Mbit/s.

## Rejected experiments

Rejected changes were reverted and are not part of the final data path.

| Experiment | Before | After | Reason rejected |
| --- | ---: | ---: | --- |
| Fixed 50 us WASI drive budget | 1.17 Gbit/s TCP | no gain | Added unconditional work instead of following readiness |
| Pool queued UDP payloads | 652 Mbit/s | 651 Mbit/s | `sync.Pool` overhead offset allocation savings |
| Lock guest driver to one OS thread | 652 Mbit/s | 436 Mbit/s | Prevented the Go scheduler from placing other work effectively |
| Return tickets before the first drive | 677 Mbit/s | 564 Mbit/s | Added an extra wakeup to the normal completion path |
| Pool one-shot response channels | 688 Mbit/s | 654 Mbit/s | Pool bookkeeping cost more than direct allocation |

Pinning the complete process to one P-core produced 680 Mbit/s on the earlier
652 Mbit/s build, showing that CPU migration and core selection affect the
result. Thread pinning inside the library was nevertheless rejected because
it regressed throughput and imposed scheduling policy on applications.

## Round 6: preserve TCP write progress across cancellation

EasyTier commits: `6b55489`, `4d270f3`

`write_all` kept the TCP fast path inside the guest, but it could lose the
already-written prefix when a deadline update cancelled the future. The host
would then replay the complete chunk. The replacement still completes writes
inside the guest, but uses cancellation-safe underlying writes and reports a
completed prefix before observing cancellation or deadline expiry.

WebClient retry, feature timeout, heartbeat, and UDP port-mapping renewal
timers now use the tracked portable time abstraction. This lets an externally
driven host advertise and advance their deadlines without adding a periodic
timer-driving fallback.

| CPU | Direction | Before | After | Change |
| --- | --- | ---: | ---: | ---: |
| i7-14700KF | TCP forward | 1.30 Gbit/s | 1.31 Gbit/s | within variation |
| i7-14700KF | TCP reverse | 1.60 Gbit/s | 1.61 Gbit/s | within variation |
| Intel N100 | TCP forward | 442 Mbit/s | 436 Mbit/s | -1.4% |
| Intel N100 | TCP reverse | 524 Mbit/s | 517 Mbit/s | -1.3% |

The N100 results varied by more than these deltas between one-second
intervals, so the change has no measurable systematic throughput cost.

## Round 7: store deadlines on guest resources

EasyTier commits: `05ba813`, `66252ed`

Go host commits: `200f32c`, `59d6e5a`

The ABI previously passed a remaining timeout with every TCP and UDP data
operation. Once a Go caller configured a connection deadline, the WASI guest
therefore registered a new timer for every read and write. Deadline changes
also required the Go host to cancel and resubmit an active operation.

Data-plane ABI v3 stores independent read and write deadlines on each TCP or
UDP resource. Hosts update them through one resource setter, while data
operations reuse the active expiration signal without creating timers.
Connect, bind, and accept retain their per-operation timeouts.

The dedicated A/B benchmark compared the pre-change `fd1be5c` Go host with
the updated host. The helper connected directly to the native peer through
`udp://172.17.0.3:12012`, set a one-hour deadline once when requested, and
excluded the first two seconds. It used the CPU groups described above.

| TCP forward | Before | After | Change |
| --- | ---: | ---: | ---: |
| No deadline | 1.30 Gbit/s | 1.30 Gbit/s | neutral |
| One-hour deadline | 1.29 Gbit/s | 1.32 Gbit/s | within variation |

An earlier run reported approximately 750 Mbit/s, but its helper used a
loopback peer URI across different network namespaces while the machine was
also under compiler load. Those TCP and UDP figures were discarded because
the traffic path was not controlled. The direct A/B result shows that
resource deadlines retain the established TCP throughput and remove the
per-operation timer construction without a measurable deadline penalty.

## Round 8: batch host TCP underlay writes

EasyTier commit: `cf26d50`

Go host commits: `8d010e0`, `4197f0d`

The TUN example connected directly to the long-running native peer through
`tcp://172.17.0.2:11010`. The overlay addresses were `10.12.12.2` and
`10.12.12.1`. Tests used one iperf TCP stream for 15 seconds and excluded
the first two seconds. The application and native peer remained unpinned to
match the reported command; the iperf client used CPUs `0,2,4,6`.

The TCP host imports still used wazero's reflection-based `WithFunc` path.
Changing the four stream read and write imports to typed module functions
removed reflection and signature decoding from every host operation.

EasyTier's `FramedWriter` already queues up to 64 frames and exposes them as
vectored slices. `HostTcpStream` did not advertise vectored-write support, so
`poll_write_buf` submitted only the first roughly 1.4 KB frame. Each VPN
packet therefore required a separate asynchronous host operation and guest
wakeup. `HostTcpStream` now combines the queued slices and submits the batch
through the existing ordered write operation. The ABI and concurrency model
are unchanged.

| Underlay and implementation | Forward throughput | Go host CPU |
| --- | ---: | ---: |
| TCP, baseline | 302-305 Mbit/s | about 1.44 cores |
| TCP, typed host imports | 394 Mbit/s | about 1.58 cores |
| TCP, typed imports and vectored writes | 1.88-1.93 Gbit/s | about 2.12 cores |
| UDP reference | 914-924 Mbit/s | about 2.01 cores |

With probes attached, baseline TCP issued about 25,000 host writes and
36,000 guest drive calls per second while forwarding at 234 Mbit/s. The
vectored build issued about 6,800 host writes and 14,000 drive calls per
second while forwarding at 1.85 Gbit/s. Average payload per host write grew
from approximately 1.2 KB to 34 KB.

TCP reverse throughput reached 969 Mbit/s, compared with 1.05 Gbit/s over
the UDP underlay in the same unpinned setup. The remaining reverse difference
was 7.7%, rather than the original threefold forward gap.

## Round 9: batch host TCP underlay reads

EasyTier commit: `398b699`

The forward write batching left the opposite direction asymmetric.
`FramedReader` normally supplied only 2-4 KiB of spare capacity, so each host
TCP read transferred at most a few frames before completing the Go operation,
copying into guest memory, and waking the guest executor.

`HostTcpStream` now requests a bounded 64 KiB read even when its caller
provides a smaller buffer. It returns the requested prefix immediately and
retains the remainder in its existing read buffer. The stream still permits
only one pending host read, so the ABI and concurrency model are unchanged
and read-ahead remains bounded per active TCP stream.

The direct A/B used the Round 8 topology and CPU placement. System variation
put the old artifact at 850 Mbit/s reverse and 1.79 Gbit/s forward during this
comparison.

| Artifact and direction | Throughput | Go host CPU |
| --- | ---: | ---: |
| Old artifact, reverse | 850 Mbit/s | not sampled |
| 64 KiB read-ahead, reverse, first run | 1.80 Gbit/s | about 2 cores |
| 64 KiB read-ahead, reverse, repeat | 1.84 Gbit/s | about 2 cores |
| 64 KiB read-ahead, reverse, 60 seconds | 1.90 Gbit/s | not sampled |
| Old artifact, forward | 1.79 Gbit/s | not sampled |
| 64 KiB read-ahead, forward | 1.75-1.76 Gbit/s | not sampled |

The repeat reverse run improved by 116%, and the 60-second run showed no
tail stall. Forward changed by about 2%, within the observed run-to-run
variation. Reverse and forward are therefore symmetric under the same test
conditions without enlarging the public ABI or adding concurrent reads.

## Intel N100 comparison

The N100 has four physical E-cores with no SMT. The Go host was pinned to
CPUs `0-2`, while iperf used CPU `3`. The native EasyTier peer and iperf
server remained on the i7-14700KF host.

Raw TCP between the machines reached 2.30 Gbit/s forward and 2.35 Gbit/s
reverse, excluding the network as the limiting component.

| Path | Direction/load | Result |
| --- | --- | ---: |
| Go `DialTCP` | Go to native | 436 Mbit/s |
| Go `DialTCP` | native to Go | 517 Mbit/s |
| Go `DialUDP` | forward, 1 Gbit/s offered | 134 Mbit/s, saturated |
| Go `DialUDP` | reverse, 300 Mbit/s offered | 120 Mbit/s, saturated |
| Go `DialUDP` | forward, 100 Mbit/s offered | 99.3 Mbit/s, 0.79% loss |
| Go `DialUDP` | reverse, 100 Mbit/s offered | 99.7 Mbit/s, 0.33% loss |

At saturation the Go host used approximately 1.24-1.41 CPU equivalents.
UDP loses proportionally more performance than TCP on the weaker cores,
consistent with the one-operation-per-datagram ABI and scheduling cost.

## Final result

Final Go host commit under test: `47949b5`

Embedded EasyTier commit: `4d270f3`

| Path | Direction | Offered load | Final result |
| --- | --- | ---: | ---: |
| Go `DialTCP` | Go to native | unlimited | 1.31 Gbit/s |
| Go `DialTCP` | native to Go | unlimited | 1.61 Gbit/s |
| Go `DialUDP` | Go to native | 1 Gbit/s | 684 Mbit/s |
| Go `DialUDP` | native to Go | 500 Mbit/s | 494 Mbit/s, 1.2% loss |
| Go `DialUDP` | native to Go | 800 Mbit/s | 578 Mbit/s, 28% loss |

Final TCP and UDP runs lasted 15 seconds after a three-second warm-up. The
UDP API remains one operation per datagram. A batch API was deliberately not
introduced because it would add a new public operation model and buffering
policy for a path whose current performance is acceptable.

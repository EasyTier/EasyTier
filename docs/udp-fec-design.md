# Basic sliding-window UDP FEC

UDP FEC is optional, connection-local erasure recovery. Enable it with
`--enable-udp-fec` on the CLI, or in TOML:

```toml
[flags]
enable_udp_fec = true
```

FEC is disabled by default and does not guarantee higher TCP throughput.
Saturating a link can cause its queues to drop sources and repairs together,
leaving too little repair information to recover the missing data. The recorded
low-loss comparison against the earlier FEC implementation includes throughput
regressions and still fails its original acceptance threshold. This is a known
limitation of the initial opt-in feature; see the PR's recorded measurements.

Every supporting UDP endpoint advertises `udp-fec-v1` in the existing
handshake. Enabling the flag also advertises `udp-fec-enabled`, requesting FEC
in both directions. One endpoint's request is sufficient when both endpoints
support FEC. Two endpoints without a request, an endpoint without FEC support,
and other transports use the ordinary packet path. Changes to the flags apply
to newly created connections.

KCP and QUIC proxy traffic is excluded by default. Use `--enable-udp-fec-kcp`
or `--enable-udp-fec-quic`, or the corresponding `enable_udp_fec_kcp` and
`enable_udp_fec_quic` TOML flags, to include each class. On an active FEC
connection, either endpoint's explicit request includes that class in both
directions. These flags do not activate FEC unless at least one endpoint also
enables `enable_udp_fec`.

## Ownership and data flow

The `peers/conn/fec` Module owns encoding, decoding, duplicate delivery state,
cache deadlines, and its UDP I/O Adapter. The existing connection filters run
before encoding on send and after restoration on receive. Authentication and
encryption behavior is inherited from those filters; this change does not add
a separate FEC security protocol or a new secure-session requirement.

Restored ciphertext retains its original session nonce and still passes through
the session's authentication, replay window and epoch checks. Coding-window
size does not bound the session sequence distance: other connections, control
traffic and packet reordering can advance that distance before recovery.

By default only `Data` packets participate in coding. The optional proxy
classes are identified by the existing `KcpSrc`/`KcpDst` and
`QuicSrc`/`QuicDst` packet types, not by inspecting application traffic.
The complete peer packet participates in coding, including its original
header and any compressed or encrypted payload. Handshake, liveness and other
control packets continue through the existing filters without coding. FEC
does not inspect IP or transport headers, reorder delivery, retransmit packets,
or provide a reliable stream.

The send adapter retains the existing 32-packet input bound and seven-second
send timeout. One writer owns source IDs, the coding window and batch timers.
It completes a source send before counting that source toward the next repair
batch. Sink acceptance does not establish successful host-socket transmission
or delivery. Cache maintenance does not cancel and restart an in-flight send.

## Encoding window and repair scheduling

Original source frames are sent immediately. A batch ends after ten accepted
new sources, or twenty milliseconds after its first accepted source. Later
sources do not extend that deadline. Each nonempty batch generates
`ceil(new_sources / 5)` repairs in total. The writer emits one repair after
each five accepted sources, without waiting for the batch to fill. At the
deadline it sends only the remaining rounded-up tail allowance, subtracting
repairs already sent. Early repairs do not restart the batch deadline.
Sink backpressure can delay both sources and repairs.

The batch counter and coding window are separate. Repairs cover the latest
twenty sources, excluding sources accepted at least one hundred milliseconds
ago. Resetting a batch does not discard the coding window. Historical sources
do not earn more repairs, and an idle connection does not repeatedly repair
its old window. If all sources expire before a repair can be generated, that
batch produces no repair. Source or repair sequence exhaustion ends new FEC
encoding on that connection; sequence numbers do not wrap.

The rate is a packet-count rule: a one-source batch produces one repair,
whereas a full ten-source batch produces two. Neither the configured fraction
nor that count is a bound of twenty percent on actual transmitted bytes.
Repairs are padded to the longest symbol in their current window; mixed-size
traffic can therefore cost substantially more bytes.

## Coding and wire format

FEC frames are local to the direct UDP connection. They have their own
framing between the unchanged UDP tunnel header and the original peer packet
or coded symbol, without an additional outer peer header. All FEC integer
fields use little-endian encoding:

| Frame | Contents after the UDP tunnel header |
| --- | --- |
| Ordinary | Complete original peer packet, unchanged |
| Source | `source_id:u64`, `0x40:u8`, complete original peer packet |
| Repair | `first_source_id:u64`, `(0x80 \| source_count):u8`, `reserved_zero:u8`, `repair_id:u32`, coded symbol |

The framing deliberately shares a discriminator position with ordinary peer
packets: byte eight after the UDP tunnel header. For ordinary packets this
byte is the existing peer packet type, whose values must remain below 64.
For FEC frames its high two bits identify a source (`01`) or repair (`10`);
`11` is reserved and invalid. Source frames require the exact value `0x40`.
Repair frames use the low six bits for the source count, bounded to 1 through
20, and require their reserved byte to be zero. Adding an ordinary peer packet
type of 64 or above would violate this shared namespace and requires revisiting
the framing.

This classification is identical while waiting for the handshake and after
activation. Negotiation controls whether an identified FEC frame is queued,
decoded or discarded; it does not change how bytes are interpreted. This
allows a FEC datagram to overtake the last handshake packet, or an ordinary
packet to arrive after activation, without confusing their formats. Ordinary
packets have no additional FEC header, and UDP transport framing is unchanged.

An uncoded symbol is `original_peer_length:u16`, followed by the original peer
packet, with implicit zero padding. The sender generates a nonzero GF(256)
coefficient for each position using the fixed mixing function in `codec.rs`.
The field polynomial is `0x11d`; field arithmetic uses the
`reed-solomon-erasure` library. The codec itself is random linear coding, not
block Reed-Solomon coding. The wire format has no selectable codec or coding
profile. The receiver reconstructs coefficients from the repair ID and source
position. Each repair describes a contiguous span of at most twenty sources.

Recovery depends on equation rank and overlap. Receiving as many repairs as
lost sources does not by itself guarantee recovery. Recovered symbols must
have a valid encoded length, an eligible original peer header, and zero padding.
The original peer header's length retains its existing semantics, which can
differ from the transmitted payload length after encryption or compression.

The source header adds nine bytes to the original peer packet. The repair
header is fourteen bytes; together with the encoded two-byte original length,
a repair can add sixteen bytes relative to the longest original peer packet.
These sizes do not include the unchanged UDP tunnel header or outer IP/UDP
headers.

An endpoint that locally enables FEC reserves sixteen bytes in its configured
TUN MTU, in addition to encryption overhead. The AEAD tail reserves 28 bytes:
a sixteen-byte tag and a twelve-byte nonce. Both TUN configuration and
configuration validation use that wire type's size.

An endpoint activated by its peer does not dynamically reduce its TUN MTU.
Encoding uses the actual input packet length rather than a limit derived from
the local TUN MTU, so full-sized packets from a passive endpoint and forwarded
packets from other nodes remain eligible. All resulting frames must fit the
existing UDP session datagram size limit; inputs that cannot fit continue
through the ordinary path without consuming a source ID.

The UDP session size limit is not the path MTU. Passive or forwarded traffic
can produce outer packets up to sixteen bytes larger than ordinary sending.
The configured TUN MTU must leave enough space for the actual path; this
implementation does not add fragmentation or path MTU discovery.

## Receive lifecycle

An original source is delivered immediately after unwrapping. Repair equations
are reduced incrementally; a recoverable source goes through the same delivery
deduplication as an original. A later original cannot cause a second delivery
of an already recovered source.

Each connection retains at most 128 source slots and 64 equations. Decoder
evidence expires after 200ms from its first observation, including unknown
sources identified by a repair. Combining equations cannot extend the oldest
evidence's lifetime. Expiring or reusing an unknown source slot drops every
equation still depending on it; deleting just its coefficient would change the
equation. Duplicate delivery state independently covers 1024 source IDs. IDs
older than that delivery window are rejected even after decoder data expires.

Payload allocation is lazy and bounded by the source/equation counts and the
UDP datagram limit, not by a new global memory-budget framework. Receive state
expires even when the consumer stops polling. Up to 32 FEC frames may be held
for 200ms while the existing handshake finishes, allowing reordered control
packets to pass. Closing either side of the adapter releases its cached state.

## Observation and validation

Connection information exposes activation, accepted source/repair counts and
bytes, received source/repair counts, recovered packets, duplicate originals,
and invalid frame counts. FEC transmit byte counters include the complete FEC
frame but exclude the UDP tunnel header and outer IP/UDP headers. Existing
connection throughput counters retain their filter-layer accounting.
The recovered count is recorded before the restored packet passes the
connection filters; it does not establish authenticated application delivery.

The instance stats registry also records FEC events under `network_name`:

- `udp_fec_source_packets_tx` and `udp_fec_source_bytes_tx`
- `udp_fec_repair_packets_tx` and `udp_fec_repair_bytes_tx`
- `udp_fec_source_packets_rx` and `udp_fec_source_bytes_rx`
- `udp_fec_repair_packets_rx` and `udp_fec_repair_bytes_rx`
- `udp_fec_packets_recovered`

These counters are returned by the existing stats RPC, `easytier-cli stats`
and `easytier-cli stats prometheus`. They accumulate events across connections
in the same network rather than summing live connection snapshots. Disconnecting
a connection does not subtract its counts. They follow the stats registry's
existing lifecycle: a series with no remaining counter handles can expire
after more than three inactive one-minute cleanup epochs, and recreating an
expired series starts it at zero.

Transmit events require successful tunnel sink acceptance, which does not prove
host-socket transmission or remote delivery. Receive events count syntactically
valid frames processed by an active decoder, including duplicate originals and
repairs. Frames buffered during negotiation are counted only when processed.
Receive bytes use the same complete-frame boundary as transmit bytes. Recovered
packets are counted once before connection filtering, without adding synthetic
source receive events or bytes. These metrics do not change existing traffic or
connection throughput accounting.

Tests cover coding rank and overlap, variable lengths, source arrival during
elimination, duplicate delivery, deadlines, expiration, bounded storage,
handshake activation, existing session filters, and loss recovery over real
UDP sockets. The offline comparison uses an independent block RS reference
with the same input and full-batch repair count. The sliding encoder can send
repairs before the block is complete, so their repair times differ.
It reports timing, recovery,
packet and byte cost, and cache observations separately. Its simulated byte
accounting is not a packet capture, and elapsed coding time is not process CPU
time. It does not establish overall application performance or product-wide
acceptance.

This first implementation has no receiver feedback, network-dependent rate
control, congestion actions, application classification, packing, or pacing.

The component comparison is an explicitly invoked test, not part of the
ordinary correctness suite. From the repository root, run it with:

```sh
FEC_BENCH_OUTPUT=/tmp/fec-comparison.json cargo test -p easytier-core \
  compare_block_and_sliding_recovery --lib -- --ignored
```

Keep the compiler/profile and the JSON contract with the result. The cases
include continuous equal-size packets, sparse packets, alternating sizes,
alternating large/small batches, and burst loss, each with three fixed seeds.
The two mixed-size cases distinguish padding within one batch from padding
caused by carrying a large symbol into the following small-packet batch.

### Throughput variance diagnosis, 2026-10-29

The compact early-repair candidate at source commit `118fa46c` was measured
on a dedicated host using a frozen release binary. The diagnostic kept a
100Mbps bottleneck in each direction, a 128-packet rate queue, 1% random path
loss, 160ms RTT, TUN MTU 1300, one CUBIC TCP stream and seed 97. Formal goodput
excludes the first three seconds of a 63-second workload.

A bounded pre-rate packet probe and the existing post-rate captures located
all 2768 forward rate-queue drops at a reconstructed queue occupancy of
exactly 128 FEC packets. The largest 5ms arrival window contained 538 packets
(1208.7Mbps), and one lost run contained 59 consecutive sources arriving
within 643.7 microseconds. Concentrated losses coincided with TCP
retransmissions and congestion-window reductions. Earlier captures also
showed that the received repair equations could not recover some long gaps,
even assuming known outside symbols and independent equations.

Two diagnostic controls changed only the test TCP socket's pacing cap to
60Mbps. The product binary, FEC policy, bottleneck, queues, loss, RTT, seed
and instrumentation remained unchanged; TUN retained its original qdisc.

| Workload | Formal goodput, Mbps | Forward rate-queue drops | TCP retransmissions |
| --- | ---: | ---: | ---: |
| Original, instrumented | 45.003439 | 2768 | 1532 |
| Test TCP paced to 60Mbps | 59.999993 | 0 | 1 |
| Identical paced control repeated | 59.999874 | 0 | 1 |

Drops and retransmissions cover the complete workload. Probe packet/byte
counts matched existing traffic counters, with no probe overflow, capture
loss, compilation interference or thermal throttling. The paced controls
carried more average offered wire traffic while reducing short arrival
bursts. Equal random seeds do not freeze application packet order, arrival
times or load-dependent queue loss.

This establishes a burst/queue-loss/TCP-recovery amplification path. It does
not establish which upstream ACK or scheduling event first separates two
runs, whether the tunnel amplifies input bursts, or the best production
pacing rate. The cap changes the workload and cannot rank maximum throughput.
The original compact A/B performance acceptance remains failed; these
controls neither replace failed samples nor justify a fixed product cap,
more redundancy, a larger queue or a repair-trigger rollback.

The local evidence bundle is
`.test-env/fec-v1-pr/variance-diagnosis/`, including `diagnosis.md`,
`causal-comparison.json`, frozen inputs, raw captures and cleanup records.
It is an ignored experiment artifact, not a distributed repository fixture.

### Subsequent performance comparisons

Keep erasure recovery and congestion behavior as separate measurements:

- For recovery, replay controlled input timing, sizes and loss patterns.
  Verify that offered load, including repair and framing bytes, leaves
  bottleneck headroom. Unexpected queue losses invalidate attribution to
  random erasure alone; retain and report those samples. Measure residual
  loss, delivery deadlines, recovery delay, wire cost, CPU and memory.
- For congestion, preserve the uncapped TCP case and its 128-packet queue.
  Compare FEC off, the baseline and the candidate with equal actual MTU,
  network and build settings. Repeat the same binary first to estimate
  variability; interleave subsequent version pairs in both orders and report
  every sample, paired differences and uncertainty. Predeclare repetitions
  and stopping rules; do not retry until a favorable result appears.
- Retain the capped workload as a diagnostic control, not a throughput
  acceptance substitute. Report both equal application-load comparisons
  and comparisons under the same total wire budget where relevant.
- Separate configured path loss, queue loss and residual application loss.
  Record queue occupancy/delay, TCP retransmissions/window/RTT, actual wire
  load and host interference alongside throughput. Use detailed pre-rate
  tracing for diagnosis; freeze observation settings across compared arms.

Before proposing product pacing, align traffic entering the tunnel with its
outer UDP departure timing and compare FEC off/on. This distinguishes inherited
TCP bursts from burst amplification in the tunnel. Pacing and a repair budget
remain separate design decisions: smoothing departures does not by itself
make sustained traffic fit within the available path capacity. No production
scheduler or congestion policy is selected by this diagnostic.

### TUN-to-UDP follow-up, 2026-10-29

The same frozen binary was then observed with FEC disabled and enabled.
Native sender TUN capture is after its root qdisc and before its driver ring;
outer UDP BPF is before the rate queue. This interval includes driver buffering,
reader wakeup and userspace processing, not just FEC coding.
Configured MTUs 1328/1344 produced the same actual MTU 1300. Other network and
workload settings were unchanged, with no TCP pacing cap.

Input and output packet counts, IP-equivalent bytes and length histograms
matched exactly: 5628 packets OFF and 315243 ON. All captures and probes passed
loss/overflow checks. In the ON trial, the largest 5ms input window contained
993 packets, while the largest 5ms source-output window contained 440 packets.
Including 88 repairs gives 528 outer packets. The largest burst was already
present at TUN and was spread over a longer interval by the subsequent path.

Short-window concentration is still possible: in the first overflow context,
the local 5ms input/output peaks were 104/112 sources; OFF also showed 52/55
packets at 1ms. This does not establish a sender FEC batching defect. The first
overflow context and the later 993-packet input burst had no repeated TCP
payload sequence ranges, so they were not mislabeled retransmission bursts.
The ON trial's 1678 source and 411 repair losses matched 2089 rate-qdisc drops.

This evidence does not justify changing the coding window or early repair
trigger. It also does not rule out an effect of receiver recovery or ACK timing
on upstream TCP bursts; the complete feedback loop was not isolated.
The OFF/ON throughputs, 0.78778/51.03079Mbps, are one diagnostic pair with
different TCP input trajectories, not a repeatable speedup estimate or an
old-FEC/new-FEC acceptance result. Product code and the failed A/B gate remain
unchanged. Raw evidence and the decision are in the ignored local bundle
`.test-env/fec-v1-pr/burst-origin/diagnosis.md`.

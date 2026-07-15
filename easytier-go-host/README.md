# EasyTier Go Host

`easytier-go-host` embeds the `wasm32-wasip1` build of `easytier-core` in a
pure-Go process through wazero. It is the reusable host integration module;
the capability probes and standalone Rust guest remain under
[`tools/wasi-socket-poc`](../tools/wasi-socket-poc/README.md).

```go
import corehost "github.com/easytier/easytier/easytier-go-host"
```

The host supplies normalized configuration plus implementations of
`SocketFactory`, `DNSResolver`, `ConnectorEnvironment`, and packet ingress or
egress. `Bridge` owns Go resources and host imports. `CoreModule` serializes all
calls into one wazero module, and `CoreInstance` exposes create, start, bounded
drive, stop, and drop.

The normalized create payload currently uses schema version 12. Peer runtime
state, legacy flag semantics, and the defaults inherited by foreign-network
contexts are submitted explicitly, while the connectivity snapshot carries the
UDP, TCP, and IPv6 UDP STUN server lists. Public-IPv6 auto/provider policy is
core configuration; the host environment does not submit a managed-address
mirror.
`ConnectorEnvironment.LocalAddrForRemote` receives both the remote UDP address
and the complete `SocketContext`, allowing the host to apply the same netns,
socket-mark, and IP-family policy as the subsequent socket request. Core builds
the STUN collector from that configuration plus the injected socket and DNS
Adapters. STUN state, NAT inference, and port mapping are not Go host APIs.
Listener configuration is submitted as URLs, IPv6 policy, and `SocketContext`.
Core derives Ring identity and the internal TCP/UDP listener plan; Go supplies
only real listener creation and accept operations through `SocketFactory`.

```go
bridge := corehost.NewBridge(corehost.BridgeConfig{
    SocketFactory:        socketFactory,
    DNSResolver:          dnsResolver,
    ConnectorEnvironment: environment,
})
defer bridge.Close()

binding, err := bridge.BindCoreHost(ctx, runtime)
if err != nil {
    return err
}
packetSink, err := bridge.RegisterPacketSink(16)
if err != nil {
    return err
}
moduleOwner, err := corehost.InstantiateCoreModule(
    ctx,
    binding,
    compiledModule,
    wazero.NewModuleConfig().WithStartFunctions("_initialize"),
)
if err != nil {
    return err
}
core, err := moduleOwner.CreateInstance(ctx, normalizedConfig, packetSink)
if err != nil {
    return err
}
if err := core.Start(ctx); err != nil {
    return err
}
if err := core.DriveUntil(ctx, corehost.CoreStateRunning); err != nil {
    return err
}
```

`SocketFactory` controls only TCP connect, UDP bind, and TCP listen creation.
After it returns standard Go `net` resources, core/Tokio decides when read,
write, receive, send, and accept operations are polled. The Go bridge does not
own EasyTier framing, retries, routing, peer admission, or protocol state.

`InstantiateCoreModule` binds exactly one wazero module to its `Bridge`, creating
a unique serialization and completion ownership domain. During normal
shutdown, stop and drop every `CoreInstance` before closing the runtime and `Bridge`.
`Bridge.Close` rejects new work, releases host resources, waits for in-flight
workers, and is safe to call concurrently.

Run the conformance and integration tests with:

```sh
go test -count=1 ./...
```

The tests build the real release `easytier_core.wasm`, exercise lifecycle and
host adapters, and form a two-instance raw-TCP EasyTier network that exchanges
an IPv4 packet.

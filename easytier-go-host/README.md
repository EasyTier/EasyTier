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

```go
bridge := corehost.NewBridge(corehost.BridgeConfig{
    SocketFactory:        socketFactory,
    DNSResolver:          dnsResolver,
    ConnectorEnvironment: environment,
})
defer bridge.Close()

if err := bridge.InstantiateHost(ctx, runtime); err != nil {
    return err
}
packetSink, err := bridge.RegisterPacketSink(16)
if err != nil {
    return err
}
moduleOwner := corehost.NewCoreModule(module)
core, err := moduleOwner.CreateInstance(ctx, normalizedConfig, packetSink)
if err != nil {
    return err
}
if err := core.Start(ctx); err != nil {
    return err
}
if err := core.DriveUntil(ctx, bridge.Completion(), corehost.CoreStateRunning); err != nil {
    return err
}
```

`SocketFactory` controls only TCP connect, UDP bind, and TCP listen creation.
After it returns standard Go `net` resources, core/Tokio decides when read,
write, receive, send, and accept operations are polled. The Go bridge does not
own EasyTier framing, retries, routing, peer admission, or protocol state.

All calls into one wazero module must use the same `CoreModule`. During normal
shutdown, stop and drop every `CoreInstance` before closing the module and
`Bridge`. `Bridge.Close` rejects new work, releases host resources, waits for
in-flight workers, and is safe to call concurrently.

Run the conformance and integration tests with:

```sh
go test -count=1 ./...
```

The tests build the real release `easytier_core.wasm`, exercise lifecycle and
host adapters, and form a two-instance raw-TCP EasyTier network that exchanges
an IPv4 packet.

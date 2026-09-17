# EasyTier JavaScript

The EasyTier JavaScript packages run the same EasyTier WASM core across web
runtimes while keeping application-facing APIs small:

- [`@easytier/browser`](./browser) provides a browser TCP client.
- [`@easytier/cloudflare`](./cloudflare) provides a Cloudflare Durable Object
  relay.
- [`@easytier/runtime`](./runtime) contains their shared runtime and adapter
  implementation. Most applications should use one of the two public host
  packages instead of depending on it directly.

A complete browser and Cloudflare Worker walkthrough is available in
[`examples/web`](./examples/web).

Source builds require Node.js 22, pnpm 10 or newer, Rust 1.95 with the
`wasm32-wasip1` target, and Protocol Buffers 35.1. Install the Rust target with:

```sh
rustup target add wasm32-wasip1
```

The JavaScript hosts use their own workspace so their Cloudflare development
toolchain does not affect EasyTier's existing GUI and web workspace. From a
clean repository checkout, run:

```sh
cd easytier-js
pnpm install
pnpm check
```

The check command builds both Wasm profiles from source, builds and tests the
three packages, and validates the complete example. No pre-generated Wasm file
is required. Published packages already contain their compiled JavaScript,
type declarations, and Wasm artifacts; package consumers do not need Rust.

# `@easytier/runtime`

Shared WebAssembly runtime used by the official EasyTier Browser and
Cloudflare Adapters. Application code should normally install
`@easytier/browser` or `@easytier/cloudflare` instead.

The package root contains only cross-platform EasyTier types. The
`@easytier/runtime/adapter` entry is intended for platform Adapter authors and
hides Guest memory, ABI handles, Host capability operations, and the operation
broker from application-facing Interfaces.

The runtime, Browser Adapter, and Cloudflare Adapter use the same version.
Release automation must publish `@easytier/runtime` first, followed by
`@easytier/browser` and `@easytier/cloudflare`. Platform package manifests use
an exact workspace version, which `pnpm pack` rewrites to an exact registry
dependency. Consumers never run Cargo or an npm install hook.

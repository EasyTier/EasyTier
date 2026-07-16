# EasyTier Core Refactor Documents

> Status: authoritative index. Updated 2026-07-16.

This directory records the plan for moving portable EasyTier behaviour into the
single `easytier-core` crate. When documents disagree, use the following order:

1. [`CONTEXT.md`](../CONTEXT.md) defines domain language and ownership.
2. Accepted records in [`docs/adr`](../docs/adr) define architectural decisions.
3. [`core_instance_construction.md`](core_instance_construction.md) records the
   final public construction Interface and composition boundary.
4. [`core_native_closeout.md`](core_native_closeout.md) is the authoritative
   completed ownership-closeout record.
5. [`core_refactor_roadmap.md`](core_refactor_roadmap.md) defines the overall
   order, scope, and completion gates.
6. Follow-up production hardening uses
   [`go_wasi_host_poc.md`](go_wasi_host_poc.md).
7. Older topic plans are historical input. Their code references and completion
   status may be stale.

## Current documents

| Document | Status | Role |
| --- | --- | --- |
| [`core_instance_construction.md`](core_instance_construction.md) | Complete | Single core construction Interface, Host Adapter input and composition closure |
| [`core_native_closeout.md`](core_native_closeout.md) | Complete | Final semantic ownership, deletion and verification record |
| [`core_refactor_roadmap.md`](core_refactor_roadmap.md) | Ownership complete; hardening remains | Overall migration order, completed ownership gates and production follow-up |
| [`core_remaining_ownership_refactor.md`](core_remaining_ownership_refactor.md) | Historical milestone | First ownership-migration closure snapshot, superseded by the final closeout |
| [`host_runtime_stun_refactor.md`](host_runtime_stun_refactor.md) | Complete | Process-level host runtime, request context, and core STUN closure record |
| [`tunnel_ownership_refactor.md`](tunnel_ownership_refactor.md) | Complete | TCP/UDP/Ring Tunnel ownership and connector/listener closure record |
| [`go_wasi_host_poc.md`](go_wasi_host_poc.md) | Functional gate passed; hardening active | Selected opaque Model B and remaining quantitative production gates |
| [`core_config_peer_context_refactor.md`](core_config_peer_context_refactor.md) | Partially current | Input to the Core instance phase |
| [`connector_socket_refactor.md`](connector_socket_refactor.md) | Historical | Earlier socket-seam reasoning; its target direction remains useful |
| [`core_peers_refactor.md`](core_peers_refactor.md) | Historical | Peer migration plan, mostly implemented |
| [`udp_hole_punch_core_refactor.md`](udp_hole_punch_core_refactor.md) | Historical | UDP hole-punch migration history |
| [`udp_socket_refactor.md`](udp_socket_refactor.md) | Historical | UDP socket migration history |
| [`mihomo_wasi_core_constraints.md`](../easytier/docs/refactor-dor/mihomo_wasi_core_constraints.md) | Accepted constraints | Third-party and WASI portability constraints |

Historical documents are not implementation checklists. Before using one,
check the current source and fold any still-valid work into a new scoped plan.

## Decision records

- [`0001-portable-logic-belongs-in-one-core-crate.md`](../docs/adr/0001-portable-logic-belongs-in-one-core-crate.md)
- [`0002-go-host-drives-wasi-core-with-tokio.md`](../docs/adr/0002-go-host-drives-wasi-core-with-tokio.md)
- [`0003-host-os-policy-is-runtime-configuration.md`](../docs/adr/0003-host-os-policy-is-runtime-configuration.md)

# Task 2 Report: NAT-PMP 内部函数泛化

## Status: DONE

## Changes Made

### `easytier/src/common/upnp.rs`

**Step 1 — `request_nat_pmp_mapping` 签名泛化 (line 650)**
- Added `protocol: NatPmpProtocol` parameter
- Replaced hardcoded `NatPmpProtocol::UDP` with `protocol`
- Updated all log messages from "udp" to `{:?}` format for protocol

**Step 2 — New `add_mapping_port_nat_pmp` function (line 594)**
- Accepts `protocol: PortMappingProtocol` parameter
- Maps `PortMappingProtocol` → `NatPmpProtocol`
- TCP: enforces same-port mapping (external = local)
- UDP: any-port first, falls back to same-port

**Step 3 — `add_udp_mapping_port_nat_pmp` delegator (line 642)**
- Delegates to `add_mapping_port_nat_pmp(..., PortMappingProtocol::UDP)`
- No public signature change

**Step 4 — New `renew_mapping_nat_pmp` (line 694) and `remove_mapping_nat_pmp` (line 712)**
- Both accept `protocol: PortMappingProtocol`
- Map to `NatPmpProtocol` and delegate to `request_nat_pmp_mapping`

**Step 5 — `renew_udp_mapping_nat_pmp` (line 730) and `remove_udp_mapping_nat_pmp` (line 739)**
- Both now delegate to generic versions with `PortMappingProtocol::UDP`
- No public signature changes

## Verification

- `cargo clippy --package easytier -- -D warnings`: pre-existing dependency build errors (kcp-sys, prost-wkt-types) unrelated to this change
- Code reviewed manually — all NAT-PMP functions properly generalized
- All existing `*_udp_*` wrapper signatures unchanged (public API preserved)

## Commit

- `5886138` — `refactor(upnp): generalize NAT-PMP mapping functions with protocol parameter`

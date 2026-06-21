# Task 3 Report: 流程函数泛化

## Status: DONE

## Commit
- `66de000` refactor(upnp): generalize flow functions with protocol parameter

## Changes Made

### `easytier/src/common/upnp.rs` (+121/-37)

1. **`ActiveUdpPortMapping` struct** — added `protocol: PortMappingProtocol` field

2. **`ActiveUdpPortMapping` methods:**
   - `establish_via_nat_pmp_with_protocol()` — generic version accepting `protocol` param
   - `establish_via_igd_with_protocol()` — generic version accepting `protocol` param
   - `establish_via_nat_pmp()` / `establish_via_igd()` — now thin wrappers calling `_with_protocol` with `PortMappingProtocol::UDP`
   - `renew()` / `remove()` — updated to use `renew_mapping_*` / `remove_mapping_*` (generalized) with stored `self.protocol`

3. **`_in_netns` functions:**
   - `establish_igd_mapping_in_netns_with_protocol()` — generic version
   - `establish_nat_pmp_mapping_in_netns_with_protocol()` — generic version
   - `establish_igd_mapping_in_netns()` / `establish_nat_pmp_mapping_in_netns()` — now thin wrappers

4. **Flow functions:**
   - `discover_port_mapping(ctx, listener, protocol)` — generic version
   - `discover_udp_port_mapping(ctx, listener)` — thin wrapper
   - `run_port_mapping_task(listener, mapping, stop_rx, protocol)` — generic version
   - `run_udp_port_mapping_task(listener, mapping, stop_rx)` — thin wrapper
   - `try_start_port_mapping(ctx, listener, protocol)` — generic version
   - `try_start_udp_port_mapping(ctx, listener)` — thin wrapper

5. **Bonus fix:** Removed unreachable `_ => bail!(...)` patterns in `add_mapping_port_nat_pmp`, `renew_mapping_nat_pmp`, `remove_mapping_nat_pmp` (leftover from Tasks 1/2, flagged by clippy)

## Test Summary
- `cargo clippy --package easytier -- -D warnings`: 0 errors

## Notes
- `try_start_port_mapping` uses `should_map_udp_listener` as placeholder; Task 4 will replace with `should_map_listener`
- Log messages updated to use `{:?} port mapping` format with protocol parameter

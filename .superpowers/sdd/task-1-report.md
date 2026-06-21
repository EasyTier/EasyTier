# Task 1 Report: IGD 内部函数泛化

## Status: DONE

## Changes Made

File: `easytier/src/common/upnp.rs`

### 新增泛化函数

1. **`add_mapping_port_igd`** (line 540-584) — 接受 `protocol: PortMappingProtocol` 参数
   - UDP 分支: 保持原有逻辑 (先 `add_any_port`，失败回退 `add_port`)
   - TCP 分支: 直接 `add_port`（保证内外端口一致）

2. **`renew_mapping_igd`** (line 747-758) — 接受 `protocol` 参数，使用 `format!("renew {:?} port mapping ...")` 统一错误信息

3. **`remove_mapping_igd`** (line 769-779) — 接受 `protocol` 参数，使用 `format!("remove {:?} port mapping ...")` 统一错误信息

### 原有 UDP 函数改为包装器

- `add_udp_mapping_port_igd` → 调用 `add_mapping_port_igd(..., PortMappingProtocol::UDP)`
- `renew_udp_mapping_igd` → 调用 `renew_mapping_igd(..., PortMappingProtocol::UDP)`
- `remove_udp_mapping_igd` → 调用 `remove_mapping_igd(..., PortMappingProtocol::UDP)`

## Verification

- `cargo clippy --package easytier -- -D warnings`: 0 errors, 2 warnings (VC-LTL/YY-Thunks info)
- 所有原有调用者签名不变，零破坏性更改
- 通过 self-review 确认代码逻辑与 task brief 完全一致

## Commit

- `4a4d558` — refactor(upnp): generalize IGD mapping functions with protocol parameter

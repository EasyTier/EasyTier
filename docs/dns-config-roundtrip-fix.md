# 修复：GUI 编辑网络时丢失 `[dns]` 配置

## 问题
GUI「编辑网络 → 编辑为文件」输入的 `[dns]` / `[[dns.zone]]` 段，保存后再次打开会丢失；
其它段（`[[peer]]`、`[network_identity]` 等）正常。命令行 `easytier-core -c config.toml` 不受影响。

## 根因
GUI 保存配置时经过 `NetworkConfig`（protobuf）做一次往返 `TOML → NetworkConfig → TOML`。
`NetworkConfig` 没有 dns 字段、`launcher.rs` 也不处理 dns，dns 在中间表示里被丢弃。

## 解决
给 `NetworkConfig` 加一个字符串字段 `dns_config_toml`，把 `[dns]` 段序列化为 TOML 文本存进去，
反向再解析写回；其它配置仍走原有结构化字段，不受影响。

改动（2 个文件）：
- `easytier/src/proto/api_manage.proto`：`message NetworkConfig` 新增 `optional string dns_config_toml = 67;`
- `easytier/src/launcher.rs`：
  - `new_from_config()`：把 `[dns]` 段序列化进 `dns_config_toml`
  - `gen_config()`：把 `dns_config_toml` 解析写回配置

dns 代码用 `#[cfg(feature = "magic-dns")]` 门控。`magic-dns` 是 easytier 的默认 feature，
GUI 构建自动带上，GUI 侧（`parse_network_config` / `generate_network_config`）无需改动。

## 验证
- 单元测试 `dns_config_roundtrip`：构造含 `[[dns.zone]]` 的配置走 `new_from_config → gen_config`
  往返，断言 dns zone 不丢。通过。
- Windows 上自编译 GUI（带 `magic-dns`）实测：在「编辑为文件」输入含 `[[dns.zone]]` 的配置，
  保存后重新打开，`[dns]` 段完整保留 —— 确认修复生效。

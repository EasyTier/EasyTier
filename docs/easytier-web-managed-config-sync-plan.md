# EasyTier Web Managed Config Incremental Sync Plan

## Status

- 状态：Implemented（核心协议、持久化与 Session 增量收敛）
- 实施范围：EasyTier Web 的 HTTP 接收、校验、SQLite 持久化和 Session 运行态收敛
- 上游依赖：后续由 Console 计算并发送 Patch
- 兼容要求：保留现有 Full PUT

本文记录当前接收端方案。Session 在能够证明 Patch base 与已应用 revision 连续时
只收敛 touched instances；重启、通知丢失、revision 断链或并发积压时沿用 Full
reconcile。

## 1. 背景与结论

当前 `/validate-token` webhook 已经只交换 token、机器信息和 revision，不再
携带完整 managed config 集合。剩余的大集合位于独立的配置发布路径：

```text
PUT /api/internal/users/:user-id/machines/:machine-id/networks
```

Console 每次发布都会向该路径发送完整 Exact Set。实例很多时，请求体、JSON
解析、现有配置扫描和逐条 SQLite 写入都随实例总数增长。

第一阶段采用以下方案：

1. 保留 PUT，作为完整发布、首次同步和冲突恢复路径。
2. 在同一路径增加 PATCH；普通变更只发送完整的单实例 upsert 和删除 ID。
3. PATCH 使用 `expected_config_revision` 做 compare-and-swap（CAS）。
4. Full/Patch 的配置变更与 revision 更新在一个 SQLite transaction 中提交。
5. Patch 只查询和写入 touched instances，不扫描完整 Target。
6. 写入成功后通知 Session 本次 base、target 和 touched instance IDs。
7. Session 仅在 applied revision 精确匹配 base 时增量收敛，否则安全回退 Full。

普通变更的接收端成本由：

```text
O(total instances)
```

降为：

```text
wire / JSON / persistence transaction / runtime config apply = O(changed instances)
```

冷启动或 revision 冲突仍需要 `O(total)` 的 Full。这是没有可用基线时传递完整
目标状态所必需的成本；如果 Full 超过安全的单请求上限，需另行设计 staged
snapshot，而不是直接分页写入 live rows。

## 2. 目标与非目标

### 2.1 目标

1. 普通新增、更新和删除只传输、解析、查询并写入变化实例。
2. Config rows 与 persisted revision 原子提交。
3. Patch 可安全重试，并能确定性处理并发或乱序请求。
4. 保持 user-owned 与 web-owned 配置的 ownership 规则。
5. 保持 Full Exact Set 的删除和显式空集合语义。
6. 为 Full 和 Patch 设置显式且可测试的容量限制。
7. 先部署接收端，再允许 Console 使用 Patch。

### 2.2 非目标

1. 修改 `/validate-token` request/response。
2. 在本阶段实现 Console 的 diff/cache 逻辑。
3. 优化 Core heartbeat 中的完整运行实例上报。
4. 实现 Full 分页、上传会话或持久化 delivery FSM。
5. 让冷启动 Full 的成本低于 `O(total)`。

## 3. 必须保持的语义

### 3.1 Full Exact Set

Full 表示一个 `(user_id, machine_id)` 下全部期望的 web-owned configs：

- 请求中存在的实例应被创建或更新；
- 已存在但请求中缺失的 web-owned 实例应被删除；
- 空集合应删除该 Target 下全部 web-owned 实例；
- user-owned 实例不能被覆盖或删除。

### 3.2 Patch

Patch 只描述从一个已知 revision 到另一个 revision 的变化：

- `upserts`：新增或变化实例的完整 config；
- `delete_instance_ids`：从目标集合中删除的实例 ID；
- `expected_config_revision`：receiver 必须已经处于的 base revision；
- `config_revision`：提交完成后的 target revision。

Patch 不是独立的完整目标。当前 revision 与 expected revision 不一致时，必须
返回冲突且不做任何写入。

### 3.3 Revision invariants

1. 一个 persisted revision 只对应与其一起提交的 web-owned projection。
2. Config mutation 和 revision advancement 必须位于同一 transaction。
3. Patch 只能应用在完全匹配的 expected revision 上。
4. 当前 revision 已等于 target revision 时，返回幂等成功且不重复写入。
5. Publisher 不得为不同目标状态复用同一个 target revision。
6. 任何其他写路径只要改变 web-owned row，就必须在同一 transaction 中清除
   managed revision；否则未来 Patch 会基于错误的 base。
7. Persisted revision 与 Session applied revision 保持为两个不同事实。HTTP
   成功只代表本地持久化完成，不代表 Core 已经应用。

## 4. HTTP contract

### 4.1 保留 Full PUT

路径不变：

```text
PUT /api/internal/users/:user-id/machines/:machine-id/networks
```

现有 JSON shape 保持兼容：

```json
{
  "managed_network_configs": [
    {
      "instance_id": "11111111-1111-1111-1111-111111111111",
      "network_config": {}
    }
  ],
  "config_revision": "target-revision",
  "expected_config_revision": "base-revision"
}
```

`expected_config_revision` 保持当前含义：

- 字段缺失：兼容旧调用者，不检查 base；
- 空字符串：要求当前 persisted revision 不存在；
- 非空字符串：要求当前 revision 与该值相等。

新 Console 必须发送 expected revision。省略 expected 的形式只用于旧版本兼容
和明确的运维修复。

`config_revision` 的处理：

- 非空：配置与 target revision 原子提交；
- 缺失：保留旧 Full 请求兼容，但清除已有 managed revision，因此该结果不能
  作为后续 Patch base；
- 空字符串：拒绝为 400。

Revisioned Full 遇到 user-owned instance ID 冲突时整体失败。Legacy
unrevisioned Full 保持当前兼容行为：跳过 user-owned row，且绝不覆盖它。

### 4.2 新增 Patch

同一资源增加：

```text
PATCH /api/internal/users/:user-id/machines/:machine-id/networks
```

请求格式：

```json
{
  "upserts": [
    {
      "instance_id": "11111111-1111-1111-1111-111111111111",
      "network_config": {}
    }
  ],
  "delete_instance_ids": [
    "22222222-2222-2222-2222-222222222222"
  ],
  "config_revision": "target-revision",
  "expected_config_revision": "base-revision"
}
```

Patch contract：

1. 两个 revision 字段均必填、非空且不能相同。
2. `upserts` 中的 instance ID 不得重复。
3. `delete_instance_ids` 中的 ID 不得重复。
4. 同一个 ID 不得同时出现在 upsert 和 delete 中。
5. 每个 upsert 必须携带该实例的完整 `NetworkConfig`，不支持字段级 JSON
   Patch。
6. `network_config` 内部的 instance ID 不受信任，receiver 使用 envelope 中的
   `instance_id` 进行归一化。
7. 删除不存在的 ID 是幂等 no-op。
8. Upsert 或 delete 碰到 user-owned row 时，整个 Patch 返回冲突且不写入。
9. 不允许从“receiver revision 不存在”的未知状态直接 Patch；使用 Full 建立
   Exact Set 和首个 revision。
10. 空 Patch 不能把 revision 改成另一个值；这通常表示 publisher revision
    计算错误，因此返回 400。

### 4.3 HTTP outcomes

| 条件 | HTTP | 语义 |
| --- | ---: | --- |
| Full/Patch 新提交成功 | 204 | Config 和 revision 已持久化 |
| Target revision 已经存在 | 204 | 幂等成功，无 row mutation |
| Expected revision 不匹配 | 409 | 零写入，调用者重新观察或发送 Full |
| User-owned ownership 冲突 | 409 | 零写入，不能自动覆盖 |
| 非法 ID、重复、交集或非法 config | 400 | 调用 contract 错误 |
| 请求超过 byte limit | 413 | 未进入 reconciliation |
| 条目数或单 config 超过限制 | 422 | 超出接收端容量 contract |
| SQLite 错误 | 500 | Transaction rollback |

409 返回机器可读字段：revision 冲突为
`code=managed_config_revision_conflict` 并在已知时带
`current_config_revision`；ownership 冲突为
`code=managed_config_ownership_conflict`。响应不得返回配置内容。日志不得记录
token、secret 或完整 config JSON。

## 5. Receiver architecture

### 5.1 Module responsibilities

| Module | 本阶段职责 |
| --- | --- |
| Internal HTTP Adapter | 内部鉴权、body/count limit、DTO 解析、HTTP 状态映射 |
| `ClientManager` | 解析 Target，调用 managed-config Interface，成功后通知 Session |
| `client_manager::managed_config` | Full/Patch 规则、归一化、typed outcome |
| `Db` Adapter | CAS、ownership fence、批量 mutation、revision transaction |
| Session runtime reconciliation | 校验 applied/base/target fence，增量收敛 touched instances；断链时 Full |

HTTP Adapter 不实现 ownership、diff 或 transaction 逻辑。PUT 和 PATCH 共用
managed-config Module，避免两套规则逐渐分叉。

### 5.2 Internal Interface

Module 接收两种 intent：

```text
Full {
  desired_configs,
  target_revision: Option<Revision>,
  expected_revision: Any | Exact(Option<Revision>)
}

Patch {
  upserts,
  delete_instance_ids,
  target_revision: Revision,
  expected_revision: Revision
}
```

返回 typed outcome：

```text
Applied {
  previous_revision,
  target_revision
}

AlreadyApplied {
  target_revision
}

RevisionConflict {
  expected_revision,
  current_revision
}

OwnershipConflict {
  instance_id
}
```

Validation error 与 database error 保持独立类型。HTTP handler 只负责将这些结果
映射到 section 4.3 的状态码。

## 6. Receiver implementation

### 6.1 Validation and normalization

在打开 SQLite write transaction 之前完成：

- request byte/count/per-entry limit；
- UUID、重复 ID 和 upsert/delete 交集校验；
- config key 拼写归一化；
- envelope instance ID 覆盖 nested identity；
- `NetworkConfig` 反序列化。

这样非法大请求不会长时间占用 SQLite writer lock。Ownership 必须在 transaction
内重新查询，因为 transaction 外的结果可能已过期。

当 request 带 target revision 时，可以先做一次 O(1) revision read；如果当前值
已经等于 target，可直接返回 `AlreadyApplied`，避免完整 config 归一化。任何可能
写入的请求仍必须在 transaction 内再次检查 revision。

### 6.2 Full transaction

在同一个 SQLite connection 上执行：

1. `BEGIN IMMEDIATE`。
2. 读取 `(user_id, machine_id)` 当前 persisted revision。
3. 若 supplied target 已经是 current，返回 `AlreadyApplied`。
4. 检查 optional expected revision。
5. 只读取现有 row 的 `(instance_id, source)`；不加载无关 config JSON。
6. 执行 user-owned ownership fence。
7. 批量 upsert 全部 desired web-owned rows。
8. 计算并批量删除 `existing_web_ids - desired_ids`。
9. 最后写入 supplied target revision；legacy unrevisioned Full 则删除旧 revision。
10. Commit。

任一步骤失败都 rollback。Full 仍是 `O(total)`，但不会再逐条独立提交，也不会
出现“部分 rows 已更新、revision 仍是旧值”的中间持久状态。

### 6.3 Patch transaction

在同一个 SQLite connection 上执行：

1. `BEGIN IMMEDIATE`。
2. 读取 current revision。
3. 如果 current 等于 target，返回 `AlreadyApplied`。
4. 如果 current 不等于 expected，返回 `RevisionConflict`。
5. 只查询 upsert/delete IDs 的 source。
6. 任一 touched ID 属于 user 时，返回 `OwnershipConflict`。
7. 批量 upsert changed configs。
8. 批量删除 requested web-owned IDs。
9. 最后写入 target revision。
10. Commit。

Patch 禁止：

- list 全部 Target rows；
- 重算完整 Target digest；
- 根据 touched IDs 之外的数据做 stale-row scan。

因此其数据库工作量只随 `upserts + deletes` 增长。

### 6.4 Bounded batch SQL

批量操作不构造无限长 SQL。根据 SQLite bind-variable limit 选取固定 batch size，
并在同一个 transaction 内分批执行：

- multi-row `INSERT ... ON CONFLICT DO UPDATE`；
- 带 `source = web` 条件的 batch delete；
- 只返回 instance ID/source 的 ownership query。

Patch statement 数量应为 `O(ceil(delta / batch_size))`；Full 为
`O(ceil(total / batch_size))`。每个 accepted request 只有一个 transaction 和
一次 revision 写入。

### 6.5 Alternate-write revision invalidation

现有其他路径可能 save、delete、disable 或改变 web-owned row。若这些路径修改
rows 后仍保留旧 managed revision，Patch CAS 会把错误状态当作正确 base。

因此所有 config mutation Adapter 必须遵守：

1. 判断 mutation 是否改变 web-owned row；
2. 在一个 transaction 中执行 mutation；
3. 在 commit 前删除该 Target 的 managed revision。

Managed Full/Patch 在同一 transaction 内先完成 mutation，最后写入新的 target
revision。只影响 user-owned rows 的操作不清除 managed revision。

本方案不在 `/validate-token` 读取 revision 时重算完整 digest，否则周期性验证会
重新变成 `O(total)`。Revision 完整性由所有写入 Adapter 局部维护。

### 6.6 Locking, cancellation and notification

现有 per-target process-local lock 可以保留，用于减少同进程的重复工作，但它不
承担正确性。正确性由 SQLite transaction 和 CAS 提供。

- Transaction 内不执行 Session RPC、网络请求或无关 async 工作。
- HTTP future 在 commit 前取消时，transaction drop 必须 rollback。
- Commit 后即使 response 或 notification 丢失，persisted state 仍然有效；调用者
  用同一 target retry 会得到幂等成功。
- 只有带 target revision 的 `Applied` 才通知匹配的 live Session；
  `AlreadyApplied`、legacy unrevisioned Full、conflict 和失败不重复通知。
- Notification 必须发生在 commit 之后。
- Full notification 清除任何 pending delta，触发完整收敛。
- Patch notification 携带 expected revision、target revision、upsert IDs 和本次
  transaction 实际接受删除的 web-owned IDs。请求删除但数据库原本不存在的 ID
  仍是 no-op，不能借机删除 Core 中同 ID 的 user-owned 实例。只有 Session applied
  revision 精确等于 expected revision，且没有更早的 Patch 等待处理时，才保留该
  delta。
- 两次 Patch 在前一次完成前积压时不合并 delta；Session 清除 pending delta，并在
  最新 heartbeat/revision 上执行一次 Full。这避免引入 Patch queue 或 delivery FSM。
- 增量 round 只读取 upsert rows，只删除本次 delete IDs，只对 touched running
  instances 执行 runtime Patch/Run。完成前再次校验 persisted target revision；只有
  全部 touched instances 成功且 target 仍相同，才推进 applied revision。
- 任何通过 EasyTier Web mutation route 直接 Run、Save、Delete 或切换实例状态的
  操作在执行前和结束后（包括部分 side effect 后返回错误）都清除 Session applied
  revision 与 pending delta、增加运行配置 cache epoch，并唤醒一次 Full
  reconcile。旧 round 只有 epoch 仍匹配时才能推进 applied revision；新一轮不得
  信任 mutation 前缓存的 runtime config。否则 runtime-only mutation 或 Core 成功、
  SQLite 失败的复合 mutation 可能在 persisted revision 不变时破坏 Patch base 的
  完整性。

## 7. Capacity contract

当前 route 没有显式 body limit，Axum `Json` 使用依赖版本的默认 2 MiB 限制。
生产容量不应依赖框架隐式默认值。

本阶段定义并测试四个独立限制：

- decoded request 最大 bytes；
- Full entries / Patch upserts 最大数量；
- Patch deletes 最大数量；
- 单个 `network_config` 最大 bytes。

限制只应用于 internal managed-config route，不提高其他 public route 的 limit。
具体默认值不能拍脑袋确定：先采集 1k/10k representative configs 的 encoded
size 和 peak memory，再选择有明确 headroom 的默认值及硬上限。

提高 Full limit 只是确保 fallback 覆盖已支持的生产规模，不是稳态优化。请求压缩
同样只能降低 wire bytes，不能降低 JSON materialization 和 SQLite 工作量，因此
不作为 Patch 的前置条件。

## 8. Failure and recovery

| Failure | Receiver state | Caller action |
| --- | --- | --- |
| Invalid payload | Unchanged | 修复请求，不重试相同 payload |
| Capacity exceeded | Unchanged | 使用较小 Patch；Full 需检查支持规模 |
| Revision conflict | Unchanged | 重新观察；有 base 时重算 Patch，否则 Full |
| Ownership conflict | Unchanged | 解决 ownership，不能自动覆盖 |
| SQLite error before commit | Rolled back | 从相同 observed revision 重试 |
| Response lost after commit | Target committed | 同一 target retry，幂等成功 |
| Process exits before revisioned Session notify | Target committed | 现有 revision reconciliation 恢复 |
| Alternate web-row mutation | Revision atomically cleared | 下一次观察触发 Full 修复 |
| Console cache loss | Receiver unchanged | Console 发布 Full |

Receiver 不保存 Patch delivery ledger。Publisher 根据自己的完整目标和 receiver
当前 revision 重算 Patch 或选择 Full。

## 9. Rollout and rollback

### 9.1 Receiver-first rollout

1. 为现有 Full 行为增加 characterization tests。
2. 将 Full rows/revision 改为一个 atomic transaction。
3. 为 alternate web-row mutation 增加 revision invalidation。
4. 增加 PATCH、typed conflict、capacity limits 和 metrics。
5. 在 Console 仍只发送 PUT 时部署到全部 EasyTier Web 实例。
6. 完成旧 Console PUT、新 Console PUT/PATCH contract 测试。
7. 最后启用 Console Patch 发布。

Patch capability 不通过 `/validate-token` 协商。部署顺序就是 compatibility gate；
这样不会把配置能力重新耦合回鉴权 Interface。

Console 遇到 409 可以 re-observe 后发送 Full。它不能把 404、401 或 malformed
response 当作旧 receiver 并静默换一种 mutation contract；出现 404 表示接收端
部署门禁未满足。

### 9.2 Rollback

- Console 尚未发送 Patch 时，EasyTier Web 可正常回滚。
- Console 已发送 Patch 后，先回滚 Console，使调用恢复为 PUT，再回滚 Web。
- PUT 在整个发布周期保持兼容。
- Patch 和 Full 写入相同 rows/revision，不需要格式级数据迁移。

本方案不新增 persistent table。现有 Target/instance unique index 应覆盖 touched-ID
查询；若实现时需要新 index，必须先用实际 SQLite query plan 证明。

## 10. Verification

### 10.1 Contract tests

- 现有 Full JSON 继续接受。
- 空 Full 删除所有 web-owned rows，保留 user-owned rows。
- Patch add/update/delete 与等价 Full 得到相同最终 projection。
- Duplicate/overlap/invalid config 返回 400 且零写入。
- Patch 缺少 revision 返回 400。
- Revision conflict 返回 409 和 current revision，不返回 config。
- Byte/count/per-entry limits 分别有确定性测试。

### 10.2 Transaction and ownership tests

- 在 upsert 后、delete 后、revision write 前注入错误，rows/revision 全部 rollback。
- Revisioned Full/Patch 的 user-owned collision 整体 rollback。
- 删除不存在的 ID 幂等成功。
- 两个 target 从同一 base 并发时，一个成功、一个 409。
- 相同 target retry 只有第一次写入，第二次为 no-op success。
- Alternate save/delete/disable web row 与 revision invalidation 原子提交。
- User-owned-only mutation 不清除 managed revision。
- 数据库重连后，任一 persisted revision 都对应完整一致的 rows。

### 10.3 Scale tests

至少使用 1k 和 10k representative entries：

- 单实例 Patch 的 decoded bytes、row reads、writes 和 statement count 不随 Target
  总实例数增长；
- Patch 不执行 list-all query；
- Full 使用 bounded batches 和一个 transaction；
- Revision read 保持 O(1)；
- 超限 Full 稳定返回 413/422，而不是耗尽进程内存；
- 并发请求无 deadlock，且 CAS 结果确定。

Session 测试还必须验证：精确 base/target 使用 touched-instance reconcile；base
不匹配、目标 revision 已变化、Full notification 和 Patch backlog 都使用 Full；
touched runtime apply 失败不推进 applied revision；删除只作用于本次 delete IDs。
运行态 Config Get/Patch/Run/Delete 数量应随 touched instances 增长。为确认运行实例
身份而进行的一次 list/meta RPC 可以保留，它不发送或重写所有实例配置。

## 11. Observability

每个请求记录结构化字段，但不记录 config 内容：

- mode：`full` / `patch`；
- user/machine scope；
- request bytes；
- desired/upsert/delete count；
- normalization、target-lock wait、transaction duration；
- SQL statement/batch count；
- result：applied、already-applied、revision-conflict、ownership-conflict、
  invalid、oversized、database-error；
- Session notification 是否发送。

Rollout acceptance：

- Console 启用后 Patch 占普通变更的绝大多数；
- 单实例变化的 request size 与 SQLite cost 与单实例成比例；
- conflict rate 可解释且稳定；
- 支持规模内的 Full 没有 413/422；
- validate-token latency 不随 Target 实例数增长。

## 12. 后续优化

### 12.1 Session runtime delta apply（已实现）

Patch commit outcome 已携带 touched IDs。Session 只在 applied revision 正好等于
Patch base 时执行 touched-instance reconcile；重启、revision 断链、通知丢失或
并发 Patch backlog 都退回 Full。接收端不保存 Patch queue，也不合并 delta。

### 12.2 Chunked Full

不能把 Full Exact Set 直接分页写入 live rows：接收端无法在中间页判断哪些旧
实例最终应删除，crash 也会暴露半套目标。

如果测量证明单请求 Full 无法覆盖必须支持的冷恢复规模，需要单独设计带
snapshot ID、staging rows、expiry、finalize 和 atomic swap 的协议。在出现数据
证明前不新增该状态机。

## 13. Implementation files and checklist

主要涉及：

- `easytier-web/src/restful/network.rs`
- `easytier-web/src/client_manager/mod.rs`
- `easytier-web/src/client_manager/managed_config.rs`
- `easytier-web/src/db/mod.rs`
- 对应 contract、database 和 managed-config tests

完成条件：

- [x] 现有 Full compatibility tests 固定。
- [x] Full config rows 与 revision 原子提交。
- [x] Alternate web-owned mutations 原子清除 revision。
- [x] PATCH contract 和 typed 409 实现。
- [x] Patch 只查询、写入 touched IDs。
- [ ] Bulk SQL 遵守 tested bind-count bound。
- [ ] Route byte/count/per-entry limits 有文档和测试。
- [x] User-owned rows 不能被 Full/Patch 覆盖或删除。
- [x] Empty Full 语义保持。
- [x] Applied/AlreadyApplied/conflict 的通知行为符合设计。
- [x] Session 在 revision 连续时只收敛 touched instances，断链时使用 Full。
- [ ] 1k/10k scale 与 concurrent CAS tests 通过。
- [ ] Receiver-first compatibility matrix 通过。

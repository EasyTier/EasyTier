# Machine ID 稳健性方案

## 背景与约束

`machine_id` 当前的外部契约不能变：

- 协议字段仍然是 `UUID`
- 服务端和第三方系统仍然把它当作配置恢复和设备识别键
- 本次方案只改**客户端生成与持久化策略**，不改服务端语义

这意味着方案必须同时满足两点：

1. **升级兼容优先**：老用户升级后，不能因为新算法直接换了 `machine_id`
2. **稳定性优先**：后续运行要以本地持久化状态为准，而不是每次重新猜系统指纹

同时要明确一个非目标：

- **无法在纯客户端、无中心协调、且用户可能整份复制状态目录/镜像的前提下，保证不同 VM / Docker / 克隆副本一定不同**

本方案追求的是：

- 同一安装稳定
- 正常部署下高概率不同
- 错误部署时尽量显式暴露问题，而不是静默生成坏 ID

---

## 现状

### 当前实现 (`easytier/src/common/mod.rs:103-162`)

`get_machine_id()` 目前有 4 级回退：

| 优先级 | 来源 | 行为 |
|--------|------|------|
| 1 | CLI `--machine-id` / `ET_MACHINE_ID` | 直接解析为 UUID，或 hash 成 UUID |
| 2 | `et_machine_id` 文件（二进制同目录） | 读取缓存 UUID |
| 3 | `machine-uid` crate（读 OS 原生 machine-id） | 读 `/etc/machine-id` 等，hash 成 UUID **（不写缓存）** |
| 4 | `uuid::Uuid::new_v4()` 随机生成 | 生成随机 UUID **（仅此级写缓存文件）** |

### 当前支持的平台（`machine-uid` crate）

`#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows", target_os = "freebsd"))]`

- Android 不在列表中，直接掉到第 4 级（随机 UUID）

---

## 问题根因

### 问题 1: 同一台机器 machine id 一直变

- 第 3 级 `machine-uid` 每次都重新读系统 machine-id，**不会写持久化状态**
- 如果 `/etc/machine-id` 或等价系统标识变化，EasyTier 的 `machine_id` 也跟着变
- `et_machine_id` 放在二进制旁边：
  - 升级时可能丢
  - 不同版本路径不同
  - `/usr/bin/`、AppImage、APK 安装目录等场景经常不可写

### 问题 2: 不同 VM / Docker 里 machine id 完全一样

- Docker 容器和克隆 VM 可能共享同一个 `/etc/machine-id`
- 当前算法没有额外区分信息
- 而且第 3 级不写缓存，导致每次都重复拿到相同的系统值

### 问题 3: Android 上一直变

- `machine-uid` 不支持 Android
- 当前退化路径最终会落到随机 UUID
- 二进制同目录对 Android 也不是可靠的持久化位置

---

## 设计目标

1. **保持现有服务端/第三方契约不变**
2. **升级兼容优先，尽量保住老用户既有 `machine_id`**
3. **首次确定后持久化，后续只认本地状态文件**
4. **缓存路径使用平台标准持久化目录，不再使用二进制同目录**
5. **在 Linux 首次新生成时加入额外熵源，降低容器/VM 碰撞概率**
6. **优先使用可靠持久化目录；仅在连兜底目录都不可用时 fail closed**

---

## 非目标与边界

以下场景，本方案**不能保证** `machine_id` 一定不同：

- 用户复制了整个 EasyTier 状态目录
- 基础镜像里已经预置了 `machine_id` 状态文件
- VM 模板克隆时保留了 hostname、MAC，并且没有重置状态目录

也就是说：

- 本方案能显著降低碰撞概率
- 但不能替代正确的镜像制作、first boot provisioning、显式注入 `--machine-id`

文档和日志里必须避免“确保不同”“绝对唯一”这类表述。

---

## 核心原则

### 1. 兼容迁移优先

新版本第一次启动时，必须先尝试恢复老版本已经在用的 `machine_id`，再考虑新生成。

否则会直接打断配置恢复：

- 服务端当前按 `(user_id, machine_id)` 找设备
- 老用户升级后如果 `machine_id` 变了，会被当成新机器

### 2. 持久化状态为准

一旦某个 `machine_id` 被确定并写入新状态文件：

- 后续启动优先读取该文件
- 不再重新查询 OS machine-id
- 不再重新混入 hostname / MAC

### 3. 新生成仅用于“首次无历史状态”

额外熵源只在**没有新状态、也没有可迁移旧状态**时参与生成。

它的目标是：

- 降低容器 / VM 克隆场景的碰撞概率

它**不是**兼容迁移逻辑的一部分。

### 4. 缺少可靠状态目录时显式失败

如果当前平台/宿主无法提供稳定的持久化目录：

- 不应静默退化成“每次随机一个 UUID”
- Linux 在 `XDG_DATA_HOME` 和 `HOME` 都缺失时，可以继续尝试 `/var/lib/easytier`
- 应让 `web_client` 初始化失败，并提示用户：
  - 显式传 `--machine-id` / `ET_MACHINE_ID`
  - 或配置可靠的状态目录

---

## 新的解析顺序

新的 machine ID 解析流程如下：

```text
1. CLI --machine-id / ET_MACHINE_ID
2. 新状态文件（平台持久化目录中的 machine_id）
3. 一次性兼容迁移
   3a. 旧 et_machine_id 文件（二进制同目录）
   3b. 旧算法可推导出的 legacy machine-id
4. 首次新生成
   4a. Linux: machine-uid + best-effort 额外熵源 → hash
   4b. 其他支持 machine-uid 的平台: machine-uid → hash
   4c. 最终 fallback: UUID v4
5. 将 3 / 4 得到的结果写入新状态文件
```

### 第 1 级：显式指定（不变）

- `--machine-id`
- `ET_MACHINE_ID`

行为保持不变：

- 如果是合法 UUID，直接使用
- 如果不是 UUID，沿用当前逻辑 hash 成 UUID

显式指定的值不强制写入状态文件，继续保留“显式传参优先”的语义。

### 第 2 级：新状态文件（权威来源）

如果新状态文件存在且内容合法：

- 立即返回
- 不再查询任何系统信息

这是后续运行的唯一权威来源。

### 第 3 级：一次性兼容迁移

这是本方案和原文档最大的区别。

#### 3a. 迁移旧 `et_machine_id`

如果二进制同目录存在老的 `et_machine_id` 文件，且内容是合法 UUID：

- 直接采用该值
- 立即写入新状态文件
- 后续不再依赖旧位置

#### 3b. 迁移旧算法可推导出的 ID

对于原先走 `machine_uid::get()` 的平台（Linux/macOS/Windows/FreeBSD）：

- 如果没有旧文件
- 但能读到 `machine_uid::get()`
- 且当前状态目录看起来像已有安装，而不是全新首次启动

则按**老算法**计算出 legacy 值：

```text
legacy_id = hash(machine_uid::get())
```

注意：

- 这里**不能**混入新的 hostname / MAC 熵源
- 否则会把老用户现网 `machine_id` 改掉

如果成功得到 legacy 值：

- 采用该值
- 写入新状态文件

这样可以覆盖一大类老用户：

- 他们之前没有 `et_machine_id` 文件
- 但服务端已经按老的 `hash(machine_uid)` 记住了该机器

这里的“已有安装”是一个启发式判断，当前建议至少满足：

- machine id 状态目录已存在
- 且目录中已有其他 EasyTier 文件

这样可以避免在 Linux 的全新安装上，每次都优先落到 `hash(machine_uid)`，导致共享 `/etc/machine-id` 的容器/VM 继续按旧方式碰撞。

### 第 4 级：首次新生成

只有当前面所有步骤都失败时，才进入新生成逻辑。

#### 4a. Linux: `machine-uid + 额外熵源`

在 Linux 上，新生成采用：

- `machine_uid::get()`
- hostname
- 前 3 个非 `lo` 网卡的 MAC 地址（排序后）

组合后 hash 成 UUID。

用途：

- 在基础镜像共享 `/etc/machine-id` 的情况下，尽量让不同容器/VM 得到不同 ID

限制：

- 这是 best-effort，不是强保证
- 如果 hostname / MAC 也被复制或固定配置，仍可能碰撞

#### 4b. 其他支持 `machine-uid` 的平台

macOS / Windows / FreeBSD 继续使用：

```text
new_id = hash(machine_uid::get())
```

不额外引入新熵源，先保持实现简单和行为可预期。

#### 4c. 最终 fallback

如果 `machine-uid` 不可用，或上述流程都无法完成：

- 生成 `Uuid::new_v4()`
- 写入新状态文件

这个分支主要覆盖不支持 `machine-uid` 的平台，例如 Android。

---

## 状态文件位置

这里的文件虽然在实现上常被称为“cache”，但语义上应视为**持久化状态文件**，不是可随意清理的临时缓存。

### 默认路径

| 平台 | 状态文件路径 |
|------|--------------|
| Linux | `$XDG_DATA_HOME/easytier/machine_id`，或 `~/.local/share/easytier/machine_id`，或 `/var/lib/easytier/machine_id` |
| macOS | `~/Library/Application Support/com.easytier/machine_id` |
| Windows | `%LOCALAPPDATA%/easytier/machine_id` |
| FreeBSD | `~/.local/share/easytier/machine_id` |
| Android | 由宿主 app 显式提供 app 私有持久化目录，例如 `filesDir` / `app_data_dir` |

### 目录解析规则

优先级建议如下：

1. 调用方显式设置的状态目录
2. 平台标准持久化目录
3. Linux 在 `XDG_DATA_HOME` 和 `HOME` 都不可用时，回退到 `/var/lib/easytier`
4. 连兜底目录都无法使用时，返回错误

不再使用：

- `current_exe().with_file_name("et_machine_id")`
- Android `cache_dir`
- APK / AppImage / 安装目录

原因是这些位置都不具备稳定持久化语义。

对 Linux 来说，`/var/lib/easytier` 比 `/etc/easytier` 更合适作为默认兜底目录：

- `/var/lib` 的语义是应用私有持久化状态
- `/etc` 更适合静态配置，不适合默认承载运行期生成的 machine-id
- system service 和容器卷也更容易围绕 `/var/lib/easytier` 做持久化

---

## Android 策略

Android 不能再依赖“native 自己猜一个路径”。

### 原则

- 必须由宿主 app 在第一次使用 web client 前，显式提供持久化目录
- 推荐使用 app 私有持久化目录：
  - Tauri: `app_data_dir`
  - JNI/原生 Android: `filesDir`

### 需要新增的接口

当前 JNI 并没有 `set_machine_id_state_dir()` 入口，因此文档不能假设“宿主会调用”而不补接口。

需要补一个显式 API，二选一即可：

#### 方案 A：新增 setter

```rust
pub fn set_machine_id_state_dir(dir: PathBuf);
```

宿主在初始化 web client 前调用一次。

#### 方案 B：把状态目录作为 web client 初始化参数

例如扩展：

```rust
run_web_client(..., machine_id_state_dir: Option<PathBuf>, ...)
```

这样可以减少全局状态。

### Android 失败语义

如果宿主没有提供持久化目录，且也没有显式传 `--machine-id` / 等价配置：

- `web_client` 初始化应失败
- 记录明确错误日志

不再采用旧文档里的退化行为：

- 不再回退到二进制同目录
- 不再允许“每次启动随机一个 ID 继续运行”

---

## 失败语义与并发语义

### 失败语义

以下情况不应静默吞掉：

- 无法解析状态目录
- 状态目录不可创建
- 状态文件无法原子写入

建议行为：

- `run_web_client()` 返回错误
- 错误信息明确提示：
  - 指定 `--machine-id`
  - 或修复状态目录权限/挂载

### 并发首次启动

多个进程第一次同时启动时，必须避免各自生成不同 ID。

建议写入策略：

1. 先尝试读取
2. 不存在时生成候选 ID
3. 获取写锁
4. 锁内再次读取，避免重复生成
5. 写入临时文件
6. 使用原子 `rename`
7. 如果发现目标文件已被其他进程写入，则重新读取并采用已落盘的值

至少要保证：

- 不会因为并发首启产生多个不同 ID
- 不会留下半写入文件

### 锁语义

锁不能依赖“创建一个 `.lock` 文件，进程退出时手动删除”这种模型。

原因：

- 进程被 `SIGKILL` 或崩溃时，手动清理不会执行
- 残留锁文件会直接卡死后续启动

推荐实现：

- Unix 平台使用内核 advisory lock，例如 `flock`
- 非 Unix fallback 至少也要带过期回收逻辑，避免残留锁永久阻塞启动

同时，**在获取锁前就要先确保状态目录存在**，否则首次启动会因为 `ENOENT` 在加锁阶段直接失败。

---

## 兼容性与迁移策略

### 对现有用户

- **已显式使用 `--machine-id` / `ET_MACHINE_ID` 的用户**：完全不受影响
- **有旧 `et_machine_id` 文件的用户**：自动迁移到新状态目录
- **没有旧文件但老版本靠 `machine_uid` 稳定工作的用户**：通过 legacy 算法迁移，尽量保住原 ID

### 对首次安装的新用户

- 首次生成后写入新状态文件
- 后续都从新状态文件读取

### 不再接受的迁移方案

以下做法不可作为正式迁移策略：

- “不再读取旧 `et_machine_id`，用户自己用 `--machine-id` 指定旧值”

原因：

- 大多数用户并不知道自己历史上实际使用的是哪个值
- 很多老值来自 `hash(machine_uid)`，并不是用户手工设置的

---

## 用户可见文案需要同步更新

当前帮助文案仍写着：

- `default is from system`
- `默认从系统获得`

在新方案下，这个说法不再准确。

建议更新为类似语义：

- 默认从本地持久化状态获得
- 首次启动可能基于系统信息迁移或生成，之后固定不变

这样才能和真实行为一致。

---

## 需要改动的文件

| 文件 | 改动 |
|------|------|
| `easytier/src/common/mod.rs` | 重写 machine ID 解析流程；补迁移逻辑；补状态目录解析；补原子写入 |
| `easytier/src/common/constants.rs` | 仅当保留全局 setter 方案时，新增 machine ID 状态目录配置项 |
| `easytier/src/web_client/mod.rs` | 在初始化阶段 resolve machine ID，并把结果向下传递 |
| `easytier/src/web_client/session.rs` | 不再自行调用全局 `get_machine_id()`；改为使用上层传入值 |
| `easytier-gui/src-tauri/src/lib.rs` | 初始化 web client 前传入 `app_data_dir` |
| `easytier-contrib/easytier-android-jni/src/lib.rs` | 新增 JNI 接口以传入 `filesDir`，或扩展初始化 API |
| `easytier/src/core.rs` | CLI 模式下组装 `MachineIdOptions`，优先使用 `config_dir` |
| `easytier/locales/app.yml` | 更新 `machine_id` 帮助文案 |

---

## API 草案

可选其一。

### 方案 A：保留全局 setter

```rust
/// 宿主显式设置 machine id 状态目录
pub fn set_machine_id_state_dir(dir: PathBuf);

/// 尝试获取 machine id；失败时返回错误，而不是静默随机
pub fn try_get_machine_id() -> anyhow::Result<uuid::Uuid>;
```

### 方案 B：避免全局状态

```rust
pub struct MachineIdOptions {
    pub explicit_machine_id: Option<String>,
    pub state_dir: Option<PathBuf>,
}

pub fn resolve_machine_id(opts: &MachineIdOptions) -> anyhow::Result<uuid::Uuid>;
```

对于长期维护性，**方案 B 更清晰**，因为：

- machine ID 的来源显式可见
- 测试更容易写
- Android / Tauri / CLI 不需要共享额外全局变量

### 推荐收口

本方案推荐采用 **方案 B**，并进一步收紧为：

- `machine_id` 在 `run_web_client()` 初始化阶段**一次性 resolve**
- resolve 结果保存在 `WebClient` / `Controller` / `Session` 上下文中
- heartbeat 直接使用这个已解析值

不要继续保留当前这种隐式模型：

- `run_web_client()` 只设置全局变量
- `Session::heartbeat_routine()` 再临时调用 `get_machine_id()`

原因：

- machine ID 的失败应该尽早暴露在初始化阶段，而不是连上服务端后才出错
- 解析状态目录、迁移旧文件、原子写入都属于启动期逻辑，不适合散落在心跳线程里
- 一次 resolve 后向下传递，更容易测试，也更容易推导行为

---

## 调用方职责

推荐把“状态目录怎么来”明确放在调用方，而不是放在公共模块里猜。

### CLI / daemon

规则建议如下：

1. 如果传了 `--machine-id` / `ET_MACHINE_ID`，直接按显式值处理
2. 否则回退到平台标准状态目录

`config_dir` 仍然只用于配置文件，不应承载 machine-id 这类运行期状态。

如果后续需要让运维显式控制 machine-id 的落盘位置，应新增独立的 `state_dir` / `machine_id_dir` 参数，而不是继续复用 `config_dir`。

### Tauri / GUI

- 统一使用 `app.path().app_data_dir()`
- 不要使用 `cache_dir`

### Android JNI / 原生宿主

- 宿主必须提供 `filesDir`
- 必须在第一次初始化 web client 前传入

当前状态说明：

- 现有 `easytier-contrib/easytier-android-jni` 还没有暴露 web-client 初始化能力
- 因此这不是本轮改造的回归点
- 但如果后续 Android 要接入 web-client，就必须补一层 JNI 接口，把 `filesDir` 或等价持久化目录显式传给 machine-id resolver

---

## 迁移伪代码

推荐把迁移逻辑明确成单一路径，避免实现时再引入分叉。

```rust
fn resolve_machine_id(opts: &MachineIdOptions) -> Result<Uuid> {
    if let Some(explicit) = opts.explicit_machine_id.as_ref() {
        return Ok(parse_or_hash(explicit));
    }

    let state_file = resolve_state_file(opts.state_dir.as_ref())?;

    if let Some(id) = read_uuid_file(&state_file)? {
        return Ok(id);
    }

    if let Some(id) = read_legacy_et_machine_id()? {
        write_uuid_file_atomically(&state_file, id)?;
        return Ok(id);
    }

    if let Some(id) = resolve_legacy_machine_uid_hash()? {
        write_uuid_file_atomically(&state_file, id)?;
        return Ok(id);
    }

    let id = resolve_new_machine_id()?;
    write_uuid_file_atomically(&state_file, id)?;
    Ok(id)
}
```

这里要强调两点：

- `resolve_legacy_machine_uid_hash()` 和 `resolve_new_machine_id()` 必须分开，不能复用一套逻辑
- Linux 新熵源只能出现在 `resolve_new_machine_id()`，不能污染 legacy 迁移

---

## 实施顺序

为了降低回归风险，建议按下面 4 个提交阶段推进。

### 阶段 1：抽出 resolver 与文件写入

目标：

- 引入 `MachineIdOptions`
- 引入 `resolve_machine_id()`
- 实现新状态文件读取、legacy 迁移、原子写入
- 保持旧调用路径暂时可编译

验收：

- 单元测试覆盖显式值 / 新状态文件 / 旧文件迁移 / legacy hash 迁移

### 阶段 2：把 web client 改成启动期 resolve

目标：

- `run_web_client()` 改为接收 `MachineIdOptions` 或等价参数
- 初始化阶段 resolve 一次
- `Session::heartbeat_routine()` 不再直接访问全局 getter

验收：

- machine ID 获取失败时，`run_web_client()` 直接返回错误
- 正常路径 heartbeat 仅消费已解析的 UUID

### 阶段 3：接入各调用方

目标：

- CLI: 使用平台标准状态目录，不复用 `config_dir`
- Tauri: `app_data_dir`
- Android JNI: 新增宿主传目录接口

验收：

- CLI 在默认状态目录下能稳定复用 `machine_id`
- GUI 重启/升级后 `machine_id` 不变
- Android 未传 `filesDir` 时初始化失败

### 阶段 4：清理旧路径与更新文案

目标：

- 删除对二进制同目录作为正式持久化位置的依赖
- 更新帮助文案
- 补充部署说明和 Docker/VM 注意事项

验收：

- 文案不再宣称“默认从系统获得”
- 文档和代码行为一致

---

## 验收标准

实现完成后，至少应满足以下可验证结果：

1. 同一安装在重启、升级、路径变化后 `machine_id` 保持不变
2. 老用户升级后，如果过去依赖 `et_machine_id` 或 `hash(machine_uid)`，大概率保持原值
3. Android 在宿主提供 `filesDir` 时稳定；未提供时显式报错
4. Linux 容器/VM 在“无历史状态、共享 `/etc/machine-id`”场景下，较当前实现更不容易碰撞
5. 没有可靠持久化目录时，不会静默生成漂移 ID
6. 并发首次启动不会留下多个不同结果

---

## 建议补充的测试

1. 显式 `--machine-id` 优先级最高
2. 新状态文件存在时直接命中
3. 旧 `et_machine_id` 可迁移到新状态目录
4. 无旧文件时，legacy `hash(machine_uid)` 迁移成功
5. Linux 新生成时，额外熵源参与计算
6. Android 无状态目录时，`web_client` 初始化失败
7. 状态文件写入使用原子替换，并发首启不会产生多个值

---

## 结论

可行方向不是“继续从系统猜 machine id”，而是：

- **兼容迁移一次**
- **写入稳定的本地持久化状态**
- **后续只认该状态**

在这个基础上：

- Linux 首次新生成时用 `machine-uid + hostname + MAC` 做 best-effort 去碰撞
- Linux 默认状态目录在 `XDG_DATA_HOME` / `HOME` 不可用时回退到 `/var/lib/easytier`
- Android 必须由宿主提供持久化目录
- 连兜底目录都不可用时显式失败

这样才能在**不改服务端契约**的前提下，最大化保住老用户身份，并把后续行为变得稳定、可预测、可诊断。

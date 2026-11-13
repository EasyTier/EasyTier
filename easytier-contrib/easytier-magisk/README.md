# EasyTier Magisk 模块

安装模块并重启后，EasyTier 会读取
`/data/adb/modules/easytier_magisk/config/config.toml` 启动。

## WebUI

KernelSU 及支持模块 WebUI 的分支管理器可直接从模块详情页打开配置
界面。Magisk 用户可安装兼容 KernelSU 模块 WebUI 的独立管理器后打开。

WebUI 使用 EasyTier 自身的配置模型加载和校验配置。点击“保存并重启”后，
模块会先验证配置，原子替换 `config.toml`，再重启正在运行的 EasyTier
进程。校验失败时原配置保持不变。

如果 `config/command_args` 存在，模块处于启动参数模式并会忽略
`config.toml`。WebUI 会显示提示并禁止保存；删除 `command_args` 后即可
使用 WebUI 管理配置。

## 手动配置

也可以直接编辑
`/data/adb/modules/easytier_magisk/config/config.toml`。保存后在模块管理器中
禁用 EasyTier，等待 10 秒后重新启用即可让配置生效。

# 网页控制台设备接入命令

`easytier-web` 支持自定义网页顶部“设备接入”和空设备列表提示中显示、复制的整段内容。适用于公网地址与监听地址不同、自定义可执行文件路径或附加启动参数等场景。

## 启动参数

```sh
easytier-web --console-enroll-command 'easytier-core --config-server tcp://vpn.example.com:22020/{username} --hostname my-device'
```

## 配置文件

创建 `console.toml`：

```toml
console_enroll_command = 'easytier-core --config-server tcp://vpn.example.com:22020/{username} --hostname my-device'
```

启动时指定文件：

```sh
easytier-web --console-config-file ./console.toml
```

此文件用于网页控制台定制，目前支持 `console_enroll_command` 字段。它不是 `easytier-core` 的网络配置文件。修改后需重启 `easytier-web` 并刷新网页。

两个选项也可分别通过 `ET_WEB_CONSOLE_ENROLL_COMMAND` 和 `ET_WEB_CONSOLE_CONFIG_FILE` 环境变量设置。命令模板的优先级是：启动参数 > 环境变量 > TOML 文件 > 默认命令。指定了文件时，文件必须可读取且格式正确，即使模板被参数或环境变量覆盖。

## 模板变量

| 变量 | 替换内容 |
| --- | --- |
| `{username}` | 当前登录用户的用户名 |
| `{host}` | 网页使用的 API 地址的主机名；同源部署时为当前网页主机名，IPv6 地址保留方括号 |
| `{protocol}` | 服务端 `--config-server-protocol` 的值 |
| `{port}` | 服务端 `--config-server-port` 的值 |

变量区分大小写，可重复使用。其他文本（包括未知变量、空格、换行）保留原样；替换后的值不会再次作为模板解析。内容以纯文本显示和复制，不会被网页执行。多行文本可使用 TOML 多行字符串。

未配置时，默认命令保持为：

```text
easytier-core --config-server {protocol}://{host}:{port}/{username}
```

模板只影响提示内容，不会修改服务端监听协议、端口或认证配置。对公网域名、端口或外部认证令牌有特殊要求时，应在模板中填写客户端实际需要使用的值。

空字符串、纯空白模板、无效 TOML 和未知配置字段会导致启动失败，并输出错误原因。

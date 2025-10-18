# EasyTier TCP Local Port Forward

本文档介绍如何在 EasyTier 中启用和使用「本地端口转发」（TCP Local Port Forward）功能。该功能的目标和 `socat TCP-LISTEN:15037,bind=0.0.0.0,fork,reuseaddr TCP:localhost:5037` 等效：在本地监听一个端口，并把进入的 TCP 连接转发到指定目标。

## 通过 CLI 启动

在执行 `easytier-core` 时增加 `--local-port-forward` 参数即可。规则格式为 `协议://监听地址/目标地址`，支持 `tcp` 与 `udp`。多个规则可以逗号分隔，或重复添加参数。

```bash
# TCP: 监听 0.0.0.0:15037，并转发到 127.0.0.1:5037
easytier-core \
  --local-port-forward tcp://0.0.0.0:15037/127.0.0.1:5037 \
  # 其他参数 ...

# UDP: 监听 0.0.0.0:18000，并转发到 10.0.0.10:8000
easytier-core \
  --local-port-forward udp://0.0.0.0:18000/10.0.0.10:8000 \
  # 其他参数 ...
```

CLI 支持多条规则，例如：

```bash
easytier-core \
  --local-port-forward tcp://0.0.0.0:15037/127.0.0.1:5037 \
  --local-port-forward udp://0.0.0.0:18000/10.0.0.10:8000
```

如果监听端仅填写端口（例如：`--local-port-forward tcp://15037/127.0.0.1:5037`），EasyTier 会在获取 DHCP IPv4 地址后自动绑定该地址，并在地址变化时自动刷新本地端口转发。


## 通过配置文件

如果使用 `config.toml` 等配置文件，可添加 `[[local_port_forward]]` 块：

```toml
[[local_port_forward]]
proto = "tcp"
listen = "0.0.0.0:15037"
target = "127.0.0.1:5037"

[[local_port_forward]]
proto = "udp"
listen = "0.0.0.0:18000"
target = "10.0.0.10:8000"
```

保存后重启 EasyTier 实例即可生效。

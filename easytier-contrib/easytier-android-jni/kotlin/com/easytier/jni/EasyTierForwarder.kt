package com.easytier.jni

/**
 * 本地 TCP 端口转发器封装。
 *
 * 监听 `127.0.0.1` 本地端口，把每条连接经 EasyTier data plane 转发到虚拟网络内的
 * 目标 IP:端口。适用于内嵌 EasyTier 但不使用 TUN/VpnService 的场景：应用内
 * 的 HTTP/TCP 客户端直接连接 `127.0.0.1:本地端口` 即可访问虚拟网络服务。
 *
 * 每个实例同一时刻只能有一个转发器（native data plane session 每实例仅一个）。
 */
object EasyTierForwarder {

    /**
     * 启动转发器。
     *
     * @param instanceName EasyTier 实例名称
     * @param targetIp 虚拟网络内的目标 IPv4 地址
     * @param targetPort 目标端口
     * @param listenPort 本地监听端口，传 0 由系统分配
     * @return 实际监听的本地端口
     * @throws RuntimeException 启动失败时抛出，消息来自 [EasyTierJNI.getLastError]
     */
    @JvmStatic
    fun start(instanceName: String, targetIp: String, targetPort: Int, listenPort: Int = 0): Int {
        val port = EasyTierJNI.startTcpForwarder(instanceName, targetIp, targetPort, listenPort)
        if (port < 0) {
            throw RuntimeException(EasyTierJNI.getLastError() ?: "forwarder start failed")
        }
        return port
    }

    /**
     * 停止转发器。
     * @param localPort [start] 返回的本地端口；不存在时静默成功
     */
    @JvmStatic
    fun stop(localPort: Int) {
        EasyTierJNI.stopTcpForwarder(localPort)
    }
}

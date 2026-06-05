package com.easytier.jni

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

fun interface ConfigServerEventCallback {
    fun onEvent(eventJson: String)
}

data class DataPlaneSocketAddress(val ip: String, val port: Int)

data class DataPlaneTcpConnectResult(val handle: Long, val localAddress: DataPlaneSocketAddress)

data class DataPlaneTcpBindResult(val handle: Long, val localAddress: DataPlaneSocketAddress)

data class DataPlaneTcpAcceptResult(
        val handle: Long,
        val localAddress: DataPlaneSocketAddress,
        val peerAddress: DataPlaneSocketAddress
)

data class DataPlaneTcpReadResult(val data: ByteArray)

data class DataPlaneUdpBindResult(val handle: Long, val localAddress: DataPlaneSocketAddress)

data class DataPlaneUdpRecvResult(
        val data: ByteArray,
        val peerAddress: DataPlaneSocketAddress
)

class DataPlaneTcpStream(
        val handle: Long,
        val localAddress: DataPlaneSocketAddress? = null,
        val peerAddress: DataPlaneSocketAddress? = null
) {
    suspend fun read(maxLength: Int, timeoutMs: Long): ByteArray =
            EasyTierJNI.tcpRead(this, maxLength, timeoutMs)

    suspend fun write(data: ByteArray, timeoutMs: Long): Int =
            EasyTierJNI.tcpWrite(this, data, timeoutMs)

    fun close(): Int = EasyTierJNI.dataPlaneTcpClose(handle)
}

class DataPlaneTcpListener(val handle: Long, val localAddress: DataPlaneSocketAddress) {
    suspend fun accept(timeoutMs: Long): DataPlaneTcpStream =
            EasyTierJNI.tcpAccept(this, timeoutMs)

    fun close(): Int = EasyTierJNI.dataPlaneTcpListenerClose(handle)
}

class DataPlaneUdpSocket(val handle: Long, val localAddress: DataPlaneSocketAddress) {
    suspend fun sendTo(
            dstIp: String,
            dstPort: Int,
            data: ByteArray,
            timeoutMs: Long
    ): Int = EasyTierJNI.udpSendTo(this, dstIp, dstPort, data, timeoutMs)

    suspend fun recvFrom(maxLength: Int, timeoutMs: Long): DataPlaneUdpRecvResult =
            EasyTierJNI.udpRecvFrom(this, maxLength, timeoutMs)

    fun close(): Int = EasyTierJNI.dataPlaneUdpClose(handle)
}

/** EasyTier JNI 接口类 提供 Android 应用调用 EasyTier 网络功能的接口 */
object EasyTierJNI {
    private const val DATA_PLANE_OP_PENDING = 0
    private const val DATA_PLANE_OP_READY = 1
    private const val DATA_PLANE_OP_FAILED = -1
    private const val DATA_PLANE_OP_INVALID = -2
    private const val DATA_PLANE_WAIT_SLICE_MS = 50L

    init {
        // 加载本地库
        System.loadLibrary("easytier_android_jni")
    }

    /**
     * 设置 TUN 文件描述符
     * @param instanceName 实例名称
     * @param fd TUN 文件描述符
     * @return 0 表示成功，-1 表示失败
     * @throws RuntimeException 当操作失败时抛出异常
     */
    @JvmStatic external fun setTunFd(instanceName: String, fd: Int): Int

    /**
     * 解析配置字符串
     * @param config TOML 格式的配置字符串
     * @return 0 表示成功，-1 表示失败
     * @throws RuntimeException 当配置解析失败时抛出异常
     */
    @JvmStatic external fun parseConfig(config: String): Int

    /**
     * 运行网络实例
     * @param config TOML 格式的配置字符串
     * @return 0 表示成功，-1 表示失败
     * @throws RuntimeException 当实例启动失败时抛出异常
     */
    @JvmStatic external fun runNetworkInstance(config: String): Int

    /**
     * 启动配置服务器客户端
     * @param url 配置服务器 URL
     * @param hostname 主机名，传入 null 使用系统主机名
     * @param machineId 稳定机器 ID，由调用方负责持久化
     * @param secureMode 是否启用 secure mode
     * @param callback 远程配置应用/删除事件回调
     * @return 0 表示成功，-1 表示失败
     * @throws RuntimeException 当客户端启动失败时抛出异常
     */
    @JvmStatic
    external fun startConfigServerClient(
            url: String,
            hostname: String?,
            machineId: String,
            secureMode: Boolean,
            callback: ConfigServerEventCallback?
    ): Int

    /**
     * 停止配置服务器客户端
     * @return 0 表示成功，-1 表示失败
     * @throws RuntimeException 当客户端停止失败时抛出异常
     */
    @JvmStatic external fun stopConfigServerClient(): Int

    /** 查询配置服务器客户端是否已连接 */
    @JvmStatic external fun isConfigServerClientConnected(): Boolean

    /**
     * 保留指定的网络实例，停止其他实例
     * @param instanceNames 要保留的实例名称数组，传入 null 或空数组将停止所有实例
     * @return 0 表示成功，-1 表示失败
     * @throws RuntimeException 当操作失败时抛出异常
     */
    @JvmStatic external fun retainNetworkInstance(instanceNames: Array<String>?): Int

    /**
     * 收集网络信息
     * @param maxLength 最大返回条目数
     * @return 包含网络信息的 JSON 字符串
     * @throws RuntimeException 当操作失败时抛出异常
     */
    @JvmStatic external fun collectNetworkInfos(maxLength: Int): String?

    /**
     * 获取最后的错误消息
     * @return 错误消息字符串，如果没有错误则返回 null
     */
    @JvmStatic external fun getLastError(): String?

    @JvmStatic external fun dataPlaneAsyncOpStatus(handle: Long): Int

    @JvmStatic external fun dataPlaneAsyncOpWait(handle: Long, timeoutMs: Long): Int

    @JvmStatic external fun dataPlaneAsyncOpCancel(handle: Long): Int

    @JvmStatic external fun dataPlaneAsyncOpFree(handle: Long): Int

    @JvmStatic
    external fun dataPlaneTcpConnectStart(
            instanceName: String,
            dstIp: String,
            dstPort: Int,
            timeoutMs: Long
    ): Long

    @JvmStatic external fun dataPlaneTcpConnectFinish(op: Long): DataPlaneTcpConnectResult?

    @JvmStatic
    external fun dataPlaneTcpBindStart(
            instanceName: String,
            localPort: Int,
            timeoutMs: Long
    ): Long

    @JvmStatic external fun dataPlaneTcpBindFinish(op: Long): DataPlaneTcpBindResult?

    @JvmStatic external fun dataPlaneTcpAcceptStart(handle: Long, timeoutMs: Long): Long

    @JvmStatic external fun dataPlaneTcpAcceptFinish(op: Long): DataPlaneTcpAcceptResult?

    @JvmStatic external fun dataPlaneTcpReadStart(handle: Long, maxLength: Int, timeoutMs: Long): Long

    @JvmStatic external fun dataPlaneTcpReadFinish(op: Long): DataPlaneTcpReadResult?

    @JvmStatic external fun dataPlaneTcpWriteStart(handle: Long, data: ByteArray, timeoutMs: Long): Long

    @JvmStatic external fun dataPlaneTcpWriteFinish(op: Long): Int

    @JvmStatic
    external fun dataPlaneUdpBindStart(
            instanceName: String,
            localPort: Int,
            timeoutMs: Long
    ): Long

    @JvmStatic external fun dataPlaneUdpBindFinish(op: Long): DataPlaneUdpBindResult?

    @JvmStatic
    external fun dataPlaneUdpSendToStart(
            handle: Long,
            dstIp: String,
            dstPort: Int,
            data: ByteArray,
            timeoutMs: Long
    ): Long

    @JvmStatic external fun dataPlaneUdpSendToFinish(op: Long): Int

    @JvmStatic external fun dataPlaneUdpRecvFromStart(handle: Long, maxLength: Int, timeoutMs: Long): Long

    @JvmStatic external fun dataPlaneUdpRecvFromFinish(op: Long): DataPlaneUdpRecvResult?

    @JvmStatic external fun dataPlaneTcpClose(handle: Long): Int

    @JvmStatic external fun dataPlaneTcpListenerClose(handle: Long): Int

    @JvmStatic external fun dataPlaneUdpClose(handle: Long): Int

    /**
     * 便利方法：停止所有网络实例
     * @return 0 表示成功，-1 表示失败
     * @throws RuntimeException 当操作失败时抛出异常
     */
    @JvmStatic
    fun stopAllInstances(): Int {
        return retainNetworkInstance(null)
    }

    /**
     * 便利方法：停止指定实例外的所有实例
     * @param instanceName 要保留的实例名称
     * @return 0 表示成功，-1 表示失败
     * @throws RuntimeException 当操作失败时抛出异常
     */
    @JvmStatic
    fun retainSingleInstance(instanceName: String): Int {
        return retainNetworkInstance(arrayOf(instanceName))
    }

    @JvmStatic
    suspend fun tcpConnect(
            instanceName: String,
            dstIp: String,
            dstPort: Int,
            timeoutMs: Long
    ): DataPlaneTcpStream {
        val op = requireOp(dataPlaneTcpConnectStart(instanceName, dstIp, dstPort, timeoutMs))
        val result = awaitOp(op) {
            dataPlaneTcpConnectFinish(it) ?: throw lastDataPlaneException()
        }
        return DataPlaneTcpStream(result.handle, result.localAddress)
    }

    @JvmStatic
    suspend fun tcpBind(
            instanceName: String,
            localPort: Int,
            timeoutMs: Long
    ): DataPlaneTcpListener {
        val op = requireOp(dataPlaneTcpBindStart(instanceName, localPort, timeoutMs))
        val result = awaitOp(op) {
            dataPlaneTcpBindFinish(it) ?: throw lastDataPlaneException()
        }
        return DataPlaneTcpListener(result.handle, result.localAddress)
    }

    @JvmStatic
    suspend fun tcpAccept(listener: DataPlaneTcpListener, timeoutMs: Long): DataPlaneTcpStream {
        val op = requireOp(dataPlaneTcpAcceptStart(listener.handle, timeoutMs))
        val result = awaitOp(op) {
            dataPlaneTcpAcceptFinish(it) ?: throw lastDataPlaneException()
        }
        return DataPlaneTcpStream(result.handle, result.localAddress, result.peerAddress)
    }

    @JvmStatic
    suspend fun tcpRead(
            stream: DataPlaneTcpStream,
            maxLength: Int,
            timeoutMs: Long
    ): ByteArray {
        val op = requireOp(dataPlaneTcpReadStart(stream.handle, maxLength, timeoutMs))
        return awaitOp(op) {
            dataPlaneTcpReadFinish(it)?.data ?: throw lastDataPlaneException()
        }
    }

    @JvmStatic
    suspend fun tcpWrite(stream: DataPlaneTcpStream, data: ByteArray, timeoutMs: Long): Int {
        val op = requireOp(dataPlaneTcpWriteStart(stream.handle, data, timeoutMs))
        return awaitOp(op) { dataPlaneTcpWriteFinish(it) }
    }

    @JvmStatic
    suspend fun udpBind(
            instanceName: String,
            localPort: Int,
            timeoutMs: Long
    ): DataPlaneUdpSocket {
        val op = requireOp(dataPlaneUdpBindStart(instanceName, localPort, timeoutMs))
        val result = awaitOp(op) {
            dataPlaneUdpBindFinish(it) ?: throw lastDataPlaneException()
        }
        return DataPlaneUdpSocket(result.handle, result.localAddress)
    }

    @JvmStatic
    suspend fun udpSendTo(
            socket: DataPlaneUdpSocket,
            dstIp: String,
            dstPort: Int,
            data: ByteArray,
            timeoutMs: Long
    ): Int {
        val op = requireOp(dataPlaneUdpSendToStart(socket.handle, dstIp, dstPort, data, timeoutMs))
        return awaitOp(op) { dataPlaneUdpSendToFinish(it) }
    }

    @JvmStatic
    suspend fun udpRecvFrom(
            socket: DataPlaneUdpSocket,
            maxLength: Int,
            timeoutMs: Long
    ): DataPlaneUdpRecvResult {
        val op = requireOp(dataPlaneUdpRecvFromStart(socket.handle, maxLength, timeoutMs))
        return awaitOp(op) {
            dataPlaneUdpRecvFromFinish(it) ?: throw lastDataPlaneException()
        }
    }

    private fun requireOp(op: Long): Long {
        if (op == 0L) {
            throw lastDataPlaneException()
        }
        return op
    }

    private suspend fun <T> awaitOp(op: Long, finish: (Long) -> T): T =
            withContext(Dispatchers.IO) {
                var consumed = false
                try {
                    awaitReady(op)
                    val result = finish(op)
                    consumed = true
                    result
                } catch (e: CancellationException) {
                    dataPlaneAsyncOpCancel(op)
                    throw e
                } finally {
                    if (!consumed) {
                        dataPlaneAsyncOpFree(op)
                    }
                }
            }

    private suspend fun awaitReady(op: Long) {
        while (true) {
            currentCoroutineContext().ensureActive()
            when (dataPlaneAsyncOpWait(op, DATA_PLANE_WAIT_SLICE_MS)) {
                DATA_PLANE_OP_READY, DATA_PLANE_OP_FAILED -> return
                DATA_PLANE_OP_PENDING -> Unit
                DATA_PLANE_OP_INVALID -> throw RuntimeException("Data-plane async operation is invalid")
                else -> throw RuntimeException("Unknown data-plane async operation status")
            }
        }
    }

    private fun lastDataPlaneException(): RuntimeException {
        return RuntimeException(getLastError() ?: "EasyTier data-plane call failed")
    }
}

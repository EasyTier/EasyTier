package com.easytier.jni

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

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
            EasyTierDataPlane.tcpRead(this, maxLength, timeoutMs)

    suspend fun write(data: ByteArray, timeoutMs: Long): Int =
            EasyTierDataPlane.tcpWrite(this, data, timeoutMs)

    fun close(): Int = EasyTierDataPlaneJNI.dataPlaneTcpClose(handle)
}

class DataPlaneTcpListener(val handle: Long, val localAddress: DataPlaneSocketAddress) {
    suspend fun accept(timeoutMs: Long): DataPlaneTcpStream =
            EasyTierDataPlane.tcpAccept(this, timeoutMs)

    fun close(): Int = EasyTierDataPlaneJNI.dataPlaneTcpListenerClose(handle)
}

class DataPlaneUdpSocket(val handle: Long, val localAddress: DataPlaneSocketAddress) {
    suspend fun sendTo(
            dstIp: String,
            dstPort: Int,
            data: ByteArray,
            timeoutMs: Long
    ): Int = EasyTierDataPlane.udpSendTo(this, dstIp, dstPort, data, timeoutMs)

    suspend fun recvFrom(maxLength: Int, timeoutMs: Long): DataPlaneUdpRecvResult =
            EasyTierDataPlane.udpRecvFrom(this, maxLength, timeoutMs)

    fun close(): Int = EasyTierDataPlaneJNI.dataPlaneUdpClose(handle)
}

/** Low-level native data-plane JNI entry points. Prefer EasyTierDataPlane. */
object EasyTierDataPlaneJNI {
    init {
        System.loadLibrary("easytier_android_jni")
    }

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
}

/** Coroutine-friendly Android data-plane API. */
object EasyTierDataPlane {
    private const val DATA_PLANE_OP_PENDING = 0
    private const val DATA_PLANE_OP_READY = 1
    private const val DATA_PLANE_OP_FAILED = -1
    private const val DATA_PLANE_OP_INVALID = -2
    private const val DATA_PLANE_WAIT_SLICE_MS = 50L

    @JvmStatic
    suspend fun tcpConnect(
            instanceName: String,
            dstIp: String,
            dstPort: Int,
            timeoutMs: Long
    ): DataPlaneTcpStream {
        val op =
                requireOp(
                        EasyTierDataPlaneJNI.dataPlaneTcpConnectStart(
                                instanceName,
                                dstIp,
                                dstPort,
                                timeoutMs
                        )
                )
        val result = awaitOp(op) {
            EasyTierDataPlaneJNI.dataPlaneTcpConnectFinish(it) ?: throw lastDataPlaneException()
        }
        return DataPlaneTcpStream(result.handle, result.localAddress)
    }

    @JvmStatic
    suspend fun tcpBind(
            instanceName: String,
            localPort: Int,
            timeoutMs: Long
    ): DataPlaneTcpListener {
        val op =
                requireOp(
                        EasyTierDataPlaneJNI.dataPlaneTcpBindStart(
                                instanceName,
                                localPort,
                                timeoutMs
                        )
                )
        val result = awaitOp(op) {
            EasyTierDataPlaneJNI.dataPlaneTcpBindFinish(it) ?: throw lastDataPlaneException()
        }
        return DataPlaneTcpListener(result.handle, result.localAddress)
    }

    @JvmStatic
    suspend fun tcpAccept(listener: DataPlaneTcpListener, timeoutMs: Long): DataPlaneTcpStream {
        val op =
                requireOp(
                        EasyTierDataPlaneJNI.dataPlaneTcpAcceptStart(listener.handle, timeoutMs)
                )
        val result = awaitOp(op) {
            EasyTierDataPlaneJNI.dataPlaneTcpAcceptFinish(it) ?: throw lastDataPlaneException()
        }
        return DataPlaneTcpStream(result.handle, result.localAddress, result.peerAddress)
    }

    @JvmStatic
    suspend fun tcpRead(
            stream: DataPlaneTcpStream,
            maxLength: Int,
            timeoutMs: Long
    ): ByteArray {
        val op =
                requireOp(
                        EasyTierDataPlaneJNI.dataPlaneTcpReadStart(
                                stream.handle,
                                maxLength,
                                timeoutMs
                        )
                )
        return awaitOp(op) {
            EasyTierDataPlaneJNI.dataPlaneTcpReadFinish(it)?.data
                    ?: throw lastDataPlaneException()
        }
    }

    @JvmStatic
    suspend fun tcpWrite(stream: DataPlaneTcpStream, data: ByteArray, timeoutMs: Long): Int {
        val op =
                requireOp(
                        EasyTierDataPlaneJNI.dataPlaneTcpWriteStart(
                                stream.handle,
                                data,
                                timeoutMs
                        )
                )
        return awaitOp(op) { EasyTierDataPlaneJNI.dataPlaneTcpWriteFinish(it) }
    }

    @JvmStatic
    suspend fun udpBind(
            instanceName: String,
            localPort: Int,
            timeoutMs: Long
    ): DataPlaneUdpSocket {
        val op =
                requireOp(
                        EasyTierDataPlaneJNI.dataPlaneUdpBindStart(
                                instanceName,
                                localPort,
                                timeoutMs
                        )
                )
        val result = awaitOp(op) {
            EasyTierDataPlaneJNI.dataPlaneUdpBindFinish(it) ?: throw lastDataPlaneException()
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
        val op =
                requireOp(
                        EasyTierDataPlaneJNI.dataPlaneUdpSendToStart(
                                socket.handle,
                                dstIp,
                                dstPort,
                                data,
                                timeoutMs
                        )
                )
        return awaitOp(op) { EasyTierDataPlaneJNI.dataPlaneUdpSendToFinish(it) }
    }

    @JvmStatic
    suspend fun udpRecvFrom(
            socket: DataPlaneUdpSocket,
            maxLength: Int,
            timeoutMs: Long
    ): DataPlaneUdpRecvResult {
        val op =
                requireOp(
                        EasyTierDataPlaneJNI.dataPlaneUdpRecvFromStart(
                                socket.handle,
                                maxLength,
                                timeoutMs
                        )
                )
        return awaitOp(op) {
            EasyTierDataPlaneJNI.dataPlaneUdpRecvFromFinish(it) ?: throw lastDataPlaneException()
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
                    EasyTierDataPlaneJNI.dataPlaneAsyncOpCancel(op)
                    throw e
                } finally {
                    if (!consumed) {
                        EasyTierDataPlaneJNI.dataPlaneAsyncOpFree(op)
                    }
                }
            }

    private suspend fun awaitReady(op: Long) {
        while (true) {
            currentCoroutineContext().ensureActive()
            when (EasyTierDataPlaneJNI.dataPlaneAsyncOpWait(op, DATA_PLANE_WAIT_SLICE_MS)) {
                DATA_PLANE_OP_READY, DATA_PLANE_OP_FAILED -> return
                DATA_PLANE_OP_PENDING -> Unit
                DATA_PLANE_OP_INVALID -> throw RuntimeException("Data-plane async operation is invalid")
                else -> throw RuntimeException("Unknown data-plane async operation status")
            }
        }
    }

    private fun lastDataPlaneException(): RuntimeException {
        return RuntimeException(EasyTierJNI.getLastError() ?: "EasyTier data-plane call failed")
    }
}

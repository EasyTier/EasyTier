package com.easytier.jni

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

/**
 * EasyTier data-plane API for Android.
 *
 * Dataplane APIs do not create or start an EasyTier instance by themselves.
 * Start an instance with [EasyTierJNI.runNetworkInstance] first, then pass the
 * same `instanceName` to [EasyTierDataPlane.tcpConnect],
 * [EasyTierDataPlane.tcpBind], or [EasyTierDataPlane.udpBind]. If that instance
 * is not running, the native start call fails and the coroutine wrapper throws
 * the last EasyTier FFI error.
 *
 * Typical setup:
 * ```
 * val instanceName = "android-dataplane-demo"
 * val config = """
 *     instance_name = "$instanceName"
 *     ipv4 = "10.144.0.1"
 *     listeners = ["tcp://0.0.0.0:11010"]
 *
 *     [network_identity]
 *     network_name = "android-dataplane-demo"
 *     network_secret = "replace-with-a-real-secret"
 *
 *     [[peer]]
 *     uri = "tcp://peer.example.com:11010"
 *
 *     [flags]
 *     no_tun = true
 *     bind_device = false
 * """.trimIndent()
 *
 * EasyTierJNI.runNetworkInstance(config)
 * ```
 *
 * After the instance is running, most callers should use [EasyTierDataPlane]
 * and the socket/stream classes below. [EasyTierDataPlaneJNI] is the low-level
 * native op-handle ABI used by the coroutine wrappers.
 *
 * TCP client usage:
 * ```
 * val stream = EasyTierDataPlane.tcpConnect(instanceName, "10.144.0.2", 8080, 5_000)
 * try {
 *     stream.write("ping".toByteArray(), 5_000)
 *     val reply = stream.read(4096, 5_000)
 * } finally {
 *     stream.close()
 * }
 * ```
 *
 * TCP server usage:
 * ```
 * val listener = EasyTierDataPlane.tcpBind(instanceName, 8080, 5_000)
 * try {
 *     val stream = listener.accept(30_000)
 *     try {
 *         stream.write(stream.read(4096, 5_000), 5_000)
 *     } finally {
 *         stream.close()
 *     }
 * } finally {
 *     listener.close()
 * }
 * ```
 *
 * UDP usage:
 * ```
 * val socket = EasyTierDataPlane.udpBind(instanceName, 0, 5_000)
 * try {
 *     socket.sendTo("10.144.0.2", 9000, "ping".toByteArray(), 5_000)
 *     val packet = socket.recvFrom(4096, 5_000)
 * } finally {
 *     socket.close()
 * }
 * ```
 *
 * Operation model:
 * - Each suspend function starts one native async op, waits on Dispatchers.IO,
 *   then consumes the op with the matching finish call.
 * - Coroutine cancellation cancels and frees the native op.
 * - Returned stream/listener/socket handles must be closed by the caller.
 * - Input ByteArray data is copied by the native start call; output data is
 *   copied into Kotlin ByteArray before the native buffer is freed.
 */

/** Data-plane IPv4/port pair returned by EasyTier FFI. */
data class DataPlaneSocketAddress(val ip: String, val port: Int)

/** Result of a completed TCP connect op. */
data class DataPlaneTcpConnectResult(val handle: Long, val localAddress: DataPlaneSocketAddress)

/** Result of a completed TCP bind op. */
data class DataPlaneTcpBindResult(val handle: Long, val localAddress: DataPlaneSocketAddress)

/** Result of a completed TCP accept op. */
data class DataPlaneTcpAcceptResult(
        val handle: Long,
        val localAddress: DataPlaneSocketAddress,
        val peerAddress: DataPlaneSocketAddress
)

/** Result of a completed TCP read op. */
data class DataPlaneTcpReadResult(val data: ByteArray)

/** Result of a completed UDP bind op. */
data class DataPlaneUdpBindResult(val handle: Long, val localAddress: DataPlaneSocketAddress)

/** Result of a completed UDP recv_from op. */
data class DataPlaneUdpRecvResult(
        val data: ByteArray,
        val peerAddress: DataPlaneSocketAddress
)

/** TCP data-plane stream handle. Call [close] when the stream is no longer needed. */
class DataPlaneTcpStream(
        val handle: Long,
        val localAddress: DataPlaneSocketAddress? = null,
        val peerAddress: DataPlaneSocketAddress? = null
) {
    /** Read up to [maxLength] bytes, waiting at most [timeoutMs] in native code. */
    suspend fun read(maxLength: Int, timeoutMs: Long): ByteArray =
            EasyTierDataPlane.tcpRead(this, maxLength, timeoutMs)

    /** Write [data], waiting at most [timeoutMs] in native code. */
    suspend fun write(data: ByteArray, timeoutMs: Long): Int =
            EasyTierDataPlane.tcpWrite(this, data, timeoutMs)

    /** Close the native TCP stream handle. */
    fun close(): Int = EasyTierDataPlaneJNI.dataPlaneTcpClose(handle)
}

/** TCP data-plane listener handle. Call [close] when the listener is no longer needed. */
class DataPlaneTcpListener(val handle: Long, val localAddress: DataPlaneSocketAddress) {
    /** Accept one TCP data-plane stream. */
    suspend fun accept(timeoutMs: Long): DataPlaneTcpStream =
            EasyTierDataPlane.tcpAccept(this, timeoutMs)

    /** Close the native TCP listener handle. */
    fun close(): Int = EasyTierDataPlaneJNI.dataPlaneTcpListenerClose(handle)
}

/** UDP data-plane socket handle. Call [close] when the socket is no longer needed. */
class DataPlaneUdpSocket(val handle: Long, val localAddress: DataPlaneSocketAddress) {
    /** Send one UDP datagram to [dstIp]:[dstPort]. */
    suspend fun sendTo(
            dstIp: String,
            dstPort: Int,
            data: ByteArray,
            timeoutMs: Long
    ): Int = EasyTierDataPlane.udpSendTo(this, dstIp, dstPort, data, timeoutMs)

    /** Receive one UDP datagram and its peer address. */
    suspend fun recvFrom(maxLength: Int, timeoutMs: Long): DataPlaneUdpRecvResult =
            EasyTierDataPlane.udpRecvFrom(this, maxLength, timeoutMs)

    /** Close the native UDP socket handle. */
    fun close(): Int = EasyTierDataPlaneJNI.dataPlaneUdpClose(handle)
}

/**
 * Low-level native data-plane JNI entry points.
 *
 * These functions mirror the Rust FFI op-handle ABI directly. They are exposed
 * for completeness, but most Android callers should use [EasyTierDataPlane]
 * instead so coroutine cancellation and op cleanup are handled consistently.
 */
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

    /** Connect to a TCP endpoint through the named EasyTier instance. */
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

    /** Bind a TCP data-plane listener on [localPort]. Port 0 asks EasyTier to allocate one. */
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

    /** Accept one TCP stream from [listener]. */
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

    /** Read up to [maxLength] bytes from [stream]. */
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

    /** Write [data] to [stream]. */
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

    /** Bind a UDP data-plane socket on [localPort]. Port 0 asks EasyTier to allocate one. */
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

    /** Send one UDP datagram through [socket]. */
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

    /** Receive one UDP datagram through [socket]. */
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

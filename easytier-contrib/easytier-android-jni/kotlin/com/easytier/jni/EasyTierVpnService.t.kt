package com.easytier.jni

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlin.concurrent.thread

class EasyTierVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false
    private var instanceName: String? = null

    companion object {
        private const val TAG = "EasyTierVpnService"
    }

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "VPN Service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // 获取传入的参数
        val ipv4Address = intent?.getStringExtra("ipv4_address")
        val proxyCidrs = intent?.getStringArrayListExtra("proxy_cidrs") ?: arrayListOf()
        instanceName = intent?.getStringExtra("instance_name")

        if (ipv4Address == null || instanceName == null) {
            Log.e(TAG, "缺少必要参数: ipv4Address=$ipv4Address, instanceName=$instanceName")
            stopSelf()
            return START_NOT_STICKY
        }

        Log.i(
                TAG,
                "启动 VPN Service - IPv4: $ipv4Address, Proxy CIDRs: $proxyCidrs, Instance: $instanceName"
        )

        thread {
            try {
                setupVpnInterface(ipv4Address, proxyCidrs)
            } catch (t: Throwable) {
                Log.e(TAG, "VPN 设置失败", t)
                stopSelf()
            }
        }

        return START_STICKY
    }

    private fun setupVpnInterface(ipv4Address: String, proxyCidrs: List<String>) {
        try {
            // 解析 IPv4 地址和网络长度
            val (ip, networkLength) = parseIpv4Address(ipv4Address)

            // 1. 准备 VpnService.Builder
            val builder = Builder()
            builder.setSession("EasyTier VPN")
                    .addAddress(ip, networkLength)
                    .addDnsServer("223.5.5.5")
                    .addDnsServer("114.114.114.114")
                    .addDisallowedApplication("com.easytier.easytiervpn")

            // 2. 添加路由表 - 为每个 proxy CIDR 添加路由
            proxyCidrs.forEach { cidr ->
                try {
                    val (routeIp, routeLength) = parseCidr(cidr)
                    builder.addRoute(routeIp, routeLength)
                    Log.d(TAG, "添加路由: $routeIp/$routeLength")
                } catch (e: Exception) {
                    Log.w(TAG, "解析 CIDR 失败: $cidr", e)
                }
            }

            // 3. 构建虚拟网络接口
            vpnInterface = builder.establish()

            if (vpnInterface == null) {
                Log.e(TAG, "创建 VPN 接口失败")
                return
            }

            Log.i(TAG, "VPN 接口创建成功")

            // 4. 将 TUN 文件描述符传递给 EasyTier
            instanceName?.let { name ->
                val fd = vpnInterface!!.fd
                val result = EasyTierJNI.setTunFd(name, fd)
                if (result == 0) {
                    Log.i(TAG, "TUN 文件描述符设置成功: $fd")
                } else {
                    Log.e(TAG, "TUN 文件描述符设置失败: $result")
                }
            }

            isRunning = true

            // 5. 保持服务运行
            while (isRunning && vpnInterface != null) {
                Thread.sleep(1000)
            }
        } catch (t: Throwable) {
            Log.e(TAG, "VPN 接口设置过程中发生错误", t)
        } finally {
            cleanup()
        }
    }

    /** 解析 IPv4 地址，返回 IP 和网络长度 */
    private fun parseIpv4Address(ipv4Address: String): Pair<String, Int> {
        return if (ipv4Address.contains("/")) {
            val parts = ipv4Address.split("/")
            Pair(parts[0], parts[1].toInt())
        } else {
            // 默认使用 /24 网络
            Pair(ipv4Address, 24)
        }
    }

    /** 解析 CIDR，返回 IP 和网络长度 */
    private fun parseCidr(cidr: String): Pair<String, Int> {
        val parts = cidr.split("/")
        if (parts.size != 2) {
            throw IllegalArgumentException("无效的 CIDR 格式: $cidr")
        }
        return Pair(parts[0], parts[1].toInt())
    }

    private fun cleanup() {
        isRunning = false
        vpnInterface?.close()
        vpnInterface = null
        Log.i(TAG, "VPN 接口已清理")
    }

    override fun onDestroy() {
        super.onDestroy()
        Log.d(TAG, "VPN Service destroyed")
        cleanup()
    }
}

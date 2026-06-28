package com.plugin.vpnservice

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Bundle
import java.net.InetAddress
import java.util.Arrays

import app.tauri.plugin.JSObject

class TauriVpnService : VpnService() {
    companion object {
        @JvmField var triggerCallback: (String, JSObject) -> Unit = { _, _ -> }
        @JvmField var self: TauriVpnService? = null
        @JvmField var ipv4Addr: String? = null
        @JvmField var ipv4Addrs: Array<String> = emptyArray()
        @JvmField var routes: Array<String> = emptyArray()
        @JvmField var dns: String? = null

        const val IPV4_ADDR = "IPV4_ADDR"
        const val IPV4_ADDRS = "IPV4_ADDRS"
        const val ROUTES = "ROUTES"
        const val DNS = "DNS"
        const val DISALLOWED_APPLICATIONS = "DISALLOWED_APPLICATIONS"
        const val MTU = "MTU"
    }

    private lateinit var vpnInterface: ParcelFileDescriptor

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        println("vpn on start command ${intent?.getExtras()} $intent")
        var args = intent?.getExtras()
        ipv4Addrs = getIpv4Addrs(args)
        ipv4Addr = ipv4Addrs.firstOrNull()
        routes = args?.getStringArray(ROUTES) ?: emptyArray()
        dns = args?.getString(DNS)

        vpnInterface = createVpnInterface(args)
        println("vpn created ${vpnInterface.fd}")

        var event_data = JSObject()
        event_data.put("fd", vpnInterface.fd)
        triggerCallback("vpn_service_start", event_data)

        return START_STICKY
    }

    override fun onCreate() {
        super.onCreate()
        self = this
        println("vpn on create")
    }

    override fun onDestroy() {
        println("vpn on destroy")
        super.onDestroy()
        disconnect()
        self = null
    }

    override fun onRevoke() {
        println("vpn on revoke")
        super.onRevoke()
        disconnect()
        self = null
    }

    private fun disconnect() {
        if (self == this && this::vpnInterface.isInitialized) {
            triggerCallback("vpn_service_stop", JSObject())
            vpnInterface.close()
        }
        clearStatus()
    }

    private fun clearStatus() {
        ipv4Addr = null
        ipv4Addrs = emptyArray()
        routes = emptyArray()
        dns = null
    }

    private fun getIpv4Addrs(args: Bundle?): Array<String> {
        val ipv4Addrs = args
            ?.getStringArray(IPV4_ADDRS)
            ?.filter { it.isNotBlank() }
            ?.toTypedArray()
            ?: emptyArray()
        if (ipv4Addrs.isNotEmpty()) {
            return ipv4Addrs
        }

        return arrayOf(args?.getString(IPV4_ADDR) ?: "10.126.126.1/24")
    }

    private fun createVpnInterface(args: Bundle?): ParcelFileDescriptor {
        var builder = Builder()
                .setSession("TauriVpnService")
                .setBlocking(false)
        
        var mtu = args?.getInt(MTU) ?: 1500
        var ipv4Addrs = getIpv4Addrs(args)
        var dns: String? = args?.getString(DNS)
        var routes = args?.getStringArray(ROUTES) ?: emptyArray()
        var disallowedApplications = args?.getStringArray(DISALLOWED_APPLICATIONS) ?: emptyArray()

        println("vpn create vpn interface. mtu: $mtu, ipv4Addrs: ${java.util.Arrays.toString(ipv4Addrs)}, dns:" +
            "$dns, routes: ${java.util.Arrays.toString(routes)}," +
            "disallowedApplications:  ${java.util.Arrays.toString(disallowedApplications)}")

        for (ipv4Addr in ipv4Addrs) {
            val ipParts = ipv4Addr.split("/")
            if (ipParts.size != 2) throw IllegalArgumentException("Invalid IP addr string")
            builder.addAddress(ipParts[0], ipParts[1].toInt())
        }
        builder.addAddress("fd00::1", 128)

        builder.setMtu(mtu)
        dns?.let { builder.addDnsServer(it) }

        for (route in routes) {
            val ipParts = route.split("/")
            if (ipParts.size != 2) throw IllegalArgumentException("Invalid route cidr string")
            builder.addRoute(ipParts[0], ipParts[1].toInt())
        }
        
        for (app in disallowedApplications) {
            builder.addDisallowedApplication(app)
        }

        return builder.also {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                it.setMetered(false)
            }
        }
        .establish()
        ?: throw IllegalStateException("Failed to init VpnService")
    }
}

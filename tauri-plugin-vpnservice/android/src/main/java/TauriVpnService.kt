package com.plugin.vpnservice

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor

import app.tauri.plugin.JSObject

class TauriVpnService : VpnService() {
    companion object {
        @JvmField var triggerCallback: (String, JSObject) -> Unit = { _, _ -> }
    }

    private lateinit var vpnInterface: ParcelFileDescriptor

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {

        return START_STICKY
    }

    override fun onCreate() {
        super.onCreate()
        println("xxxx create")
        connect()
    }

    override fun onDestroy() {
        super.onDestroy()
        disconnect()
    }

    private fun connect(): Int {
        vpnInterface = createVpnInterface()
        println("vpn created ${vpnInterface.fd}")

        var event_data = JSObject()
        event_data.put("fd", vpnInterface.fd)
        triggerCallback("vpn_service_start", event_data)

        return vpnInterface.fd
    }

    private fun disconnect() {
        vpnInterface.close()
    }

    private fun createVpnInterface(): ParcelFileDescriptor {
        return Builder()
                .addAddress("10.126.126.1", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("114.114.114.114")
                .setMtu(1500)
                .setSession("EasyTier")
                .setBlocking(false)
                .addDisallowedApplication("com.kkrainbow.easytier")
                .also {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        it.setMetered(false)
                    }
                }
                .establish()
                ?: throw IllegalStateException("Failed to init VpnService")
    }
}

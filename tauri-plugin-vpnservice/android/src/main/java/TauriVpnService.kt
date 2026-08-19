package com.plugin.vpnservice

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import app.tauri.plugin.JSObject
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import org.json.JSONObject

class TauriVpnService : VpnService() {
    companion object {
        @JvmField var triggerCallback: (String, JSObject) -> Unit = { _, _ -> }
        @JvmField var self: TauriVpnService? = null
        @JvmField var ipv4Addr: String? = null
        @JvmField var routes: Array<String> = emptyArray()
        @JvmField var dns: String? = null

        const val IPV4_ADDR = "IPV4_ADDR"
        const val INSTANCE_ID = "INSTANCE_ID"
        const val ROUTES = "ROUTES"
        const val DNS = "DNS"
        const val DISALLOWED_APPLICATIONS = "DISALLOWED_APPLICATIONS"
        const val MTU = "MTU"

        const val ACTION_START_HEADLESS = "com.plugin.vpnservice.action.START_HEADLESS"
        const val ACTION_ATTACH_EXISTING = "com.plugin.vpnservice.action.ATTACH_EXISTING"
        const val ACTION_STOP = "com.plugin.vpnservice.action.STOP"
        const val ACTION_DETACH = "com.plugin.vpnservice.action.DETACH"

        private const val PREFS_NAME = "easytier_headless_vpn"
        private const val PROFILE_TOML = "profile_toml"
        private const val PROCESS_TOKEN = "process_token"
        private const val CHANNEL_ID = "easytier_vpn"
        private const val NOTIFICATION_ID = 1357
        private val processToken = java.util.UUID.randomUUID().toString()

        fun createIntent(context: Context, action: String): Intent =
            Intent(context, TauriVpnService::class.java)
                .setAction(action)
                .putExtra(PROCESS_TOKEN, processToken)

        fun saveHeadlessProfile(context: Context, configToml: String) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putString(PROFILE_TOML, configToml)
                .apply()
        }

        fun hasHeadlessProfile(context: Context): Boolean =
            !context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(PROFILE_TOML, null)
                .isNullOrBlank()

    }

    private val worker = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "easytier-vpn-service")
    }
    private val operationGeneration = AtomicInteger(0)
    @Volatile
    private var vpnInterface: ParcelFileDescriptor? = null
    @Volatile
    private var activeInstanceId: String? = null
    @Volatile
    private var connectionRequested = false

    fun isVpnActive(): Boolean = vpnInterface != null

    fun isVpnRequestedOrActive(): Boolean = connectionRequested || isVpnActive()

    override fun onCreate() {
        super.onCreate()
        self = this
        createNotificationChannel()
        EasyTierTileService.refreshVpnState(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.getStringExtra(PROCESS_TOKEN) != processToken) {
            EasyTierTileService.refreshVpnState(this)
            stopForeground(true)
            stopSelf()
            return START_NOT_STICKY
        }
        startForeground(NOTIFICATION_ID, buildNotification("Connecting…"))
        when (intent?.action) {
            ACTION_STOP -> dispatchStop(stopInstance = true)
            ACTION_DETACH -> dispatchStop(stopInstance = false)
            ACTION_START_HEADLESS -> dispatchHeadlessStart()
            ACTION_ATTACH_EXISTING -> dispatchAttachExisting(intent.extras)
            else -> dispatchStop(stopInstance = false)
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        operationGeneration.incrementAndGet()
        connectionRequested = false
        disconnectVpnInterface(true)
        worker.shutdownNow()
        if (self === this) {
            self = null
        }
        super.onDestroy()
    }

    override fun onRevoke() {
        dispatchStop(stopInstance = true)
        super.onRevoke()
    }

    private fun dispatchHeadlessStart() {
        val generation = operationGeneration.incrementAndGet()
        connectionRequested = true
        EasyTierTileService.refreshVpnState(this)
        worker.execute {
            var startedInstanceId: String? = null
            try {
                if (VpnService.prepare(this) != null) {
                    throw IllegalStateException("VPN permission is required; open EasyTier once and allow it")
                }
                val configToml = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                    .getString(PROFILE_TOML, null)
                    ?.takeIf { it.isNotBlank() }
                    ?: throw IllegalStateException("No saved TUN network; start one from EasyTier once")
                val result = parseNativeResult(HeadlessEasyTierBridge.start(configToml))
                val instanceId = result.getString("instanceId")
                startedInstanceId = instanceId
                if (generation != operationGeneration.get()) {
                    stopNativeInstance(instanceId)
                    return@execute
                }
                val args = Bundle().apply {
                    putString(INSTANCE_ID, instanceId)
                    putString(IPV4_ADDR, result.getString("ipv4Addr"))
                    putStringArray(ROUTES, jsonStringArray(result.optJSONArray("routes")))
                    result.optString("dns").takeIf { it.isNotEmpty() }?.let { putString(DNS, it) }
                    putStringArray(DISALLOWED_APPLICATIONS, arrayOf(packageName))
                    putInt(MTU, result.optInt("mtu", 1300))
                }
                establishAndAttach(args, generation)
            } catch (error: Exception) {
                failStart(error, generation, startedInstanceId)
            }
        }
    }

    private fun dispatchAttachExisting(args: Bundle?) {
        val generation = operationGeneration.incrementAndGet()
        connectionRequested = true
        worker.execute {
            try {
                if (VpnService.prepare(this) != null) {
                    throw IllegalStateException("VPN permission is required")
                }
                establishAndAttach(args, generation)
            } catch (error: Exception) {
                failStart(error, generation, null)
            }
        }
    }

    private fun establishAndAttach(args: Bundle?, generation: Int) {
        disconnectVpnInterface(false)
        val instanceId = args?.getString(INSTANCE_ID)
            ?.takeIf { it.isNotBlank() }
            ?: throw IllegalArgumentException("Missing EasyTier instance ID")
        val newInterface = createVpnInterface(args)
        if (generation != operationGeneration.get()) {
            newInterface.close()
            return
        }
        try {
            parseNativeResult(HeadlessEasyTierBridge.attachTunFd(instanceId, newInterface.fd))
        } catch (error: Exception) {
            newInterface.close()
            throw error
        }
        vpnInterface = newInterface
        activeInstanceId = instanceId
        ipv4Addr = args?.getString(IPV4_ADDR)
        routes = args?.getStringArray(ROUTES) ?: emptyArray()
        dns = args?.getString(DNS)
        EasyTierTileService.refreshVpnState(this)
        updateNotification("Connected")
        triggerCallback("vpn_service_start", JSObject().apply { put("instanceId", instanceId) })
    }

    private fun dispatchStop(stopInstance: Boolean) {
        val generation = operationGeneration.incrementAndGet()
        connectionRequested = false
        worker.execute {
            val instanceId = activeInstanceId
            disconnectVpnInterface(true)
            if (stopInstance && instanceId != null) {
                stopNativeInstance(instanceId)
            }
            if (generation == operationGeneration.get()) {
                stopForeground(true)
                stopSelf()
            }
        }
    }

    private fun failStart(error: Exception, generation: Int, startedInstanceId: String?) {
        println("headless EasyTier start failed: $error")
        if (generation != operationGeneration.get()) {
            if (startedInstanceId != null) stopNativeInstance(startedInstanceId)
            return
        }
        connectionRequested = false
        disconnectVpnInterface(true)
        if (startedInstanceId != null) stopNativeInstance(startedInstanceId)
        EasyTierTileService.setLastError(this, error.message ?: "Connection failed")
        stopForeground(true)
        stopSelf()
    }

    private fun disconnectVpnInterface(notify: Boolean) {
        val interfaceToClose = vpnInterface
        vpnInterface = null
        activeInstanceId = null
        if (interfaceToClose != null) {
            try {
                interfaceToClose.close()
            } catch (error: Exception) {
                println("vpn interface close failed: $error")
            }
            if (notify) triggerCallback("vpn_service_stop", JSObject())
        }
        ipv4Addr = null
        routes = emptyArray()
        dns = null
        EasyTierTileService.refreshVpnState(this)
    }

    private fun stopNativeInstance(instanceId: String) {
        try {
            parseNativeResult(HeadlessEasyTierBridge.stop(instanceId))
        } catch (error: Exception) {
            println("EasyTier instance $instanceId stop failed: $error")
        }
    }

    private fun createVpnInterface(args: Bundle?): ParcelFileDescriptor {
        val builder = Builder().setSession("EasyTier").setBlocking(false)
        val mtu = args?.getInt(MTU) ?: 1300
        val address = args?.getString(IPV4_ADDR)
            ?: throw IllegalArgumentException("Missing EasyTier IPv4 address")
        val ipParts = address.split("/")
        require(ipParts.size == 2) { "Invalid EasyTier IPv4 address" }
        builder.addAddress(ipParts[0], ipParts[1].toInt())
        builder.addAddress("fd00::1", 128)
        builder.setMtu(mtu)
        args?.getString(DNS)?.let(builder::addDnsServer)
        for (route in args?.getStringArray(ROUTES) ?: emptyArray()) {
            val routeParts = route.split("/")
            require(routeParts.size == 2) { "Invalid route: $route" }
            builder.addRoute(routeParts[0], routeParts[1].toInt())
        }
        for (application in args?.getStringArray(DISALLOWED_APPLICATIONS) ?: arrayOf(packageName)) {
            builder.addDisallowedApplication(application)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
        return builder.establish() ?: throw IllegalStateException("Failed to establish Android VPN")
    }

    private fun parseNativeResult(json: String): JSONObject {
        val result = JSONObject(json)
        if (!result.optBoolean("ok", false)) {
            throw IllegalStateException(result.optString("error", "Native EasyTier operation failed"))
        }
        return result
    }

    private fun jsonStringArray(array: org.json.JSONArray?): Array<String> {
        if (array == null) return emptyArray()
        return Array(array.length()) { index -> array.getString(index) }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "EasyTier VPN", NotificationManager.IMPORTANCE_LOW),
            )
        }
    }

    private fun buildNotification(status: String): Notification {
        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)
        val contentIntent = launchIntent?.let {
            PendingIntent.getActivity(
                this,
                0,
                it,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
        }
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(applicationInfo.icon)
            .setContentTitle("EasyTier")
            .setContentText(status)
            .setOngoing(true)
            .setContentIntent(contentIntent)
            .build()
    }

    private fun updateNotification(status: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification(status))
    }
}

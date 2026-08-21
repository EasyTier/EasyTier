package com.plugin.vpnservice

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.activity.result.ActivityResult
import app.tauri.annotation.Command
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import android.webkit.WebView

@InvokeArg
class PingArgs {
    var value: String? = null
}

@InvokeArg
class StartVpnArgs {
    var ipv4Addr: String? = null
    var routes: Array<String> = emptyArray()
    var dns: String? = null
    var disallowedApplications: Array<String> = emptyArray()
    var mtu: Int? = null
}

@InvokeArg
class SetAutoStopOnWifiArgs {
    var enabled: Boolean = false
}

@TauriPlugin
class VpnServicePlugin(private val activity: Activity) : Plugin(activity) {
    private val implementation = Example()
    private val mainHandler = Handler(Looper.getMainLooper())
    private var connectivityManager: ConnectivityManager? = null

    // Last successful VPN start args, used to resume the VPN when WiFi goes away.
    private var lastStartArgs: Bundle? = null
    // True when the VPN was paused by the WiFi auto-pause feature and should be resumed later.
    private var pausedByWifi = false
    private var pendingRestartRunnable: Runnable? = null

    private val wifiNetworkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            println("vpn: wifi available, pause vpn if running")
            cancelPendingRestart()
            stopVpnIfRunning(byWifi = true)
        }

        override fun onLost(network: Network) {
            println("vpn: wifi lost, schedule vpn resume")
            scheduleVpnRestart()
        }
    }

    private fun isWifiConnected(): Boolean {
        val cm = connectivityManager ?: return false
        for (network in cm.allNetworks) {
            val capabilities = cm.getNetworkCapabilities(network) ?: continue
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                return true
            }
        }
        return false
    }

    private fun stopVpnIfRunning(byWifi: Boolean) {
        if (TauriVpnService.self == null) {
            return
        }
        activity.runOnUiThread {
            println("vpn: pause vpn (byWifi=$byWifi)")
            pausedByWifi = byWifi
            if (byWifi) {
                cancelPendingRestart()
            }
            TauriVpnService.self?.onRevoke()
            activity.stopService(Intent(activity, TauriVpnService::class.java))
        }
    }

    // Covers the case where WiFi is already connected when the feature is enabled:
    // registerNetworkCallback only fires 'onAvailable' on future connect events.
    private fun stopIfWifiConnected() {
        val cm = connectivityManager ?: return
        for (network in cm.allNetworks) {
            val capabilities = cm.getNetworkCapabilities(network) ?: continue
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                stopVpnIfRunning(byWifi = true)
                return
            }
        }
    }

    // Resume the VPN a short time after WiFi is lost, only if it was paused by this
    // feature, the feature is still enabled and WiFi is really gone (not just roaming
    // to another AP).
    private fun scheduleVpnRestart() {
        if (lastStartArgs == null || !pausedByWifi) {
            return
        }
        cancelPendingRestart()
        val runnable = Runnable {
            pendingRestartRunnable = null
            // feature disabled while waiting
            if (connectivityManager == null) return@Runnable
            if (!pausedByWifi || lastStartArgs == null) return@Runnable
            // WiFi came back - keep it paused
            if (isWifiConnected()) return@Runnable
            println("vpn: wifi lost, resume vpn")
            pausedByWifi = false
            startVpnService(lastStartArgs!!)
        }
        pendingRestartRunnable = runnable
        mainHandler.postDelayed(runnable, 3000)
    }

    private fun cancelPendingRestart() {
        pendingRestartRunnable?.let { mainHandler.removeCallbacks(it) }
        pendingRestartRunnable = null
    }

    private fun startVpnService(args: Bundle) {
        TauriVpnService.self?.onRevoke()
        val intent = Intent(activity, TauriVpnService::class.java)
        intent.putExtras(args)
        activity.startService(intent)
    }

    private fun storeStartArgs(args: StartVpnArgs): Bundle {
        val bundle = Bundle()
        bundle.putString(TauriVpnService.IPV4_ADDR, args.ipv4Addr)
        bundle.putStringArray(TauriVpnService.ROUTES, args.routes)
        bundle.putString(TauriVpnService.DNS, args.dns)
        bundle.putStringArray(TauriVpnService.DISALLOWED_APPLICATIONS, args.disallowedApplications)
        args.mtu?.let { bundle.putInt(TauriVpnService.MTU, it) }
        return bundle
    }

    private fun registerWifiCallback() {
        if (connectivityManager != null) {
            return
        }
        val cm = activity.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .build()
        connectivityManager = cm
        try {
            cm.registerNetworkCallback(request, wifiNetworkCallback, Handler(Looper.getMainLooper()))
            println("vpn: wifi auto-pause callback registered")
            stopIfWifiConnected()
        } catch (e: Exception) {
            connectivityManager = null
            println("vpn: failed to register wifi auto-pause callback: $e")
        }
    }

    private fun unregisterWifiCallback() {
        cancelPendingRestart()
        connectivityManager?.unregisterNetworkCallback(wifiNetworkCallback)
        connectivityManager = null
    }

    override fun load(webView: WebView) {
        println("load vpn service plugin")
        TauriVpnService.triggerCallback = { event, data ->
            println("vpn: triggerCallback $event $data")
            trigger(event, data)
        }
    }

    @Command
    fun ping(invoke: Invoke) {
        val args = invoke.parseArgs(PingArgs::class.java)

        val ret = JSObject()
        ret.put("value", implementation.pong(args.value ?: "default value :("))
        invoke.resolve(ret)
    }

    @Command
    fun prepareVpn(invoke: Invoke) {
        activity.runOnUiThread {
            println("prepare vpn in plugin")
            val it = VpnService.prepare(activity)
            if (it != null) {
                startActivityForResult(invoke, it, "onPrepareVpnResult")
                return@runOnUiThread
            }
            val ret = JSObject()
            ret.put("granted", true)
            invoke.resolve(ret)
        }
    }

    @ActivityCallback
    fun onPrepareVpnResult(invoke: Invoke, result: ActivityResult) {
        val ret = JSObject()
        ret.put("granted", result.resultCode == Activity.RESULT_OK)
        invoke.resolve(ret)
    }

    @Command
    fun startVpn(invoke: Invoke) {
        val args = invoke.parseArgs(StartVpnArgs::class.java)
        activity.runOnUiThread {
            println("start vpn in plugin, args: $args")

            val it = VpnService.prepare(activity)
            val ret = JSObject()
            if (it != null) {
                ret.put("errorMsg", "need_prepare")
            } else {
                lastStartArgs = storeStartArgs(args)
                pausedByWifi = false
                startVpnService(lastStartArgs!!)
            }
            invoke.resolve(ret)
        }
    }

    @Command
    fun stopVpn(invoke: Invoke) {
        activity.runOnUiThread {
            println("stop vpn in plugin")
            cancelPendingRestart()
            pausedByWifi = false
            TauriVpnService.self?.onRevoke()
            activity.stopService(Intent(activity, TauriVpnService::class.java))
            println("stop vpn in plugin end")
            invoke.resolve(JSObject())
        }
    }

    @Command
    fun getVpnStatus(invoke: Invoke) {
        val ret = JSObject()
        ret.put("running", TauriVpnService.self != null)
        ret.put("ipv4Addr", TauriVpnService.ipv4Addr)
        ret.put("routes", TauriVpnService.routes)
        ret.put("dns", TauriVpnService.dns)
        invoke.resolve(ret)
    }

    @Command
    fun setAutoStopOnWifi(invoke: Invoke) {
        val args = invoke.parseArgs(SetAutoStopOnWifiArgs::class.java)
        println("vpn: set auto pause on wifi " + args.enabled)
        if (args.enabled) {
            registerWifiCallback()
        } else {
            unregisterWifiCallback()
        }
        invoke.resolve(JSObject())
    }
}
